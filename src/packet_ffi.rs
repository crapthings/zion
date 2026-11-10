//! A bounded C ABI embeds the same packet engine in a GUI worker or NetworkExtension.

use crate::{
    config::ClientConfig,
    packet::{PacketSender, PacketTunnel},
    tunnel::tls::Identity,
};
use serde::Deserialize;
use std::{
    ffi::c_void,
    sync::{Arc, Mutex},
    thread::JoinHandle,
};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

/// Native hosts copy callback bytes synchronously and retain their context until destroy returns.
pub type NativeCallback = unsafe extern "C" fn(*mut c_void, *const u8, usize);
/// A native configuration carries transient PEM data separately from ordinary client metadata.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeConfiguration {
    client: ClientConfig,
    ca_pem: Option<String>,
    cert_pem: Option<String>,
    key_pem: Option<String>,
    mtu: usize,
}

/// A native handle owns ingress access and joins its callback worker before destruction.
pub struct NativeEngine {
    input: Arc<Mutex<Option<PacketSender>>>,
    shutdown: CancellationToken,
    thread: Option<JoinHandle<()>>,
}

/// Callback state crosses one owned worker thread while its caller guarantees context lifetime.
#[derive(Clone, Copy)]
struct Callbacks {
    packet: NativeCallback,
    event: NativeCallback,
    context: usize,
}

/// Callback emission borrows a byte slice only for the synchronous duration of the C call.
impl Callbacks {
    /// Invoke a packet callback using storage that remains valid until the host returns.
    fn packet(&self, data: &[u8]) {
        // SAFETY: create requires valid callbacks and context until its worker has been joined.
        unsafe {
            (self.packet)(self.context as *mut c_void, data.as_ptr(), data.len());
        }
    }

    /// Emit a fixed lifecycle event without serializing credentials or user-supplied diagnostics.
    fn event(&self, event: &str) {
        let data = format!("{{\"event\":\"{event}\"}}");
        // SAFETY: create requires valid callbacks and context until its worker has been joined.
        unsafe {
            (self.event)(self.context as *mut c_void, data.as_ptr(), data.len());
        }
    }
}

/// Start a packet worker using bounded in-memory JSON without accessing system networking.
///
/// # Safety
/// Input bytes and callbacks must be valid, and context must remain alive until destroy returns.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zion_packet_create(
    data: *const u8,
    length: usize,
    packet: NativeCallback,
    event: NativeCallback,
    context: *mut c_void,
) -> *mut NativeEngine {
    if data.is_null() || length == 0 || length > 256 * 1024 {
        return std::ptr::null_mut();
    }
    // SAFETY: the caller promises that length input bytes remain readable for this call.
    let source = Zeroizing::new(unsafe { std::slice::from_raw_parts(data, length) }.to_vec());
    let Ok(config) = serde_json::from_slice::<NativeConfiguration>(&source) else {
        return std::ptr::null_mut();
    };
    let input = Arc::new(Mutex::new(None));
    let shutdown = CancellationToken::new();
    let callbacks = Callbacks {
        packet,
        event,
        context: context as usize,
    };
    let shared = input.clone();
    let stopping = shutdown.clone();
    let Ok(thread) = std::thread::Builder::new()
        .name("zion-packet".into())
        .spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .max_blocking_threads(2)
                    .enable_all()
                    .build()?;
                let result = runtime.block_on(run(config, shared, stopping, callbacks));
                runtime.shutdown_timeout(std::time::Duration::from_secs(1));
                result
            }));
            match result {
                Ok(Ok(())) => callbacks.event("stopped"),
                _ => callbacks.event("error"),
            }
        })
    else {
        return std::ptr::null_mut();
    };
    Box::into_raw(Box::new(NativeEngine {
        input,
        shutdown,
        thread: Some(thread),
    }))
}

/// Submit one IP packet without blocking a platform callback or accepting an oversized allocation.
///
/// # Safety
/// Handle must remain live and packet must reference length readable bytes during this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zion_packet_send(
    handle: *mut NativeEngine,
    packet: *const u8,
    length: usize,
) -> i32 {
    if handle.is_null() || packet.is_null() || length == 0 || length > crate::packet::MAX_MTU {
        return -1;
    }
    // SAFETY: the caller serializes destruction with packet submission and supplies readable bytes.
    let engine = unsafe { &*handle };
    let guard = engine
        .input
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let Some(input) = guard.as_ref() else {
        return -1;
    };
    // SAFETY: length was bounded and the caller promises valid input storage.
    let data = unsafe { std::slice::from_raw_parts(packet, length) }.to_vec();
    match input.try_send(data) {
        Ok(()) => 1,
        Err(_) => 0,
    }
}

/// Stop and join the native worker before releasing callback context or closing interface ownership.
///
/// # Safety
/// Handle must be returned by create, destroyed once outside a callback, and have no concurrent send.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zion_packet_destroy(handle: *mut NativeEngine) {
    if handle.is_null() {
        return;
    }
    // SAFETY: the caller transfers unique ownership of its previously returned live handle.
    let mut engine = unsafe { Box::from_raw(handle) };
    engine.shutdown.cancel();
    if let Some(thread) = engine.thread.take() {
        let _ = thread.join();
    }
}

/// Load transient credentials and authenticate before delivering any packet-engine readiness event.
async fn run(
    mut config: NativeConfiguration,
    input: Arc<Mutex<Option<PacketSender>>>,
    shutdown: CancellationToken,
    callbacks: Callbacks,
) -> anyhow::Result<()> {
    let key = config.key_pem.take().map(Zeroizing::new);
    anyhow::ensure!(
        config.client.ca.is_some() == config.ca_pem.is_some()
            && config.client.cert.is_some() == config.cert_pem.is_some()
            && config.client.key.is_some() == key.is_some(),
        "embedded credentials do not match the selected profile"
    );
    let identity = Identity::client_from_pem(
        config.ca_pem.as_deref().map(str::as_bytes),
        config.cert_pem.as_deref().map(str::as_bytes),
        key.as_deref().map(|value| value.as_bytes()),
    )?;
    drop(key);
    let mtu = config.mtu;
    let start = async {
        let config = config.client.build_with_identity(identity).await?;
        PacketTunnel::start(config, mtu).await
    };
    // Build the runtime configuration separately so cancellation can stop DNS or authentication promptly.
    let mut tunnel =
        tokio::select! { _ = shutdown.cancelled() => return Ok(()), result = start => result? };
    *input.lock().unwrap_or_else(|error| error.into_inner()) = Some(tunnel.sender());
    callbacks.event("ready");
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            packet = tunnel.receive() => match packet { Some(packet) => callbacks.packet(&packet), None => anyhow::bail!("packet engine closed") }
        }
    }
    *input.lock().unwrap_or_else(|error| error.into_inner()) = None;
    tunnel.stop().await
}
