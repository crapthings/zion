import Foundation
import CZionPacket

/// Callback ownership keeps synchronous packet delivery independent of the main actor.
private final class PacketCallbacks: @unchecked Sendable {
    let packet: @Sendable (Data) -> Void
    let event: @Sendable (Data) -> Void
    init(packet: @escaping @Sendable (Data) -> Void, event: @escaping @Sendable (Data) -> Void) {
        self.packet = packet; self.event = event
    }
}

/// A packet callback copies borrowed Rust storage before its synchronous lifetime ends.
private func receivePacket(_ context: UnsafeMutableRawPointer?, _ bytes: UnsafePointer<UInt8>?, _ length: Int) {
    guard let context, let bytes, length > 0, length <= 9000 else { return }
    Unmanaged<PacketCallbacks>.fromOpaque(context).takeUnretainedValue().packet(Data(bytes: bytes, count: length))
}

/// A lifecycle callback forwards only bounded JSON events to the main actor.
private func receivePacketEvent(_ context: UnsafeMutableRawPointer?, _ bytes: UnsafePointer<UInt8>?, _ length: Int) {
    guard let context, let bytes, length > 0, length <= 4096 else { return }
    Unmanaged<PacketCallbacks>.fromOpaque(context).takeUnretainedValue().event(Data(bytes: bytes, count: length))
}

/// Detached resources remain owned until Rust has joined every callback.
private final class PacketResources: @unchecked Sendable {
    let handle: OpaquePointer
    let context: UnsafeMutableRawPointer
    init(handle: OpaquePointer, context: UnsafeMutableRawPointer) { self.handle = handle; self.context = context }

    /// Destroy on a background thread so shutdown never joins its own callback thread.
    func destroy() {
        #if ZION_PACKET_CORE
        zion_packet_destroy(handle)
        #endif
        Unmanaged<PacketCallbacks>.fromOpaque(context).release()
    }
}

/// A small lock serializes packet submission against handle removal during shutdown.
private final class PacketHandle: @unchecked Sendable {
    private let lock = NSLock()
    private var resources: PacketResources?

    /// Cancel an abandoned engine on a background thread while retaining its callback context.
    deinit {
        if let resources = take() { Task.detached { resources.destroy() } }
    }

    /// Publish a handle only after native creation has returned successfully.
    func install(_ value: PacketResources) { lock.lock(); defer { lock.unlock() }; resources = value }

    /// Transfer resources exactly once before asynchronous native destruction.
    func take() -> PacketResources? { lock.lock(); defer { lock.unlock() }; let value = resources; resources = nil; return value }

    /// Submit synchronously without retaining packet buffers or queuing unbounded Swift tasks.
    func send(_ packet: Data) -> Bool {
        lock.lock(); defer { lock.unlock() }
        #if ZION_PACKET_CORE
        guard let resources else { return false }
        return packet.withUnsafeBytes { buffer in
            zion_packet_send(resources.handle, buffer.bindMemory(to: UInt8.self).baseAddress, buffer.count) == 1
        }
        #else
        return false
        #endif
    }
}

/// A native packet engine is shared by platform adapters while interface and route ownership stay outside Rust.
@MainActor public final class NativePacketEngine {
    private nonisolated let handle = PacketHandle()
    private var pending: CheckedContinuation<Void, Error>?
    private var timeoutTask: Task<Void, Never>?
    private var stopping = false
    private var running = false
    private var stopTask: Task<Void, Never>?
    private var generation = UUID()
    public var onExit: (@MainActor (String) -> Void)?

    /// Report actual static-library linkage rather than assuming a selected backend is executable.
    public static var isLinked: Bool {
        #if ZION_PACKET_CORE
        true
        #else
        false
        #endif
    }

    public init() {}

    /// Start and authenticate the embedded core using a transient credential envelope.
    public func start(payload: Data, onPacket: @escaping @Sendable (Data) -> Void) async throws {
        guard pending == nil, !stopping, !running else { throw ControlError("数据引擎状态不允许启动。") }
        #if ZION_PACKET_CORE
        running = true
        let token = UUID(); generation = token
        do {
        try await withCheckedThrowingContinuation { continuation in
            pending = continuation
            let callbacks = PacketCallbacks(packet: onPacket, event: { [weak self] data in
                Task { @MainActor in self?.event(data, token: token) }
            })
            let context = Unmanaged.passRetained(callbacks).toOpaque()
            let pointer = payload.withUnsafeBytes { buffer in
                zion_packet_create(buffer.bindMemory(to: UInt8.self).baseAddress, buffer.count, receivePacket, receivePacketEvent, context)
            }
            guard let pointer else {
                Unmanaged<PacketCallbacks>.fromOpaque(context).release()
                running = false
                finish(ControlError("虚拟网卡配置无法加载。"))
                return
            }
            handle.install(PacketResources(handle: pointer, context: context))
            timeoutTask = Task { [weak self] in
                try? await Task.sleep(for: .seconds(30))
                guard !Task.isCancelled, let self, self.pending != nil else { return }
                self.finish(ControlError("虚拟网卡数据引擎启动超时。"))
                await self.stop()
            }
        }
        } catch {
            await stop()
            throw error
        }
        #else
        throw ControlError("此构建未链接虚拟网卡数据引擎。")
        #endif
    }

    /// Submit a complete packet directly from a platform callback with bounded backpressure.
    public nonisolated func send(_ packet: Data) -> Bool { handle.send(packet) }

    /// Join Rust before releasing callbacks so a virtual-interface owner can safely close afterward.
    public func stop() async {
        if let stopTask { await stopTask.value; return }
        stopping = true
        generation = UUID()
        finish(ControlError("虚拟网卡数据引擎已停止。"))
        let resources = handle.take()
        let task = Task { @MainActor in
            if let resources { await Task.detached { resources.destroy() }.value }
            self.running = false
            self.stopping = false
            self.stopTask = nil
        }
        stopTask = task
        await task.value
    }

    /// Decode lifecycle state without exposing transient credentials in diagnostics.
    private func event(_ data: Data, token: UUID) {
        guard generation == token, !stopping, let value = try? JSONSerialization.jsonObject(with: data) as? [String: String] else { return }
        switch value["event"] {
        case "ready": timeoutTask?.cancel(); pending?.resume(); pending = nil
        case "error":
            let message = "虚拟网卡数据引擎连接失败，请检查服务器与证书。"
            let starting = pending != nil
            finish(ControlError(message))
            if !starting { onExit?(message) }
        case "stopped": finish(ControlError("虚拟网卡数据引擎已退出。")); onExit?("虚拟网卡数据引擎已退出。")
        default: finish(ControlError("虚拟网卡数据引擎状态无效。"))
        }
    }

    /// Complete a pending start exactly once and cancel its startup timer.
    private func finish(_ error: Error) {
        timeoutTask?.cancel(); timeoutTask = nil
        pending?.resume(throwing: error); pending = nil
    }
}
