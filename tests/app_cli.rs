//! Native app CLI tests exercise the local wire contract without running a GUI or changing networking.

#![cfg(target_vendor = "apple")]

use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Write},
    os::unix::net::UnixListener,
    process::Command,
};

/// Run the actual CLI against one same-user fake app endpoint and capture its request.
fn call(arguments: &[&str], response: Value) -> (std::process::Output, Value) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("app.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let server = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        let mut line = String::new();
        BufReader::new(socket.try_clone().unwrap())
            .read_line(&mut line)
            .unwrap();
        writeln!(socket, "{response}").unwrap();
        serde_json::from_str::<Value>(&line).unwrap()
    });
    let output = Command::new(env!("CARGO_BIN_EXE_zion"))
        .args(["app", "--socket", path.to_str().unwrap()])
        .args(arguments)
        .output()
        .unwrap();
    (output, server.join().unwrap())
}

/// Status produces only a versioned JSON response and sends no implicit mutations.
#[test]
fn status_uses_versioned_json() {
    let response = json!({"version":1,"ok":true,"result":{"phase":"disconnected"}});
    let (output, request) = call(&["status"], response.clone());
    assert!(output.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap(),
        response
    );
    assert_eq!(
        request,
        json!({"version":1,"command":"status","arguments":{}})
    );
}

/// An app error remains structured and returns a failing exit code without being disguised as success.
#[test]
fn remote_failure_is_not_success() {
    let response =
        json!({"version":1,"ok":false,"error":{"code":"no_profile","message":"Select a profile."}});
    let (output, _) = call(&["connect"], response.clone());
    assert!(!output.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap(),
        response
    );
}

/// YAML imports resolve credentials relative to the file and keep secrets out of CLI output.
#[test]
fn import_resolves_paths_and_redacts_output() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("client.yaml");
    std::fs::write(
        &path,
        "server: passage.example.com:8443\npassword: test-secret-value\nca: ca.pem\n",
    )
    .unwrap();
    let (output, request) = call(
        &[
            "profile",
            "import",
            "--name",
            "Test",
            "-c",
            path.to_str().unwrap(),
        ],
        json!({"version":1,"ok":true,"result":{"id":"example"}}),
    );
    assert!(output.status.success());
    let config: Value =
        serde_json::from_str(request["arguments"]["config"].as_str().unwrap()).unwrap();
    assert_eq!(
        config["ca"],
        directory.path().join("ca.pem").to_str().unwrap()
    );
    assert_eq!(config["password"], "test-secret-value");
    assert!(!String::from_utf8_lossy(&output.stdout).contains("test-secret-value"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("test-secret-value"));
}

/// An absent app reports failure promptly rather than starting a proxy or opening the UI.
#[test]
fn missing_app_has_json_failure() {
    let directory = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_zion"))
        .args([
            "app",
            "--socket",
            directory.path().join("missing.sock").to_str().unwrap(),
            "status",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["error"]["code"], "control_unavailable");
}

/// Invalid local input fails before contacting the app and never echoes a supplied password.
#[test]
fn invalid_import_is_a_structured_local_error() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("invalid.json");
    std::fs::write(&path, r#"{"server":"invalid","password":"private-value"}"#).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_zion"))
        .args([
            "app",
            "profile",
            "import",
            "--name",
            "Invalid",
            "-c",
            path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["error"]["code"], "invalid_arguments");
    assert!(!String::from_utf8_lossy(&output.stdout).contains("private-value"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("private-value"));
}

/// Log reads carry an explicit bounded count through the same authenticated local endpoint.
#[test]
fn logs_use_bounded_read_command() {
    let (output, request) = call(
        &["logs", "--limit", "20"],
        json!({"version":1,"ok":true,"result":{"entries":[],"retained":0}}),
    );
    assert!(output.status.success());
    assert_eq!(
        request,
        json!({"version":1,"command":"logs.read","arguments":{"limit":"20"}})
    );
}

/// Invalid log limits are rejected by argument parsing before any app connection is attempted.
#[test]
fn invalid_log_limit_is_rejected() {
    let output = Command::new(env!("CARGO_BIN_EXE_zion"))
        .args(["app", "logs", "--limit", "101"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
}
