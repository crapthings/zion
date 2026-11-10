import Foundation

/// Core supervision reports only authenticated readiness rather than process liveness.
@MainActor public protocol EngineServing: AnyObject {
    var onLog: (@MainActor (String) -> Void)? { get set }
    var onExit: (@MainActor (Int32) -> Void)? { get set }
    func start(configuration: CoreConfiguration) async throws -> ProxyEndpoint
    func stop() async
}

/// Core events decode the stable JSON lifecycle messages written by Rust.
private struct CoreEvent: Decodable {
    let event: String
    let listen: String?
    let message: String?
}

/// A core process transports configuration through a pipe and bounds diagnostic buffering.
@MainActor public final class CoreProcess: EngineServing {
    public var onLog: (@MainActor (String) -> Void)?
    public var onExit: (@MainActor (Int32) -> Void)?
    private let executable: URL
    private var process: Process?
    private var stdoutPipe: Pipe?
    private var stderrPipe: Pipe?
    private var output = Data()
    private var errors = Data()
    private var pending: CheckedContinuation<ProxyEndpoint, Error>?
    private var timeoutTask: Task<Void, Never>?
    private var generation = UUID()
    private var sanitizer = DiagnosticSanitizer()

    /// Inject a binary in tests while resolving the packaged core in the desktop app.
    public init(executable: URL? = nil) { self.executable = executable ?? Self.defaultExecutable() }

    /// Authenticate the remote server and wait for the core's explicit ready event.
    public func start(configuration: CoreConfiguration) async throws -> ProxyEndpoint {
        guard process == nil else { throw ControlError("代理核心已经在运行。") }
        guard FileManager.default.isExecutableFile(atPath: executable.path) else {
            throw ControlError("没有找到可执行的代理核心，请使用完整的 Zion.app。")
        }
        sanitizer = DiagnosticSanitizer(password: configuration.password)
        onLog?("隧道传输：" + configuration.transport.title)
        let data = try JSONEncoder().encode(configuration)
        let token = UUID()
        generation = token
        return try await withCheckedThrowingContinuation { continuation in
            pending = continuation
            let task = Process()
            let input = Pipe(), stdout = Pipe(), stderr = Pipe()
            task.executableURL = executable
            task.arguments = ["client", "--config", "-", "--events-json"]
            var environment = ProcessInfo.processInfo.environment
            environment["RUST_LOG"] = "zion=info"
            environment["NO_COLOR"] = "1"
            task.environment = environment
            task.standardInput = input
            task.standardOutput = stdout
            task.standardError = stderr
            process = task
            stdoutPipe = stdout
            stderrPipe = stderr
            output.removeAll(keepingCapacity: true)
            errors.removeAll(keepingCapacity: true)
            stdout.fileHandleForReading.readabilityHandler = { [weak self] handle in
                let data = handle.availableData
                Task { @MainActor in self?.consume(data, diagnostic: false, token: token) }
            }
            stderr.fileHandleForReading.readabilityHandler = { [weak self] handle in
                let data = handle.availableData
                Task { @MainActor in self?.consume(data, diagnostic: true, token: token) }
            }
            task.terminationHandler = { [weak self] process in
                let status = process.terminationStatus
                Task { @MainActor in self?.terminated(status: status, token: token) }
            }
            do {
                try task.run()
                try input.fileHandleForWriting.write(contentsOf: data)
                try input.fileHandleForWriting.close()
                timeoutTask = Task { [weak self] in
                    try? await Task.sleep(for: .seconds(30))
                    guard !Task.isCancelled, let self, self.generation == token, self.pending != nil else { return }
                    self.fail(ControlError("连接服务器超时，请检查服务器、证书与出口网卡。"))
                    await self.stop()
                }
            } catch {
                fail(error)
                if task.isRunning { task.terminate() }
                clearHandlers()
                process = nil
            }
        }
    }

    /// Stop this app's core after allowing its supervised sessions to close.
    public func stop() async {
        fail(ControlError("连接已取消。"))
        guard let process else { return }
        if process.isRunning { process.interrupt() }
        for _ in 0..<120 {
            if !process.isRunning { break }
            try? await Task.sleep(for: .milliseconds(50))
        }
        if process.isRunning { process.terminate() }
        for _ in 0..<20 {
            if !process.isRunning { break }
            try? await Task.sleep(for: .milliseconds(50))
        }
        if !process.isRunning {
            generation = UUID()
            clearHandlers()
            self.process = nil
        }
    }

    /// Buffer complete lines while rejecting oversized or malformed control output.
    private func consume(_ data: Data, diagnostic: Bool, token: UUID) {
        guard token == generation else { return }
        if data.isEmpty {
            if diagnostic && !errors.isEmpty {
                let message = sanitizer.clean(String(decoding: errors, as: UTF8.self))
                if !message.isEmpty { onLog?(message) }
                errors.removeAll()
            }
            return
        }
        if diagnostic { errors.append(data) } else { output.append(data) }
        var buffer = diagnostic ? errors : output
        guard buffer.count <= 64 * 1024 else {
            fail(ControlError("核心输出超过限制，连接已停止。"))
            process?.terminate()
            return
        }
        while let newline = buffer.firstIndex(of: 10) {
            let line = Data(buffer[..<newline])
            buffer.removeSubrange(...newline)
            if diagnostic {
                let message = sanitizer.clean(String(decoding: line, as: UTF8.self))
                if !message.isEmpty { onLog?(message) }
            }
            else { receive(line) }
        }
        if diagnostic { errors = buffer } else { output = buffer }
    }

    /// Decode lifecycle events without reading credentials from diagnostic text.
    private func receive(_ line: Data) {
        guard let event = try? JSONDecoder().decode(CoreEvent.self, from: line) else {
            fail(ControlError("核心返回了无法识别的状态。"))
            process?.terminate()
            return
        }
        switch event.event {
        case "ready":
            do {
                let endpoint = try ProxyEndpoint(listen: event.listen ?? "")
                timeoutTask?.cancel()
                pending?.resume(returning: endpoint)
                pending = nil
            } catch { fail(error); process?.terminate() }
        case "error": fail(ControlError(sanitizer.clean(event.message ?? "核心连接失败。")))
        case "stopped": break
        default: fail(ControlError("核心状态版本不兼容。")); process?.terminate()
        }
    }

    /// Finish pending startup and report an unexpected process exit to its coordinator.
    private func terminated(status: Int32, token: UUID) {
        guard token == generation else { return }
        fail(ControlError("代理核心已退出（\(status)），可在日志中查看详情。"))
        clearHandlers()
        process = nil
        onExit?(status)
    }

    /// Resolve a startup failure exactly once and cancel its deadline task.
    private func fail(_ error: Error) {
        timeoutTask?.cancel()
        timeoutTask = nil
        pending?.resume(throwing: error)
        pending = nil
    }

    /// Remove callbacks before releasing pipes to prevent stale process events.
    private func clearHandlers() {
        stdoutPipe?.fileHandleForReading.readabilityHandler = nil
        stderrPipe?.fileHandleForReading.readabilityHandler = nil
        stdoutPipe = nil
        stderrPipe = nil
    }

    /// Resolve the bundled helper before considering an explicit development binary.
    public static func defaultExecutable() -> URL {
        if let path = ProcessInfo.processInfo.environment["ZION_CORE_PATH"] { return URL(fileURLWithPath: path) }
        let bundled = Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/zion-core")
        if FileManager.default.isExecutableFile(atPath: bundled.path) { return bundled }
        var root = URL(fileURLWithPath: #filePath)
        for _ in 0..<4 { root.deleteLastPathComponent() }
        return root.appendingPathComponent("target/debug/zion")
    }
}
