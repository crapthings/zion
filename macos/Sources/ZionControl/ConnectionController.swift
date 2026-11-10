import Foundation
import Observation

/// Connection phases distinguish server readiness from completed system proxy activation.
public enum ConnectionPhase: Equatable, Sendable {
    case disconnected, connecting, authorizing, connected, disconnecting, recoveryRequired, failed(String)

    public var busy: Bool { self == .connecting || self == .authorizing || self == .disconnecting }
    public var connected: Bool { self == .connected }
    public var active: Bool { connected || self == .recoveryRequired }
    public var idle: Bool { switch self { case .disconnected, .failed: true; default: false } }

    /// Present an honest state label without inventing traffic or latency measurements.
    public var title: String {
        switch self {
        case .disconnected: "尚未连接"
        case .connecting: "正在连接服务器"
        case .authorizing: "正在启用系统代理"
        case .connected: "系统代理已开启"
        case .disconnecting: "正在恢复网络"
        case .recoveryRequired: "需要恢复网络"
        case .failed: "连接未完成"
        }
    }
}

/// A connection coordinator restores networking before stopping its owned core process.
@Observable @MainActor public final class ConnectionController {
    public private(set) var phase = ConnectionPhase.disconnected
    public private(set) var endpoint: ProxyEndpoint?
    public private(set) var lastError: String?
    public var onLog: (@MainActor (String) -> Void)?
    private let engine: any EngineServing
    private let proxy: any SystemProxyServing
    private var operation = UUID()
    private var recoveryRecorded: Bool

    /// Inject platform services so lifecycle tests never touch actual system proxy preferences.
    public init(engine: any EngineServing, proxy: any SystemProxyServing) {
        self.engine = engine; self.proxy = proxy
        recoveryRecorded = proxy.needsRecovery
        engine.onLog = { [weak self] text in self?.onLog?(text) }
        engine.onExit = { [weak self] status in self?.exited(status) }
    }

    public var needsRecovery: Bool { phase.idle && recoveryRecorded }

    /// Activate system proxy settings only after the core verifies remote authentication.
    public func connect(configuration: CoreConfiguration) async {
        guard phase.idle else { return }
        defer { recoveryRecorded = proxy.needsRecovery }
        let token = UUID(); operation = token
        lastError = nil
        phase = .connecting
        var readyEndpoint: ProxyEndpoint?
        do {
            let ready = try await engine.start(configuration: configuration)
            guard operation == token else { return }
            readyEndpoint = ready
            phase = .authorizing
            try proxy.enable(endpoint: ready)
            endpoint = ready
            phase = .connected
            onLog?("系统代理已启用。")
        } catch {
            guard operation == token else { return }
            if let readyEndpoint, proxy.needsRecovery {
                endpoint = readyEndpoint
                phase = .recoveryRequired
                lastError = error.localizedDescription
                return
            }
            await engine.stop()
            lastError = error.localizedDescription
            phase = .failed(error.localizedDescription)
        }
    }

    /// Preserve a functioning core if restoring its proxy settings fails.
    @discardableResult public func disconnect() async -> Bool {
        defer { recoveryRecorded = proxy.needsRecovery }
        operation = UUID()
        let previous = phase
        phase = .disconnecting
        do { try proxy.restore() }
        catch {
            lastError = error.localizedDescription
            phase = previous.active ? previous : .failed(error.localizedDescription)
            return false
        }
        await engine.stop()
        endpoint = nil
        phase = .disconnected
        lastError = nil
        onLog?("已断开，系统代理设置已恢复。")
        return true
    }

    /// Restore an interrupted connection's journal only after a user requests recovery.
    public func recover() {
        guard phase.idle else { return }
        defer { recoveryRecorded = proxy.needsRecovery }
        do { try proxy.restore(); lastError = nil; onLog?("网络代理设置已恢复。") }
        catch { lastError = error.localizedDescription }
    }

    /// Restore owned proxy settings after an unexpected core exit.
    private func exited(_ status: Int32) {
        guard phase != .disconnected && phase != .disconnecting else { return }
        defer { recoveryRecorded = proxy.needsRecovery }
        operation = UUID()
        do {
            try proxy.restore()
            endpoint = nil
            phase = .failed("连接已中断，系统代理已恢复。")
            lastError = "代理核心已退出（\(status)）。"
        } catch {
            endpoint = nil
            phase = .failed("连接已中断，需要恢复网络设置。")
            lastError = error.localizedDescription
        }
    }
}
