import Foundation
import Observation

/// A backend coordinator keeps selection independent from the backend that currently owns networking.
@Observable @MainActor public final class BackendConnection {
    public private(set) var selectedBackend: ConnectionBackend
    private var ownerBackend: ConnectionBackend?
    public var onLog: (@MainActor (String) -> Void)?
    private let system: ConnectionController
    private let enhanced: [ConnectionBackend: any TunnelBackendServing]
    private var enhancedPhase = ConnectionPhase.disconnected
    private var enhancedError: String?
    private var operation = UUID()
    private var disconnectTask: Task<Bool, Never>?

    /// Inject all transports so mutual exclusion and failures can be tested without network changes.
    public init(system: ConnectionController, enhanced: [any TunnelBackendServing], selected: ConnectionBackend = .systemProxy) {
        self.system = system
        self.enhanced = Dictionary(uniqueKeysWithValues: enhanced.map { ($0.backend, $0) })
        selectedBackend = selected
        system.onLog = { [weak self] message in self?.onLog?(message) }
        for driver in enhanced {
            let backend = driver.backend
            driver.onExit = { [weak self] message in self?.exited(backend: backend, message: message) }
        }
    }

    public var activeBackend: ConnectionBackend? { phase.active || phase.busy ? ownerBackend : nil }
    public var phase: ConnectionPhase { ownerBackend == .systemProxy ? system.phase : enhancedPhase }
    public var endpoint: ProxyEndpoint? { ownerBackend == .systemProxy ? system.endpoint : nil }
    public var lastError: String? { ownerBackend == .systemProxy ? system.lastError : enhancedError }
    public var needsRecovery: Bool {
        (phase.idle || phase == .recoveryRequired) && (system.needsRecovery || enhanced.values.contains { $0.needsRecovery })
    }
    public var statusTitle: String {
        if phase.connected { ownerBackend == .systemProxy ? "系统代理已开启" : "增强模式已开启" } else { phase.title }
    }

    /// Report the selected transport's own readiness without treating another backend as its fallback.
    public func readiness(for backend: ConnectionBackend) -> BackendReadiness {
        if backend != .systemProxy, let driver = enhanced[backend] { return driver.readiness }
        switch backend {
        case .systemProxy: return .ready
        case .networkExtension: return .unavailable("NetworkExtension 提供器尚未接入，当前可保存此选择。")
        case .helperTun: return .unavailable("TUN 的 utun、路由与 DNS 接管尚未接入。")
        }
    }

    /// Require a clean disconnection before changing the transport that will own the next connection.
    public func select(_ backend: ConnectionBackend) throws {
        guard phase.idle && !needsRecovery && disconnectTask == nil else { throw ControlError("请先断开连接并恢复网络设置，再切换接管方式。") }
        selectedBackend = backend
        ownerBackend = nil
        enhancedPhase = .disconnected
        enhancedError = nil
    }

    /// Connect exactly the selected transport and never silently downgrade on startup failure.
    public func connect(configuration: CoreConfiguration) async {
        guard phase.idle && disconnectTask == nil else { return }
        guard !needsRecovery else {
            ownerBackend = nil
            enhancedError = "请先恢复上次连接留下的网络设置。"
            enhancedPhase = .failed(enhancedError!)
            return
        }
        let backend = selectedBackend
        guard readiness(for: backend).canConnect else {
            ownerBackend = nil
            enhancedError = readiness(for: backend).explanation
            enhancedPhase = .failed(enhancedError ?? "后端不可用。")
            return
        }
        let token = UUID(); operation = token
        ownerBackend = backend
        enhancedError = nil
        if backend == .systemProxy {
            await system.connect(configuration: configuration)
            if system.phase.idle {
                enhancedPhase = system.phase
                enhancedError = system.lastError
                ownerBackend = nil
            }
            return
        }
        guard let driver = enhanced[backend] else { return }
        enhancedPhase = .connecting
        do {
            try await driver.start(configuration: configuration)
            guard token == operation else { return }
            enhancedPhase = .connected
            onLog?("\(backend.title) 已启用。")
        } catch {
            guard token == operation else { return }
            enhancedError = error.localizedDescription
            enhancedPhase = driver.needsRecovery ? .recoveryRequired : .failed(error.localizedDescription)
            if !driver.needsRecovery { ownerBackend = nil }
        }
    }

    /// Stop only the active owner and retain recovery state if its cleanup fails.
    @discardableResult public func disconnect() async -> Bool {
        if let disconnectTask { return await disconnectTask.value }
        let task = Task { @MainActor in
            let result = await self.performDisconnect()
            self.disconnectTask = nil
            return result
        }
        disconnectTask = task
        return await task.value
    }

    /// Finish one owned teardown before another connection or backend selection can proceed.
    private func performDisconnect() async -> Bool {
        operation = UUID()
        if ownerBackend == .systemProxy {
            let restored = await system.disconnect()
            if restored { ownerBackend = nil; enhancedPhase = .disconnected }
            return restored
        }
        guard let backend = ownerBackend, let driver = enhanced[backend] else {
            return await recoverInactiveOwners()
        }
        enhancedPhase = .disconnecting
        do {
            try await driver.stop()
            enhancedPhase = .disconnected
            ownerBackend = nil
            enhancedError = nil
            onLog?("\(backend.title) 已断开。")
            return true
        } catch {
            enhancedPhase = .recoveryRequired
            enhancedError = error.localizedDescription
            return false
        }
    }

    /// Recover every known owner before allowing another backend to claim the network.
    public func recover() async {
        guard phase.idle || phase == .recoveryRequired else { return }
        _ = await disconnect()
    }

    /// Restore abandoned owners within the same serialized teardown used by explicit disconnection.
    private func recoverInactiveOwners() async -> Bool {
        enhancedPhase = .disconnecting
        system.recover()
        if system.needsRecovery { enhancedError = system.lastError }
        for driver in enhanced.values where driver.needsRecovery {
            do { try await driver.stop() } catch { enhancedError = error.localizedDescription }
        }
        if system.needsRecovery || enhanced.values.contains(where: { $0.needsRecovery }) {
            enhancedPhase = .recoveryRequired
            return false
        }
        ownerBackend = nil
        enhancedPhase = .disconnected
        enhancedError = nil
        return true
    }

    /// Keep an unexpectedly stopped adapter visible until its owned network settings are restored.
    private func exited(backend: ConnectionBackend, message: String) {
        guard ownerBackend == backend && phase != .disconnecting else { return }
        operation = UUID()
        enhancedError = message
        enhancedPhase = enhanced[backend]?.needsRecovery == true ? .recoveryRequired : .failed(message)
    }
}
