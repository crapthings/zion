import AppKit
import SwiftUI
import ZionControl

/// The application delegate restores networking before allowing a connected app to quit.
@MainActor final class AppDelegate: NSObject, NSApplicationDelegate {
    weak var model: AppModel?
    private var terminating = false

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard let model, !model.connection.phase.idle || model.connection.needsRecovery else { return .terminateNow }
        guard !terminating else { return .terminateLater }
        terminating = true
        Task {
            let restored = await model.connection.disconnect()
            terminating = false
            sender.reply(toApplicationShouldTerminate: restored)
        }
        return .terminateLater
    }
}

/// Zion presents a native window and a persistent menu-bar control for the same connection.
@main @MainActor struct ZionApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @State private var model = AppModel()

    var body: some Scene {
        WindowGroup(id: "main") {
            RootView(model: model)
                .onAppear { delegate.model = model }
        }
        .defaultSize(width: 920, height: 650)
        .commands { CommandGroup(after: .newItem) { Button("导入 JSON 配置…") { model.importJSON() }.keyboardShortcut("i", modifiers: [.command, .shift]) } }
        MenuBarExtra("Zion", systemImage: model.connection.phase.connected ? "shield.lefthalf.filled" : "shield") {
            MenuContent(model: model).onAppear { delegate.model = model }
        }
    }
}

/// The menu-bar view exposes current state without showing sensitive server credentials.
private struct MenuContent: View {
    let model: AppModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Text(model.connection.statusTitle)
        if let profile = model.selectedProfile { Text(profile.name) }
        Picker("接管方式", selection: Binding(get: { model.connection.selectedBackend }, set: { model.selectBackend($0) })) {
            ForEach(ConnectionBackend.allCases) { Text($0.title).tag($0) }
        }.disabled(!model.connection.phase.idle || model.connection.needsRecovery)
        Divider()
        Button(model.connection.phase == .recoveryRequired ? "恢复网络" : model.connection.phase.connected ? "断开连接" : "连接") { Task { await model.toggle() } }
            .disabled(model.connection.phase.busy || (model.connection.phase.idle && !model.canConnect))
        Button("打开 Zion") { openWindow(id: "main"); NSApp.activate(ignoringOtherApps: true) }
        Divider()
        Button("退出 Zion") { NSApp.terminate(nil) }.keyboardShortcut("q")
    }
}
