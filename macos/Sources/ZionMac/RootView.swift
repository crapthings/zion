import AppKit
import SwiftUI
import ZionControl

/// Navigation groups the primary workflow separately from auxiliary pages added later.
private enum Page: String, CaseIterable, Identifiable {
    case overview = "概览", servers = "服务器", traffic = "进程流量", routing = "规则与策略", logs = "日志", settings = "设置"
    var id: Self { self }
    var symbol: String {
        switch self { case .overview: "shield"; case .servers: "server.rack"; case .traffic: "chart.bar.xaxis"; case .routing: "line.3.horizontal.decrease.circle"; case .logs: "doc.text.magnifyingglass"; case .settings: "gearshape" }
    }
}

/// The root window keeps navigation quiet and prioritizes the current connection.
struct RootView: View {
    @Bindable var model: AppModel
    @Environment(\.scenePhase) private var scenePhase
    @State private var page: Page? = .overview

    var body: some View {
        Group {
            if model.setupGuide.isPresented { SetupGuideView(model: model) }
            else { mainContent }
        }
        .onChange(of: scenePhase) { _, phase in
            if phase == .active {
                model.helperInstallation.refresh()
                if model.setupGuide.isPresented { model.setupGuide.refresh() }
            }
        }
        .onChange(of: model.connection.phase) { _, _ in if model.setupGuide.isPresented { model.setupGuide.refresh() } }
        .buttonStyle(.borderless)
        .textFieldStyle(.plain)
        .frame(minWidth: 780, minHeight: 600)
        .sheet(item: $model.editing) { profile in ProfileEditor(model: model, initial: profile, initialPassword: model.editingPassword) }
        .alert("Zion", isPresented: Binding(get: { model.alert != nil }, set: { if !$0 { model.alert = nil } })) { Button("好") { model.alert = nil } } message: { Text(model.alert ?? "") }
    }

    /// Preserve the main workspace independently from the skippable first-launch guide.
    private var mainContent: some View {
        NavigationSplitView {
            List(Page.allCases, selection: $page) { item in Label(item.rawValue, systemImage: item.symbol).tag(item) }
                .listStyle(.sidebar)
                .navigationSplitViewColumnWidth(min: 160, ideal: 180, max: 220)
        } detail: {
            Group {
                switch page ?? .overview {
                case .overview: OverviewView(model: model)
                case .servers: ServerListView(model: model)
                case .traffic: TrafficView(model: model)
                case .routing: RoutingView(model: model)
                case .logs: LogsView(model: model)
                case .settings: SettingsView(model: model)
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            .navigationTitle((page ?? .overview).rawValue)
            .toolbar {
                if page == .overview || page == .servers {
                    ToolbarItem {
                        Button { model.importJSON() } label: { Label("导入", systemImage: "square.and.arrow.down") }
                            .help("导入服务器 JSON").disabled(!model.connection.phase.idle)
                    }
                }
            }
        }
    }
}

/// A full-width section separates related controls with spacing instead of a surrounding border.
struct Surface<Content: View>: View {
    @ViewBuilder let content: Content
    var body: some View {
        content.padding(.vertical, InterfaceSpacing.medium)
            .frame(maxWidth: .infinity, alignment: .leading)
    }
}

/// The overview exposes one primary connection action and an honest mode capability summary.
private struct OverviewView: View {
    let model: AppModel

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: InterfaceSpacing.medium) {
                HStack(alignment: .center, spacing: InterfaceSpacing.medium) {
                    Image(systemName: model.connection.phase.connected ? "shield.lefthalf.filled" : "shield")
                        .font(.system(size: 30, weight: .light)).foregroundStyle(model.connection.phase.connected ? Color.accentColor : Color.secondary)
                        .frame(width: 48, height: 48)
                    VStack(alignment: .leading, spacing: InterfaceSpacing.small) {
                        Text(model.connection.statusTitle).font(.system(size: 24, weight: .semibold, design: .rounded))
                        Text(model.connection.phase == .recoveryRequired ? "需要恢复代理设置" : model.connection.phase.connected ? (model.connection.activeBackend?.title ?? "已连接") : model.connection.selectedBackend.title)
                            .foregroundStyle(.secondary)
                    }
                    Spacer(minLength: InterfaceSpacing.small)
                    Button(model.connection.phase == .recoveryRequired ? "恢复网络" : model.connection.phase.connected ? "断开连接" : model.connection.phase.busy ? "取消" : "连接") { Task { await model.toggle() } }
                        .buttonStyle(.borderless).controlSize(.large)
                        .disabled(model.connection.phase == .authorizing || model.connection.phase == .disconnecting || (model.connection.phase.idle && !model.canConnect))
                }.padding(.vertical, InterfaceSpacing.small)
                if let error = model.connection.lastError { Label(error, systemImage: "exclamationmark.circle").font(.callout).foregroundStyle(.orange).textSelection(.enabled) }
                Surface {
                    HStack(spacing: InterfaceSpacing.small) {
                        VStack(alignment: .leading, spacing: InterfaceSpacing.small) {
                            Text("服务器").font(.caption).foregroundStyle(.secondary)
                            if model.document.profiles.isEmpty {
                                Text("未添加").font(.headline)
                            } else {
                                WorkspacePicker(title: "服务器", selectionTitle: model.selectedProfile?.name ?? "选择服务器", selection: Binding(get: { model.document.selectedID }, set: { id in if let profile = model.document.profiles.first(where: { $0.id == id }) { model.select(profile) } })) {
                                    ForEach(model.document.profiles) { Text($0.name).tag(Optional($0.id)) }
                                }.labelsHidden().frame(maxWidth: .infinity, alignment: .leading).disabled(!model.connection.phase.idle)
                            }
                            if let profile = model.selectedProfile {
                                Text(profile.server + " · " + profile.transport.title).font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
                            }
                        }
                        Spacer()
                        Button { model.edit(model.selectedProfile) } label: { Image(systemName: model.selectedProfile == nil ? "plus" : "slider.horizontal.3") }.help("配置服务器").disabled(!model.connection.phase.idle)
                    }
                }
                BackendPicker(model: model)
                if model.connection.needsRecovery {
                    Surface { HStack(spacing: InterfaceSpacing.small) { Label("代理设置待恢复", systemImage: "arrow.counterclockwise"); Spacer(); Button("恢复代理设置") { Task { await model.recover() } } } }
                }
            }.padding(InterfaceSpacing.large).frame(maxWidth: .infinity, alignment: .leading)
        }.background(Color(nsColor: .windowBackgroundColor))
    }
}

/// Server management keeps credentials behind an editor rather than placing them in list rows.
private struct ServerListView: View {
    let model: AppModel
    var body: some View {
        VStack(spacing: 0) {
            if model.document.profiles.isEmpty {
                VStack(alignment: .leading, spacing: InterfaceSpacing.medium) {
                    Label("暂无服务器", systemImage: "server.rack").foregroundStyle(.secondary)
                    Button("添加服务器", systemImage: "plus") { model.edit() }
                }.padding(InterfaceSpacing.large)
                    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            } else {
                List(model.document.profiles) { profile in
                    HStack(spacing: InterfaceSpacing.medium) {
                        Image(systemName: "server.rack").font(.title2).foregroundStyle(.secondary)
                        VStack(alignment: .leading, spacing: InterfaceSpacing.small) { Text(profile.name).font(.headline); Text(profile.server + " · " + profile.transport.title).font(.callout).foregroundStyle(.secondary) }
                        Spacer()
                        if profile.id == model.document.selectedID { Image(systemName: "checkmark.circle.fill").foregroundStyle(Color.accentColor) }
                        Button("选择") { model.select(profile) }.disabled(!model.connection.phase.idle)
                        Button { model.edit(profile) } label: { Image(systemName: "pencil") }.disabled(!model.connection.phase.idle)
                    }.padding(.vertical, InterfaceSpacing.medium).contextMenu { Button("删除服务器", role: .destructive) { model.remove(profile) }.disabled(!model.connection.phase.idle) }
                }.listStyle(.plain)
            }
            HStack(spacing: InterfaceSpacing.small) { Text("\(model.document.profiles.count) 台服务器").font(.caption).foregroundStyle(.secondary); Spacer(); Button("添加服务器", systemImage: "plus") { model.edit() }.disabled(!model.connection.phase.idle) }.padding(.horizontal, InterfaceSpacing.medium).padding(.vertical, InterfaceSpacing.small)
        }
    }
}

/// Settings exposes recovery and local data management separately from the connection workflow.
private struct SettingsView: View {
    let model: AppModel
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: InterfaceSpacing.large) {
                BackendPicker(model: model)
                VStack(alignment: .leading, spacing: InterfaceSpacing.medium) {
                    LabeledContent("实际运行", value: model.connection.phase.connected ? (model.connection.activeBackend?.title ?? "尚未连接") : "尚未连接")
                    LabeledContent("本地监听", value: model.connection.endpoint?.description ?? "连接时自动分配")
                    if model.connection.needsRecovery {
                        Button("恢复网络") { Task { await model.recover() } }
                    }
                }
                VStack(alignment: .leading, spacing: InterfaceSpacing.medium) {
                    Button("打开配置目录", systemImage: "folder") {
                        try? FileManager.default.createDirectory(at: model.store.directory, withIntermediateDirectories: true)
                        NSWorkspace.shared.open(model.store.directory)
                    }
                    Button("启动引导", systemImage: "sparkles") { model.showSetup() }
                }
                LabeledContent("版本", value: "0.1.0").foregroundStyle(.secondary)
            }.frame(maxWidth: .infinity, alignment: .leading).padding(InterfaceSpacing.large)
        }.frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }
}

/// The backend picker persists one explicit choice while exposing implementation and authorization status.
struct BackendPicker: View {
    let model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: InterfaceSpacing.medium) {
            HStack(spacing: InterfaceSpacing.small) {
                Text("接管方式").font(.headline)
                Image(systemName: "info.circle").foregroundStyle(.secondary)
                    .help(model.connection.selectedBackend.explanation + " 切换前需断开连接。")
            }
            WorkspacePicker(title: "接管方式", selectionTitle: model.connection.selectedBackend.title, selection: Binding(
                get: { model.connection.selectedBackend },
                set: { model.selectBackend($0) }
            )) {
                ForEach(ConnectionBackend.allCases) { Text($0.title).tag($0) }
            }
                .disabled(!model.connection.phase.idle || model.connection.needsRecovery || model.helperInstallation.busy)
            if let reason = model.connection.readiness(for: model.connection.selectedBackend).explanation {
                Label("暂不可用", systemImage: "info.circle").font(.callout).foregroundStyle(.orange).help(reason)
            }
            if model.connection.selectedBackend == .helperTun { HelperInstallationView(model: model) }
        }
    }
}
