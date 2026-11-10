import AppKit
import SwiftUI
import ZionControl

/// Navigation groups the primary workflow separately from auxiliary pages added later.
private enum Page: String, CaseIterable, Identifiable {
    case overview = "概览", servers = "服务器", activity = "活动", settings = "设置"
    var id: Self { self }
    var symbol: String {
        switch self { case .overview: "shield"; case .servers: "server.rack"; case .activity: "waveform.path"; case .settings: "gearshape" }
    }
}

/// The root window keeps navigation quiet and prioritizes the current connection.
struct RootView: View {
    @Bindable var model: AppModel
    @State private var page: Page? = .overview

    var body: some View {
        NavigationSplitView {
            List(Page.allCases, selection: $page) { item in Label(item.rawValue, systemImage: item.symbol).tag(item) }
                .listStyle(.sidebar)
                .navigationSplitViewColumnWidth(min: 160, ideal: 180, max: 220)
                .safeAreaInset(edge: .bottom) {
                    HStack(spacing: 8) {
                        Circle().fill(model.connection.phase.connected ? Color.green : Color.secondary.opacity(0.4)).frame(width: 7, height: 7)
                        Text("Zion").font(.system(.subheadline, design: .rounded).weight(.semibold))
                        Spacer()
                        Text("0.1").foregroundStyle(.tertiary)
                    }.padding(18)
                }
        } detail: {
            Group {
                switch page ?? .overview {
                case .overview: OverviewView(model: model)
                case .servers: ServerListView(model: model)
                case .activity: ActivityView(model: model)
                case .settings: SettingsView(model: model)
                }
            }
            .navigationTitle((page ?? .overview).rawValue)
            .toolbar { ToolbarItem { Button { model.importJSON() } label: { Label("导入 JSON", systemImage: "square.and.arrow.down") }.disabled(!model.connection.phase.idle) } }
        }
        .frame(minWidth: 780, minHeight: 540)
        .sheet(item: $model.editing) { profile in ProfileEditor(model: model, initial: profile, initialPassword: model.editingPassword) }
        .alert("Zion", isPresented: Binding(get: { model.alert != nil }, set: { if !$0 { model.alert = nil } })) { Button("好") { model.alert = nil } } message: { Text(model.alert ?? "") }
    }
}

/// A reusable surface creates hierarchy using native colors instead of decorative imagery.
struct Surface<Content: View>: View {
    @ViewBuilder let content: Content
    var body: some View {
        content.padding(20).frame(maxWidth: .infinity, alignment: .leading)
            .background(.background, in: RoundedRectangle(cornerRadius: 14))
            .overlay(RoundedRectangle(cornerRadius: 14).stroke(.primary.opacity(0.07), lineWidth: 1))
    }
}

/// The overview exposes one primary connection action and an honest mode capability summary.
private struct OverviewView: View {
    let model: AppModel

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                HStack(alignment: .center, spacing: 20) {
                    Image(systemName: model.connection.phase.connected ? "shield.lefthalf.filled" : "shield")
                        .font(.system(size: 40, weight: .light)).foregroundStyle(model.connection.phase.connected ? Color.accentColor : Color.secondary)
                        .frame(width: 68, height: 68).background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 20))
                    VStack(alignment: .leading, spacing: 7) {
                        Text(model.connection.statusTitle).font(.system(size: 27, weight: .semibold, design: .rounded))
                        Text(model.connection.phase == .recoveryRequired ? "请先恢复系统代理设置，再重新连接。" : model.connection.phase.connected ? "跟随系统代理的应用正在通过 Zion 连接。" : "选择服务器，开始连接。")
                            .foregroundStyle(.secondary)
                    }
                    Spacer(minLength: 8)
                    Button(model.connection.phase == .recoveryRequired ? "恢复网络" : model.connection.phase.connected ? "断开连接" : model.connection.phase.busy ? "取消" : "连接") { Task { await model.toggle() } }
                        .buttonStyle(.borderedProminent).controlSize(.large)
                        .disabled(model.connection.phase == .authorizing || model.connection.phase == .disconnecting || (model.connection.phase.idle && !model.canConnect))
                }.padding(.vertical, 8)
                if let error = model.connection.lastError { Label(error, systemImage: "exclamationmark.circle").font(.callout).foregroundStyle(.orange).textSelection(.enabled) }
                Surface {
                    HStack {
                        VStack(alignment: .leading, spacing: 8) {
                            Text("当前服务器").font(.subheadline).foregroundStyle(.secondary)
                            Text(model.selectedProfile?.name ?? "尚未添加服务器").font(.title3.weight(.semibold))
                            if let profile = model.selectedProfile { Text(profile.server).font(.callout).foregroundStyle(.secondary) }
                        }
                        Spacer()
                        if !model.document.profiles.isEmpty {
                            Picker("服务器", selection: Binding(get: { model.document.selectedID }, set: { id in if let profile = model.document.profiles.first(where: { $0.id == id }) { model.select(profile) } })) {
                                ForEach(model.document.profiles) { Text($0.name).tag(Optional($0.id)) }
                            }.labelsHidden().frame(maxWidth: 210).disabled(!model.connection.phase.idle)
                        }
                        Button { model.edit(model.selectedProfile) } label: { Image(systemName: model.selectedProfile == nil ? "plus" : "slider.horizontal.3") }.help("配置服务器").disabled(!model.connection.phase.idle)
                    }
                }
                BackendPicker(model: model)
                if model.connection.needsRecovery {
                    Surface { HStack { Label("发现上次连接留下的网络恢复记录。", systemImage: "arrow.counterclockwise"); Spacer(); Button("恢复代理设置") { Task { await model.recover() } } } }
                }
            }.padding(32).frame(maxWidth: 940)
        }.background(Color(nsColor: .windowBackgroundColor))
    }
}

/// Server management keeps credentials behind an editor rather than placing them in list rows.
private struct ServerListView: View {
    let model: AppModel
    var body: some View {
        VStack(spacing: 0) {
            if model.document.profiles.isEmpty {
                ContentUnavailableView { Label("添加第一台服务器", systemImage: "server.rack") } description: { Text("使用密码或客户端证书连接，不需要用户名。") } actions: { Button("添加服务器") { model.edit() }.buttonStyle(.borderedProminent) }
            } else {
                List(model.document.profiles) { profile in
                    HStack(spacing: 14) {
                        Image(systemName: "server.rack").font(.title2).foregroundStyle(.secondary)
                        VStack(alignment: .leading, spacing: 5) { Text(profile.name).font(.headline); Text(profile.server).font(.callout).foregroundStyle(.secondary) }
                        Spacer()
                        if profile.id == model.document.selectedID { Image(systemName: "checkmark.circle.fill").foregroundStyle(Color.accentColor) }
                        Button("选择") { model.select(profile) }.disabled(!model.connection.phase.idle)
                        Button { model.edit(profile) } label: { Image(systemName: "pencil") }.disabled(!model.connection.phase.idle)
                    }.padding(.vertical, 10).contextMenu { Button("删除服务器", role: .destructive) { model.remove(profile) }.disabled(!model.connection.phase.idle) }
                }.listStyle(.inset)
            }
            HStack { Text("密码保存在 macOS 钥匙串中。").font(.caption).foregroundStyle(.secondary); Spacer(); Button("添加服务器", systemImage: "plus") { model.edit() }.disabled(!model.connection.phase.idle) }.padding(20)
        }
    }
}

/// Activity displays actual bounded core logs without inventing traffic statistics.
private struct ActivityView: View {
    let model: AppModel
    var body: some View {
        VStack(spacing: 0) {
            if model.activities.isEmpty { ContentUnavailableView("暂无活动", systemImage: "waveform.path", description: Text("连接后，这里会显示状态与诊断信息。")) }
            else {
                List(model.activities) { entry in
                    HStack(alignment: .top, spacing: 16) {
                        Text(entry.date, style: .time).foregroundStyle(.secondary).frame(width: 74, alignment: .leading)
                        Text(entry.message).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading)
                    }.font(.system(.caption, design: .monospaced)).padding(.vertical, 3)
                }.listStyle(.plain)
            }
            HStack { Text("仅保留最近 500 条记录").font(.caption).foregroundStyle(.secondary); Spacer(); Button("清空") { model.activities.removeAll() } }.padding(20)
        }
    }
}

/// Settings exposes recovery and local data management separately from the connection workflow.
private struct SettingsView: View {
    let model: AppModel
    var body: some View {
        Form {
            Section("网络") {
                BackendPicker(model: model)
                LabeledContent("实际运行", value: model.connection.phase.connected ? (model.connection.activeBackend?.title ?? "尚未连接") : "尚未连接")
                LabeledContent("本地监听", value: model.connection.endpoint?.description ?? "连接时自动分配")
                if model.connection.needsRecovery { Button("恢复上次网络设置") { Task { await model.recover() } } }
            }
            Section("配置") {
                Text("服务器信息保存在本机，密码独立保存在钥匙串。").foregroundStyle(.secondary)
                Button("打开配置目录") { try? FileManager.default.createDirectory(at: model.store.directory, withIntermediateDirectories: true); NSWorkspace.shared.open(model.store.directory) }
            }
            Section("关于") { LabeledContent("Zion", value: "0.1.0"); Text("原生 macOS 界面 · Rust 网络核心").foregroundStyle(.secondary) }
        }.formStyle(.grouped).padding(16)
    }
}

/// The backend picker persists one explicit choice while exposing implementation and authorization status.
struct BackendPicker: View {
    let model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("接管方式").font(.headline)
            Picker("接管方式", selection: Binding(
                get: { model.connection.selectedBackend },
                set: { model.selectBackend($0) }
            )) {
                ForEach(ConnectionBackend.allCases) { Text($0.title).tag($0) }
            }.pickerStyle(.segmented).labelsHidden()
                .disabled(!model.connection.phase.idle || model.connection.needsRecovery)
            Text(model.connection.selectedBackend.explanation).font(.callout).foregroundStyle(.secondary)
            if let reason = model.connection.readiness(for: model.connection.selectedBackend).explanation {
                Label(reason, systemImage: "info.circle").font(.callout).foregroundStyle(.orange)
            }
            Text("切换接管方式前需要先断开连接。系统代理只覆盖遵循系统 SOCKS 设置的应用。")
                .font(.caption).foregroundStyle(.secondary)
        }
    }
}
