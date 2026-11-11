import SwiftUI
import ZionControl

/// Process traffic focuses on egress decisions and retained counters instead of request debugging.
struct TrafficView: View {
    let model: AppModel
    @State private var selection: String?
    @State private var search = ""

    private var rows: [ProcessTraffic] {
        model.traffic.processes.filter { search.isEmpty || $0.process.title.localizedCaseInsensitiveContains(search) || ($0.process.path?.localizedCaseInsensitiveContains(search) ?? false) }
    }
    private var connections: [TrafficRecord] {
        model.traffic.records.filter { selection == nil || $0.process.key == selection }
    }
    private var editable: Bool { model.connection.phase.idle && !model.connection.needsRecovery && model.traffic.storageError == nil }

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: InterfaceSpacing.medium) {
                TextField("搜索进程", text: $search)
                    .textFieldStyle(WorkspaceSearchStyle()).frame(maxWidth: 320)
                    .help("按进程名或路径搜索")
                Spacer(minLength: 0)
                Button("清除", systemImage: "trash") { model.traffic.clearCompleted() }
                    .labelStyle(.iconOnly).help("清除已结束的连接")
                    .disabled(!model.traffic.records.contains { !$0.active })
            }.padding(.horizontal, InterfaceSpacing.medium).padding(.vertical, InterfaceSpacing.small)
            Divider()
            if model.traffic.records.isEmpty {
                WorkspaceEmptyState(title: "暂无流量", symbol: "network")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                VSplitView {
                    processTable.frame(minHeight: 150)
                    VStack(spacing: 0) {
                        HStack(spacing: InterfaceSpacing.small) {
                            Text(selection.flatMap { key in model.traffic.processes.first { $0.id == key }?.process.title } ?? "连接").font(.subheadline.weight(.medium)).lineLimit(1)
                            Text("\(connections.count)").foregroundStyle(.secondary).monospacedDigit()
                            Spacer()
                            if selection != nil { Button("全部", systemImage: "xmark.circle.fill") { selection = nil }.buttonStyle(.plain).foregroundStyle(.secondary).help("显示全部连接") }
                        }.padding(.horizontal, InterfaceSpacing.medium).padding(.vertical, InterfaceSpacing.small)
                        Divider()
                        connectionTable
                    }.frame(minHeight: 170)
                }
            }
            Divider()
            HStack(spacing: InterfaceSpacing.medium) {
                Text("\(model.traffic.processes.count) 个进程 · \(model.traffic.records.count) 条连接")
                Spacer(minLength: 0)
                if !editable { Image(systemName: "lock").accessibilityLabel("策略已锁定").help("断开后可修改策略") }
                Image(systemName: "info.circle").accessibilityLabel("统计范围").help("保留最近 500 条连接。仅统计进入 Zion 的流量；TCP 为应用数据，UDP 含 SOCKS 封装。")
            }.font(.caption).foregroundStyle(.secondary)
                .padding(.horizontal, InterfaceSpacing.medium).padding(.vertical, InterfaceSpacing.small)
        }.frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    /// A full-width process table keeps paths in tooltips and reserves stable columns for counters.
    private var processTable: some View {
        Table(rows, selection: $selection) {
            TableColumn("进程") { row in
                Text(row.process.title).lineLimit(1)
                    .help(row.process.path ?? "路径未知，未识别进程遵循默认策略。")
            }.width(min: 140, ideal: 240)
            TableColumn("上传") { Text(bytes($0.up)).monospacedDigit() }.width(70)
            TableColumn("下载") { Text(bytes($0.down)).monospacedDigit() }.width(70)
            TableColumn("活跃 / 总计") { Text("\($0.active) / \($0.connections)").monospacedDigit() }.width(80)
            TableColumn("策略") { row in
                Menu {
                    ForEach(RoutingPolicy.allCases, id: \.self) { policy in
                        Button(policy.title) { assign(row.process, policy: policy) }
                    }
                } label: { Image(systemName: "slider.horizontal.3") }
                    .menuStyle(.borderlessButton).menuIndicator(.hidden)
                    .accessibilityLabel("设置进程策略")
                    .disabled(!editable || (row.process.path == nil && row.process.name == nil))
                    .help(editable ? "为此进程添加最高优先级规则" : "断开连接后可修改策略")
            }.width(80)
        }
    }

    /// Connection rows explain observed egress decisions in a resizable secondary pane.
    private var connectionTable: some View {
        Table(connections) {
            TableColumn("进程") { Text($0.process.title).lineLimit(1) }.width(min: 80, ideal: 120)
            TableColumn("目标") { Text($0.protocol == "UDP" ? "UDP 关联" : $0.target).lineLimit(1).help($0.target) }
            TableColumn("策略") { Text($0.policy.title) }.width(45)
            TableColumn("规则") { Text($0.rule).lineLimit(1).help($0.rule) }
            TableColumn("上传 / 下载") { Text("\(bytes($0.up)) / \(bytes($0.down))").monospacedDigit() }.width(120)
            TableColumn("状态") { Text(status($0.status)) }.width(50)
        }
    }

    /// Prefer an executable path and replace its existing matcher to avoid shadowed quick rules.
    private func assign(_ process: TrafficProcess, policy: RoutingPolicy) {
        let matcher: ProcessMatcher = process.path == nil ? .processName : .processPath
        guard let value = process.path ?? process.name else { return }
        var routing = model.traffic.routing
        routing.rules.removeAll { $0.matcher == matcher && $0.value == value }
        routing.rules.insert(ProcessRule(matcher: matcher, value: value, policy: policy), at: 0)
        model.saveRouting(routing)
    }

    /// Format retained byte counters consistently with native macOS units.
    private func bytes(_ value: UInt64) -> String { ByteCountFormatter.string(fromByteCount: Int64(clamping: value), countStyle: .file) }

    /// Translate terminal outcomes without treating failed connections as successful traffic.
    private func status(_ value: String) -> String {
        switch value { case "active": "活跃"; case "closed": "结束"; case "rejected": "拒绝"; case "failed": "失败"; default: "中断" }
    }
}

/// Routing management exposes ordered exact process rules and one explicit FINAL policy.
struct RoutingView: View {
    let model: AppModel
    @State private var matcher = ProcessMatcher.processPath
    @State private var value = ""
    @State private var policy = RoutingPolicy.proxy
    @State private var adding = false
    private var editable: Bool { model.connection.phase.idle && !model.connection.needsRecovery && model.traffic.storageError == nil }

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: InterfaceSpacing.medium) {
                Text("默认").font(.subheadline.weight(.medium))
                WorkspacePicker(title: "默认策略", selectionTitle: model.traffic.routing.defaultPolicy.title, selection: Binding(get: { model.traffic.routing.defaultPolicy }, set: { policy in
                    var next = model.traffic.routing; next.defaultPolicy = policy; model.saveRouting(next)
                })) { ForEach(RoutingPolicy.allCases, id: \.self) { Text($0.title).tag($0) } }
                    .labelsHidden().frame(width: 100).disabled(!editable)
                    .help("FINAL：没有匹配规则或无法识别的进程使用此策略")
                Spacer(minLength: 0)
                Button("添加规则", systemImage: "plus") { adding = true }.disabled(!editable)
            }.padding(.horizontal, InterfaceSpacing.medium).padding(.vertical, InterfaceSpacing.small)
            Divider()
            if let error = model.traffic.storageError {
                Label(error, systemImage: "exclamationmark.triangle")
                    .font(.callout).foregroundStyle(.orange)
                    .frame(maxWidth: .infinity, alignment: .leading).padding(InterfaceSpacing.medium)
            }
            if model.traffic.routing.rules.isEmpty {
                WorkspaceEmptyState(title: "暂无规则", symbol: "line.3.horizontal.decrease.circle")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List {
                    ForEach(Array(model.traffic.routing.rules.enumerated()), id: \.offset) { index, rule in
                        ruleRow(index, rule: rule)
                    }
                }.listStyle(.plain).disabled(!editable)
            }
            Divider()
            HStack(spacing: InterfaceSpacing.medium) {
                Text("\(model.traffic.routing.rules.count) 条规则")
                    .help("首条启用且精确匹配的规则生效；进程名区分大小写，建议优先使用完整路径。")
                Spacer(minLength: 0)
                if !model.connection.phase.idle || model.connection.needsRecovery {
                    Image(systemName: "lock").accessibilityLabel("规则已锁定").help("断开后可编辑")
                }
            }.font(.caption).foregroundStyle(.secondary)
                .padding(.horizontal, InterfaceSpacing.medium).padding(.vertical, InterfaceSpacing.small)
        }.frame(maxWidth: .infinity, maxHeight: .infinity)
            .sheet(isPresented: $adding) { ruleEditor }
    }

    /// A compact row aligns rule order, matcher, process value, and policy across the entire list.
    private func ruleRow(_ index: Int, rule: ProcessRule) -> some View {
        HStack(spacing: InterfaceSpacing.medium) {
            Text("\(index + 1)").monospacedDigit().foregroundStyle(.tertiary)
                .frame(width: 24, alignment: .trailing)
            Toggle("启用", isOn: Binding(get: { rule.enabled }, set: { enabled in change(index) { $0.enabled = enabled } }))
                .labelsHidden().toggleStyle(.checkbox).help("启用规则")
            Text(rule.matcher == .processPath ? "路径" : "名称").font(.caption).foregroundStyle(.secondary).frame(width: 32, alignment: .leading)
            Text(rule.value).lineLimit(1).truncationMode(.middle)
                .frame(maxWidth: .infinity, alignment: .leading).help(rule.value).foregroundStyle(rule.enabled ? .primary : .secondary)
            WorkspacePicker(title: "策略", selectionTitle: rule.policy.title, selection: Binding(get: { rule.policy }, set: { policy in change(index) { $0.policy = policy } })) {
                ForEach(RoutingPolicy.allCases, id: \.self) { Text($0.title).tag($0) }
            }.labelsHidden().frame(width: 86)
            Menu {
                Button("上移", systemImage: "arrow.up") { move(index, by: -1) }.disabled(index == 0)
                Button("下移", systemImage: "arrow.down") { move(index, by: 1) }.disabled(index + 1 == model.traffic.routing.rules.count)
                Divider()
                Button("删除", systemImage: "trash", role: .destructive) {
                    var next = model.traffic.routing; next.rules.remove(at: index); model.saveRouting(next)
                }
            } label: { Image(systemName: "ellipsis") }
                .menuStyle(.borderlessButton).menuIndicator(.hidden).frame(width: 24).help("规则操作")
        }.padding(.vertical, InterfaceSpacing.small)
    }

    /// A separate editor gives process paths enough space without crowding the main rule list.
    private var ruleEditor: some View {
        VStack(alignment: .leading, spacing: InterfaceSpacing.medium) {
            Text("添加规则").font(.headline)
            Form {
                LabeledContent("匹配") {
                    WorkspacePicker(title: "匹配", selectionTitle: matcher.title, selection: $matcher) {
                        ForEach(ProcessMatcher.allCases, id: \.self) { Text($0.title).tag($0) }
                    }
                }
                TextField(matcher == .processPath ? "绝对路径" : "进程名", text: $value)
                    .textFieldStyle(WorkspaceSearchStyle())
                LabeledContent("策略") {
                    WorkspacePicker(title: "策略", selectionTitle: policy.title, selection: $policy) {
                        ForEach(RoutingPolicy.allCases, id: \.self) { Text($0.title).tag($0) }
                    }
                }
            }
            HStack(spacing: InterfaceSpacing.small) {
                Spacer()
                Button("取消") { adding = false }.keyboardShortcut(.cancelAction)
                Button("添加") {
                    var next = model.traffic.routing
                    next.rules.append(ProcessRule(matcher: matcher, value: value, policy: policy))
                    model.saveRouting(next)
                    if model.traffic.routing == next { value = ""; adding = false }
                }.keyboardShortcut(.defaultAction)
                    .disabled(!editable || value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
        }.padding(InterfaceSpacing.large).frame(width: 440)
            .buttonStyle(.borderless).textFieldStyle(.plain)
    }

    /// Update one rule through the same validated persistence path used by quick assignments.
    private func change(_ index: Int, edit: (inout ProcessRule) -> Void) {
        var next = model.traffic.routing; edit(&next.rules[index]); model.saveRouting(next)
    }

    /// Reorder adjacent rules to make precedence explicit without implicit sorting.
    private func move(_ index: Int, by offset: Int) {
        var next = model.traffic.routing; next.rules.swapAt(index, index + offset); model.saveRouting(next)
    }
}
