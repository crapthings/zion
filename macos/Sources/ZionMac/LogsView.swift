import AppKit
import SwiftUI
import ZionControl

/// The log page displays searchable session events without duplicating connection status.
struct LogsView: View {
    let model: AppModel
    @State private var query = ""
    @State private var level: DiagnosticLevel?
    @State private var follow = true

    /// Filter only the displayed rows while preserving the complete retained session log.
    private var entries: [DiagnosticEntry] {
        model.logs.entries.filter {
            (level == nil || $0.level == level) && (query.isEmpty || $0.message.localizedCaseInsensitiveContains(query))
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: InterfaceSpacing.medium) {
                TextField("搜索日志", text: $query).textFieldStyle(WorkspaceSearchStyle())
                WorkspacePicker(title: "级别", selectionTitle: level?.rawValue.uppercased() ?? "全部", selection: $level) {
                    Text("全部").tag(Optional<DiagnosticLevel>.none)
                    ForEach(DiagnosticLevel.allCases, id: \.self) { Text($0.rawValue.uppercased()).tag(Optional($0)) }
                }.labelsHidden().frame(width: 110)
                Toggle("跟随", isOn: $follow).toggleStyle(.checkbox)
            }.padding(.horizontal, InterfaceSpacing.medium).padding(.vertical, InterfaceSpacing.small)
            ScrollViewReader { proxy in
                Group {
                    if entries.isEmpty {
                        WorkspaceEmptyState(title: query.isEmpty && level == nil ? "暂无日志" : "没有匹配的日志", symbol: "doc.text.magnifyingglass")
                    } else {
                        List(entries) { entry in
                            HStack(alignment: .top, spacing: InterfaceSpacing.medium) {
                                Text(entry.date, format: .dateTime.hour().minute().second()).foregroundStyle(.secondary).frame(width: 70, alignment: .leading)
                                Text(entry.level.rawValue.uppercased()).foregroundStyle(color(entry.level)).frame(width: 55, alignment: .leading)
                                Text(entry.message).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading)
                            }.font(.system(.caption, design: .monospaced)).padding(.vertical, InterfaceSpacing.small).id(entry.id)
                        }.listStyle(.plain)
                    }
                }
                .onChange(of: entries.last?.id) { _, id in if follow, let id { proxy.scrollTo(id, anchor: .bottom) } }
                .onAppear { if follow, let id = entries.last?.id { proxy.scrollTo(id, anchor: .bottom) } }
            }
            Divider()
            HStack(spacing: InterfaceSpacing.medium) {
                Text("\(model.logs.entries.count) / 500 条").font(.caption).foregroundStyle(.secondary)
                Spacer()
                Button("复制诊断", systemImage: "doc.on.doc") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(model.diagnosticReport, forType: .string)
                }.help("复制当前状态和保留的日志，包含服务器地址。")
                Button("清空") { model.logs.clear() }.disabled(model.logs.entries.isEmpty)
            }.padding(.horizontal, InterfaceSpacing.medium).padding(.vertical, InterfaceSpacing.small)
        }
    }

    /// Highlight severity with native semantic colors while keeping the text label visible.
    private func color(_ level: DiagnosticLevel) -> Color {
        switch level { case .error: .red; case .warning: .orange; case .debug: .secondary; case .info: .primary }
    }
}
