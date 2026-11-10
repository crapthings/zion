import AppKit
import SwiftUI
import ZionControl

/// The log page combines observed connection diagnostics with searchable, bounded session events.
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
            VStack(alignment: .leading, spacing: 12) {
                Grid(alignment: .leading, horizontalSpacing: 24, verticalSpacing: 8) {
                    ForEach([0, 2, 4], id: \.self) { index in
                        GridRow {
                            ForEach(Array(model.diagnosticFields[index...index + 1])) { field in
                                HStack(spacing: 10) {
                                    Text(field.label).foregroundStyle(.secondary)
                                    Text(field.value).textSelection(.enabled).lineLimit(1).truncationMode(.middle)
                                    Spacer(minLength: 0)
                                }
                            }
                        }
                    }
                }.font(.callout)
                if let error = model.connection.lastError {
                    Label(error, systemImage: "exclamationmark.circle").font(.callout).foregroundStyle(.orange).textSelection(.enabled)
                }
                if let reason = model.connection.readiness(for: model.connection.selectedBackend).explanation {
                    Label(reason, systemImage: "info.circle").font(.callout).foregroundStyle(.secondary)
                }
            }.padding(20).frame(maxWidth: .infinity, alignment: .leading)
            Divider()
            HStack(spacing: 12) {
                TextField("搜索日志", text: $query).textFieldStyle(.roundedBorder)
                Picker("级别", selection: $level) {
                    Text("全部").tag(Optional<DiagnosticLevel>.none)
                    ForEach(DiagnosticLevel.allCases, id: \.self) { Text($0.rawValue.uppercased()).tag(Optional($0)) }
                }.labelsHidden().frame(width: 110)
                Toggle("跟随", isOn: $follow).toggleStyle(.checkbox)
            }.padding(.horizontal, 20).padding(.vertical, 12)
            ScrollViewReader { proxy in
                Group {
                    if entries.isEmpty {
                        ContentUnavailableView(query.isEmpty && level == nil ? "暂无日志" : "没有匹配的日志", systemImage: "doc.text.magnifyingglass", description: Text("这里记录本次运行的连接过程、核心输出与错误。"))
                    } else {
                        List(entries) { entry in
                            HStack(alignment: .top, spacing: 12) {
                                Text(entry.date, format: .dateTime.hour().minute().second()).foregroundStyle(.secondary).frame(width: 70, alignment: .leading)
                                Text(entry.level.rawValue.uppercased()).foregroundStyle(color(entry.level)).frame(width: 55, alignment: .leading)
                                Text(entry.message).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading)
                            }.font(.system(.caption, design: .monospaced)).padding(.vertical, 3).id(entry.id)
                        }.listStyle(.plain)
                    }
                }
                .onChange(of: entries.last?.id) { _, id in if follow, let id { proxy.scrollTo(id, anchor: .bottom) } }
                .onAppear { if follow, let id = entries.last?.id { proxy.scrollTo(id, anchor: .bottom) } }
            }
            Divider()
            HStack(spacing: 12) {
                Text("\(model.logs.entries.count) / 500 条 · 仅本次运行").font(.caption).foregroundStyle(.secondary)
                Spacer()
                Button("复制诊断", systemImage: "doc.on.doc") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(model.diagnosticReport, forType: .string)
                }.help("复制当前状态和保留的日志，包含服务器地址。")
                Button("清空") { model.logs.clear() }.disabled(model.logs.entries.isEmpty)
            }.padding(20)
        }
    }

    /// Highlight severity with native semantic colors while keeping the text label visible.
    private func color(_ level: DiagnosticLevel) -> Color {
        switch level { case .error: .red; case .warning: .orange; case .debug: .secondary; case .info: .primary }
    }
}
