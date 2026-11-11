import AppKit
import SwiftUI
import ZionControl

/// The profile editor prioritizes connection fields and keeps optional certificate settings in a disclosure.
struct ProfileEditor: View {
    let model: AppModel
    @State private var profile: ServerProfile
    @State private var password: String
    @State private var error: String?
    @State private var advanced = false
    @Environment(\.dismiss) private var dismiss

    init(model: AppModel, initial: ServerProfile, initialPassword: String) {
        self.model = model
        _profile = State(initialValue: initial)
        _password = State(initialValue: initialPassword)
        _advanced = State(initialValue: !initial.ca.isEmpty || !initial.serverName.isEmpty || !initial.interface.isEmpty || (initial.authentication == .password && !initial.certificate.isEmpty))
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: InterfaceSpacing.small) { Text("服务器").font(.headline); Spacer() }.padding(InterfaceSpacing.medium)
            Form {
                Section {
                    TextField("名称", text: $profile.name)
                    TextField("地址", text: $profile.server, prompt: Text("example.com:38443"))
                    LabeledContent("传输") {
                        WorkspacePicker(title: "传输", selectionTitle: profile.transport.title, selection: $profile.transport) {
                            ForEach(TunnelTransport.allCases, id: \.self) { Text($0.title).tag($0) }
                        }
                    }
                    LabeledContent("认证") {
                        WorkspacePicker(title: "认证", selectionTitle: profile.authentication == .password ? "密码" : "证书", selection: $profile.authentication) {
                            Text("密码").tag(Authentication.password)
                            Text("证书").tag(Authentication.certificate)
                        }
                    }
                    if profile.authentication == .password { SecureField("密码", text: $password) }
                    if profile.authentication == .certificate {
                        fileRow("客户端证书", path: $profile.certificate)
                        fileRow("私钥", path: $profile.privateKey)
                    }
                }
                DisclosureGroup("高级选项", isExpanded: $advanced) {
                    fileRow("服务端 CA", path: $profile.ca)
                    TextField("证书名称", text: $profile.serverName, prompt: Text("默认主机名")).help("TLS 证书校验名称，留空使用服务器主机名")
                    TextField("出口网卡", text: $profile.interface, prompt: Text("自动")).help("指定出口网卡，例如 en0")
                    if profile.authentication == .password {
                        fileRow("附加客户端证书", path: $profile.certificate)
                        fileRow("附加私钥", path: $profile.privateKey)
                    }
                }
                if let error { Text(error).font(.callout).foregroundStyle(.red) }
            }.formStyle(.columns).frame(maxWidth: .infinity, alignment: .leading).padding(.horizontal, InterfaceSpacing.medium)
            HStack(spacing: InterfaceSpacing.small) { Spacer(); Button("取消") { dismiss() }.keyboardShortcut(.cancelAction); Button("保存") { save() }.buttonStyle(.borderless).keyboardShortcut(.defaultAction) }.padding(InterfaceSpacing.medium)
        }.buttonStyle(.borderless).textFieldStyle(.plain)
            .frame(width: 500, height: advanced ? 560 : 430)
    }

    /// Render a native file chooser with a removable absolute credential path.
    private func fileRow(_ title: String, path: Binding<String>) -> some View {
        LabeledContent(title) {
            HStack(spacing: InterfaceSpacing.small) {
                Text(path.wrappedValue.isEmpty ? "未选择" : URL(fileURLWithPath: path.wrappedValue).lastPathComponent).foregroundStyle(.secondary).lineLimit(1).help(path.wrappedValue)
                if !path.wrappedValue.isEmpty { Button { path.wrappedValue = "" } label: { Image(systemName: "xmark.circle.fill") }.buttonStyle(.plain).foregroundStyle(.tertiary) }
                Button("选择…") {
                    let panel = NSOpenPanel()
                    panel.canChooseDirectories = false
                    if panel.runModal() == .OK, let url = panel.url { path.wrappedValue = url.path }
                }
            }
        }
    }

    /// Validate and save without including entered credentials in any error message.
    private func save() {
        do { try model.save(profile, password: password); password = ""; dismiss() }
        catch { self.error = error.localizedDescription }
    }
}
