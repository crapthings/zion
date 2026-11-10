import AppKit
import SwiftUI
import ZionControl

/// The profile editor collects only connection essentials and reveals advanced fields on demand.
struct ProfileEditor: View {
    let model: AppModel
    @State private var profile: ServerProfile
    @State private var password: String
    @State private var error: String?
    @Environment(\.dismiss) private var dismiss

    init(model: AppModel, initial: ServerProfile, initialPassword: String) {
        self.model = model
        _profile = State(initialValue: initial)
        _password = State(initialValue: initialPassword)
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack { Text("服务器").font(.title2.weight(.semibold)); Spacer(); Button { dismiss() } label: { Image(systemName: "xmark") }.buttonStyle(.plain).foregroundStyle(.secondary) }.padding(24)
            Form {
                Section {
                    TextField("名称", text: $profile.name)
                    TextField("地址", text: $profile.server, prompt: Text("example.com:38443"))
                    Picker("认证", selection: $profile.authentication) { Text("密码").tag(Authentication.password); Text("客户端证书").tag(Authentication.certificate) }.pickerStyle(.segmented)
                    if profile.authentication == .password { SecureField("密码", text: $password) }
                    if profile.authentication == .certificate {
                        fileRow("客户端证书", path: $profile.certificate)
                        fileRow("私钥", path: $profile.privateKey)
                    }
                }
                Section {
                    DisclosureGroup("证书与网络选项") {
                        fileRow("服务端 CA", path: $profile.ca)
                        Text("公共 CA 证书无需填写；私有 CA 需要选择对应证书。").font(.caption).foregroundStyle(.secondary)
                        TextField("证书名称", text: $profile.serverName, prompt: Text("默认使用连接地址中的主机名"))
                        TextField("出口网卡", text: $profile.interface, prompt: Text("自动；运行其他代理时可指定 en1"))
                        if profile.authentication == .password {
                            fileRow("附加客户端证书", path: $profile.certificate)
                            fileRow("附加私钥", path: $profile.privateKey)
                        }
                    }
                }
                if let error { Text(error).font(.callout).foregroundStyle(.red) }
            }.formStyle(.grouped)
            HStack { Text("密码将保存在钥匙串中。").font(.caption).foregroundStyle(.secondary); Spacer(); Button("取消") { dismiss() }.keyboardShortcut(.cancelAction); Button("保存") { save() }.buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction) }.padding(20)
        }.frame(width: 530, height: 560)
    }

    /// Render a native file chooser with a removable absolute credential path.
    private func fileRow(_ title: String, path: Binding<String>) -> some View {
        LabeledContent(title) {
            HStack {
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
