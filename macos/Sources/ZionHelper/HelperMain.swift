import Foundation
import Security
import ZionHelperProtocol

/// The helper reports its actual capabilities without claiming a working TUN adapter.
final class HelperStatus: NSObject, HelperStatusProtocol {
    func status(reply: @escaping (String) -> Void) {
        reply(#"{"version":1,"component":"dev.zion.helper","tun_available":false}"#)
    }
}

/// The listener accepts only the signed host app from the helper's own Apple signing team.
final class HelperListener: NSObject, NSXPCListenerDelegate {
    private let requirement: String?

    /// Disable IPC for ad hoc builds that cannot establish a shared signing-team identity.
    override init() {
        var code: SecCode?
        var information: CFDictionary?
        var staticCode: SecStaticCode?
        if SecCodeCopySelf([], &code) == errSecSuccess, let code,
           SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode,
           SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
           let values = information as? [String: Any], let team = values[kSecCodeInfoTeamIdentifier as String] as? String,
           team.range(of: #"^[A-Z0-9]{10}$"#, options: .regularExpression) != nil {
            requirement = "anchor apple generic and identifier \"dev.zion.client\" and certificate leaf[subject.OU] = \"\(team)\""
        } else { requirement = nil }
        super.init()
    }

    /// Bind code-signature validation before exposing the read-only status object to a connection.
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        guard let requirement else { return false }
        connection.setCodeSigningRequirement(requirement)
        connection.exportedInterface = NSXPCInterface(with: HelperStatusProtocol.self)
        connection.exportedObject = HelperStatus()
        connection.resume()
        return true
    }
}

/// Launchd starts this on-demand helper after the app registration receives administrator approval.
@main struct HelperMain {
    static func main() {
        let delegate = HelperListener()
        let listener = NSXPCListener(machServiceName: HelperComponent.label)
        listener.delegate = delegate
        listener.resume()
        withExtendedLifetime(delegate) { dispatchMain() }
    }
}
