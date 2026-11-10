import Foundation
import Security

/// Secret storage keeps profile passwords separate from ordinary configuration metadata.
@MainActor public protocol SecretStore: AnyObject {
    func password(for id: UUID) throws -> String?
    func save(_ password: String, for id: UUID) throws
    func delete(for id: UUID) throws
}

/// Keychain storage associates one password with each stable profile identifier.
@MainActor public final class KeychainStore: SecretStore {
    private let service: String

    public init(service: String = "dev.zion.client.password") { self.service = service }

    /// Read a password only when preparing a connection or editing its profile.
    public func password(for id: UUID) throws -> String? {
        var query = query(for: id)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        try check(status)
        guard let data = result as? Data, let value = String(data: data, encoding: .utf8) else {
            throw ControlError("无法读取这个服务器的钥匙串密码。")
        }
        return value
    }

    /// Update or create a password without including it in process arguments or log messages.
    public func save(_ password: String, for id: UUID) throws {
        let values = [kSecValueData as String: Data(password.utf8)]
        let status = SecItemUpdate(query(for: id) as CFDictionary, values as CFDictionary)
        if status == errSecItemNotFound {
            var entry = query(for: id)
            entry.merge(values) { _, new in new }
            entry[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            try check(SecItemAdd(entry as CFDictionary, nil))
        } else { try check(status) }
    }

    /// Delete a removed profile's password while tolerating an already absent item.
    public func delete(for id: UUID) throws {
        let status = SecItemDelete(query(for: id) as CFDictionary)
        if status != errSecItemNotFound { try check(status) }
    }

    /// Scope every Keychain operation to this app service and one profile account.
    private func query(for id: UUID) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: id.uuidString]
    }

    /// Report an operating-system status without exposing stored secret data.
    private func check(_ status: OSStatus) throws {
        guard status == errSecSuccess else { throw ControlError("钥匙串操作失败（\(status)）。") }
    }
}
