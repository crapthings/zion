import Foundation

/// A transient envelope embeds credential bytes so an extension never depends on arbitrary host file access.
public struct PacketConfiguration: Encodable, Sendable {
    let client: CoreConfiguration
    let caPem: String?
    let certPem: String?
    let keyPem: String?
    let mtu: Int

    /// Wire fields are private to the native bridge and do not alter the minimal CLI configuration schema.
    enum CodingKeys: String, CodingKey {
        case client, mtu
        case caPem = "ca_pem", certPem = "cert_pem", keyPem = "key_pem"
    }

    /// Read bounded credentials into an in-memory envelope that must never be persisted or logged.
    public init(client: CoreConfiguration, mtu: Int = 1500) throws {
        guard (1280...9000).contains(mtu) else { throw ControlError("虚拟网卡 MTU 无效。") }
        self.client = client; self.mtu = mtu
        caPem = try Self.read(client.ca)
        certPem = try Self.read(client.cert)
        keyPem = try Self.read(client.key)
    }

    /// Encode transient credentials within the Rust bridge's fixed input limit.
    public func encoded() throws -> Data {
        let data = try JSONEncoder().encode(self)
        guard data.count <= 256 * 1024 else { throw ControlError("虚拟网卡配置超过限制。") }
        return data
    }

    /// Read one UTF-8 PEM file with a hard limit before allocating its complete contents.
    private static func read(_ path: String?) throws -> String? {
        guard let path else { return nil }
        let handle = try FileHandle(forReadingFrom: URL(fileURLWithPath: path))
        defer { try? handle.close() }
        let data = try handle.read(upToCount: 64 * 1024 + 1) ?? Data()
        guard data.count <= 64 * 1024, let text = String(data: data, encoding: .utf8) else {
            throw ControlError("证书或私钥文件格式无效或超过大小限制。")
        }
        return text
    }
}
