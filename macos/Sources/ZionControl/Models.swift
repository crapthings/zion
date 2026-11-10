import Foundation

/// Authentication determines whether the profile reads a password or client certificate pair.
public enum Authentication: String, Codable, CaseIterable, Sendable {
    case password, certificate
}

/// A tunnel carrier chooses UDP/QUIC or TCP/TLS independently of the destination protocol.
public enum TunnelTransport: String, Codable, CaseIterable, Sendable {
    case quic, tls
    public var title: String { self == .quic ? "UDP · QUIC" : "TCP · TLS" }

    /// Accept protocol names and their network aliases while rejecting unknown carriers.
    public init(from decoder: Decoder) throws {
        let value = try decoder.singleValueContainer()
        switch try value.decode(String.self) {
        case "quic", "udp": self = .quic
        case "tls", "tcp": self = .tls
        default: throw DecodingError.dataCorruptedError(in: value, debugDescription: "Unknown tunnel transport")
        }
    }
}

/// A saved profile contains connection metadata while its password stays in Keychain.
public struct ServerProfile: Identifiable, Codable, Equatable, Sendable {
    public var id = UUID()
    public var name = "新服务器"
    public var server = ""
    public var transport = TunnelTransport.quic
    public var authentication = Authentication.password
    public var ca = ""
    public var certificate = ""
    public var privateKey = ""
    public var serverName = ""
    public var interface = ""

    /// Create an empty profile for a user-supplied server.
    public init() {}

    /// Stored fields retain their existing names while older profiles default to the QUIC carrier.
    private enum CodingKeys: String, CodingKey {
        case id, name, server, transport, authentication, ca, certificate, privateKey, serverName, interface
    }

    /// Decode older profiles without inventing a transport for an unrecognized explicit value.
    public init(from decoder: Decoder) throws {
        self.init()
        let values = try decoder.container(keyedBy: CodingKeys.self)
        id = try values.decode(UUID.self, forKey: .id)
        name = try values.decode(String.self, forKey: .name)
        server = try values.decode(String.self, forKey: .server)
        transport = values.contains(.transport) ? try values.decode(TunnelTransport.self, forKey: .transport) : .quic
        authentication = try values.decode(Authentication.self, forKey: .authentication)
        ca = try values.decode(String.self, forKey: .ca)
        certificate = try values.decode(String.self, forKey: .certificate)
        privateKey = try values.decode(String.self, forKey: .privateKey)
        serverName = try values.decode(String.self, forKey: .serverName)
        interface = try values.decode(String.self, forKey: .interface)
    }

    /// Validate editable fields without weakening TLS authentication.
    public func validate() throws {
        guard !name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              let url = URLComponents(string: "quic://\(server)"),
              url.host?.isEmpty == false, let port = url.port, (1...65535).contains(port),
              url.user == nil, url.password == nil, url.path.isEmpty,
              url.query == nil, url.fragment == nil else {
            throw ControlError("请输入名称和有效的服务器地址，例如 example.com:38443。")
        }
        guard certificate.isEmpty == privateKey.isEmpty else {
            throw ControlError("客户端证书与私钥需要一起选择。")
        }
        if authentication == .certificate && certificate.isEmpty {
            throw ControlError("请选择客户端证书和私钥。")
        }
    }

    /// Build the in-memory core configuration without persisting a password in the profile.
    public func configuration(password: String?) throws -> CoreConfiguration {
        try validate()
        if authentication == .password && (password?.isEmpty ?? true) {
            throw ControlError("请为这个服务器设置密码。")
        }
        return CoreConfiguration(
            server: server, transport: transport, password: authentication == .password ? password : nil,
            ca: ca.nilIfEmpty, cert: certificate.nilIfEmpty, key: privateKey.nilIfEmpty,
            serverName: serverName.nilIfEmpty, interface: interface.nilIfEmpty
        )
    }
}

/// The core receives credentials through stdin and chooses an unused loopback listener port.
public struct CoreConfiguration: Encodable, Sendable {
    public var server: String
    public var transport = TunnelTransport.quic
    public var password: String?
    public var ca: String?
    public var cert: String?
    public var key: String?
    public var serverName: String?
    public var interface: String?
    public var listen = "127.0.0.1:0"

    /// Wire keys match the existing flat Rust JSON schema.
    enum CodingKeys: String, CodingKey {
        case server, transport, password, ca, cert, key, interface, listen
        case serverName = "server_name"
    }
}

/// A validated endpoint identifies only the local SOCKS5 listener controlled by this app.
public struct ProxyEndpoint: Equatable, Sendable {
    public let host: String
    public let port: Int

    /// Reject non-loopback readiness messages before changing any system proxy settings.
    public init(listen: String) throws {
        guard let url = URLComponents(string: "socks5://\(listen)"),
              let host = url.host, ["127.0.0.1", "::1", "[::1]"].contains(host),
              let port = url.port, (1...65535).contains(port),
              url.user == nil, url.password == nil, url.path.isEmpty,
              url.query == nil, url.fragment == nil else {
            throw ControlError("核心返回了无效的本地代理地址。")
        }
        self.host = host.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        self.port = port
    }

    /// Display the actual loopback endpoint without exposing credentials.
    public var description: String { host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)" }
}

/// A control error carries a user-facing explanation without including secret configuration.
public struct ControlError: LocalizedError, Sendable {
    public let message: String
    public init(_ message: String) { self.message = message }
    public var errorDescription: String? { message }
}

/// String helpers omit unset optional fields from the core configuration.
extension String {
    public var nilIfEmpty: String? { isEmpty ? nil : self }
}
