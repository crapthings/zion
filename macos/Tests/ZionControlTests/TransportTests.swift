import Foundation
import Testing
@testable import ZionControl

/// Carrier tests require the current stored schema and preserve the exact core wire value.
@Suite @MainActor struct TransportTests {
    /// Current profiles round-trip while incomplete or invalid stored carriers fail explicitly.
    @Test func profileRequiresExplicitStoredTransport() throws {
        let profile = ServerProfile()
        let data = try JSONEncoder().encode(profile)
        #expect(try JSONDecoder().decode(ServerProfile.self, from: data) == profile)
        var value = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        value.removeValue(forKey: "transport")
        #expect(throws: (any Error).self) {
            try JSONDecoder().decode(ServerProfile.self, from: JSONSerialization.data(withJSONObject: value))
        }
        for invalid in ["unknown" as Any, NSNull()] {
            value["transport"] = invalid
            #expect(throws: (any Error).self) {
                try JSONDecoder().decode(ServerProfile.self, from: JSONSerialization.data(withJSONObject: value))
            }
        }
    }

    /// Explicit TCP selection survives both stdin JSON and the native in-memory credential envelope.
    @Test func tlsSelectionReachesBothCoreEntryPoints() throws {
        var profile = ServerProfile(); profile.name = "TLS"; profile.server = "passage.example.com:8443"; profile.transport = .tls
        let config = try profile.configuration(password:"secret")
        let wire = try JSONSerialization.jsonObject(with:JSONEncoder().encode(config)) as! [String:Any]
        #expect(wire["transport"] as? String == "tls")
        let packet = try JSONSerialization.jsonObject(with:PacketConfiguration(client:config).encoded()) as! [String:Any]
        #expect((packet["client"] as? [String:Any])?["transport"] as? String == "tls")
    }

    /// Network aliases decode explicitly while stored values use stable protocol names.
    @Test func aliasesAreCanonicalized() throws {
        for (input, expected) in [("tcp",TunnelTransport.tls),("tls",.tls),("udp",.quic),("quic",.quic)] {
            let value = try JSONDecoder().decode(TunnelTransport.self,from:JSONEncoder().encode(input))
            #expect(value == expected)
            #expect(try JSONDecoder().decode(String.self,from:JSONEncoder().encode(value)) == expected.rawValue)
        }
    }
}
