import Foundation

/// A profile document stores selection and server metadata without authentication secrets.
public struct ProfileDocument: Codable, Equatable, Sendable {
    public var profiles: [ServerProfile] = []
    public var selectedID: UUID?
    public init() {}
}

/// The profile store atomically persists metadata in a private application support directory.
@MainActor public final class ProfileStore {
    public let directory: URL
    public let file: URL

    /// Use an injectable directory so tests never modify real application preferences.
    public init(directory: URL? = nil) {
        self.directory = directory ?? FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].appendingPathComponent("Zion", isDirectory: true)
        file = self.directory.appendingPathComponent("profiles.json")
    }

    /// Read existing profiles while preserving malformed files for explicit user recovery.
    public func load() throws -> ProfileDocument {
        guard FileManager.default.fileExists(atPath: file.path) else { return ProfileDocument() }
        return try JSONDecoder().decode(ProfileDocument.self, from: Data(contentsOf: file))
    }

    /// Write metadata atomically without serializing any Keychain password.
    public func save(_ document: ProfileDocument) throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try encoder.encode(document).write(to: file, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
    }
}
