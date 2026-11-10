import Foundation
import Observation

/// Log levels classify actual core events and application lifecycle messages.
public enum DiagnosticLevel: String, Codable, CaseIterable, Sendable {
    case debug, info, warning, error
}

/// A diagnostic entry stores one bounded line with its arrival time and severity.
public struct DiagnosticEntry: Identifiable, Codable, Sendable {
    public let id: UUID
    public let date: Date
    public let level: DiagnosticLevel
    public let message: String

    /// Create a timestamped event after its text has passed through the log sanitizer.
    public init(date: Date = Date(), level: DiagnosticLevel, message: String) {
        self.id = UUID(); self.date = date; self.level = level; self.message = message
    }
}

/// A sanitizer removes terminal escapes, known passwords, and private-key blocks before storage.
public struct DiagnosticSanitizer {
    private let password: String?
    private var insideKey = false

    /// Capture only the current connection's password for exact-value redaction.
    public init(password: String? = nil) { self.password = password?.nilIfEmpty }

    /// Clean one diagnostic line while suppressing multiline PEM private-key material.
    public mutating func clean(_ line: String) -> String {
        let text = line.replacingOccurrences(of: "\u{1B}\\[[0-?]*[ -/]*[@-~]", with: "", options: .regularExpression)
        if text.contains("-----BEGIN ") && text.contains("PRIVATE KEY-----") {
            insideKey = !text.contains("-----END ")
            return "[private key redacted]"
        }
        if insideKey {
            if text.contains("-----END ") && text.contains("PRIVATE KEY-----") { insideKey = false }
            return ""
        }
        var result = text
        if let password { result = result.replacingOccurrences(of: password, with: "[redacted]") }
        result = result.replacingOccurrences(of: #"(?i)("?(?:password|token|secret)"?\s*[:=]\s*)("(?:[^"\\]|\\.)*"|[^\s,}]+)"#, with: "$1[redacted]", options: .regularExpression)
        return result
    }
}

/// A session log bounds retained events and exposes the same sanitized entries to UI and CLI.
@Observable @MainActor public final class DiagnosticLog {
    public private(set) var entries: [DiagnosticEntry] = []
    private var sanitizer = DiagnosticSanitizer()

    /// Start with an empty in-memory session log.
    public init() {}

    /// Store up to 500 lines, each limited to roughly one KiB of UTF-8 text.
    public func append(_ message: String, level: DiagnosticLevel? = nil) {
        for line in message.split(separator: "\n", omittingEmptySubsequences: false).prefix(501) {
            let text = sanitizer.clean(String(line))
            guard !text.isEmpty else { continue }
            let bounded = text.utf8.count > 1024 ? String(decoding: text.utf8.prefix(1024), as: UTF8.self) + "…" : text
            entries.append(DiagnosticEntry(level: level ?? severity(text), message: bounded))
        }
        if entries.count > 500 { entries.removeFirst(entries.count - 500) }
    }

    /// Clear retained events without altering connection state or the active sanitizer.
    public func clear() { entries.removeAll() }

    /// Format retained entries consistently for copyable diagnostic reports.
    public func text() -> String {
        entries.map { "\($0.date.ISO8601Format()) [\($0.level.rawValue)] \($0.message)" }.joined(separator: "\n")
    }

    /// Recognize tracing severity tokens without guessing severity from localized message wording.
    private func severity(_ text: String) -> DiagnosticLevel {
        if text.range(of: #"\bERROR\b"#, options: .regularExpression) != nil { return .error }
        if text.range(of: #"\bWARN(?:ING)?\b"#, options: .regularExpression) != nil { return .warning }
        if text.range(of: #"\b(?:DEBUG|TRACE)\b"#, options: .regularExpression) != nil { return .debug }
        return .info
    }
}
