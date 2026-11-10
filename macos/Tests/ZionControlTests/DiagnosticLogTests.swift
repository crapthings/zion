import Foundation
import Testing
@testable import ZionControl

/// Log tests verify privacy, bounded storage, and severity without touching platform settings.
@Suite @MainActor struct DiagnosticLogTests {
    /// Known passwords and named secret fields are removed before text is delivered to consumers.
    @Test func sanitizerRemovesSecretsAndTerminalEscapes() {
        var sanitizer = DiagnosticSanitizer(password: "private-value")
        let text = sanitizer.clean("\u{1B}[31mERROR private-value password=hidden token=other\u{1B}[0m")
        #expect(text.contains("ERROR"))
        #expect(!text.contains("private-value") && !text.contains("hidden") && !text.contains("other") && !text.contains("\u{1B}"))
        #expect(sanitizer.clean(#"{"password":"escaped\"value"}"#) == #"{"password":[redacted]}"#)
    }

    /// Multiline private-key bodies never enter the retained log, including after clearing its display.
    @Test func privateKeyBlockIsSuppressedAcrossClear() {
        let log = DiagnosticLog()
        log.append("-----BEGIN PRIVATE KEY-----")
        log.clear()
        log.append("secret-key-body\n-----END PRIVATE KEY-----\nINFO recovered")
        #expect(log.entries.count == 1)
        #expect(log.entries[0].message == "INFO recovered")
    }

    /// Excess rows and oversized UTF-8 lines cannot grow session storage without bound.
    @Test func capacityAndLineLengthAreBounded() {
        let log = DiagnosticLog()
        for index in 0..<600 { log.append("INFO event \(index)") }
        #expect(log.entries.count == 500)
        #expect(log.entries.first?.message == "INFO event 100")
        log.append(String(repeating: "界", count: 5000))
        #expect(log.entries.last!.message.utf8.count <= 1030)
        #expect(log.entries.count == 500)
    }

    /// Severity labels and copied text retain real messages with timestamps.
    @Test func severityAndCopyReflectStoredEvents() {
        let log = DiagnosticLog()
        log.append("ERROR failed\nWARN retry\nDEBUG details\nconnected")
        #expect(log.entries.map(\.level) == [.error, .warning, .debug, .info])
        #expect(log.text().contains("[error] ERROR failed"))
        log.clear()
        #expect(log.text().isEmpty)
    }
}
