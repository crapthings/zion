import Foundation
import Testing
@testable import ZionControl

/// A fake reader supplies network observations without accessing actual interfaces or proxy settings.
@MainActor final class SetupReaderFixture: SetupNetworkReading {
    var reads = 0
    var fail = false
    var snapshot = SetupNetworkSnapshot(proxies: [.socks], virtualInterfaces: ["utun2"])
    func read() throws -> SetupNetworkSnapshot {
        reads += 1
        if fail { throw ControlError("unavailable") }
        return snapshot
    }
}

/// Setup tests cover presentation, persistence, read-only detection, and ambiguous network ownership.
@Suite @MainActor struct SetupGuideTests {
    /// A skipped first launch is remembered without reading or configuring the network.
    @Test func firstLaunchCanBeSkippedWithoutNetworkAccess() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let reader = SetupReaderFixture()
        let guide = SetupGuide(directory: directory, reader: reader)
        #expect(guide.isPresented && !guide.showOnLaunch)
        #expect(reader.reads == 0)
        guide.finish()
        #expect(!guide.isPresented && reader.reads == 0)
        let restored = SetupGuide(directory: directory, reader: reader)
        #expect(!restored.isPresented)
        let attributes = try FileManager.default.attributesOfItem(atPath: directory.appendingPathComponent("setup.json").path)
        #expect((attributes[.posixPermissions] as? NSNumber)?.intValue == 0o600)
        restored.open()
        #expect(restored.isPresented && reader.reads == 0)
    }

    /// Choosing every-launch presentation survives completion and can later be turned off.
    @Test func launchPreferenceIsExplicit() {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let guide = SetupGuide(directory: directory, reader: SetupReaderFixture())
        guide.showOnLaunch = true; guide.finish()
        let restored = SetupGuide(directory: directory, reader: SetupReaderFixture())
        #expect(restored.isPresented && restored.showOnLaunch)
        restored.showOnLaunch = false; restored.finish()
        #expect(!SetupGuide(directory: directory, reader: SetupReaderFixture()).isPresented)
    }

    /// Refresh exposes observed state and reports detection failure without claiming that proxies are off.
    @Test func detectionFailureIsNotAnInactiveState() {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let reader = SetupReaderFixture(); let guide = SetupGuide(directory: directory, reader: reader)
        guide.refresh()
        #expect(guide.snapshot?.proxies == [.socks])
        #expect(guide.snapshot?.virtualInterfaces == ["utun2"])
        reader.fail = true; guide.refresh()
        #expect(guide.snapshot == nil && guide.detectionError != nil)
        reader.fail = false; guide.refresh()
        #expect(guide.snapshot != nil && guide.detectionError == nil && reader.reads == 3)
    }

    /// Corrupt preferences remain intact while the user can still dismiss the guide.
    @Test func corruptPreferencesDoNotTrapOrOverwrite() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let file = directory.appendingPathComponent("setup.json")
        let original = Data("invalid".utf8); try original.write(to: file)
        let guide = SetupGuide(directory: directory, reader: SetupReaderFixture())
        #expect(guide.isPresented && guide.preferenceError != nil)
        guide.finish()
        let retained = try Data(contentsOf: file)
        #expect(!guide.isPresented && retained == original)
    }

    /// A secondary or storage-blocked app can skip without persisting preferences behind the owner.
    @Test func dismissalCanAvoidPersistence() {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let guide = SetupGuide(directory: directory, reader: SetupReaderFixture())
        guide.finish(persist: false)
        #expect(!guide.isPresented && !FileManager.default.fileExists(atPath: directory.path))
    }

    /// Global and scoped proxy flags are combined without reading credentials or counting disabled entries.
    @Test func proxyFlagsIncludeScopedMechanisms() {
        let values: [String: Any] = ["HTTPEnable": 0, "SOCKSEnable": true,
            "__SCOPED__": ["en0": ["HTTPSEnable": 1], "utun2": ["ProxyAutoConfigEnable": 1, "HTTPEnable": 0]]]
        #expect(SystemProxyKind.enabled(in: values) == [.https, .socks, .pac])
        #expect(SystemProxyKind.enabled(in: ["SOCKSEnable": 0]).isEmpty)
    }
}
