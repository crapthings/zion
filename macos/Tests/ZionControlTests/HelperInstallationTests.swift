import Foundation
import Testing
@testable import ZionControl

/// A fake registration service simulates OS approval without installing any launchd job.
@MainActor final class RegistrationFixture: HelperRegistrationServing {
    var status = HelperRegistration.notRegistered
    var registers = 0
    var unregisters = 0
    var openedSettings = 0
    var reject = false
    var suspendRemoval = false
    var removal: CheckedContinuation<Void, Never>?
    func register() throws {
        registers += 1
        if reject { throw NSError(domain: "SMAppServiceErrorDomain", code: 1) }
        status = .requiresApproval
    }
    func unregister() async throws {
        unregisters += 1
        if suspendRemoval { await withCheckedContinuation { removal = $0 } }
        if reject { throw NSError(domain: "SMAppServiceErrorDomain", code: 2) }
        status = .notRegistered
    }
    func openApprovalSettings() { openedSettings += 1 }
}

/// Installation tests keep component registration separate from actual network takeover.
@Suite @MainActor struct HelperInstallationTests {
    /// Registering a bundled helper preserves pending approval rather than claiming it is enabled.
    @Test func registrationWaitsForApproval() {
        let service = RegistrationFixture()
        let installation = HelperInstallation(service: service, bundled: true)
        #expect(service.registers == 0)
        installation.install()
        #expect(service.registers == 1 && installation.status == .requiresApproval)
        #expect(!installation.canInstall && installation.canUninstall)
        #expect(service.openedSettings == 0)
        installation.openApprovalSettings()
        #expect(service.openedSettings == 1)
        service.status = .enabled
        installation.refresh()
        #expect(installation.status == .enabled)
    }

    /// Missing payloads never issue installation requests to the operating system.
    @Test func missingBundleCannotInstall() {
        let service = RegistrationFixture()
        let installation = HelperInstallation(service: service, bundled: false)
        installation.install()
        #expect(!installation.canInstall && service.registers == 0)
    }

    /// Registration errors preserve the real state and produce useful domain/code diagnostics.
    @Test func failureDoesNotClaimInstallation() {
        let service = RegistrationFixture(); service.reject = true
        let installation = HelperInstallation(service: service, bundled: true)
        installation.install()
        #expect(installation.status == .notRegistered && !installation.busy)
        #expect(installation.lastError?.contains("SMAppServiceErrorDomain") == true)
    }

    /// Removal is serialized and rejects overlapping registration or duplicate removal requests.
    @Test func pendingRemovalBlocksOtherOperations() async {
        let service = RegistrationFixture(); service.status = .requiresApproval; service.suspendRemoval = true
        let installation = HelperInstallation(service: service, bundled: true)
        let task = Task { await installation.uninstall() }
        while service.removal == nil { await Task.yield() }
        #expect(installation.busy && !installation.canInstall && !installation.canUninstall)
        installation.install()
        await installation.uninstall()
        #expect(service.registers == 0 && service.unregisters == 1)
        service.removal?.resume(); service.removal = nil
        await task.value
        #expect(installation.status == .notRegistered && !installation.busy)
    }

    /// Failed removal retains an approved registration so the user can retry safely.
    @Test func failedRemovalRetainsState() async {
        let service = RegistrationFixture(); service.status = .enabled; service.reject = true
        let installation = HelperInstallation(service: service, bundled: true)
        await installation.uninstall()
        #expect(installation.status == .enabled && installation.canUninstall)
        #expect(installation.lastError != nil)
    }
}
