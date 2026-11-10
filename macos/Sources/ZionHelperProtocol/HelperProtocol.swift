import Foundation

/// Helper identity constants keep packaging, registration, and IPC names aligned.
public enum HelperComponent {
    public static let label = "dev.zion.helper"
    public static let plist = "dev.zion.helper.plist"
    public static let program = "Contents/Library/HelperTools/zion-helper"
}

/// The initial helper exposes read-only capabilities and no privileged network operations.
@objc public protocol HelperStatusProtocol {
    func status(reply: @escaping (String) -> Void)
}
