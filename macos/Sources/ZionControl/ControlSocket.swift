import Darwin
import Foundation

/// A versioned request names one app operation and its bounded JSON arguments.
public struct AppControlRequest: Codable, Sendable {
    public var version: Int
    public var command: String
    public var arguments: [String: String]
}

/// A local socket serves same-user clients while the app remains the sole settings owner.
@MainActor public final class ControlSocket {
    private var listener: Int32 = -1
    private var lock: Int32 = -1
    private var source: DispatchSourceRead?
    private var clients = 0
    private let path: String
    private let handler: @MainActor (AppControlRequest) async -> Data

    /// Scope the endpoint to the current user and inject the app's command dispatcher.
    public init(path: String = "/tmp/zion-\(getuid())/control.sock", handler: @escaping @MainActor (AppControlRequest) async -> Data) {
        self.path = path; self.handler = handler
    }

    /// Bind a private socket after taking an exclusive app-instance lock.
    public func start() throws {
        guard listener == -1 else { return }
        let directory = (path as NSString).deletingLastPathComponent
        if mkdir(directory, 0o700) != 0 && errno != EEXIST { throw ControlError("Cannot create control directory.") }
        var info = stat()
        guard lstat(directory, &info) == 0, info.st_uid == getuid(),
              (info.st_mode & S_IFMT) == S_IFDIR, info.st_mode & 0o077 == 0 else {
            throw ControlError("Control directory must be private and owned by this user.")
        }
        let owner = open(directory + "/control.lock", O_CREAT | O_RDWR | O_NOFOLLOW, 0o600)
        guard owner >= 0 else { throw ControlError("Cannot open app control lock.") }
        guard flock(owner, LOCK_EX | LOCK_NB) == 0 else { close(owner); throw ControlError("Another Zion app owns the control socket.") }
        lock = owner
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { stop(); throw ControlError("Cannot create control socket.") }
        listener = fd
        do {
            var address = try controlAddress(path)
            unlink(path)
            let result = withUnsafePointer(to: &address) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
            }
            guard result == 0, chmod(path, 0o600) == 0, listen(fd, 8) == 0,
                  fcntl(fd, F_SETFL, O_NONBLOCK) == 0 else { throw ControlError("Cannot bind app control socket.") }
            let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: .main)
            source.setEventHandler { [weak self] in self?.acceptClient() }
            self.source = source; source.resume()
        } catch { stop(); throw error }
    }

    /// Close the listener and remove only the endpoint protected by this instance's lock.
    public func stop() {
        source?.cancel(); source = nil
        if listener >= 0 { close(listener); listener = -1 }
        if lock >= 0 { unlink(path); flock(lock, LOCK_UN); close(lock); lock = -1 }
    }

    /// Bound concurrent clients and verify the peer UID before reading any request.
    private func acceptClient() {
        let fd = accept(listener, nil, nil)
        guard fd >= 0 else { return }
        var uid: uid_t = 0; var gid: gid_t = 0
        guard clients < 8, fcntl(fd, F_SETFL, 0) == 0, getpeereid(fd, &uid, &gid) == 0, uid == getuid() else { close(fd); return }
        clients += 1
        Task { [self] in
            let request = await Task.detached { readControlRequest(fd) }.value
            let response: Data
            if let request { response = await handler(request) }
            else { response = controlFailure("invalid_request", "Expected one JSON request of at most 64 KiB.") }
            await Task.detached { writeControlResponse(fd, response) }.value
            clients -= 1
        }
    }
}

/// Encode a fixed error envelope without reflecting request contents or credentials.
public func controlFailure(_ code: String, _ message: String) -> Data {
    (try? JSONSerialization.data(withJSONObject: ["version": 1, "ok": false, "error": ["code": code, "message": message]], options: [.sortedKeys])) ?? Data()
}

/// Construct a bounded Unix-domain address without truncating its filesystem path.
private func controlAddress(_ path: String) throws -> sockaddr_un {
    var address = sockaddr_un()
    address.sun_family = sa_family_t(AF_UNIX)
    address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
    let bytes = Array(path.utf8) + [0]
    guard bytes.count <= MemoryLayout.size(ofValue: address.sun_path) else { throw ControlError("Control socket path is too long.") }
    withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: bytes) }
    return address
}

/// Read one bounded JSON line on a worker thread with a fixed total deadline.
private func readControlRequest(_ fd: Int32) -> AppControlRequest? {
    var timeout = timeval(tv_sec: 1, tv_usec: 0)
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
    var data = Data(); var buffer = [UInt8](repeating: 0, count: 4096)
    let deadline = Date().addingTimeInterval(5)
    while data.count <= 64 * 1024 && Date() < deadline {
        let count = read(fd, &buffer, min(buffer.count, 64 * 1024 + 1 - data.count))
        if count <= 0 { return nil }
        data.append(contentsOf: buffer.prefix(count))
        if let end = data.firstIndex(of: 10) {
            guard end == data.count - 1 else { return nil }
            return try? JSONDecoder().decode(AppControlRequest.self, from: data.prefix(upTo: end))
        }
    }
    return nil
}

/// Send a bounded response without SIGPIPE and close the client on every exit path.
private func writeControlResponse(_ fd: Int32, _ response: Data) {
    defer { close(fd) }
    var flag: Int32 = 1
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &flag, socklen_t(MemoryLayout<Int32>.size))
    var timeout = timeval(tv_sec: 2, tv_usec: 0)
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
    let bounded = response.count <= 256 * 1024 ? response : controlFailure("response_too_large", "Control response exceeds 256 KiB.")
    let data = bounded + Data([10])
    data.withUnsafeBytes { bytes in
        var offset = 0
        while offset < bytes.count {
            let count = write(fd, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
            if count <= 0 { break }
            offset += count
        }
    }
}
