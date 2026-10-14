import Darwin
import Foundation

/// Internal execution mechanics for the existing typed callers, not a command admission API.
/// Callers remain responsible for fixed executable/argument/environment policy. This owns
/// the spawned process group; it cannot confer custody of a deliberately detached daemon.
public struct BoundedProcessLimits: Sendable {
    public let timeout: TimeInterval
    public let terminationGrace: TimeInterval
    public let cleanupGrace: TimeInterval
    public let pipeGrace: TimeInterval
    public let maximumOutputBytes: Int

    public init(timeout: TimeInterval = 300, terminationGrace: TimeInterval = 0.5,
                cleanupGrace: TimeInterval = 1, pipeGrace: TimeInterval = 0.1,
                maximumOutputBytes: Int = 1_048_576) {
        self.timeout = timeout
        self.terminationGrace = terminationGrace
        self.cleanupGrace = cleanupGrace
        self.pipeGrace = pipeGrace
        self.maximumOutputBytes = maximumOutputBytes
    }
}

public enum BoundedProcessOutcome: String, Sendable {
    case exited, timedOut, outputLimit, descendantPipeHold, unknown
}

public struct BoundedProcessResult: Sendable {
    public let status: Int32
    public let stdout: String
    public let stderr: String
    public let outcome: BoundedProcessOutcome
    /// True only after waitpid reaped the direct child, both pipes reached EOF,
    /// and the owned process group was observed absent. Timeout is never success.
    public let settled: Bool
}

public enum BoundedProcessFailure: Error, CustomStringConvertible {
    case rejected(String)
    public var description: String {
        switch self { case .rejected(let reason): return reason }
    }
}

public enum BoundedProcess {
    public static func run(executable: String, arguments: [String],
                           environment: [String: String],
                           limits: BoundedProcessLimits = .init()) throws -> BoundedProcessResult {
        let intervals = [limits.timeout, limits.terminationGrace, limits.cleanupGrace, limits.pipeGrace]
        guard intervals.allSatisfy({ $0.isFinite && $0 > 0 && $0 <= 86_400 }),
              limits.maximumOutputBytes > 0, limits.maximumOutputBytes <= 16 * 1_048_576,
              executable.hasPrefix("/"), !executable.utf8.contains(0),
              arguments.allSatisfy({ !$0.utf8.contains(0) }),
              environment.allSatisfy({ !$0.key.isEmpty && !$0.key.contains("=") &&
                  !$0.key.utf8.contains(0) && !$0.value.utf8.contains(0) }) else {
            throw BoundedProcessFailure.rejected("bounded_process_invalid_input")
        }

        // No Foundation Pipe/FileHandle blocking reads or asynchronous readers survive return.
        var outputPipe: [Int32] = [-1, -1]
        var errorPipe: [Int32] = [-1, -1]
        var nullFD: Int32 = -1
        defer {
            for fd in outputPipe + errorPipe + [nullFD] where fd >= 0 { _ = Darwin.close(fd) }
        }
        guard pipe(&outputPipe) == 0, pipe(&errorPipe) == 0 else {
            throw BoundedProcessFailure.rejected("bounded_process_pipe_setup")
        }
        // A caller may arrive with a closed standard descriptor. Keep all
        // private descriptors above stderr so the ordered dup2 actions cannot
        // clobber the other pipe or the null input.
        func aboveStandardDescriptors(_ fd: Int32) throws -> Int32 {
            guard fd <= STDERR_FILENO else { return fd }
            let moved = fcntl(fd, F_DUPFD_CLOEXEC, 3)
            guard moved >= 0 else {
                throw BoundedProcessFailure.rejected("bounded_process_descriptor_setup")
            }
            _ = Darwin.close(fd)
            return moved
        }
        for index in outputPipe.indices { outputPipe[index] = try aboveStandardDescriptors(outputPipe[index]) }
        for index in errorPipe.indices { errorPipe[index] = try aboveStandardDescriptors(errorPipe[index]) }
        nullFD = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC)
        guard nullFD >= 0 else { throw BoundedProcessFailure.rejected("bounded_process_stdin_setup") }
        nullFD = try aboveStandardDescriptors(nullFD)
        for fd in outputPipe + errorPipe {
            guard fcntl(fd, F_SETFD, FD_CLOEXEC) == 0 else {
                throw BoundedProcessFailure.rejected("bounded_process_descriptor_setup")
            }
        }
        for fd in [outputPipe[0], errorPipe[0]] {
            guard fcntl(fd, F_SETFL, O_NONBLOCK) == 0 else {
                throw BoundedProcessFailure.rejected("bounded_process_nonblocking_setup")
            }
        }

        var actions: posix_spawn_file_actions_t?
        var attributes: posix_spawnattr_t?
        guard posix_spawn_file_actions_init(&actions) == 0 else {
            throw BoundedProcessFailure.rejected("bounded_process_actions_setup")
        }
        defer { posix_spawn_file_actions_destroy(&actions) }
        guard posix_spawnattr_init(&attributes) == 0 else {
            throw BoundedProcessFailure.rejected("bounded_process_attributes_setup")
        }
        defer { posix_spawnattr_destroy(&attributes) }
        // The child is group leader at spawn, eliminating a racy parent-side setpgid.
        let flags = Int16(POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_CLOEXEC_DEFAULT)
        guard posix_spawnattr_setflags(&attributes, flags) == 0,
              posix_spawnattr_setpgroup(&attributes, 0) == 0,
              posix_spawn_file_actions_adddup2(&actions, nullFD, STDIN_FILENO) == 0,
              posix_spawn_file_actions_adddup2(&actions, outputPipe[1], STDOUT_FILENO) == 0,
              posix_spawn_file_actions_adddup2(&actions, errorPipe[1], STDERR_FILENO) == 0 else {
            throw BoundedProcessFailure.rejected("bounded_process_spawn_setup")
        }
        let argv = ([executable] + arguments).map { strdup($0) } + [nil]
        let envp = environment.keys.sorted().map { strdup("\($0)=\(environment[$0]!)") } + [nil]
        defer { for pointer in argv + envp { free(pointer) } }
        guard argv.dropLast().allSatisfy({ $0 != nil }), envp.dropLast().allSatisfy({ $0 != nil }) else {
            throw BoundedProcessFailure.rejected("bounded_process_allocation")
        }
        var child: pid_t = 0
        let spawnStatus = argv.withUnsafeBufferPointer { av in
            envp.withUnsafeBufferPointer { ev in
                posix_spawn(&child, executable, &actions, &attributes, av.baseAddress!, ev.baseAddress!)
            }
        }
        guard spawnStatus == 0 else { throw BoundedProcessFailure.rejected("bounded_process_spawn_failed") }
        _ = Darwin.close(outputPipe[1]); outputPipe[1] = -1
        _ = Darwin.close(errorPipe[1]); errorPipe[1] = -1

        func now() -> Double { Double(DispatchTime.now().uptimeNanoseconds) / 1_000_000_000 }
        let deadline = now() + limits.timeout
        var stdout = Data(), stderr = Data()
        var stdoutEOF = false, stderrEOF = false
        var reaped = false, waitStatus: Int32 = 0
        var reason: BoundedProcessOutcome?
        var exitObservedAt: Double?
        var terminateAt: Double?
        var killAt: Double?
        var uncertain = false
        var settled = false
        var buffer = [UInt8](repeating: 0, count: 8192)

        func groupAbsent() -> Bool {
            if Darwin.kill(-child, 0) == 0 { return false }
            if errno == ESRCH { return true }
            // EPERM is an existence observation, not proof that custody can
            // never settle. A later ESRCH plus reap/EOF resolves it safely.
            if errno == EPERM { return false }
            uncertain = true
            return false
        }
        func signalGroup(_ signal: Int32) {
            if Darwin.kill(-child, signal) != 0 && errno != ESRCH && errno != EPERM { uncertain = true }
        }
        func drain(_ fd: Int32, data: inout Data, eof: inout Bool, otherCount: Int) {
            guard !eof else { return }
            // A continuously writable child cannot monopolize a deadline iteration.
            for _ in 0..<8 {
                let count = Darwin.read(fd, &buffer, buffer.count)
                if count > 0 {
                    let available = max(0, limits.maximumOutputBytes - data.count - otherCount)
                    data.append(contentsOf: buffer.prefix(min(count, available)))
                    if count > available && reason == nil { reason = .outputLimit }
                } else if count == 0 {
                    eof = true
                    return
                } else if errno == EAGAIN || errno == EWOULDBLOCK {
                    return
                } else if errno != EINTR {
                    uncertain = true
                    return
                }
            }
        }

        while true {
            drain(outputPipe[0], data: &stdout, eof: &stdoutEOF, otherCount: stderr.count)
            drain(errorPipe[0], data: &stderr, eof: &stderrEOF, otherCount: stdout.count)
            if !reaped {
                let waited = waitpid(child, &waitStatus, WNOHANG)
                if waited == child { reaped = true; exitObservedAt = now() }
                else if waited < 0 && errno != EINTR { uncertain = true }
            }
            let time = now()
            let absent = groupAbsent()
            settled = reaped && stdoutEOF && stderrEOF && absent && !uncertain
            if reason == nil && time >= deadline { reason = .timedOut }
            if settled { break }
            if uncertain && reason == nil { reason = .unknown }
            if reason == nil, let exited = exitObservedAt, time >= exited + limits.pipeGrace {
                reason = .descendantPipeHold
            }
            if reason != nil && terminateAt == nil {
                signalGroup(SIGTERM)
                terminateAt = time
            }
            if let term = terminateAt, killAt == nil, time >= term + limits.terminationGrace {
                signalGroup(SIGKILL)
                killAt = time
            }
            if let killed = killAt, time >= killed + limits.cleanupGrace { break }
            var pollDescriptors = [
                pollfd(fd: stdoutEOF ? -1 : outputPipe[0], events: Int16(POLLIN | POLLHUP), revents: 0),
                pollfd(fd: stderrEOF ? -1 : errorPipe[0], events: Int16(POLLIN | POLLHUP), revents: 0),
            ]
            _ = poll(&pollDescriptors, nfds_t(pollDescriptors.count), 10)
        }
        let exitCode: Int32 = reaped ? ((waitStatus & 0x7f) == 0 ? (waitStatus >> 8) & 0xff : 128 + (waitStatus & 0x7f)) : -1
        // Invalid UTF-8 replacement can expand captured bytes. Bound the encoded
        // Strings as well, and never report success if this requires truncation.
        func boundedText(_ data: Data, budget: Int) -> String {
            let text = String(decoding: data, as: UTF8.self)
            if text.utf8.count <= budget { return text }
            if reason == nil { reason = .outputLimit }
            var prefix = Array(text.utf8.prefix(budget))
            while let last = prefix.last {
                if let valid = String(bytes: prefix, encoding: .utf8) { return valid }
                _ = last
                prefix.removeLast()
            }
            return ""
        }
        let outputText = boundedText(stdout, budget: limits.maximumOutputBytes)
        let errorText = boundedText(stderr, budget: limits.maximumOutputBytes - outputText.utf8.count)
        return BoundedProcessResult(status: exitCode,
                                    stdout: outputText,
                                    stderr: errorText,
                                    outcome: settled ? (reason ?? .exited) : .unknown,
                                    settled: settled)
    }
}
