import AidAdminRuntime
import Darwin
import Foundation

private func expect(_ condition: @autoclosure () -> Bool, _ reason: String) throws {
    if !condition() { throw BoundedProcessFailure.rejected(reason) }
}

private func emit(_ text: String, fd: Int32 = STDOUT_FILENO) {
    let bytes = Array(text.utf8)
    bytes.withUnsafeBytes { pointer in _ = Darwin.write(fd, pointer.baseAddress!, pointer.count) }
}

@main
struct RuntimeTests {
    static func fixture(_ kind: String) -> Never {
        if kind == "exit" {
            emit("fixture-out\n"); emit("fixture-err\n", fd: STDERR_FILENO); _exit(7)
        }
        if kind == "stdin" {
            var byte: UInt8 = 0
            _exit(Darwin.read(STDIN_FILENO, &byte, 1) == 0 ? 0 : 19)
        }
        if kind == "invalid-utf8" {
            let bytes = [UInt8](repeating: 0xff, count: 2048)
            bytes.withUnsafeBytes { _ = Darwin.write(STDOUT_FILENO, $0.baseAddress!, $0.count) }
            _exit(0)
        }
        if kind == "closed-stdio" {
            for fd in [STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO] { _ = Darwin.close(fd) }
            do {
                let result = try BoundedProcess.run(executable: CommandLine.arguments[0],
                                                    arguments: ["--fixture", "exit"], environment: [:],
                                                    limits: .init(timeout: 1))
                _exit(result.settled && result.outcome == .exited && result.status == 7 &&
                      result.stdout == "fixture-out\n" && result.stderr == "fixture-err\n" ? 0 : 22)
            } catch { _exit(23) }
        }
        if kind == "flood" {
            while true { emit(String(repeating: "x", count: 8192)); emit(String(repeating: "y", count: 8192), fd: STDERR_FILENO) }
        }
        if kind == "ignore-term" {
            signal(SIGTERM, SIG_IGN)
            emit("\(getpid())\n")
            usleep(3_000_000)
            _exit(0)
        }
        if kind.hasPrefix("grandchild-") {
            if kind == "grandchild-escape" { _ = setsid() }
            if kind == "grandchild-closed-descendant" {
                _ = Darwin.close(STDOUT_FILENO); _ = Darwin.close(STDERR_FILENO)
            }
            // A finite safety net protects the fixture even if the runner is broken.
            usleep(2_000_000)
            _exit(0)
        }
        if kind == "descendant" || kind == "closed-descendant" || kind == "escape" {
            let executable = CommandLine.arguments[0]
            let argv = [executable, "--fixture", "grandchild-\(kind)"].map { strdup($0) } + [nil]
            let envp: [UnsafeMutablePointer<CChar>?] = [nil]
            var child: pid_t = 0
            let status = argv.withUnsafeBufferPointer { av in
                envp.withUnsafeBufferPointer { ev in
                    posix_spawn(&child, executable, nil, nil, av.baseAddress!, ev.baseAddress!)
                }
            }
            for pointer in argv { free(pointer) }
            if status != 0 { _exit(20) }
            emit("\(child)\n")
            // Let the escaped child complete setsid before the leader exits.
            if kind == "escape" { usleep(50_000) }
            _exit(0)
        }
        _exit(21)
    }

    static func main() throws {
        guard getuid() != 0 && geteuid() != 0 else {
            throw BoundedProcessFailure.rejected("runtime_fixtures_require_nonroot")
        }
        if CommandLine.arguments.count == 3, CommandLine.arguments[1] == "--fixture" {
            fixture(CommandLine.arguments[2])
        }
        let executable = URL(fileURLWithPath: CommandLine.arguments[0]).standardizedFileURL.path
        let limits = BoundedProcessLimits(timeout: 0.2, terminationGrace: 0.1,
                                          cleanupGrace: 0.5, pipeGrace: 0.05,
                                          maximumOutputBytes: 4096)
        func run(_ kind: String, _ custom: BoundedProcessLimits? = nil) throws -> BoundedProcessResult {
            try BoundedProcess.run(executable: executable, arguments: ["--fixture", kind],
                                   environment: ["PATH": "/usr/bin:/bin", "LC_ALL": "C"],
                                   limits: custom ?? limits)
        }
        func absent(_ pid: Int32) -> Bool { Darwin.kill(pid, 0) < 0 && errno == ESRCH }
        func waitAbsent(_ pid: Int32) -> Bool {
            for _ in 0..<200 {
                if absent(pid) { return true }
                usleep(10_000)
            }
            return absent(pid)
        }
        var count = 0
        func check(_ name: String, _ body: () throws -> Void) throws {
            try body(); count += 1; print("PASS \(name)")
        }
        try check("separate-output-and-nonzero-exit") {
            let result = try run("exit")
            try expect(result.settled && result.outcome == .exited && result.status == 7, "exit_status")
            try expect(result.stdout == "fixture-out\n" && result.stderr == "fixture-err\n", "output_capture")
        }
        try check("null-stdin") {
            let result = try run("stdin")
            try expect(result.settled && result.outcome == .exited && result.status == 0, "stdin_not_null")
        }
        try check("monotonic-timeout-kill-reap") {
            let start = DispatchTime.now().uptimeNanoseconds
            let result = try run("ignore-term")
            let elapsed = Double(DispatchTime.now().uptimeNanoseconds - start) / 1e9
            try expect(result.settled && result.outcome == .timedOut, "timeout_unsettled")
            try expect(result.status == 128 + SIGKILL, "term_ignore_not_killed")
            try expect(elapsed >= 0.2 && elapsed < 2, "timeout_not_bounded")
            guard let pid = Int32(result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)) else {
                throw BoundedProcessFailure.rejected("missing_fixture_pid")
            }
            try expect(absent(pid), "direct_child_not_reaped")
        }
        try check("combined-output-cap") {
            let result = try run("flood")
            try expect(result.settled && result.outcome == .outputLimit, "output_limit_not_settled")
            try expect(result.stdout.utf8.count + result.stderr.utf8.count == 4096, "output_not_capped")
        }
        try check("invalid-utf8-still-byte-capped") {
            let result = try run("invalid-utf8")
            try expect(result.settled && result.outcome == .outputLimit, "replacement_truncation_not_reported")
            try expect(result.stdout.utf8.count + result.stderr.utf8.count <= 4096, "replacement_exceeds_cap")
        }
        try check("closed-standard-descriptors") {
            let result = try run("closed-stdio", .init(timeout: 2))
            try expect(result.settled && result.outcome == .exited && result.status == 0, "stdio_aliasing")
        }
        try check("descriptors-close-on-success-and-spawn-failure") {
            func openDescriptors() -> Set<Int32> {
                Set((3..<256).compactMap { number in
                    let fd = Int32(number)
                    return fcntl(fd, F_GETFD) >= 0 ? fd : nil
                })
            }
            let before = openDescriptors()
            for _ in 0..<10 {
                _ = try run("exit")
                _ = try? BoundedProcess.run(executable: "/nonexistent/fixture", arguments: [], environment: [:])
            }
            try expect(openDescriptors() == before, "descriptor_leak")
        }
        for kind in ["descendant", "closed-descendant"] {
            try check(kind) {
                let result = try run(kind)
                try expect(result.settled && result.outcome == .descendantPipeHold, "descendant_not_settled_\(kind)")
                guard let pid = Int32(result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)) else {
                    throw BoundedProcessFailure.rejected("missing_descendant_pid")
                }
                try expect(absent(pid), "descendant_survived_\(kind)")
            }
        }
        try check("escaped-pipe-holder-is-unknown") {
            let start = DispatchTime.now().uptimeNanoseconds
            let result = try run("escape")
            guard let pid = Int32(result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)) else {
                throw BoundedProcessFailure.rejected("missing_escaped_pid")
            }
            // This is fixture cleanup, not production authority to signal arbitrary descendants.
            _ = Darwin.kill(pid, SIGKILL)
            let gone = waitAbsent(pid)
            try expect(!result.settled && result.outcome == .unknown, "escape_claimed_settled")
            try expect(Double(DispatchTime.now().uptimeNanoseconds - start) / 1e9 < 3, "escape_wait_unbounded")
            try expect(gone, "escaped_fixture_cleanup_failed")
        }
        try check("spawn-error-is-redacted") {
            do {
                _ = try BoundedProcess.run(executable: "/nonexistent/fixture-secret", arguments: [], environment: [:])
                throw BoundedProcessFailure.rejected("missing_spawn_error")
            } catch let failure as BoundedProcessFailure {
                try expect(failure.description == "bounded_process_spawn_failed", "spawn_error_detail")
            }
        }
        try check("invalid-limits-denied-before-spawn") {
            do {
                _ = try BoundedProcess.run(executable: executable, arguments: [], environment: [:],
                                           limits: .init(timeout: .infinity))
                throw BoundedProcessFailure.rejected("missing_limit_error")
            } catch let failure as BoundedProcessFailure {
                try expect(failure.description == "bounded_process_invalid_input", "invalid_limits_error")
            }
        }
        print("PASS \(count) bounded subprocess tests; nonroot fixtures only")
    }
}
