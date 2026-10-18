import Darwin
import Foundation
#if canImport(AidAdminEmergencyCore)
import AidAdminEmergencyCore
#endif

private func expect(_ condition: @autoclosure () -> Bool, _ reason: String = "expectation") throws {
    if !condition() { throw EmergencyFailure.rejected(reason) }
}

private func expectThrows(_ body: () throws -> Void) throws -> String {
    do {
        try body()
        throw EmergencyFailure.rejected("expected_rejection")
    } catch let failure as EmergencyFailure {
        if failure.description == "expected_rejection" { throw failure }
        return failure.description
    }
}

private final class FakeAccounts: EmergencyAccountLookingUp {
    var names: [UInt32: String] = [12345: "agentowner"]
    var uids: [String: UInt32] = ["agentowner": 12345]
    func name(forUID uid: UInt32) -> String? { names[uid] }
    func uid(forName name: String) -> UInt32? { uids[name] }
}

private final class FakeRunner: EmergencyCommandRunning {
    var calls: [(String, [String], [String: String])] = []
    var failCall: Int?
    var unknownCall: Int?
    var failureOutput = "bounded-fixture-output"

    func run(executable: String, arguments: [String],
             environment: [String: String]) throws -> EmergencyCommandResult {
        calls.append((executable, arguments, environment))
        if calls.count == unknownCall { throw EmergencyFailure.rejected("emergency_process_unknown") }
        let status: Int32 = calls.count == failCall ? 1 : 0
        return EmergencyCommandResult(status: status,
                                      output: status == 0 ? "bounded-fixture-output" : failureOutput)
    }
}

private final class FakeHooks: EmergencyHooks {
    var failStep: String?
    var rollbackFails = false
    var crashStep: String?
    var beforeTransitionAction: ((String) throws -> Void)?

    func beforeTransition(step: String) throws {
        try beforeTransitionAction?(step)
    }

    func afterMutation(step: String) throws {
        if step == crashStep { _exit(73) }
        if step == failStep { throw EmergencyFailure.rejected("injected_" + step) }
    }

    func beforeRollback() throws {
        if rollbackFails { throw EmergencyFailure.rejected("injected_rollback_failure") }
    }
}

private final class ScriptedOwnerRunner: EmergencyCommandRunning {
    struct Call {
        let arguments: [String]
        let result: EmergencyCommandResult
    }

    var expected: [Call]
    var calls: [[String]] = []
    var interactiveCalls: [[String]] = []
    var throwOnCall: Int?

    init(_ expected: [Call]) { self.expected = expected }

    func run(executable: String, arguments: [String],
             environment: [String: String]) throws -> EmergencyCommandResult {
        try expect(executable == "/usr/bin/sudo", "owner_runner_executable")
        try expect(environment == EmergencyTransaction.cleanEnvironment,
                   "owner_runner_environment")
        try expect(!expected.isEmpty, "owner_runner_unexpected_call")
        let next = expected.removeFirst()
        try expect(arguments == next.arguments, "owner_runner_arguments")
        calls.append(arguments)
        if calls.count == throwOnCall { throw EmergencyFailure.rejected("emergency_process_unknown") }
        return next.result
    }

    func runInteractive(executable: String, arguments: [String],
                        environment: [String: String]) throws -> EmergencyCommandResult {
        interactiveCalls.append(arguments)
        return try run(executable: executable, arguments: arguments, environment: environment)
    }
}

private func writeFixtureOutput(_ value: String) {
    let bytes = Array(value.utf8)
    _ = bytes.withUnsafeBytes { raw in
        Darwin.write(STDOUT_FILENO, raw.baseAddress, raw.count)
    }
}

private func runPTYForegroundHelper() -> Int32 {
    guard isatty(STDIN_FILENO) == 1 else { return 31 }
    guard getpgrp() == tcgetpgrp(STDIN_FILENO) else {
        writeFixtureOutput("fixture_background_detected\n")
        return 32
    }
    var original = termios()
    guard tcgetattr(STDIN_FILENO, &original) == 0 else { return 33 }
    var hidden = original
    hidden.c_lflag &= ~tcflag_t(ECHO)
    guard tcsetattr(STDIN_FILENO, TCSAFLUSH, &hidden) == 0 else { return 34 }
    var observed = termios()
    guard tcgetattr(STDIN_FILENO, &observed) == 0,
          observed.c_lflag & tcflag_t(ECHO) == 0 else {
        _ = tcsetattr(STDIN_FILENO, TCSANOW, &original)
        return 35
    }
    writeFixtureOutput("fixture_prompt_ready\n")
    var received = [UInt8]()
    var byte: UInt8 = 0
    while received.count < 128 {
        let count = Darwin.read(STDIN_FILENO, &byte, 1)
        if count == 1 {
            if byte == 0x0a { break }
            received.append(byte)
        } else if count < 0 && errno == EINTR {
            continue
        } else {
            _ = tcsetattr(STDIN_FILENO, TCSANOW, &original)
            return 36
        }
    }
    guard tcsetattr(STDIN_FILENO, TCSANOW, &original) == 0 && !received.isEmpty else {
        return 37
    }
    _ = received.withUnsafeMutableBytes {
        $0.initializeMemory(as: UInt8.self, repeating: 0)
    }
    writeFixtureOutput("fixture_foreground=true\n")
    writeFixtureOutput("fixture_echo_disabled=true\n")
    writeFixtureOutput("fixture_secret_read=true\n")
    return 0
}

private func fixtureExecutablePath() throws -> String {
    var size: UInt32 = 0
    _NSGetExecutablePath(nil, &size)
    var buffer = [CChar](repeating: 0, count: Int(size))
    try expect(_NSGetExecutablePath(&buffer, &size) == 0, "fixture_executable_path")
    let raw = String(cString: buffer)
    guard let resolved = realpath(raw, nil) else {
        throw EmergencyFailure.rejected("fixture_executable_realpath")
    }
    defer { free(resolved) }
    return String(cString: resolved)
}

private func runPTYSessionRunner() -> Int32 {
    do {
        let executable = try fixtureExecutablePath()
        let result = try EmergencyProcessRunner().runInteractive(
            executable: executable,
            arguments: ["__pty-foreground-helper"],
            environment: EmergencyTransaction.cleanEnvironment)
        return result.status
    } catch {
        writeFixtureOutput("fixture_session_runner_failed\n")
        return 38
    }
}

private final class Fixture {
    let root: URL
    let owner = EmergencyInvokingOwner(name: "agentowner", uid: 12345)
    let runner = FakeRunner()
    let hooks = FakeHooks()
    let expectations: EmergencyArtifactExpectations

    private let binaryData = Data("broker-fixture-v1".utf8)
    private let policyData = Data("{\"fixture\":true}\n".utf8)
    private let mainSudoersData = Data((
        "Defaults env_reset\n" +
        "root ALL=(ALL) ALL\n" +
        "@includedir /private/etc/sudoers.d\n").utf8)
    private let sudoersData = Data((
        "Cmnd_Alias AGENT_FIRST_MAC_AID_ADMIN = /usr/local/libexec/aid-admin\n" +
        "agentowner ALL=(root) NOPASSWD: AGENT_FIRST_MAC_AID_ADMIN\n").utf8)
    private let attestationData: Data

    private var ownsRoot = true

    init(disabled: Bool = false, existingRoot: String? = nil) throws {
        let created = existingRoot.map { URL(fileURLWithPath: $0) } ?? FileManager.default.temporaryDirectory
            .appendingPathComponent("aid-admin-emergency-fixture." + UUID().uuidString,
                                    isDirectory: true)
        if existingRoot == nil {
            try FileManager.default.createDirectory(at: created, withIntermediateDirectories: false)
        }
        ownsRoot = existingRoot == nil
        guard let resolved = realpath(created.path, nil) else {
            throw EmergencyFailure.rejected("fixture_realpath")
        }
        defer { free(resolved) }
        root = URL(fileURLWithPath: String(cString: resolved), isDirectory: true)

        var provisional: Data
        let attestation: [String: Any] = [
            "agentOwnerIdentity": owner.name,
            "agentOwnerUID": owner.uid,
            "binarySHA256": emergencySHA256(binaryData),
            "policySHA256": emergencySHA256(policyData),
            "schema": 1,
            "sudoersSHA256": emergencySHA256(sudoersData),
        ]
        provisional = try JSONSerialization.data(withJSONObject: attestation,
                                                  options: [.prettyPrinted, .sortedKeys])
        provisional.append(0x0a)
        attestationData = provisional
        expectations = EmergencyArtifactExpectations(
            binarySHA256: emergencySHA256(binaryData), binarySize: binaryData.count,
            policySHA256: emergencySHA256(policyData), policySize: policyData.count,
            sudoersSHA256: emergencySHA256(sudoersData), sudoersSize: sudoersData.count,
            attestationSize: attestationData.count)

        if existingRoot != nil { return }

        try directory("/private/etc", 0o755)
        try FileManager.default.createSymbolicLink(
            atPath: root.appendingPathComponent("etc").path,
            withDestinationPath: "private/etc")
        try directory("/usr/local/libexec", 0o755)
        try directory("/etc/agent-first-mac", 0o755)
        try directory("/etc/sudoers.d", 0o755)
        try directory("/var/log/agent-first-mac/aid-admin", 0o700)
        try directory("/var/db/agent-first-mac/staging", 0o700)
        try write(EmergencyTransaction.binaryPath, binaryData, 0o555)
        try write(EmergencyTransaction.mainSudoersPath, mainSudoersData, 0o440)
        try write(EmergencyTransaction.policyPath, policyData, 0o444)
        try write(EmergencyTransaction.attestationPath, attestationData, 0o400)
        if disabled {
            try write(EmergencyTransaction.disabledSudoersPath, sudoersData, 0o440)
            try write(EmergencyTransaction.markerPath, EmergencyTransaction.markerData, 0o400)
        } else {
            try write(EmergencyTransaction.sudoersPath, sudoersData, 0o440)
        }
    }

    deinit { if ownsRoot { try? FileManager.default.removeItem(at: root) } }

    func transaction(trustedUID: uid_t = getuid(), effectiveUID: uid_t = getuid()) -> EmergencyTransaction {
        let context = EmergencyContext(
            rootPrefix: root.path, trustedUID: trustedUID, trustedGID: getgid(),
            effectiveUID: effectiveUID, invokingOwner: owner, fixtureMode: true,
            expectations: expectations)
        return EmergencyTransaction(context: context, runner: runner, hooks: hooks)
    }

    func physical(_ logical: String) -> URL {
        root.appendingPathComponent(String(logical.dropFirst()))
    }

    func write(_ logical: String, _ data: Data, _ mode: mode_t) throws {
        let path = physical(logical)
        try FileManager.default.createDirectory(at: path.deletingLastPathComponent(),
                                                withIntermediateDirectories: true)
        try expect(!path.exists, "fixture_file_preexisting")
        let fd = Darwin.open(path.path, O_WRONLY | O_CREAT | O_EXCL, mode)
        try expect(fd >= 0, "fixture_file_open_" + String(errno))
        defer { Darwin.close(fd) }
        var offset = 0
        while offset < data.count {
            let count = data.withUnsafeBytes { raw -> Int in
                guard let base = raw.baseAddress else { return -1 }
                return Darwin.write(fd, base.advanced(by: offset), raw.count - offset)
            }
            try expect(count > 0, "fixture_file_write")
            offset += count
        }
        try expect(chmod(path.path, mode) == 0, "chmod")
    }

    func directory(_ logical: String, _ mode: mode_t) throws {
        let path = physical(logical)
        try FileManager.default.createDirectory(at: path, withIntermediateDirectories: true)
        try expect(chmod(path.path, mode) == 0, "directory_chmod")
    }

    func enabledState() -> Bool {
        physical(EmergencyTransaction.sudoersPath).isFile &&
        !physical(EmergencyTransaction.disabledSudoersPath).exists &&
        !physical(EmergencyTransaction.markerPath).exists
    }

    func disabledState() -> Bool {
        !physical(EmergencyTransaction.sudoersPath).exists &&
        physical(EmergencyTransaction.disabledSudoersPath).isFile &&
        physical(EmergencyTransaction.markerPath).isFile
    }

    func mutate(_ logical: String, data: Data? = nil, mode: mode_t? = nil) throws {
        let path = physical(logical)
        var before = stat()
        try expect(lstat(path.path, &before) == 0, "mutate_stat")
        if let data {
            try expect(chmod(path.path, 0o600) == 0, "mutate_writable")
            try data.write(to: path)
            try expect(chmod(path.path, mode ?? (before.st_mode & 0o777)) == 0,
                       "mutate_restore_mode")
        }
        if data == nil, let mode { try expect(chmod(path.path, mode) == 0, "mutate_chmod") }
    }

    func replaceWithSymlink(_ logical: String) throws {
        let path = physical(logical)
        let target = root.appendingPathComponent("symlink-target-" + UUID().uuidString)
        try Data("target".utf8).write(to: target)
        try FileManager.default.removeItem(at: path)
        try FileManager.default.createSymbolicLink(atPath: path.path, withDestinationPath: target.path)
    }

    func replaceDirectoryWithSymlink(_ logical: String) throws {
        let path = physical(logical)
        let retained = root.appendingPathComponent("retained-directory-" + UUID().uuidString,
                                                   isDirectory: true)
        try FileManager.default.moveItem(at: path, to: retained)
        try FileManager.default.createSymbolicLink(atPath: path.path,
                                                   withDestinationPath: retained.path)
    }

    func replaceDirectoryWithFile(_ logical: String) throws {
        let path = physical(logical)
        let retained = root.appendingPathComponent("retained-directory-" + UUID().uuidString,
                                                   isDirectory: true)
        try FileManager.default.moveItem(at: path, to: retained)
        try Data("not-a-directory".utf8).write(to: path)
    }
}

private extension URL {
    var exists: Bool { FileManager.default.fileExists(atPath: path) || isSymbolicLink }
    var isFile: Bool {
        guard let values = try? resourceValues(forKeys: [.isRegularFileKey]) else { return false }
        return values.isRegularFile == true && !isSymbolicLink
    }
    var isSymbolicLink: Bool {
        var info = stat()
        return lstat(path, &info) == 0 && (info.st_mode & S_IFMT) == S_IFLNK
    }
}

private struct Suite {
    func interruptedFreshProcessMatrix() throws {
        try expect(geteuid() != 0, "emergency_crash_fixture_must_be_non_root")
        let executable = try fixtureExecutablePath()
        for action in ["disable", "recover"] {
            let steps = action == "disable" ?
                ["emergency-journal-opened", "emergency-journal-written", "emergency-journal-created",
                 "sudoers-moved", "marker-temporary-opened", "marker-temporary-written", "marker-temporary-created",
                 "marker-created", "disabled-final-verification"] :
                ["emergency-journal-opened", "emergency-journal-written", "emergency-journal-created", "sudoers-restored", "marker-staged",
                 "marker-removed", "enabled-final-verification"]
            for step in steps {
                let fixture = try Fixture(disabled: action == "recover")
                let crashed = try EmergencyProcessRunner().run(executable: executable,
                    arguments: ["__emergency-fixture", fixture.root.path, action, step],
                    environment: EmergencyTransaction.cleanEnvironment)
                try expect(crashed.status == 73, "crash_point_not_reached_" + step)
                try expect(fixture.physical(EmergencyTransaction.journalPath).isFile ||
                           fixture.physical(EmergencyTransaction.journalTemporaryPath).isFile,
                           "crash_journal_not_retained")
                // A wholly new process conservatively finishes revocation; no
                // cached actor state and no fresh-enable authority is inferred.
                let disabled = try EmergencyProcessRunner().run(executable: executable,
                    arguments: ["__emergency-fixture", fixture.root.path, "disable", "none"],
                    environment: EmergencyTransaction.cleanEnvironment)
                try expect(disabled.status == 0 && fixture.disabledState(),
                           "fresh_process_reconciliation_" + action + "_" + step)
                let recovered = try EmergencyProcessRunner().run(executable: executable,
                    arguments: ["__emergency-fixture", fixture.root.path, "recover", "none"],
                    environment: EmergencyTransaction.cleanEnvironment)
                try expect(recovered.status == 0 && fixture.enabledState(),
                           "fresh_process_recovery_" + step)
                try expect(!fixture.physical(EmergencyTransaction.journalPath).exists,
                           "settled_journal_retained")
            }
        }
    }

    func sharedApplyLockAndUnresolvedMatrix() throws {
        let fixture = try Fixture()
        let path = fixture.physical(EmergencyTransaction.operationRootPath).appendingPathComponent(".operation.lock")
        let fd = open(path.path, O_RDWR | O_CREAT | O_EXCL, 0o600)
        try expect(fd >= 0 && flock(fd, LOCK_EX | LOCK_NB) == 0, "fixture_apply_lock")
        defer { Darwin.close(fd) }
        let executable = try fixtureExecutablePath()
        let disable = try EmergencyProcessRunner().run(executable: executable,
            arguments: ["__emergency-fixture", fixture.root.path, "disable", "none"],
            environment: EmergencyTransaction.cleanEnvironment)
        try expect(disable.status == 0, "cross_process_disable_busy_apply")
        try expect(fixture.disabledState(), "disable_waited_for_apply_lock")
        let busy = try expectThrows { _ = try fixture.transaction().recover() }
        try expect(busy == "emergency_apply_busy" && fixture.disabledState())
        let childBusy = try EmergencyProcessRunner().run(executable: executable,
            arguments: ["__emergency-fixture", fixture.root.path, "recover", "none"],
            environment: EmergencyTransaction.cleanEnvironment)
        try expect(childBusy.status == 74 && childBusy.output == "emergency_apply_busy",
                   "cross_process_recovery_busy_apply")
        try expect(flock(fd, LOCK_UN) == 0, "fixture_apply_unlock")
        for phase in ["profile_switching", "activating", "recovery_required", "unknown"] {
            let other = try Fixture(disabled: true)
            let data = try JSONSerialization.data(withJSONObject: ["schema": 1, "phase": phase])
            try other.write(EmergencyTransaction.operationPath, data, 0o600)
            let reason = try expectThrows { _ = try other.transaction().recover() }
            try expect(reason == "emergency_apply_unresolved" && other.disabledState())
        }
        for phase in ["complete", "rollback_verified"] {
            let other = try Fixture(disabled: true)
            let data = try JSONSerialization.data(withJSONObject: ["schema": 1, "phase": phase])
            try other.write(EmergencyTransaction.operationPath, data, 0o600)
            _ = try other.transaction().recover()
            try expect(other.enabledState())
        }
        for data in [Data("{".utf8), Data("{\"schema\":true,\"phase\":\"complete\"}".utf8),
                     Data("{\"schema\":3,\"phase\":\"complete\"}".utf8)] {
            let other = try Fixture(disabled: true)
            try other.write(EmergencyTransaction.operationPath, data, 0o600)
            let reason = try expectThrows { _ = try other.transaction().recover() }
            try expect(reason == "emergency_apply_unresolved" && other.disabledState())
        }
    }

    func unsettledCommandPreservesRecoveryState() throws {
        let fixture = try Fixture()
        fixture.hooks.failStep = "marker-created"
        let reason = try expectThrows { _ = try fixture.transaction().disable() }
        try expect(reason == "injected_marker-created" && fixture.disabledState(),
                   "unsettled_command_rolled_back")
        try expect(fixture.physical(EmergencyTransaction.journalPath).isFile)
        fixture.hooks.failStep = nil
        _ = try fixture.transaction().recover()
        try expect(fixture.enabledState())
    }

    func interruptedMetadataBoundaries() throws {
        for logical in [EmergencyTransaction.journalPath, EmergencyTransaction.journalTemporaryPath,
                        EmergencyTransaction.operationPath] {
            let fixture = try Fixture(disabled: logical == EmergencyTransaction.operationPath)
            try expect(mkfifo(fixture.physical(logical).path, 0o600) == 0, "fixture_fifo_create")
            let start = DispatchTime.now().uptimeNanoseconds
            _ = try expectThrows {
                if logical == EmergencyTransaction.operationPath { _ = try fixture.transaction().recover() }
                else { _ = try fixture.transaction().disable() }
            }
            try expect(DispatchTime.now().uptimeNanoseconds - start < 1_000_000_000,
                       "metadata_fifo_did_not_fail_promptly")
            try expect(fixture.physical(logical).exists, "metadata_fifo_removed")
        }
        let partialJournal = try Fixture()
        try partialJournal.write(EmergencyTransaction.journalTemporaryPath,
                                 Data("{\"action\":\"dis".utf8), 0o600)
        _ = try partialJournal.transaction().disable()
        try expect(partialJournal.disabledState(), "partial_journal_recovery")

        let unknown = try Fixture()
        let unknownBytes = Data("unknown-third-party-bytes".utf8)
        try unknown.write(EmergencyTransaction.journalTemporaryPath, unknownBytes, 0o600)
        _ = try expectThrows { _ = try unknown.transaction().disable() }
        let retained = try Data(contentsOf: unknown.physical(EmergencyTransaction.journalTemporaryPath))
        try expect(unknown.enabledState() && retained == unknownBytes, "unknown_metadata_not_preserved")

        let marker = try Fixture()
        marker.hooks.failStep = "sudoers-moved"
        marker.hooks.rollbackFails = true
        _ = try expectThrows { _ = try marker.transaction().disable() }
        marker.hooks.failStep = nil
        try marker.write(EmergencyTransaction.markerPath + ".new",
                         Data(EmergencyTransaction.markerData.prefix(7)), 0o400)
        _ = try marker.transaction().disable()
        try expect(marker.disabledState(), "partial_marker_recovery")
    }

    func ownerResumeFreshAuthentication() throws {
        let executable = "/fixed/reviewed/aid-admin-emergency-action"
        let commit = String(repeating: "a", count: 40)
        func call(_ arguments: [String], _ status: Int32 = 0) -> ScriptedOwnerRunner.Call {
            .init(arguments: arguments, result: .init(status: status, output: ""))
        }
        for invalid in ["", String(repeating: "a", count: 39), String(repeating: "A", count: 40),
                        commit + "\n", "--help", "/tmp/receipt", commit + " extra"] {
            let runner = ScriptedOwnerRunner([])
            let reason = try expectThrows {
                _ = try EmergencyOwnerOrchestrator(executablePath: executable, runner: runner)
                    .performResume(commit: invalid)
            }
            try expect(reason == "resume_commit_syntax" && runner.calls.isEmpty,
                       "resume_invalid_reached_auth")
        }
        let runner = ScriptedOwnerRunner([
            call(["-k", "--", executable, "__root-resume", commit]), call(["-k"]),
        ])
        let facts = try EmergencyOwnerOrchestrator(executablePath: executable, runner: runner)
            .performResume(commit: commit)
        try expect(runner.expected.isEmpty && runner.interactiveCalls == [
            ["-k", "--", executable, "__root-resume", commit],
        ], "resume_fresh_auth_boundary")
        try expect(facts.contains("broker_admission_disabled=true") &&
                   facts.first == "EMERGENCY_OPERATION_RESUMED_DISABLED" &&
                   facts.contains("recorded_operation_resumed=true") &&
                   !facts.contains("operational_state_accepted=true") &&
                   facts.contains("arbitrary_data_restoration_claimed=false") &&
                   facts.contains("reenable_requires_separate_fresh_standard_sudo=true"),
                   "resume_scope_facts")
        for status: Int32 in [1, 65] {
            let failed = ScriptedOwnerRunner([
                call(["-k", "--", executable, "__root-resume", commit], status), call(["-k"]),
            ])
            let reason = try expectThrows {
                _ = try EmergencyOwnerOrchestrator(executablePath: executable, runner: failed)
                    .performResume(commit: commit)
            }
            try expect(reason == "resume_root_transaction_failed" && failed.expected.isEmpty,
                       "resume_failure_timestamp_clear")
        }
        let unknown = ScriptedOwnerRunner([
            call(["-k", "--", executable, "__root-resume", commit]), call(["-k"]),
        ])
        unknown.throwOnCall = 1
        let reason = try expectThrows {
            _ = try EmergencyOwnerOrchestrator(executablePath: executable, runner: unknown)
                .performResume(commit: commit)
        }
        try expect(reason == "resume_root_transaction_unknown" && unknown.expected.isEmpty,
                   "resume_unknown_timestamp_clear")

        let clearFailure = ScriptedOwnerRunner([
            call(["-k", "--", executable, "__root-resume", commit]), call(["-k"], 1),
        ])
        let clearReason = try expectThrows {
            _ = try EmergencyOwnerOrchestrator(executablePath: executable, runner: clearFailure)
                .performResume(commit: commit)
        }
        try expect(clearReason == "resume_timestamp_clear_failed" && clearFailure.expected.isEmpty,
                   "resume_timestamp_failure_reported_success")
    }

    func disabledResumeBoundary() throws {
        let commit = String(repeating: "b", count: 40)
        let enabled = try Fixture()
        var called = false
        _ = try expectThrows {
            _ = try enabled.transaction().resume(commit: commit) { _ in
                called = true
                return "OPERATION_RESUMED_DISABLED"
            }
        }
        try expect(!called && enabled.enabledState(), "enabled_resume_reached_core")

        let disabled = try Fixture(disabled: true)
        let result = try disabled.transaction().resume(commit: commit) { captured in
            try expect(captured == commit, "resume_commit_changed")
            let lockPath = disabled.physical(EmergencyTransaction.operationRootPath)
                .appendingPathComponent(".emergency.lock").path
            let fd = open(lockPath, O_RDWR | O_NOFOLLOW | O_CLOEXEC)
            try expect(fd >= 0, "resume_lock_fixture_open")
            defer { Darwin.close(fd) }
            try expect(flock(fd, LOCK_EX | LOCK_NB) != 0, "resume_missing_authority_lock")
            try expect(disabled.disabledState(), "resume_callback_not_disabled")
            return "OPERATION_RESUMED_DISABLED"
        }
        try expect(result == "OPERATION_RESUMED_DISABLED" && disabled.disabledState(),
                   "resume_enabled_admission")
        let failure = try expectThrows {
            _ = try disabled.transaction().resume(commit: commit) { _ in
                throw EmergencyFailure.rejected("fixture_resume_unresolved")
            }
        }
        try expect(failure == "fixture_resume_unresolved" && disabled.disabledState(),
                   "failed_resume_enabled_admission")
        let badResult = try expectThrows {
            _ = try disabled.transaction().resume(commit: commit) { _ in "arbitrary-success" }
        }
        try expect(badResult == "resume_result_contract" && disabled.disabledState())
        let staleResult = try expectThrows {
            _ = try disabled.transaction().resume(commit: commit) { _ in "OPERATION_RECONCILED_DISABLED" }
        }
        try expect(staleResult == "resume_result_contract" && disabled.disabledState(),
                   "resume_accepted_passive_reconciliation")

        let drift = try Fixture(disabled: true)
        try drift.mutate(EmergencyTransaction.policyPath, data: Data("drift".utf8))
        called = false
        _ = try expectThrows {
            _ = try drift.transaction().resume(commit: commit) { _ in
                called = true
                return "OPERATION_RESUMED_DISABLED"
            }
        }
        try expect(!called && drift.disabledState(), "resume_drift_reached_core")

        let busy = try Fixture(disabled: true)
        let busyPath = busy.physical(EmergencyTransaction.operationRootPath)
            .appendingPathComponent(".emergency.lock").path
        let busyFD = open(busyPath, O_RDWR | O_CREAT | O_EXCL, 0o600)
        try expect(busyFD >= 0 && flock(busyFD, LOCK_EX | LOCK_NB) == 0, "resume_busy_fixture")
        defer { Darwin.close(busyFD) }
        called = false
        let busyReason = try expectThrows {
            _ = try busy.transaction().resume(commit: commit) { _ in
                called = true
                return "OPERATION_RESUMED_DISABLED"
            }
        }
        try expect(!called && busyReason == "emergency_busy" && busy.disabledState(),
                   "resume_busy_reached_core")

        for schema in [1, 2] {
            let fixture = try Fixture(disabled: true)
            let journal = try JSONSerialization.data(withJSONObject: ["schema": schema, "phase": "resumed"])
            try fixture.write(EmergencyTransaction.operationPath, journal, 0o600)
            if schema == 1 {
                _ = try expectThrows { _ = try fixture.transaction().recover() }
                try expect(fixture.disabledState(), "legacy_journal_inferred_recovery")
            } else {
                _ = try fixture.transaction().recover()
                try expect(fixture.enabledState(), "resumed_schema2_did_not_converge")
            }
        }
        for phase in ["resume_pending", "resume_committed", "reconciled", "reconciliation_committed"] {
            let interrupted = try Fixture(disabled: true)
            let bytes = try JSONSerialization.data(withJSONObject: ["schema": 2, "phase": phase])
            try interrupted.write(EmergencyTransaction.operationPath, bytes, 0o600)
            _ = try expectThrows { _ = try interrupted.transaction().recover() }
            try expect(interrupted.disabledState(), "unfinished_or_passive_recovery_enabled")
        }
    }

    func interruptedUnknownStatePreservation() throws {
        let fixture = try Fixture()
        fixture.hooks.failStep = "sudoers-moved"
        fixture.hooks.rollbackFails = true
        _ = try expectThrows { _ = try fixture.transaction().disable() }
        let old = fixture.physical(EmergencyTransaction.disabledSudoersPath)
        let bytes = try Data(contentsOf: old)
        try FileManager.default.moveItem(at: old, to: old.appendingPathExtension("retained"))
        try fixture.write(EmergencyTransaction.disabledSudoersPath, bytes, 0o440)
        let reason = try expectThrows { _ = try fixture.transaction().recover() }
        try expect(reason == "emergency_interrupted_sudoers_identity")
        try expect(fixture.physical(EmergencyTransaction.journalPath).isFile &&
                   !fixture.physical(EmergencyTransaction.sudoersPath).exists,
                   "unknown_interrupted_state_not_preserved")
    }

    func positiveDisableRecovery() throws {
        let fixture = try Fixture()
        let disabled = try fixture.transaction().disable()
        try expect(disabled == "EMERGENCY_DISABLE_TRANSACTION_COMMITTED")
        try expect(fixture.disabledState())
        let recovered = try fixture.transaction().recover()
        try expect(recovered == "EMERGENCY_RECOVERY_TRANSACTION_COMMITTED")
        try expect(fixture.enabledState())
        try expect(fixture.runner.calls.allSatisfy {
            $0.0 == "/usr/sbin/visudo" && $0.2 == EmergencyTransaction.cleanEnvironment
        })
        try expect(!fixture.runner.calls.contains { $0.1 == ["-c"] },
                   "bare_global_visudo_regression")
        let expectedFull = ["-cf", fixture.physical(EmergencyTransaction.mainSudoersPath).path]
        try expect(fixture.runner.calls.filter { $0.1 == expectedFull }.count == 2,
                   "canonical_main_visudo_contract")
    }

    func sudoProvenanceMatrix() throws -> Int {
        let accounts = FakeAccounts()
        let positive = try deriveEmergencyStandardSudoOwner(
            environment: ["SUDO_UID": "12345", "SUDO_USER": "agentowner"], accounts: accounts)
        try expect(positive == EmergencyInvokingOwner(name: "agentowner", uid: 12345))
        let cases: [[String: String]] = [
            [:], ["SUDO_UID": "12345"], ["SUDO_USER": "agentowner"],
            ["SUDO_UID": "0", "SUDO_USER": "root"],
            ["SUDO_UID": "+12345", "SUDO_USER": "agentowner"],
            ["SUDO_UID": "12345x", "SUDO_USER": "agentowner"],
            ["SUDO_UID": "12345", "SUDO_USER": "AgentOwner"],
            ["SUDO_UID": "12345", "SUDO_USER": "%admin"],
            ["SUDO_UID": "12345", "SUDO_USER": "alternate"],
            ["SUDO_UID": "54321", "SUDO_USER": "agentowner"],
        ]
        for environment in cases {
            _ = try expectThrows {
                _ = try deriveEmergencyStandardSudoOwner(environment: environment, accounts: accounts)
            }
        }
        accounts.names[12345] = "different"
        _ = try expectThrows {
            _ = try deriveEmergencyStandardSudoOwner(
                environment: ["SUDO_UID": "12345", "SUDO_USER": "agentowner"], accounts: accounts)
        }
        return cases.count + 2
    }

    func symlinkMatrix() throws {
        for logical in [EmergencyTransaction.sudoersPath] {
            let fixture = try Fixture()
            try fixture.replaceWithSymlink(logical)
            _ = try expectThrows { _ = try fixture.transaction().disable() }
        }
        let marker = try Fixture()
        try marker.replaceWithSymlink(EmergencyTransaction.sudoersPath)
        _ = try expectThrows { _ = try marker.transaction().disable() }
        let disabled = try Fixture(disabled: true)
        try disabled.replaceWithSymlink(EmergencyTransaction.disabledSudoersPath)
        _ = try expectThrows { _ = try disabled.transaction().recover() }
    }

    func hashAndAttestationDriftMatrix() throws {
        for logical in [EmergencyTransaction.sudoersPath] {
            let fixture = try Fixture()
            try fixture.mutate(logical, data: Data("drift".utf8))
            _ = try expectThrows { _ = try fixture.transaction().disable() }
        }
        let disabled = try Fixture(disabled: true)
        try disabled.mutate(EmergencyTransaction.markerPath, data: Data("drift".utf8))
        _ = try expectThrows { _ = try disabled.transaction().recover() }
    }

    func revokeWithBrokenRuntime() throws {
        // Damage is irrelevant to removing the exact pinned grant, but still
        // forbids recovery. Include missing files and no-follow hostile shapes.
        for logical in [EmergencyTransaction.binaryPath, EmergencyTransaction.policyPath,
                        EmergencyTransaction.attestationPath] {
            for damage in ["bytes", "symlink", "mode", "missing"] {
                let fixture = try Fixture()
                switch damage {
                case "bytes": try fixture.mutate(logical, data: Data("drift".utf8))
                case "symlink": try fixture.replaceWithSymlink(logical)
                case "mode": try fixture.mutate(logical, mode: 0o600)
                default: try FileManager.default.removeItem(at: fixture.physical(logical))
                }
                _ = try fixture.transaction().disable()
                try expect(fixture.disabledState() && fixture.runner.calls.isEmpty,
                           "broken_runtime_blocks_revoke")
                _ = try expectThrows { _ = try fixture.transaction().recover() }
                try expect(!fixture.physical(EmergencyTransaction.sudoersPath).exists,
                           "broken_runtime_reenabled")
            }
        }
        for directory in [EmergencyTransaction.auditPath, "/usr/local/libexec"] {
            let fixture = try Fixture()
            try FileManager.default.moveItem(at: fixture.physical(directory),
                to: fixture.physical(directory + ".retained"))
            _ = try fixture.transaction().disable()
            try expect(fixture.disabledState(), "irrelevant_directory_blocks_revoke")
        }
    }

    func wrongModeAndOwnerMatrix() throws {
        for logical in [EmergencyTransaction.sudoersPath] {
            let fixture = try Fixture()
            try fixture.mutate(logical, mode: 0o600)
            _ = try expectThrows { _ = try fixture.transaction().disable() }
        }
        let owner = try Fixture()
        _ = try expectThrows {
            _ = try owner.transaction(trustedUID: getuid() + 1, effectiveUID: getuid() + 1).disable()
        }
    }

    func unexpectedStateMatrix() throws {
        let both = try Fixture()
        try both.write(EmergencyTransaction.disabledSudoersPath,
                       Data("unexpected".utf8), 0o440)
        _ = try expectThrows { _ = try both.transaction().disable() }
        let marker = try Fixture()
        try marker.write(EmergencyTransaction.markerPath, EmergencyTransaction.markerData, 0o400)
        _ = try expectThrows { _ = try marker.transaction().disable() }
        let enabledRecover = try Fixture()
        _ = try expectThrows { _ = try enabledRecover.transaction().recover() }
        let disabledDisable = try Fixture(disabled: true)
        _ = try expectThrows { _ = try disabledDisable.transaction().disable() }
    }

    func disablePartialFailureRollbackMatrix() throws {
        for step in ["sudoers-moved", "marker-created", "disabled-final-verification"] {
            let fixture = try Fixture()
            fixture.hooks.failStep = step
            let reason = try expectThrows { _ = try fixture.transaction().disable() }
            try expect(reason == "injected_" + step, "disable_retention_reason")
            try expect(!fixture.physical(EmergencyTransaction.sudoersPath).exists,
                       "disable_must_not_restore_authority")
            fixture.hooks.failStep = nil
            _ = try fixture.transaction().disable()
            try expect(fixture.disabledState(), "disable_reconciled")
        }
    }

    func recoveryPartialFailureRollbackMatrix() throws {
        for step in ["sudoers-restored", "marker-removed", "enabled-visudo",
                     "full-visudo-enabled", "enabled-final-verification"] {
            let fixture = try Fixture(disabled: true)
            fixture.hooks.failStep = step
            let reason = try expectThrows { _ = try fixture.transaction().recover() }
            try expect(reason.hasSuffix("_rolled_back"), "recovery_rollback_reason")
            try expect(fixture.disabledState(), "recovery_rollback_state")
        }
    }

    func visudoFailureMatrix() throws {
        let preDisable = try Fixture()
        preDisable.runner.failCall = 1
        _ = try preDisable.transaction().disable()
        try expect(preDisable.disabledState() && preDisable.runner.calls.isEmpty)
        let preDisableFull = try Fixture()
        preDisableFull.runner.failCall = 2
        preDisableFull.runner.failureOutput =
            "fixture/private/path: syntax error near line 1\nraw policy omitted"
        _ = try preDisableFull.transaction().disable()
        try expect(preDisableFull.disabledState() && preDisableFull.runner.calls.isEmpty)
        let postDisable = try Fixture()
        postDisable.runner.failCall = 4
        _ = try postDisable.transaction().disable()
        try expect(postDisable.disabledState())
        let preRecovery = try Fixture(disabled: true)
        preRecovery.runner.failCall = 1
        _ = try expectThrows { _ = try preRecovery.transaction().recover() }
        try expect(preRecovery.disabledState())
        let preRecoveryFull = try Fixture(disabled: true)
        preRecoveryFull.runner.failCall = 2
        preRecoveryFull.runner.failureOutput = "unable to open included policy"
        let unavailable = try expectThrows { _ = try preRecoveryFull.transaction().recover() }
        try expect(unavailable == "visudo_full_syntax_failed_include_unavailable" &&
                   preRecoveryFull.disabledState())
        let postRecovery = try Fixture(disabled: true)
        postRecovery.runner.failCall = 4
        let recoveryReason = try expectThrows { _ = try postRecovery.transaction().recover() }
        try expect(recoveryReason.hasSuffix("_rolled_back") && postRecovery.disabledState())
    }

    func explicitMainVisudoIntegration() throws {
        try expect(geteuid() != 0, "visudo_fixture_must_be_non_root")
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("aid-admin-visudo-fixture." + UUID().uuidString,
                                    isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: root) }
        let included = root.appendingPathComponent("sudoers.d", isDirectory: true)
        let immutable = root.appendingPathComponent("immutable", isDirectory: true)
        try FileManager.default.createDirectory(at: included, withIntermediateDirectories: false)
        try FileManager.default.createDirectory(at: immutable, withIntermediateDirectories: false)
        let target = immutable.appendingPathComponent("policy")
        try Data(("Cmnd_Alias FIXTURE_READ = /usr/bin/true\n" +
                  "root ALL=(root) FIXTURE_READ\n").utf8).write(to: target)
        try expect(chmod(target.path, 0o444) == 0, "visudo_target_mode")
        let second = root.appendingPathComponent("declarative-link")
        try FileManager.default.createSymbolicLink(atPath: second.path,
                                                   withDestinationPath: target.path)
        let first = included.appendingPathComponent("10-declarative")
        try FileManager.default.createSymbolicLink(atPath: first.path,
                                                   withDestinationPath: second.path)
        let main = root.appendingPathComponent("sudoers")
        try Data(("Defaults env_reset\n" +
                  "root ALL=(root) ALL\n" +
                  "@includedir " + included.path + "\n").utf8).write(to: main)
        try expect(chmod(main.path, 0o644) == 0, "visudo_main_mode")

        let runner = EmergencyProcessRunner()
        let explicit = try runner.run(executable: "/usr/sbin/visudo",
                                      arguments: ["-cf", main.path],
                                      environment: EmergencyTransaction.cleanEnvironment)
        try expect(explicit.status == 0, "explicit_main_syntax_parse")
        let legacy = try runner.run(executable: "/usr/sbin/visudo",
                                    arguments: ["-c", "-O", "-P", "-f", main.path],
                                    environment: EmergencyTransaction.cleanEnvironment)
        try expect(legacy.status != 0, "legacy_owner_permission_check_should_fail")

        try expect(chmod(target.path, 0o600) == 0, "visudo_target_mutable")
        try Data("this is not valid sudoers syntax !!!\n".utf8).write(to: target)
        try expect(chmod(target.path, 0o444) == 0, "visudo_target_mode_restore")
        let malformed = try runner.run(executable: "/usr/sbin/visudo",
                                       arguments: ["-cf", main.path],
                                       environment: EmergencyTransaction.cleanEnvironment)
        try expect(malformed.status != 0, "malformed_included_policy_accepted")
    }

    func rollbackFailureIsDistinct() throws {
        let disable = try Fixture()
        disable.hooks.failStep = "marker-created"
        disable.hooks.rollbackFails = true
        let disableReason = try expectThrows { _ = try disable.transaction().disable() }
        try expect(disableReason == "injected_marker-created" && disable.disabledState())
        let recovery = try Fixture(disabled: true)
        recovery.hooks.failStep = "marker-removed"
        recovery.hooks.rollbackFails = true
        let recoveryReason = try expectThrows { _ = try recovery.transaction().recover() }
        try expect(recoveryReason.hasSuffix("_rollback_failed"))
    }

    func parentTrustAndRaceMatrix() throws {
        let parents = ["/private/etc", "/private/etc/sudoers.d", "/etc/sudoers.d",
                       "/etc/agent-first-mac"]
        for logical in parents {
            let writable = try Fixture()
            try writable.directory(logical, 0o777)
            _ = try expectThrows { _ = try writable.transaction().disable() }

            let wrongType = try Fixture()
            try wrongType.replaceDirectoryWithFile(logical)
            _ = try expectThrows { _ = try wrongType.transaction().disable() }

            let symlink = try Fixture()
            try symlink.replaceDirectoryWithSymlink(logical)
            _ = try expectThrows { _ = try symlink.transaction().disable() }
        }
        for logical in [EmergencyTransaction.stagingPath] {
            let writable = try Fixture()
            try writable.directory(logical, 0o755)
            _ = try expectThrows { _ = try writable.transaction().disable() }
        }
        let racingMode = try Fixture()
        racingMode.hooks.beforeTransitionAction = { step in
            if step == "disable-sudoers-move" {
                try racingMode.directory("/etc/sudoers.d", 0o777)
            }
        }
        _ = try expectThrows { _ = try racingMode.transaction().disable() }
        try expect(racingMode.physical(EmergencyTransaction.sudoersPath).isFile,
                   "parent_race_mutated_sudoers")
    }

    func noReplaceDestinationMatrix() throws {
        let disableDestination = try Fixture()
        var injectedDisableDestination = false
        disableDestination.hooks.beforeTransitionAction = { step in
            if step == "disable-sudoers-move" && !injectedDisableDestination {
                injectedDisableDestination = true
                try disableDestination.write(EmergencyTransaction.disabledSudoersPath,
                                             Data("racing-disabled-destination".utf8), 0o440)
            }
        }
        _ = try expectThrows { _ = try disableDestination.transaction().disable() }
        try expect(disableDestination.physical(EmergencyTransaction.sudoersPath).isFile)
        let disableDestinationData = try Data(contentsOf: disableDestination.physical(
            EmergencyTransaction.disabledSudoersPath))
        try expect(disableDestinationData == Data("racing-disabled-destination".utf8),
                   "disable_destination_overwritten")

        let markerDestination = try Fixture()
        markerDestination.hooks.beforeTransitionAction = { step in
            if step == "disable-marker-commit" {
                try markerDestination.write(EmergencyTransaction.markerPath,
                                            Data("racing-marker-destination".utf8), 0o400)
            }
        }
        let markerReason = try expectThrows { _ = try markerDestination.transaction().disable() }
        try expect(!markerReason.isEmpty && !markerDestination.physical(EmergencyTransaction.sudoersPath).exists,
                   "marker_race_must_not_restore_grant")
        let markerDestinationData = try Data(contentsOf: markerDestination.physical(
            EmergencyTransaction.markerPath))
        try expect(markerDestinationData == Data("racing-marker-destination".utf8),
                   "marker_destination_overwritten")

        let recoveryDestination = try Fixture(disabled: true)
        recoveryDestination.hooks.beforeTransitionAction = { step in
            if step == "recovery-sudoers-restore" {
                try recoveryDestination.write(EmergencyTransaction.sudoersPath,
                                              Data("racing-enabled-destination".utf8), 0o440)
            }
        }
        _ = try expectThrows { _ = try recoveryDestination.transaction().recover() }
        try expect(recoveryDestination.physical(EmergencyTransaction.disabledSudoersPath).isFile)
        let recoveryDestinationData = try Data(contentsOf: recoveryDestination.physical(
            EmergencyTransaction.sudoersPath))
        try expect(recoveryDestinationData == Data("racing-enabled-destination".utf8),
                   "recovery_destination_overwritten")

        let disableRollbackRace = try Fixture()
        disableRollbackRace.hooks.failStep = "marker-created"
        disableRollbackRace.hooks.beforeTransitionAction = { step in
            if step == "rollback-disable-sudoers-restore" {
                try disableRollbackRace.write(EmergencyTransaction.sudoersPath,
                                              Data("racing-rollback-enabled".utf8), 0o440)
            }
        }
        let disableRollbackReason = try expectThrows {
            _ = try disableRollbackRace.transaction().disable()
        }
        try expect(disableRollbackReason == "injected_marker-created" &&
                   !disableRollbackRace.physical(EmergencyTransaction.sudoersPath).exists,
                   "disable_rollback_must_not_run")

        let recoveryRollbackRace = try Fixture(disabled: true)
        recoveryRollbackRace.hooks.failStep = "marker-removed"
        recoveryRollbackRace.hooks.beforeTransitionAction = { step in
            if step == "rollback-recovery-sudoers-disable" {
                try recoveryRollbackRace.write(EmergencyTransaction.disabledSudoersPath,
                                               Data("racing-rollback-disabled".utf8), 0o440)
            }
        }
        let recoveryRollbackReason = try expectThrows {
            _ = try recoveryRollbackRace.transaction().recover()
        }
        try expect(recoveryRollbackReason.hasSuffix("_rollback_failed"))
        let recoveryRollbackData = try Data(contentsOf: recoveryRollbackRace.physical(
            EmergencyTransaction.disabledSudoersPath))
        try expect(recoveryRollbackData == Data("racing-rollback-disabled".utf8),
                   "recovery_rollback_destination_overwritten")

        let recoveryMarkerStageRace = try Fixture(disabled: true)
        recoveryMarkerStageRace.hooks.beforeTransitionAction = { step in
            if step == "recovery-marker-stage" {
                try recoveryMarkerStageRace.write(EmergencyTransaction.markerPath + ".new",
                                                  Data("racing-marker-stage".utf8), 0o400)
            }
        }
        let markerStageReason = try expectThrows {
            _ = try recoveryMarkerStageRace.transaction().recover()
        }
        try expect(markerStageReason.hasSuffix("_rollback_failed"))
        let markerStageData = try Data(contentsOf: recoveryMarkerStageRace.physical(
            EmergencyTransaction.markerPath + ".new"))
        try expect(markerStageData == Data("racing-marker-stage".utf8),
                   "recovery_marker_stage_destination_overwritten")

        let recoveryMarkerRollbackRace = try Fixture(disabled: true)
        recoveryMarkerRollbackRace.hooks.failStep = "marker-removed"
        recoveryMarkerRollbackRace.hooks.beforeTransitionAction = { step in
            if step == "disable-marker-commit" {
                try recoveryMarkerRollbackRace.write(EmergencyTransaction.markerPath,
                                                     Data("racing-marker-rollback".utf8), 0o400)
            }
        }
        let markerRollbackReason = try expectThrows {
            _ = try recoveryMarkerRollbackRace.transaction().recover()
        }
        try expect(markerRollbackReason.hasSuffix("_rollback_failed"))
        let markerRollbackData = try Data(contentsOf: recoveryMarkerRollbackRace.physical(
            EmergencyTransaction.markerPath))
        try expect(markerRollbackData == Data("racing-marker-rollback".utf8),
                   "recovery_marker_rollback_destination_overwritten")
    }

    func foregroundPTYIntegration() throws {
        let executable = try fixtureExecutablePath()
        guard let executablePointer = strdup(executable),
              let modePointer = strdup("__pty-session-runner") else {
            throw EmergencyFailure.rejected("pty_argument_allocation")
        }
        defer {
            free(executablePointer)
            free(modePointer)
        }
        var arguments: [UnsafeMutablePointer<CChar>?] = [
            executablePointer, modePointer, nil,
        ]
        var master: Int32 = -1
        let session = forkpty(&master, nil, nil, nil)
        try expect(session >= 0, "pty_fork")
        if session == 0 {
            _ = arguments.withUnsafeMutableBufferPointer { buffer in
                execv(executablePointer, buffer.baseAddress!)
            }
            _exit(127)
        }
        defer { Darwin.close(master) }

        var output = Data()
        let mockSecret = Data("mock-password-fixture\n".utf8)
        var secretSent = false
        var waitStatus: Int32 = 0
        var completed = false
        var stopped = false
        for _ in 0..<200 {
            var descriptor = pollfd(fd: master, events: Int16(POLLIN | POLLHUP), revents: 0)
            let polled = poll(&descriptor, 1, 25)
            if polled > 0 && descriptor.revents & Int16(POLLIN | POLLHUP) != 0 {
                var buffer = [UInt8](repeating: 0, count: 1024)
                let count = Darwin.read(master, &buffer, buffer.count)
                if count > 0 { output.append(contentsOf: buffer.prefix(count)) }
            }
            let text = String(decoding: output, as: UTF8.self)
            if !secretSent && text.contains("fixture_prompt_ready") {
                var offset = 0
                while offset < mockSecret.count {
                    let count = mockSecret.withUnsafeBytes { raw -> Int in
                        guard let base = raw.baseAddress else { return -1 }
                        return Darwin.write(master, base.advanced(by: offset),
                                            raw.count - offset)
                    }
                    try expect(count > 0, "pty_secret_write")
                    offset += count
                }
                secretSent = true
            }
            let waited = waitpid(session, &waitStatus, WNOHANG | WUNTRACED)
            if waited == session {
                let reason = waitStatus & 0x7f
                stopped = reason == 0x7f
                completed = !stopped
                break
            }
            try expect(waited == 0 || (waited < 0 && errno == EINTR), "pty_wait")
        }
        if !completed {
            _ = kill(-session, SIGKILL)
            _ = kill(session, SIGKILL)
            while waitpid(session, &waitStatus, 0) < 0 && errno == EINTR {}
        }
        try expect(completed && !stopped, "pty_process_stopped_or_timed_out")
        try expect((waitStatus & 0x7f) == 0 && ((waitStatus >> 8) & 0xff) == 0,
                   "pty_process_exit")
        for _ in 0..<8 {
            var descriptor = pollfd(fd: master, events: Int16(POLLIN | POLLHUP), revents: 0)
            if poll(&descriptor, 1, 10) <= 0 { break }
            var buffer = [UInt8](repeating: 0, count: 1024)
            let count = Darwin.read(master, &buffer, buffer.count)
            if count > 0 { output.append(contentsOf: buffer.prefix(count)) } else { break }
        }
        let text = String(decoding: output, as: UTF8.self)
        try expect(secretSent, "pty_prompt_not_observed")
        try expect(text.contains("fixture_foreground=true") &&
                   text.contains("fixture_echo_disabled=true") &&
                   text.contains("fixture_secret_read=true"), "pty_fixture_facts")
        try expect(!text.contains("mock-password-fixture") &&
                   !text.contains("fixture_background_detected") &&
                   !text.contains("fixture_session_runner_failed"),
                   "pty_secret_or_background_leak")
    }

    func ownerOrchestrationMatrix() throws {
        let executable = "/fixed/reviewed/aid-admin-emergency-action"
        let ready = "{\"problems\":[],\"readOnly\":true," +
            "\"systemMutationsPerformed\":false,\"verdict\":\"ROOT_CONTRACT_READY\"}"
        func call(_ arguments: [String], _ status: Int32,
                  _ output: String = "") -> ScriptedOwnerRunner.Call {
            ScriptedOwnerRunner.Call(arguments: arguments,
                                     result: EmergencyCommandResult(status: status,
                                                                    output: output))
        }

        let disable = ScriptedOwnerRunner([
            call(["-k", "--", executable, "__root-disable"], 0),
            call(["-k"], 0),
        ])
        let disableLines = try EmergencyOwnerOrchestrator(
            executablePath: executable, runner: disable).perform(.disable)
        try expect(disableLines.first == "EMERGENCY_DISABLE_VERIFIED" &&
                   disable.expected.isEmpty, "owner_disable_success")
        try expect(disableLines.contains("in_flight_apply_state=UNKNOWN") &&
                   disableLines.contains("in_flight_apply_stopped=false"),
                   "disable_did_not_report_unknown_inflight")
        try expect(disable.interactiveCalls == [
            ["-k", "--", executable, "__root-disable"],
        ], "owner_disable_interactive_boundary")

        let disableVerificationFailure = ScriptedOwnerRunner([
            call(["-k", "--", executable, "__root-disable"], 0),
            call(["-k"], 1),
        ])
        let disableFailure = try expectThrows {
            _ = try EmergencyOwnerOrchestrator(
                executablePath: executable, runner: disableVerificationFailure).perform(.disable)
        }
        try expect(disableFailure == "disable_timestamp_clear_failed_state_retained")

        let rootFailure = ScriptedOwnerRunner([
            call(["-k", "--", executable, "__root-disable"], 1),
            call(["-k"], 0),
        ])
        let rootFailureReason = try expectThrows {
            _ = try EmergencyOwnerOrchestrator(
                executablePath: executable, runner: rootFailure).perform(.disable)
        }
        try expect(rootFailureReason == "disable_root_transaction_failed" &&
                   rootFailure.expected.isEmpty, "root_failure_timestamp_clear")

        let recovery = ScriptedOwnerRunner([
            call(["-k", "--", executable, "__root-recover"], 0),
            call(["-n", "/usr/local/libexec/aid-admin", "doctor-root", "--json"], 0, ready),
            call(["-k"], 0),
        ])
        let recoveryLines = try EmergencyOwnerOrchestrator(
            executablePath: executable, runner: recovery).perform(.recover)
        try expect(recoveryLines.first == "EMERGENCY_RECOVERY_VERIFIED" &&
                   recovery.expected.isEmpty, "owner_recovery_success")

        let unknownDoctor = ScriptedOwnerRunner([
            call(["-k", "--", executable, "__root-recover"], 0),
            call(["-n", "/usr/local/libexec/aid-admin", "doctor-root", "--json"], 0),
            call(["-n", "--", executable, "__root-disable"], 0),
            call(["-k"], 0),
            call(["-n", "/usr/local/libexec/aid-admin", "doctor-root", "--json"], 1),
        ])
        unknownDoctor.throwOnCall = 2
        let unknownReason = try expectThrows {
            _ = try EmergencyOwnerOrchestrator(executablePath: executable,
                                               runner: unknownDoctor).perform(.recover)
        }
        try expect(unknownReason == "recovery_doctor_unknown_rolled_back" &&
                   unknownDoctor.expected.isEmpty, "unknown_doctor_revocation_cleanup")

        let unknownRollback = ScriptedOwnerRunner([
            call(["-k", "--", executable, "__root-recover"], 0),
            call(["-n", "/usr/local/libexec/aid-admin", "doctor-root", "--json"], 1),
            call(["-n", "--", executable, "__root-disable"], 0),
            call(["-k"], 0),
        ])
        unknownRollback.throwOnCall = 3
        let unknownRollbackReason = try expectThrows {
            _ = try EmergencyOwnerOrchestrator(executablePath: executable,
                                               runner: unknownRollback).perform(.recover)
        }
        try expect(unknownRollbackReason == "recovery_verification_failed_rollback_unknown" &&
                   unknownRollback.expected.isEmpty, "unknown_rollback_timestamp_cleanup")
        try expect(recovery.calls.filter { $0.starts(with: ["-k", "--"]) }.count == 1,
                   "recovery_authentication_boundary")
        try expect(recovery.interactiveCalls == [
            ["-k", "--", executable, "__root-recover"],
        ], "owner_recovery_interactive_boundary")

        let rolledBack = ScriptedOwnerRunner([
            call(["-k", "--", executable, "__root-recover"], 0),
            call(["-n", "/usr/local/libexec/aid-admin", "doctor-root", "--json"], 1),
            call(["-n", "--", executable, "__root-disable"], 0),
            call(["-k"], 0),
            call(["-n", "/usr/local/libexec/aid-admin", "doctor-root", "--json"], 1),
        ])
        let rolledBackReason = try expectThrows {
            _ = try EmergencyOwnerOrchestrator(
                executablePath: executable, runner: rolledBack).perform(.recover)
        }
        try expect(rolledBackReason == "recovery_verification_failed_rolled_back" &&
                   rolledBack.expected.isEmpty, "owner_recovery_rolled_back")
        try expect(rolledBack.calls.filter { $0.starts(with: ["-k", "--"]) }.count == 1 &&
                   rolledBack.calls.contains(["-k"]), "owner_rollback_prompt_boundary")
        try expect(rolledBack.interactiveCalls == [
            ["-k", "--", executable, "__root-recover"],
        ], "owner_rollback_noninteractive_boundary")

        let rollbackCommandFailure = ScriptedOwnerRunner([
            call(["-k", "--", executable, "__root-recover"], 0),
            call(["-n", "/usr/local/libexec/aid-admin", "doctor-root", "--json"], 1),
            call(["-n", "--", executable, "__root-disable"], 1),
            call(["-k"], 0),
        ])
        let rollbackFailure = try expectThrows {
            _ = try EmergencyOwnerOrchestrator(
                executablePath: executable, runner: rollbackCommandFailure).perform(.recover)
        }
        try expect(rollbackFailure == "recovery_verification_failed_rollback_failed" &&
                   rollbackCommandFailure.expected.isEmpty)

        let rollbackProofFailure = ScriptedOwnerRunner([
            call(["-k", "--", executable, "__root-recover"], 0),
            call(["-n", "/usr/local/libexec/aid-admin", "doctor-root", "--json"], 1),
            call(["-n", "--", executable, "__root-disable"], 0),
            call(["-k"], 0),
            call(["-n", "/usr/local/libexec/aid-admin", "doctor-root", "--json"], 0, ready),
        ])
        let proofFailure = try expectThrows {
            _ = try EmergencyOwnerOrchestrator(
                executablePath: executable, runner: rollbackProofFailure).perform(.recover)
        }
        try expect(proofFailure == "recovery_verification_failed_rollback_failed" &&
                   rollbackProofFailure.expected.isEmpty)
    }

    func noRecursiveOrUnrelatedMutation() throws {
        let fixture = try Fixture()
        let audit = fixture.physical(EmergencyTransaction.auditPath)
            .appendingPathComponent("retained-audit.json")
        let staging = fixture.physical(EmergencyTransaction.stagingPath)
            .appendingPathComponent("retained-transaction")
        try Data("audit".utf8).write(to: audit)
        try FileManager.default.createDirectory(at: staging, withIntermediateDirectories: false)
        _ = try fixture.transaction().disable()
        _ = try fixture.transaction().recover()
        try expect(audit.isFile && staging.exists)
    }
}

@main
private struct TestMain {
    static func main() {
        let arguments = Array(CommandLine.arguments.dropFirst())
        if arguments == ["__pty-foreground-helper"] {
            exit(runPTYForegroundHelper())
        }
        if arguments == ["__pty-session-runner"] {
            exit(runPTYSessionRunner())
        }
        if arguments.count == 4 && arguments[0] == "__emergency-fixture" {
            do {
                try expect(geteuid() != 0 && arguments[1].contains("/aid-admin-emergency-fixture."),
                           "fixture_child_scope")
                let fixture = try Fixture(existingRoot: arguments[1])
                fixture.hooks.crashStep = arguments[3]
                if arguments[2] == "disable" { _ = try fixture.transaction().disable() }
                else if arguments[2] == "recover" { _ = try fixture.transaction().recover() }
                else { throw EmergencyFailure.rejected("fixture_child_action") }
                exit(0)
            } catch { writeFixtureOutput(String(describing: error)); exit(74) }
        }
        do {
            let suite = Suite()
            let groups: [(String, () throws -> Void)] = [
                ("positive_disable_recovery", suite.positiveDisableRecovery),
                ("symlink_matrix", suite.symlinkMatrix),
                ("hash_attestation_drift", suite.hashAndAttestationDriftMatrix),
                ("revoke_broken_runtime", suite.revokeWithBrokenRuntime),
                ("wrong_mode_owner", suite.wrongModeAndOwnerMatrix),
                ("unexpected_state", suite.unexpectedStateMatrix),
                ("disable_partial_rollback", suite.disablePartialFailureRollbackMatrix),
                ("recovery_partial_rollback", suite.recoveryPartialFailureRollbackMatrix),
                ("visudo_failure", suite.visudoFailureMatrix),
                ("explicit_main_visudo", suite.explicitMainVisudoIntegration),
                ("rollback_failure", suite.rollbackFailureIsDistinct),
                ("parent_trust_race", suite.parentTrustAndRaceMatrix),
                ("no_replace_destinations", suite.noReplaceDestinationMatrix),
                ("foreground_pty_integration", suite.foregroundPTYIntegration),
                ("owner_orchestration", suite.ownerOrchestrationMatrix),
                ("retention", suite.noRecursiveOrUnrelatedMutation),
                ("interrupted_fresh_process", suite.interruptedFreshProcessMatrix),
                ("shared_apply_lock_unresolved", suite.sharedApplyLockAndUnresolvedMatrix),
                ("interrupted_unknown_preservation", suite.interruptedUnknownStatePreservation),
                ("unsettled_command_retention", suite.unsettledCommandPreservesRecoveryState),
                ("interrupted_metadata_boundaries", suite.interruptedMetadataBoundaries),
                ("owner_resume_fresh_auth", suite.ownerResumeFreshAuthentication),
                ("disabled_resume_boundary", suite.disabledResumeBoundary),
            ]
            var completed = 0
            for (name, test) in groups {
                do { try test(); completed += 1 }
                catch { throw EmergencyFailure.rejected(name + ":" + String(describing: error)) }
            }
            let provenanceCases = try suite.sudoProvenanceMatrix()
            print("{\"provenanceCases\":\(provenanceCases),\"result\":\"pass\",\"tests\":\(completed + 1)}")
        } catch {
            print("{\"result\":\"fail\",\"reason\":\"\(String(describing: error))\"}")
            exit(1)
        }
    }
}
