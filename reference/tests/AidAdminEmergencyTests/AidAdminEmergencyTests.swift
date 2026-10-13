import Darwin
import Foundation

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
    var failureOutput = "bounded-fixture-output"

    func run(executable: String, arguments: [String],
             environment: [String: String]) throws -> EmergencyCommandResult {
        calls.append((executable, arguments, environment))
        let status: Int32 = calls.count == failCall ? 1 : 0
        return EmergencyCommandResult(status: status,
                                      output: status == 0 ? "bounded-fixture-output" : failureOutput)
    }
}

private final class FakeHooks: EmergencyHooks {
    var failStep: String?
    var rollbackFails = false
    var beforeTransitionAction: ((String) throws -> Void)?

    func beforeTransition(step: String) throws {
        try beforeTransitionAction?(step)
    }

    func afterMutation(step: String) throws {
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

    init(disabled: Bool = false) throws {
        let created = FileManager.default.temporaryDirectory
            .appendingPathComponent("aid-admin-emergency-fixture." + UUID().uuidString,
                                    isDirectory: true)
        try FileManager.default.createDirectory(at: created, withIntermediateDirectories: false)
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

    deinit { try? FileManager.default.removeItem(at: root) }

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
        try expect(fixture.runner.calls.filter { $0.1 == expectedFull }.count == 4,
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
        for logical in [EmergencyTransaction.binaryPath, EmergencyTransaction.policyPath,
                        EmergencyTransaction.attestationPath, EmergencyTransaction.sudoersPath,
                        EmergencyTransaction.mainSudoersPath] {
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
        for logical in [EmergencyTransaction.binaryPath, EmergencyTransaction.policyPath,
                        EmergencyTransaction.sudoersPath, EmergencyTransaction.attestationPath] {
            let fixture = try Fixture()
            try fixture.mutate(logical, data: Data("drift".utf8))
            _ = try expectThrows { _ = try fixture.transaction().disable() }
        }
        let disabled = try Fixture(disabled: true)
        try disabled.mutate(EmergencyTransaction.markerPath, data: Data("drift".utf8))
        _ = try expectThrows { _ = try disabled.transaction().recover() }
    }

    func wrongModeAndOwnerMatrix() throws {
        for logical in [EmergencyTransaction.binaryPath, EmergencyTransaction.policyPath,
                        EmergencyTransaction.attestationPath, EmergencyTransaction.sudoersPath,
                        EmergencyTransaction.mainSudoersPath] {
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
        for step in ["sudoers-moved", "marker-created", "disabled-visudo",
                     "full-visudo-disabled", "disabled-final-verification"] {
            let fixture = try Fixture()
            fixture.hooks.failStep = step
            let reason = try expectThrows { _ = try fixture.transaction().disable() }
            try expect(reason.hasSuffix("_rolled_back"), "disable_rollback_reason")
            try expect(fixture.enabledState(), "disable_rollback_state")
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
        _ = try expectThrows { _ = try preDisable.transaction().disable() }
        try expect(preDisable.enabledState())
        let preDisableFull = try Fixture()
        preDisableFull.runner.failCall = 2
        preDisableFull.runner.failureOutput =
            "fixture/private/path: syntax error near line 1\nraw policy omitted"
        let classified = try expectThrows { _ = try preDisableFull.transaction().disable() }
        try expect(classified == "visudo_full_syntax_failed_syntax" &&
                   !classified.contains("private") && preDisableFull.enabledState(),
                   "full_visudo_diagnostic_classification")
        let postDisable = try Fixture()
        postDisable.runner.failCall = 4
        let disableReason = try expectThrows { _ = try postDisable.transaction().disable() }
        try expect(disableReason.hasSuffix("_rolled_back") && postDisable.enabledState())
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
        try expect(disableReason.hasSuffix("_rollback_failed"))
        let recovery = try Fixture(disabled: true)
        recovery.hooks.failStep = "marker-removed"
        recovery.hooks.rollbackFails = true
        let recoveryReason = try expectThrows { _ = try recovery.transaction().recover() }
        try expect(recoveryReason.hasSuffix("_rollback_failed"))
    }

    func parentTrustAndRaceMatrix() throws {
        let parents = ["/private/etc", "/private/etc/sudoers.d", "/etc/sudoers.d",
                       "/etc/agent-first-mac", "/usr/local/libexec"]
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
        for logical in [EmergencyTransaction.auditPath, EmergencyTransaction.stagingPath] {
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
        try expect(markerReason.hasSuffix("_rollback_failed"), "marker_race_rollback_result")
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
        try expect(disableRollbackReason.hasSuffix("_rollback_failed"))
        let disableRollbackData = try Data(contentsOf: disableRollbackRace.physical(
            EmergencyTransaction.sudoersPath))
        try expect(disableRollbackData == Data("racing-rollback-enabled".utf8),
                   "disable_rollback_destination_overwritten")

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
            call(["-n", "/usr/local/libexec/aid-admin", "doctor-root", "--json"], 1),
        ])
        let disableLines = try EmergencyOwnerOrchestrator(
            executablePath: executable, runner: disable).perform(.disable)
        try expect(disableLines.first == "EMERGENCY_DISABLE_VERIFIED" &&
                   disable.expected.isEmpty, "owner_disable_success")
        try expect(disable.interactiveCalls == [
            ["-k", "--", executable, "__root-disable"],
        ], "owner_disable_interactive_boundary")

        let disableVerificationFailure = ScriptedOwnerRunner([
            call(["-k", "--", executable, "__root-disable"], 0),
            call(["-k"], 0),
            call(["-n", "/usr/local/libexec/aid-admin", "doctor-root", "--json"], 0, ready),
        ])
        let disableFailure = try expectThrows {
            _ = try EmergencyOwnerOrchestrator(
                executablePath: executable, runner: disableVerificationFailure).perform(.disable)
        }
        try expect(disableFailure == "disable_verification_failed_state_retained")

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
        do {
            let suite = Suite()
            let groups: [(String, () throws -> Void)] = [
                ("positive_disable_recovery", suite.positiveDisableRecovery),
                ("symlink_matrix", suite.symlinkMatrix),
                ("hash_attestation_drift", suite.hashAndAttestationDriftMatrix),
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
            ]
            var completed = 0
            for (_, test) in groups { try test(); completed += 1 }
            let provenanceCases = try suite.sudoProvenanceMatrix()
            print("{\"provenanceCases\":\(provenanceCases),\"result\":\"pass\",\"tests\":\(completed + 1)}")
        } catch {
            print("{\"result\":\"fail\",\"reason\":\"\(String(describing: error))\"}")
            exit(1)
        }
    }
}
