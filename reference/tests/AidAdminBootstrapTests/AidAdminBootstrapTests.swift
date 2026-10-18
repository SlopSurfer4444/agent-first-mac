import AidAdminBootstrapCore
import Darwin
import Foundation

private func expect(_ condition: @autoclosure () throws -> Bool,
                    _ reason: String = "expectation_failed") throws {
    if try !condition() { throw BootstrapFailure.rejected(reason) }
}

private func expectThrows(_ action: () throws -> Void) throws -> String {
    do { try action() }
    catch { return String(describing: error) }
    throw BootstrapFailure.rejected("expected_error")
}

private final class FakeRunner: BootstrapCommandRunning {
    var status: Int32 = 0
    var calls: [(String, [String], [String: String])] = []
    func run(executable: String, arguments: [String], environment: [String: String]) throws -> Int32 {
        calls.append((executable, arguments, environment))
        return status
    }
}

private struct FakeAccountLookup: BootstrapAccountLookingUp {
    let namesByUID: [UInt32: String]
    let uidsByName: [String: UInt32]

    func name(forUID uid: UInt32) -> String? { namesByUID[uid] }
    func uid(forName name: String) -> UInt32? { uidsByName[name] }
}

private final class TestHooks: BootstrapHooks {
    var failStep: String?
    var rollbackFails = false
    var afterStage: (([String: String]) throws -> Void)?
    var afterStep: ((String) throws -> Void)?

    func afterStaging(paths: [String: String]) throws { try afterStage?(paths) }
    func afterMutation(step: String) throws {
        try afterStep?(step)
        if step == failStep { throw BootstrapFailure.rejected("injected_" + step) }
    }
    func beforeRollback() throws {
        if rollbackFails { throw BootstrapFailure.rejected("injected_rollback_failure") }
    }
}

private final class Fixture {
    let root: URL
    let sources: URL
    let runner = FakeRunner()
    let hooks = TestHooks()
    let uid = getuid()
    let gid = getgid()
    let bootstrap: URL
    let broker: URL
    let policy: URL
    let sudoersTemplate: URL
    let inputs: URL
    private let fm = FileManager.default

    init(template: String? = nil) throws {
        let candidate = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("aid-admin-bootstrap-fixture." + UUID().uuidString,
                                    isDirectory: true)
        try fm.createDirectory(at: candidate, withIntermediateDirectories: true)
        guard let pointer = realpath(candidate.path, nil) else {
            throw BootstrapFailure.rejected("fixture_realpath")
        }
        root = URL(fileURLWithPath: String(cString: pointer), isDirectory: true)
        free(pointer)
        sources = root.appendingPathComponent("reviewed", isDirectory: true)
        try fm.createDirectory(at: sources, withIntermediateDirectories: true)
        bootstrap = sources.appendingPathComponent("aid-admin-bootstrap")
        broker = sources.appendingPathComponent("aid-admin")
        policy = sources.appendingPathComponent("aid-admin-policy.json")
        sudoersTemplate = sources.appendingPathComponent("sudoers-template")
        inputs = sources.appendingPathComponent("install-inputs.json")

        for path in ["etc", "etc/sudoers.d", "usr", "usr/local", "usr/local/libexec",
                     "var", "var/db", "var/log"] {
            let directory = root.appendingPathComponent(path, isDirectory: true)
            try fm.createDirectory(at: directory, withIntermediateDirectories: true)
            try fm.setAttributes([.posixPermissions: NSNumber(value: 0o755)],
                                 ofItemAtPath: directory.path)
        }
        try write(bootstrap, Data("bootstrap-fixture".utf8), mode: 0o555)
        try write(broker, Data("broker-fixture-v1".utf8), mode: 0o555)
        try write(policy, Data("{\"fixture\":true}\n".utf8), mode: 0o444)
        let exactTemplate = template ?? (
            "Cmnd_Alias AGENT_FIRST_MAC_AID_ADMIN = /usr/local/libexec/aid-admin\n" +
            "@@AGENT_OWNER@@ ALL=(root) NOPASSWD: AGENT_FIRST_MAC_AID_ADMIN\n")
        try write(sudoersTemplate, Data(exactTemplate.utf8), mode: 0o444)
        try refreshInputs()
    }

    deinit { try? fm.removeItem(at: root) }

    func installer() -> BootstrapInstaller {
        let context = BootstrapContext(rootPrefix: root.path, trustedUID: uid, trustedGID: gid,
                                       effectiveUID: uid, currentExecutablePath: bootstrap.path,
                                       invokingOwner: BootstrapInvokingOwner(
                                           name: "agentowner", uid: 12345),
                                       fixtureMode: true)
        return BootstrapInstaller(context: context, runner: runner, hooks: hooks,
                                  actionID: { "11111111-2222-3333-4444-555555555555" })
    }

    func subprocess(_ mode: String, step: String = "") throws -> Int32 {
        let child = Process()
        var length: UInt32 = 0
        _ = _NSGetExecutablePath(nil, &length)
        var buffer = [CChar](repeating: 0, count: Int(length))
        try expect(_NSGetExecutablePath(&buffer, &length) == 0, "test_executable_path")
        child.executableURL = URL(fileURLWithPath: String(cString: buffer))
        child.arguments = [mode, root.path, step]
        child.standardOutput = FileHandle.nullDevice
        child.standardError = FileHandle.nullDevice
        try child.run()
        child.waitUntilExit()
        return child.terminationStatus
    }

    func request(owner: String = "agentowner", ownerUID: UInt32 = 12345,
                 identity: String = "name:agentowner",
                 brokerPath: String? = nil) throws -> BootstrapRequest {
        let data = try Data(contentsOf: inputs)
        return BootstrapRequest(
            brokerPath: brokerPath ?? broker.path, policyPath: policy.path,
            sudoersTemplatePath: sudoersTemplate.path, inputsPath: inputs.path,
            inputsSHA256: bootstrapSHA256(data), inputsSize: data.count,
            ownerName: owner, ownerUID: ownerUID, sudoersIdentity: identity)
    }

    func refreshInputs(renderedOverride: ArtifactPin? = nil,
                       bootstrapOverride: ArtifactPin? = nil) throws {
        let rendered = sudoersTemplateData().replacingOccurrences(
            of: Data("@@AGENT_OWNER@@".utf8), with: Data("agentowner".utf8))
        let value: [String: Any] = [
            "artifactSet": "phase4-aid-admin-install-bundle-v1",
            "bootstrap": pinObject(bootstrapOverride ?? pin(bootstrap)),
            "broker": pinObject(pin(broker)),
            "policy": pinObject(pin(policy)),
            "renderedSudoers": pinObject(renderedOverride ?? ArtifactPin(
                sha256: bootstrapSHA256(rendered), size: rendered.count)),
            "schema": 1,
            "sudoersTemplate": pinObject(pin(sudoersTemplate)),
        ]
        var data = try JSONSerialization.data(withJSONObject: value, options: [.prettyPrinted, .sortedKeys])
        data.append(0x0a)
        if inputs.exists { try fm.removeItem(at: inputs) }
        try write(inputs, data, mode: 0o444)
    }

    func expectedPathsPresent() -> Bool {
        [BootstrapInstaller.binaryPath, BootstrapInstaller.policyPath,
         BootstrapInstaller.attestationPath, BootstrapInstaller.sudoersPath,
         BootstrapInstaller.auditPath, BootstrapInstaller.brokerStagingPath]
            .allSatisfy { physical($0).exists }
    }

    func expectedPathsAbsent() -> Bool {
        [BootstrapInstaller.binaryPath, BootstrapInstaller.policyPath,
         BootstrapInstaller.attestationPath, BootstrapInstaller.sudoersPath,
         BootstrapInstaller.auditPath, BootstrapInstaller.brokerStagingPath]
            .allSatisfy { !physical($0).exists }
    }

    func physical(_ logical: String) -> URL {
        root.appendingPathComponent(String(logical.dropFirst()))
    }

    func fileHashes() throws -> [String: String] {
        var result: [String: String] = [:]
        for path in [BootstrapInstaller.binaryPath, BootstrapInstaller.policyPath,
                     BootstrapInstaller.attestationPath, BootstrapInstaller.sudoersPath] {
            result[path] = bootstrapSHA256(try Data(contentsOf: physical(path)))
        }
        return result
    }

    private func pin(_ path: URL) -> ArtifactPin {
        let data = try! Data(contentsOf: path)
        return ArtifactPin(sha256: bootstrapSHA256(data), size: data.count)
    }

    private func pinObject(_ pin: ArtifactPin) -> [String: Any] {
        ["sha256": pin.sha256, "size": pin.size]
    }

    private func sudoersTemplateData() -> Data { try! Data(contentsOf: sudoersTemplate) }

    private func write(_ path: URL, _ data: Data, mode: Int16) throws {
        try data.write(to: path, options: .withoutOverwriting)
        try fm.setAttributes([.posixPermissions: NSNumber(value: mode)], ofItemAtPath: path.path)
    }
}

private extension URL {
    var exists: Bool { FileManager.default.fileExists(atPath: path) }
}

private extension Data {
    func replacingOccurrences(of needle: Data, with replacement: Data) -> Data {
        guard let range = range(of: needle) else { return self }
        var copy = self
        copy.replaceSubrange(range, with: replacement)
        return copy
    }
}

private struct BootstrapTests {
    func testStandardSudoInvokerProvenanceMatrix() throws {
        let exact = FakeAccountLookup(
            namesByUID: [12345: "agentowner"],
            uidsByName: ["agentowner": 12345])
        let owner = try deriveStandardSudoInvokingOwner(
            environment: ["SUDO_UID": "12345", "SUDO_USER": "agentowner"],
            accounts: exact)
        try expect(owner == BootstrapInvokingOwner(name: "agentowner", uid: 12345))

        let invalidEnvironments: [[String: String]] = [
            [:],
            ["SUDO_UID": "12345"],
            ["SUDO_USER": "agentowner"],
            ["SUDO_UID": "0", "SUDO_USER": "agentowner"],
            ["SUDO_UID": "012345", "SUDO_USER": "agentowner"],
            ["SUDO_UID": "not-a-uid", "SUDO_USER": "agentowner"],
            ["SUDO_UID": "4294967296", "SUDO_USER": "agentowner"],
            ["SUDO_UID": "12345", "SUDO_USER": "%admin"],
            ["SUDO_UID": "12345", "SUDO_USER": "12345"],
            ["SUDO_UID": "12345", "SUDO_USER": "bad name"],
            ["SUDO_UID": "12345", "SUDO_USER": "root"],
        ]
        for environment in invalidEnvironments {
            _ = try expectThrows {
                _ = try deriveStandardSudoInvokingOwner(environment: environment,
                                                        accounts: exact)
            }
        }

        let wrongName = FakeAccountLookup(
            namesByUID: [12345: "secondowner"],
            uidsByName: ["agentowner": 12345])
        _ = try expectThrows {
            _ = try deriveStandardSudoInvokingOwner(
                environment: ["SUDO_UID": "12345", "SUDO_USER": "agentowner"],
                accounts: wrongName)
        }
        let wrongUID = FakeAccountLookup(
            namesByUID: [12345: "agentowner"],
            uidsByName: ["agentowner": 23456])
        _ = try expectThrows {
            _ = try deriveStandardSudoInvokingOwner(
                environment: ["SUDO_UID": "12345", "SUDO_USER": "agentowner"],
                accounts: wrongUID)
        }
    }

    func testRequestAndSudoersMustMatchValidatedInvoker() throws {
        let invalid: [(String, UInt32, String)] = [
            ("secondowner", 12345, "name:secondowner"),
            ("agentowner", 23456, "name:agentowner"),
            ("agentowner", 12345, "name:secondowner"),
            ("agentowner", 12345, "group:agentowner"),
            ("agentowner", 12345, "uid:12345"),
            ("agentowner", 12345, "#12345"),
        ]
        for (name, uid, identity) in invalid {
            let fixture = try Fixture()
            _ = try expectThrows {
                _ = try fixture.installer().install(
                    fixture.request(owner: name, ownerUID: uid, identity: identity))
            }
            try expect(fixture.expectedPathsAbsent())
        }
    }

    func testSuccessAndExactAttestation() throws {
        let fixture = try Fixture()
        try expect(try fixture.installer().install(fixture.request()) == "INSTALL_TRANSACTION_COMMITTED")
        try expect(fixture.expectedPathsPresent())
        let attestation = try JSONSerialization.jsonObject(
            with: Data(contentsOf: fixture.physical(BootstrapInstaller.attestationPath))) as! [String: Any]
        try expect(attestation["agentOwnerIdentity"] as? String == "agentowner")
        try expect(attestation["agentOwnerUID"] as? UInt32 == 12345)
        let sudoers = try String(contentsOf: fixture.physical(BootstrapInstaller.sudoersPath),
                                 encoding: .utf8)
        try expect(sudoers.contains("agentowner ALL=(root) NOPASSWD:"))
        try expect(fixture.runner.calls.count == 1 && fixture.runner.calls[0].0 == "/usr/sbin/visudo")
    }

    func testSourceMutationAfterRootCopyCannotChangeInstalledBytes() throws {
        let fixture = try Fixture()
        let original = bootstrapSHA256(try Data(contentsOf: fixture.broker))
        fixture.hooks.afterStage = { _ in
            try FileManager.default.setAttributes([.posixPermissions: NSNumber(value: 0o600)],
                                                  ofItemAtPath: fixture.broker.path)
            try Data("mutated-source".utf8).write(to: fixture.broker)
        }
        _ = try fixture.installer().install(fixture.request())
        try expect(bootstrapSHA256(try Data(contentsOf: fixture.physical(
            BootstrapInstaller.binaryPath))) == original)
    }

    func testStagedMutationFailsBeforeEnablement() throws {
        let fixture = try Fixture()
        fixture.hooks.afterStage = { paths in
            let path = paths["policy"]!
            try FileManager.default.setAttributes([.posixPermissions: NSNumber(value: 0o600)],
                                                  ofItemAtPath: path)
            try Data("staged-corruption".utf8).write(to: URL(fileURLWithPath: path))
        }
        _ = try expectThrows { _ = try fixture.installer().install(fixture.request()) }
        try expect(fixture.expectedPathsAbsent())
    }

    func testHashSizeSymlinkAndTraversalRejections() throws {
        let hash = try Fixture()
        try FileManager.default.setAttributes([.posixPermissions: NSNumber(value: 0o600)],
                                              ofItemAtPath: hash.broker.path)
        try Data("changed".utf8).write(to: hash.broker)
        _ = try expectThrows { _ = try hash.installer().install(hash.request()) }
        try expect(hash.expectedPathsAbsent())

        let symlink = try Fixture()
        let link = symlink.sources.appendingPathComponent("broker-link")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: symlink.broker)
        _ = try expectThrows { _ = try symlink.installer().install(
            symlink.request(brokerPath: link.path)) }
        try expect(symlink.expectedPathsAbsent())

        let traversal = try Fixture()
        let path = traversal.sources.path + "/../reviewed/aid-admin"
        _ = try expectThrows { _ = try traversal.installer().install(
            traversal.request(brokerPath: path)) }
        try expect(traversal.expectedPathsAbsent())
    }

    func testOwnerModeAndUnexpectedPathRejections() throws {
        for (owner, uid, identity) in [("%admin", UInt32(12345), "name:%admin"),
                                       ("bad name", UInt32(12345), "name:bad name"),
                                       ("agentowner", UInt32(0), "uid:0"),
                                       ("agentowner", UInt32(12345), "group:admin")] {
            let fixture = try Fixture()
            _ = try expectThrows { _ = try fixture.installer().install(
                fixture.request(owner: owner, ownerUID: uid, identity: identity)) }
            try expect(fixture.expectedPathsAbsent())
        }
        let mode = try Fixture()
        try FileManager.default.setAttributes([.posixPermissions: NSNumber(value: 0o666)],
                                              ofItemAtPath: mode.policy.path)
        _ = try expectThrows { _ = try mode.installer().install(mode.request()) }
        try expect(mode.expectedPathsAbsent())

        let partial = try Fixture()
        let unexpected = partial.physical(BootstrapInstaller.binaryPath)
        try Data("partial".utf8).write(to: unexpected)
        try FileManager.default.setAttributes([.posixPermissions: NSNumber(value: 0o555)],
                                              ofItemAtPath: unexpected.path)
        _ = try expectThrows { _ = try partial.installer().install(partial.request()) }

        let targetSymlink = try Fixture()
        let outside = targetSymlink.sources.appendingPathComponent("outside-target")
        try Data("outside\n".utf8).write(to: outside)
        try FileManager.default.createSymbolicLink(
            at: targetSymlink.physical(BootstrapInstaller.binaryPath),
            withDestinationURL: outside)
        _ = try expectThrows {
            _ = try targetSymlink.installer().install(targetSymlink.request())
        }
        try expect(try String(contentsOf: outside, encoding: .utf8) == "outside\n")
    }

    func testVisudoFailureNeverEnablesSudoers() throws {
        let fixture = try Fixture()
        fixture.runner.status = 1
        _ = try expectThrows { _ = try fixture.installer().install(fixture.request()) }
        try expect(fixture.expectedPathsAbsent())
    }

    func testFailureAtEveryMutationStepRollsBackAbsentState() throws {
        for step in ["runtime-directories", "binary", "policy", "attestation", "sudoers",
                     "final-verification"] {
            let fixture = try Fixture()
            fixture.hooks.failStep = step
            let reason = try expectThrows { _ = try fixture.installer().install(fixture.request()) }
            try expect(reason.hasSuffix("_rolled_back"), reason)
            try expect(fixture.expectedPathsAbsent(), "rollback_absent_" + step)
        }
    }

    func testFailureRestoresExactPriorInstalledState() throws {
        let fixture = try Fixture()
        _ = try fixture.installer().install(fixture.request())
        let before = try fixture.fileHashes()
        fixture.hooks.failStep = "policy"
        let reason = try expectThrows { _ = try fixture.installer().install(fixture.request()) }
        try expect(reason.hasSuffix("_rolled_back"))
        try expect(try fixture.fileHashes() == before)
        try expect(fixture.expectedPathsPresent())
    }

    func testRollbackFailureIsDistinct() throws {
        let fixture = try Fixture()
        fixture.hooks.failStep = "binary"
        fixture.hooks.rollbackFails = true
        let reason = try expectThrows { _ = try fixture.installer().install(fixture.request()) }
        try expect(reason.hasSuffix("_rollback_failed"))
    }

    func testAttestationMismatchTriggersRollback() throws {
        let fixture = try Fixture()
        fixture.hooks.afterStep = { step in
            if step == "sudoers" {
                let path = fixture.physical(BootstrapInstaller.attestationPath)
                try FileManager.default.setAttributes([.posixPermissions: NSNumber(value: 0o600)],
                                                      ofItemAtPath: path.path)
                try Data("attestation-drift".utf8).write(to: path)
                try FileManager.default.setAttributes([.posixPermissions: NSNumber(value: 0o400)],
                                                      ofItemAtPath: path.path)
            }
        }
        let reason = try expectThrows { _ = try fixture.installer().install(fixture.request()) }
        try expect(reason.hasSuffix("_rollback_failed"))
        try expect(try String(contentsOf: fixture.physical(BootstrapInstaller.attestationPath),
                              encoding: .utf8) == "attestation-drift")
        try expect(try expectThrows { _ = try fixture.installer().reconcileInterruptedInstall() }.contains("UNKNOWN"))
    }

    func testRenderedSudoersAndDirectBackendRejections() throws {
        let drift = try Fixture()
        try drift.refreshInputs(renderedOverride: ArtifactPin(
            sha256: String(repeating: "0", count: 64), size: 1))
        _ = try expectThrows { _ = try drift.installer().install(drift.request()) }
        try expect(drift.expectedPathsAbsent())

        for text in [
            "Cmnd_Alias AGENT_FIRST_MAC_AID_ADMIN = ALL\n@@AGENT_OWNER@@ ALL=(root) NOPASSWD: ALL\n",
            "Cmnd_Alias AGENT_FIRST_MAC_AID_ADMIN = /run/current-system/sw/bin/darwin-rebuild\n@@AGENT_OWNER@@ ALL=(root) NOPASSWD: AGENT_FIRST_MAC_AID_ADMIN\n",
        ] {
            let fixture = try Fixture(template: text)
            _ = try expectThrows { _ = try fixture.installer().install(fixture.request()) }
            try expect(fixture.expectedPathsAbsent())
        }
    }

    func testBootstrapSelfAttestationFailsClosed() throws {
        let fixture = try Fixture()
        try fixture.refreshInputs(bootstrapOverride: ArtifactPin(
            sha256: String(repeating: "1", count: 64), size: 1))
        _ = try expectThrows { _ = try fixture.installer().install(fixture.request()) }
        try expect(fixture.expectedPathsAbsent())
    }

    func testCrashRestartMatrix() throws {
        let targets = ["aid-admin", "aid-admin-policy.json", "aid-admin-install.json",
                       "agent-first-mac-aid-admin"]
        let steps = ["journal-prepared", "runtime-directories", "final-verification"] +
            targets.flatMap { ["before-backup-" + $0, "after-backup-" + $0, "after-publication-" + $0] }
        for installed in [false, true] {
            for step in steps {
                let fixture = try Fixture()
                if installed { _ = try fixture.installer().install(fixture.request()) }
                let prior = installed ? try fixture.fileHashes() : [:]
                try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: fixture.broker.path)
                try Data("changed-broker-v2".utf8).write(to: fixture.broker)
                try FileManager.default.setAttributes([.posixPermissions: 0o555], ofItemAtPath: fixture.broker.path)
                try fixture.refreshInputs()
                try expect(try fixture.subprocess("--crash", step: step) == 77, "crash_seam_" + step)
                try expect(try fixture.subprocess("--reconcile") == 0, "restart_reconcile_" + step)
                if installed {
                    try expect(try fixture.fileHashes() == prior, "exact_restore_" + step)
                } else {
                    try expect(fixture.expectedPathsAbsent(), "absent_restore_" + step)
                }
                try expect(try fixture.installer().reconcileInterruptedInstall() == "NO_INTERRUPTED_INSTALL")
            }
        }
        for directory in ["/etc/agent-first-mac", "/var/log/agent-first-mac",
                          BootstrapInstaller.auditPath, BootstrapInstaller.brokerStagingPath] {
            for prefix in ["before-directory-publication-", "after-directory-publication-"] {
                let fixture = try Fixture()
                try expect(try fixture.subprocess("--crash", step: prefix + directory) == 77)
                try expect(try fixture.subprocess("--reconcile") == 0, "directory_restart_" + prefix + directory)
                try expect(fixture.expectedPathsAbsent())
            }
        }
    }

    func testPreparationCrashPreservesAndUnblocks() throws {
        let steps = ["preparation-intent", "preparation-directory-created",
                     "preparation-directory-recorded"] +
            ["active.json.next", "install-inputs.json", "aid-admin", "sudoers-rendered"].flatMap {
                ["preparation-file-created-" + $0, "preparation-file-written-" + $0,
                 "preparation-file-synced-" + $0]
            }
        for step in steps {
            let fixture = try Fixture()
            if step == "preparation-file-written-aid-admin" {
                try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: fixture.broker.path)
                try Data(repeating: 65, count: 128 * 1024).write(to: fixture.broker)
                try FileManager.default.setAttributes([.posixPermissions: 0o555], ofItemAtPath: fixture.broker.path)
                try fixture.refreshInputs()
            }
            try expect(try fixture.subprocess("--crash", step: step) == 77, "preparation_crash_" + step)
            try expect(fixture.expectedPathsAbsent(), "preparation_changed_live_state")
            try expect(try fixture.subprocess("--reconcile") == 0, "preparation_reconcile_" + step)
            try expect(fixture.expectedPathsAbsent(), "preparation_reconcile_changed_live_state")
            let retained = fixture.physical("/var/db/agent-first-mac/bootstrap/retained-preparations")
            try expect(retained.exists, "preparation_evidence_lost")
            if step == "preparation-file-written-aid-admin" {
                let partial = retained.appendingPathComponent("transaction-11111111-2222-3333-4444-555555555555/aid-admin")
                try expect(try Data(contentsOf: partial) == Data(repeating: 65, count: 64 * 1024),
                           "partial_write_not_preserved")
            }
            try expect(try fixture.installer().install(fixture.request()) == "INSTALL_TRANSACTION_COMMITTED",
                       "preparation_still_blocks_new_install")
        }
        let fixture = try Fixture()
        try expect(try fixture.subprocess("--crash", step: "preparation-directory-recorded") == 77)
        let stage = fixture.physical("/var/db/agent-first-mac/bootstrap/transaction-11111111-2222-3333-4444-555555555555")
        let foreign = stage.appendingPathComponent("unknown-owner-material")
        try Data("preserve-even-unknown".utf8).write(to: foreign)
        try expect(try fixture.subprocess("--reconcile") == 0)
        let retained = fixture.physical("/var/db/agent-first-mac/bootstrap/retained-preparations/transaction-11111111-2222-3333-4444-555555555555/unknown-owner-material")
        try expect(try Data(contentsOf: retained) == Data("preserve-even-unknown".utf8), "unknown_preparation_deleted")

        let interruptedRetention = try Fixture()
        try expect(try interruptedRetention.subprocess("--crash", step: "preparation-directory-recorded") == 77)
        try expect(try interruptedRetention.subprocess("--rollback-crash", step: "preparation-retained") == 77)
        try expect(try interruptedRetention.subprocess("--reconcile") == 0, "retention_cannot_restart")

        let replaced = try Fixture()
        try expect(try replaced.subprocess("--crash", step: "preparation-directory-recorded") == 77)
        let recorded = replaced.physical("/var/db/agent-first-mac/bootstrap/transaction-11111111-2222-3333-4444-555555555555")
        try FileManager.default.moveItem(at: recorded, to: recorded.appendingPathExtension("foreign-retained"))
        try FileManager.default.createDirectory(at: recorded, withIntermediateDirectories: false,
                                              attributes: [.posixPermissions: 0o700])
        try expect(try replaced.subprocess("--reconcile") == 78, "replacement_directory_adopted")
        try expect(recorded.exists && replaced.expectedPathsAbsent(), "foreign_preparation_changed")

        let unrecorded = try Fixture()
        try expect(try unrecorded.subprocess("--crash", step: "preparation-directory-created") == 77)
        let unrecordedDirectory = unrecorded.physical("/var/db/agent-first-mac/bootstrap/transaction-11111111-2222-3333-4444-555555555555")
        let unknown = unrecordedDirectory.appendingPathComponent("unknown")
        try Data("foreign".utf8).write(to: unknown)
        try expect(try unrecorded.subprocess("--reconcile") == 78, "unrecorded_nonempty_directory_adopted")
        try expect(try Data(contentsOf: unknown) == Data("foreign".utf8), "unknown_directory_erased")
    }

    func testCommittedCrashDoesNotUndoInstall() throws {
        let fixture = try Fixture()
        try expect(try fixture.subprocess("--crash", step: "journal-committed") == 77)
        let committed = try fixture.fileHashes()
        try expect(try fixture.subprocess("--reconcile") == 0)
        try expect(try fixture.fileHashes() == committed)
        try expect(fixture.expectedPathsPresent())
    }

    private var preparationID: String { "11111111-2222-3333-4444-555555555555" }
    private var retainedPath: String { "/var/db/agent-first-mac/bootstrap/retained-preparations" }

    func testPreparationRetirementExactNamespacesAndRestart() throws {
        for preparationStep in ["preparation-intent", "preparation-directory-created",
                                "preparation-directory-recorded", "preparation-file-recorded-install-inputs.json",
                                "preparation-file-recorded-aid-admin-policy.json"] {
            let fixture = try Fixture()
            try expect(try fixture.subprocess("--crash", step: preparationStep) == 77)
            try expect(try fixture.subprocess("--reconcile") == 0)
            let inventory = try fixture.installer().inventoryPreparations()
            try expect(inventory.entries.count == 1 && inventory.entries[0].status == "RETIRABLE")
            try expect(inventory.unknownEntries == 0 && !inventory.truncated && !inventory.activeInstall)
            if preparationStep.contains("recorded-aid-admin-policy") {
                try expect(inventory.entries[0].knownFiles == 3 && inventory.entries[0].knownBytes > 0)
            }
            try expect(try fixture.installer().retirePreparation(identifier: preparationID) == "PREPARATION_RETIRED")
            try expect(try fixture.installer().inventoryPreparations().observedEntries == 0)
            try expect(fixture.expectedPathsAbsent() && fixture.runner.calls.isEmpty, "retirement_touched_live_targets")
        }
        for step in ["preparation-retirement-intent", "preparation-retirement-file-install-inputs.json",
                     "preparation-retirement-file-aid-admin", "preparation-retirement-file-aid-admin-policy.json",
                     "preparation-retirement-directory"] {
            let fixture = try Fixture()
            try expect(try fixture.subprocess("--crash", step: "preparation-file-recorded-aid-admin-policy.json") == 77)
            try expect(try fixture.subprocess("--reconcile") == 0)
            try expect(try fixture.subprocess("--retire-crash", step: step) == 77, step)
            try expect(try fixture.installer().inventoryPreparations().entries[0].status == "RETIREMENT_PENDING")
            try expect(try fixture.installer().retirePreparation(identifier: preparationID) == "PREPARATION_RETIRED")
            try expect(try fixture.installer().inventoryPreparations().observedEntries == 0)
            try expect(fixture.expectedPathsAbsent())
        }
        let installed = try Fixture()
        _ = try installed.installer().install(installed.request())
        let before = try installed.fileHashes()
        try expect(try installed.subprocess("--crash", step: "preparation-file-recorded-aid-admin-policy.json") == 77)
        try expect(try installed.subprocess("--reconcile") == 0)
        _ = try installed.installer().retirePreparation(identifier: preparationID)
        try expect(try installed.fileHashes() == before && installed.expectedPathsPresent(), "retirement_changed_installed_state")
    }

    func testPreparationRetirementUnknownAndRollbackPreservation() throws {
        for attack in ["unknown-name", "allowed-name-unrecorded", "file-identity", "directory-identity",
                       "symlink", "hardlink", "missing-file", "legacy-partial", "rollback-journal",
                       "file-content", "legacy-empty-identity", "missing-directory"] {
            let fixture = try Fixture()
            try expect(try fixture.subprocess("--crash", step: "preparation-file-recorded-install-inputs.json") == 77)
            try expect(try fixture.subprocess("--reconcile") == 0)
            let directory = fixture.physical(retainedPath + "/transaction-" + preparationID)
            let journal = directory.appendingPathExtension("json")
            let file = directory.appendingPathComponent("install-inputs.json")
            if attack == "unknown-name" || attack == "allowed-name-unrecorded" {
                try Data("foreign".utf8).write(to: directory.appendingPathComponent(attack == "unknown-name" ? "foreign" : "aid-admin"))
            } else if attack == "directory-identity" || attack == "missing-directory" {
                try FileManager.default.moveItem(at: directory, to: directory.appendingPathExtension("saved"))
                if attack == "directory-identity" {
                    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false,
                                                           attributes: [.posixPermissions: 0o700])
                }
            } else if attack == "file-content" {
                try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
                try Data("changed-content".utf8).write(to: file)
                try FileManager.default.setAttributes([.posixPermissions: 0o400], ofItemAtPath: file.path)
            } else if attack == "legacy-partial" || attack == "rollback-journal" || attack == "legacy-empty-identity" {
                var record = try JSONSerialization.jsonObject(with: Data(contentsOf: journal)) as! [String: Any]
                if attack == "legacy-partial" { record["stagedFiles"] = [String: Any]() }
                else if attack == "legacy-empty-identity" {
                    record["stagedFiles"] = [String: Any](); record["directoryIdentities"] = [String: Any]()
                    try FileManager.default.removeItem(at: file)
                }
                else { record["mutationStarted"] = true; record["phase"] = "prepared" }
                try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: journal.path)
                try JSONSerialization.data(withJSONObject: record, options: [.sortedKeys]).write(to: journal)
                try FileManager.default.setAttributes([.posixPermissions: 0o400], ofItemAtPath: journal.path)
            } else {
                let bytes = try Data(contentsOf: file)
                try FileManager.default.moveItem(at: file, to: fixture.root.appendingPathComponent("saved-inputs"))
                if attack == "symlink" { try FileManager.default.createSymbolicLink(at: file, withDestinationURL: fixture.inputs) }
                else if attack == "hardlink" { try FileManager.default.linkItem(at: fixture.inputs, to: file) }
                else if attack != "missing-file" {
                    try bytes.write(to: file)
                    try FileManager.default.setAttributes([.posixPermissions: 0o400], ofItemAtPath: file.path)
                }
            }
            let before = try Data(contentsOf: journal)
            try expect(try fixture.installer().inventoryPreparations().entries[0].status == "UNKNOWN_PRESERVED", attack)
            let reason = try expectThrows { _ = try fixture.installer().retirePreparation(identifier: preparationID) }
            try expect(!reason.contains("noncanonical"), "test_journal_not_canonical_" + attack)
            try expect(try Data(contentsOf: journal) == before, "unknown_journal_changed_" + attack)
            try expect((directory.exists || attack == "missing-directory") && fixture.expectedPathsAbsent(), "unknown_state_deleted_" + attack)
        }
        let opaque = try Fixture()
        try expect(try opaque.subprocess("--crash", step: "preparation-file-created-active.json.next") == 77)
        try expect(try opaque.subprocess("--reconcile") == 0)
        let inventory = try opaque.installer().inventoryPreparations()
        try expect(inventory.unknownEntries == 1 && inventory.entries.isEmpty, "opaque_inventory_hidden")
        _ = try expectThrows { _ = try opaque.installer().retirePreparation(identifier: preparationID) }
        try expect(try opaque.installer().inventoryPreparations().unknownEntries == 1)
    }

    func testPreparationCustodyCannotAdoptOrDeleteReplacements() throws {
        let fixture = try Fixture()
        fixture.hooks.afterStep = { step in
            if step == "preparation-file-synced-aid-admin" {
                let path = fixture.physical("/var/db/agent-first-mac/bootstrap/transaction-" + preparationID + "/aid-admin")
                let bytes = try Data(contentsOf: path)
                try FileManager.default.moveItem(at: path, to: fixture.root.appendingPathComponent("saved-broker"))
                try bytes.write(to: path)
                try FileManager.default.setAttributes([.posixPermissions: 0o400], ofItemAtPath: path.path)
            }
        }
        try expect(try expectThrows { _ = try fixture.installer().install(fixture.request()) }.contains("preparation_write_identity_UNKNOWN"))
        try expect(try fixture.installer().inventoryPreparations().entries[0].status == "UNKNOWN_PRESERVED")
        try expect(fixture.expectedPathsAbsent())
        for step in ["preparation-retirement-intent", "preparation-retirement-file-install-inputs.json",
                     "preparation-retirement-directory"] {
            let fixture = try Fixture()
            try expect(try fixture.subprocess("--crash", step: "preparation-file-recorded-install-inputs.json") == 77)
            try expect(try fixture.subprocess("--reconcile") == 0)
            let marker = fixture.physical(retainedPath + "/transaction-" + preparationID + ".retiring.json")
            let foreign = Data("foreign-journal-must-survive".utf8)
            fixture.hooks.afterStep = { actual in
                if actual == step {
                    try FileManager.default.moveItem(at: marker, to: fixture.root.appendingPathComponent("saved-marker"))
                    try foreign.write(to: marker)
                    try FileManager.default.setAttributes([.posixPermissions: 0o400], ofItemAtPath: marker.path)
                }
            }
            try expect(try expectThrows { _ = try fixture.installer().retirePreparation(identifier: preparationID) }.contains("preparation_journal_identity_UNKNOWN"))
            try expect(try Data(contentsOf: marker) == foreign && fixture.expectedPathsAbsent(), "replacement_journal_deleted")
        }
    }

    func testPreparationRetirementActiveAndCapacity() throws {
        let fixture = try Fixture()
        try expect(try fixture.subprocess("--crash", step: "preparation-directory-recorded") == 77)
        try expect(try fixture.subprocess("--reconcile") == 0)
        let active = fixture.physical("/var/db/agent-first-mac/bootstrap/active.json")
        let journal = fixture.physical(retainedPath + "/transaction-" + preparationID + ".json")
        try FileManager.default.copyItem(at: journal, to: active)
        try expect(try fixture.installer().inventoryPreparations().activeInstall)
        try expect(try expectThrows { _ = try fixture.installer().retirePreparation(identifier: preparationID) }.contains("active_install"))
        try FileManager.default.removeItem(at: active)
        let staging = fixture.physical(BootstrapInstaller.brokerStagingPath)
        try FileManager.default.createDirectory(at: staging, withIntermediateDirectories: false,
                                               attributes: [.posixPermissions: 0o700])
        let operation = staging.appendingPathComponent("operation.json")
        let hash = String(repeating: "a", count: 64)
        let target = "/nix/store/" + String(repeating: "a", count: 32) + "-darwin-system-fixture"
        let record: [String: Any] = ["schema": 1, "identifier": preparationID,
            "commit": String(repeating: "a", count: 40), "tree": String(repeating: "b", count: 40),
            "policyHash": hash, "receiptHash": hash, "previousIdentifier": "1",
            "previousTarget": target, "target": target,
            "activationExecutable": "/nix/store/activation", "activationHash": hash,
            "nixEnvExecutable": "/nix/store/nix-env", "nixEnvHash": hash,
            "caller": "sudo-user", "targetIdentifier": "2", "phase": "activation_pending", "sourceDrift": false]
        try JSONSerialization.data(withJSONObject: record, options: [.sortedKeys]).write(to: operation)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: operation.path)
        _ = try expectThrows { _ = try fixture.installer().retirePreparation(identifier: preparationID) }
        try expect(journal.exists, "active_apply_retirement")
        try FileManager.default.removeItem(at: operation)
        try FileManager.default.removeItem(at: staging)
        for index in 0..<129 {
            try Data("opaque".utf8).write(to: fixture.physical(retainedPath + "/opaque-\(index)"))
        }
        let inventory = try fixture.installer().inventoryPreparations()
        try expect(inventory.truncated && inventory.observedEntries == 129)
        try expect(try expectThrows { _ = try fixture.installer().install(fixture.request()) }.contains("preparation_capacity"))
        try expect(fixture.expectedPathsAbsent())
        try expect(try fixture.installer().retirePreparation(identifier: preparationID) == "PREPARATION_RETIRED")
        try expect(try FileManager.default.contentsOfDirectory(atPath: fixture.physical(retainedPath).path).count == 129,
                   "capacity_retirement_swept_unknown")
        let repeated = try Fixture()
        for _ in 0..<66 {
            try expect(try repeated.subprocess("--crash", step: "preparation-file-recorded-install-inputs.json") == 77)
            try expect(try repeated.subprocess("--reconcile") == 0)
            _ = try repeated.installer().retirePreparation(identifier: preparationID)
        }
        try expect(try repeated.installer().inventoryPreparations().observedEntries == 0 && repeated.expectedPathsAbsent(),
                   "retirement_accumulates_capacity_debt")
    }

    func testForeignAndUntrustedRecoveryStayUnknown() throws {
        for attack in ["target", "journal-mode", "journal-symlink", "backup"] {
            let fixture = try Fixture()
            if attack == "backup" { _ = try fixture.installer().install(fixture.request()) }
            try expect(try fixture.subprocess("--crash", step: "after-publication-aid-admin") == 77)
            let journal = fixture.physical("/var/db/agent-first-mac/bootstrap/active.json")
            let target = fixture.physical(BootstrapInstaller.binaryPath)
            if attack == "target" || attack == "backup" {
                let path = attack == "target" ? target : fixture.physical(
                    "/var/db/agent-first-mac/bootstrap/transaction-11111111-2222-3333-4444-555555555555/prior-aid-admin")
                try FileManager.default.removeItem(at: path)
                try Data("foreign-do-not-delete".utf8).write(to: path)
                try FileManager.default.setAttributes([.posixPermissions: 0o555], ofItemAtPath: path.path)
                try expect(try fixture.subprocess("--reconcile") == 78)
                try expect(try String(contentsOf: path, encoding: .utf8) == "foreign-do-not-delete")
            } else if attack == "journal-mode" {
                try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: journal.path)
                try expect(try fixture.subprocess("--reconcile") == 78)
            } else {
                try FileManager.default.removeItem(at: journal)
                try FileManager.default.createSymbolicLink(at: journal, withDestinationURL: fixture.inputs)
                try expect(try fixture.subprocess("--reconcile") == 78)
            }
            try expect(target.exists)
        }
    }

    func testInstallReconcilesBeforeNewAdmission() throws {
        let fixture = try Fixture()
        try expect(try fixture.subprocess("--crash", step: "after-publication-aid-admin") == 77)
        try expect(try fixture.installer().install(fixture.request()) == "INSTALL_TRANSACTION_COMMITTED")
    }

    func testRecoveryCanItselfRestartAndLockIsExclusive() throws {
        let fixture = try Fixture()
        _ = try fixture.installer().install(fixture.request())
        let prior = try fixture.fileHashes()
        try expect(try fixture.subprocess("--crash", step: "after-publication-aid-admin-policy.json") == 77)
        try expect(try fixture.subprocess("--rollback-crash", step: "rollback-aid-admin-policy.json") == 77)
        try expect(try fixture.subprocess("--reconcile") == 0)
        try expect(try fixture.fileHashes() == prior)
        let lock = fixture.physical("/var/db/agent-first-mac/.operation.lock")
        let fd = Darwin.open(lock.path, O_RDWR | O_NOFOLLOW)
        try expect(fd >= 0)
        defer { Darwin.close(fd) }
        try expect(flock(fd, LOCK_EX | LOCK_NB) == 0)
        try expect(try fixture.subprocess("--reconcile") == 78)
        try expect(try fixture.fileHashes() == prior)
    }

    func testEmergencyRevocationNeverRepublishesGrant() throws {
        for installed in [false, true] {
            let fixture = try Fixture()
            if installed { _ = try fixture.installer().install(fixture.request()) }
            fixture.hooks.afterStep = { step in
                if step == "after-backup-agent-first-mac-aid-admin" {
                    try Data("emergency-disabled".utf8).write(to: fixture.physical(BootstrapInstaller.emergencyDisablePath))
                }
            }
            let reason = try expectThrows { _ = try fixture.installer().install(fixture.request()) }
            try expect(reason == "bootstrap_emergency_revocation_UNKNOWN")
            try expect(!fixture.physical(BootstrapInstaller.sudoersPath).exists)
            try expect(try fixture.subprocess("--reconcile") == 78)
            try expect(!fixture.physical(BootstrapInstaller.sudoersPath).exists)
        }
    }

    func testApplyJournalAdmissionAndParentIdentity() throws {
        for phase in ["complete", "rollback_verified", "activation_pending", "unknown"] {
            let fixture = try Fixture()
            _ = try fixture.installer().install(fixture.request())
            let hash = String(repeating: "a", count: 64)
            let target = "/nix/store/" + String(repeating: "a", count: 32) + "-darwin-system-fixture"
            let record: [String: Any] = ["schema": 1,
                "identifier": "11111111-2222-3333-4444-555555555555",
                "commit": String(repeating: "a", count: 40), "tree": String(repeating: "b", count: 40),
                "policyHash": hash, "receiptHash": hash, "previousIdentifier": "1",
                "previousTarget": target, "target": target,
                "activationExecutable": "/nix/store/activation", "activationHash": hash,
                "nixEnvExecutable": "/nix/store/nix-env", "nixEnvHash": hash,
                "caller": "sudo-user", "targetIdentifier": "2", "phase": phase, "sourceDrift": false]
            let path = fixture.physical(BootstrapInstaller.brokerStagingPath + "/operation.json")
            try JSONSerialization.data(withJSONObject: record, options: [.sortedKeys]).write(to: path)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path.path)
            let before = try fixture.fileHashes()
            if ["complete", "rollback_verified"].contains(phase) {
                try expect(try fixture.installer().install(fixture.request()) == "INSTALL_TRANSACTION_COMMITTED")
            } else {
                _ = try expectThrows { _ = try fixture.installer().install(fixture.request()) }
            }
            try expect(try fixture.fileHashes() == before)
        }
        let fixture = try Fixture()
        fixture.hooks.afterStep = { step in
            if step == "binary" {
                let parent = fixture.physical("/usr/local/libexec")
                try FileManager.default.moveItem(at: parent, to: fixture.physical("/usr/local/retained-libexec"))
                try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: false)
                try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: parent.path)
            }
        }
        let reason = try expectThrows { _ = try fixture.installer().install(fixture.request()) }
        try expect(reason.contains("bound_directory_drift_UNKNOWN"))
        try expect(fixture.physical("/usr/local/retained-libexec/aid-admin").exists)
        try expect(!fixture.physical(BootstrapInstaller.binaryPath).exists)
    }
}

@main
private struct TestMain {
    static func main() throws {
        if CommandLine.arguments.count == 4 {
            let mode = CommandLine.arguments[1], root = CommandLine.arguments[2]
            let context = BootstrapContext(rootPrefix: root, trustedUID: getuid(), trustedGID: getgid(),
                effectiveUID: getuid(), currentExecutablePath: root + "/reviewed/aid-admin-bootstrap",
                invokingOwner: .init(name: "agentowner", uid: 12345), fixtureMode: true)
            let hooks = TestHooks()
            hooks.afterStep = { step in if step == CommandLine.arguments[3] { _exit(77) } }
            let installer = BootstrapInstaller(context: context, runner: FakeRunner(), hooks: hooks,
                actionID: { "11111111-2222-3333-4444-555555555555" })
            do {
                if mode == "--retire-crash" { _ = try installer.retirePreparation(identifier: "11111111-2222-3333-4444-555555555555") }
                else if mode == "--reconcile" || mode == "--rollback-crash" { _ = try installer.reconcileInterruptedInstall() }
                else {
                    let inputs = root + "/reviewed/install-inputs.json"
                    let bytes = try Data(contentsOf: URL(fileURLWithPath: inputs))
                    _ = try installer.install(.init(brokerPath: root + "/reviewed/aid-admin",
                        policyPath: root + "/reviewed/aid-admin-policy.json",
                        sudoersTemplatePath: root + "/reviewed/sudoers-template", inputsPath: inputs,
                        inputsSHA256: bootstrapSHA256(bytes), inputsSize: bytes.count,
                        ownerName: "agentowner", ownerUID: 12345, sudoersIdentity: "name:agentowner"))
                }
                exit(0)
            } catch { FileHandle.standardError.write(Data("\(error)\n".utf8)); exit(78) }
        }
        let suite = BootstrapTests()
        let tests: [(String, () throws -> Void)] = [
            ("sudo_invoker_provenance_matrix", suite.testStandardSudoInvokerProvenanceMatrix),
            ("validated_invoker_request_matrix", suite.testRequestAndSudoersMustMatchValidatedInvoker),
            ("success_attestation", suite.testSuccessAndExactAttestation),
            ("source_mutation", suite.testSourceMutationAfterRootCopyCannotChangeInstalledBytes),
            ("staged_mutation", suite.testStagedMutationFailsBeforeEnablement),
            ("hash_size_symlink_traversal", suite.testHashSizeSymlinkAndTraversalRejections),
            ("owner_mode_preexisting", suite.testOwnerModeAndUnexpectedPathRejections),
            ("visudo_failure", suite.testVisudoFailureNeverEnablesSudoers),
            ("partial_failure_matrix", suite.testFailureAtEveryMutationStepRollsBackAbsentState),
            ("installed_state_rollback", suite.testFailureRestoresExactPriorInstalledState),
            ("rollback_failure", suite.testRollbackFailureIsDistinct),
            ("attestation_mismatch", suite.testAttestationMismatchTriggersRollback),
            ("sudoers_drift_direct_backend", suite.testRenderedSudoersAndDirectBackendRejections),
            ("bootstrap_self_attestation", suite.testBootstrapSelfAttestationFailsClosed),
            ("crash_restart_matrix", suite.testCrashRestartMatrix),
            ("preparation_crash_retention", suite.testPreparationCrashPreservesAndUnblocks),
            ("preparation_retirement_restart", suite.testPreparationRetirementExactNamespacesAndRestart),
            ("preparation_retirement_unknown", suite.testPreparationRetirementUnknownAndRollbackPreservation),
            ("preparation_retirement_capacity", suite.testPreparationRetirementActiveAndCapacity),
            ("preparation_custody_substitutions", suite.testPreparationCustodyCannotAdoptOrDeleteReplacements),
            ("committed_crash", suite.testCommittedCrashDoesNotUndoInstall),
            ("foreign_recovery", suite.testForeignAndUntrustedRecoveryStayUnknown),
            ("restart_before_admission", suite.testInstallReconcilesBeforeNewAdmission),
            ("recovery_restart_lock", suite.testRecoveryCanItselfRestartAndLockIsExclusive),
            ("emergency_revocation", suite.testEmergencyRevocationNeverRepublishesGrant),
            ("apply_journal_parent_identity", suite.testApplyJournalAdmissionAndParentIdentity),
        ]
        for (name, test) in tests {
            do { try test() }
            catch {
                FileHandle.standardError.write(Data("FAIL \(name): \(error)\n".utf8))
                exit(1)
            }
        }
        print("{\"invokerSemanticCases\":20,\"result\":\"pass\",\"tests\":\(tests.count)}")
    }
}
