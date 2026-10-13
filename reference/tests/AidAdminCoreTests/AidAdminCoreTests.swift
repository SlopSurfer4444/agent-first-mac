import AidAdminCore
import Darwin
import Foundation

private let commit = String(repeating: "a", count: 40)
private let tree = String(repeating: "b", count: 40)
private let actionID = "11111111-2222-3333-4444-555555555555"
private let ownerIdentity = "agentowner"
private let previousStore = "/nix/store/00000000000000000000000000000000-darwin-system-previous"
private let targetStore = "/nix/store/11111111111111111111111111111111-darwin-system-target"
private let toolStore = "/nix/store/22222222222222222222222222222222-aid-admin-tools"
private let versionStore = "/nix/store/44444444444444444444444444444444-darwin-version.json"
private let secondVersionStore = "/nix/store/55555555555555555555555555555555-darwin-version.json"
private let narHash = "sha256:" + String(repeating: "1", count: 52)

private func darwinVersionData(configurationRevision: String) -> Data {
    Data(("""
    {
      "configurationRevision": "\(configurationRevision)",
      "darwinLabel": "26.05.fixture",
      "darwinRevision": "\(String(repeating: "c", count: 40))",
      "nixpkgsRevision": "\(String(repeating: "d", count: 40))"
    }

    """).utf8)
}

private func unwrap<T>(_ value: T?, _ reason: String = "unexpected_nil") throws -> T {
    guard let value else { throw BrokerFailure.rejected(reason) }
    return value
}

private func expect(_ condition: @autoclosure () throws -> Bool,
                    _ reason: String = "expectation_failed") throws {
    if try !condition() { throw BrokerFailure.rejected(reason) }
}

private func expectThrows(_ action: () throws -> Void) throws -> String {
    do { try action() }
    catch { return String(describing: error) }
    throw BrokerFailure.rejected("expected_error_not_thrown")
}

private func pathExistsIncludingSymlink(_ path: String) -> Bool {
    var info = stat()
    return lstat(path, &info) == 0
}

private final class FakeRunner: CommandRunning {
    enum GitFault { case none, dirty, wrongBranch, unreachable }

    var gitFault: GitFault = .none
    var profileSetStatus: Int32 = 0
    var activationStatus: Int32 = 0
    var rollbackStatus: Int32 = 0
    var mutateOnProfileFailure = true
    var postApplyVerificationFailure = false
    var rollbackVerificationFailure = false
    var driftNixStoreAfterFirstInvocation = false
    var root: URL?
    var invocations: [(String, [String], [String: String])] = []
    private var nixStoreInvocations = 0

    func run(executable: String, arguments: [String], environment: [String: String]) throws -> CommandResult {
        invocations.append((executable, arguments, environment))
        if executable.hasSuffix("/usr/bin/git") {
            if arguments.contains("cat-file") && gitFault == .unreachable {
                return CommandResult(status: 1, output: "")
            }
            if arguments.contains("--show-current") {
                return CommandResult(status: 0, output: gitFault == .wrongBranch ? "topic\n" : "main\n")
            }
            if arguments.contains("--porcelain") {
                return CommandResult(status: 0, output: gitFault == .dirty ? " M flake.nix\n" : "")
            }
            if arguments.last == "HEAD" { return CommandResult(status: 0, output: commit + "\n") }
            if arguments.last == commit + "^{tree}" { return CommandResult(status: 0, output: tree + "\n") }
            return CommandResult(status: 0, output: "")
        }
        if executable.hasSuffix("/nix-store") {
            nixStoreInvocations += 1
            if driftNixStoreAfterFirstInvocation && nixStoreInvocations == 1 {
                try replaceToolApplet("nix-store", destination: "nix-malicious")
            }
            if arguments.first == "--verify-path" { return CommandResult(status: 0, output: "") }
            if arguments.starts(with: ["--query", "--hash"]) {
                return CommandResult(status: 0, output: narHash + "\n")
            }
        }
        if executable.hasSuffix("/nix-env") {
            if profileSetStatus == 0 || mutateOnProfileFailure { try createTargetGeneration() }
            return CommandResult(status: profileSetStatus, output: "profile-output-must-not-be-audited")
        }
        if executable.hasSuffix("/darwin-rebuild"), arguments == ["--switch-generation", "1"] {
            if rollbackStatus == 0 { try switchToPrevious(sabotage: rollbackVerificationFailure) }
            return CommandResult(status: rollbackStatus, output: "rollback-output-must-not-be-audited")
        }
        if executable.hasSuffix("/darwin-rebuild"), arguments == ["--switch-generation", "2"] {
            if activationStatus == 0 { try activateTarget(sabotage: postApplyVerificationFailure) }
            return CommandResult(status: activationStatus, output: "activation-output-must-not-be-audited")
        }
        return CommandResult(status: 99, output: "unexpected")
    }

    private func replaceToolApplet(_ name: String, destination: String) throws {
        let directory = try physical(toolStore + "/bin")
        try FileManager.default.setAttributes([.posixPermissions: NSNumber(value: 0o755)],
                                              ofItemAtPath: directory.path)
        let applet = directory.appendingPathComponent(name)
        try FileManager.default.removeItem(at: applet)
        try FileManager.default.createSymbolicLink(atPath: applet.path,
                                                   withDestinationPath: destination)
        try FileManager.default.setAttributes([.posixPermissions: NSNumber(value: 0o555)],
                                              ofItemAtPath: directory.path)
    }

    private func physical(_ logical: String) throws -> URL {
        try unwrap(root).appendingPathComponent(String(logical.dropFirst()))
    }

    private func replaceSymlink(_ logical: String, destination: String) throws {
        let url = try physical(logical)
        if pathExistsIncludingSymlink(url.path) { try FileManager.default.removeItem(at: url) }
        try FileManager.default.createSymbolicLink(atPath: url.path, withDestinationPath: destination)
    }

    private func createTargetGeneration() throws {
        let link = try physical("/nix/var/nix/profiles/system-2-link")
        if !pathExistsIncludingSymlink(link.path) {
            try FileManager.default.createSymbolicLink(atPath: link.path,
                                                       withDestinationPath: "../../../store/" +
                                                       URL(fileURLWithPath: targetStore).lastPathComponent)
        }
        try replaceSymlink("/nix/var/nix/profiles/system", destination: "system-2-link")
    }

    private func activateTarget(sabotage: Bool) throws {
        try replaceSymlink("/run/current-system",
                           destination: "../nix/store/" + URL(fileURLWithPath: sabotage ? previousStore : targetStore).lastPathComponent)
    }

    private func switchToPrevious(sabotage: Bool) throws {
        try replaceSymlink("/nix/var/nix/profiles/system", destination: "system-1-link")
        try replaceSymlink("/run/current-system",
                           destination: "../nix/store/" + URL(fileURLWithPath: sabotage ? targetStore : previousStore).lastPathComponent)
    }
}

private final class ResultFailingAuditWriter: AuditWriting {
    private let writer = AtomicAuditWriter()
    func write(_ record: AuditRecord, directory: String, suffix: String, maximumBytes: Int) throws {
        if suffix == "result" { throw BrokerFailure.rejected("simulated_final_audit_failure") }
        try writer.write(record, directory: directory, suffix: suffix, maximumBytes: maximumBytes)
    }
}

private final class PreFailingAuditWriter: AuditWriting {
    func write(_ record: AuditRecord, directory: String, suffix: String, maximumBytes: Int) throws {
        throw BrokerFailure.rejected("simulated_pre_audit_failure")
    }
}

private final class Fixture {
    let root: URL
    let uid = getuid()
    let runner = FakeRunner()
    private(set) var policyData = Data()
    private(set) var policyHash = ""
    private let fm = FileManager.default

    init() throws {
        let candidate = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("aid-admin-fixture." + UUID().uuidString, isDirectory: true)
        try fm.createDirectory(at: candidate, withIntermediateDirectories: true)
        guard let pointer = realpath(candidate.path, nil) else {
            throw BrokerFailure.rejected("fixture_realpath")
        }
        root = URL(fileURLWithPath: String(cString: pointer), isDirectory: true)
        free(pointer)
        runner.root = root
        try populate()
    }

    deinit { try? fm.removeItem(at: root) }

    var context: RuntimeContext {
        RuntimeContext(rootPrefix: root.path, trustedUID: uid, realUID: uid,
                       effectiveUID: 0, callerHome: physical("/home/agentowner").path,
                       callerIdentity: ownerIdentity,
                       currentExecutablePath: physical("/usr/local/libexec/aid-admin").path)
    }

    func broker(auditWriter: AuditWriting = AtomicAuditWriter(),
                expectedHash: String? = nil, context alternate: RuntimeContext? = nil) -> AidAdminBroker {
        AidAdminBroker(context: alternate ?? context, runner: runner, auditWriter: auditWriter,
                       expectedPolicyHash: expectedHash ?? policyHash,
                       actionID: { actionID })
    }

    func physical(_ logical: String) -> URL {
        root.appendingPathComponent(String(logical.dropFirst()))
    }

    func receiptURL() -> URL {
        physical("/home/agentowner/AIDev/state/phase-4/apply-receipts/\(commit).json")
    }

    func currentProfileIdentifier() throws -> String {
        let value = try fm.destinationOfSymbolicLink(atPath: physical("/nix/var/nix/profiles/system").path)
        return value.replacingOccurrences(of: "system-", with: "").replacingOccurrences(of: "-link", with: "")
    }

    func currentSystemTarget() throws -> String {
        try realpathString(physical("/run/current-system").path)
    }

    func mutatePolicy(_ mutate: (inout [String: Any]) -> Void) throws {
        var object = try unwrap(JSONSerialization.jsonObject(with: policyData) as? [String: Any])
        mutate(&object)
        policyData = try JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys])
        policyData.append(0x0a)
        policyHash = sha256Hex(policyData)
        try replaceFile("/etc/agent-first-mac/aid-admin-policy.json", data: policyData, mode: 0o444)
        try refreshReceipt(target: targetStore)
        try refreshAttestation()
    }

    func mutateReceipt(_ mutate: (inout [String: Any]) -> Void) throws {
        var object = try unwrap(JSONSerialization.jsonObject(with: Data(contentsOf: receiptURL())) as? [String: Any])
        mutate(&object)
        let data = try JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys]) + Data([0x0a])
        try replaceFile("/home/agentowner/AIDev/state/phase-4/apply-receipts/\(commit).json",
                        data: data, mode: 0o400)
    }

    func setReceiptTargetPrevious() throws { try refreshReceipt(target: previousStore) }

    func replaceToolApplet(_ name: String, destination: String) throws {
        let directory = physical(toolStore + "/bin")
        try fm.setAttributes([.posixPermissions: NSNumber(value: 0o755)],
                             ofItemAtPath: directory.path)
        let applet = directory.appendingPathComponent(name)
        try fm.removeItem(at: applet)
        try fm.createSymbolicLink(atPath: applet.path, withDestinationPath: destination)
        try fm.setAttributes([.posixPermissions: NSNumber(value: 0o555)],
                             ofItemAtPath: directory.path)
    }

    func makeToolDirectoryMutable() throws {
        try fm.setAttributes([.posixPermissions: NSNumber(value: 0o777)],
                             ofItemAtPath: physical(toolStore + "/bin").path)
    }

    func replaceTargetRevision(_ data: Data, mode: Int16 = 0o444) throws {
        let directory = physical(targetStore)
        try fm.setAttributes([.posixPermissions: NSNumber(value: 0o755)], ofItemAtPath: directory.path)
        let logical = targetStore + "/darwin-version.json"
        if pathExistsIncludingSymlink(physical(logical).path) {
            let path = physical(logical)
            var info = stat()
            if lstat(path.path, &info) == 0 && (info.st_mode & S_IFMT) != S_IFLNK {
                try fm.setAttributes([.posixPermissions: NSNumber(value: 0o600)], ofItemAtPath: path.path)
            }
            try fm.removeItem(at: path)
        }
        try writeFile(logical, data: data, mode: mode)
        try fm.setAttributes([.posixPermissions: NSNumber(value: 0o555)], ofItemAtPath: directory.path)
    }

    func removeTargetRevision() throws {
        let directory = physical(targetStore)
        let path = physical(targetStore + "/darwin-version.json")
        try fm.setAttributes([.posixPermissions: NSNumber(value: 0o755)], ofItemAtPath: directory.path)
        try fm.removeItem(at: path)
        try fm.setAttributes([.posixPermissions: NSNumber(value: 0o555)], ofItemAtPath: directory.path)
    }

    func replaceTargetRevisionWithSymlink(destination: String) throws {
        let directory = physical(targetStore)
        let path = physical(targetStore + "/darwin-version.json")
        try fm.setAttributes([.posixPermissions: NSNumber(value: 0o755)], ofItemAtPath: directory.path)
        try fm.setAttributes([.posixPermissions: NSNumber(value: 0o600)], ofItemAtPath: path.path)
        try fm.removeItem(at: path)
        try fm.createSymbolicLink(atPath: path.path, withDestinationPath: destination)
        try fm.setAttributes([.posixPermissions: NSNumber(value: 0o555)], ofItemAtPath: directory.path)
    }

    func replaceTargetRevisionWithStoreSymlink(
        data: Data = darwinVersionData(configurationRevision: commit), mode: Int16 = 0o444
    ) throws {
        try writeFile(versionStore, data: data, mode: mode)
        try replaceTargetRevisionWithSymlink(destination: versionStore)
    }

    func replaceTargetRevisionWithNestedStoreSymlink() throws {
        try writeFile(secondVersionStore,
                      data: darwinVersionData(configurationRevision: commit), mode: 0o444)
        try fm.createSymbolicLink(atPath: physical(versionStore).path,
                                  withDestinationPath: secondVersionStore)
        try replaceTargetRevisionWithSymlink(destination: versionStore)
    }

    func replaceTargetRevisionWithStoreDirectory() throws {
        try makeDirectory(versionStore, mode: 0o555)
        try replaceTargetRevisionWithSymlink(destination: versionStore)
    }

    func auditResult() throws -> Data {
        try Data(contentsOf: physical("/var/log/agent-first-mac/aid-admin/\(actionID).result.json"))
    }

    private func populate() throws {
        for directory in [
            "/etc/agent-first-mac", "/etc/sudoers.d", "/usr/local/libexec",
            "/var/log/agent-first-mac/aid-admin", "/var/db/agent-first-mac/staging",
            "/usr/bin", "/run", "/nix/store", "/nix/var/nix/profiles",
            "/home/agentowner/AIDev/control", "/home/agentowner/AIDev/state/phase-4/apply-receipts",
            previousStore, targetStore, toolStore + "/bin",
        ] {
            let restricted = directory == "/var/log/agent-first-mac/aid-admin" ||
                directory == "/var/db/agent-first-mac/staging" ||
                directory.hasSuffix("apply-receipts")
            try makeDirectory(directory, mode: restricted ? 0o700 : 0o755)
        }
        for closure in [previousStore, targetStore] {
            try makeDirectory(closure + "/sw/bin", mode: 0o755)
            try writeFile(closure + "/activate", data: Data("activate".utf8), mode: 0o555)
            try writeFile(closure + "/systemConfig", data: Data("system".utf8), mode: 0o444)
            try writeFile(closure + "/darwin-version.json",
                          data: darwinVersionData(configurationRevision: commit), mode: 0o444)
            try writeFile(closure + "/sw/bin/darwin-rebuild", data: Data("backend".utf8), mode: 0o555)
            try fm.setAttributes([.posixPermissions: NSNumber(value: 0o555)],
                                 ofItemAtPath: physical(closure + "/sw/bin").path)
            try fm.setAttributes([.posixPermissions: NSNumber(value: 0o555)],
                                 ofItemAtPath: physical(closure + "/sw").path)
            try fm.setAttributes([.posixPermissions: NSNumber(value: 0o555)],
                                 ofItemAtPath: physical(closure).path)
        }
        try writeFile(toolStore + "/bin/nix", data: Data("nix-multicall".utf8), mode: 0o555)
        try writeFile(toolStore + "/bin/nix-malicious", data: Data("wrong".utf8), mode: 0o555)
        try fm.createSymbolicLink(atPath: physical(toolStore + "/bin/nix-env").path,
                                  withDestinationPath: "nix")
        try fm.createSymbolicLink(atPath: physical(toolStore + "/bin/nix-store").path,
                                  withDestinationPath: "nix")
        try fm.setAttributes([.posixPermissions: NSNumber(value: 0o555)],
                             ofItemAtPath: physical(toolStore + "/bin").path)
        try writeFile("/usr/local/libexec/aid-admin", data: Data("fixture-binary".utf8), mode: 0o555)
        let rendered = "Cmnd_Alias AGENT_FIRST_MAC_AID_ADMIN = /usr/local/libexec/aid-admin\n" +
            "\(ownerIdentity) ALL=(root) NOPASSWD: AGENT_FIRST_MAC_AID_ADMIN\n"
        try writeFile("/etc/sudoers.d/agent-first-mac-aid-admin", data: Data(rendered.utf8), mode: 0o440)
        try writeFile("/usr/bin/git", data: Data("fake-git".utf8), mode: 0o555)
        try fm.createSymbolicLink(atPath: physical("/nix/var/nix/profiles/default").path,
                                  withDestinationPath: "../../../store/" +
                                  URL(fileURLWithPath: toolStore).lastPathComponent)
        try fm.createSymbolicLink(atPath: physical("/nix/var/nix/profiles/system-1-link").path,
                                  withDestinationPath: "../../../store/" +
                                  URL(fileURLWithPath: previousStore).lastPathComponent)
        try fm.createSymbolicLink(atPath: physical("/nix/var/nix/profiles/system").path,
                                  withDestinationPath: "system-1-link")
        try fm.createSymbolicLink(atPath: physical("/run/current-system").path,
                                  withDestinationPath: "../nix/store/" +
                                  URL(fileURLWithPath: previousStore).lastPathComponent)

        let repositoryPolicy = try Data(contentsOf: repositoryRoot().appendingPathComponent("policy/aid-admin-policy.json"))
        var object = try unwrap(JSONSerialization.jsonObject(with: repositoryPolicy) as? [String: Any])
        object["preparationOnly"] = false
        var apply = try unwrap(object["apply"] as? [String: Any])
        apply["applyGateAccepted"] = true
        object["apply"] = apply
        policyData = try JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys])
        policyData.append(0x0a)
        policyHash = sha256Hex(policyData)
        try writeFile("/etc/agent-first-mac/aid-admin-policy.json", data: policyData, mode: 0o444)
        try refreshReceipt(target: targetStore)
        try refreshAttestation()
    }

    private func refreshReceipt(target: String) throws {
        let object: [String: Any] = [
            "controlCommit": commit, "controlTree": tree, "policyHash": policyHash,
            "reviewed": true, "schema": 1, "targetSystemNarHash": narHash,
            "targetSystemPath": target,
        ]
        let data = try JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys]) + Data([0x0a])
        let logical = "/home/agentowner/AIDev/state/phase-4/apply-receipts/\(commit).json"
        if pathExistsIncludingSymlink(physical(logical).path) {
            try replaceFile(logical, data: data, mode: 0o400)
        } else {
            try writeFile(logical, data: data, mode: 0o400)
        }
    }

    private func refreshAttestation() throws {
        let binary = try Data(contentsOf: physical("/usr/local/libexec/aid-admin"))
        let sudoers = try Data(contentsOf: physical("/etc/sudoers.d/agent-first-mac-aid-admin"))
        let object: [String: Any] = [
            "agentOwnerIdentity": ownerIdentity, "agentOwnerUID": uid,
            "binarySHA256": sha256Hex(binary), "policySHA256": policyHash,
            "schema": 1, "sudoersSHA256": sha256Hex(sudoers),
        ]
        let data = try JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys]) + Data([0x0a])
        let logical = "/etc/agent-first-mac/aid-admin-install.json"
        if pathExistsIncludingSymlink(physical(logical).path) {
            try replaceFile(logical, data: data, mode: 0o400)
        } else {
            try writeFile(logical, data: data, mode: 0o400)
        }
    }

    private func repositoryRoot() -> URL {
        URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
    }

    private func makeDirectory(_ logical: String, mode: Int16) throws {
        let url = physical(logical)
        try fm.createDirectory(at: url, withIntermediateDirectories: true)
        try fm.setAttributes([.posixPermissions: NSNumber(value: mode)], ofItemAtPath: url.path)
    }

    private func writeFile(_ logical: String, data: Data, mode: Int16) throws {
        let url = physical(logical)
        try fm.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try data.write(to: url, options: .withoutOverwriting)
        try fm.setAttributes([.posixPermissions: NSNumber(value: mode)], ofItemAtPath: url.path)
    }

    private func replaceFile(_ logical: String, data: Data, mode: Int16) throws {
        let url = physical(logical)
        try fm.setAttributes([.posixPermissions: NSNumber(value: 0o600)], ofItemAtPath: url.path)
        try fm.removeItem(at: url)
        try writeFile(logical, data: data, mode: mode)
    }

    private func realpathString(_ path: String) throws -> String {
        guard let pointer = realpath(path, nil) else { throw BrokerFailure.rejected("realpath") }
        defer { free(pointer) }
        return String(cString: pointer)
    }
}

private func runProcess(_ executable: String, _ arguments: [String],
                        environment: [String: String] = BrokerPolicy.cleanEnvironment) throws -> CommandResult {
    try ProcessCommandRunner().run(executable: executable, arguments: arguments, environment: environment)
}

struct AidAdminCoreTests {
    func testCommitAndStrictSchemaRejections() throws {
        for value in ["", "abc", String(repeating: "a", count: 39), String(repeating: "A", count: 40),
                      String(repeating: "g", count: 40), commit + ";id", "../../" + commit, "$(id)"] {
            _ = try expectThrows { try validateCommit(value) }
        }
        try validateCommit(commit)
        let fixture = try Fixture()
        for mutation: (inout [String: Any]) -> Void in [
            { $0["unexpected"] = true },
            { value in var paths = value["installedPaths"] as! [String: Any]; paths["binary"] = "/usr/local/../tmp/x"; value["installedPaths"] = paths },
            { $0["allowedCommands"] = ["apply-system", "doctor-root", "install-pkg"] },
        ] {
            var object = try unwrap(JSONSerialization.jsonObject(with: fixture.policyData) as? [String: Any])
            mutation(&object)
            let data = try JSONSerialization.data(withJSONObject: object)
            _ = try expectThrows { _ = try BrokerPolicy.decodeStrict(data) }
        }
    }

    func testAutonomousApplyCreatesNewGenerationFromUnlinkedClosure() throws {
        setenv("PATH", "/tmp/poison", 1)
        setenv("SECRET_TOKEN", "must-not-cross-boundary", 1)
        let fixture = try Fixture()
        try expect(!pathExistsIncludingSymlink(fixture.physical("/nix/var/nix/profiles/system-2-link").path))
        try expect(try fixture.broker().applySystem(commit: commit) == 0)
        try expect(pathExistsIncludingSymlink(fixture.physical("/nix/var/nix/profiles/system-2-link").path))
        try expect(try fixture.currentProfileIdentifier() == "2")
        try expect(try fixture.currentSystemTarget().hasSuffix(URL(fileURLWithPath: targetStore).lastPathComponent))
        let nixEnv = fixture.runner.invocations.first { $0.0.hasSuffix("/nix-env") }
        try expect(nixEnv?.1 == ["--profile", "/nix/var/nix/profiles/system", "--set", targetStore])
        let activation = fixture.runner.invocations.first { $0.0.hasSuffix("/darwin-rebuild") }
        try expect(activation?.1 == ["--switch-generation", "2"])
        try expect(activation?.2["SECRET_TOKEN"] == nil && activation?.2["PATH"] == "/usr/bin:/bin")
        try expect(activation?.2["SUDO_USER"] == ownerIdentity)
        let audit = String(decoding: try fixture.auditResult(), as: UTF8.self)
        try expect(!audit.contains("must-not-cross-boundary") && !audit.contains("activation-output"))
        try expect(!audit.contains(fixture.root.path))
    }

    func testNoOpRepeatDoesNotCreateGeneration() throws {
        let fixture = try Fixture()
        try fixture.setReceiptTargetPrevious()
        try expect(try fixture.broker().applySystem(commit: commit) == 0)
        try expect(try fixture.currentProfileIdentifier() == "1")
        try expect(!pathExistsIncludingSymlink(fixture.physical("/nix/var/nix/profiles/system-2-link").path))
        try expect(fixture.runner.invocations.allSatisfy { !$0.0.hasSuffix("/nix-env") && !$0.0.hasSuffix("/darwin-rebuild") })
        let audit = try JSONSerialization.jsonObject(with: fixture.auditResult()) as! [String: Any]
        try expect(audit["outcome"] as? String == "already_current")
    }

    func testMulticallAppletDispatchPreservesBasenameAndRejectsDrift() throws {
        let positive = try Fixture()
        try expect(try positive.broker().applySystem(commit: commit) == 0)
        let appletCalls = positive.runner.invocations.filter {
            ["nix-store", "nix-env"].contains(URL(fileURLWithPath: $0.0).lastPathComponent)
        }
        try expect(appletCalls.contains { $0.0.hasSuffix("/nix-store") &&
            $0.1.first == "--verify-path" })
        try expect(appletCalls.contains { $0.0.hasSuffix("/nix-store") &&
            $0.1.starts(with: ["--query", "--hash"]) })
        try expect(appletCalls.contains { $0.0.hasSuffix("/nix-env") &&
            $0.1.starts(with: ["--profile", "/nix/var/nix/profiles/system", "--set"]) })
        try expect(positive.runner.invocations.allSatisfy {
            URL(fileURLWithPath: $0.0).lastPathComponent != "nix"
        }, "canonical_multicall_target_dispatched")

        for (name, destination) in [("nix-store", "nix-env"),
                                    ("nix-store", "nix-malicious"),
                                    ("nix-env", "nix-store")] {
            let fixture = try Fixture()
            try fixture.replaceToolApplet(name, destination: destination)
            _ = try expectThrows { _ = try fixture.broker().applySystem(commit: commit) }
            try expect(fixture.runner.invocations.allSatisfy {
                !$0.0.hasSuffix("/nix-env") && !$0.0.hasSuffix("/darwin-rebuild")
            })
        }

        let mutableParent = try Fixture()
        try mutableParent.makeToolDirectoryMutable()
        _ = try expectThrows { _ = try mutableParent.broker().applySystem(commit: commit) }
        try expect(mutableParent.runner.invocations.isEmpty)

        let drift = try Fixture()
        drift.runner.driftNixStoreAfterFirstInvocation = true
        _ = try expectThrows { _ = try drift.broker().applySystem(commit: commit) }
        try expect(drift.runner.invocations.allSatisfy {
            !$0.0.hasSuffix("/nix-env") && !$0.0.hasSuffix("/darwin-rebuild")
        }, "nix_applet_drift_reached_mutation")
    }

    func testClosureRevisionIsAuthoritativeAndStrict() throws {
        func expectRevisionRejection(_ configure: (Fixture) throws -> Void) throws {
            let fixture = try Fixture()
            try configure(fixture)
            _ = try expectThrows { _ = try fixture.broker().applySystem(commit: commit) }
            try expect(fixture.runner.invocations.allSatisfy {
                !$0.0.hasSuffix("/nix-env") && !$0.0.hasSuffix("/darwin-rebuild")
            })
            try expect(!pathExistsIncludingSymlink(fixture.physical(
                "/var/log/agent-first-mac/aid-admin/\(actionID).pre.json").path),
                "revision_failure_reached_pre_audit")
        }

        try expectRevisionRejection { fixture in
            try fixture.replaceTargetRevision(
                darwinVersionData(configurationRevision: String(repeating: "e", count: 40)))
        }
        try expectRevisionRejection { fixture in
            try fixture.replaceTargetRevision(
                darwinVersionData(configurationRevision: commit + "-dirty"))
        }
        try expectRevisionRejection { try $0.removeTargetRevision() }
        try expectRevisionRejection { try $0.replaceTargetRevision(Data("{".utf8)) }
        try expectRevisionRejection { fixture in
            try fixture.replaceTargetRevision(Data(("""
            {
              "configurationRevision": null,
              "darwinLabel": "26.05.fixture",
              "darwinRevision": "\(String(repeating: "c", count: 40))",
              "nixpkgsRevision": "\(String(repeating: "d", count: 40))"
            }
            """).utf8))
        }
        try expectRevisionRejection { fixture in
            try fixture.replaceTargetRevision(Data(("""
            {
              "configurationRevision": "\(commit)",
              "darwinLabel": "26.05.fixture",
              "darwinRevision": "\(String(repeating: "c", count: 40))",
              "nixpkgsRevision": "\(String(repeating: "d", count: 40))",
              "unexpected": "value"
            }
            """).utf8))
        }
        try expectRevisionRejection { fixture in
            try fixture.replaceTargetRevision(Data(("""
            {
              "configurationRevision": "\(commit)",
              "configurationRevision": "\(String(repeating: "e", count: 40))",
              "darwinLabel": "26.05.fixture",
              "darwinRevision": "\(String(repeating: "c", count: 40))",
              "nixpkgsRevision": "\(String(repeating: "d", count: 40))"
            }
            """).utf8))
        }
        try expectRevisionRejection {
            try $0.replaceTargetRevisionWithSymlink(destination: "../systemConfig")
        }
        try expectRevisionRejection {
            try $0.replaceTargetRevisionWithSymlink(destination: "/private/tmp/darwin-version.json")
        }
        try expectRevisionRejection {
            try $0.replaceTargetRevisionWithSymlink(
                destination: "/nix/store/44444444444444444444444444444444-darwin-version.json.extra")
        }
        try expectRevisionRejection {
            try $0.replaceTargetRevisionWithNestedStoreSymlink()
        }
        try expectRevisionRejection {
            try $0.replaceTargetRevisionWithStoreDirectory()
        }
        try expectRevisionRejection {
            try $0.replaceTargetRevisionWithStoreSymlink(mode: 0o666)
        }
        try expectRevisionRejection {
            try $0.replaceTargetRevisionWithStoreSymlink(data: Data("{".utf8))
        }
        try expectRevisionRejection { fixture in
            try fixture.replaceTargetRevisionWithStoreSymlink(
                data: darwinVersionData(configurationRevision: String(repeating: "e", count: 40)))
        }
        try expectRevisionRejection {
            try $0.replaceTargetRevision(darwinVersionData(configurationRevision: commit), mode: 0o666)
        }

        let liveLayout = try Fixture()
        try liveLayout.replaceTargetRevisionWithStoreSymlink()
        try expect(try liveLayout.broker().applySystem(commit: commit) == 0)
        try expect(try liveLayout.currentProfileIdentifier() == "2")
        try expect(try liveLayout.currentSystemTarget().hasSuffix(
            URL(fileURLWithPath: targetStore).lastPathComponent))
    }

    func testAuditAndDoctorAreStableRedacted() throws {
        let first = try Fixture()
        let second = try Fixture()
        try expect(try first.broker().applySystem(commit: commit) == 0)
        try expect(try second.broker().applySystem(commit: commit) == 0)
        try expect(try first.auditResult() == second.auditResult())
        let fixture = try Fixture()
        let one = try encodeDoctorJSON(fixture.broker().doctorRoot())
        let two = try encodeDoctorJSON(fixture.broker().doctorRoot())
        try expect(one == two && one.contains("ROOT_CONTRACT_READY"))
        try expect(!one.contains(fixture.root.path) && !one.contains(ownerIdentity))
    }

    func testGitBoundaryUsesFixedArgumentsAndEnvironment() throws {
        let fixture = try Fixture()
        try fixture.setReceiptTargetPrevious()
        try expect(try fixture.broker().applySystem(commit: commit) == 0)
        let repository = fixture.physical("/home/agentowner/AIDev/control").path
        let gitCalls = fixture.runner.invocations.filter { $0.0.hasSuffix("/usr/bin/git") }
        try expect(!gitCalls.isEmpty)
        for call in gitCalls {
            try expect(call.1.starts(with: fixedGitArguments(repository: repository, command: [])))
            try expect(call.2 == fixedGitEnvironment(base: BrokerPolicy.cleanEnvironment))
            try expect(call.2["SUDO_UID"] == nil && call.2["SECRET_TOKEN"] == nil)
        }

        let realRoot = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("aid-admin-git-fixture." + UUID().uuidString)
        try FileManager.default.createDirectory(at: realRoot, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: realRoot) }
        for arguments in [["init", "-q"], ["config", "user.name", "Fixture"],
                          ["config", "user.email", "fixture.invalid@example.invalid"]] {
            let result = try runProcess("/usr/bin/git", ["-C", realRoot.path] + arguments)
            try expect(result.status == 0, result.output)
        }
        let tracked = realRoot.appendingPathComponent("tracked")
        try Data("value\n".utf8).write(to: tracked)
        _ = try runProcess("/usr/bin/git", ["-C", realRoot.path, "add", "tracked"])
        try expect(try runProcess("/usr/bin/git", ["-C", realRoot.path, "commit", "-q", "-m", "fixture"]).status == 0)
        let marker = realRoot.appendingPathComponent("fsmonitor-ran")
        let monitor = realRoot.appendingPathComponent("malicious-fsmonitor")
        try Data("#!/bin/sh\n/usr/bin/touch \"\(marker.path)\"\nexit 0\n".utf8).write(to: monitor)
        try FileManager.default.setAttributes([.posixPermissions: NSNumber(value: 0o755)], ofItemAtPath: monitor.path)
        try expect(try runProcess("/usr/bin/git", ["-C", realRoot.path, "config", "core.fsmonitor", monitor.path]).status == 0)
        let safe = try runProcess("/usr/bin/git",
                                  fixedGitArguments(repository: realRoot.path,
                                                    command: ["status", "--porcelain", "--untracked-files=normal"]),
                                  environment: fixedGitEnvironment(base: BrokerPolicy.cleanEnvironment))
        try expect(safe.status == 0, safe.output)
        try expect(!marker.isFileURL || !FileManager.default.fileExists(atPath: marker.path),
                   "fsmonitor_executed")
    }

    func testGitProvenanceAndReceiptBoundariesFailClosed() throws {
        for fault in [FakeRunner.GitFault.dirty, .wrongBranch, .unreachable] {
            let fixture = try Fixture()
            fixture.runner.gitFault = fault
            _ = try expectThrows { _ = try fixture.broker().applySystem(commit: commit) }
            try expect(fixture.runner.invocations.allSatisfy { $0.0.hasSuffix("/usr/bin/git") })
        }
        let traversal = try Fixture()
        try traversal.mutateReceipt { $0["targetSystemPath"] = "/nix/store/../mutable" }
        _ = try expectThrows { _ = try traversal.broker().applySystem(commit: commit) }
        try expect(traversal.runner.invocations.allSatisfy { $0.0.hasSuffix("/usr/bin/git") })

        let symlink = try Fixture()
        let receipt = symlink.receiptURL()
        let outside = receipt.deletingLastPathComponent().appendingPathComponent("outside.json")
        try FileManager.default.setAttributes([.posixPermissions: NSNumber(value: 0o600)], ofItemAtPath: receipt.path)
        try FileManager.default.moveItem(at: receipt, to: outside)
        try FileManager.default.createSymbolicLink(at: receipt, withDestinationURL: outside)
        _ = try expectThrows { _ = try symlink.broker().applySystem(commit: commit) }
    }

    func testOwnerModePolicyAttestationAndTargetFailuresCloseGate() throws {
        let other = try Fixture()
        let context = RuntimeContext(rootPrefix: other.root.path, trustedUID: other.uid,
                                     realUID: other.uid, effectiveUID: 0,
                                     callerHome: other.physical("/home/agentowner").path,
                                     callerIdentity: "differentowner",
                                     currentExecutablePath: other.physical("/usr/local/libexec/aid-admin").path)
        try expect(other.broker(context: context).doctorRoot().verdict == "BLOCKED")

        for target in ["/etc/agent-first-mac/aid-admin-policy.json",
                       "/etc/agent-first-mac/aid-admin-install.json",
                       "/usr/local/libexec/aid-admin", "/usr/bin/git",
                       "/var/log/agent-first-mac/aid-admin", "/var/db/agent-first-mac/staging",
                       targetStore] {
            let fixture = try Fixture()
            try FileManager.default.setAttributes([.posixPermissions: NSNumber(value: 0o777)],
                                                  ofItemAtPath: fixture.physical(target).path)
            _ = try expectThrows { _ = try fixture.broker().applySystem(commit: commit) }
            try expect(fixture.runner.invocations.allSatisfy { invocation in
                invocation.0.hasSuffix("/usr/bin/git") || invocation.0.hasSuffix("/nix-store")
            })
        }
        let drift = try Fixture()
        _ = try expectThrows {
            _ = try drift.broker(expectedHash: String(repeating: "0", count: 64)).applySystem(commit: commit)
        }
        try expect(drift.runner.invocations.isEmpty)

        let absent = try Fixture()
        try absent.mutateReceipt {
            $0["targetSystemPath"] = "/nix/store/33333333333333333333333333333333-darwin-system-absent"
        }
        _ = try expectThrows { _ = try absent.broker().applySystem(commit: commit) }
        try expect(absent.runner.invocations.allSatisfy { $0.0.hasSuffix("/usr/bin/git") })

        let narDrift = try Fixture()
        try narDrift.mutateReceipt { $0["targetSystemNarHash"] = "sha256:" + String(repeating: "2", count: 52) }
        _ = try expectThrows { _ = try narDrift.broker().applySystem(commit: commit) }
        try expect(narDrift.runner.invocations.allSatisfy {
            $0.0.hasSuffix("/usr/bin/git") || $0.0.hasSuffix("/nix-store")
        })

        let callerWritable = try Fixture()
        try FileManager.default.setAttributes([.posixPermissions: NSNumber(value: 0o666)],
                                              ofItemAtPath: callerWritable.receiptURL().path)
        _ = try expectThrows { _ = try callerWritable.broker().applySystem(commit: commit) }
        try expect(callerWritable.runner.invocations.allSatisfy { $0.0.hasSuffix("/usr/bin/git") })

        let rollbackPrerequisite = try Fixture()
        let currentSystem = rollbackPrerequisite.physical("/run/current-system")
        try FileManager.default.removeItem(at: currentSystem)
        try FileManager.default.createSymbolicLink(atPath: currentSystem.path,
            withDestinationPath: "../nix/store/" + URL(fileURLWithPath: targetStore).lastPathComponent)
        _ = try expectThrows { _ = try rollbackPrerequisite.broker().applySystem(commit: commit) }
        try expect(rollbackPrerequisite.runner.invocations.allSatisfy {
            $0.0.hasSuffix("/usr/bin/git") || $0.0.hasSuffix("/nix-store")
        })
    }

    func testPreAuditAndPreparationGateNeverMutateProfile() throws {
        let audit = try Fixture()
        _ = try expectThrows { _ = try audit.broker(auditWriter: PreFailingAuditWriter()).applySystem(commit: commit) }
        try expect(try audit.currentProfileIdentifier() == "1")
        try expect(audit.runner.invocations.allSatisfy { !$0.0.hasSuffix("/nix-env") && !$0.0.hasSuffix("/darwin-rebuild") })

        let gate = try Fixture()
        try gate.mutatePolicy { value in
            value["preparationOnly"] = true
            var apply = value["apply"] as! [String: Any]
            apply["applyGateAccepted"] = false
            value["apply"] = apply
        }
        _ = try expectThrows { _ = try gate.broker().applySystem(commit: commit) }
        try expect(gate.runner.invocations.isEmpty)
    }

    func testActivationFailureRollbackIsExactAndKeepsGeneration() throws {
        let fixture = try Fixture()
        fixture.runner.activationStatus = 23
        try expect(try fixture.broker().applySystem(commit: commit) == 23)
        try expect(try fixture.currentProfileIdentifier() == "1")
        try expect(try fixture.currentSystemTarget().hasSuffix(URL(fileURLWithPath: previousStore).lastPathComponent))
        try expect(pathExistsIncludingSymlink(fixture.physical("/nix/var/nix/profiles/system-2-link").path),
                   "accepted_state_deleted")
        let audit = try JSONSerialization.jsonObject(with: fixture.auditResult()) as! [String: Any]
        try expect(audit["outcome"] as? String == "activation_failed_rolled_back")
    }

    func testPostApplyVerificationFailureRollsBackExactly() throws {
        let fixture = try Fixture()
        fixture.runner.postApplyVerificationFailure = true
        try expect(try fixture.broker().applySystem(commit: commit) == 70)
        try expect(try fixture.currentProfileIdentifier() == "1")
        try expect(try fixture.currentSystemTarget().hasSuffix(URL(fileURLWithPath: previousStore).lastPathComponent))
        let audit = try JSONSerialization.jsonObject(with: fixture.auditResult()) as! [String: Any]
        try expect(audit["outcome"] as? String == "post_apply_verification_failed_rolled_back")
    }

    func testFinalAuditFailureRollsBackExactly() throws {
        let fixture = try Fixture()
        let reason = try expectThrows {
            _ = try fixture.broker(auditWriter: ResultFailingAuditWriter()).applySystem(commit: commit)
        }
        try expect(reason == "final_audit_failed_rolled_back")
        try expect(try fixture.currentProfileIdentifier() == "1")
        try expect(try fixture.currentSystemTarget().hasSuffix(URL(fileURLWithPath: previousStore).lastPathComponent))
    }

    func testRollbackCommandAndVerificationFailuresAreDistinct() throws {
        let commandFailure = try Fixture()
        commandFailure.runner.activationStatus = 23
        commandFailure.runner.rollbackStatus = 31
        let commandReason = try expectThrows {
            _ = try commandFailure.broker().applySystem(commit: commit)
        }
        try expect(commandReason == "activation_failed_rollback_command_failed")

        let verificationFailure = try Fixture()
        verificationFailure.runner.activationStatus = 23
        verificationFailure.runner.rollbackVerificationFailure = true
        let verificationReason = try expectThrows {
            _ = try verificationFailure.broker().applySystem(commit: commit)
        }
        try expect(verificationReason == "activation_failed_rollback_verification_failed")
    }

    func testProfileUpdateFailureAlsoRollsBackUncertainMutation() throws {
        let fixture = try Fixture()
        fixture.runner.profileSetStatus = 19
        try expect(try fixture.broker().applySystem(commit: commit) == 19)
        try expect(try fixture.currentProfileIdentifier() == "1")
        let backends = fixture.runner.invocations.filter { $0.0.hasSuffix("/nix-env") || $0.0.hasSuffix("/darwin-rebuild") }
        try expect(backends.map(\.1) == [
            ["--profile", "/nix/var/nix/profiles/system", "--set", targetStore],
            ["--switch-generation", "1"],
        ])
    }
}

@main
struct TestMain {
    static func main() throws {
        let suite = AidAdminCoreTests()
        let tests: [(String, () throws -> Void)] = [
            ("commit_and_schema", suite.testCommitAndStrictSchemaRejections),
            ("autonomous_generation_creation", suite.testAutonomousApplyCreatesNewGenerationFromUnlinkedClosure),
            ("repeat_noop", suite.testNoOpRepeatDoesNotCreateGeneration),
            ("multicall_applet_dispatch", suite.testMulticallAppletDispatchPreservesBasenameAndRejectsDrift),
            ("closure_revision_binding", suite.testClosureRevisionIsAuthoritativeAndStrict),
            ("stable_redacted_output", suite.testAuditAndDoctorAreStableRedacted),
            ("safe_git_boundary", suite.testGitBoundaryUsesFixedArgumentsAndEnvironment),
            ("git_and_receipt_rejections", suite.testGitProvenanceAndReceiptBoundariesFailClosed),
            ("owner_mode_attestation_target", suite.testOwnerModePolicyAttestationAndTargetFailuresCloseGate),
            ("preaudit_and_gate", suite.testPreAuditAndPreparationGateNeverMutateProfile),
            ("activation_rollback", suite.testActivationFailureRollbackIsExactAndKeepsGeneration),
            ("post_verify_rollback", suite.testPostApplyVerificationFailureRollsBackExactly),
            ("final_audit_rollback", suite.testFinalAuditFailureRollsBackExactly),
            ("rollback_failure_distinction", suite.testRollbackCommandAndVerificationFailuresAreDistinct),
            ("profile_failure_rollback", suite.testProfileUpdateFailureAlsoRollsBackUncertainMutation),
        ]
        for (name, test) in tests {
            do { try test() }
            catch {
                FileHandle.standardError.write(Data("FAIL \(name): \(error)\n".utf8))
                exit(1)
            }
        }
        print("{\"result\":\"pass\",\"tests\":\(tests.count)}")
    }
}
