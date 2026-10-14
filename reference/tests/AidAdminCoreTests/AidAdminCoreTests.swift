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
private let fixtureBoot = String(repeating: "e", count: 64)

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
    var checkoutDriftAfterActivation = false
    var duringMutation: (() throws -> Void)?
    var afterActivation: (() throws -> Void)?
    var postValidationUnknown = false
    var activationUnknown = false
    private var activationAttempted = false
    var rollbackVerificationFailure = false
    var driftNixStoreAfterFirstInvocation = false
    var root: URL?
    var invocations: [(String, [String], [String: String])] = []
    private var nixStoreInvocations = 0

    func run(executable: String, arguments: [String], environment: [String: String]) throws -> CommandResult {
        invocations.append((executable, arguments, environment))
        if executable.hasSuffix("/bin/launchctl") {
            if arguments == ["print", "system"] { return CommandResult(status: 0, output: "system = {\n}\n") }
            if arguments == ["print-disabled", "system"] { return CommandResult(status: 0, output: "disabled services = {\n}\n") }
            if arguments == ["print", "system/org.nixos.activate-system"] {
                let path = try physical("/Library/LaunchDaemons/org.nixos.activate-system.plist").path
                return CommandResult(status: 0, output: "system/org.nixos.activate-system = {\n\tpath = \(path)\n\tprogram = /bin/sh\n\targuments = {\n\t\t/bin/sh\n\t\t-c\n\t\tfixture-boot\n\t}\n\tstate = not running\n\truns = 1\n}\n")
            }
        }
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
            if postValidationUnknown && activationAttempted {
                throw BrokerFailure.rejected("process_unknown_needs_reconcile")
            }
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
            try duringMutation?()
            if profileSetStatus == 0 || mutateOnProfileFailure { try createTargetGeneration() }
            return CommandResult(status: profileSetStatus, output: "profile-output-must-not-be-audited")
        }
        if executable.hasSuffix("/darwin-rebuild"), arguments == ["--switch-generation", "1"] {
            if rollbackStatus == 0 { try switchToPrevious(sabotage: rollbackVerificationFailure) }
            return CommandResult(status: rollbackStatus, output: "rollback-output-must-not-be-audited")
        }
        if executable.hasSuffix("/darwin-rebuild"), arguments == ["--switch-generation", "2"] {
            activationAttempted = true
            if activationUnknown { throw BrokerFailure.rejected("process_unknown_needs_reconcile") }
            try createTargetGeneration()
            if activationStatus == 0 { try activateTarget(sabotage: postApplyVerificationFailure) }
            if checkoutDriftAfterActivation { gitFault = .dirty }
            try afterActivation?()
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

private func prepareResumeHomeManagerFixture(_ fixture: Fixture) throws {
    let wrapper = "/nix/store/" + String(repeating: "6", count: 32) + "-activation-agentowner"
    let generation = "/nix/store/" + String(repeating: "7", count: 32) + "-home-manager-generation"
    let fonts = "/nix/store/" + String(repeating: "8", count: 32) + "-home-manager-fonts"
    let marker = "/nix/store/" + String(repeating: "9", count: 32) + "-font-marker"
    let rsync = "/nix/store/" + String(repeating: "a", count: 32) + "-rsync-3.4.4/bin/rsync"
    let home = "/Users/agentowner"
    let destination = home + "/Library/Fonts/HomeManager"
    func write(_ path: String, _ text: String, mode: mode_t = 0o444) throws {
        let url = fixture.physical(path)
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        chmod(url.path, 0o644)
        try Data(text.utf8).write(to: url)
        chmod(url.path, mode)
    }
    let targetScript = try String(contentsOf: fixture.physical(targetStore + "/activate"), encoding: .utf8)
    try write(targetStore + "/activate", targetScript + "launchctl asuser \"$(id -u agentowner)\" sudo -u agentowner --set-home \"${hmDryRunArgs[@]}\" " + wrapper + "\n", mode: 0o555)
    try write(wrapper, "#!/nix/store/" + String(repeating: "b", count: 32) + "-bash/bin/bash\n\nexec " + generation + "/activate --driver-version 1 >&2\n")
    try write(marker, fonts)
    let activation = """
    _iNote "Activating %s" "checkFilesChanged"
    _cmp \(marker) \(home)/Library/Fonts/.home-manager-fonts-version \\
      && changedFiles[Library/Fonts/.home-manager-fonts-version]=0 \\
      || changedFiles[Library/Fonts/.home-manager-fonts-version]=1
    _iNote "Activating %s" "linkGeneration"
    # only synthetic files, never executed
    _iNote "Activating %s" "onFilesChange"
    if (( ${changedFiles[Library/Fonts/.home-manager-fonts-version]} == 1 )); then
      if [[ -v DRY_RUN || -v VERBOSE ]]; then
        echo "Running onChange hook for" Library/Fonts/.home-manager-fonts-version
      fi
      if [[ ! -v DRY_RUN ]]; then
        run mkdir -p \(destination)
    run \(rsync) $VERBOSE_ARG -acL --chmod=u+w --delete \\
      \(fonts)/share/fonts/ \(destination)

      fi
    fi

    _iNote "Activating %s" "setupLaunchAgents"
    """
    try write(generation + "/activate", activation)
    try FileManager.default.createDirectory(at: fixture.physical(fonts + "/share/fonts"), withIntermediateDirectories: true)
    try FileManager.default.createDirectory(at: fixture.physical(destination), withIntermediateDirectories: true)
    for path in [generation, fonts, fonts + "/share", fonts + "/share/fonts"] { chmod(fixture.physical(path).path, 0o555) }
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
                expectedHash: String? = nil, context alternate: RuntimeContext? = nil,
                boot: String = fixtureBoot, checkpoint: @escaping (String) throws -> Void = { _ in }) -> AidAdminBroker {
        AidAdminBroker(context: alternate ?? context, runner: runner, auditWriter: auditWriter,
                       expectedPolicyHash: expectedHash ?? policyHash,
                       actionID: { actionID }, operationCheckpoint: checkpoint, bootGeneration: { boot })
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

    func testFinalAuditFailurePreservesCommitAndReconciles() throws {
        let fixture = try Fixture()
        let reason = try expectThrows {
            _ = try fixture.broker(auditWriter: ResultFailingAuditWriter()).applySystem(commit: commit)
        }
        try expect(reason == "applied_audit_incomplete_needs_reconcile")
        try expect(try fixture.currentProfileIdentifier() == "2")
        try expect(try fixture.currentSystemTarget().hasSuffix(URL(fileURLWithPath: targetStore).lastPathComponent))
        try expect(fixture.broker().doctorRoot().verdict == "BLOCKED")
        let before = fixture.runner.invocations.count
        try expect(try fixture.broker().applySystem(commit: commit) == 0)
        try expect(fixture.runner.invocations.dropFirst(before).allSatisfy {
            !$0.0.hasSuffix("/nix-env") && !$0.0.hasSuffix("/darwin-rebuild")
        })
        try expect(fixture.broker().doctorRoot().verdict == "ROOT_CONTRACT_READY")
    }

    func testSealedApplyDoesNotRollbackForCheckoutDrift() throws {
        let fixture = try Fixture()
        fixture.runner.checkoutDriftAfterActivation = true
        try expect(try fixture.broker().applySystem(commit: commit) == 0)
        try expect(try fixture.currentProfileIdentifier() == "2")
        try expect(fixture.runner.invocations.filter { $0.0.hasSuffix("/darwin-rebuild") }.count == 1)
        let data = try Data(contentsOf: fixture.physical("/var/db/agent-first-mac/staging/operation.json"))
        let journal = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        try expect(journal["sourceDrift"] as? Bool == true)
        try expect(journal["phase"] as? String == "complete")
    }

    func testAuditFailureBoundariesNeverInvertVisibleApplied() throws {
        for phase in ["before_open", "after_write", "after_file_sync", "after_rename", "after_directory_sync"] {
            let fixture = try Fixture()
            let writer = AtomicAuditWriter(checkpoint: { suffix, observed in
                if suffix == "result" && observed == phase { throw BrokerFailure.rejected("fixture_audit_io") }
            })
            let reason = try expectThrows { _ = try fixture.broker(auditWriter: writer).applySystem(commit: commit) }
            try expect(reason == "applied_audit_incomplete_needs_reconcile", phase)
            try expect(try fixture.currentProfileIdentifier() == "2", phase)
            try expect(fixture.runner.invocations.filter { $0.0.hasSuffix("/darwin-rebuild") }.count == 1)
            if ["after_rename", "after_directory_sync"].contains(phase) {
                let visible = try JSONSerialization.jsonObject(with: fixture.auditResult()) as! [String: Any]
                try expect(visible["outcome"] as? String == "applied")
            }
            try expect(try fixture.broker().applySystem(commit: commit) == 0)
            try expect(fixture.runner.invocations.filter { $0.0.hasSuffix("/darwin-rebuild") }.count == 1)
        }
    }

    func testUnknownVerificationAndForeignPreviousNeverRollback() throws {
        let unknown = try Fixture()
        unknown.runner.postValidationUnknown = true
        let reason = try expectThrows { _ = try unknown.broker().applySystem(commit: commit) }
        try expect(reason == "verification_process_unknown_no_rollback")
        try expect(unknown.runner.invocations.filter { $0.0.hasSuffix("/darwin-rebuild") }.count == 1)
        try expect(try unknown.broker().inspectOperation()["state"] == "unknown")

        let foreign = try Fixture()
        foreign.runner.activationStatus = 23
        foreign.runner.afterActivation = {
            let previous = foreign.physical("/nix/var/nix/profiles/system-1-link")
            try FileManager.default.removeItem(at: previous)
            try FileManager.default.createSymbolicLink(atPath: previous.path,
                withDestinationPath: foreign.physical(targetStore).path)
        }
        let foreignReason = try expectThrows { _ = try foreign.broker().applySystem(commit: commit) }
        try expect(foreignReason == "previous_generation_drift_unknown_no_rollback")
        try expect(foreign.runner.invocations.filter { $0.0.hasSuffix("/darwin-rebuild") }.count == 1)
    }

    func testExactTargetResumeLeavesDisabled() throws {
        let newBoot = String(repeating: "f", count: 64)
        let thirdBoot = String(repeating: "d", count: 64)
        func resumeBroker(_ fixture: Fixture, auditWriter: AuditWriting = AtomicAuditWriter(), boot: String = fixtureBoot,
                          checkpoint: @escaping (String) throws -> Void = { _ in }) -> AidAdminBroker {
            let context = RuntimeContext(rootPrefix: fixture.root.path, trustedUID: fixture.uid, realUID: fixture.uid,
                effectiveUID: 0, callerHome: fixture.physical("/Users/agentowner").path, callerIdentity: ownerIdentity,
                currentExecutablePath: fixture.context.currentExecutablePath)
            return fixture.broker(auditWriter: auditWriter, context: context, boot: boot, checkpoint: checkpoint)
        }
        func write(_ fixture: Fixture, _ logical: String, _ data: Data, _ mode: mode_t) throws {
            let path = fixture.physical(logical)
            try FileManager.default.createDirectory(at: path.deletingLastPathComponent(), withIntermediateDirectories: true)
            if pathExistsIncludingSymlink(path.path) { chmod(path.path, 0o600) }
            try data.write(to: path); chmod(path.path, mode)
        }
        func prepare(_ fixture: Fixture) throws {
            let bootPlist: [String: Any] = ["Label": "org.nixos.activate-system",
                "ProgramArguments": ["/bin/sh", "-c", "fixture-boot"], "RunAtLoad": true]
            let bytes = try PropertyListSerialization.data(fromPropertyList: bootPlist, format: .xml, options: 0)
            for target in [targetStore, previousStore] {
                chmod(fixture.physical(target).path, 0o755)
                for suffix in ["Library/LaunchAgents", "Library/LaunchDaemons", "user/Library/LaunchAgents"] {
                    try FileManager.default.createDirectory(at: fixture.physical(target + "/" + suffix), withIntermediateDirectories: true)
                }
                try write(fixture, target + "/Library/LaunchDaemons/org.nixos.activate-system.plist", bytes, 0o444)
                for suffix in ["Library/LaunchAgents", "Library/LaunchDaemons", "Library", "user/Library/LaunchAgents", "user/Library", "user"] {
                    chmod(fixture.physical(target + "/" + suffix).path, 0o555)
                }
                chmod(fixture.physical(target).path, 0o555)
            }
            try write(fixture, "/bin/launchctl", Data("fixture launchctl".utf8), 0o555)
            try write(fixture, "/Library/LaunchDaemons/org.nixos.activate-system.plist", bytes, 0o644)
            let script = "# aid-admin-resume-windows-marker-guards-v1\n# aid-admin-resume-rustdesk-marker-guards-v1\n"
            try write(fixture, targetStore + "/activate", Data(script.utf8), 0o555)
            // Home Manager's synthetic immutable hook contract is populated below.
            try prepareResumeHomeManagerFixture(fixture)
            fixture.runner.postValidationUnknown = true
            _ = try expectThrows { _ = try fixture.broker().applySystem(commit: commit) }
            fixture.runner.postValidationUnknown = false
            let sudoers = fixture.physical("/etc/sudoers.d/agent-first-mac-aid-admin")
            try FileManager.default.moveItem(atPath: sudoers.path, toPath: sudoers.path + ".disabled")
            try write(fixture, "/etc/agent-first-mac/aid-admin.disabled",
                      Data("agent-first-mac-aid-admin-disabled-v1\n".utf8), 0o400)
        }
        func mutations(_ fixture: Fixture, after: Int) -> [(String, [String], [String: String])] {
            fixture.runner.invocations.dropFirst(after).filter {
                $0.0.hasSuffix("/nix-env") || $0.0.hasSuffix("/darwin-rebuild")
            }
        }
        let success = try Fixture(); try prepare(success)
        let before = success.runner.invocations.count
        try expect(try expectThrows { _ = try resumeBroker(success).resumeInterruptedOperation(commit: commit) }
                   == "resume_requires_changed_last_attempt_boot")
        try expect(try resumeBroker(success, boot: newBoot).resumeInterruptedOperation(commit: commit) == "OPERATION_RESUMED_DISABLED")
        try expect(mutations(success, after: before).count == 1, "already_current_resume_must_activate")
        try expect(mutations(success, after: before).first?.1 == ["--switch-generation", "2"])
        try expect(try success.broker(boot: newBoot).inspectOperation()["state"] == "resumed")
        let after = success.runner.invocations.count
        try expect(try resumeBroker(success, boot: newBoot).resumeInterruptedOperation(commit: commit) == "OPERATION_RESUMED_DISABLED")
        try expect(mutations(success, after: after).isEmpty, "settled_resume_replayed")
        try expect(!pathExistsIncludingSymlink(success.physical("/etc/sudoers.d/agent-first-mac-aid-admin").path))

        for fault in ["activation_status", "activation_unknown", "postcondition", "postcondition_unknown"] {
            let fixture = try Fixture(); try prepare(fixture)
            if fault == "activation_status" { fixture.runner.activationStatus = 1 }
            if fault == "activation_unknown" { fixture.runner.activationUnknown = true }
            if fault == "postcondition" { fixture.runner.postApplyVerificationFailure = true }
            if fault == "postcondition_unknown" {
                fixture.runner.afterActivation = { fixture.runner.postValidationUnknown = true }
            }
            let start = fixture.runner.invocations.count
            let reason = try expectThrows { _ = try resumeBroker(fixture, boot: newBoot).resumeInterruptedOperation(commit: commit) }
            try expect(reason.hasPrefix("resume_failed_or_unknown_disabled:"), reason)
            try expect(try fixture.broker(boot: newBoot).inspectOperation()["state"] == "unknown")
            try expect(!mutations(fixture, after: start).contains(where: { $0.1 == ["--switch-generation", "1"] }), "resume_inverted")
            fixture.runner.activationStatus = 0; fixture.runner.activationUnknown = false
            fixture.runner.postApplyVerificationFailure = false; fixture.runner.postValidationUnknown = false
            fixture.runner.afterActivation = nil
            try expect(try expectThrows { _ = try resumeBroker(fixture, boot: newBoot).resumeInterruptedOperation(commit: commit) }
                       == "resume_requires_changed_last_attempt_boot")
            try expect(try resumeBroker(fixture, boot: thirdBoot).resumeInterruptedOperation(commit: commit) == "OPERATION_RESUMED_DISABLED")
            try expect(try fixture.broker(boot: thirdBoot).inspectOperation()["resume_attempt_count"] == "2")
        }
        let audit = try Fixture(); try prepare(audit)
        let writer = AtomicAuditWriter(checkpoint: { suffix, phase in
            if suffix == "resume-1-result" && phase == "after_rename" { throw BrokerFailure.rejected("fixture_audit_error") }
        })
        try expect(try expectThrows {
            _ = try resumeBroker(audit, auditWriter: writer, boot: newBoot).resumeInterruptedOperation(commit: commit)
        } == "resumed_applied_audit_incomplete_disabled")
        try expect(try audit.broker(boot: newBoot).inspectOperation()["state"] == "resume_committed")
        let auditBefore = audit.runner.invocations.count
        try expect(try resumeBroker(audit, boot: newBoot).resumeInterruptedOperation(commit: commit) == "OPERATION_RESUMED_DISABLED")
        try expect(mutations(audit, after: auditBefore).isEmpty)

        func childResume(_ fixture: Fixture, _ mode: String, _ phase: String) throws -> Int32 {
            let process = Process()
            process.executableURL = URL(fileURLWithPath: CommandLine.arguments[0])
            process.arguments = ["--fixture-child", fixture.root.path, mode, phase]
            try process.run(); process.waitUntilExit()
            return process.terminationStatus
        }
        for phase in ["resume_pending", "resume_committed"] {
            let fixture = try Fixture(); try prepare(fixture)
            try expect(try childResume(fixture, "resume-crash", phase) == 86, "resume_crash_seam_missing")
            try expect(try fixture.broker(boot: newBoot).inspectOperation()["state"] == phase)
            let start = fixture.runner.invocations.count
            if phase == "resume_pending" {
                try expect(try expectThrows {
                    _ = try resumeBroker(fixture, boot: newBoot).resumeInterruptedOperation(commit: commit)
                } == "resume_requires_changed_last_attempt_boot")
                try expect(mutations(fixture, after: start).isEmpty)
                try expect(try resumeBroker(fixture, boot: thirdBoot).resumeInterruptedOperation(commit: commit) == "OPERATION_RESUMED_DISABLED")
            } else {
                try expect(try fixture.broker(boot: newBoot).inspectOperation()["next_action"] == "fresh_authenticated_exact_target_resume_audit_only")
                try expect(try resumeBroker(fixture, boot: newBoot).resumeInterruptedOperation(commit: commit) == "OPERATION_RESUMED_DISABLED")
                try expect(mutations(fixture, after: start).isEmpty, "committed_resume_replayed")
            }
        }
        let busy = try Fixture(); try prepare(busy)
        busy.runner.duringMutation = {
            try expect(try childResume(busy, "resume-busy", "") == 0, "resume_competing_process_not_busy")
        }
        try expect(try resumeBroker(busy, boot: newBoot).resumeInterruptedOperation(commit: commit) == "OPERATION_RESUMED_DISABLED")

        let drift = try Fixture(); try prepare(drift)
        let driftStart = drift.runner.invocations.count
        let driftReason = try expectThrows {
            _ = try resumeBroker(drift, boot: newBoot, checkpoint: { phase in
                if phase == "resume_pending" {
                    try write(drift, "/Library/LaunchDaemons/org.nixos.activate-system.plist", Data("foreign after journal".utf8), 0o644)
                }
            }).resumeInterruptedOperation(commit: commit)
        }
        try expect(driftReason.hasPrefix("resume_failed_or_unknown_disabled:"), driftReason)
        try expect(mutations(drift, after: driftStart).isEmpty, "preactivation_foreign_drift_mutated")
        try expect(try drift.broker(boot: newBoot).inspectOperation()["state"] == "unknown")

        let fontDrift = try Fixture(); try prepare(fontDrift)
        let fontDriftPath = fontDrift.physical("/Users/agentowner/Library/Fonts/HomeManager/owner-added.ttf")
        var fontDriftBefore = stat()
        let fontDriftStart = fontDrift.runner.invocations.count
        _ = try expectThrows {
            _ = try resumeBroker(fontDrift, boot: newBoot, checkpoint: { phase in
                if phase == "resume_pending" {
                    try write(fontDrift, "/Users/agentowner/Library/Fonts/HomeManager/owner-added.ttf", Data("late foreign font".utf8), 0o644)
                    try expect(lstat(fontDriftPath.path, &fontDriftBefore) == 0)
                }
            }).resumeInterruptedOperation(commit: commit)
        }
        var fontDriftAfter = stat()
        try expect(lstat(fontDriftPath.path, &fontDriftAfter) == 0 && fontDriftBefore.st_ino == fontDriftAfter.st_ino)
        try expect(try Data(contentsOf: fontDriftPath) == Data("late foreign font".utf8))
        try expect(mutations(fontDrift, after: fontDriftStart).isEmpty, "late_foreign_font_activated")

        for fault in ["schema1", "entry_guards", "retained_stage", "wrong_commit", "previous_generation", "foreign_fonts"] {
            let fixture = try Fixture(); try prepare(fixture)
            if fault == "schema1" {
                let path = fixture.physical("/var/db/agent-first-mac/staging/operation.json")
                var record = try JSONSerialization.jsonObject(with: Data(contentsOf: path)) as! [String: Any]
                record["schema"] = 1
                for key in ["bootGeneration", "previousNarHash", "targetNarHash", "previousRevision"] { record.removeValue(forKey: key) }
                try JSONSerialization.data(withJSONObject: record, options: [.sortedKeys]).write(to: path)
            }
            if fault == "entry_guards" { try write(fixture, targetStore + "/activate", Data("old activate".utf8), 0o555) }
            if fault == "retained_stage" { try FileManager.default.createDirectory(at: fixture.physical("/Applications/.gametomac-stage.retained"), withIntermediateDirectories: true) }
            if fault == "foreign_fonts" {
                try write(fixture, "/Users/agentowner/Library/Fonts/HomeManager/owner-added.ttf", Data("foreign owner font".utf8), 0o644)
            }
            if fault == "previous_generation" {
                let path = fixture.physical("/nix/var/nix/profiles/system-1-link")
                try FileManager.default.removeItem(at: path)
                try FileManager.default.createSymbolicLink(atPath: path.path, withDestinationPath: fixture.physical(targetStore).path)
            }
            var fontBefore = stat()
            if fault == "foreign_fonts" {
                try expect(lstat(fixture.physical("/Users/agentowner/Library/Fonts/HomeManager/owner-added.ttf").path, &fontBefore) == 0)
            }
            let start = fixture.runner.invocations.count
            _ = try expectThrows {
                _ = try resumeBroker(fixture, boot: newBoot).resumeInterruptedOperation(commit: fault == "wrong_commit" ? tree : commit)
            }
            try expect(mutations(fixture, after: start).isEmpty, "resume_negative_mutated")
            if fault == "foreign_fonts" {
                var fontAfter = stat()
                try expect(lstat(fixture.physical("/Users/agentowner/Library/Fonts/HomeManager/owner-added.ttf").path, &fontAfter) == 0 && fontBefore.st_ino == fontAfter.st_ino)
                try expect(try Data(contentsOf: fixture.physical("/Users/agentowner/Library/Fonts/HomeManager/owner-added.ttf")) == Data("foreign owner font".utf8), "foreign_font_removed")
            }
            try expect(!pathExistsIncludingSymlink(fixture.physical("/etc/sudoers.d/agent-first-mac-aid-admin").path))
        }
    }

    func testCrossProcessBusyAndCrashRecovery() throws {
        let fixture = try Fixture()
        func child(_ mode: String, _ phase: String = "") throws -> Int32 {
            let process = Process()
            process.executableURL = URL(fileURLWithPath: CommandLine.arguments[0])
            process.arguments = ["--fixture-child", fixture.root.path, mode, phase]
            process.standardOutput = FileHandle.nullDevice
            process.standardError = FileHandle.nullDevice
            try process.run(); process.waitUntilExit()
            return process.terminationStatus
        }
        fixture.runner.duringMutation = {
            try expect(try child("busy") == 0, "second_process_not_busy")
        }
        try expect(try fixture.broker().applySystem(commit: commit) == 0)

        for phase in ["sealed", "profile_pending", "profile_ready", "activation_pending", "committed", "complete",
                      "audit_after_write", "audit_after_rename"] {
            let crashFixture = try Fixture()
            let process = Process()
            process.executableURL = URL(fileURLWithPath: CommandLine.arguments[0])
            process.arguments = ["--fixture-child", crashFixture.root.path, "crash", phase]
            try process.run(); process.waitUntilExit()
            try expect(process.terminationStatus == 86, "crash_seam_not_reached_" + phase)
            let inspect = try crashFixture.broker().inspectOperation()
            try expect(inspect["state"] == (phase.hasPrefix("audit_") ? "committed" : phase))
            let before = crashFixture.runner.invocations.count
            if phase == "committed" || phase.hasPrefix("audit_") {
                try expect(try crashFixture.broker().applySystem(commit: commit) == 0)
                try expect(crashFixture.runner.invocations.dropFirst(before).allSatisfy {
                    !$0.0.hasSuffix("/nix-env") && !$0.0.hasSuffix("/darwin-rebuild")
                }, "duplicate_activation_on_reconcile")
            } else if phase == "sealed" {
                let reason = try expectThrows { _ = try crashFixture.broker().applySystem(commit: commit) }
                try expect(reason == "interrupted_before_mutation_reconciled_no_apply")
            } else if phase == "profile_ready" {
                try expect(try crashFixture.broker().applySystem(commit: commit) == 70)
                try expect(try crashFixture.currentProfileIdentifier() == "1")
            } else if phase != "complete" {
                let reason = try expectThrows { _ = try crashFixture.broker().applySystem(commit: commit) }
                try expect(reason.contains("operation_unknown_requires_owner_reconciliation"))
                try expect(crashFixture.runner.invocations.dropFirst(before).allSatisfy {
                    !$0.0.hasSuffix("/nix-env") && !$0.0.hasSuffix("/darwin-rebuild")
                }, "unknown_state_started_mutation")
            }
        }
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
        if CommandLine.arguments.count == 5 && CommandLine.arguments[1] == "--fixture-child" {
            let root = CommandLine.arguments[2]
            let mode = CommandLine.arguments[3]
            let phase = CommandLine.arguments[4]
            let runner = FakeRunner(); runner.root = URL(fileURLWithPath: root)
            let policyBytes = try Data(contentsOf: URL(fileURLWithPath: root + "/etc/agent-first-mac/aid-admin-policy.json"))
            let context = RuntimeContext(rootPrefix: root, trustedUID: getuid(), realUID: getuid(), effectiveUID: 0,
                callerHome: root + (mode.hasPrefix("resume-") ? "/Users/agentowner" : "/home/agentowner"), callerIdentity: ownerIdentity,
                currentExecutablePath: root + "/usr/local/libexec/aid-admin")
            let writer = AtomicAuditWriter(checkpoint: { suffix, observed in
                if mode == "crash" && suffix == "result" && phase == "audit_" + observed { _exit(86) }
            })
            let broker = AidAdminBroker(context: context, runner: runner, auditWriter: writer,
                expectedPolicyHash: sha256Hex(policyBytes), actionID: { actionID },
                operationCheckpoint: { observed in if (mode == "crash" || mode == "resume-crash") && observed == phase { _exit(86) } },
                bootGeneration: { mode.hasPrefix("resume-") ? String(repeating: "f", count: 64) : fixtureBoot })
            do {
                if mode.hasPrefix("resume-") { _ = try broker.resumeInterruptedOperation(commit: commit) }
                else { _ = try broker.applySystem(commit: commit) }
                exit(90)
            }
            catch {
                if (mode == "busy" || mode == "resume-busy") && String(describing: error) == "operation_busy" { exit(0) }
                throw error
            }
        }
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
            ("final_audit_reconcile", suite.testFinalAuditFailurePreservesCommitAndReconciles),
            ("sealed_checkout_drift", suite.testSealedApplyDoesNotRollbackForCheckoutDrift),
            ("audit_failure_boundaries", suite.testAuditFailureBoundariesNeverInvertVisibleApplied),
            ("unknown_foreign_no_inverse", suite.testUnknownVerificationAndForeignPreviousNeverRollback),
            ("exact_target_resume", suite.testExactTargetResumeLeavesDisabled),
            ("cross_process_crash", suite.testCrossProcessBusyAndCrashRecovery),
            ("rollback_failure_distinction", suite.testRollbackCommandAndVerificationFailuresAreDistinct),
            ("profile_failure_rollback", suite.testProfileUpdateFailureAlsoRollsBackUncertainMutation),
        ]
        var executed = 0
        for (name, test) in tests {
            if CommandLine.arguments.count == 3 && CommandLine.arguments[1] == "--only" && name != CommandLine.arguments[2] { continue }
            do { try test() }
            catch {
                FileHandle.standardError.write(Data("FAIL \(name): \(error)\n".utf8))
                exit(1)
            }
            executed += 1
        }
        try expect(executed > 0, "no_tests_selected")
        print("{\"result\":\"pass\",\"tests\":\(executed)}")
    }
}
