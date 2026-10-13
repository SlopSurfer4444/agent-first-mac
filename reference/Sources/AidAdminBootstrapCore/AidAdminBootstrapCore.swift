import CryptoKit
import Darwin
import Foundation

public enum BootstrapFailure: Error, CustomStringConvertible, Equatable {
    case rejected(String)

    public var description: String {
        switch self { case .rejected(let reason): return reason }
    }
}

private func require(_ condition: @autoclosure () -> Bool, _ reason: String) throws {
    if !condition() { throw BootstrapFailure.rejected(reason) }
}

public func bootstrapSHA256(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}

private func strictKeys(_ value: Any, expected: Set<String>, reason: String) throws -> [String: Any] {
    guard let object = value as? [String: Any], Set(object.keys) == expected else {
        throw BootstrapFailure.rejected(reason)
    }
    return object
}

public struct ArtifactPin: Codable, Equatable {
    public let sha256: String
    public let size: Int

    public init(sha256: String, size: Int) {
        self.sha256 = sha256
        self.size = size
    }
}

public struct InstallInputs: Codable, Equatable {
    public let artifactSet: String
    public let bootstrap: ArtifactPin
    public let broker: ArtifactPin
    public let policy: ArtifactPin
    public let renderedSudoers: ArtifactPin
    public let schema: Int
    public let sudoersTemplate: ArtifactPin

    public static func decodeStrict(_ data: Data) throws -> InstallInputs {
        let raw = try JSONSerialization.jsonObject(with: data)
        let root = try strictKeys(raw, expected: ["artifactSet", "bootstrap", "broker", "policy",
                                                  "renderedSudoers", "schema", "sudoersTemplate"],
                                  reason: "install_inputs_keys")
        for key in ["bootstrap", "broker", "policy", "renderedSudoers", "sudoersTemplate"] {
            _ = try strictKeys(root[key] as Any, expected: ["sha256", "size"],
                               reason: "install_inputs_pin_keys")
        }
        let value = try JSONDecoder().decode(InstallInputs.self, from: data)
        try require(value.schema == 1 && value.artifactSet == "phase4-aid-admin-install-bundle-v1",
                    "install_inputs_header")
        for pin in [value.bootstrap, value.broker, value.policy, value.renderedSudoers,
                    value.sudoersTemplate] {
            try require(pin.sha256.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil,
                        "install_inputs_hash")
            try require(pin.size > 0 && pin.size <= 64 * 1024 * 1024, "install_inputs_size")
        }
        return value
    }
}

public struct BootstrapRequest {
    public let brokerPath: String
    public let policyPath: String
    public let sudoersTemplatePath: String
    public let inputsPath: String
    public let inputsSHA256: String
    public let inputsSize: Int
    public let ownerName: String
    public let ownerUID: UInt32
    public let sudoersIdentity: String

    public init(brokerPath: String, policyPath: String, sudoersTemplatePath: String,
                inputsPath: String, inputsSHA256: String, inputsSize: Int,
                ownerName: String, ownerUID: UInt32, sudoersIdentity: String) {
        self.brokerPath = brokerPath
        self.policyPath = policyPath
        self.sudoersTemplatePath = sudoersTemplatePath
        self.inputsPath = inputsPath
        self.inputsSHA256 = inputsSHA256
        self.inputsSize = inputsSize
        self.ownerName = ownerName
        self.ownerUID = ownerUID
        self.sudoersIdentity = sudoersIdentity
    }
}

public struct BootstrapInvokingOwner: Equatable {
    public let name: String
    public let uid: UInt32

    public init(name: String, uid: UInt32) {
        self.name = name
        self.uid = uid
    }
}

public protocol BootstrapAccountLookingUp {
    func name(forUID uid: UInt32) -> String?
    func uid(forName name: String) -> UInt32?
}

public struct SystemBootstrapAccountLookup: BootstrapAccountLookingUp {
    public init() {}

    public func name(forUID uid: UInt32) -> String? {
        guard let entry = getpwuid(uid_t(uid)), let pointer = entry.pointee.pw_name else {
            return nil
        }
        return String(cString: pointer)
    }

    public func uid(forName name: String) -> UInt32? {
        guard let entry = getpwnam(name), entry.pointee.pw_uid <= UInt32.max else {
            return nil
        }
        return UInt32(entry.pointee.pw_uid)
    }
}

public func deriveStandardSudoInvokingOwner(
    environment: [String: String],
    accounts: BootstrapAccountLookingUp
) throws -> BootstrapInvokingOwner {
    guard let rawUID = environment["SUDO_UID"],
          let rawName = environment["SUDO_USER"] else {
        throw BootstrapFailure.rejected("sudo_provenance_missing")
    }
    try require(rawUID.range(of: "^[1-9][0-9]{0,9}$", options: .regularExpression) != nil,
                "sudo_uid_syntax")
    guard let uid = UInt32(rawUID), uid > 0 else {
        throw BootstrapFailure.rejected("sudo_uid_syntax")
    }
    try require(rawName.range(of: "^[a-z_][a-z0-9_-]{0,31}$",
                              options: .regularExpression) != nil && rawName != "root",
                "sudo_user_syntax")
    try require(accounts.name(forUID: uid) == rawName, "sudo_uid_passwd_mismatch")
    try require(accounts.uid(forName: rawName) == uid, "sudo_user_passwd_mismatch")
    return BootstrapInvokingOwner(name: rawName, uid: uid)
}

public struct BootstrapContext {
    public let rootPrefix: String
    public let trustedUID: uid_t
    public let trustedGID: gid_t
    public let effectiveUID: uid_t
    public let currentExecutablePath: String
    public let invokingOwner: BootstrapInvokingOwner
    public let fixtureMode: Bool

    public init(rootPrefix: String = "/", trustedUID: uid_t = 0, trustedGID: gid_t = 0,
                effectiveUID: uid_t, currentExecutablePath: String,
                invokingOwner: BootstrapInvokingOwner, fixtureMode: Bool = false) {
        self.rootPrefix = rootPrefix
        self.trustedUID = trustedUID
        self.trustedGID = trustedGID
        self.effectiveUID = effectiveUID
        self.currentExecutablePath = currentExecutablePath
        self.invokingOwner = invokingOwner
        self.fixtureMode = fixtureMode
    }
}

public protocol BootstrapCommandRunning {
    func run(executable: String, arguments: [String], environment: [String: String]) throws -> Int32
}

public final class BootstrapProcessRunner: BootstrapCommandRunning {
    public init() {}
    public func run(executable: String, arguments: [String], environment: [String: String]) throws -> Int32 {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.environment = environment
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        process.waitUntilExit()
        return process.terminationStatus
    }
}

public protocol BootstrapHooks {
    func afterStaging(paths: [String: String]) throws
    func afterMutation(step: String) throws
    func beforeRollback() throws
}

public struct NoBootstrapHooks: BootstrapHooks {
    public init() {}
    public func afterStaging(paths: [String: String]) throws {}
    public func afterMutation(step: String) throws {}
    public func beforeRollback() throws {}
}

private struct FileSnapshot {
    let existed: Bool
    let sha256: String
    let size: Int
    let uid: uid_t
    let gid: gid_t
    let mode: mode_t
    var backup: String?
}

private struct TransactionState {
    var createdDirectories: [String] = []
    var files: [String: FileSnapshot] = [:]
    var mutationStarted = false
    var staging = ""
}

public final class BootstrapInstaller {
    public static let binaryPath = "/usr/local/libexec/aid-admin"
    public static let policyPath = "/etc/agent-first-mac/aid-admin-policy.json"
    public static let attestationPath = "/etc/agent-first-mac/aid-admin-install.json"
    public static let sudoersPath = "/etc/sudoers.d/agent-first-mac-aid-admin"
    public static let auditPath = "/var/log/agent-first-mac/aid-admin"
    public static let brokerStagingPath = "/var/db/agent-first-mac/staging"
    public static let emergencyDisablePath = "/etc/agent-first-mac/aid-admin.disabled"
    public static let disabledSudoersPath = "/etc/sudoers.d/agent-first-mac-aid-admin.disabled"
    private static let bootstrapRoot = "/var/db/agent-first-mac/bootstrap"
    private static let token = "@@AGENT_OWNER@@"
    private static let cleanEnvironment = [
        "HOME": "/var/empty", "LANG": "C", "LC_ALL": "C",
        "PATH": "/usr/bin:/bin", "TMPDIR": "/var/empty",
    ]

    private let context: BootstrapContext
    private let runner: BootstrapCommandRunning
    private let hooks: BootstrapHooks
    private let actionID: () -> String

    public init(context: BootstrapContext, runner: BootstrapCommandRunning = BootstrapProcessRunner(),
                hooks: BootstrapHooks = NoBootstrapHooks(),
                actionID: @escaping () -> String = { UUID().uuidString.lowercased() }) {
        self.context = context
        self.runner = runner
        self.hooks = hooks
        self.actionID = actionID
    }

    public func install(_ request: BootstrapRequest) throws -> String {
        try validateContext()
        let owner = try validateOwner(request)
        try require(request.inputsSHA256.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil,
                    "inputs_hash_argument")
        try require(request.inputsSize > 0 && request.inputsSize <= 64 * 1024 * 1024,
                    "inputs_size_argument")
        try preflightState()

        var transaction = TransactionState()
        do {
            try ensureDirectory("/var/db/agent-first-mac", mode: 0o755, state: &transaction)
            try ensureDirectory(Self.bootstrapRoot, mode: 0o700, state: &transaction)
            let identifier = actionID()
            try require(identifier.range(of: "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
                                         options: .regularExpression) != nil, "transaction_identifier")
            transaction.staging = Self.bootstrapRoot + "/transaction-" + identifier
            try ensureDirectory(transaction.staging, mode: 0o700, state: &transaction)

            let stagedInputs = transaction.staging + "/install-inputs.json"
            try copyReviewedSource(request.inputsPath, to: stagedInputs,
                                   pin: ArtifactPin(sha256: request.inputsSHA256,
                                                    size: request.inputsSize))
            let inputsData = try readTrustedFile(stagedInputs, mode: 0o400, maximum: 64 * 1024)
            let inputs = try InstallInputs.decodeStrict(inputsData)
            let executable = try readExternalFile(context.currentExecutablePath,
                                                  maximum: 64 * 1024 * 1024)
            try require(executable.count == inputs.bootstrap.size &&
                        bootstrapSHA256(executable) == inputs.bootstrap.sha256,
                        "bootstrap_self_attestation")

            let stagedBroker = transaction.staging + "/aid-admin"
            let stagedPolicy = transaction.staging + "/aid-admin-policy.json"
            let stagedTemplate = transaction.staging + "/sudoers-template"
            try copyReviewedSource(request.brokerPath, to: stagedBroker, pin: inputs.broker)
            try copyReviewedSource(request.policyPath, to: stagedPolicy, pin: inputs.policy)
            try copyReviewedSource(request.sudoersTemplatePath, to: stagedTemplate,
                                   pin: inputs.sudoersTemplate)
            try hooks.afterStaging(paths: ["broker": physical(stagedBroker),
                                           "policy": physical(stagedPolicy),
                                           "sudoersTemplate": physical(stagedTemplate)])
            try verifyPin(stagedBroker, pin: inputs.broker, mode: 0o400)
            try verifyPin(stagedPolicy, pin: inputs.policy, mode: 0o400)
            try verifyPin(stagedTemplate, pin: inputs.sudoersTemplate, mode: 0o400)

            let rendered = try renderSudoers(try readTrustedFile(stagedTemplate, mode: 0o400,
                                                                 maximum: 4096),
                                             principal: owner.name)
            try require(rendered.count == inputs.renderedSudoers.size &&
                        bootstrapSHA256(rendered) == inputs.renderedSudoers.sha256,
                        "rendered_sudoers_drift")
            let stagedRendered = transaction.staging + "/sudoers-rendered"
            try writeExclusive(rendered, logical: stagedRendered, mode: 0o440)
            let visudo = context.fixtureMode ? "/usr/sbin/visudo" : "/usr/sbin/visudo"
            let visudoStatus = try runner.run(executable: visudo,
                                              arguments: ["-cf", physical(stagedRendered)],
                                              environment: Self.cleanEnvironment)
            try require(visudoStatus == 0, "visudo_failed")

            let attestation = try makeAttestation(owner: owner, inputs: inputs)
            let stagedAttestation = transaction.staging + "/aid-admin-install.json"
            try writeExclusive(attestation, logical: stagedAttestation, mode: 0o400)

            try ensureDirectory("/etc/sudoers.d", mode: 0o755, state: &transaction)
            try ensureDirectory("/etc/agent-first-mac", mode: 0o755, state: &transaction)
            try ensureDirectory("/usr/local", mode: 0o755, state: &transaction)
            try ensureDirectory("/usr/local/libexec", mode: 0o755, state: &transaction)
            try ensureDirectory("/var/log/agent-first-mac", mode: 0o755, state: &transaction)
            try ensureDirectory(Self.auditPath, mode: 0o700, state: &transaction)
            try ensureDirectory(Self.brokerStagingPath, mode: 0o700, state: &transaction)
            transaction.mutationStarted = true
            try hooks.afterMutation(step: "runtime-directories")

            try replaceTarget(stagedBroker, target: Self.binaryPath, mode: 0o555,
                              pin: inputs.broker, state: &transaction)
            try hooks.afterMutation(step: "binary")
            try replaceTarget(stagedPolicy, target: Self.policyPath, mode: 0o444,
                              pin: inputs.policy, state: &transaction)
            try hooks.afterMutation(step: "policy")
            let attestationPin = ArtifactPin(sha256: bootstrapSHA256(attestation), size: attestation.count)
            try replaceTarget(stagedAttestation, target: Self.attestationPath, mode: 0o400,
                              pin: attestationPin, state: &transaction)
            try hooks.afterMutation(step: "attestation")
            try replaceTarget(stagedRendered, target: Self.sudoersPath, mode: 0o440,
                              pin: inputs.renderedSudoers, state: &transaction)
            try hooks.afterMutation(step: "sudoers")
            try verifyInstalled(inputs: inputs, attestation: attestationPin)
            try hooks.afterMutation(step: "final-verification")
            try cleanupStaging(state: &transaction, success: true)
            return "INSTALL_TRANSACTION_COMMITTED"
        } catch {
            let original = String(describing: error)
            if transaction.mutationStarted {
                do {
                    try hooks.beforeRollback()
                    try rollback(state: &transaction)
                    throw BootstrapFailure.rejected(original + "_rolled_back")
                } catch let failure as BootstrapFailure where failure.description.hasSuffix("_rolled_back") {
                    throw failure
                } catch {
                    throw BootstrapFailure.rejected(original + "_rollback_failed")
                }
            }
            try? cleanupStaging(state: &transaction, success: false)
            throw error
        }
    }

    private func validateContext() throws {
        if context.fixtureMode {
            try require(context.rootPrefix != "/" && context.rootPrefix.hasPrefix("/private/") ||
                        context.rootPrefix.hasPrefix("/tmp/"), "fixture_root_contract")
            try require(context.effectiveUID == context.trustedUID, "fixture_identity")
        } else {
            try require(context.rootPrefix == "/" && context.effectiveUID == 0 &&
                        context.trustedUID == 0 && context.trustedGID == 0, "root_required")
        }
        try require(context.invokingOwner.uid > 0 && context.invokingOwner.name != "root" &&
                    context.invokingOwner.name.range(of: "^[a-z_][a-z0-9_-]{0,31}$",
                                                     options: .regularExpression) != nil,
                    "invoking_owner_contract")
    }

    private func validateOwner(_ request: BootstrapRequest) throws -> BootstrapInvokingOwner {
        try require(request.ownerName.range(of: "^[a-z_][a-z0-9_-]{0,31}$",
                                           options: .regularExpression) != nil, "unsafe_owner_name")
        try require(request.ownerUID > 0, "unsafe_owner_uid")
        try require(request.ownerName == context.invokingOwner.name,
                    "request_owner_name_mismatch")
        try require(request.ownerUID == context.invokingOwner.uid,
                    "request_owner_uid_mismatch")
        try require(request.sudoersIdentity == "name:" + context.invokingOwner.name,
                    "sudoers_identity_not_exact_invoker")
        return context.invokingOwner
    }

    private func preflightState() throws {
        try require(!exists(Self.emergencyDisablePath) && !exists(Self.disabledSudoersPath),
                    "emergency_or_disabled_state_present")
        let files: [String: mode_t] = [Self.binaryPath: 0o555, Self.policyPath: 0o444,
                                      Self.attestationPath: 0o400, Self.sudoersPath: 0o440]
        let directories: [String: mode_t] = [Self.auditPath: 0o700,
                                             Self.brokerStagingPath: 0o700]
        let present = files.keys.filter(exists).count + directories.keys.filter(exists).count
        try require(present == 0 || present == files.count + directories.count,
                    "unexpected_preexisting_path")
        if present > 0 {
            for (path, mode) in files { _ = try trustedFileSnapshot(path, mode: mode) }
            for (path, mode) in directories { try validateDirectory(path, mode: mode) }
        }
    }

    private func makeAttestation(owner: BootstrapInvokingOwner, inputs: InstallInputs) throws -> Data {
        let value: [String: Any] = [
            "agentOwnerIdentity": owner.name,
            "agentOwnerUID": owner.uid,
            "binarySHA256": inputs.broker.sha256,
            "policySHA256": inputs.policy.sha256,
            "schema": 1,
            "sudoersSHA256": inputs.renderedSudoers.sha256,
        ]
        var data = try JSONSerialization.data(withJSONObject: value, options: [.prettyPrinted, .sortedKeys])
        data.append(0x0a)
        try require(data.count <= 4096, "attestation_size")
        return data
    }

    private func renderSudoers(_ data: Data, principal: String) throws -> Data {
        guard let text = String(data: data, encoding: .utf8) else {
            throw BootstrapFailure.rejected("sudoers_template_utf8")
        }
        let expected = "Cmnd_Alias AGENT_FIRST_MAC_AID_ADMIN = /usr/local/libexec/aid-admin\n" +
            Self.token + " ALL=(root) NOPASSWD: AGENT_FIRST_MAC_AID_ADMIN\n"
        try require(text == expected && text.components(separatedBy: Self.token).count == 2,
                    "sudoers_template_contract")
        let rendered = text.replacingOccurrences(of: Self.token, with: principal)
        let lowered = rendered.lowercased()
        for forbidden in ["%admin", "nopasswd: all", "*", "/bin/sh", "/bin/zsh",
                          "darwin-rebuild", "/usr/bin/git", "nix-env", "nix-store"] {
            try require(!lowered.contains(forbidden), "sudoers_direct_backend")
        }
        return Data(rendered.utf8)
    }

    private func copyReviewedSource(_ source: String, to logical: String, pin: ArtifactPin) throws {
        let data = try readExternalFile(source, maximum: 64 * 1024 * 1024)
        try require(data.count == pin.size && bootstrapSHA256(data) == pin.sha256,
                    "source_hash_or_size_mismatch")
        try writeExclusive(data, logical: logical, mode: 0o400)
        try verifyPin(logical, pin: pin, mode: 0o400)
    }

    private func readExternalFile(_ path: String, maximum: Int) throws -> Data {
        try require(path.hasPrefix("/") && !path.contains("/../") && !path.contains("//"),
                    "source_path_contract")
        let fd = Darwin.open(path, O_RDONLY | O_NOFOLLOW)
        try require(fd >= 0, "source_open")
        defer { Darwin.close(fd) }
        var before = stat()
        try require(fstat(fd, &before) == 0 && (before.st_mode & S_IFMT) == S_IFREG,
                    "source_type")
        try require((before.st_mode & 0o022) == 0, "source_mutable")
        return try readBounded(fd: fd, before: before, maximum: maximum, reason: "source_race")
    }

    private func readTrustedFile(_ logical: String, mode: mode_t, maximum: Int) throws -> Data {
        let fd = Darwin.open(physical(logical), O_RDONLY | O_NOFOLLOW)
        try require(fd >= 0, "trusted_open")
        defer { Darwin.close(fd) }
        var before = stat()
        try require(fstat(fd, &before) == 0 && (before.st_mode & S_IFMT) == S_IFREG &&
                    before.st_uid == context.trustedUID && before.st_gid == context.trustedGID &&
                    (before.st_mode & 0o777) == mode, "trusted_file_contract")
        return try readBounded(fd: fd, before: before, maximum: maximum, reason: "trusted_file_race")
    }

    private func readBounded(fd: Int32, before: stat, maximum: Int, reason: String) throws -> Data {
        try require(before.st_size >= 0 && before.st_size <= maximum, "file_size")
        var data = Data(count: Int(before.st_size))
        var offset = 0
        while offset < data.count {
            let count = data.withUnsafeMutableBytes { raw -> Int in
                guard let base = raw.baseAddress else { return -1 }
                return Darwin.read(fd, base.advanced(by: offset), raw.count - offset)
            }
            try require(count > 0, "file_read")
            offset += count
        }
        var after = stat()
        try require(fstat(fd, &after) == 0 && before.st_dev == after.st_dev &&
                    before.st_ino == after.st_ino && before.st_size == after.st_size &&
                    before.st_uid == after.st_uid && before.st_gid == after.st_gid &&
                    before.st_mode == after.st_mode &&
                    before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec &&
                    before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec &&
                    before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec &&
                    before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec, reason)
        return data
    }

    private func verifyPin(_ logical: String, pin: ArtifactPin, mode: mode_t) throws {
        let data = try readTrustedFile(logical, mode: mode, maximum: 64 * 1024 * 1024)
        try require(data.count == pin.size && bootstrapSHA256(data) == pin.sha256,
                    "staged_hash_or_size_mismatch")
    }

    private func replaceTarget(_ staged: String, target: String, mode: mode_t,
                               pin: ArtifactPin, state: inout TransactionState) throws {
        var snapshot = try trustedFileSnapshotIfPresent(target, mode: mode)
        if snapshot.existed {
            let backup = state.staging + "/prior-" + URL(fileURLWithPath: target).lastPathComponent
            try require(rename(physical(target), physical(backup)) == 0, "prior_backup_failed")
            snapshot.backup = backup
        }
        state.files[target] = snapshot
        state.mutationStarted = true
        let data = try readTrustedFile(staged, mode: target == Self.sudoersPath ? 0o440 : 0o400,
                                       maximum: 64 * 1024 * 1024)
        try atomicWrite(data, target: target, mode: mode)
        try verifyPin(target, pin: pin, mode: mode)
    }

    private func atomicWrite(_ data: Data, target: String, mode: mode_t) throws {
        let temporary = target + ".bootstrap-new"
        try require(!exists(temporary), "install_temporary_exists")
        try writeExclusive(data, logical: temporary, mode: mode)
        try require(rename(physical(temporary), physical(target)) == 0, "install_rename_failed")
        try syncParent(target)
    }

    private func writeExclusive(_ data: Data, logical: String, mode: mode_t) throws {
        let fd = Darwin.open(physical(logical), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, mode)
        try require(fd >= 0, "exclusive_write_open")
        defer { Darwin.close(fd) }
        try require(fchown(fd, context.trustedUID, context.trustedGID) == 0 &&
                    fchmod(fd, mode) == 0, "exclusive_write_owner_mode")
        var offset = 0
        while offset < data.count {
            let count = data.withUnsafeBytes { raw -> Int in
                guard let base = raw.baseAddress else { return -1 }
                return Darwin.write(fd, base.advanced(by: offset), raw.count - offset)
            }
            try require(count > 0, "exclusive_write")
            offset += count
        }
        try require(fsync(fd) == 0, "exclusive_write_sync")
    }

    private func trustedFileSnapshotIfPresent(_ logical: String, mode: mode_t) throws -> FileSnapshot {
        if !exists(logical) {
            return FileSnapshot(existed: false, sha256: "", size: 0, uid: 0, gid: 0,
                                mode: mode, backup: nil)
        }
        return try trustedFileSnapshot(logical, mode: mode)
    }

    private func trustedFileSnapshot(_ logical: String, mode: mode_t) throws -> FileSnapshot {
        let data = try readTrustedFile(logical, mode: mode, maximum: 64 * 1024 * 1024)
        var facts = stat()
        try require(lstat(physical(logical), &facts) == 0, "snapshot_stat")
        return FileSnapshot(existed: true, sha256: bootstrapSHA256(data), size: data.count,
                            uid: facts.st_uid, gid: facts.st_gid, mode: facts.st_mode & 0o777,
                            backup: nil)
    }

    private func verifyInstalled(inputs: InstallInputs, attestation: ArtifactPin) throws {
        try verifyPin(Self.binaryPath, pin: inputs.broker, mode: 0o555)
        try verifyPin(Self.policyPath, pin: inputs.policy, mode: 0o444)
        try verifyPin(Self.attestationPath, pin: attestation, mode: 0o400)
        try verifyPin(Self.sudoersPath, pin: inputs.renderedSudoers, mode: 0o440)
        try validateDirectory(Self.auditPath, mode: 0o700)
        try validateDirectory(Self.brokerStagingPath, mode: 0o700)
    }

    private func rollback(state: inout TransactionState) throws {
        for target in [Self.sudoersPath, Self.attestationPath, Self.policyPath, Self.binaryPath] {
            guard let snapshot = state.files[target] else { continue }
            if exists(target) { try require(unlink(physical(target)) == 0, "rollback_unlink") }
            if snapshot.existed {
                guard let backup = snapshot.backup else {
                    throw BootstrapFailure.rejected("rollback_backup_missing")
                }
                try require(rename(physical(backup), physical(target)) == 0, "rollback_restore")
                let restored = try trustedFileSnapshot(target, mode: snapshot.mode)
                try require(restored.sha256 == snapshot.sha256 && restored.size == snapshot.size &&
                            restored.uid == snapshot.uid && restored.gid == snapshot.gid,
                            "rollback_file_verification")
            }
        }
        try cleanupStaging(state: &state, success: false)
        let expected = [Self.binaryPath, Self.policyPath, Self.attestationPath, Self.sudoersPath,
                        Self.auditPath, Self.brokerStagingPath]
        let priorInstalled = state.files.values.contains { $0.existed }
        if priorInstalled {
            try require(expected.allSatisfy(exists), "rollback_installed_state")
        } else {
            try require(expected.allSatisfy { !exists($0) }, "rollback_absent_state")
        }
    }

    private func cleanupStaging(state: inout TransactionState, success: Bool) throws {
        if !state.staging.isEmpty && exists(state.staging) {
            let prefix = physical(Self.bootstrapRoot) + "/transaction-"
            try require(physical(state.staging).hasPrefix(prefix), "staging_cleanup_scope")
            try FileManager.default.removeItem(atPath: physical(state.staging))
        }
        let keepOnSuccess = Set(["/etc/sudoers.d", "/etc/agent-first-mac",
                                 "/usr/local", "/usr/local/libexec",
                                 "/var/log/agent-first-mac",
                                 Self.auditPath, Self.brokerStagingPath,
                                 "/var/db/agent-first-mac"])
        for logical in state.createdDirectories.reversed() {
            if success && keepOnSuccess.contains(logical) { continue }
            if exists(logical) {
                try require(rmdir(physical(logical)) == 0, "directory_cleanup_not_empty")
            }
        }
    }

    private func ensureDirectory(_ logical: String, mode: mode_t,
                                 state: inout TransactionState) throws {
        if exists(logical) {
            try validateDirectory(logical, mode: mode)
            return
        }
        try require(mkdir(physical(logical), mode) == 0, "directory_create")
        try require(chown(physical(logical), context.trustedUID, context.trustedGID) == 0 &&
                    chmod(physical(logical), mode) == 0, "directory_owner_mode")
        state.createdDirectories.append(logical)
        try validateDirectory(logical, mode: mode)
    }

    private func validateDirectory(_ logical: String, mode: mode_t) throws {
        var facts = stat()
        try require(lstat(physical(logical), &facts) == 0 && (facts.st_mode & S_IFMT) == S_IFDIR &&
                    facts.st_uid == context.trustedUID && facts.st_gid == context.trustedGID &&
                    (facts.st_mode & 0o777) == mode, "directory_contract")
    }

    private func syncParent(_ logical: String) throws {
        let parent = URL(fileURLWithPath: physical(logical)).deletingLastPathComponent().path
        let fd = Darwin.open(parent, O_RDONLY | O_DIRECTORY)
        try require(fd >= 0, "parent_sync_open")
        defer { Darwin.close(fd) }
        try require(fsync(fd) == 0, "parent_sync")
    }

    private func exists(_ logical: String) -> Bool {
        var facts = stat()
        return lstat(physical(logical), &facts) == 0
    }

    private func physical(_ logical: String) -> String {
        context.rootPrefix == "/" ? logical : context.rootPrefix + logical
    }
}
