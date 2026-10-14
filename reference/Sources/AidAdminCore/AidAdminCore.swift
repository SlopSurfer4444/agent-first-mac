import CryptoKit
import Darwin
import Foundation
#if canImport(AidAdminRuntime)
import AidAdminRuntime
#endif

public let compiledPolicySHA256 = "dfa6376b60831d2dea55c9717a64fe37c6afe432f499b7181b2cd1854d919462"

public enum BrokerFailure: Error, CustomStringConvertible, Equatable {
    case rejected(String)

    public var description: String {
        switch self {
        case .rejected(let reason): return reason
        }
    }
}

private func require(_ condition: @autoclosure () -> Bool, _ reason: String) throws {
    if !condition() { throw BrokerFailure.rejected(reason) }
}

public func sha256Hex(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}

public func nativeBootGeneration() throws -> String {
    var boot = timeval()
    var size = MemoryLayout<timeval>.size
    try require(sysctlbyname("kern.boottime", &boot, &size, nil, 0) == 0 &&
                size == MemoryLayout<timeval>.size && boot.tv_sec > 0, "boot_generation_unavailable")
    return sha256Hex(Data("darwin-boot-v1:\(boot.tv_sec):\(boot.tv_usec)".utf8))
}

private func exactKeys(_ value: [String: Any], _ expected: Set<String>, _ context: String) throws {
    try require(Set(value.keys) == expected, "unexpected_\(context)_key")
}

private func exactObjectKeys(_ root: [String: Any], _ key: String, _ expected: Set<String>) throws {
    guard let value = root[key] as? [String: Any] else {
        throw BrokerFailure.rejected("policy_\(key)_not_object")
    }
    try exactKeys(value, expected, key)
}

public func validateCommit(_ value: String) throws {
    try validatePattern(value, "^[0-9a-f]{40}$", "commit_must_be_40_lowercase_hex")
}

private func validateHex(_ value: String, count: Int, reason: String) throws {
    try validatePattern(value, "^[0-9a-f]{\(count)}$", reason)
}

private func validatePattern(_ value: String, _ pattern: String, _ reason: String) throws {
    let expression = try NSRegularExpression(pattern: pattern)
    let range = NSRange(value.startIndex..<value.endIndex, in: value)
    try require(expression.firstMatch(in: value, range: range) != nil, reason)
}

private func validateLogicalPath(_ value: String) throws {
    try require(value.hasPrefix("/"), "path_not_absolute")
    let parts = value.split(separator: "/", omittingEmptySubsequences: false)
    try require(!parts.contains(".") && !parts.contains(".."), "path_traversal")
    try require(!value.contains("//"), "path_not_canonical")
}

private func validateRelativeSuffix(_ value: String) throws {
    try require(!value.isEmpty && !value.hasPrefix("/"), "suffix_not_relative")
    try require(!value.contains("//"), "suffix_not_canonical")
    let parts = value.split(separator: "/")
    try require(!parts.contains(".") && !parts.contains(".."), "suffix_traversal")
}

private func validateGenerationIdentifier(_ value: String) throws {
    try validatePattern(value, "^[1-9][0-9]{0,8}$", "generation_identifier")
}

private func validateCallerIdentity(_ value: String) throws {
    try validatePattern(value, "^[a-z_][a-z0-9_-]{0,31}$", "caller_identity")
}

public struct InstalledPaths: Codable, Equatable {
    public let attestation: String
    public let audit: String
    public let binary: String
    public let emergencyDisable: String
    public let policy: String
    public let staging: String
    public let sudoers: String
}

public struct ControlPolicy: Codable, Equatable {
    public let expectedBranch: String
    public let provenanceRule: String
    public let repositoryRule: String
    public let repositorySuffix: String
    public let requireClean: Bool
    public let requireExactHead: Bool
}

public struct ExecutablePolicy: Codable, Equatable {
    public let activation: String
    public let git: String
    public let nixEnv: String
    public let nixStore: String
}

public struct ApplyPolicy: Codable, Equatable {
    public let activationArguments: [String]
    public let applyGateAccepted: Bool
    public let profilePath: String
    public let receiptSuffix: String
    public let rollbackArguments: [String]
    public let storeRoot: String
}

public struct AuditPolicy: Codable, Equatable {
    public let maxRecordBytes: Int
    public let retentionDays: Int
    public let rollbackHint: String
}

public struct BrokerPolicy: Codable, Equatable {
    public let allowedCommands: [String]
    public let apply: ApplyPolicy
    public let audit: AuditPolicy
    public let control: ControlPolicy
    public let environment: [String: String]
    public let executables: ExecutablePolicy
    public let installedPaths: InstalledPaths
    public let preparationOnly: Bool
    public let schema: Int

    public static let cleanEnvironment = [
        "HOME": "/var/empty",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "TMPDIR": "/var/empty",
    ]

    public static func decodeStrict(_ data: Data) throws -> BrokerPolicy {
        let object = try JSONSerialization.jsonObject(with: data)
        guard let root = object as? [String: Any] else {
            throw BrokerFailure.rejected("policy_not_object")
        }
        try exactKeys(root, ["allowedCommands", "apply", "audit", "control", "environment",
                             "executables", "installedPaths", "preparationOnly", "schema"], "policy")
        try exactObjectKeys(root, "apply", ["activationArguments", "applyGateAccepted", "profilePath",
                                             "receiptSuffix", "rollbackArguments", "storeRoot"])
        try exactObjectKeys(root, "audit", ["maxRecordBytes", "retentionDays", "rollbackHint"])
        try exactObjectKeys(root, "control", ["expectedBranch", "provenanceRule", "repositoryRule",
                                               "repositorySuffix", "requireClean", "requireExactHead"])
        try exactObjectKeys(root, "executables", ["activation", "git", "nixEnv", "nixStore"])
        try exactObjectKeys(root, "installedPaths", ["attestation", "audit", "binary",
                                                    "emergencyDisable", "policy", "staging", "sudoers"])
        let policy = try JSONDecoder().decode(BrokerPolicy.self, from: data)
        try policy.validateContract()
        return policy
    }

    public func validateContract() throws {
        try require(schema == 2, "policy_schema")
        try require(allowedCommands == ["apply-system", "doctor-root"], "allowed_command_drift")
        try require(installedPaths == InstalledPaths(
            attestation: "/etc/agent-first-mac/aid-admin-install.json",
            audit: "/var/log/agent-first-mac/aid-admin",
            binary: "/usr/local/libexec/aid-admin",
            emergencyDisable: "/etc/agent-first-mac/aid-admin.disabled",
            policy: "/etc/agent-first-mac/aid-admin-policy.json",
            staging: "/var/db/agent-first-mac/staging",
            sudoers: "/etc/sudoers.d/agent-first-mac-aid-admin"
        ), "installed_path_drift")
        try require(control == ControlPolicy(
            expectedBranch: "main", provenanceRule: "local-reviewed-main-exact-head",
            repositoryRule: "caller-home-relative", repositorySuffix: "AIDev/control",
            requireClean: true, requireExactHead: true
        ), "control_policy_drift")
        try require(executables == ExecutablePolicy(
            activation: "/run/current-system/sw/bin/darwin-rebuild", git: "/usr/bin/git",
            nixEnv: "/nix/var/nix/profiles/default/bin/nix-env",
            nixStore: "/nix/var/nix/profiles/default/bin/nix-store"
        ), "executable_policy_drift")
        try require(apply.activationArguments == ["--switch-generation"] &&
                    apply.rollbackArguments == ["--switch-generation"] &&
                    apply.profilePath == "/nix/var/nix/profiles/system" &&
                    apply.receiptSuffix == "AIDev/state/phase-4/apply-receipts" &&
                    apply.storeRoot == "/nix/store", "apply_policy_drift")
        try require(environment == BrokerPolicy.cleanEnvironment, "environment_policy_drift")
        try require(audit.maxRecordBytes == 4096 && audit.retentionDays == 30 &&
                    audit.rollbackHint == "switch-to-exact-previous-generation-and-verify",
                    "audit_policy_drift")
        for path in [installedPaths.attestation, installedPaths.audit, installedPaths.binary,
                     installedPaths.emergencyDisable, installedPaths.policy, installedPaths.staging,
                     installedPaths.sudoers, executables.activation, executables.git,
                     executables.nixEnv, executables.nixStore, apply.profilePath, apply.storeRoot] {
            try validateLogicalPath(path)
        }
        try validateRelativeSuffix(control.repositorySuffix)
        try validateRelativeSuffix(apply.receiptSuffix)
    }
}

public struct RuntimeContext {
    public let rootPrefix: String
    public let trustedUID: uid_t
    public let realUID: uid_t
    public let effectiveUID: uid_t
    public let callerHome: String
    public let callerIdentity: String
    public let currentExecutablePath: String

    public init(rootPrefix: String = "/", trustedUID: uid_t = 0, realUID: uid_t,
                effectiveUID: uid_t, callerHome: String, callerIdentity: String,
                currentExecutablePath: String) {
        self.rootPrefix = rootPrefix
        self.trustedUID = trustedUID
        self.realUID = realUID
        self.effectiveUID = effectiveUID
        self.callerHome = callerHome
        self.callerIdentity = callerIdentity
        self.currentExecutablePath = currentExecutablePath
    }
}

public struct CommandResult: Equatable {
    public let status: Int32
    public let output: String
    public init(status: Int32, output: String) { self.status = status; self.output = output }
}

public protocol CommandRunning {
    func run(executable: String, arguments: [String], environment: [String: String]) throws -> CommandResult
}

public final class ProcessCommandRunner: CommandRunning {
    public init() {}
    public func run(executable: String, arguments: [String], environment: [String: String]) throws -> CommandResult {
        let result = try BoundedProcess.run(executable: executable, arguments: arguments, environment: environment)
        try require(result.settled && result.outcome == .exited,
                    "process_" + result.outcome.rawValue + "_needs_reconcile")
        return CommandResult(status: result.status,
                             output: String((result.stdout + result.stderr).prefix(8192)))
    }
}

public func fixedGitArguments(repository: String, command: [String]) -> [String] {
    [
        "--no-optional-locks",
        "-c", "safe.directory=\(repository)",
        "-c", "core.fsmonitor=false",
        "-c", "core.hooksPath=/dev/null",
        "-c", "core.pager=cat",
        "-c", "pager.status=false",
        "-c", "pager.branch=false",
        "-c", "diff.external=",
        "-C", repository,
    ] + command
}

public func fixedGitEnvironment(base: [String: String]) -> [String: String] {
    base.merging([
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_EXTERNAL_DIFF": "",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_PAGER": "cat",
        "GIT_TERMINAL_PROMPT": "0",
    ]) { _, fixed in fixed }
}

public struct AuditRecord: Codable, Equatable {
    public let actionID: String
    public let action: String
    public let callerClass: String
    public let controlCommit: String
    public let outcome: String
    public let exit: Int32
    public let policyHash: String
    public let previousGenerationIdentifier: String
    public let rollbackHint: String
    public let targetGenerationIdentifier: String
}

public protocol AuditWriting {
    func write(_ record: AuditRecord, directory: String, suffix: String, maximumBytes: Int) throws
}

public final class AtomicAuditWriter: AuditWriting {
    private let checkpoint: (String, String) throws -> Void
    public init(checkpoint: @escaping (String, String) throws -> Void = { _, _ in }) {
        self.checkpoint = checkpoint
    }
    public func write(_ record: AuditRecord, directory: String, suffix: String, maximumBytes: Int) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        var data = try encoder.encode(record)
        data.append(0x0a)
        try require(data.count <= maximumBytes, "audit_record_too_large")
        let final = directory + "/" + record.actionID + "." + suffix + ".json"
        // A killed publisher may leave its private temporary. A fresh publisher
        // never reuses/removes that ambiguous inode or collides with its name.
        let temporary = final + "." + UUID().uuidString.lowercased() + ".tmp"
        var existingInfo = stat()
        if lstat(final, &existingInfo) == 0 {
            try require(existingInfo.st_mode & S_IFMT == S_IFREG && existingInfo.st_uid == geteuid() &&
                        existingInfo.st_mode & 0o7777 == 0o600 && existingInfo.st_nlink == 1 &&
                        existingInfo.st_size == data.count, "audit_existing_identity_conflict")
            let existingFD = Darwin.open(final, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
            try require(existingFD >= 0, "audit_existing_open")
            defer { Darwin.close(existingFD) }
            let handle = FileHandle(fileDescriptor: existingFD, closeOnDealloc: false)
            let existing = try handle.read(upToCount: maximumBytes + 1) ?? Data()
            try require(existing == data, "audit_existing_content_conflict")
        } else {
            try require(errno == ENOENT, "audit_existing_lookup")
        }
        try checkpoint(suffix, "before_open")
        let fd = Darwin.open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
        try require(fd >= 0, "audit_open_failed")
        defer { Darwin.close(fd) }
        defer { unlink(temporary) }
        var offset = 0
        while offset < data.count {
            let count = data.withUnsafeBytes { raw -> Int in
                guard let base = raw.baseAddress else { return -1 }
                return Darwin.write(fd, base.advanced(by: offset), raw.count - offset)
            }
            if count <= 0 {
                unlink(temporary)
                throw BrokerFailure.rejected("audit_write_failed")
            }
            offset += count
            try checkpoint(suffix, "after_write")
        }
        if fsync(fd) != 0 {
            unlink(temporary)
            throw BrokerFailure.rejected("audit_commit_failed")
        }
        try checkpoint(suffix, "after_file_sync")
        if rename(temporary, final) != 0 { throw BrokerFailure.rejected("audit_commit_failed") }
        try checkpoint(suffix, "after_rename")
        let directoryFD = Darwin.open(directory, O_RDONLY | O_DIRECTORY)
        if directoryFD < 0 || fsync(directoryFD) != 0 {
            if directoryFD >= 0 { Darwin.close(directoryFD) }
            throw BrokerFailure.rejected("audit_directory_sync_failed")
        }
        Darwin.close(directoryFD)
        try checkpoint(suffix, "after_directory_sync")
    }
}

public struct ApplyReceipt: Codable, Equatable {
    public let controlCommit: String
    public let controlTree: String
    public let policyHash: String
    public let reviewed: Bool
    public let schema: Int
    public let targetSystemNarHash: String
    public let targetSystemPath: String

    static func decodeStrict(_ data: Data) throws -> ApplyReceipt {
        let object = try JSONSerialization.jsonObject(with: data)
        guard let root = object as? [String: Any] else {
            throw BrokerFailure.rejected("receipt_not_object")
        }
        try exactKeys(root, ["controlCommit", "controlTree", "policyHash", "reviewed", "schema",
                             "targetSystemNarHash", "targetSystemPath"], "receipt")
        let value = try JSONDecoder().decode(ApplyReceipt.self, from: data)
        try require(value.schema == 1 && value.reviewed, "receipt_not_reviewed")
        try validateCommit(value.controlCommit)
        try validateHex(value.controlTree, count: 40, reason: "control_tree")
        try validateHex(value.policyHash, count: 64, reason: "receipt_policy_hash")
        try validatePattern(value.targetSystemNarHash,
                            "^sha256:[0-9abcdfghijklmnpqrsvwxyz]{52}$",
                            "target_nar_hash")
        try validatePattern(value.targetSystemPath,
                            "^/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-darwin-system-[A-Za-z0-9._+-]{1,96}$",
                            "target_system_path")
        return value
    }
}

private struct StrictStringObjectParser {
    private let bytes: [UInt8]
    private var index = 0

    init(data: Data) throws {
        try require(String(data: data, encoding: .utf8) != nil, "strict_json_utf8")
        bytes = Array(data)
    }

    mutating func parse(expectedKeys: Set<String>, context: String) throws -> [String: String] {
        skipWhitespace()
        try consume(0x7b, reason: "\(context)_object")
        skipWhitespace()
        var result: [String: String] = [:]
        if peek() != 0x7d {
            while true {
                let key = try parseString(context: context)
                try require(result[key] == nil, "duplicate_\(context)_key")
                skipWhitespace()
                try consume(0x3a, reason: "\(context)_colon")
                skipWhitespace()
                result[key] = try parseString(context: context)
                skipWhitespace()
                if peek() == 0x2c {
                    index += 1
                    skipWhitespace()
                    continue
                }
                break
            }
        }
        try consume(0x7d, reason: "\(context)_object_end")
        skipWhitespace()
        try require(index == bytes.count, "\(context)_trailing_data")
        try require(Set(result.keys) == expectedKeys, "unexpected_\(context)_key")
        return result
    }

    private mutating func parseString(context: String) throws -> String {
        try consume(0x22, reason: "\(context)_string")
        let start = index
        while index < bytes.count && bytes[index] != 0x22 {
            let byte = bytes[index]
            try require(byte >= 0x20 && byte < 0x7f && byte != 0x5c,
                        "\(context)_string_escape_or_character")
            index += 1
        }
        try require(index < bytes.count, "\(context)_unterminated_string")
        let value = String(decoding: bytes[start..<index], as: UTF8.self)
        index += 1
        return value
    }

    private mutating func skipWhitespace() {
        while index < bytes.count && [0x09, 0x0a, 0x0d, 0x20].contains(bytes[index]) {
            index += 1
        }
    }

    private func peek() -> UInt8? {
        index < bytes.count ? bytes[index] : nil
    }

    private mutating func consume(_ expected: UInt8, reason: String) throws {
        try require(peek() == expected, reason)
        index += 1
    }
}

private struct DarwinVersionRecord {
    let configurationRevision: String
    let darwinLabel: String
    let darwinRevision: String
    let nixpkgsRevision: String

    static func decodeStrict(_ data: Data, expectedCommit: String) throws -> DarwinVersionRecord {
        var parser = try StrictStringObjectParser(data: data)
        let object = try parser.parse(
            expectedKeys: ["configurationRevision", "darwinLabel", "darwinRevision", "nixpkgsRevision"],
            context: "darwin_version")
        let value = DarwinVersionRecord(
            configurationRevision: object["configurationRevision"] ?? "",
            darwinLabel: object["darwinLabel"] ?? "",
            darwinRevision: object["darwinRevision"] ?? "",
            nixpkgsRevision: object["nixpkgsRevision"] ?? "")
        try validateCommit(value.configurationRevision)
        try validateCommit(value.darwinRevision)
        try validateCommit(value.nixpkgsRevision)
        try validatePattern(value.darwinLabel, "^[0-9A-Za-z][0-9A-Za-z._+-]{0,95}$",
                            "darwin_version_label")
        try require(value.configurationRevision == expectedCommit,
                    "target_configuration_revision_mismatch")
        return value
    }
}

public struct InstallAttestation: Codable, Equatable {
    public let agentOwnerIdentity: String
    public let agentOwnerUID: UInt32
    public let binarySHA256: String
    public let policySHA256: String
    public let schema: Int
    public let sudoersSHA256: String

    static func decodeStrict(_ data: Data) throws -> InstallAttestation {
        let object = try JSONSerialization.jsonObject(with: data)
        guard let root = object as? [String: Any] else {
            throw BrokerFailure.rejected("attestation_not_object")
        }
        try exactKeys(root, ["agentOwnerIdentity", "agentOwnerUID", "binarySHA256",
                             "policySHA256", "schema", "sudoersSHA256"], "attestation")
        let value = try JSONDecoder().decode(InstallAttestation.self, from: data)
        try require(value.schema == 1 && value.agentOwnerUID > 0, "attestation_identity")
        try validateCallerIdentity(value.agentOwnerIdentity)
        try validateHex(value.binarySHA256, count: 64, reason: "attestation_binary_hash")
        try validateHex(value.policySHA256, count: 64, reason: "attestation_policy_hash")
        try validateHex(value.sudoersSHA256, count: 64, reason: "attestation_sudoers_hash")
        return value
    }
}

public struct DoctorReport: Codable, Equatable {
    public let schema: Int
    public let command: String
    public let readOnly: Bool
    public let checks: [String: Bool]
    public let problems: [String]
    public let verdict: String
    public let systemMutationsPerformed: Bool
}

private struct GenerationState {
    let identifier: String
    let targetLogical: String
    let targetPhysical: String
}

private struct RollbackResult {
    let commandStatus: Int32
    let verified: Bool
}

public final class AidAdminBroker {
    private let context: RuntimeContext
    private let runner: CommandRunning
    private let auditWriter: AuditWriting
    private let expectedPolicyHash: String
    private let actionID: () -> String
    private let fixedPolicyPath = "/etc/agent-first-mac/aid-admin-policy.json"
    private var operationLease: ApplyOperationLease?
    private var operation: ApplyOperation?
    private let operationCheckpoint: (String) throws -> Void
    private let bootGeneration: () throws -> String

    public init(context: RuntimeContext, runner: CommandRunning = ProcessCommandRunner(),
                auditWriter: AuditWriting = AtomicAuditWriter(),
                expectedPolicyHash: String = compiledPolicySHA256,
                actionID: @escaping () -> String = { UUID().uuidString.lowercased() },
                operationCheckpoint: @escaping (String) throws -> Void = { _ in },
                bootGeneration: @escaping () throws -> String = nativeBootGeneration) {
        self.context = context
        self.runner = runner
        self.auditWriter = auditWriter
        self.expectedPolicyHash = expectedPolicyHash
        self.actionID = actionID
        self.operationCheckpoint = operationCheckpoint
        self.bootGeneration = bootGeneration
    }

    public func doctorRoot() -> DoctorReport {
        var checks: [String: Bool] = [:]
        var problems: [String] = []
        do {
            let (policy, hash) = try loadPolicy()
            checks["policy_hash"] = hash == expectedPolicyHash
            try require(hash == expectedPolicyHash, "policy_hash_drift")
            let disabled = pathExists(policy.installedPaths.emergencyDisable)
            checks["emergency_disable_absent"] = !disabled
            if disabled { problems.append("emergency_disabled") }
            try validateInstalledContract(policy, policyHash: hash, includeCurrentExecutable: true)
            checks["installed_artifact_attestation"] = true
            checks["installed_contract"] = true
            // Read-only doctor does not create a lock or repair transaction state.
            let journalPath = policy.installedPaths.staging + "/operation.json"
            if pathExists(journalPath) {
                let bytes = try readTrustedFile(journalPath, exactMode: 0o600, maximumBytes: 16384)
                try validateSettledApplyJournal(bytes)
            }
            checks["operation_settled"] = true
        } catch {
            problems.append(String(describing: error))
            checks["installed_artifact_attestation"] = false
            checks["installed_contract"] = false
        }
        return DoctorReport(schema: 1, command: "doctor-root", readOnly: true,
                            checks: checks, problems: Array(Set(problems)).sorted(),
                            verdict: problems.isEmpty ? "ROOT_CONTRACT_READY" : "BLOCKED",
                            systemMutationsPerformed: false)
    }

    public func applySystem(commit: String) throws -> Int32 {
        try validateCommit(commit)
        try require(context.effectiveUID == 0, "root_required")
        let (policy, policyHash) = try loadPolicy()
        try require(policyHash == expectedPolicyHash, "policy_hash_drift")
        try require(!policy.preparationOnly && policy.apply.applyGateAccepted, "phase4_apply_gate_closed")
        try require(!pathExists(policy.installedPaths.emergencyDisable), "emergency_disabled")
        try validateInstalledContract(policy, policyHash: policyHash, includeCurrentExecutable: true)

        let lease = try ApplyOperationLease(directory: physical(policy.installedPaths.staging), uid: context.trustedUID)
        operationLease = lease
        defer { operation = nil; operationLease = nil }
        if let pending = try lease.read(), !["complete", "rollback_verified", "resumed"].contains(pending.phase) {
            return try reconcileOperation(pending, lease: lease, commit: commit, policy: policy, policyHash: policyHash)
        }

        let activationExecutable = try physicalResolvedExecutable(policy.executables.activation, policy: policy)
        let nixEnvExecutable = try physicalValidatedNixApplet(
            policy.executables.nixEnv, expectedBasename: "nix-env", policy: policy)
        let repository = try callerRepository(policy)
        let controlTree = try validateRepository(repository, commit: commit, policy: policy)

        let receiptPath = try callerReceiptPath(policy, commit: commit)
        let receiptBytes = try readCallerFile(receiptPath, maximumBytes: 8192)
        let receipt = try ApplyReceipt.decodeStrict(receiptBytes)
        try require(receipt.controlCommit == commit && receipt.controlTree == controlTree &&
                    receipt.policyHash == policyHash, "receipt_binding_drift")

        let identifier = actionID()
        try validateActionID(identifier)
        let staging = try createStagingDirectory(policy.installedPaths.staging, identifier: identifier)
        let stagedReceiptPath = staging + "/apply-receipt.json"
        try writeExclusive(receiptBytes, logicalPath: stagedReceiptPath, mode: 0o400)
        let stagedBytes = try readTrustedFile(stagedReceiptPath, exactMode: 0o400, maximumBytes: 8192)
        try require(stagedBytes == receiptBytes, "staged_receipt_byte_drift")
        let stagedHash = sha256Hex(stagedBytes)
        let stagedReceipt = try ApplyReceipt.decodeStrict(stagedBytes)

        let previous = try currentGeneration(policy)
        try validateCurrentSystem(previous)
        let targetPhysical = try validateTargetClosure(stagedReceipt, expectedCommit: commit,
                                                       policy: policy)
        let beforeIdentifiers = try generationIdentifiers(policy)
        if targetPhysical != previous.targetPhysical {
            let existingTargets = try generationTargets(policy)
            try require(!existingTargets.values.contains(targetPhysical), "target_already_numbered")
        }

        let callerClass = context.realUID == 0 ? "root-direct" : "sudo-user"
        let preTarget = targetPhysical == previous.targetPhysical ? previous.identifier : "pending"
        let preRecord = auditRecord(identifier, outcome: "validated", status: 0, caller: callerClass,
                                    commit: commit, policyHash: policyHash, previous: previous.identifier,
                                    target: preTarget, policy: policy)
        try auditWriter.write(preRecord, directory: physical(policy.installedPaths.audit),
                              suffix: "pre", maximumBytes: policy.audit.maxRecordBytes)

        try recheckImmutableInputs(policy: policy, policyHash: policyHash, repository: repository,
                                   commit: commit, controlTree: controlTree,
                                   stagedReceiptPath: stagedReceiptPath, stagedHash: stagedHash,
                                   receipt: stagedReceipt)

        operation = ApplyOperation(schema: 2, identifier: identifier, commit: commit, tree: controlTree,
            policyHash: policyHash, receiptHash: stagedHash, previousIdentifier: previous.identifier,
            previousTarget: previous.targetLogical, target: stagedReceipt.targetSystemPath,
            activationExecutable: activationExecutable, activationHash: try executionHash(activationExecutable),
            nixEnvExecutable: nixEnvExecutable, nixEnvHash: try executionHash(nixEnvExecutable),
            caller: callerClass, targetIdentifier: preTarget, phase: "sealed", sourceDrift: false)
        operation?.bootGeneration = try validatedBootGeneration()
        operation?.previousNarHash = try observedNarHash(previous.targetLogical, policy: policy)
        operation?.targetNarHash = stagedReceipt.targetSystemNarHash
        operation?.previousRevision = try closureRevision(previous.targetLogical, policy: policy)
        try persistOperation("sealed")

        if targetPhysical == previous.targetPhysical {
            let current = try currentGeneration(policy)
            try require(current.identifier == previous.identifier && current.targetPhysical == previous.targetPhysical,
                        "noop_prestate_changed_no_mutation")
            try validateCurrentSystem(previous)
            try persistOperation("committed")
            let record = auditRecord(identifier, outcome: "already_current", status: 0,
                                     caller: callerClass, commit: commit, policyHash: policyHash,
                                     previous: previous.identifier, target: previous.identifier, policy: policy)
            try publishCommittedAudit(record, policy: policy)
            return 0
        }

        let setResult: CommandResult
        try verifySealedExecutors()
        try require(!pathExists(policy.installedPaths.emergencyDisable), "emergency_disabled_before_profile")
        try persistOperation("profile_pending")
        do {
            setResult = try runner.run(executable: nixEnvExecutable,
                                       arguments: ["--profile", policy.apply.profilePath,
                                                   "--set", stagedReceipt.targetSystemPath],
                                       environment: policy.environment)
        } catch {
            if String(describing: error).contains("process_") {
                try? persistOperation("unknown")
                throw BrokerFailure.rejected("profile_process_unknown_needs_reconcile")
            }
            return try failAfterMutation("profile_update_launch_failed", status: 127,
                                         identifier: identifier, caller: callerClass, commit: commit,
                                         policyHash: policyHash, previous: previous, target: "pending",
                                         rollbackExecutable: activationExecutable, policy: policy)
        }
        if setResult.status != 0 {
            return try failAfterMutation("profile_update_failed", status: setResult.status,
                                         identifier: identifier, caller: callerClass, commit: commit,
                                         policyHash: policyHash, previous: previous, target: "pending",
                                         rollbackExecutable: activationExecutable, policy: policy)
        }

        let targetGeneration: GenerationState
        do {
            let after = try currentGeneration(policy)
            let afterIdentifiers = try generationIdentifiers(policy)
            let created = afterIdentifiers.subtracting(beforeIdentifiers)
            try require(created.count == 1 && created.contains(after.identifier), "new_generation_not_unique")
            try require(after.targetPhysical == targetPhysical, "new_generation_target_mismatch")
            targetGeneration = after
            operation?.targetIdentifier = after.identifier
            try persistOperation("profile_ready")
        } catch {
            return try failAfterMutation("profile_update_verification_failed", status: 70,
                                         identifier: identifier, caller: callerClass, commit: commit,
                                         policyHash: policyHash, previous: previous, target: "unknown",
                                         rollbackExecutable: activationExecutable, policy: policy)
        }

        let activation: CommandResult
        try verifySealedExecutors()
        try require(!pathExists(policy.installedPaths.emergencyDisable), "emergency_disabled_before_activation")
        try persistOperation("activation_pending")
        do {
            activation = try runner.run(executable: activationExecutable,
                                        arguments: policy.apply.activationArguments + [targetGeneration.identifier],
                                        environment: activationEnvironment(policy))
        } catch {
            if String(describing: error).contains("process_") {
                try? persistOperation("unknown")
                throw BrokerFailure.rejected("activation_process_unknown_needs_reconcile")
            }
            return try failAfterMutation("activation_launch_failed", status: 127,
                                         identifier: identifier, caller: callerClass, commit: commit,
                                         policyHash: policyHash, previous: previous,
                                         target: targetGeneration.identifier,
                                         rollbackExecutable: activationExecutable, policy: policy)
        }
        if activation.status != 0 {
            return try failAfterMutation("activation_failed", status: activation.status,
                                         identifier: identifier, caller: callerClass, commit: commit,
                                         policyHash: policyHash, previous: previous,
                                         target: targetGeneration.identifier,
                                         rollbackExecutable: activationExecutable, policy: policy)
        }

        do {
            try recheckImmutableInputs(policy: policy, policyHash: policyHash, repository: repository,
                                       commit: commit, controlTree: controlTree,
                                       stagedReceiptPath: stagedReceiptPath, stagedHash: stagedHash,
                                       receipt: stagedReceipt, checkRepository: false)
            try verifySealedExecutors()
            let current = try currentGeneration(policy)
            try require(current.identifier == targetGeneration.identifier &&
                        current.targetPhysical == targetPhysical, "post_apply_profile_mismatch")
            try validateCurrentSystem(current)
        } catch {
            if String(describing: error).contains("process_") {
                try? persistOperation("unknown")
                throw BrokerFailure.rejected("verification_process_unknown_no_rollback")
            }
            return try failAfterMutation("post_apply_verification_failed", status: 70,
                                         identifier: identifier, caller: callerClass, commit: commit,
                                         policyHash: policyHash, previous: previous,
                                         target: targetGeneration.identifier,
                                         rollbackExecutable: activationExecutable, policy: policy)
        }

        // Git is mutable owner state, not an input once the execution seal exists.
        // It can block the next operation, but is not an inverse trigger here.
        do {
            operation?.sourceDrift = try validateRepository(repository, commit: commit, policy: policy) != controlTree
        } catch {
            operation?.sourceDrift = true
            if String(describing: error).contains("process_") {
                try? persistOperation("unknown")
                throw BrokerFailure.rejected("applied_source_observation_process_unknown_no_rollback")
            }
        }
        try persistOperation("committed")

        let record = auditRecord(identifier, outcome: "applied", status: 0, caller: callerClass,
                                 commit: commit, policyHash: policyHash, previous: previous.identifier,
                                 target: targetGeneration.identifier, policy: policy)
        try publishCommittedAudit(record, policy: policy)
        return 0
    }

    private func persistOperation(_ phase: String) throws {
        guard var value = operation, let lease = operationLease else {
            throw BrokerFailure.rejected("operation_missing_unknown")
        }
        value.phase = phase
        try lease.write(value)
        operation = value
        try operationCheckpoint(phase)
    }

    private func validatedBootGeneration() throws -> String {
        let value = try bootGeneration()
        try validateHex(value, count: 64, reason: "boot_generation_invalid")
        return value
    }

    private func observedNarHash(_ target: String, policy: BrokerPolicy) throws -> String {
        _ = try validateClosureFilesystem(target, policy: policy)
        let executable = try physicalValidatedNixApplet(policy.executables.nixStore,
            expectedBasename: "nix-store", policy: policy)
        let verify = try runner.run(executable: executable, arguments: ["--verify-path", target],
                                    environment: policy.environment)
        try require(verify.status == 0, "recovery_closure_verify_failed")
        let result = try runner.run(executable: executable, arguments: ["--query", "--hash", target],
                                    environment: policy.environment)
        let hash = result.output.trimmingCharacters(in: .whitespacesAndNewlines)
        try require(result.status == 0, "recovery_closure_hash_failed")
        try validatePattern(hash, "^sha256:[0-9abcdfghijklmnpqrsvwxyz]{52}$", "recovery_closure_hash")
        return hash
    }

    private func closureRevision(_ target: String, policy: BrokerPolicy) throws -> String {
        let path = try canonicalPhysical(target + "/darwin-version.json", allowSymlink: true)
        let bytes = try readImmutableStoreFile(logicalFromPhysical(path), policy: policy, maximumBytes: 4096)
        var parser = try StrictStringObjectParser(data: bytes)
        let object = try parser.parse(expectedKeys: ["configurationRevision", "darwinLabel", "darwinRevision", "nixpkgsRevision"],
                                      context: "recovery_revision")
        let revision = object["configurationRevision"] ?? ""
        try validateClosureRevision(target, expectedCommit: revision, policy: policy)
        return revision
    }

    private func executionHash(_ path: String) throws -> String {
        let resolved = try canonicalArbitraryPhysical(path)
        let fd = Darwin.open(resolved, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        try require(fd >= 0, "sealed_executor_open")
        defer { Darwin.close(fd) }
        var info = stat()
        try require(fstat(fd, &info) == 0 && info.st_uid == context.trustedUID &&
                    info.st_mode & S_IFMT == S_IFREG && info.st_mode & 0o222 == 0 &&
                    info.st_size >= 0 && info.st_size <= 32 * 1024 * 1024, "sealed_executor_identity")
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: false)
        let data = try handle.read(upToCount: Int(info.st_size) + 1) ?? Data()
        try require(data.count == info.st_size, "sealed_executor_size")
        return sha256Hex(data)
    }

    private func verifySealedExecutors() throws {
        guard let value = operation else { throw BrokerFailure.rejected("operation_missing_unknown") }
        let activationHash = try executionHash(value.activationExecutable)
        let nixEnvHash = try executionHash(value.nixEnvExecutable)
        try require(activationHash == value.activationHash, "sealed_activation_drift")
        try require(nixEnvHash == value.nixEnvHash, "sealed_nix_env_drift")
    }

    private func publishCommittedAudit(_ record: AuditRecord, policy: BrokerPolicy) throws {
        do {
            try auditWriter.write(record, directory: physical(policy.installedPaths.audit),
                                  suffix: "result", maximumBytes: policy.audit.maxRecordBytes)
            try persistOperation("complete")
        } catch {
            // A renamed applied audit may already be visible. The durable
            // operational commit is never inverted merely to repair logging.
            try? persistOperation("audit_incomplete")
            throw BrokerFailure.rejected("applied_audit_incomplete_needs_reconcile")
        }
    }

    private func reconcileOperation(_ pending: ApplyOperation, lease: ApplyOperationLease,
                                    commit: String, policy: BrokerPolicy, policyHash: String) throws -> Int32 {
        try require(pending.commit == commit && pending.policyHash == policyHash,
                    "operation_pending_different_identity")
        operation = pending
        if pending.phase == "sealed" {
            let current = try currentGeneration(policy)
            try require(current.identifier == pending.previousIdentifier && current.targetLogical == pending.previousTarget,
                        "sealed_prestate_drift_unknown")
            try validateCurrentSystem(current)
            try persistOperation("rollback_verified")
            throw BrokerFailure.rejected("interrupted_before_mutation_reconciled_no_apply")
        }
        if pending.phase == "profile_ready" {
            let current = try currentGeneration(policy)
            try require(current.identifier == pending.targetIdentifier && current.targetLogical == pending.target,
                        "interrupted_profile_foreign_unknown")
            let previousPhysical = try validateClosureFilesystem(pending.previousTarget, policy: policy)
            let previous = GenerationState(identifier: pending.previousIdentifier,
                targetLogical: pending.previousTarget, targetPhysical: previousPhysical)
            // profile_ready is durable only after --set has settled, and before
            // activation can spawn. Reconcile this owned intermediate state only
            // while the running system is still the exact previous generation.
            try validateCurrentSystem(previous)
            try verifySealedExecutors()
            return try failAfterMutation("interrupted_profile_reconciled", status: 70,
                identifier: pending.identifier, caller: pending.caller, commit: pending.commit,
                policyHash: pending.policyHash, previous: previous, target: pending.targetIdentifier,
                rollbackExecutable: pending.activationExecutable, policy: policy)
        }
        // Only the durable commit attests settled activation. Matching symlinks
        // alone cannot establish completion or payload recovery after a crash.
        try require(["committed", "audit_incomplete"].contains(pending.phase),
                    "operation_unknown_requires_owner_reconciliation_" + pending.phase)
        let receiptPath = policy.installedPaths.staging + "/" + pending.identifier + "/apply-receipt.json"
        let bytes = try readTrustedFile(receiptPath, exactMode: 0o400, maximumBytes: 8192)
        try require(sha256Hex(bytes) == pending.receiptHash, "operation_receipt_drift")
        let receipt = try ApplyReceipt.decodeStrict(bytes)
        try require(receipt.controlCommit == pending.commit && receipt.controlTree == pending.tree &&
                    receipt.policyHash == pending.policyHash && receipt.targetSystemPath == pending.target,
                    "operation_seal_drift")
        _ = try validateTargetClosure(receipt, expectedCommit: pending.commit, policy: policy)
        try verifySealedExecutors()
        let current = try currentGeneration(policy)
        try require(current.identifier == pending.targetIdentifier && current.targetLogical == pending.target,
                    "operation_committed_state_drift_unknown")
        try validateCurrentSystem(current)
        let record = auditRecord(pending.identifier,
            outcome: pending.previousTarget == pending.target ? "already_current" : "applied",
            status: 0, caller: pending.caller, commit: pending.commit, policyHash: pending.policyHash,
            previous: pending.previousIdentifier, target: pending.targetIdentifier, policy: policy)
        try publishCommittedAudit(record, policy: policy)
        return 0
    }

    public func inspectOperation() throws -> [String: String] {
        let (policy, hash) = try loadPolicy()
        try require(hash == expectedPolicyHash, "policy_hash_drift")
        let path = policy.installedPaths.staging + "/operation.json"
        guard pathExists(path) else { return ["state": "no_operation", "system_mutations_performed": "false"] }
        let bytes = try readTrustedFile(path, exactMode: 0o600, maximumBytes: 16384)
        let value = try ApplyOperation.decodeStrict(bytes)
        try validateCommit(value.commit)
        var report = ["state": value.phase, "operation_id": value.identifier,
                "applied_target_revision": value.commit, "source_drift": String(value.sourceDrift),
                "generation_recovery_is_payload_recovery": "false",
                "system_mutations_performed": "false",
                "next_action": ["committed", "audit_incomplete", "profile_ready", "sealed"].contains(value.phase)
                    ? "repeat_exact_apply_system_commit_to_reconcile_without_duplicate_apply"
                    : (["complete", "rollback_verified", "resumed"].contains(value.phase) ? "none"
                       : (value.phase == "resume_committed" ? "fresh_authenticated_exact_target_resume_audit_only"
                          : (value.schema == 1 ? "schema1_unknown_requires_separate_reviewed_migration"
                             : "owner_disable_reboot_then_fresh_authenticated_exact_target_resume")))]
        if value.schema == 2 {
            report.merge(["schema": "2", "operation_seal_sha256": try value.sealSHA256(),
                "staged_receipt_sha256": value.receiptHash, "policy_hash": value.policyHash,
                "original_boot_generation": value.bootGeneration ?? "",
                "last_attempt_boot_generation": value.lastAttemptBoot ?? value.bootGeneration ?? "",
                "resume_attempt_count": String(value.resumeAttemptCount ?? 0),
                "current_boot_generation": try validatedBootGeneration(),
                "previous_target_path": value.previousTarget, "previous_nar_hash": value.previousNarHash ?? "",
                "target_path": value.target, "target_nar_hash": value.targetNarHash ?? "",
                "previous_generation_identifier": value.previousIdentifier, "target_generation_identifier": value.targetIdentifier,
                "target_revision": value.commit, "previous_revision": value.previousRevision ?? ""]) { _, new in new }
        }
        return report
    }

    /// Called only by the compiled fresh-standard-sudo emergency action while
    /// its emergency lock is held. This authorizes a NEW exact-target attempt;
    /// it does not assert that old effects or arbitrary payload data were restored.
    public func resumeInterruptedOperation(commit: String) throws -> String {
        try validateCommit(commit)
        try require(context.effectiveUID == 0 && context.realUID != 0, "resume_owner_root_required")
        let (policy, policyHash) = try loadPolicy()
        try require(policyHash == expectedPolicyHash && !policy.preparationOnly && policy.apply.applyGateAccepted,
                    "resume_policy_binding")
        try validateInstalledContract(policy, policyHash: policyHash, includeCurrentExecutable: false, disabled: true)
        let lease = try ApplyOperationLease(directory: physical(policy.installedPaths.staging), uid: context.trustedUID)
        operationLease = lease
        defer { operation = nil; operationLease = nil }
        guard let pending = try lease.read() else { throw BrokerFailure.rejected("resume_operation_missing") }
        try require(pending.schema == 2, "schema1_unknown_requires_separate_reviewed_migration")
        try require(pending.commit == commit && pending.policyHash == policyHash, "resume_operation_binding")
        try require(!["complete", "rollback_verified"].contains(pending.phase), "resume_operation_already_settled")
        operation = pending
        let boot = try validatedBootGeneration()
        let auditOnly = ["resume_committed", "resumed"].contains(pending.phase)
        if !auditOnly {
            try require((pending.lastAttemptBoot ?? pending.bootGeneration) != boot, "resume_requires_changed_last_attempt_boot")
            try require((pending.resumeAttemptCount ?? 0) < 16, "resume_attempt_limit_owner_handoff")
        }
        let receiptPath = policy.installedPaths.staging + "/" + pending.identifier + "/apply-receipt.json"
        let original = try readTrustedFile(receiptPath, exactMode: 0o400, maximumBytes: 8192)
        try require(sha256Hex(original) == pending.receiptHash, "resume_original_receipt_drift")
        let receipt = try ApplyReceipt.decodeStrict(original)
        try require(receipt.controlCommit == commit && receipt.controlTree == pending.tree &&
                    receipt.policyHash == policyHash && receipt.targetSystemPath == pending.target &&
                    receipt.targetSystemNarHash == pending.targetNarHash, "resume_original_binding")
        let targetPhysical = try validateTargetClosure(receipt, expectedCommit: commit, policy: policy)
        let previousPhysical = try validateClosureFilesystem(pending.previousTarget, policy: policy)
        try validateClosureRevision(pending.previousTarget, expectedCommit: pending.previousRevision!, policy: policy)
        let previousNar = try observedNarHash(pending.previousTarget, policy: policy)
        try require(previousNar == pending.previousNarHash, "resume_previous_closure_drift")
        try verifySealedExecutors()

        // These reviewed generated guards were not present in historical targets.
        // Fresh authentication cannot upgrade an immutable old activation script.
        let activation = String(decoding: try readImmutableStoreFile(pending.target + "/activate",
            policy: policy, maximumBytes: 1024 * 1024), as: UTF8.self)
        for marker in ["aid-admin-resume-windows-marker-guards-v1", "aid-admin-resume-rustdesk-marker-guards-v1"] {
            try require(activation.contains(marker), "resume_target_entry_guards_unavailable")
        }
        try validateResumeStaging()
        let jobs = ResumeLaunchdVerifier(context: context, runner: runner, environment: policy.environment)
        try jobs.validateInventory(target: pending.target, previous: pending.previousTarget)
        let home = ResumeHomeManagerVerifier(context: context, runner: runner, environment: policy.environment)
        try home.validateInventory(target: pending.target)
        // The original hook itself contains rsync --delete. Refuse divergent
        // owner additions BEFORE replay, not merely after its destructive hook.
        try home.converge(target: pending.target, beforeRepair: {
            throw BrokerFailure.rejected("resume_home_prestate_no_repair")
        })

        func checkCapturedPrestate() throws -> [String: String] {
            let targets = try generationTargets(policy)
            try require(targets[pending.previousIdentifier] == previousPhysical, "resume_previous_generation_drift")
            let current = try currentGeneration(policy)
            try require((current.identifier == pending.previousIdentifier && current.targetPhysical == previousPhysical) ||
                        (current.targetPhysical == targetPhysical &&
                         (pending.targetIdentifier == "pending" || current.identifier == pending.targetIdentifier)),
                        "resume_foreign_profile")
            let running = try canonicalPhysical("/run/current-system", allowSymlink: true)
            try require(running == previousPhysical || running == targetPhysical, "resume_foreign_running_system")
            return targets
        }
        func verifyAppliedState() throws {
            try recheckImmutableInputs(policy: policy, policyHash: policyHash, repository: "", commit: commit,
                controlTree: pending.tree, stagedReceiptPath: receiptPath, stagedHash: pending.receiptHash,
                receipt: receipt, checkRepository: false)
            try verifySealedExecutors()
            try validateInstalledContract(policy, policyHash: policyHash, includeCurrentExecutable: false, disabled: true)
            let current = try currentGeneration(policy)
            try require(current.identifier == operation?.targetIdentifier && current.targetPhysical == targetPhysical,
                        "resume_post_apply_profile_mismatch")
            try validateCurrentSystem(current)
            let finalBoot = try validatedBootGeneration()
            try require(finalBoot == boot, "resume_boot_drift")
            try validateResumeStaging()
        }
        func publishResumeAudit() throws {
            let record = auditRecord(pending.identifier, outcome: "resumed_applied", status: 0,
                caller: pending.caller, commit: commit, policyHash: policyHash,
                previous: pending.previousIdentifier, target: operation!.targetIdentifier, policy: policy)
            do {
                try auditWriter.write(record, directory: physical(policy.installedPaths.audit),
                    suffix: "resume-" + String(operation!.resumeAttemptCount!) + "-result", maximumBytes: policy.audit.maxRecordBytes)
                try persistOperation("resumed")
            } catch {
                throw BrokerFailure.rejected("resumed_applied_audit_incomplete_disabled")
            }
        }
        if auditOnly {
            try verifyAppliedState()
            try jobs.converge(target: pending.target, previous: pending.previousTarget, beforeBootstrap: {
                throw BrokerFailure.rejected("resumed_committed_job_drift_no_mutation")
            })
            try home.converge(target: pending.target, beforeRepair: {
                throw BrokerFailure.rejected("resumed_committed_home_drift_no_mutation")
            })
            try verifyAppliedState()
            if pending.phase == "resume_committed" { try publishResumeAudit() }
            return "OPERATION_RESUMED_DISABLED"
        }

        let beforeTargets = try checkCapturedPrestate()
        let matching = beforeTargets.filter { $0.value == targetPhysical }.map { $0.key }
        try require(matching.count <= 1, "resume_ambiguous_target_generation")
        if pending.targetIdentifier != "pending" {
            try require(matching == [pending.targetIdentifier], "resume_recorded_target_generation_drift")
        }
        let latestBoot = try validatedBootGeneration()
        try require(latestBoot == boot, "resume_boot_drift")
        try validateInstalledContract(policy, policyHash: policyHash, includeCurrentExecutable: false, disabled: true)
        operation?.lastAttemptBoot = boot
        operation?.resumeAttemptCount = (pending.resumeAttemptCount ?? 0) + 1
        if let existing = matching.first { operation?.targetIdentifier = existing }
        let pre = auditRecord(pending.identifier, outcome: "resume_authorized", status: 0,
            caller: pending.caller, commit: commit, policyHash: policyHash,
            previous: pending.previousIdentifier, target: operation!.targetIdentifier, policy: policy)
        try auditWriter.write(pre, directory: physical(policy.installedPaths.audit),
            suffix: "resume-" + String(operation!.resumeAttemptCount!) + "-pre", maximumBytes: policy.audit.maxRecordBytes)
        // Durable latest-attempt boot BEFORE any profile/activation/corrective job mutation.
        try persistOperation("resume_pending")
        do {
            _ = try checkCapturedPrestate()
            try verifySealedExecutors()
            if matching.isEmpty {
                let set = try runner.run(executable: pending.nixEnvExecutable,
                    arguments: ["--profile", policy.apply.profilePath, "--set", pending.target],
                    environment: policy.environment)
                try require(set.status == 0, "resume_profile_update_failed")
                let current = try currentGeneration(policy)
                let after = try generationTargets(policy)
                let created = Set(after.keys).subtracting(beforeTargets.keys)
                try require(current.targetPhysical == targetPhysical && created == [current.identifier],
                            "resume_profile_allocation_mismatch")
                operation?.targetIdentifier = current.identifier
                try persistOperation("resume_pending")
            }
            try verifySealedExecutors()
            // Pre-audit/journal/profile I/O must not leave a stale admission for
            // upstream's copy-if-different job transition or a foreign plist.
            try jobs.validateInventory(target: pending.target, previous: pending.previousTarget)
            try home.converge(target: pending.target, beforeRepair: {
                throw BrokerFailure.rejected("resume_home_prestate_no_repair")
            })
            // Deliberately no already-current fast path. Pinned darwin-rebuild
            // switches the numbered profile and executes its activate script.
            let result = try runner.run(executable: pending.activationExecutable,
                arguments: policy.apply.activationArguments + [operation!.targetIdentifier],
                environment: activationEnvironment(policy))
            try require(result.status == 0, "resume_activation_failed")
            try verifyAppliedState()
            try jobs.converge(target: pending.target, previous: pending.previousTarget, beforeBootstrap: {
                try self.verifySealedExecutors()
                try self.persistOperation("resume_pending")
            })
            try home.converge(target: pending.target, beforeRepair: {
                try self.verifySealedExecutors()
                try self.persistOperation("resume_pending")
            })
            try verifyAppliedState()
        } catch {
            // New attempt failure is not evidence that either generation's
            // effects were restored; never invoke the old inverse here.
            try? persistOperation("unknown")
            throw BrokerFailure.rejected("resume_failed_or_unknown_disabled:" + String(describing: error))
        }
        // If this publication itself is uncertain, retain the visible journal;
        // never overwrite a possibly committed state with rollback/UNKNOWN.
        try persistOperation("resume_committed")
        try publishResumeAudit()
        return "OPERATION_RESUMED_DISABLED"
    }

    private func validateResumeStaging() throws {
        let applications = physical("/Applications")
        if pathExists("/Applications") {
            let names = try FileManager.default.contentsOfDirectory(atPath: applications)
            try require(!names.contains(where: { $0.hasPrefix(".gametomac-stage.") }),
                        "resume_gametomac_retained_stage_owner_handoff")
        }
    }

    private func failAfterMutation(_ failure: String, status: Int32, identifier: String,
                                   caller: String, commit: String, policyHash: String,
                                   previous: GenerationState, target: String,
                                   rollbackExecutable: String, policy: BrokerPolicy) throws -> Int32 {
        // Compare before inverse: never roll back a foreign generation or closure.
        guard let owned = operation else { throw BrokerFailure.rejected("operation_missing_unknown") }
        let current = try currentGeneration(policy)
        try require((current.identifier == previous.identifier && current.targetLogical == previous.targetLogical) ||
                    (current.targetLogical == owned.target && (target == "pending" || target == "unknown" || current.identifier == target)),
                    "foreign_generation_unknown_no_rollback")
        let previousLink = try canonicalPhysical(policy.apply.profilePath + "-" + previous.identifier + "-link",
                                                 allowSymlink: true)
        try require(previousLink == previous.targetPhysical, "previous_generation_drift_unknown_no_rollback")
        let running = try canonicalPhysical("/run/current-system", allowSymlink: true)
        try require(running == previous.targetPhysical || running == physical(owned.target),
                    "foreign_running_system_unknown_no_rollback")
        try verifySealedExecutors()
        try persistOperation("rollback_pending")
        let rollback = rollbackAndVerify(previous, executable: rollbackExecutable, policy: policy)
        let outcome: String
        if rollback.commandStatus != 0 {
            outcome = failure + "_rollback_command_failed"
        } else if !rollback.verified {
            outcome = failure + "_rollback_verification_failed"
        } else {
            outcome = failure + "_rolled_back"
        }
        // This attests generation links only, never restoration of payload data.
        try persistOperation(rollback.commandStatus == 0 && rollback.verified ? "rollback_verified" : "unknown")
        let record = auditRecord(identifier, outcome: outcome, status: status, caller: caller,
                                 commit: commit, policyHash: policyHash, previous: previous.identifier,
                                 target: target, policy: policy)
        do {
            try auditWriter.write(record, directory: physical(policy.installedPaths.audit),
                                  suffix: "result", maximumBytes: policy.audit.maxRecordBytes)
        } catch {
            throw BrokerFailure.rejected(outcome + "_audit_failed")
        }
        if rollback.commandStatus != 0 {
            throw BrokerFailure.rejected(outcome)
        }
        if !rollback.verified {
            throw BrokerFailure.rejected(outcome)
        }
        return status == 0 ? 70 : status
    }

    private func rollbackAndVerify(_ previous: GenerationState, executable: String,
                                   policy: BrokerPolicy) -> RollbackResult {
        let status: Int32
        do {
            status = try runner.run(executable: executable,
                                    arguments: policy.apply.rollbackArguments + [previous.identifier],
                                    environment: activationEnvironment(policy)).status
        } catch {
            status = 127
        }
        var verified = false
        do {
            let current = try currentGeneration(policy)
            try require(current.identifier == previous.identifier &&
                        current.targetPhysical == previous.targetPhysical,
                        "rollback_profile_mismatch")
            try validateCurrentSystem(previous)
            verified = true
        } catch {
            verified = false
        }
        return RollbackResult(commandStatus: status, verified: verified)
    }

    private func auditRecord(_ id: String, outcome: String, status: Int32, caller: String,
                             commit: String, policyHash: String, previous: String,
                             target: String, policy: BrokerPolicy) -> AuditRecord {
        AuditRecord(actionID: id, action: "apply-system", callerClass: caller,
                    controlCommit: commit, outcome: outcome, exit: status, policyHash: policyHash,
                    previousGenerationIdentifier: previous, rollbackHint: policy.audit.rollbackHint,
                    targetGenerationIdentifier: target)
    }

    private func recheckImmutableInputs(policy: BrokerPolicy, policyHash: String,
                                        repository: String, commit: String, controlTree: String,
                                        stagedReceiptPath: String, stagedHash: String,
                                        receipt: ApplyReceipt, checkRepository: Bool = true) throws {
        let (_, secondPolicyHash) = try loadPolicy()
        try require(secondPolicyHash == policyHash, "policy_hash_drift")
        if checkRepository {
            let secondTree = try validateRepository(repository, commit: commit, policy: policy)
            try require(secondTree == controlTree, "control_tree_drift")
        }
        let secondBytes = try readTrustedFile(stagedReceiptPath, exactMode: 0o400, maximumBytes: 8192)
        let secondReceipt = try ApplyReceipt.decodeStrict(secondBytes)
        try require(sha256Hex(secondBytes) == stagedHash && secondReceipt == receipt,
                    "staged_receipt_drift")
        _ = try validateTargetClosure(receipt, expectedCommit: commit, policy: policy)
    }

    private func validateInstalledContract(_ policy: BrokerPolicy, policyHash: String,
                                           includeCurrentExecutable: Bool, disabled: Bool = false) throws {
        let binary = try readTrustedFile(policy.installedPaths.binary, exactMode: 0o555,
                                         maximumBytes: 32 * 1024 * 1024)
        let installedPolicy = try readTrustedFile(policy.installedPaths.policy, exactMode: 0o444,
                                                  maximumBytes: 64 * 1024)
        if disabled {
            try require(!pathExists(policy.installedPaths.sudoers), "reconciliation_requires_disabled_grant")
            let marker = try readTrustedFile(policy.installedPaths.emergencyDisable, exactMode: 0o400, maximumBytes: 128)
            try require(marker == Data("agent-first-mac-aid-admin-disabled-v1\n".utf8), "reconciliation_disable_marker")
        }
        let sudoers = try readTrustedFile(policy.installedPaths.sudoers + (disabled ? ".disabled" : ""), exactMode: 0o440,
                                          maximumBytes: 4096)
        let attestationData = try readTrustedFile(policy.installedPaths.attestation, exactMode: 0o400,
                                                  maximumBytes: 4096)
        let attestation = try InstallAttestation.decodeStrict(attestationData)
        try require(attestation.agentOwnerUID == context.realUID &&
                    attestation.agentOwnerIdentity == context.callerIdentity, "caller_not_installed_owner")
        try require(attestation.binarySHA256 == sha256Hex(binary) &&
                    attestation.policySHA256 == policyHash &&
                    attestation.policySHA256 == sha256Hex(installedPolicy) &&
                    attestation.sudoersSHA256 == sha256Hex(sudoers), "installed_artifact_hash_drift")
        try validateDirectory(policy.installedPaths.staging, exactMode: 0o700)
        try validateDirectory(policy.installedPaths.audit, exactMode: 0o700)
        try validateExecutable(policy.executables.git, policy: policy)
        try validateExecutable(policy.executables.activation, policy: policy)
        _ = try physicalValidatedNixApplet(
            policy.executables.nixEnv, expectedBasename: "nix-env", policy: policy)
        _ = try physicalValidatedNixApplet(
            policy.executables.nixStore, expectedBasename: "nix-store", policy: policy)
        if includeCurrentExecutable {
            let expected = try canonicalPhysical(policy.installedPaths.binary, allowSymlink: false)
            let actual = try canonicalArbitraryPhysical(context.currentExecutablePath)
            try require(actual == expected, "uninstalled_executable_invocation")
        }
    }

    private func loadPolicy() throws -> (BrokerPolicy, String) {
        let data = try readTrustedFile(fixedPolicyPath, exactMode: 0o444, maximumBytes: 64 * 1024)
        let hash = sha256Hex(data)
        return (try BrokerPolicy.decodeStrict(data), hash)
    }

    private func callerRepository(_ policy: BrokerPolicy) throws -> String {
        try callerPath(policy.control.repositorySuffix, reason: "control_repository_symlink")
    }

    private func callerReceiptPath(_ policy: BrokerPolicy, commit: String) throws -> String {
        let directory = try callerPath(policy.apply.receiptSuffix, reason: "receipt_directory_symlink")
        var info = stat()
        try require(lstat(directory, &info) == 0 && (info.st_mode & S_IFMT) == S_IFDIR,
                    "receipt_directory_type")
        try require(info.st_uid == context.realUID && (info.st_mode & 0o022) == 0,
                    "receipt_directory_mutable")
        return directory + "/" + commit + ".json"
    }

    private func callerPath(_ suffix: String, reason: String) throws -> String {
        try require(context.callerHome.hasPrefix("/") && !context.callerHome.contains("..") &&
                    !context.callerHome.contains("//"), "caller_home_not_canonical")
        let home = try canonicalArbitraryPhysical(context.callerHome)
        let expected = home + "/" + suffix
        let resolved = try canonicalArbitraryPhysical(expected)
        try require(resolved == expected, reason)
        return resolved
    }

    private func validateRepository(_ repository: String, commit: String,
                                    policy: BrokerPolicy) throws -> String {
        var before = stat()
        try require(lstat(repository, &before) == 0 && (before.st_mode & S_IFMT) == S_IFDIR &&
                    before.st_uid == context.realUID && (before.st_mode & 0o022) == 0,
                    "control_repository_mutable")
        let gitEnvironment = fixedGitEnvironment(base: policy.environment)
        let gitExecutable = try physicalResolvedExecutable(policy.executables.git, policy: policy)
        func git(_ arguments: [String], expectedOutput: String? = nil) throws -> String {
            let result = try runner.run(executable: gitExecutable,
                                        arguments: fixedGitArguments(repository: repository, command: arguments),
                                        environment: gitEnvironment)
            try require(result.status == 0, "control_git_\(arguments.first ?? "command")")
            let output = result.output.trimmingCharacters(in: .whitespacesAndNewlines)
            if let expectedOutput { try require(output == expectedOutput, "control_git_output") }
            return output
        }
        _ = try git(["rev-parse", "HEAD"], expectedOutput: commit)
        _ = try git(["branch", "--show-current"], expectedOutput: policy.control.expectedBranch)
        _ = try git(["status", "--porcelain", "--untracked-files=normal"], expectedOutput: "")
        _ = try git(["cat-file", "-e", commit + "^{commit}"])
        let tree = try git(["rev-parse", commit + "^{tree}"])
        var after = stat()
        try require(lstat(repository, &after) == 0 && before.st_dev == after.st_dev &&
                    before.st_ino == after.st_ino && before.st_uid == after.st_uid &&
                    before.st_mode == after.st_mode, "control_repository_race")
        return tree
    }

    private func validateTargetClosure(_ receipt: ApplyReceipt, expectedCommit: String,
                                       policy: BrokerPolicy) throws -> String {
        let resolved = try validateClosureFilesystem(receipt.targetSystemPath, policy: policy)
        try validateClosureRevision(receipt.targetSystemPath, expectedCommit: expectedCommit,
                                    policy: policy)
        let nixStore = try physicalValidatedNixApplet(
            policy.executables.nixStore, expectedBasename: "nix-store", policy: policy)
        let verify = try runner.run(executable: nixStore,
                                    arguments: ["--verify-path", receipt.targetSystemPath],
                                    environment: policy.environment)
        try require(verify.status == 0, "target_store_verification_failed")
        let hash = try runner.run(executable: nixStore,
                                  arguments: ["--query", "--hash", receipt.targetSystemPath],
                                  environment: policy.environment)
        try require(hash.status == 0 &&
                    hash.output.trimmingCharacters(in: .whitespacesAndNewlines) == receipt.targetSystemNarHash,
                    "target_store_hash_drift")
        return resolved
    }

    private func validateClosureRevision(_ closureLogical: String, expectedCommit: String,
                                         policy: BrokerPolicy) throws {
        let revisionLogical = closureLogical + "/darwin-version.json"
        let revisionPhysical = physical(revisionLogical)
        var linkBefore = stat()
        try require(lstat(revisionPhysical, &linkBefore) == 0, "darwin_version_missing")
        let immutableLogical: String
        if (linkBefore.st_mode & S_IFMT) == S_IFREG {
            let closureResolved = try canonicalPhysical(closureLogical, allowSymlink: false)
            let revisionResolved = try canonicalPhysical(revisionLogical, allowSymlink: false)
            try require(revisionResolved == closureResolved + "/darwin-version.json",
                        "darwin_version_escape")
            immutableLogical = revisionLogical
        } else if (linkBefore.st_mode & S_IFMT) == S_IFLNK {
            try require(linkBefore.st_uid == context.trustedUID &&
                        (linkBefore.st_mode & 0o022) == 0, "darwin_version_link_mutable")
            let destination = try readLink(revisionPhysical)
            try validatePattern(destination,
                                "^/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-darwin-version\\.json$",
                                "darwin_version_link_target")
            immutableLogical = destination
        } else {
            throw BrokerFailure.rejected("darwin_version_not_regular_or_link")
        }
        let data = try readImmutableStoreFile(immutableLogical, policy: policy, maximumBytes: 4096)
        if (linkBefore.st_mode & S_IFMT) == S_IFLNK {
            var linkAfter = stat()
            let destinationAfter = try readLink(revisionPhysical)
            try require(lstat(revisionPhysical, &linkAfter) == 0 &&
                        linkBefore.st_dev == linkAfter.st_dev &&
                        linkBefore.st_ino == linkAfter.st_ino &&
                        linkBefore.st_uid == linkAfter.st_uid &&
                        linkBefore.st_gid == linkAfter.st_gid &&
                        linkBefore.st_mode == linkAfter.st_mode &&
                        linkBefore.st_size == linkAfter.st_size &&
                        linkBefore.st_mtimespec.tv_sec == linkAfter.st_mtimespec.tv_sec &&
                        linkBefore.st_mtimespec.tv_nsec == linkAfter.st_mtimespec.tv_nsec &&
                        linkBefore.st_ctimespec.tv_sec == linkAfter.st_ctimespec.tv_sec &&
                        linkBefore.st_ctimespec.tv_nsec == linkAfter.st_ctimespec.tv_nsec &&
                        destinationAfter == immutableLogical,
                        "darwin_version_link_race")
        }
        _ = try DarwinVersionRecord.decodeStrict(data, expectedCommit: expectedCommit)
    }

    private func validateClosureFilesystem(_ logical: String, policy: BrokerPolicy) throws -> String {
        try validatePattern(logical,
                            "^/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-darwin-system-[A-Za-z0-9._+-]{1,96}$",
                            "target_system_path")
        let resolved = try canonicalPhysical(logical, allowSymlink: false)
        try require(resolved.hasPrefix(physical(policy.apply.storeRoot) + "/"), "store_path_escape")
        var info = stat()
        try require(stat(resolved, &info) == 0 && (info.st_mode & S_IFMT) == S_IFDIR &&
                    info.st_uid == context.trustedUID && (info.st_mode & 0o022) == 0,
                    "store_path_mutable")
        for suffix in ["/activate", "/systemConfig", "/sw/bin/darwin-rebuild"] {
            let childLogical = logical + suffix
            let child = try canonicalPhysical(childLogical, allowSymlink: true)
            if suffix == "/sw/bin/darwin-rebuild" {
                try require(child.hasPrefix(physical(policy.apply.storeRoot) + "/"),
                            "store_closure_child_escape")
            } else {
                try require(child == resolved + suffix, "store_closure_child_escape")
            }
            var childInfo = stat()
            try require(stat(child, &childInfo) == 0 && (childInfo.st_mode & S_IFMT) == S_IFREG &&
                        childInfo.st_uid == context.trustedUID && (childInfo.st_mode & 0o022) == 0,
                        "store_closure_incomplete")
        }
        return resolved
    }

    private func currentGeneration(_ policy: BrokerPolicy) throws -> GenerationState {
        let currentPhysical = physical(policy.apply.profilePath)
        var info = stat()
        try require(lstat(currentPhysical, &info) == 0 && (info.st_mode & S_IFMT) == S_IFLNK &&
                    info.st_uid == context.trustedUID, "current_generation_link")
        let destination = try readLink(currentPhysical)
        let basename = URL(fileURLWithPath: destination).lastPathComponent
        try validatePattern(basename, "^system-[1-9][0-9]{0,8}-link$", "current_generation_identifier")
        let identifier = String(basename.dropFirst("system-".count).dropLast("-link".count))
        try validateGenerationIdentifier(identifier)
        let generationLogical = policy.apply.profilePath + "-" + identifier + "-link"
        let targetPhysical = try canonicalPhysical(generationLogical, allowSymlink: true)
        let actualProfileTarget = try canonicalPhysical(policy.apply.profilePath, allowSymlink: true)
        try require(actualProfileTarget == targetPhysical, "profile_link_resolution_drift")
        try require(targetPhysical.hasPrefix(physical(policy.apply.storeRoot) + "/"),
                    "generation_target_escape")
        let targetLogical = logicalFromPhysical(targetPhysical)
        _ = try validateClosureFilesystem(targetLogical, policy: policy)
        return GenerationState(identifier: identifier, targetLogical: targetLogical,
                               targetPhysical: targetPhysical)
    }

    private func validateCurrentSystem(_ state: GenerationState) throws {
        let current = try canonicalPhysical("/run/current-system", allowSymlink: true)
        try require(current == state.targetPhysical, "current_system_mismatch")
    }

    private func generationIdentifiers(_ policy: BrokerPolicy) throws -> Set<String> {
        let parent = URL(fileURLWithPath: physical(policy.apply.profilePath)).deletingLastPathComponent()
        let names = try FileManager.default.contentsOfDirectory(atPath: parent.path)
        var result = Set<String>()
        for name in names {
            let prefix = "system-"
            let suffix = "-link"
            if name.hasPrefix(prefix) && name.hasSuffix(suffix) {
                let value = String(name.dropFirst(prefix.count).dropLast(suffix.count))
                if (try? validateGenerationIdentifier(value)) != nil { result.insert(value) }
            }
        }
        return result
    }

    private func generationTargets(_ policy: BrokerPolicy) throws -> [String: String] {
        var result: [String: String] = [:]
        for identifier in try generationIdentifiers(policy) {
            let logical = policy.apply.profilePath + "-" + identifier + "-link"
            result[identifier] = try canonicalPhysical(logical, allowSymlink: true)
        }
        return result
    }

    private func activationEnvironment(_ policy: BrokerPolicy) -> [String: String] {
        policy.environment.merging([
            "SUDO_UID": String(context.realUID),
            "SUDO_USER": context.callerIdentity,
        ]) { _, fixed in fixed }
    }

    private func validateExecutable(_ logical: String, policy: BrokerPolicy) throws {
        let resolved = try canonicalPhysical(logical, allowSymlink: true)
        if logical == policy.executables.git {
            try require(resolved == physical("/usr/bin/git"), "git_resolution_drift")
        } else {
            try require(resolved.hasPrefix(physical(policy.apply.storeRoot) + "/"),
                        "executable_symlink_escape")
        }
        var info = stat()
        try require(stat(resolved, &info) == 0 && (info.st_mode & S_IFMT) == S_IFREG,
                    "executable_missing")
        try require(info.st_uid == context.trustedUID && (info.st_mode & 0o022) == 0,
                    "executable_mutable")
        try require((info.st_mode & 0o111) != 0, "executable_not_executable")
    }

    private func physicalResolvedExecutable(_ logical: String, policy: BrokerPolicy) throws -> String {
        try validateExecutable(logical, policy: policy)
        return try canonicalPhysical(logical, allowSymlink: true)
    }

    private func physicalValidatedNixApplet(_ logical: String, expectedBasename: String,
                                            policy: BrokerPolicy) throws -> String {
        try require(["nix-env", "nix-store"].contains(expectedBasename),
                    "nix_applet_basename")
        try require(URL(fileURLWithPath: logical).lastPathComponent == expectedBasename,
                    "nix_applet_policy_name")

        let logicalPhysical = physical(logical)
        var logicalBefore = stat()
        try require(lstat(logicalPhysical, &logicalBefore) == 0 &&
                    (logicalBefore.st_mode & S_IFMT) == S_IFLNK &&
                    logicalBefore.st_uid == context.trustedUID,
                    "nix_applet_logical_link")

        let parentLogical = URL(fileURLWithPath: logical).deletingLastPathComponent().path
        let immutableParent = try canonicalArbitraryPhysical(physical(parentLogical))
        try require(immutableParent.hasPrefix(physical(policy.apply.storeRoot) + "/") &&
                    URL(fileURLWithPath: immutableParent).lastPathComponent == "bin",
                    "nix_applet_parent_escape")
        var parentInfo = stat()
        try require(lstat(immutableParent, &parentInfo) == 0 &&
                    (parentInfo.st_mode & S_IFMT) == S_IFDIR &&
                    parentInfo.st_uid == context.trustedUID &&
                    (parentInfo.st_mode & 0o022) == 0,
                    "nix_applet_parent_mutable")

        let applet = immutableParent + "/" + expectedBasename
        let appletLogical = logicalFromPhysical(applet)
        try validatePattern(appletLogical,
                            "^/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-[A-Za-z0-9._+-]{1,128}/bin/\(expectedBasename)$",
                            "nix_applet_store_path")
        var appletBefore = stat()
        try require(lstat(applet, &appletBefore) == 0 &&
                    (appletBefore.st_mode & S_IFMT) == S_IFLNK &&
                    appletBefore.st_uid == context.trustedUID,
                    "nix_applet_store_link")
        try require(logicalBefore.st_dev == appletBefore.st_dev &&
                    logicalBefore.st_ino == appletBefore.st_ino,
                    "nix_applet_logical_identity")
        let destination = try readLink(applet)

        let common = immutableParent + "/nix"
        let commonLogical = logicalFromPhysical(common)
        try require(destination == "nix" || destination == commonLogical,
                    "nix_applet_not_direct_common_binary")
        let oneHop = destination == "nix" ? common : physical(destination)
        try require(oneHop == common, "nix_applet_link_target")
        var commonInfo = stat()
        try require(lstat(common, &commonInfo) == 0 &&
                    (commonInfo.st_mode & S_IFMT) == S_IFREG &&
                    commonInfo.st_uid == context.trustedUID &&
                    (commonInfo.st_mode & 0o022) == 0 &&
                    (commonInfo.st_mode & 0o111) != 0,
                    "nix_common_binary_mutable")
        let resolvedLogical = try physicalResolvedExecutable(logical, policy: policy)
        let resolvedApplet = try canonicalArbitraryPhysical(applet)
        try require(resolvedLogical == common && resolvedApplet == common,
                    "nix_applet_common_identity")

        var appletAfter = stat()
        var logicalAfter = stat()
        let destinationAfter = try readLink(applet)
        try require(lstat(applet, &appletAfter) == 0 &&
                    lstat(logicalPhysical, &logicalAfter) == 0 &&
                    appletBefore.st_dev == appletAfter.st_dev &&
                    appletBefore.st_ino == appletAfter.st_ino &&
                    appletBefore.st_uid == appletAfter.st_uid &&
                    appletBefore.st_gid == appletAfter.st_gid &&
                    appletBefore.st_mode == appletAfter.st_mode &&
                    appletBefore.st_size == appletAfter.st_size &&
                    appletBefore.st_mtimespec.tv_sec == appletAfter.st_mtimespec.tv_sec &&
                    appletBefore.st_mtimespec.tv_nsec == appletAfter.st_mtimespec.tv_nsec &&
                    appletBefore.st_ctimespec.tv_sec == appletAfter.st_ctimespec.tv_sec &&
                    appletBefore.st_ctimespec.tv_nsec == appletAfter.st_ctimespec.tv_nsec &&
                    logicalBefore.st_dev == logicalAfter.st_dev &&
                    logicalBefore.st_ino == logicalAfter.st_ino &&
                    destinationAfter == destination,
                    "nix_applet_symlink_drift")
        return applet
    }

    private func readCallerFile(_ path: String, maximumBytes: Int) throws -> Data {
        let fd = Darwin.open(path, O_RDONLY | O_NOFOLLOW)
        try require(fd >= 0, "caller_receipt_missing")
        defer { Darwin.close(fd) }
        var before = stat()
        try require(fstat(fd, &before) == 0 && (before.st_mode & S_IFMT) == S_IFREG,
                    "caller_receipt_type")
        try require(before.st_uid == context.realUID && (before.st_mode & 0o022) == 0,
                    "caller_receipt_mutable")
        return try readBounded(fd: fd, before: before, maximumBytes: maximumBytes,
                               raceReason: "caller_receipt_race")
    }

    private func readTrustedFile(_ logical: String, exactMode: mode_t,
                                 maximumBytes: Int) throws -> Data {
        try validateLogicalPath(logical)
        let path = physical(logical)
        let resolved = try canonicalArbitraryPhysical(path)
        try validateCanonicalDomain(logical: logical, resolved: resolved)
        let fd = Darwin.open(path, O_RDONLY | O_NOFOLLOW)
        try require(fd >= 0, "trusted_file_missing")
        defer { Darwin.close(fd) }
        var before = stat()
        try require(fstat(fd, &before) == 0 && (before.st_mode & S_IFMT) == S_IFREG,
                    "trusted_file_type")
        try require(before.st_uid == context.trustedUID, "trusted_file_owner")
        try require((before.st_mode & 0o777) == exactMode, "trusted_file_mode")
        return try readBounded(fd: fd, before: before, maximumBytes: maximumBytes,
                               raceReason: "trusted_file_race")
    }

    private func readImmutableStoreFile(_ logical: String, policy: BrokerPolicy,
                                        maximumBytes: Int) throws -> Data {
        try validateLogicalPath(logical)
        try require(logical.hasPrefix(policy.apply.storeRoot + "/"), "immutable_store_file_path")
        let path = physical(logical)
        let resolved = try canonicalPhysical(logical, allowSymlink: false)
        try require(resolved.hasPrefix(physical(policy.apply.storeRoot) + "/"),
                    "immutable_store_file_escape")
        let fd = Darwin.open(path, O_RDONLY | O_NOFOLLOW)
        try require(fd >= 0, "immutable_store_file_missing")
        defer { Darwin.close(fd) }
        var before = stat()
        try require(fstat(fd, &before) == 0 && (before.st_mode & S_IFMT) == S_IFREG,
                    "immutable_store_file_type")
        try require(before.st_uid == context.trustedUID && (before.st_mode & 0o022) == 0,
                    "immutable_store_file_mutable")
        return try readBounded(fd: fd, before: before, maximumBytes: maximumBytes,
                               raceReason: "immutable_store_file_race")
    }

    private func readBounded(fd: Int32, before: stat, maximumBytes: Int,
                             raceReason: String) throws -> Data {
        try require(before.st_size >= 0 && before.st_size <= maximumBytes, "trusted_file_size")
        var data = Data(count: Int(before.st_size))
        var offset = 0
        while offset < data.count {
            let count = data.withUnsafeMutableBytes { raw -> Int in
                guard let base = raw.baseAddress else { return -1 }
                return Darwin.read(fd, base.advanced(by: offset), raw.count - offset)
            }
            try require(count > 0, "trusted_file_read")
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
                    before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec, raceReason)
        return data
    }

    private func validateDirectory(_ logical: String, exactMode: mode_t) throws {
        let path = try canonicalPhysical(logical, allowSymlink: false)
        var info = stat()
        try require(stat(path, &info) == 0 && (info.st_mode & S_IFMT) == S_IFDIR,
                    "trusted_directory_type")
        try require(info.st_uid == context.trustedUID, "trusted_directory_owner")
        try require((info.st_mode & 0o777) == exactMode, "trusted_directory_mode")
    }

    private func createStagingDirectory(_ root: String, identifier: String) throws -> String {
        try validateDirectory(root, exactMode: 0o700)
        let logical = root + "/" + identifier
        try require(mkdir(physical(logical), 0o700) == 0, "staging_create_failed")
        try validateDirectory(logical, exactMode: 0o700)
        let parent = Darwin.open(physical(root), O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
        try require(parent >= 0, "staging_parent_open")
        defer { Darwin.close(parent) }
        try require(fsync(parent) == 0, "staging_parent_sync")
        return logical
    }

    private func writeExclusive(_ data: Data, logicalPath: String, mode: mode_t) throws {
        let fd = Darwin.open(physical(logicalPath), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, mode)
        try require(fd >= 0, "staging_write_open")
        defer { Darwin.close(fd) }
        var offset = 0
        while offset < data.count {
            let count = data.withUnsafeBytes { raw -> Int in
                guard let base = raw.baseAddress else { return -1 }
                return Darwin.write(fd, base.advanced(by: offset), raw.count - offset)
            }
            try require(count > 0, "staging_write_failed")
            offset += count
        }
        try require(fsync(fd) == 0, "staging_write_failed")
        let parentPath = URL(fileURLWithPath: physical(logicalPath)).deletingLastPathComponent().path
        let parent = Darwin.open(parentPath, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
        try require(parent >= 0, "staging_receipt_parent_open")
        defer { Darwin.close(parent) }
        try require(fsync(parent) == 0, "staging_receipt_parent_sync")
    }

    private func validateActionID(_ value: String) throws {
        try validatePattern(value,
                            "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
                            "action_id")
    }

    private func pathExists(_ logical: String) -> Bool {
        var info = stat()
        return lstat(physical(logical), &info) == 0
    }

    private func physical(_ logical: String) -> String {
        context.rootPrefix == "/" ? logical : context.rootPrefix + logical
    }

    private func logicalFromPhysical(_ path: String) -> String {
        if context.rootPrefix == "/" { return path }
        return String(path.dropFirst(context.rootPrefix.count))
    }

    private func canonicalPhysical(_ logical: String, allowSymlink: Bool) throws -> String {
        try validateLogicalPath(logical)
        let candidate = physical(logical)
        if !allowSymlink {
            var info = stat()
            try require(lstat(candidate, &info) == 0 && (info.st_mode & S_IFMT) != S_IFLNK,
                        "symlink_not_allowed")
        }
        let resolved = try canonicalArbitraryPhysical(candidate)
        if !allowSymlink { try validateCanonicalDomain(logical: logical, resolved: resolved) }
        return resolved
    }

    private func validateCanonicalDomain(logical: String, resolved: String) throws {
        let first = logical.split(separator: "/").first.map(String.init) ?? ""
        let allowed: String
        if context.rootPrefix != "/" {
            allowed = context.rootPrefix + "/" + first
        } else if first == "etc" || first == "var" {
            allowed = "/private/" + first
        } else {
            allowed = "/" + first
        }
        try require(resolved == allowed || resolved.hasPrefix(allowed + "/"), "symlink_escape")
    }

    private func canonicalArbitraryPhysical(_ path: String) throws -> String {
        guard let resolvedPointer = realpath(path, nil) else {
            throw BrokerFailure.rejected("path_unavailable")
        }
        defer { free(resolvedPointer) }
        let resolved = String(cString: resolvedPointer)
        if context.rootPrefix != "/" {
            try require(resolved == context.rootPrefix || resolved.hasPrefix(context.rootPrefix + "/"),
                        "fixture_symlink_escape")
        }
        return resolved
    }

    private func readLink(_ path: String) throws -> String {
        var buffer = [CChar](repeating: 0, count: Int(PATH_MAX) + 1)
        let count = Darwin.readlink(path, &buffer, buffer.count - 1)
        try require(count > 0, "readlink_failed")
        return String(decoding: buffer.prefix(count).map { UInt8(bitPattern: $0) }, as: UTF8.self)
    }
}

public func encodeDoctorJSON(_ report: DoctorReport) throws -> String {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
    return String(decoding: try encoder.encode(report), as: UTF8.self) + "\n"
}
