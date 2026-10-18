import CryptoKit
import Darwin
import Foundation
#if canImport(AidAdminCore)
import AidAdminCore
#endif
#if canImport(AidAdminRuntime)
import AidAdminRuntime
#endif

public enum BootstrapFailure: Error, CustomStringConvertible, Equatable {
    case rejected(String)

    public var description: String {
        switch self { case .rejected(let reason): return reason }
    }
}

private func require(_ condition: @autoclosure () throws -> Bool, _ reason: String) throws {
    if try !condition() { throw BootstrapFailure.rejected(reason) }
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
        #if canImport(AidAdminRuntime)
        let result = try BoundedProcess.run(executable: executable, arguments: arguments,
                                            environment: environment,
                                            limits: .init(timeout: 30, maximumOutputBytes: 65536))
        try require(result.settled, "bootstrap_process_unsettled_UNKNOWN")
        try require(result.outcome == .exited, "bootstrap_process_" + result.outcome.rawValue)
        return result.status
        #else
        throw BootstrapFailure.rejected("bootstrap_bounded_runtime_unavailable")
        #endif
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

private struct FileSnapshot: Codable, Equatable {
    let existed: Bool
    let sha256: String
    let size: Int
    let uid: uid_t
    let gid: gid_t
    let mode: mode_t
    var backup: String?
    var device: UInt64 = 0
    var inode: UInt64 = 0
}

private struct TransactionState: Codable {
    var createdDirectories: [String] = []
    var files: [String: FileSnapshot] = [:]
    var mutationStarted = false
    var staging = ""
    var schema = 1
    var phase = "prepared"
    var post: [String: FileSnapshot] = [:]
    var stagedFiles: [String: FileSnapshot] = [:]
    var directoryIdentities: [String: [UInt64]] = [:]
    var directoryStaging: [String: String] = [:]
    var boundDirectories: [String: [UInt64]] = [:]
}

public struct BootstrapPreparationInventory: Codable {
    public struct Entry: Codable {
        public let identifier: String
        public let status: String
        public let knownFiles: Int
        public let knownBytes: Int
    }
    public let entries: [Entry]
    public let observedEntries: Int
    public let truncated: Bool
    public let activeInstall: Bool
    public let unknownEntries: Int
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
    private static let journalPath = bootstrapRoot + "/active.json"
    private static let retainedPreparations = bootstrapRoot + "/retained-preparations"
    private static let preparationLimit = 128
    private static let preparationNames: Set<String> = ["install-inputs.json", "aid-admin",
        "aid-admin-policy.json", "sudoers-template", "sudoers-rendered", "aid-admin-install.json",
        "new-aid-admin", "new-aid-admin-policy.json", "new-aid-admin-install.json",
        "new-agent-first-mac-aid-admin"]
    private static let token = "@@AGENT_OWNER@@"
    private static let cleanEnvironment = [
        "HOME": "/var/empty", "LANG": "C", "LC_ALL": "C",
        "PATH": "/usr/bin:/bin", "TMPDIR": "/var/empty",
    ]

    private let context: BootstrapContext
    private let runner: BootstrapCommandRunning
    private let hooks: BootstrapHooks
    private let actionID: () -> String
    private var writtenPreparationFiles: [String: FileSnapshot] = [:]

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
        let leases = try acquireLeases()
        defer { for fd in leases { Darwin.close(fd) } }
        _ = try reconcileLocked()
        try preflightState()
        if exists(Self.retainedPreparations) {
            try validateDirectory(Self.retainedPreparations, mode: 0o700)
            try require(try boundedNames(Self.retainedPreparations, limit: Self.preparationLimit).count < Self.preparationLimit - 1,
                        "preparation_capacity_retire_known_or_preserve_UNKNOWN")
        }

        var transaction = TransactionState()
        do {
            try ensureDirectory("/var/db/agent-first-mac", mode: 0o755, state: &transaction)
            try ensureDirectory(Self.bootstrapRoot, mode: 0o700, state: &transaction)
            let identifier = actionID()
            try require(identifier.range(of: "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
                                         options: .regularExpression) != nil, "transaction_identifier")
            transaction.staging = Self.bootstrapRoot + "/transaction-" + identifier
            try require(!exists(transaction.staging), "transaction_already_exists_UNKNOWN")
            // Preparation has no target writes. Publish intent before allocation
            // so even interrupted copies can be preserved without blocking a
            // later authenticated attempt or adopting partial executable bytes.
            transaction.phase = "preparing"
            try saveJournal(transaction)
            try hooks.afterMutation(step: "preparation-intent")
            try ensureDirectory(transaction.staging, mode: 0o700, state: &transaction)
            try hooks.afterMutation(step: "preparation-directory-created")
            try saveJournal(transaction)
            try hooks.afterMutation(step: "preparation-directory-recorded")

            let stagedInputs = transaction.staging + "/install-inputs.json"
            try copyReviewedSource(request.inputsPath, to: stagedInputs,
                                   pin: ArtifactPin(sha256: request.inputsSHA256,
                                                    size: request.inputsSize))
            try recordPreparationFile(stagedInputs, mode: 0o400, state: &transaction)
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
            try recordPreparationFile(stagedBroker, mode: 0o400, state: &transaction)
            try copyReviewedSource(request.policyPath, to: stagedPolicy, pin: inputs.policy)
            try recordPreparationFile(stagedPolicy, mode: 0o400, state: &transaction)
            try copyReviewedSource(request.sudoersTemplatePath, to: stagedTemplate,
                                   pin: inputs.sudoersTemplate)
            try recordPreparationFile(stagedTemplate, mode: 0o400, state: &transaction)
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
            try recordPreparationFile(stagedRendered, mode: 0o440, state: &transaction)
            let visudo = context.fixtureMode ? "/usr/sbin/visudo" : "/usr/sbin/visudo"
            let visudoStatus = try runner.run(executable: visudo,
                                              arguments: ["-cf", physical(stagedRendered)],
                                              environment: Self.cleanEnvironment)
            try require(visudoStatus == 0, "visudo_failed")

            let attestation = try makeAttestation(owner: owner, inputs: inputs)
            let stagedAttestation = transaction.staging + "/aid-admin-install.json"
            try writeExclusive(attestation, logical: stagedAttestation, mode: 0o400)
            try recordPreparationFile(stagedAttestation, mode: 0o400, state: &transaction)

            // Freeze every preimage and the exact inode to be published before
            // the first externally visible artifact mutation.
            let attestationPin = ArtifactPin(sha256: bootstrapSHA256(attestation), size: attestation.count)
            for (source, target, mode, pin) in [
                (stagedBroker, Self.binaryPath, mode_t(0o555), inputs.broker),
                (stagedPolicy, Self.policyPath, mode_t(0o444), inputs.policy),
                (stagedAttestation, Self.attestationPath, mode_t(0o400), attestationPin),
                (stagedRendered, Self.sudoersPath, mode_t(0o440), inputs.renderedSudoers),
            ] {
                var prior = try trustedFileSnapshotIfPresent(target, mode: mode)
                prior.backup = transaction.staging + "/prior-" + URL(fileURLWithPath: target).lastPathComponent
                transaction.files[target] = prior
                let publication = transaction.staging + "/new-" + URL(fileURLWithPath: target).lastPathComponent
                let bytes = try readTrustedFile(source, mode: source == stagedRendered ? 0o440 : 0o400,
                                                maximum: 64 * 1024 * 1024)
                try writeExclusive(bytes, logical: publication, mode: mode)
                try recordPreparationFile(publication, mode: mode, state: &transaction)
                try verifyPin(publication, pin: pin, mode: mode)
                transaction.post[target] = try trustedFileSnapshot(publication, mode: mode)
            }
            transaction.mutationStarted = true
            transaction.phase = "prepared"
            for target in transaction.files.keys {
                var parent = URL(fileURLWithPath: target).deletingLastPathComponent().path
                while parent != "/" {
                    if exists(parent) {
                        var facts = stat()
                        try require(stat(physical(parent), &facts) == 0, "parent_binding")
                        transaction.boundDirectories[parent] = [UInt64(facts.st_dev), UInt64(facts.st_ino)]
                    }
                    parent = URL(fileURLWithPath: parent).deletingLastPathComponent().path
                }
            }
            for name in try FileManager.default.contentsOfDirectory(atPath: physical(transaction.staging)) {
                let path = transaction.staging + "/" + name
                var facts = stat()
                try require(lstat(physical(path), &facts) == 0, "staging_snapshot")
                transaction.stagedFiles[name] = try trustedFileSnapshot(path, mode: facts.st_mode & 0o777)
            }
            try saveJournal(transaction)
            try hooks.afterMutation(step: "journal-prepared")

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
            try replaceTarget(stagedAttestation, target: Self.attestationPath, mode: 0o400,
                              pin: attestationPin, state: &transaction)
            try hooks.afterMutation(step: "attestation")
            try replaceTarget(stagedRendered, target: Self.sudoersPath, mode: 0o440,
                              pin: inputs.renderedSudoers, state: &transaction)
            try hooks.afterMutation(step: "sudoers")
            let verificationLease = try acquireEmergencyLease()
            defer { Darwin.close(verificationLease) }
            try verifyInstalled(inputs: inputs, attestation: attestationPin)
            try hooks.afterMutation(step: "final-verification")
            transaction.phase = "committed"
            try saveJournal(transaction)
            try hooks.afterMutation(step: "journal-committed")
            try cleanupStaging(state: &transaction, success: true)
            return "INSTALL_TRANSACTION_COMMITTED"
        } catch {
            let original = String(describing: error)
            if original.contains("unsettled_UNKNOWN") { throw error }
            if transaction.mutationStarted && (exists(Self.emergencyDisablePath) || exists(Self.disabledSudoersPath)) {
                throw BootstrapFailure.rejected("bootstrap_emergency_revocation_UNKNOWN")
            }
            if transaction.mutationStarted {
                if transaction.phase == "committed" {
                    throw BootstrapFailure.rejected(original + "_committed_cleanup_pending")
                }
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
            // Preparation bytes may be partial or foreign. Preserve them under
            // the recorded private namespace; never recursively delete them.
            if exists(Self.journalPath) { _ = try? reconcileLocked() }
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

    /// Fresh-process reconciliation precedes admission of a new request. This
    /// entrypoint performs no new installation and preserves unknown state.
    public func reconcileInterruptedInstall() throws -> String {
        try validateContext()
        let leases = try acquireLeases()
        defer { for fd in leases { Darwin.close(fd) } }
        return try reconcileLocked()
    }

    private func acquireLeases(create: Bool = true) throws -> [Int32] {
        var setup = TransactionState()
        if create {
            try ensureDirectory("/var/db/agent-first-mac", mode: 0o755, state: &setup)
            try ensureDirectory(Self.bootstrapRoot, mode: 0o700, state: &setup)
        } else {
            try validateDirectory(Self.bootstrapRoot, mode: 0o700)
        }
        var result: [Int32] = []
        do {
            let paths = ["/var/db/agent-first-mac/.operation.lock"]
            for path in paths {
                try validateAncestors(path)
                let fd = Darwin.open(physical(path), (create ? O_RDWR | O_CREAT : O_RDONLY) | O_NOFOLLOW | O_CLOEXEC, 0o600)
                try require(fd >= 0, "bootstrap_lock_open_UNKNOWN")
                result.append(fd)
                var facts = stat()
                try require(fstat(fd, &facts) == 0 && (facts.st_mode & S_IFMT) == S_IFREG &&
                            facts.st_uid == context.trustedUID && facts.st_gid == context.trustedGID &&
                            facts.st_nlink == 1 && (facts.st_mode & 0o7777) == 0o600,
                            "bootstrap_lock_contract_UNKNOWN")
                try require(flock(fd, LOCK_EX | LOCK_NB) == 0, "bootstrap_operation_BUSY")
            }
            let applyJournal = Self.brokerStagingPath + "/operation.json"
            if exists(applyJournal) {
                let bytes = try readTrustedFile(applyJournal, mode: 0o600, maximum: 16384)
                #if canImport(AidAdminCore)
                try validateSettledApplyJournal(bytes)
                #else
                throw BootstrapFailure.rejected("broker_operation_pending_UNKNOWN")
                #endif
            }
            return result
        } catch {
            for fd in result { Darwin.close(fd) }
            throw error
        }
    }

    private func recordPreparationFile(_ path: String, mode: mode_t, state: inout TransactionState) throws {
        guard let created = writtenPreparationFiles[path], created.mode == mode else {
            throw BootstrapFailure.rejected("preparation_write_identity_UNKNOWN")
        }
        try require(try matches(path, created), "preparation_write_identity_UNKNOWN")
        state.stagedFiles[URL(fileURLWithPath: path).lastPathComponent] = created
        try syncParent(path)
        // Pre/post target snapshots are not authority until the final prepared
        // journal. Keep this durable record strictly pre-mutation.
        var preparation = state
        preparation.files = [:]; preparation.post = [:]
        try saveJournal(preparation)
        try hooks.afterMutation(step: "preparation-file-recorded-" + URL(fileURLWithPath: path).lastPathComponent)
    }

    private func boundedNames(_ logical: String, limit: Int) throws -> [String] {
        try validateDirectory(logical, mode: 0o700)
        guard let directory = opendir(physical(logical)) else {
            throw BootstrapFailure.rejected("preparation_inventory_UNKNOWN")
        }
        defer { closedir(directory) }
        var names: [String] = []
        errno = 0
        while let entry = readdir(directory) {
            let name = withUnsafePointer(to: &entry.pointee.d_name) {
                $0.withMemoryRebound(to: CChar.self, capacity: Int(entry.pointee.d_namlen) + 1) { String(cString: $0) }
            }
            if name == "." || name == ".." { continue }
            names.append(name)
            if names.count > limit { return names }
            errno = 0
        }
        try require(errno == 0, "preparation_inventory_UNKNOWN")
        return names.sorted()
    }

    private func preparationState(_ journal: String) throws -> TransactionState {
        let bytes = try readTrustedFile(journal, mode: 0o400, maximum: 128 * 1024)
        let state = try JSONDecoder().decode(TransactionState.self, from: bytes)
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        try require(try encoder.encode(state) == bytes, "preparation_journal_noncanonical_UNKNOWN")
        try validatePreparationIntent(state)
        return state
    }

    private func validateRetirement(_ state: TransactionState, retained: String, retiring: Bool) throws {
        if !exists(retained) {
            try require(retiring || state.directoryIdentities.isEmpty, "preparation_directory_missing_UNKNOWN")
            return
        }
        try validateDirectory(retained, mode: 0o700)
        let names = try boundedNames(retained, limit: Self.preparationNames.count)
        if state.directoryIdentities[state.staging] != nil {
            try validateDirectoryIdentity(retained, state: state, expectedPath: state.staging)
        } else {
            throw BootstrapFailure.rejected("preparation_directory_identity_UNKNOWN")
        }
        try require(Set(names).isSubset(of: Set(state.stagedFiles.keys)), "preparation_unknown_contents_preserved")
        for name in names {
            try require(try matches(retained + "/" + name, state.stagedFiles[name]!), "preparation_file_identity_UNKNOWN")
        }
        if !retiring {
            try require(Set(names) == Set(state.stagedFiles.keys), "preparation_file_missing_UNKNOWN")
        }
    }

    /// Authenticated, read-only bounded custody report; never reconciles an
    /// install or interprets unpublished journal candidates as authority.
    public func inventoryPreparations() throws -> BootstrapPreparationInventory {
        try validateContext()
        guard exists(Self.bootstrapRoot) else {
            return .init(entries: [], observedEntries: 0, truncated: false, activeInstall: false, unknownEntries: 0)
        }
        let leases = try acquireLeases(create: false)
        defer { for fd in leases { Darwin.close(fd) } }
        let active = exists(Self.journalPath) || exists(Self.journalPath + ".next")
        guard exists(Self.retainedPreparations) else {
            return .init(entries: [], observedEntries: 0, truncated: false, activeInstall: active, unknownEntries: 0)
        }
        let names = try boundedNames(Self.retainedPreparations, limit: Self.preparationLimit)
        var entries: [BootstrapPreparationInventory.Entry] = []
        var accounted: Set<String> = []
        for name in names.prefix(Self.preparationLimit) {
            let retiring = name.hasSuffix(".retiring.json")
            let suffix = retiring ? ".retiring.json" : ".json"
            guard name.hasSuffix(suffix) else { continue }
            let stem = String(name.dropLast(suffix.count))
            guard stem.range(of: "^transaction-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", options: .regularExpression) != nil else { continue }
            let journal = Self.retainedPreparations + "/" + name
            let retained = Self.retainedPreparations + "/" + stem
            do {
                let state = try preparationState(journal)
                try require(state.staging == Self.bootstrapRoot + "/" + stem &&
                    !exists(retained + (retiring ? ".json" : ".retiring.json")) && !exists(state.staging),
                    "preparation_retention_collision_UNKNOWN")
                try validateRetirement(state, retained: retained, retiring: retiring)
                let remaining = exists(retained) ? try boundedNames(retained, limit: Self.preparationNames.count) : []
                entries.append(.init(identifier: String(stem.dropFirst("transaction-".count)),
                    status: active ? "ACTIVE_INSTALL_PRESERVED" : (retiring ? "RETIREMENT_PENDING" : "RETIRABLE"),
                    knownFiles: remaining.count, knownBytes: remaining.reduce(0) { $0 + state.stagedFiles[$1]!.size }))
                accounted.insert(name); if exists(retained) { accounted.insert(stem) }
            } catch {
                entries.append(.init(identifier: String(stem.dropFirst("transaction-".count)),
                                     status: "UNKNOWN_PRESERVED", knownFiles: 0, knownBytes: 0))
            }
        }
        return .init(entries: entries, observedEntries: names.count, truncated: names.count > Self.preparationLimit,
                     activeInstall: active, unknownEntries: names.filter { !accounted.contains($0) }.count)
    }

    /// Deletes only one journal-proven pre-mutation namespace. The journal is
    /// renamed first and removed last so every interrupted step is restartable.
    /// No broker target, rollback preimage, opaque candidate or sibling is used.
    public func retirePreparation(identifier: String) throws -> String {
        try validateContext()
        try require(identifier.range(of: "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", options: .regularExpression) != nil,
                    "preparation_identifier")
        let leases = try acquireLeases(create: false)
        defer { for fd in leases { Darwin.close(fd) } }
        try require(!exists(Self.journalPath) && !exists(Self.journalPath + ".next"), "preparation_active_install_preserved")
        try validateDirectory(Self.retainedPreparations, mode: 0o700)
        let retained = Self.retainedPreparations + "/transaction-" + identifier
        let original = retained + ".json", retiring = retained + ".retiring.json"
        try require(!(exists(original) && exists(retiring)), "preparation_retention_collision_UNKNOWN")
        let inProgress = exists(retiring)
        let journal = inProgress ? retiring : original
        let journalSnapshot = try trustedFileSnapshot(journal, mode: 0o400)
        let state = try preparationState(journal)
        try require(try matches(journal, journalSnapshot), "preparation_journal_identity_UNKNOWN")
        try require(state.staging == Self.bootstrapRoot + "/transaction-" + identifier && !exists(state.staging),
                    "preparation_retention_collision_UNKNOWN")
        try validateRetirement(state, retained: retained, retiring: inProgress)
        if !inProgress {
            try require(renameatx_np(AT_FDCWD, physical(original), AT_FDCWD, physical(retiring), UInt32(RENAME_EXCL)) == 0,
                        "preparation_retirement_intent_UNKNOWN")
            try syncParent(retiring)
            try hooks.afterMutation(step: "preparation-retirement-intent")
        }
        if exists(retained) {
            for name in state.stagedFiles.keys.sorted() where exists(retained + "/" + name) {
                try require(try matches(retiring, journalSnapshot), "preparation_journal_identity_UNKNOWN")
                try validateRetirement(state, retained: retained, retiring: true)
                try require(unlink(physical(retained + "/" + name)) == 0, "preparation_retirement_file_UNKNOWN")
                try syncParent(retained + "/" + name)
                try hooks.afterMutation(step: "preparation-retirement-file-" + name)
            }
            try require(try matches(retiring, journalSnapshot), "preparation_journal_identity_UNKNOWN")
            try validateRetirement(state, retained: retained, retiring: true)
            try require(rmdir(physical(retained)) == 0, "preparation_retirement_directory_UNKNOWN")
            try syncParent(retained)
            try hooks.afterMutation(step: "preparation-retirement-directory")
        }
        try require(try matches(retiring, journalSnapshot), "preparation_journal_identity_UNKNOWN")
        try require(!exists(retained), "preparation_retirement_directory_UNKNOWN")
        try require(unlink(physical(retiring)) == 0, "preparation_retirement_journal_UNKNOWN")
        try syncParent(retiring)
        try hooks.afterMutation(step: "preparation-retirement-complete")
        return "PREPARATION_RETIRED"
    }

    private func saveJournal(_ state: TransactionState) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let bytes = try encoder.encode(state)
        try require(bytes.count <= 128 * 1024, "journal_bound")
        // The prior record remains authoritative until this fsynced candidate
        // is renamed. A leftover candidate is never interpreted as authority.
        let temporary = Self.journalPath + ".next"
        if exists(temporary) {
            _ = try readTrustedFile(temporary, mode: 0o400, maximum: 128 * 1024)
            try require(unlink(physical(temporary)) == 0, "journal_candidate_retire")
        }
        try writeExclusive(bytes, logical: temporary, mode: 0o400)
        try require(rename(physical(temporary), physical(Self.journalPath)) == 0, "journal_publish")
        try syncParent(Self.journalPath)
    }

    private func acquireEmergencyLease() throws -> Int32 {
        let path = "/var/db/agent-first-mac/.emergency.lock"
        try validateAncestors(path)
        let fd = Darwin.open(physical(path), O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0o600)
        try require(fd >= 0, "emergency_lock_open_UNKNOWN")
        do {
            var facts = stat()
            try require(fstat(fd, &facts) == 0 && (facts.st_mode & S_IFMT) == S_IFREG &&
                        facts.st_uid == context.trustedUID && facts.st_gid == context.trustedGID &&
                        facts.st_nlink == 1 && (facts.st_mode & 0o7777) == 0o600,
                        "emergency_lock_contract_UNKNOWN")
            try require(flock(fd, LOCK_EX | LOCK_NB) == 0, "emergency_operation_BUSY")
            return fd
        } catch { Darwin.close(fd); throw error }
    }

    private func reconcileLocked() throws -> String {
        try require(!exists(Self.emergencyDisablePath) && !exists(Self.disabledSudoersPath),
                    "bootstrap_emergency_revocation_UNKNOWN")
        guard exists(Self.journalPath) else {
            let entries = try FileManager.default.contentsOfDirectory(atPath: physical(Self.bootstrapRoot))
            try require(entries.allSatisfy { ["retained-preparations", "active.json.next"].contains($0) },
                        "bootstrap_orphan_UNKNOWN")
            if entries.contains("active.json.next") {
                // No directory allocation or live mutation can precede the
                // first published journal. Preserve even partial candidate bytes
                // as data, never interpret them as a recovery command.
                _ = try readTrustedFile(Self.journalPath + ".next", mode: 0o400, maximum: 128 * 1024)
                var retention = TransactionState()
                try ensureDirectory(Self.retainedPreparations, mode: 0o700, state: &retention)
                let destination = Self.retainedPreparations + "/unpublished-" + UUID().uuidString.lowercased() + ".json"
                try require(renameatx_np(AT_FDCWD, physical(Self.journalPath + ".next"), AT_FDCWD,
                                        physical(destination), UInt32(RENAME_EXCL)) == 0,
                            "preparation_unpublished_retention_UNKNOWN")
                try syncParent(Self.journalPath)
                try syncParent(destination)
            }
            if entries.contains("retained-preparations") {
                try validateDirectory(Self.retainedPreparations, mode: 0o700)
            }
            return "NO_INTERRUPTED_INSTALL"
        }
        do {
            let bytes = try readTrustedFile(Self.journalPath, mode: 0o400, maximum: 128 * 1024)
            var state = try JSONDecoder().decode(TransactionState.self, from: bytes)
            let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
            try require(try encoder.encode(state) == bytes, "journal_noncanonical_UNKNOWN")
            if state.phase == "preparing" {
                return try retainInterruptedPreparation(state)
            }
            let targets = Set([Self.binaryPath, Self.policyPath, Self.attestationPath, Self.sudoersPath])
            try require(state.schema == 1 && state.mutationStarted &&
                        ["prepared", "committed", "rolled-back"].contains(state.phase) &&
                        Set(state.files.keys) == targets && Set(state.post.keys) == targets &&
                        state.staging.range(of: "^" + Self.bootstrapRoot + "/transaction-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", options: .regularExpression) != nil,
                        "journal_schema_UNKNOWN")
            let directories = Set(["/etc/sudoers.d", "/etc/agent-first-mac", "/usr/local",
                "/usr/local/libexec", "/var/log/agent-first-mac", Self.auditPath,
                Self.brokerStagingPath, Self.bootstrapRoot, "/var/db/agent-first-mac", state.staging])
            try require(Set(state.createdDirectories).isSubset(of: directories) &&
                        Set(state.createdDirectories).count == state.createdDirectories.count,
                        "journal_directory_scope_UNKNOWN")
            for target in targets {
                try require(state.files[target]?.backup == state.staging + "/prior-" + URL(fileURLWithPath: target).lastPathComponent,
                            "journal_backup_scope_UNKNOWN")
            }
            try require(state.directoryIdentities.keys.allSatisfy { directories.contains($0) },
                        "journal_directory_identity_scope_UNKNOWN")
            let boundParents: Set<String> = ["/etc", "/etc/agent-first-mac", "/etc/sudoers.d",
                "/usr", "/usr/local", "/usr/local/libexec"]
            try require(Set(state.boundDirectories.keys).isSubset(of: boundParents),
                        "journal_bound_directory_scope_UNKNOWN")
            for (target, candidate) in state.directoryStaging {
                try require(directories.contains(target) && candidate == state.staging + "/directory-" + target.replacingOccurrences(of: "/", with: "_"),
                            "journal_directory_candidate_UNKNOWN")
            }
            if state.phase == "prepared" {
                try validateDirectory(state.staging, mode: 0o700)
                try rollback(state: &state)
                return "INTERRUPTED_INSTALL_ROLLED_BACK"
            }
            if state.phase == "committed" {
                try validateRecoveryState(state, committed: true)
            } else {
                for (path, snapshot) in state.files {
                    try require(try matches(path, snapshot), "rollback_terminal_UNKNOWN")
                }
            }
            try cleanupStaging(state: &state, success: state.phase == "committed")
            return state.phase == "committed" ? "INSTALL_TRANSACTION_COMMITTED" : "INTERRUPTED_INSTALL_ROLLED_BACK"
        } catch {
            throw BootstrapFailure.rejected("bootstrap_recovery_UNKNOWN_" + String(describing: error))
        }
    }

    private func validatePreparationIntent(_ state: TransactionState) throws {
        try require(state.schema == 1 && state.phase == "preparing" && !state.mutationStarted && state.files.isEmpty &&
                    state.post.isEmpty && Set(state.stagedFiles.keys).isSubset(of: Self.preparationNames) &&
                    state.directoryStaging.isEmpty && state.boundDirectories.isEmpty &&
                    state.staging.range(of: "^" + Self.bootstrapRoot + "/transaction-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", options: .regularExpression) != nil &&
                    Set(state.createdDirectories).isSubset(of: [state.staging]) &&
                    Set(state.directoryIdentities.keys).isSubset(of: [state.staging]),
                    "preparation_intent_UNKNOWN")
        for snapshot in state.stagedFiles.values {
            try require(snapshot.existed && snapshot.backup == nil && snapshot.device > 0 && snapshot.inode > 0 &&
                        snapshot.uid == context.trustedUID && snapshot.gid == context.trustedGID &&
                        [mode_t(0o400), 0o440, 0o444, 0o555].contains(snapshot.mode) &&
                        snapshot.size >= 0 && snapshot.size <= 64 * 1024 * 1024 &&
                        snapshot.sha256.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil &&
                        state.directoryIdentities[state.staging]?.count == 2,
                        "preparation_file_proof_UNKNOWN")
        }
    }

    /// No preparation content is executed, adopted or deleted. The durable
    /// intent owns only this UUID namespace; exact directory identity is held
    /// once available. A crash between mkdir and identity publication can retain
    /// an empty private directory but cannot infer ownership of populated state.
    private func retainInterruptedPreparation(_ original: TransactionState) throws -> String {
        var state = original
        try validatePreparationIntent(state)
        var retention = TransactionState()
        try ensureDirectory(Self.retainedPreparations, mode: 0o700, state: &retention)
        let name = URL(fileURLWithPath: state.staging).lastPathComponent
        let retained = Self.retainedPreparations + "/" + name
        let retainedJournal = retained + ".json"
        try require(!exists(retainedJournal), "preparation_retention_collision_UNKNOWN")
        if exists(state.staging) {
            try require(!exists(retained), "preparation_retention_collision_UNKNOWN")
            try validateDirectory(state.staging, mode: 0o700)
            if state.directoryIdentities[state.staging] != nil {
                try validateDirectoryIdentity(state.staging, state: state)
            } else {
                try require(try FileManager.default.contentsOfDirectory(atPath: physical(state.staging)).isEmpty,
                            "preparation_unrecorded_contents_UNKNOWN")
                var facts = stat()
                try require(lstat(physical(state.staging), &facts) == 0, "preparation_directory_identity_UNKNOWN")
                state.directoryIdentities[state.staging] = [UInt64(facts.st_dev), UInt64(facts.st_ino)]
                try saveJournal(state)
            }
            try require(renameatx_np(AT_FDCWD, physical(state.staging), AT_FDCWD,
                                    physical(retained), UInt32(RENAME_EXCL)) == 0,
                        "preparation_retention_move_UNKNOWN")
            try syncParent(state.staging)
            try syncParent(retained)
            try hooks.afterMutation(step: "preparation-retained")
        } else if exists(retained) {
            try validateDirectory(retained, mode: 0o700)
            if state.directoryIdentities[state.staging] != nil {
                try validateDirectoryIdentity(retained, state: state, expectedPath: state.staging)
            } else {
                try require(try FileManager.default.contentsOfDirectory(atPath: physical(retained)).isEmpty,
                            "preparation_unrecorded_contents_UNKNOWN")
                var facts = stat()
                try require(lstat(physical(retained), &facts) == 0, "preparation_directory_identity_UNKNOWN")
                state.directoryIdentities[state.staging] = [UInt64(facts.st_dev), UInt64(facts.st_ino)]
                try saveJournal(state)
            }
        } else {
            try require(state.directoryIdentities.isEmpty, "preparation_directory_missing_UNKNOWN")
        }
        try require(renameatx_np(AT_FDCWD, physical(Self.journalPath), AT_FDCWD,
                                physical(retainedJournal), UInt32(RENAME_EXCL)) == 0,
                    "preparation_intent_retention_UNKNOWN")
        try syncParent(Self.journalPath)
        try syncParent(retainedJournal)
        return "INTERRUPTED_PREPARATION_RETAINED"
    }

    private func matches(_ path: String, _ snapshot: FileSnapshot) throws -> Bool {
        if !snapshot.existed { return !exists(path) }
        if !exists(path) { return false }
        let current = try trustedFileSnapshot(path, mode: snapshot.mode)
        return current.sha256 == snapshot.sha256 && current.size == snapshot.size &&
            current.uid == snapshot.uid && current.gid == snapshot.gid &&
            current.device == snapshot.device && current.inode == snapshot.inode
    }

    private func validateRecoveryState(_ state: TransactionState, committed: Bool) throws {
        try validateBoundDirectories(state)
        for logical in state.createdDirectories where logical != state.staging &&
            logical != Self.bootstrapRoot && logical != "/var/db/agent-first-mac" {
            if exists(logical) { try validateDirectoryIdentity(logical, state: state) }
            else if let candidate = state.directoryStaging[logical], exists(candidate) {
                try validateDirectoryIdentity(candidate, state: state, expectedPath: logical)
            } else if state.phase == "prepared" {
                throw BootstrapFailure.rejected("directory_missing_UNKNOWN")
            }
        }
        for (path, prior) in state.files {
            guard let post = state.post[path] else { throw BootstrapFailure.rejected("journal_post_UNKNOWN") }
            if let backup = prior.backup, exists(backup) {
                try require(prior.existed && (try matches(backup, prior)), "foreign_backup_UNKNOWN")
            }
            if committed {
                try require(try matches(path, post), "committed_target_UNKNOWN")
            } else if try matches(path, prior) {
                // No target mutation, or an already completed rollback step.
                continue
            } else {
                try require(!exists(path) || (try matches(path, post)), "foreign_target_UNKNOWN")
                if prior.existed {
                    try require(try matches(prior.backup!, prior), "backup_identity_UNKNOWN")
                }
            }
        }
    }

    private func validateBoundDirectories(_ state: TransactionState) throws {
        for (logical, expected) in state.boundDirectories {
            var facts = stat()
            try validateAncestors(logical + "/entry")
            try require(stat(physical(logical), &facts) == 0 &&
                        expected == [UInt64(facts.st_dev), UInt64(facts.st_ino)],
                        "bound_directory_drift_UNKNOWN")
        }
        for logical in state.directoryIdentities.keys where exists(logical) {
            try validateDirectoryIdentity(logical, state: state)
        }
    }

    private func validateAncestors(_ logical: String) throws {
        let parts = logical.split(separator: "/").dropLast()
        var path = ""
        for part in parts {
            path += "/" + part
            var facts = stat()
            if !context.fixtureMode && ["/etc", "/var"].contains(path) {
                let expected = "/private" + path
                try require(try FileManager.default.destinationOfSymbolicLink(atPath: path) == expected.dropFirst(),
                            "system_alias_contract")
                try require(stat(expected, &facts) == 0, "ancestor_stat")
            } else {
                try require(lstat(physical(path), &facts) == 0, "ancestor_stat")
            }
            try require((facts.st_mode & S_IFMT) == S_IFDIR && facts.st_uid == context.trustedUID &&
                        (facts.st_mode & 0o022) == 0, "ancestor_contract_UNKNOWN")
        }
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
        try validateAncestors(logical)
        let fd = Darwin.open(physical(logical), O_RDONLY | O_NOFOLLOW)
        try require(fd >= 0, "trusted_open")
        defer { Darwin.close(fd) }
        var before = stat()
        try require(fstat(fd, &before) == 0 && (before.st_mode & S_IFMT) == S_IFREG &&
                    before.st_uid == context.trustedUID && before.st_gid == context.trustedGID &&
                    before.st_nlink == 1 && (before.st_mode & 0o7777) == mode, "trusted_file_contract")
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
        try validateBoundDirectories(state)
        let emergencyLease = target == Self.sudoersPath ? try acquireEmergencyLease() : -1
        defer { if emergencyLease >= 0 { Darwin.close(emergencyLease) } }
        if target == Self.sudoersPath {
            try require(!exists(Self.emergencyDisablePath) && !exists(Self.disabledSudoersPath),
                        "bootstrap_emergency_revocation_UNKNOWN")
        }
        guard let snapshot = state.files[target], let post = state.post[target] else {
            throw BootstrapFailure.rejected("journal_binding_UNKNOWN")
        }
        try require(try matches(target, snapshot), "target_preimage_UNKNOWN")
        let publication = state.staging + "/new-" + URL(fileURLWithPath: target).lastPathComponent
        try require(try matches(publication, post), "publication_identity_UNKNOWN")
        try hooks.afterMutation(step: "before-backup-" + URL(fileURLWithPath: target).lastPathComponent)
        if snapshot.existed {
            let backup = snapshot.backup!
            try require(!exists(backup), "backup_exists_UNKNOWN")
            try require(renameatx_np(AT_FDCWD, physical(target), AT_FDCWD, physical(backup), UInt32(RENAME_EXCL)) == 0, "prior_backup_failed")
            try syncParent(target)
            try syncParent(backup)
        }
        try hooks.afterMutation(step: "after-backup-" + URL(fileURLWithPath: target).lastPathComponent)
        try validateBoundDirectories(state)
        if target == Self.sudoersPath {
            try require(!exists(Self.emergencyDisablePath) && !exists(Self.disabledSudoersPath),
                        "bootstrap_emergency_revocation_UNKNOWN")
        }
        try require(!exists(target), "target_publication_conflict_UNKNOWN")
        try require(renameatx_np(AT_FDCWD, physical(publication), AT_FDCWD, physical(target), UInt32(RENAME_EXCL)) == 0, "install_rename_failed")
        try syncParent(target)
        try syncParent(publication)
        try hooks.afterMutation(step: "after-publication-" + URL(fileURLWithPath: target).lastPathComponent)
        try verifyPin(target, pin: pin, mode: mode)
    }

    private func writeExclusive(_ data: Data, logical: String, mode: mode_t) throws {
        try validateAncestors(logical)
        let fd = Darwin.open(physical(logical), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode)
        try require(fd >= 0, "exclusive_write_open")
        defer { Darwin.close(fd) }
        try require(fchown(fd, context.trustedUID, context.trustedGID) == 0 &&
                    fchmod(fd, mode) == 0, "exclusive_write_owner_mode")
        let preparationFile = logical.hasPrefix(Self.bootstrapRoot + "/transaction-") ||
            logical == Self.journalPath + ".next"
        let name = URL(fileURLWithPath: logical).lastPathComponent
        if preparationFile { try hooks.afterMutation(step: "preparation-file-created-" + name) }
        var offset = 0
        while offset < data.count {
            let count = data.withUnsafeBytes { raw -> Int in
                guard let base = raw.baseAddress else { return -1 }
                return Darwin.write(fd, base.advanced(by: offset), min(raw.count - offset, 64 * 1024))
            }
            try require(count > 0, "exclusive_write")
            offset += count
            if preparationFile { try hooks.afterMutation(step: "preparation-file-written-" + name) }
        }
        try require(fsync(fd) == 0, "exclusive_write_sync")
        if logical.hasPrefix(Self.bootstrapRoot + "/transaction-") {
            var facts = stat()
            try require(fstat(fd, &facts) == 0 && facts.st_nlink == 1 && facts.st_size == data.count,
                        "preparation_write_identity_UNKNOWN")
            writtenPreparationFiles[logical] = FileSnapshot(existed: true,
                sha256: bootstrapSHA256(data), size: data.count, uid: facts.st_uid, gid: facts.st_gid,
                mode: facts.st_mode & 0o777, backup: nil, device: UInt64(facts.st_dev), inode: UInt64(facts.st_ino))
        }
        if preparationFile { try hooks.afterMutation(step: "preparation-file-synced-" + name) }
    }

    private func trustedFileSnapshotIfPresent(_ logical: String, mode: mode_t) throws -> FileSnapshot {
        if !exists(logical) {
            return FileSnapshot(existed: false, sha256: "", size: 0, uid: 0, gid: 0,
                                mode: mode, backup: nil)
        }
        return try trustedFileSnapshot(logical, mode: mode)
    }

    private func trustedFileSnapshot(_ logical: String, mode: mode_t) throws -> FileSnapshot {
        var before = stat()
        try require(lstat(physical(logical), &before) == 0, "snapshot_initial_stat")
        let data = try readTrustedFile(logical, mode: mode, maximum: 64 * 1024 * 1024)
        var facts = stat()
        try require(lstat(physical(logical), &facts) == 0 && before.st_dev == facts.st_dev &&
                    before.st_ino == facts.st_ino && before.st_mode == facts.st_mode &&
                    before.st_size == facts.st_size && before.st_uid == facts.st_uid &&
                    before.st_gid == facts.st_gid && before.st_nlink == facts.st_nlink &&
                    before.st_mtimespec.tv_sec == facts.st_mtimespec.tv_sec &&
                    before.st_mtimespec.tv_nsec == facts.st_mtimespec.tv_nsec &&
                    before.st_ctimespec.tv_sec == facts.st_ctimespec.tv_sec &&
                    before.st_ctimespec.tv_nsec == facts.st_ctimespec.tv_nsec,
                    "snapshot_identity_drift_UNKNOWN")
        return FileSnapshot(existed: true, sha256: bootstrapSHA256(data), size: data.count,
                            uid: facts.st_uid, gid: facts.st_gid, mode: facts.st_mode & 0o777,
                            backup: nil, device: UInt64(facts.st_dev), inode: UInt64(facts.st_ino))
    }

    private func verifyInstalled(inputs: InstallInputs, attestation: ArtifactPin) throws {
        try require(!exists(Self.emergencyDisablePath) && !exists(Self.disabledSudoersPath),
                    "bootstrap_emergency_revocation_UNKNOWN")
        try verifyPin(Self.binaryPath, pin: inputs.broker, mode: 0o555)
        try verifyPin(Self.policyPath, pin: inputs.policy, mode: 0o444)
        try verifyPin(Self.attestationPath, pin: attestation, mode: 0o400)
        try verifyPin(Self.sudoersPath, pin: inputs.renderedSudoers, mode: 0o440)
        try validateDirectory(Self.auditPath, mode: 0o700)
        try validateDirectory(Self.brokerStagingPath, mode: 0o700)
    }

    private func rollback(state: inout TransactionState) throws {
        try require(!exists(Self.emergencyDisablePath) && !exists(Self.disabledSudoersPath),
                    "bootstrap_emergency_revocation_UNKNOWN")
        // Check the entire set before touching anything. A foreign target is
        // not permission to restore a backup over it.
        try validateRecoveryState(state, committed: false)
        for target in [Self.sudoersPath, Self.attestationPath, Self.policyPath, Self.binaryPath] {
            let emergencyLease = target == Self.sudoersPath ? try acquireEmergencyLease() : -1
            defer { if emergencyLease >= 0 { Darwin.close(emergencyLease) } }
            try require(!exists(Self.emergencyDisablePath) && !exists(Self.disabledSudoersPath),
                        "bootstrap_emergency_revocation_UNKNOWN")
            guard let snapshot = state.files[target] else { continue }
            if try matches(target, snapshot) { continue }
            if exists(target) {
                try require(try matches(target, state.post[target]!), "rollback_foreign_UNKNOWN")
                try require(unlink(physical(target)) == 0, "rollback_unlink")
                try syncParent(target)
            }
            if snapshot.existed {
                try require(!exists(Self.emergencyDisablePath) && !exists(Self.disabledSudoersPath),
                            "bootstrap_emergency_revocation_UNKNOWN")
                guard let backup = snapshot.backup else {
                    throw BootstrapFailure.rejected("rollback_backup_missing")
                }
                try require(renameatx_np(AT_FDCWD, physical(backup), AT_FDCWD, physical(target), UInt32(RENAME_EXCL)) == 0, "rollback_restore")
                try syncParent(target)
                try syncParent(backup)
                let restored = try trustedFileSnapshot(target, mode: snapshot.mode)
                try require(restored.sha256 == snapshot.sha256 && restored.size == snapshot.size &&
                            restored.uid == snapshot.uid && restored.gid == snapshot.gid,
                            "rollback_file_verification")
            }
            try hooks.afterMutation(step: "rollback-" + URL(fileURLWithPath: target).lastPathComponent)
        }
        state.phase = "rolled-back"
        try saveJournal(state)
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
        try validateBoundDirectories(state)
        if !state.staging.isEmpty && exists(state.staging) {
            let prefix = physical(Self.bootstrapRoot) + "/transaction-"
            try require(physical(state.staging).hasPrefix(prefix), "staging_cleanup_scope")
            try validateDirectoryIdentity(state.staging, state: state)
            if state.mutationStarted {
                let names = try FileManager.default.contentsOfDirectory(atPath: physical(state.staging))
                for name in names {
                    let path = state.staging + "/" + name
                    if let directory = state.directoryStaging.first(where: { $0.value == path }) {
                        try validateDirectoryIdentity(path, state: state, expectedPath: directory.key)
                        try require(try FileManager.default.contentsOfDirectory(atPath: physical(path)).isEmpty,
                                    "directory_candidate_foreign_UNKNOWN")
                        continue
                    }
                    let prior = state.files.values.first { $0.backup == path && $0.existed }
                    guard let expected = prior ?? state.stagedFiles[name] else {
                        throw BootstrapFailure.rejected("staging_foreign_UNKNOWN")
                    }
                    try require(try matches(path, expected), "staging_identity_UNKNOWN")
                }
                for name in names {
                    let path = state.staging + "/" + name
                    if state.directoryStaging.values.contains(path) {
                        try require(rmdir(physical(path)) == 0, "staging_directory_retire")
                    } else {
                        try require(unlink(physical(path)) == 0, "staging_retire")
                    }
                }
                try require(rmdir(physical(state.staging)) == 0, "staging_directory_retire")
                try syncParent(state.staging)
            } else {
                throw BootstrapFailure.rejected("preparation_requires_retention")
            }
        }
        let keepOnSuccess = Set(["/etc/sudoers.d", "/etc/agent-first-mac",
                                 "/usr/local", "/usr/local/libexec",
                                 "/var/log/agent-first-mac",
                                 Self.auditPath, Self.brokerStagingPath,
                                 "/var/db/agent-first-mac"])
        for logical in state.createdDirectories.reversed() {
            if logical == Self.bootstrapRoot || logical == "/var/db/agent-first-mac" ||
                logical == state.staging { continue }
            if success && keepOnSuccess.contains(logical) { continue }
            if exists(logical) {
                try validateDirectoryIdentity(logical, state: state)
                try require(rmdir(physical(logical)) == 0, "directory_cleanup_not_empty")
                try syncParent(logical)
            }
        }
        if exists(Self.journalPath) {
            try require(unlink(physical(Self.journalPath)) == 0, "journal_retire")
            try syncParent(Self.journalPath)
        }
    }

    private func ensureDirectory(_ logical: String, mode: mode_t,
                                 state: inout TransactionState) throws {
        if exists(logical) {
            try validateDirectory(logical, mode: mode)
            return
        }
        let candidate = state.mutationStarted ? state.staging + "/directory-" + logical.replacingOccurrences(of: "/", with: "_") : logical
        try require(mkdir(physical(candidate), mode) == 0, "directory_create")
        try require(chown(physical(candidate), context.trustedUID, context.trustedGID) == 0 &&
                    chmod(physical(candidate), mode) == 0, "directory_owner_mode")
        state.createdDirectories.append(logical)
        try validateDirectory(candidate, mode: mode)
        var identity = stat()
        try require(lstat(physical(candidate), &identity) == 0, "directory_identity")
        state.directoryIdentities[logical] = [UInt64(identity.st_dev), UInt64(identity.st_ino)]
        if state.mutationStarted {
            state.directoryStaging[logical] = candidate
            try syncParent(candidate)
            try saveJournal(state)
            try hooks.afterMutation(step: "before-directory-publication-" + logical)
            try require(!exists(logical) && renameatx_np(AT_FDCWD, physical(candidate), AT_FDCWD, physical(logical), UInt32(RENAME_EXCL)) == 0,
                        "directory_publication_UNKNOWN")
            try syncParent(candidate)
        }
        try syncParent(logical)
        if state.mutationStarted { try hooks.afterMutation(step: "after-directory-publication-" + logical) }
    }

    private func validateDirectory(_ logical: String, mode: mode_t) throws {
        try validateAncestors(logical)
        var facts = stat()
        try require(lstat(physical(logical), &facts) == 0 && (facts.st_mode & S_IFMT) == S_IFDIR &&
                    facts.st_uid == context.trustedUID && facts.st_gid == context.trustedGID &&
                    (facts.st_mode & 0o022) == 0 &&
                    (facts.st_mode & 0o7777) == mode, "directory_contract")
    }

    private func validateDirectoryIdentity(_ logical: String, state: TransactionState, expectedPath: String? = nil) throws {
        var facts = stat()
        try validateAncestors(logical)
        try require(lstat(physical(logical), &facts) == 0 && (facts.st_mode & S_IFMT) == S_IFDIR &&
                    facts.st_uid == context.trustedUID && facts.st_gid == context.trustedGID &&
                    state.directoryIdentities[expectedPath ?? logical] == [UInt64(facts.st_dev), UInt64(facts.st_ino)],
                    "directory_identity_UNKNOWN")
    }

    private func syncParent(_ logical: String) throws {
        let parent = URL(fileURLWithPath: physical(logical)).deletingLastPathComponent().path
        let fd = Darwin.open(parent, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
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
