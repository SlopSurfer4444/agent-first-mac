import CryptoKit
import Darwin
import Foundation
#if canImport(AidAdminRuntime)
import AidAdminRuntime
#endif

public enum EmergencyFailure: Error, CustomStringConvertible, Equatable {
    case rejected(String)

    public var description: String {
        switch self { case .rejected(let reason): return reason }
    }
}

private func require(_ condition: @autoclosure () -> Bool, _ reason: String) throws {
    if !condition() { throw EmergencyFailure.rejected(reason) }
}

public func emergencySHA256(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}

public struct EmergencyInvokingOwner: Equatable {
    public let name: String
    public let uid: UInt32

    public init(name: String, uid: UInt32) {
        self.name = name
        self.uid = uid
    }
}

public protocol EmergencyAccountLookingUp {
    func name(forUID uid: UInt32) -> String?
    func uid(forName name: String) -> UInt32?
}

public struct SystemEmergencyAccountLookup: EmergencyAccountLookingUp {
    public init() {}

    public func name(forUID uid: UInt32) -> String? {
        guard let entry = getpwuid(uid_t(uid)), let pointer = entry.pointee.pw_name else {
            return nil
        }
        return String(cString: pointer)
    }

    public func uid(forName name: String) -> UInt32? {
        guard let entry = getpwnam(name) else { return nil }
        return UInt32(entry.pointee.pw_uid)
    }
}

public func deriveEmergencyStandardSudoOwner(
    environment: [String: String],
    accounts: EmergencyAccountLookingUp
) throws -> EmergencyInvokingOwner {
    guard let rawUID = environment["SUDO_UID"], let rawName = environment["SUDO_USER"] else {
        throw EmergencyFailure.rejected("sudo_provenance_missing")
    }
    try require(rawUID.range(of: "^[1-9][0-9]{0,9}$", options: .regularExpression) != nil,
                "sudo_uid_syntax")
    guard let uid = UInt32(rawUID), uid > 0 else {
        throw EmergencyFailure.rejected("sudo_uid_syntax")
    }
    try require(rawName.range(of: "^[a-z_][a-z0-9_-]{0,31}$",
                              options: .regularExpression) != nil && rawName != "root",
                "sudo_user_syntax")
    try require(accounts.name(forUID: uid) == rawName, "sudo_uid_passwd_mismatch")
    try require(accounts.uid(forName: rawName) == uid, "sudo_user_passwd_mismatch")
    return EmergencyInvokingOwner(name: rawName, uid: uid)
}

public struct EmergencyContext {
    public let rootPrefix: String
    public let trustedUID: uid_t
    public let trustedGID: gid_t
    public let effectiveUID: uid_t
    public let invokingOwner: EmergencyInvokingOwner
    public let fixtureMode: Bool
    public let expectations: EmergencyArtifactExpectations

    public init(rootPrefix: String = "/", trustedUID: uid_t = 0, trustedGID: gid_t = 0,
                effectiveUID: uid_t, invokingOwner: EmergencyInvokingOwner,
                fixtureMode: Bool = false,
                expectations: EmergencyArtifactExpectations = .production) {
        self.rootPrefix = rootPrefix
        self.trustedUID = trustedUID
        self.trustedGID = trustedGID
        self.effectiveUID = effectiveUID
        self.invokingOwner = invokingOwner
        self.fixtureMode = fixtureMode
        self.expectations = expectations
    }
}

public struct EmergencyArtifactExpectations: Equatable, Sendable {
    public let binarySHA256: String
    public let binarySize: Int
    public let policySHA256: String
    public let policySize: Int
    public let sudoersSHA256: String
    public let sudoersSize: Int
    public let attestationSize: Int

    public init(binarySHA256: String, binarySize: Int,
                policySHA256: String, policySize: Int,
                sudoersSHA256: String, sudoersSize: Int,
                attestationSize: Int) {
        self.binarySHA256 = binarySHA256
        self.binarySize = binarySize
        self.policySHA256 = policySHA256
        self.policySize = policySize
        self.sudoersSHA256 = sudoersSHA256
        self.sudoersSize = sudoersSize
        self.attestationSize = attestationSize
    }

    public static let production = EmergencyArtifactExpectations(
        binarySHA256: "447fb83a10f2d66239b3a226a245de247559e1f900434eb80882f500fc659024",
        binarySize: 847_376,
        policySHA256: "2555b3f0ed1f75cd26bc41af6512ecc30d444ba1b0113458f72efcfccc304225",
        policySize: 1_617,
        sudoersSHA256: "b51a2c60bae3652decef1df7ffe2fd66931ee317305fbf1bc5c50e491f5c3ee6",
        sudoersSize: 122,
        attestationSize: 341)
}

public struct EmergencyCommandResult: Equatable {
    public let status: Int32
    public let output: String

    public init(status: Int32, output: String) {
        self.status = status
        self.output = output
    }
}

public protocol EmergencyCommandRunning {
    func run(executable: String, arguments: [String],
             environment: [String: String]) throws -> EmergencyCommandResult
    func runInteractive(executable: String, arguments: [String],
                        environment: [String: String]) throws -> EmergencyCommandResult
}

public extension EmergencyCommandRunning {
    func runInteractive(executable: String, arguments: [String],
                        environment: [String: String]) throws -> EmergencyCommandResult {
        try run(executable: executable, arguments: arguments, environment: environment)
    }
}

public final class EmergencyProcessRunner: EmergencyCommandRunning {
    public init() {}

    public func run(executable: String, arguments: [String],
                    environment: [String: String]) throws -> EmergencyCommandResult {
        let result = try BoundedProcess.run(
            executable: executable, arguments: arguments, environment: environment,
            limits: .init(timeout: 30, maximumOutputBytes: 4096))
        try require(result.outcome == .exited && result.settled,
                    "emergency_process_" + result.outcome.rawValue)
        return EmergencyCommandResult(status: result.status,
                                      output: result.stdout + result.stderr)
    }

    public func runInteractive(
        executable: String, arguments: [String], environment: [String: String]
    ) throws -> EmergencyCommandResult {
        try require(executable.hasPrefix("/") && !executable.utf8.contains(0),
                    "interactive_executable_contract")
        try require(arguments.allSatisfy { !$0.utf8.contains(0) } &&
                    environment.allSatisfy { !$0.key.utf8.contains(0) &&
                                             !$0.value.utf8.contains(0) },
                    "interactive_argument_contract")
        try require(isatty(STDIN_FILENO) == 1, "interactive_controlling_tty_required")
        let ownerGroup = getpgrp()
        try require(ownerGroup > 0 && tcgetpgrp(STDIN_FILENO) == ownerGroup,
                    "interactive_foreground_group_required")

        var argumentPointers = try cStringVector([executable] + arguments)
        var environmentPointers = try cStringVector(
            environment.keys.sorted().map { $0 + "=" + environment[$0]! })
        defer {
            releaseCStringVector(argumentPointers)
            releaseCStringVector(environmentPointers)
        }

        var child: pid_t = 0
        let spawnStatus = executable.withCString { executablePointer in
            argumentPointers.withUnsafeMutableBufferPointer { argumentBuffer in
                environmentPointers.withUnsafeMutableBufferPointer { environmentBuffer in
                    posix_spawn(&child, executablePointer, nil, nil,
                                argumentBuffer.baseAddress!, environmentBuffer.baseAddress!)
                }
            }
        }
        try require(spawnStatus == 0 && child > 0, "interactive_spawn_failed")

        let childGroup = getpgid(child)
        let stillForeground = tcgetpgrp(STDIN_FILENO)
        guard childGroup == ownerGroup && stillForeground == ownerGroup else {
            _ = kill(child, SIGKILL)
            var discarded: Int32 = 0
            while waitpid(child, &discarded, 0) < 0 && errno == EINTR {}
            throw EmergencyFailure.rejected("interactive_foreground_inheritance_failed")
        }

        var waitStatus: Int32 = 0
        var waited: pid_t
        repeat { waited = waitpid(child, &waitStatus, 0) }
        while waited < 0 && errno == EINTR
        try require(waited == child, "interactive_wait_failed")
        let reason = waitStatus & 0x7f
        let status: Int32
        if reason == 0 {
            status = (waitStatus >> 8) & 0xff
        } else {
            status = 128 + reason
        }
        return EmergencyCommandResult(status: status, output: "")
    }

    private func cStringVector(_ values: [String]) throws -> [UnsafeMutablePointer<CChar>?] {
        var result: [UnsafeMutablePointer<CChar>?] = []
        for value in values {
            guard let pointer = strdup(value) else {
                releaseCStringVector(result)
                throw EmergencyFailure.rejected("interactive_argument_allocation_failed")
            }
            result.append(pointer)
        }
        result.append(nil)
        return result
    }

    private func releaseCStringVector(_ values: [UnsafeMutablePointer<CChar>?]) {
        for case let pointer? in values { free(pointer) }
    }
}

public protocol EmergencyHooks {
    func beforeTransition(step: String) throws
    func afterMutation(step: String) throws
    func beforeRollback() throws
}

public struct NoEmergencyHooks: EmergencyHooks {
    public init() {}
    public func beforeTransition(step: String) throws {}
    public func afterMutation(step: String) throws {}
    public func beforeRollback() throws {}
}

public enum EmergencyOwnerAction: String {
    case disable
    case recover
}

public func validateEmergencyRecoveryCommit(_ commit: String) throws {
    try require(commit.utf8.count == 40 &&
                commit.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) },
                "resume_commit_syntax")
}

public final class EmergencyOwnerOrchestrator {
    private let runner: EmergencyCommandRunning
    private let executablePath: String

    public init(executablePath: String, runner: EmergencyCommandRunning) {
        self.executablePath = executablePath
        self.runner = runner
    }

    public func perform(_ action: EmergencyOwnerAction) throws -> [String] {
        let internalAction = action == .disable ? "__root-disable" : "__root-recover"
        let rootResult: EmergencyCommandResult
        do { rootResult = try interactiveSudo(["-k", "--", executablePath, internalAction]) }
        catch {
            _ = try? clearTimestamp()
            throw EmergencyFailure.rejected(action.rawValue + "_root_transaction_unknown")
        }
        if rootResult.status != 0 {
            try clearTimestampOrReject(action.rawValue + "_root_transaction_failed")
            throw EmergencyFailure.rejected(action.rawValue + "_root_transaction_failed")
        }
        if action == .disable {
            return try finishDisable()
        }
        return try finishRecovery()
    }

    /// Resumes only the recorded exact target under a new standard-sudo boundary.
    /// It never restores broker admission and never claims payload data recovery.
    public func performResume(commit: String) throws -> [String] {
        try validateEmergencyRecoveryCommit(commit)
        let result: EmergencyCommandResult
        do {
            result = try interactiveSudo(["-k", "--", executablePath, "__root-resume", commit])
        } catch {
            _ = try? clearTimestamp()
            throw EmergencyFailure.rejected("resume_root_transaction_unknown")
        }
        try clearTimestampOrReject("resume_timestamp_clear_failed")
        try require(result.status == 0, "resume_root_transaction_failed")
        return [
            "EMERGENCY_OPERATION_RESUMED_DISABLED",
            "recorded_operation_resumed=true",
            "arbitrary_data_restoration_claimed=false",
            "broker_admission_disabled=true",
            "sudo_timestamp_cleared=true",
            "reenable_requires_separate_fresh_standard_sudo=true",
        ]
    }

    private func finishDisable() throws -> [String] {
        try clearTimestampOrReject("disable_timestamp_clear_failed_state_retained")
        // The authenticated transaction verified exact grant absence. A broken
        // broker's exit status cannot prove sudo denial and must not be run here.
        return [
            "EMERGENCY_DISABLE_VERIFIED",
            "exact_managed_grant_absent=true",
            "sudo_timestamp_cleared=true",
            "recovery_requires_fresh_standard_sudo=true",
            "in_flight_apply_state=UNKNOWN",
            "in_flight_apply_stopped=false",
        ]
    }

    private func finishRecovery() throws -> [String] {
        let doctor: EmergencyCommandResult
        do { doctor = try doctorResult() }
        catch {
            // The doctor is read-only. Revocation is safe even if its child
            // settlement is unknown; this does not claim that child stopped.
            return try rollbackFailedRecovery(original: "recovery_doctor_unknown")
        }
        guard recoveredDoctorIsReady(doctor) else {
            return try rollbackFailedRecovery()
        }
        do {
            try clearTimestampOrReject("recovery_timestamp_clear_failed")
        } catch {
            return try rollbackFailedRecovery(original: "recovery_timestamp_clear_failed")
        }
        return [
            "EMERGENCY_RECOVERY_VERIFIED",
            "root_contract_ready=true",
            "sudo_timestamp_cleared=true",
        ]
    }

    private func rollbackFailedRecovery(
        original: String = "recovery_verification_failed"
    ) throws -> [String] {
        let rollback: EmergencyCommandResult
        do { rollback = try sudo(["-n", "--", executablePath, "__root-disable"]) }
        catch {
            _ = try? clearTimestamp()
            throw EmergencyFailure.rejected(original + "_rollback_unknown")
        }
        guard rollback.status == 0 else {
            _ = try? clearTimestamp()
            throw EmergencyFailure.rejected(original + "_rollback_failed")
        }
        do {
            try clearTimestamp()
        } catch {
            throw EmergencyFailure.rejected(original + "_rollback_failed")
        }
        // The authenticated disable transaction verified exact grant absence.
        // An enabled-only broker doctor cannot attest revocation and may be broken.
        throw EmergencyFailure.rejected(original + "_rolled_back")
    }

    private func doctorResult() throws -> EmergencyCommandResult {
        try sudo(["-n", "/usr/local/libexec/aid-admin", "doctor-root", "--json"])
    }

    private func recoveredDoctorIsReady(_ result: EmergencyCommandResult) -> Bool {
        guard result.status == 0, let data = result.output.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return false }
        return object["verdict"] as? String == "ROOT_CONTRACT_READY" &&
            object["readOnly"] as? Bool == true &&
            object["systemMutationsPerformed"] as? Bool == false &&
            (object["problems"] as? [Any])?.isEmpty == true
    }

    private func clearTimestampOrReject(_ reason: String) throws {
        do { try clearTimestamp() }
        catch { throw EmergencyFailure.rejected(reason) }
    }

    private func clearTimestamp() throws {
        let result = try sudo(["-k"])
        try require(result.status == 0, "sudo_timestamp_clear_failed")
    }

    private func sudo(_ arguments: [String]) throws -> EmergencyCommandResult {
        try runner.run(executable: "/usr/bin/sudo", arguments: arguments,
                       environment: EmergencyTransaction.cleanEnvironment)
    }

    private func interactiveSudo(_ arguments: [String]) throws -> EmergencyCommandResult {
        try runner.runInteractive(executable: "/usr/bin/sudo", arguments: arguments,
                                  environment: EmergencyTransaction.cleanEnvironment)
    }
}

private struct EmergencyInstallAttestation: Codable {
    let agentOwnerIdentity: String
    let agentOwnerUID: UInt32
    let binarySHA256: String
    let policySHA256: String
    let schema: Int
    let sudoersSHA256: String
}

private final class TrustedEmergencyDirectory {
    let logicalPath: String
    let fd: Int32
    let device: dev_t
    let inode: ino_t
    let mode: mode_t

    init(logicalPath: String, fd: Int32, facts: stat, mode: mode_t) {
        self.logicalPath = logicalPath
        self.fd = fd
        self.device = facts.st_dev
        self.inode = facts.st_ino
        self.mode = mode
    }

    deinit { Darwin.close(fd) }
}

private struct TrustedEmergencyParents {
    let sudoers: TrustedEmergencyDirectory
    let canonicalEtc: TrustedEmergencyDirectory
    let canonicalSudoers: TrustedEmergencyDirectory
    let agentConfiguration: TrustedEmergencyDirectory
    let libexec: TrustedEmergencyDirectory?
    let audit: TrustedEmergencyDirectory?
    let staging: TrustedEmergencyDirectory?
    let operationRoot: TrustedEmergencyDirectory
    let revocationOnly: Bool
}

private struct EmergencyFileIdentity: Equatable {
    let device: dev_t
    let inode: ino_t
}

// Write-ahead ownership, not a success receipt. Kept until exact terminal state
// is verified, so another authenticated process can reconcile an interruption.
private struct EmergencyJournal: Codable {
    let schema: Int
    let action: String
    let sudoersDevice: Int64
    let sudoersInode: UInt64
}

private final class EmergencyLease {
    let fd: Int32
    init(_ fd: Int32) { self.fd = fd }
    deinit { _ = flock(fd, LOCK_UN); Darwin.close(fd) }
}

public final class EmergencyTransaction {
    public static let mainSudoersPath = "/private/etc/sudoers"
    public static let binaryPath = "/usr/local/libexec/aid-admin"
    public static let policyPath = "/etc/agent-first-mac/aid-admin-policy.json"
    public static let attestationPath = "/etc/agent-first-mac/aid-admin-install.json"
    public static let sudoersPath = "/etc/sudoers.d/agent-first-mac-aid-admin"
    public static let disabledSudoersPath = "/etc/sudoers.d/agent-first-mac-aid-admin.disabled"
    public static let markerPath = "/etc/agent-first-mac/aid-admin.disabled"
    public static let auditPath = "/var/log/agent-first-mac/aid-admin"
    public static let stagingPath = "/var/db/agent-first-mac/staging"
    public static let operationRootPath = "/var/db/agent-first-mac"
    // Revocation must not depend on the apply staging directory. The existing
    // operation root also holds the installer/emergency exclusion lease.
    public static let journalPath = operationRootPath + "/emergency-operation.json"
    public static let journalTemporaryPath = journalPath + ".new"
    public static let operationPath = stagingPath + "/operation.json"
    private static let legacyJournalPath = stagingPath + "/emergency-operation.json"
    private static let legacyJournalTemporaryPath = legacyJournalPath + ".new"

    public static let binarySHA256 = EmergencyArtifactExpectations.production.binarySHA256
    public static let binarySize = EmergencyArtifactExpectations.production.binarySize
    public static let policySHA256 = EmergencyArtifactExpectations.production.policySHA256
    public static let policySize = EmergencyArtifactExpectations.production.policySize
    public static let sudoersSHA256 = EmergencyArtifactExpectations.production.sudoersSHA256
    public static let sudoersSize = EmergencyArtifactExpectations.production.sudoersSize
    public static let attestationSize = EmergencyArtifactExpectations.production.attestationSize
    public static let markerData = Data("agent-first-mac-aid-admin-disabled-v1\n".utf8)
    public static let cleanEnvironment = [
        "HOME": "/var/empty", "LANG": "C", "LC_ALL": "C",
        "PATH": "/usr/bin:/bin", "TMPDIR": "/var/empty",
    ]

    private static let markerTemporaryPath = markerPath + ".new"
    private let context: EmergencyContext
    private let runner: EmergencyCommandRunning
    private let hooks: EmergencyHooks

    public init(context: EmergencyContext, runner: EmergencyCommandRunning = EmergencyProcessRunner(),
                hooks: EmergencyHooks = NoEmergencyHooks()) {
        self.context = context
        self.runner = runner
        self.hooks = hooks
    }

    public func disable() throws -> String {
        try validateContext()
        let parents = try openTrustedParents(revocationOnly: true)
        let lease = try acquireLease(".emergency.lock", parents)
        defer { withExtendedLifetime(lease) {} }
        if try reconcileInterrupted(parents) {
            return "EMERGENCY_DISABLE_TRANSACTION_COMMITTED"
        }
        if try !exists(Self.sudoersPath, parents) {
            try validateDisabledState(parents)
            return "EMERGENCY_DISABLE_ALREADY_DISABLED"
        }
        try validateEnabledState(parents)
        try beginJournal(action: "disable", sudoers: Self.sudoersPath, parents)
        do {
            try renameNoReplace(Self.sudoersPath, Self.disabledSudoersPath,
                                parents: parents, step: "disable-sudoers-move",
                                failure: "disable_sudoers_move")
            try hooks.afterMutation(step: "sudoers-moved")
            _ = try readExpectedSudoers(Self.disabledSudoersPath, parents)

            _ = try createMarker(parents)
            try hooks.afterMutation(step: "marker-created")
            try validateDisabledState(parents)
            try hooks.afterMutation(step: "disabled-final-verification")
            try clearJournal(parents)
            return "EMERGENCY_DISABLE_TRANSACTION_COMMITTED"
        } catch {
            // Retain the write-ahead record and exact moved grant. Never restore
            // authority merely because marker/audit publication was interrupted.
            throw error
        }
    }

    public func recover() throws -> String {
        try validateContext()
        let parents = try openTrustedParents()
        let lease = try acquireLease(".emergency.lock", parents)
        defer { withExtendedLifetime(lease) {} }
        try requireNoLegacyEmergencyJournal(parents)
        _ = try reconcileInterrupted(parents)
        let applyLease = try acquireLease(".operation.lock", parents)
        defer { withExtendedLifetime(applyLease) {} }
        try requireSettledApply(parents)
        try validateDisabledState(parents)
        try validateSudoers(Self.disabledSudoersPath, parents)
        try validateFullSudoers(parents)
        try beginJournal(action: "recover", sudoers: Self.disabledSudoersPath, parents)
        var mutationStarted = false
        do {
            try renameNoReplace(Self.disabledSudoersPath, Self.sudoersPath,
                                parents: parents, step: "recovery-sudoers-restore",
                                failure: "recovery_sudoers_restore")
            mutationStarted = true
            try hooks.afterMutation(step: "sudoers-restored")
            try renameNoReplace(Self.markerPath, Self.markerTemporaryPath,
                                parents: parents, step: "recovery-marker-stage",
                                failure: "recovery_marker_stage")
            try hooks.afterMutation(step: "marker-staged")
            let markerIdentity = try identity(Self.markerTemporaryPath, parents)
            try removeExactFile(Self.markerTemporaryPath, expected: markerIdentity,
                                parents: parents, failure: "recovery_marker_remove")
            try hooks.afterMutation(step: "marker-removed")
            try validateSudoers(Self.sudoersPath, parents)
            try hooks.afterMutation(step: "enabled-visudo")
            try validateFullSudoers(parents)
            try hooks.afterMutation(step: "full-visudo-enabled")
            try validateEnabledState(parents)
            try hooks.afterMutation(step: "enabled-final-verification")
            try clearJournal(parents)
            return "EMERGENCY_RECOVERY_TRANSACTION_COMMITTED"
        } catch {
            let original = String(describing: error)
            if original.hasPrefix("emergency_process_") { throw error }
            if mutationStarted {
                do {
                    try hooks.beforeRollback()
                    try rollbackRecovery(parents)
                    try clearJournal(parents)
                    throw EmergencyFailure.rejected(original + "_rolled_back")
                } catch let failure as EmergencyFailure where failure.description.hasSuffix("_rolled_back") {
                    throw failure
                } catch {
                    throw EmergencyFailure.rejected(original + "_rollback_failed")
                }
            }
            throw error
        }
    }

    public func validateEnabledState() throws {
        try validateContext()
        try validateEnabledState(openTrustedParents())
    }

    /// The executable supplies the fixed broker method, never a user-selected
    /// command, path or generation. Core owns the operation lease and reviewed
    /// receipt/boot/state checks; this boundary owns disabled-artifact trust and
    /// exclusion against authority publication for the entire exact-target resume.
    public func resume(commit: String, operation: (String) throws -> String) throws -> String {
        try validateEmergencyRecoveryCommit(commit)
        try validateContext()
        let parents = try openTrustedParents()
        let lease = try acquireLease(".emergency.lock", parents)
        defer { withExtendedLifetime(lease) {} }
        try requireNoLegacyEmergencyJournal(parents)
        _ = try reconcileInterrupted(parents)
        try validateDisabledState(parents)
        try validateSudoers(Self.disabledSudoersPath, parents)
        try validateFullSudoers(parents)
        do {
            let result = try operation(commit)
            try require(result == "OPERATION_RESUMED_DISABLED", "resume_result_contract")
            try validateDisabledState(parents)
            return result
        } catch {
            // Do not enable, repeat a possibly committed operation, or erase its
            // journal. The core's exact error/phase remains available for retry.
            try validateDisabledState(parents)
            throw error
        }
    }

    public func validateDisabledState() throws {
        try validateContext()
        try validateDisabledState(openTrustedParents())
    }

    private func acquireLease(_ name: String, _ parents: TrustedEmergencyParents) throws -> EmergencyLease {
        let directory = parents.operationRoot
        try revalidateDirectory(directory)
        let fd = openat(directory.fd, name,
                        O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0o600)
        try require(fd >= 0, "emergency_lock_open")
        do {
            var descriptor = stat(), named = stat()
            try require(fstat(fd, &descriptor) == 0 &&
                        fstatat(directory.fd, name, &named, AT_SYMLINK_NOFOLLOW) == 0 &&
                        (descriptor.st_mode & S_IFMT) == S_IFREG &&
                        descriptor.st_nlink == 1 && descriptor.st_uid == context.trustedUID &&
                        descriptor.st_gid == context.trustedGID &&
                        (descriptor.st_mode & 0o777) == 0o600 &&
                        descriptor.st_dev == named.st_dev && descriptor.st_ino == named.st_ino,
                        "emergency_lock_contract")
            try require(flock(fd, LOCK_EX | LOCK_NB) == 0,
                        name == ".operation.lock" ? "emergency_apply_busy" : "emergency_busy")
            try require(fstatat(directory.fd, name, &named, AT_SYMLINK_NOFOLLOW) == 0 &&
                        descriptor.st_dev == named.st_dev && descriptor.st_ino == named.st_ino,
                        "emergency_lock_identity_drift")
            return EmergencyLease(fd)
        } catch {
            Darwin.close(fd)
            throw error
        }
    }

    private func requireSettledApply(_ parents: TrustedEmergencyParents) throws {
        guard try exists(Self.operationPath, parents) else { return }
        let bytes = try readTrustedFile(Self.operationPath, mode: 0o600,
                                        maximum: 64 * 1024, parents: parents)
        guard let object = try? JSONSerialization.jsonObject(with: bytes) as? [String: Any],
              let schema = object["schema"] as? NSNumber,
              CFGetTypeID(schema) != CFBooleanGetTypeID(),
              [1, 2].contains(schema.intValue), schema.doubleValue == Double(schema.intValue),
              let phase = object["phase"] as? String,
              (["complete", "rollback_verified"].contains(phase) ||
               (schema.intValue == 2 && phase == "resumed")) else {
            throw EmergencyFailure.rejected("emergency_apply_unresolved")
        }
    }

    private func requireNoLegacyEmergencyJournal(_ parents: TrustedEmergencyParents) throws {
        // Do not infer settlement, migrate, or delete records from the previous
        // layout. Revocation needs only the exact grant; regrant/resume cannot
        // ignore retained legacy recovery ownership.
        for path in [Self.legacyJournalPath, Self.legacyJournalTemporaryPath] {
            let present = try exists(path, parents)
            try require(!present, "emergency_legacy_journal_unresolved")
        }
    }

    private func beginJournal(action: String, sudoers: String,
                              _ parents: TrustedEmergencyParents) throws {
        let sudoersIdentity = try identity(sudoers, parents)
        let journal = EmergencyJournal(schema: 1, action: action,
            sudoersDevice: Int64(sudoersIdentity.device), sudoersInode: UInt64(sudoersIdentity.inode))
        let data = try journalBytes(journal)
        let location = try fileLocation(Self.journalTemporaryPath, parents)
        let fd = openat(location.directory.fd, location.name,
                        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        try require(fd >= 0, "emergency_journal_create")
        defer { Darwin.close(fd) }
        try hooks.afterMutation(step: "emergency-journal-opened")
        var offset = 0
        while offset < data.count {
            let count = data.withUnsafeBytes {
                Darwin.write(fd, $0.baseAddress!.advanced(by: offset), data.count - offset)
            }
            try require(count > 0, "emergency_journal_write")
            offset += count
            try hooks.afterMutation(step: "emergency-journal-written")
        }
        try require(fsync(fd) == 0 && fsync(location.directory.fd) == 0,
                    "emergency_journal_sync")
        let staged = try readTrustedFile(Self.journalTemporaryPath, mode: 0o600,
                                         maximum: 4096, parents: parents)
        try require(staged == data, "emergency_journal_staging_drift")
        try renameNoReplace(Self.journalTemporaryPath, Self.journalPath, parents: parents,
                            step: "emergency-journal-publish", failure: "emergency_journal_publish")
        _ = try readJournal(parents)
        try hooks.afterMutation(step: "emergency-journal-created")
    }

    private func journalBytes(_ journal: EmergencyJournal) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(journal)
    }

    /// A pre-publication crash cannot have mutated sudoers. Retire only the
    /// fixed temporary file whose bytes are an exact canonical journal prefix
    /// for the freshly verified terminal prestate and original descriptor.
    private func reconcileJournalTemporary(_ parents: TrustedEmergencyParents) throws -> Bool {
        guard try exists(Self.journalTemporaryPath, parents) else { return false }
        let final = try exists(Self.journalPath, parents)
        try require(!final, "emergency_journal_collision")
        let enabled = try exists(Self.sudoersPath, parents)
        if enabled { try validateEnabledState(parents) }
        else { try validateDisabledState(parents) }
        let sudoers = enabled ? Self.sudoersPath : Self.disabledSudoersPath
        let source = try identity(sudoers, parents)
        let canonical = try journalBytes(EmergencyJournal(schema: 1,
            action: enabled ? "disable" : "recover", sudoersDevice: Int64(source.device),
            sudoersInode: UInt64(source.inode)))
        let bytes = try readTrustedFile(Self.journalTemporaryPath, mode: 0o600,
                                        maximum: 4096, parents: parents)
        try require(canonical.starts(with: bytes), "emergency_journal_temporary_unknown")
        let expected = try identity(Self.journalTemporaryPath, parents)
        let location = try fileLocation(Self.journalTemporaryPath, parents)
        let current = try identity(Self.journalTemporaryPath, parents)
        try require(current == expected && unlinkat(location.directory.fd, location.name, 0) == 0 &&
                    fsync(location.directory.fd) == 0, "emergency_journal_temporary_remove")
        return !enabled
    }

    private func readJournal(_ parents: TrustedEmergencyParents) throws -> EmergencyJournal {
        let data = try readTrustedFile(Self.journalPath, mode: 0o600, maximum: 4096, parents: parents)
        guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys) == ["schema", "action", "sudoersDevice", "sudoersInode"],
              let journal = try? JSONDecoder().decode(EmergencyJournal.self, from: data),
              journal.schema == 1, ["disable", "recover"].contains(journal.action) else {
            throw EmergencyFailure.rejected("emergency_journal_invalid")
        }
        return journal
    }

    private func clearJournal(_ parents: TrustedEmergencyParents) throws {
        _ = try readJournal(parents)
        let expected = try identity(Self.journalPath, parents)
        let location = try fileLocation(Self.journalPath, parents)
        try revalidateDirectory(location.directory)
        let current = try identity(Self.journalPath, parents)
        try require(current == expected && unlinkat(location.directory.fd, location.name, 0) == 0 &&
                    fsync(location.directory.fd) == 0, "emergency_journal_remove")
    }

    /// No inferred phase permits overwrite. A retained write-ahead record and
    /// exact original sudoers inode/bytes must agree with one known partial state.
    /// Reconciliation first returns authority to disabled; recovery is separate.
    private func reconcileInterrupted(_ parents: TrustedEmergencyParents) throws -> Bool {
        let alreadyDisabled = try reconcileJournalTemporary(parents)
        guard try exists(Self.journalPath, parents) else { return alreadyDisabled }
        let journal = try readJournal(parents)
        let enabled = try exists(Self.sudoersPath, parents)
        let disabled = try exists(Self.disabledSudoersPath, parents)
        try require(enabled != disabled, "emergency_interrupted_sudoers_state")
        let sudoers = enabled ? Self.sudoersPath : Self.disabledSudoersPath
        try validateStaticArtifacts(sudoers: sudoers, parents: parents)
        let current = try identity(sudoers, parents)
        try require(Int64(current.device) == journal.sudoersDevice &&
                    UInt64(current.inode) == journal.sudoersInode,
                    "emergency_interrupted_sudoers_identity")
        let marker = try exists(Self.markerPath, parents)
        let temporary = try exists(Self.markerTemporaryPath, parents)
        try require(!(marker && temporary), "emergency_interrupted_marker_collision")
        var partialTemporary = false
        for path in [Self.markerPath, Self.markerTemporaryPath] where try exists(path, parents) {
            let bytes = try readTrustedFile(path, mode: 0o400, maximum: 256, parents: parents)
            if path == Self.markerTemporaryPath && bytes != Self.markerData {
                try require(Self.markerData.starts(with: bytes), "emergency_interrupted_marker_drift")
                partialTemporary = true
            } else {
                try require(bytes == Self.markerData, "emergency_interrupted_marker_drift")
            }
        }
        if enabled {
            try renameNoReplace(Self.sudoersPath, Self.disabledSudoersPath, parents: parents,
                                step: "interrupted-sudoers-disable", failure: "interrupted_sudoers_disable")
        }
        if temporary {
            if partialTemporary {
                let expected = try identity(Self.markerTemporaryPath, parents)
                let location = try fileLocation(Self.markerTemporaryPath, parents)
                let current = try identity(Self.markerTemporaryPath, parents)
                try require(current == expected && unlinkat(location.directory.fd, location.name, 0) == 0 &&
                            fsync(location.directory.fd) == 0, "interrupted_marker_partial_remove")
                _ = try createMarker(parents)
            } else {
                try renameNoReplace(Self.markerTemporaryPath, Self.markerPath, parents: parents,
                                    step: "interrupted-marker-restore", failure: "interrupted_marker_restore")
            }
        } else if !marker {
            _ = try createMarker(parents)
        }
        if !parents.revocationOnly {
            try validateSudoers(Self.disabledSudoersPath, parents)
            try validateFullSudoers(parents)
        }
        try validateDisabledState(parents)
        try clearJournal(parents)
        return true
    }

    private func validateEnabledState(_ parents: TrustedEmergencyParents) throws {
        try validateStaticArtifacts(sudoers: Self.sudoersPath, parents: parents)
        let disabledSudoersExists = try exists(Self.disabledSudoersPath, parents)
        let markerExists = try exists(Self.markerPath, parents)
        let temporaryMarkerExists = try exists(Self.markerTemporaryPath, parents)
        try require(!disabledSudoersExists && !markerExists && !temporaryMarkerExists,
                    "enabled_state_extra_path")
    }

    private func validateDisabledState(_ parents: TrustedEmergencyParents) throws {
        let enabledSudoersExists = try exists(Self.sudoersPath, parents)
        try require(!enabledSudoersExists, "disabled_state_enabled_sudoers_present")
        try validateStaticArtifacts(sudoers: Self.disabledSudoersPath, parents: parents)
        let marker = try readTrustedFile(Self.markerPath, mode: 0o400, maximum: 256,
                                         parents: parents)
        try require(marker == Self.markerData, "disable_marker_drift")
        let temporaryMarkerExists = try exists(Self.markerTemporaryPath, parents)
        try require(!temporaryMarkerExists, "disable_marker_temporary_present")
    }

    private func validateContext() throws {
        if context.fixtureMode {
            try require(context.rootPrefix != "/" &&
                        (context.rootPrefix.hasPrefix("/private/") ||
                         context.rootPrefix.hasPrefix("/tmp/")), "fixture_root_contract")
            try require(context.effectiveUID == context.trustedUID, "fixture_identity")
        } else {
            try require(context.rootPrefix == "/" && context.effectiveUID == 0 &&
                        context.trustedUID == 0 && context.trustedGID == 0,
                        "root_required")
        }
        try require(context.invokingOwner.uid > 0 && context.invokingOwner.name != "root" &&
                    context.invokingOwner.name.range(of: "^[a-z_][a-z0-9_-]{0,31}$",
                                                     options: .regularExpression) != nil,
                    "invoking_owner_contract")
    }

    private func validateStaticArtifacts(
        sudoers: String, parents: TrustedEmergencyParents
    ) throws {
        if parents.revocationOnly {
            let bytes = try readExpectedSudoers(sudoers, parents)
            let expected = "Cmnd_Alias AGENT_FIRST_MAC_AID_ADMIN = /usr/local/libexec/aid-admin\n" +
                context.invokingOwner.name + " ALL=(root) NOPASSWD: AGENT_FIRST_MAC_AID_ADMIN\n"
            try require(bytes == Data(expected.utf8), "revocation_grant_owner_binding")
            return
        }
        let binary = try readTrustedFile(Self.binaryPath, mode: 0o555,
                                         maximum: 32 * 1024 * 1024, parents: parents)
        try require(binary.count == context.expectations.binarySize &&
                    emergencySHA256(binary) == context.expectations.binarySHA256, "binary_drift")
        let policy = try readTrustedFile(Self.policyPath, mode: 0o444, maximum: 64 * 1024,
                                         parents: parents)
        try require(policy.count == context.expectations.policySize &&
                    emergencySHA256(policy) == context.expectations.policySHA256, "policy_drift")
        let sudoersData = try readExpectedSudoers(sudoers, parents)
        let attestationData = try readTrustedFile(Self.attestationPath, mode: 0o400,
                                                  maximum: 4096, parents: parents)
        try require(attestationData.count == context.expectations.attestationSize,
                    "attestation_size_drift")
        let raw = try JSONSerialization.jsonObject(with: attestationData)
        guard let object = raw as? [String: Any] else {
            throw EmergencyFailure.rejected("attestation_not_object")
        }
        try require(Set(object.keys) == ["agentOwnerIdentity", "agentOwnerUID", "binarySHA256",
                                        "policySHA256", "schema", "sudoersSHA256"],
                    "attestation_keys")
        let value = try JSONDecoder().decode(EmergencyInstallAttestation.self, from: attestationData)
        try require(value.schema == 1 && value.agentOwnerIdentity == context.invokingOwner.name &&
                    value.agentOwnerUID == context.invokingOwner.uid,
                    "attestation_owner_binding")
        try require(value.binarySHA256 == context.expectations.binarySHA256 &&
                    value.policySHA256 == context.expectations.policySHA256 &&
                    value.sudoersSHA256 == context.expectations.sudoersSHA256,
                    "attestation_hash_binding")
        try require(emergencySHA256(sudoersData) == value.sudoersSHA256,
                    "attestation_sudoers_binding")
        guard let audit = parents.audit else { throw EmergencyFailure.rejected("recovery_audit_missing") }
        try revalidateDirectory(audit)
        guard let staging = parents.staging else { throw EmergencyFailure.rejected("recovery_staging_missing") }
        try revalidateDirectory(staging)
    }

    private func readExpectedSudoers(
        _ logical: String, _ parents: TrustedEmergencyParents
    ) throws -> Data {
        let data = try readTrustedFile(logical, mode: 0o440, maximum: 4096,
                                       parents: parents)
        try require(data.count == context.expectations.sudoersSize &&
                    emergencySHA256(data) == context.expectations.sudoersSHA256,
                    "sudoers_drift")
        return data
    }

    private func validateSudoers(
        _ logical: String, _ parents: TrustedEmergencyParents
    ) throws {
        _ = try readExpectedSudoers(logical, parents)
        let result = try runner.run(executable: "/usr/sbin/visudo",
                                    arguments: ["-cf", physical(logical)],
                                    environment: Self.cleanEnvironment)
        try require(result.status == 0, "visudo_file_failed")
    }

    private func validateFullSudoers(_ parents: TrustedEmergencyParents) throws {
        _ = try readTrustedFile(Self.mainSudoersPath, mode: 0o440,
                                maximum: 64 * 1024, parents: parents)
        try revalidateDirectory(parents.canonicalEtc)
        try revalidateDirectory(parents.canonicalSudoers)
        try require(parents.sudoers.device == parents.canonicalSudoers.device &&
                    parents.sudoers.inode == parents.canonicalSudoers.inode,
                    "sudoers_directory_alias_drift")
        let result = try runner.run(executable: "/usr/sbin/visudo",
                                    arguments: ["-cf", physical(Self.mainSudoersPath)],
                                    environment: Self.cleanEnvironment)
        if result.status != 0 {
            throw EmergencyFailure.rejected(
                "visudo_full_syntax_failed_" + classifyFullVisudoFailure(result.output))
        }
    }

    private func classifyFullVisudoFailure(_ boundedOutput: String) -> String {
        let value = boundedOutput.prefix(4096).lowercased()
        if value.contains("syntax error") || value.contains("parse error") {
            return "syntax"
        }
        if value.contains("unable to open") || value.contains("no such file") ||
            value.contains("not found") {
            return "include_unavailable"
        }
        if value.contains("permission denied") { return "access" }
        return "rejected"
    }

    private func rollbackRecovery(_ parents: TrustedEmergencyParents) throws {
        let enabledSudoersExists = try exists(Self.sudoersPath, parents)
        let disabledSudoersExists = try exists(Self.disabledSudoersPath, parents)
        try require(enabledSudoersExists && !disabledSudoersExists,
                    "rollback_recovery_sudoers_state")
        try renameNoReplace(Self.sudoersPath, Self.disabledSudoersPath,
                            parents: parents, step: "rollback-recovery-sudoers-disable",
                            failure: "rollback_recovery_sudoers_disable")
        let finalExists = try exists(Self.markerPath, parents)
        let temporaryExists = try exists(Self.markerTemporaryPath, parents)
        if finalExists && !temporaryExists {
            let marker = try readTrustedFile(Self.markerPath, mode: 0o400, maximum: 256,
                                             parents: parents)
            try require(marker == Self.markerData, "rollback_recovery_marker_drift")
        } else if !finalExists && temporaryExists {
            let marker = try readTrustedFile(Self.markerTemporaryPath, mode: 0o400,
                                             maximum: 256, parents: parents)
            try require(marker == Self.markerData, "rollback_recovery_marker_temporary_drift")
            try renameNoReplace(Self.markerTemporaryPath, Self.markerPath,
                                parents: parents, step: "rollback-recovery-marker-restore",
                                failure: "rollback_recovery_marker_restore")
        } else if !finalExists && !temporaryExists {
            _ = try createMarker(parents)
        } else {
            throw EmergencyFailure.rejected("rollback_recovery_marker_state")
        }
        try validateSudoers(Self.disabledSudoersPath, parents)
        try validateFullSudoers(parents)
        try validateDisabledState(parents)
    }

    private func createMarker(
        _ parents: TrustedEmergencyParents
    ) throws -> EmergencyFileIdentity {
        let markerExists = try exists(Self.markerPath, parents)
        let temporaryMarkerExists = try exists(Self.markerTemporaryPath, parents)
        try require(!markerExists && !temporaryMarkerExists,
                    "disable_marker_preexisting")
        let location = try fileLocation(Self.markerTemporaryPath, parents)
        try revalidateDirectory(location.directory)
        let fd = Darwin.openat(location.directory.fd, location.name,
                               O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o400)
        try require(fd >= 0, "trusted_file_missing")
        var temporaryIdentity: EmergencyFileIdentity?
        defer { Darwin.close(fd) }
        do {
            try hooks.afterMutation(step: "marker-temporary-opened")
            var offset = 0
            while offset < Self.markerData.count {
                let count = Self.markerData.withUnsafeBytes { raw -> Int in
                    guard let base = raw.baseAddress else { return -1 }
                    return Darwin.write(fd, base.advanced(by: offset), raw.count - offset)
                }
                try require(count > 0, "disable_marker_write")
                offset += count
                try hooks.afterMutation(step: "marker-temporary-written")
            }
            try require(fchown(fd, context.trustedUID, context.trustedGID) == 0 &&
                        fchmod(fd, 0o400) == 0 && fsync(fd) == 0,
                        "disable_marker_metadata")
            var created = stat()
            try require(fstat(fd, &created) == 0, "disable_marker_stat")
            temporaryIdentity = EmergencyFileIdentity(device: created.st_dev,
                                                      inode: created.st_ino)
            try hooks.afterMutation(step: "marker-temporary-created")
            try renameNoReplace(Self.markerTemporaryPath, Self.markerPath,
                                parents: parents, step: "disable-marker-commit",
                                failure: "disable_marker_commit")
            let finalIdentity = try identity(Self.markerPath, parents)
            try require(finalIdentity == temporaryIdentity, "disable_marker_identity")
            let data = try readTrustedFile(Self.markerPath, mode: 0o400, maximum: 256,
                                           parents: parents)
            try require(data == Self.markerData, "disable_marker_verification")
            return finalIdentity
        } catch {
            if let temporaryIdentity, try exists(Self.markerTemporaryPath, parents) {
                do {
                    try removeExactFile(Self.markerTemporaryPath, expected: temporaryIdentity,
                                        parents: parents,
                                        failure: "disable_marker_temporary_cleanup")
                } catch {
                    throw EmergencyFailure.rejected("disable_marker_temporary_cleanup_failed")
                }
            }
            throw error
        }
    }

    private func readTrustedFile(
        _ logical: String, mode: mode_t, maximum: Int,
        parents: TrustedEmergencyParents
    ) throws -> Data {
        let location = try fileLocation(logical, parents)
        try revalidateDirectory(location.directory)
        let fd = Darwin.openat(location.directory.fd, location.name,
                               O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        try require(fd >= 0, "trusted_file_missing")
        defer { Darwin.close(fd) }
        var before = stat()
        try require(fstat(fd, &before) == 0 && (before.st_mode & S_IFMT) == S_IFREG,
                    "trusted_file_type")
        try require(before.st_nlink == 1 && before.st_uid == context.trustedUID && before.st_gid == context.trustedGID,
                    "trusted_file_owner")
        try require((before.st_mode & 0o777) == mode, "trusted_file_mode")
        try require(before.st_size >= 0 && before.st_size <= maximum, "trusted_file_size")
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
                    before.st_nlink == after.st_nlink &&
                    before.st_uid == after.st_uid && before.st_gid == after.st_gid &&
                    before.st_mode == after.st_mode &&
                    before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec &&
                    before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec &&
                    before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec &&
                    before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec,
                    "trusted_file_race")
        try revalidateDirectory(location.directory)
        let namedIdentity = try identity(logical, parents)
        try require(namedIdentity.device == before.st_dev && namedIdentity.inode == before.st_ino,
                    "trusted_file_named_identity_drift")
        return data
    }

    private func openTrustedParents(revocationOnly: Bool = false) throws -> TrustedEmergencyParents {
        let sudoers = try openTrustedDirectory("/etc/sudoers.d", mode: 0o755)
        let canonicalEtc = try openTrustedDirectory("/private/etc", mode: 0o755)
        let canonicalSudoers = try openTrustedDirectory("/private/etc/sudoers.d", mode: 0o755)
        try require(sudoers.device == canonicalSudoers.device &&
                    sudoers.inode == canonicalSudoers.inode,
                    "sudoers_directory_alias_mismatch")
        return TrustedEmergencyParents(
            sudoers: sudoers,
            canonicalEtc: canonicalEtc,
            canonicalSudoers: canonicalSudoers,
            agentConfiguration: try openTrustedDirectory("/etc/agent-first-mac", mode: 0o755),
            libexec: revocationOnly ? nil : try openTrustedDirectory("/usr/local/libexec", mode: 0o755),
            audit: revocationOnly ? nil : try openTrustedDirectory(Self.auditPath, mode: 0o700),
            staging: revocationOnly ? nil : try openTrustedDirectory(Self.stagingPath, mode: 0o700),
            operationRoot: try openTrustedDirectory(Self.operationRootPath, mode: 0o755),
            revocationOnly: revocationOnly)
    }

    private func openTrustedDirectory(
        _ logical: String, mode: mode_t
    ) throws -> TrustedEmergencyDirectory {
        try validateLogicalPath(logical)
        let path = physical(logical)
        var pathFacts = stat()
        try require(lstat(path, &pathFacts) == 0 &&
                    (pathFacts.st_mode & S_IFMT) == S_IFDIR,
                    "trusted_directory_type")
        let fd = Darwin.open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        try require(fd >= 0, "trusted_directory_open")
        var descriptorFacts = stat()
        guard fstat(fd, &descriptorFacts) == 0 else {
            Darwin.close(fd)
            throw EmergencyFailure.rejected("trusted_directory_stat")
        }
        do {
            try require((descriptorFacts.st_mode & S_IFMT) == S_IFDIR &&
                        descriptorFacts.st_dev == pathFacts.st_dev &&
                        descriptorFacts.st_ino == pathFacts.st_ino,
                        "trusted_directory_race")
            try require(descriptorFacts.st_uid == context.trustedUID &&
                        descriptorFacts.st_gid == context.trustedGID &&
                        (descriptorFacts.st_mode & 0o777) == mode,
                        "trusted_directory_contract")
        } catch {
            Darwin.close(fd)
            throw error
        }
        return TrustedEmergencyDirectory(logicalPath: logical, fd: fd,
                                         facts: descriptorFacts, mode: mode)
    }

    private func revalidateDirectory(_ directory: TrustedEmergencyDirectory) throws {
        var facts = stat()
        try require(fstat(directory.fd, &facts) == 0 &&
                    (facts.st_mode & S_IFMT) == S_IFDIR &&
                    facts.st_dev == directory.device && facts.st_ino == directory.inode,
                    "trusted_directory_identity_drift")
        try require(facts.st_uid == context.trustedUID &&
                    facts.st_gid == context.trustedGID &&
                    (facts.st_mode & 0o777) == directory.mode,
                    "trusted_directory_contract_drift")
    }

    private func fileLocation(
        _ logical: String, _ parents: TrustedEmergencyParents
    ) throws -> (directory: TrustedEmergencyDirectory, name: String) {
        switch logical {
        case Self.mainSudoersPath:
            return (parents.canonicalEtc, "sudoers")
        case Self.binaryPath:
            guard let libexec = parents.libexec else { throw EmergencyFailure.rejected("recovery_libexec_missing") }
            return (libexec, "aid-admin")
        case Self.policyPath:
            return (parents.agentConfiguration, "aid-admin-policy.json")
        case Self.attestationPath:
            return (parents.agentConfiguration, "aid-admin-install.json")
        case Self.markerPath:
            return (parents.agentConfiguration, "aid-admin.disabled")
        case Self.markerTemporaryPath:
            return (parents.agentConfiguration, "aid-admin.disabled.new")
        case Self.sudoersPath:
            return (parents.sudoers, "agent-first-mac-aid-admin")
        case Self.disabledSudoersPath:
            return (parents.sudoers, "agent-first-mac-aid-admin.disabled")
        case Self.journalPath:
            return (parents.operationRoot, "emergency-operation.json")
        case Self.journalTemporaryPath:
            return (parents.operationRoot, "emergency-operation.json.new")
        case Self.legacyJournalPath, Self.legacyJournalTemporaryPath:
            guard let staging = parents.staging else { throw EmergencyFailure.rejected("recovery_staging_missing") }
            return (staging, logical == Self.legacyJournalPath ?
                    "emergency-operation.json" : "emergency-operation.json.new")
        case Self.operationPath:
            guard let staging = parents.staging else { throw EmergencyFailure.rejected("recovery_staging_missing") }
            return (staging, "operation.json")
        default:
            throw EmergencyFailure.rejected("fixed_path_not_allowed")
        }
    }

    private func exists(
        _ logical: String, _ parents: TrustedEmergencyParents
    ) throws -> Bool {
        let location = try fileLocation(logical, parents)
        try revalidateDirectory(location.directory)
        var facts = stat()
        if fstatat(location.directory.fd, location.name, &facts, AT_SYMLINK_NOFOLLOW) == 0 {
            return true
        }
        if errno == ENOENT { return false }
        throw EmergencyFailure.rejected("fixed_path_state_unavailable")
    }

    private func identity(
        _ logical: String, _ parents: TrustedEmergencyParents
    ) throws -> EmergencyFileIdentity {
        let location = try fileLocation(logical, parents)
        try revalidateDirectory(location.directory)
        var facts = stat()
        try require(fstatat(location.directory.fd, location.name, &facts,
                            AT_SYMLINK_NOFOLLOW) == 0 &&
                    (facts.st_mode & S_IFMT) == S_IFREG,
                    "fixed_path_identity")
        return EmergencyFileIdentity(device: facts.st_dev, inode: facts.st_ino)
    }

    private func renameNoReplace(
        _ source: String, _ destination: String, parents: TrustedEmergencyParents,
        step: String, failure: String
    ) throws {
        let sourceLocation = try fileLocation(source, parents)
        let destinationLocation = try fileLocation(destination, parents)
        let sourceIdentity = try identity(source, parents)
        try revalidateDirectory(sourceLocation.directory)
        try revalidateDirectory(destinationLocation.directory)
        try hooks.beforeTransition(step: step)
        try revalidateDirectory(sourceLocation.directory)
        try revalidateDirectory(destinationLocation.directory)
        let currentSource = try identity(source, parents)
        try require(currentSource == sourceIdentity, failure + "_source_identity")
        try require(renameatx_np(sourceLocation.directory.fd, sourceLocation.name,
                                 destinationLocation.directory.fd, destinationLocation.name,
                                 UInt32(RENAME_EXCL)) == 0, failure)
        try require(fsync(sourceLocation.directory.fd) == 0, failure + "_sync")
        if sourceLocation.directory.fd != destinationLocation.directory.fd {
            try require(fsync(destinationLocation.directory.fd) == 0, failure + "_sync")
        }
        try revalidateDirectory(sourceLocation.directory)
        try revalidateDirectory(destinationLocation.directory)
    }

    private func removeExactFile(
        _ logical: String, expected: EmergencyFileIdentity,
        parents: TrustedEmergencyParents, failure: String
    ) throws {
        let marker = try readTrustedFile(logical, mode: 0o400, maximum: 256,
                                         parents: parents)
        try require(marker == Self.markerData, failure + "_drift")
        let location = try fileLocation(logical, parents)
        let currentIdentity = try identity(logical, parents)
        try require(currentIdentity == expected, failure + "_identity")
        try require(unlinkat(location.directory.fd, location.name, 0) == 0, failure)
        try require(fsync(location.directory.fd) == 0, failure + "_sync")
        let remains = try exists(logical, parents)
        try require(!remains, failure + "_poststate")
    }

    private func physical(_ logical: String) -> String {
        context.rootPrefix == "/" ? logical : context.rootPrefix + logical
    }

    private func validateLogicalPath(_ value: String) throws {
        try require(value.hasPrefix("/") && !value.contains("//"), "path_not_absolute_canonical")
        let parts = value.split(separator: "/", omittingEmptySubsequences: false)
        try require(!parts.contains(".") && !parts.contains(".."), "path_traversal")
        if context.fixtureMode {
            let candidate = physical(value)
            var ancestor = URL(fileURLWithPath: candidate)
            while !FileManager.default.fileExists(atPath: ancestor.path) &&
                    ancestor.path != context.rootPrefix {
                ancestor.deleteLastPathComponent()
            }
            guard let resolved = realpath(ancestor.path, nil) else {
                throw EmergencyFailure.rejected("fixture_path_unavailable")
            }
            defer { free(resolved) }
            let actual = String(cString: resolved)
            try require(actual == context.rootPrefix || actual.hasPrefix(context.rootPrefix + "/"),
                        "fixture_symlink_escape")
        }
    }
}
