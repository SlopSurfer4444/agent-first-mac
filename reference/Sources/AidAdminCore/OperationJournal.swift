import Darwin
import Foundation

/// Admission helper shared with the installer; parsing a record grants no apply authority.
public func validateSettledApplyJournal(_ data: Data) throws {
    let value = try ApplyOperation.decodeStrict(data)
    guard ["complete", "rollback_verified", "resumed"].contains(value.phase) else {
        throw BrokerFailure.rejected("operation_needs_reconcile")
    }
}

// Fixed-location, root-owned state. A freed flock never proves that an interrupted
// activation (or one of its descendants) stopped. Such phases remain UNKNOWN.
struct ApplyOperation: Codable, Equatable {
    let schema: Int
    let identifier: String
    let commit: String
    let tree: String
    let policyHash: String
    let receiptHash: String
    let previousIdentifier: String
    let previousTarget: String
    let target: String
    let activationExecutable: String
    let activationHash: String
    let nixEnvExecutable: String
    let nixEnvHash: String
    let caller: String
    var targetIdentifier: String
    var phase: String
    var sourceDrift: Bool
    var bootGeneration: String? = nil
    var previousNarHash: String? = nil
    var targetNarHash: String? = nil
    var previousRevision: String? = nil
    var lastAttemptBoot: String? = nil
    var resumeAttemptCount: Int? = nil

    func sealSHA256() throws -> String {
        let immutable = ["schema": String(schema), "identifier": identifier, "commit": commit,
            "tree": tree, "policyHash": policyHash, "receiptHash": receiptHash,
            "previousIdentifier": previousIdentifier, "previousTarget": previousTarget, "target": target,
            "activationExecutable": activationExecutable, "activationHash": activationHash,
            "nixEnvExecutable": nixEnvExecutable, "nixEnvHash": nixEnvHash, "caller": caller,
            "bootGeneration": bootGeneration ?? "", "previousNarHash": previousNarHash ?? "",
            "targetNarHash": targetNarHash ?? "", "previousRevision": previousRevision ?? ""]
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        return sha256Hex(try encoder.encode(immutable))
    }

    static func decodeStrict(_ data: Data) throws -> ApplyOperation {
        let value = try JSONDecoder().decode(Self.self, from: data)
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        guard try encoder.encode(value) == data, [1, 2].contains(value.schema),
              ["sealed", "profile_pending", "profile_ready", "activation_pending", "committed",
               "audit_incomplete", "complete", "rollback_pending", "rollback_verified", "unknown",
               "resume_pending", "resume_committed", "resumed"].contains(value.phase),
              value.identifier.range(of: "^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$", options: .regularExpression) != nil,
              [value.policyHash, value.receiptHash, value.activationHash, value.nixEnvHash].allSatisfy({
                  $0.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil
              }),
              [value.previousTarget, value.target].allSatisfy({
                  $0.range(of: "^/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-darwin-system-[A-Za-z0-9._+-]{1,96}$", options: .regularExpression) != nil
              }),
              value.previousIdentifier.range(of: "^[1-9][0-9]{0,8}$", options: .regularExpression) != nil,
              value.targetIdentifier == "pending" || value.targetIdentifier.range(of: "^[1-9][0-9]{0,8}$", options: .regularExpression) != nil,
              ["root-direct", "sudo-user"].contains(value.caller) else {
            throw BrokerFailure.rejected("operation_journal_schema")
        }
        try validateCommit(value.commit); try validateCommit(value.tree)
        if value.schema == 2 {
            guard let boot = value.bootGeneration, boot.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil,
                  let previousNar = value.previousNarHash, let targetNar = value.targetNarHash,
                  [previousNar, targetNar].allSatisfy({ $0.range(of: "^sha256:[0-9abcdfghijklmnpqrsvwxyz]{52}$", options: .regularExpression) != nil }),
                  let previousRevision = value.previousRevision else {
                throw BrokerFailure.rejected("operation_schema2_recovery_identity")
            }
            try validateCommit(previousRevision)
        } else if value.bootGeneration != nil || value.previousNarHash != nil || value.targetNarHash != nil ||
                    value.previousRevision != nil || value.lastAttemptBoot != nil || value.resumeAttemptCount != nil ||
                    ["resume_pending", "resume_committed", "resumed"].contains(value.phase) {
            throw BrokerFailure.rejected("operation_schema1_not_upgradable")
        }
        if value.lastAttemptBoot != nil || value.resumeAttemptCount != nil ||
                ["resume_pending", "resume_committed", "resumed"].contains(value.phase) {
            guard let boot = value.lastAttemptBoot,
                  boot.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil,
                  let count = value.resumeAttemptCount, count >= 1 && count <= 16 else {
                throw BrokerFailure.rejected("operation_resume_identity")
            }
        }
        return value
    }
}

final class ApplyOperationLease {
    private let directory: String
    private let directoryFD: Int32
    private let lockFD: Int32
    private let lockParentFD: Int32
    private let lockParent: String
    private let uid: uid_t
    private static let phases: Set<String> = ["sealed", "profile_pending", "profile_ready",
        "activation_pending", "committed", "audit_incomplete", "complete", "rollback_pending",
        "rollback_verified", "unknown", "resume_pending", "resume_committed", "resumed"]

    init(directory: String, uid: uid_t) throws {
        self.directory = directory; self.uid = uid
        lockParent = URL(fileURLWithPath: directory).deletingLastPathComponent().path
        let dir = open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard dir >= 0 else { throw BrokerFailure.rejected("operation_directory_open") }
        var info = stat()
        guard fstat(dir, &info) == 0, info.st_uid == uid, info.st_mode & 0o7777 == 0o700 else {
            close(dir); throw BrokerFailure.rejected("operation_directory_identity")
        }
        let lockParentDescriptor = open(lockParent, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard lockParentDescriptor >= 0, fstat(lockParentDescriptor, &info) == 0,
              info.st_uid == uid, info.st_mode & 0o7777 == 0o755 else {
            if lockParentDescriptor >= 0 { close(lockParentDescriptor) }
            close(dir); throw BrokerFailure.rejected("operation_lock_parent")
        }
        let lock = openat(lockParentDescriptor, ".operation.lock", O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard lock >= 0 else { close(lockParentDescriptor); close(dir); throw BrokerFailure.rejected("operation_lock_open") }
        guard fstat(lock, &info) == 0, info.st_uid == uid,
              info.st_mode & S_IFMT == S_IFREG, info.st_mode & 0o7777 == 0o600,
              info.st_nlink == 1 else {
            close(lock); close(lockParentDescriptor); close(dir); throw BrokerFailure.rejected("operation_lock_identity")
        }
        guard flock(lock, LOCK_EX | LOCK_NB) == 0 else {
            close(lock); close(lockParentDescriptor); close(dir); throw BrokerFailure.rejected("operation_busy")
        }
        directoryFD = dir; lockFD = lock; lockParentFD = lockParentDescriptor
        do { try revalidate() } catch { close(lock); close(lockParentDescriptor); close(dir); throw error }
    }

    deinit { flock(lockFD, LOCK_UN); close(lockFD); close(lockParentFD); close(directoryFD) }

    private func revalidate() throws {
        var held = stat(); var named = stat(); var lockHeld = stat(); var lockNamed = stat()
        var parentHeld = stat(); var parentNamed = stat()
        guard fstat(directoryFD, &held) == 0, lstat(directory, &named) == 0,
              held.st_dev == named.st_dev, held.st_ino == named.st_ino,
              named.st_uid == uid, named.st_mode & S_IFMT == S_IFDIR,
              named.st_mode & 0o7777 == 0o700,
              fstat(lockParentFD, &parentHeld) == 0, lstat(lockParent, &parentNamed) == 0,
              parentHeld.st_ino == parentNamed.st_ino, parentHeld.st_dev == parentNamed.st_dev,
              parentNamed.st_mode & S_IFMT == S_IFDIR, parentNamed.st_mode & 0o7777 == 0o755,
              parentNamed.st_uid == uid,
              fstat(lockFD, &lockHeld) == 0,
              fstatat(lockParentFD, ".operation.lock", &lockNamed, AT_SYMLINK_NOFOLLOW) == 0,
              lockHeld.st_dev == lockNamed.st_dev, lockHeld.st_ino == lockNamed.st_ino,
              lockNamed.st_uid == uid, lockNamed.st_nlink == 1,
              lockNamed.st_mode & S_IFMT == S_IFREG, lockNamed.st_mode & 0o7777 == 0o600 else {
            throw BrokerFailure.rejected("operation_parent_or_lock_drift")
        }
    }

    func read() throws -> ApplyOperation? {
        try revalidate()
        let fd = openat(directoryFD, "operation.json", O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        if fd < 0 { if errno == ENOENT { return nil }; throw BrokerFailure.rejected("operation_journal_open") }
        defer { close(fd) }
        var before = stat()
        guard fstat(fd, &before) == 0, before.st_uid == uid, before.st_nlink == 1,
              before.st_mode & S_IFMT == S_IFREG, before.st_mode & 0o7777 == 0o600,
              before.st_size > 0, before.st_size <= 16384 else {
            throw BrokerFailure.rejected("operation_journal_identity")
        }
        var bytes = [UInt8](repeating: 0, count: Int(before.st_size))
        var offset = 0
        while offset < bytes.count {
            let n = bytes.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress!.advanced(by: offset), $0.count - offset) }
            guard n > 0 else { throw BrokerFailure.rejected("operation_journal_read") }; offset += n
        }
        let value: ApplyOperation
        do { value = try ApplyOperation.decodeStrict(Data(bytes)) }
        catch { throw BrokerFailure.rejected("operation_journal_corrupt") }
        guard [1, 2].contains(value.schema), Self.phases.contains(value.phase),
              value.identifier.range(of: "^[0-9a-f-]{36}$", options: .regularExpression) != nil,
              value.previousIdentifier.range(of: "^[1-9][0-9]{0,8}$", options: .regularExpression) != nil,
              value.target.hasPrefix("/nix/store/"), value.previousTarget.hasPrefix("/nix/store/") else {
            throw BrokerFailure.rejected("operation_journal_schema")
        }
        try validateCommit(value.commit)
        try revalidate()
        return value
    }

    func write(_ value: ApplyOperation) throws {
        try revalidate()
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(value)
        guard data.count <= 16384 else { throw BrokerFailure.rejected("operation_journal_size") }
        let name = ".operation-" + UUID().uuidString.lowercased()
        let fd = openat(directoryFD, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw BrokerFailure.rejected("operation_journal_create") }
        defer { close(fd); unlinkat(directoryFD, name, 0) }
        var offset = 0
        while offset < data.count {
            let n = data.withUnsafeBytes { Darwin.write(fd, $0.baseAddress!.advanced(by: offset), $0.count - offset) }
            guard n > 0 else { throw BrokerFailure.rejected("operation_journal_write") }; offset += n
        }
        guard fsync(fd) == 0 else { throw BrokerFailure.rejected("operation_journal_file_sync") }
        try revalidate()
        guard renameat(directoryFD, name, directoryFD, "operation.json") == 0,
              fsync(directoryFD) == 0 else { throw BrokerFailure.rejected("operation_journal_publish_unknown") }
    }
}
