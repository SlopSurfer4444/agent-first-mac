import Darwin
import Foundation

private func require(_ condition: @autoclosure () -> Bool, _ reason: String) throws {
    if !condition() { throw BrokerFailure.rejected(reason) }
}

/// The child is the already-attested installed broker, not a user wrapper. It
/// execs Git in the SAME process group owned by BoundedProcess. No fork occurs
/// inside Swift, and no root process reads repository configuration.
public enum GitObservation {
    public static let helperMode = "--internal-git-observe"
    private static let setupFailure = "git_observer_setup_failed\n"

    public static func helperArguments(userID: uid_t, repository: String,
                                       command: [String]) throws -> [String] {
        try require(userID != 0 && repository.hasPrefix("/") && !repository.utf8.contains(0),
                    "git_observer_identity_or_path")
        let simple = [["rev-parse", "HEAD"], ["branch", "--show-current"],
                      ["status", "--porcelain", "--untracked-files=normal"]]
        let objectCommand = command.count == 2 && command[0] == "rev-parse" &&
            validObject(command[1], suffix: "^{tree}")
        let commitCommand = command.count == 3 && command[0] == "cat-file" && command[1] == "-e" &&
            validObject(command[2], suffix: "^{commit}")
        try require(simple.contains(command) || objectCommand || commitCommand, "git_observer_command")
        return [helperMode, String(userID), repository] + command
    }

    private static func validObject(_ value: String, suffix: String) -> Bool {
        value.hasSuffix(suffix) && value.count == 40 + suffix.count &&
            value.prefix(40).allSatisfy { "0123456789abcdef".contains($0) }
    }

    /// Called at fresh executable startup, before constructing a broker. The
    /// executable-level sudoers grant also reaches this internal entry: bind
    /// its UID to the root-owned installation receipt, not the caller's argv.
    public static func handleHelperIfRequested(_ arguments: [String]) {
        guard arguments.first == helperMode else { return }
        do {
            try require(arguments.count >= 4, "git_observer_arguments")
            guard let uid = uid_t(arguments[1]), String(uid) == arguments[1] else {
                throw BrokerFailure.rejected("git_observer_uid")
            }
            let repository = arguments[2], command = Array(arguments.dropFirst(3))
            _ = try helperArguments(userID: uid, repository: repository, command: command)
            if geteuid() == 0 {
                guard let account = getpwuid(uid), let name = account.pointee.pw_name else {
                    throw BrokerFailure.rejected("git_observer_account")
                }
                let context = RuntimeContext(realUID: uid, effectiveUID: 0, callerHome: "/var/empty",
                    callerIdentity: String(cString: name), currentExecutablePath: "")
                try AidAdminBroker(context: context).validateGitObservationOwner()
            }
            try dropGitObservationPrivileges(userID: uid, credentials: SystemGitCredentials())
            // Credential-sensitive input (repository/config/attributes/filter) is
            // first interpreted by Git only after the drop. Do not inherit env.
            let executable = "/usr/bin/git"
            let argv = ([executable] + fixedGitArguments(repository: repository, command: command)).map { strdup($0) } + [nil]
            let environment = fixedGitEnvironment(base: BrokerPolicy.cleanEnvironment)
            let envp = environment.keys.sorted().map { strdup("\($0)=\(environment[$0]!)") } + [nil]
            defer { for pointer in argv + envp { free(pointer) } }
            try require(argv.dropLast().allSatisfy { $0 != nil } && envp.dropLast().allSatisfy { $0 != nil },
                        "git_observer_allocation")
            argv.withUnsafeBufferPointer { av in
                envp.withUnsafeBufferPointer { ev in
                    _ = execve(executable, av.baseAddress!, ev.baseAddress!)
                }
            }
        } catch { /* fixed error below; never emit account/repository details */ }
        FileHandle.standardError.write(Data(setupFailure.utf8))
        _exit(126)
    }
}

/// Small injectable syscall contract: tests exercise ordering and every failure
/// without root. Production only uses SystemGitCredentials in a fresh helper.
public protocol GitCredentials {
    var realUID: uid_t { get }
    var effectiveUID: uid_t { get }
    var realGID: gid_t { get }
    var effectiveGID: gid_t { get }
    func primaryGID(userID: uid_t) throws -> gid_t
    func clearGroups() -> Bool
    func setGroup(_ gid: gid_t) -> Bool
    func setUser(_ uid: uid_t) -> Bool
    func regainRoot() -> Bool
}

public func dropGitObservationPrivileges(userID: uid_t, credentials: GitCredentials) throws {
    try require(userID != 0, "git_observer_root_target")
    let group = try credentials.primaryGID(userID: userID)
    try require(group != 0, "git_observer_root_group")
    if credentials.effectiveUID == 0 {
        // Root groups are never inherited. Owner-owned control needs no
        // supplemental group access; a group-only dependency fails closed.
        try require(credentials.clearGroups(), "git_observer_groups")
    } else {
        try require(credentials.realUID == userID && credentials.effectiveUID == userID &&
                    credentials.realGID == group && credentials.effectiveGID == group,
                    "git_observer_nonroot_identity")
    }
    // Darwin setgid/setuid also set the saved IDs when the supplied ID equals
    // the effective ID or the caller is root. Do not substitute seteuid/setegid.
    try require(credentials.setGroup(group), "git_observer_gid")
    try require(credentials.setUser(userID), "git_observer_uid")
    try require(credentials.realUID == userID && credentials.effectiveUID == userID &&
                credentials.realGID == group && credentials.effectiveGID == group,
                "git_observer_drop_incomplete")
    try require(!credentials.regainRoot(), "git_observer_drop_reversible")
}

private struct SystemGitCredentials: GitCredentials {
    var realUID: uid_t { getuid() }
    var effectiveUID: uid_t { geteuid() }
    var realGID: gid_t { getgid() }
    var effectiveGID: gid_t { getegid() }
    func primaryGID(userID: uid_t) throws -> gid_t {
        var entry = passwd(), result: UnsafeMutablePointer<passwd>?
        var storage = [CChar](repeating: 0, count: 16_384)
        let status = getpwuid_r(userID, &entry, &storage, storage.count, &result)
        try require(status == 0 && result != nil && entry.pw_uid == userID, "git_observer_account")
        return entry.pw_gid
    }
    func clearGroups() -> Bool { setgroups(0, nil) == 0 }
    func setGroup(_ gid: gid_t) -> Bool { setgid(gid) == 0 }
    func setUser(_ uid: uid_t) -> Bool { setuid(uid) == 0 }
    func regainRoot() -> Bool { setuid(0) == 0 }
}
