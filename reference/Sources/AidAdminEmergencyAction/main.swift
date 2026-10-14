import Darwin
import Foundation
#if canImport(AidAdminEmergencyCore)
import AidAdminEmergencyCore
#endif
#if canImport(AidAdminCore)
import AidAdminCore
#endif

private func fail(_ reason: String, code: Int32 = 64) -> Never {
    FileHandle.standardError.write(Data("aid-admin-emergency: rejected: \(reason)\n".utf8))
    exit(code)
}

private func runtimeExecutablePath() throws -> String {
    var size: UInt32 = 0
    _NSGetExecutablePath(nil, &size)
    var buffer = [CChar](repeating: 0, count: Int(size))
    guard _NSGetExecutablePath(&buffer, &size) == 0 else {
        throw EmergencyFailure.rejected("executable_path")
    }
    let bytes = buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }
    let path = String(decoding: bytes, as: UTF8.self)
    return path
}

private func executablePath() throws -> String {
    let path = try runtimeExecutablePath()
    var info = stat()
    try requireOwner(lstat(path, &info) == 0 && (info.st_mode & S_IFMT) == S_IFREG &&
                     info.st_uid == getuid() && (info.st_mode & 0o022) == 0 &&
                     (info.st_mode & 0o111) != 0, "owner_action_file_contract")
    return path
}

private func requireOwner(_ value: @autoclosure () -> Bool, _ reason: String) throws {
    if !value() { throw EmergencyFailure.rejected(reason) }
}

private func ownerAction(_ action: String, commit: String? = nil) throws {
    try requireOwner(getuid() > 0 && geteuid() == getuid(), "owner_execution_required")
    let executable = try executablePath()
    let orchestrator = EmergencyOwnerOrchestrator(
        executablePath: executable, runner: EmergencyProcessRunner())
    if action == "resume", let commit {
        for line in try orchestrator.performResume(commit: commit) { print(line) }
        return
    }
    guard let ownerAction = EmergencyOwnerAction(rawValue: action) else {
        throw EmergencyFailure.rejected("unknown_action")
    }
    for line in try orchestrator.perform(ownerAction) { print(line) }
}

private func rootAction(_ action: String, commit: String? = nil) throws {
    try requireOwner(geteuid() == 0, "root_required")
    let owner = try deriveEmergencyStandardSudoOwner(
        environment: ProcessInfo.processInfo.environment,
        accounts: SystemEmergencyAccountLookup())
    let context = EmergencyContext(effectiveUID: geteuid(), invokingOwner: owner)
    let transaction = EmergencyTransaction(context: context)
    if action == "__root-disable" {
        _ = try transaction.disable()
    } else if action == "__root-recover" {
        _ = try transaction.recover()
    } else if action == "__root-resume", let commit {
        guard let entry = getpwuid(owner.uid), let home = entry.pointee.pw_dir else {
            throw EmergencyFailure.rejected("resume_owner_home_unavailable")
        }
        let brokerContext = RuntimeContext(realUID: owner.uid, effectiveUID: geteuid(),
            callerHome: String(cString: home), callerIdentity: owner.name,
            currentExecutablePath: try runtimeExecutablePath())
        let broker = AidAdminBroker(context: brokerContext,
            expectedPolicyHash: EmergencyArtifactExpectations.production.policySHA256)
        _ = try transaction.resume(commit: commit) {
            try broker.resumeInterruptedOperation(commit: $0)
        }
    } else {
        throw EmergencyFailure.rejected("unknown_action")
    }
}

do {
    let arguments = Array(CommandLine.arguments.dropFirst())
    guard let action = arguments.first else { fail("usage") }
    switch action {
    case "disable", "recover":
        guard arguments.count == 1 else { fail("usage") }
        try ownerAction(action)
    case "__root-disable", "__root-recover":
        guard arguments.count == 1 else { fail("usage") }
        try rootAction(action)
    case "resume", "__root-resume":
        guard arguments.count == 2 else { fail("usage") }
        try validateEmergencyRecoveryCommit(arguments[1])
        if action == "resume" { try ownerAction(action, commit: arguments[1]) }
        else { try rootAction(action, commit: arguments[1]) }
    default:
        fail("unknown_action")
    }
} catch {
    fail(String(describing: error), code: 1)
}
