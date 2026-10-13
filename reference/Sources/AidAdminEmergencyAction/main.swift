import Darwin
import Foundation

private func fail(_ reason: String, code: Int32 = 64) -> Never {
    FileHandle.standardError.write(Data("aid-admin-emergency: rejected: \(reason)\n".utf8))
    exit(code)
}

private func executablePath() throws -> String {
    var size: UInt32 = 0
    _NSGetExecutablePath(nil, &size)
    var buffer = [CChar](repeating: 0, count: Int(size))
    guard _NSGetExecutablePath(&buffer, &size) == 0 else {
        throw EmergencyFailure.rejected("executable_path")
    }
    let bytes = buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }
    let path = String(decoding: bytes, as: UTF8.self)
    var info = stat()
    try requireOwner(lstat(path, &info) == 0 && (info.st_mode & S_IFMT) == S_IFREG &&
                     info.st_uid == getuid() && (info.st_mode & 0o022) == 0 &&
                     (info.st_mode & 0o111) != 0, "owner_action_file_contract")
    return path
}

private func requireOwner(_ value: @autoclosure () -> Bool, _ reason: String) throws {
    if !value() { throw EmergencyFailure.rejected(reason) }
}

private func ownerAction(_ action: String) throws {
    try requireOwner(getuid() > 0 && geteuid() == getuid(), "owner_execution_required")
    let executable = try executablePath()
    guard let ownerAction = EmergencyOwnerAction(rawValue: action) else {
        throw EmergencyFailure.rejected("unknown_action")
    }
    let orchestrator = EmergencyOwnerOrchestrator(
        executablePath: executable, runner: EmergencyProcessRunner())
    for line in try orchestrator.perform(ownerAction) { print(line) }
}

private func rootAction(_ action: String) throws {
    try requireOwner(geteuid() == 0, "root_required")
    let owner = try deriveEmergencyStandardSudoOwner(
        environment: ProcessInfo.processInfo.environment,
        accounts: SystemEmergencyAccountLookup())
    let context = EmergencyContext(effectiveUID: geteuid(), invokingOwner: owner)
    let transaction = EmergencyTransaction(context: context)
    if action == "__root-disable" {
        _ = try transaction.disable()
    } else {
        _ = try transaction.recover()
    }
}

do {
    let arguments = Array(CommandLine.arguments.dropFirst())
    guard arguments.count == 1 else { fail("usage") }
    switch arguments[0] {
    case "disable", "recover":
        try ownerAction(arguments[0])
    case "__root-disable", "__root-recover":
        try rootAction(arguments[0])
    default:
        fail("unknown_action")
    }
} catch {
    fail(String(describing: error), code: 1)
}
