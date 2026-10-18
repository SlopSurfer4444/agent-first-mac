import AidAdminBootstrapCore
import Darwin
import Foundation

private func executablePath() -> String {
    var size: UInt32 = 0
    _NSGetExecutablePath(nil, &size)
    var buffer = [CChar](repeating: 0, count: Int(size))
    guard _NSGetExecutablePath(&buffer, &size) == 0 else { return CommandLine.arguments[0] }
    let bytes = buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }
    return String(decoding: bytes, as: UTF8.self)
}

private func fail(_ reason: String, code: Int32 = 64) -> Never {
    FileHandle.standardError.write(Data("aid-admin-bootstrap: rejected: \(reason)\n".utf8))
    exit(code)
}

let arguments = Array(CommandLine.arguments.dropFirst())
// These fixed maintenance actions share the same standard-sudo provenance as
// installation; they add no broker command or passwordless grant.
if arguments == ["inventory-preparations"] ||
    (arguments.count == 2 && arguments[0] == "retire-preparation") {
    do {
        let invokingOwner = try deriveStandardSudoInvokingOwner(
            environment: ProcessInfo.processInfo.environment,
            accounts: SystemBootstrapAccountLookup())
        let context = BootstrapContext(effectiveUID: geteuid(), currentExecutablePath: executablePath(),
                                       invokingOwner: invokingOwner)
        let installer = BootstrapInstaller(context: context)
        if arguments[0] == "inventory-preparations" {
            let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
            let bytes = try encoder.encode(installer.inventoryPreparations())
            FileHandle.standardOutput.write(bytes + Data("\n".utf8))
        } else {
            print(try installer.retirePreparation(identifier: arguments[1]))
        }
        exit(0)
    } catch { fail(String(describing: error), code: 65) }
}
guard arguments.count == 10, arguments[0] == "install" else {
    fail("usage")
}
guard let inputsSize = Int(arguments[6]), let ownerUID = UInt32(arguments[8]) else {
    fail("numeric_argument")
}

let request = BootstrapRequest(
    brokerPath: arguments[1], policyPath: arguments[2], sudoersTemplatePath: arguments[3],
    inputsPath: arguments[4], inputsSHA256: arguments[5], inputsSize: inputsSize,
    ownerName: arguments[7], ownerUID: ownerUID, sudoersIdentity: arguments[9])

do {
    let invokingOwner = try deriveStandardSudoInvokingOwner(
        environment: ProcessInfo.processInfo.environment,
        accounts: SystemBootstrapAccountLookup())
    let context = BootstrapContext(effectiveUID: geteuid(), currentExecutablePath: executablePath(),
                                   invokingOwner: invokingOwner)
    let verdict = try BootstrapInstaller(context: context).install(request)
    print(verdict)
    print("sudoers_installed_last=true")
    print("rollback_contract=exact_prior_absent_or_installed_state")
    exit(0)
} catch {
    fail(String(describing: error), code: 65)
}
