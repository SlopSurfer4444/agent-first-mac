import AidAdminCore
import Darwin
import Foundation

private let applyPolicySHA256 = "2555b3f0ed1f75cd26bc41af6512ecc30d444ba1b0113458f72efcfccc304225"

private func executablePath() -> String {
    var size: UInt32 = 0
    _NSGetExecutablePath(nil, &size)
    var buffer = [CChar](repeating: 0, count: Int(size))
    guard _NSGetExecutablePath(&buffer, &size) == 0 else { return CommandLine.arguments[0] }
    let bytes = buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }
    return String(decoding: bytes, as: UTF8.self)
}

private func callerHome(realUID: uid_t) -> String {
    guard let entry = getpwuid(realUID), let directory = entry.pointee.pw_dir else { return "/var/empty" }
    return String(cString: directory)
}

private func callerIdentity(realUID: uid_t) -> String {
    guard let entry = getpwuid(realUID), let name = entry.pointee.pw_name else { return "invalid" }
    return String(cString: name)
}

private func invokingUID() -> uid_t {
    let current = getuid()
    guard geteuid() == 0, let raw = ProcessInfo.processInfo.environment["SUDO_UID"],
          !raw.isEmpty, raw.allSatisfy({ $0.isNumber }), let value = UInt32(raw), value != 0,
          getpwuid(value) != nil else { return current }
    return value
}

private func fail(_ reason: String, code: Int32 = 64) -> Never {
    FileHandle.standardError.write(Data("aid-admin: rejected: \(reason)\n".utf8))
    exit(code)
}

let arguments = Array(CommandLine.arguments.dropFirst())
guard let command = arguments.first else { fail("missing_command") }
let real = invokingUID()
let context = RuntimeContext(realUID: real, effectiveUID: geteuid(),
                             callerHome: callerHome(realUID: real),
                             callerIdentity: callerIdentity(realUID: real),
                             currentExecutablePath: executablePath())
let broker = AidAdminBroker(context: context, expectedPolicyHash: applyPolicySHA256)

switch command {
case "doctor-root":
    guard arguments.count == 1 || arguments == ["doctor-root", "--json"] else {
        fail("doctor_root_arguments")
    }
    let report = broker.doctorRoot()
    if arguments.count == 2 {
        do { print(try encodeDoctorJSON(report), terminator: "") }
        catch { fail("doctor_json_encoding", code: 70) }
    } else {
        print("aid-admin doctor-root: \(report.verdict)")
        print("read_only=true")
        print("system_mutations_performed=false")
        if !report.problems.isEmpty { print("problems=\(report.problems.joined(separator: ","))") }
    }
    exit(report.problems.isEmpty ? 0 : 1)
case "apply-system":
    guard arguments.count == 2 else { fail("apply_system_requires_exactly_one_commit") }
    do { exit(try broker.applySystem(commit: arguments[1])) }
    catch { fail(String(describing: error), code: 65) }
default:
    fail("unknown_command")
}
