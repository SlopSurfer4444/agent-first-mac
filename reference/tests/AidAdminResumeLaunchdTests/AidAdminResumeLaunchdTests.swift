import AidAdminCore
import Darwin
import Foundation

private let bootLabel = "org.nixos.activate-system"
private let target = "/nix/store/00000000000000000000000000000000-darwin-system-target"
private let previous = "/nix/store/11111111111111111111111111111111-darwin-system-previous"

private func expect(_ condition: @autoclosure () throws -> Bool, _ reason: String) throws {
    if try !condition() { throw BrokerFailure.rejected(reason) }
}

private final class FixtureRunner: CommandRunning {
    struct Job {
        let path: String
        let program: String
        let args: [String]
        var state = "waiting"
        var pid: Int? = nil
        var loaded = true
        var runs: Int? = 1
        var variables: [String: String] = [:]
    }
    var jobs: [String: Job] = [:]
    var disabled = Set<String>()
    var unavailableDomains = Set<String>()
    var unknownMissing = false
    var commands: [[String]] = []
    var bootstrapObserver: (() throws -> Void)?

    func run(executable: String, arguments: [String], environment: [String: String]) throws -> CommandResult {
        commands.append(arguments)
        if arguments[0] == "print-disabled" {
            let entries = disabled.sorted().map { "\t\"\($0)\" => true" }.joined(separator: "\n")
            return CommandResult(status: 0, output: "disabled services = {\n" + entries + "\n}\n")
        }
        if arguments[0] == "bootstrap" {
            try bootstrapObserver?()
            guard let key = jobs.keys.first(where: { jobs[$0]!.path == arguments[2] }) else {
                throw BrokerFailure.rejected("fixture_unexpected_bootstrap")
            }
            jobs[key]!.loaded = true
            return CommandResult(status: 0, output: "")
        }
        try expect(arguments[0] == "print", "fixture_unexpected_command")
        let key = arguments[1]
        if key == "system" || key == "gui/\(getuid())" {
            if unavailableDomains.contains(key) { return CommandResult(status: 5, output: "Could not find domain\n") }
            return CommandResult(status: 0, output: key + " = {\n}\n")
        }
        if let job = jobs[key], job.loaded {
            let args = job.args.map { "\t\t" + $0 }.joined(separator: "\n")
            let pid = job.pid.map { "\tpid = \($0)\n" } ?? ""
            let runs = job.runs.map { "\truns = \($0)\n" } ?? ""
            let variables = job.variables.sorted { $0.key < $1.key }.map { "\t\t\($0.key) => \($0.value)" }.joined(separator: "\n")
            return CommandResult(status: 0, output: key + " = {\n\tpath = " + job.path +
                "\n\tprogram = " + job.program + "\n\targuments = {\n" + args +
                "\n\t}\n\tenvironment = {\n" + variables + "\n\t}\n\tstate = " + job.state + "\n" + pid + runs + "}\n")
        }
        if unknownMissing { return CommandResult(status: 5, output: "Operation not permitted\n") }
        let label = key.split(separator: "/").last!
        let domain = key.hasPrefix("system/") ? "system" : "user gui: \(getuid())"
        return CommandResult(status: 113, output: "Bad request.\nCould not find service \"\(label)\" in domain for \(domain)\n")
    }
}

private final class Fixture {
    let root = URL(fileURLWithPath: "/private/tmp/resume-launchd-fixture-" + UUID().uuidString)
    let runner = FixtureRunner()
    var callbacks = 0
    var context: RuntimeContext {
        RuntimeContext(rootPrefix: root.path, trustedUID: getuid(), realUID: getuid(), effectiveUID: 0,
                       callerHome: path("/home/fixture"), callerIdentity: "fixture", currentExecutablePath: "/fixture")
    }
    var verifier: ResumeLaunchdVerifier { .init(context: context, runner: runner, environment: ["PATH": "/usr/bin:/bin"]) }
    func path(_ logical: String) -> String { root.path + logical }
    func directory(_ logical: String) throws {
        try FileManager.default.createDirectory(atPath: path(logical), withIntermediateDirectories: true,
                                               attributes: [.posixPermissions: NSNumber(value: 0o755)])
    }
    func write(_ logical: String, _ bytes: Data, mode: Int = 0o444) throws {
        let destination = path(logical)
        let parent = URL(fileURLWithPath: destination).deletingLastPathComponent().path
        _ = chmod(parent, 0o755)
        _ = chmod(destination, 0o644)
        try bytes.write(to: URL(fileURLWithPath: destination))
        _ = chmod(destination, mode_t(mode))
        if parent.hasPrefix(path("/nix/store/")) { _ = chmod(parent, 0o555) }
    }
    @discardableResult
    func add(_ label: String, user: Bool = false, closure: String = target, install: Bool = true,
             extra: [String: Any] = [:]) throws -> String {
        let args = ["/bin/sh", "-c", "fixture-" + label]
        var plist: [String: Any] = ["Label": label, "ProgramArguments": args, "RunAtLoad": true]
        for (key, value) in extra { plist[key] = value }
        let bytes = try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
        let suffix = user ? "user/Library/LaunchAgents" : "Library/LaunchDaemons"
        try write(closure + "/" + suffix + "/" + label + ".plist", bytes)
        let installed = (user ? "/home/fixture/Library/LaunchAgents/" : "/Library/LaunchDaemons/") + label + ".plist"
        let domain = user ? "gui/\(getuid())" : "system"
        if install {
            try write(installed, bytes, mode: 0o644)
            runner.jobs[domain + "/" + label] = .init(path: path(installed), program: "/bin/sh", args: args)
            runner.jobs[domain + "/" + label]!.variables = extra["EnvironmentVariables"] as? [String: String] ?? [:]
        }
        return domain + "/" + label
    }
    init() throws {
        for directory in ["/bin", "/Library/LaunchDaemons", "/home/fixture/Library/LaunchAgents"] { try self.directory(directory) }
        try write("/bin/launchctl", Data("fixture-executable\n".utf8), mode: 0o755)
        for closure in [target, previous] {
            for suffix in ["Library/LaunchAgents", "Library/LaunchDaemons", "user/Library/LaunchAgents"] {
                try directory(closure + "/" + suffix)
            }
            try add(bootLabel, closure: closure)
            for suffix in ["Library/LaunchAgents", "Library/LaunchDaemons", "user/Library/LaunchAgents", "user/Library", "user", "Library", ""] {
                _ = chmod(path(closure + (suffix.isEmpty ? "" : "/" + suffix)), 0o555)
            }
        }
        runner.jobs["system/" + bootLabel]!.state = "not running"
    }
    deinit {
        if let enumerator = FileManager.default.enumerator(atPath: root.path) {
            for case let relative as String in enumerator {
                let item = root.appendingPathComponent(relative).path
                var info = stat()
                if lstat(item, &info) == 0 && info.st_mode & S_IFMT == S_IFDIR { _ = chmod(item, 0o755) }
            }
        }
        try? FileManager.default.removeItem(at: root)
    }
    func converge() throws {
        try verifier.converge(target: target, previous: previous, beforeBootstrap: { self.callbacks += 1 })
    }
    func expectDenied(_ body: () throws -> Void) throws {
        do { try body() } catch { return }
        throw BrokerFailure.rejected("fixture_expected_refusal")
    }
}

@main
struct TestMain {
    static func main() throws {
        try expect(getuid() != 0 && geteuid() != 0, "nonroot_fixtures_only")
        var count = 0
        func test(_ name: String, _ body: () throws -> Void) throws {
            try body(); count += 1; print("PASS " + name)
        }
        try test("loaded-waiting-and-not-running-are-not-missing") {
            let f = try Fixture(); try f.add("example.system"); try f.add("example.user", user: true, extra: ["ThrottleInterval": 15])
            try f.verifier.validateInventory(target: target, previous: previous)
            try f.converge()
            try expect(f.callbacks == 0 && !f.runner.commands.contains(where: { $0[0] == "bootstrap" }), "unexpected_bootstrap")
        }
        try test("positive-absent-fixed-bootstrap-after-durable-callback") {
            let f = try Fixture(); let key = try f.add("example.user", user: true)
            f.runner.jobs[key]!.loaded = false
            f.runner.bootstrapObserver = { try expect(f.callbacks == 1, "bootstrap_precedes_journal") }
            try f.converge()
            try expect(f.callbacks == 1 && f.runner.jobs[key]!.loaded, "missing_bootstrap")
            let mutations = f.runner.commands.filter { $0[0] == "bootstrap" }
            try expect(mutations == [["bootstrap", "gui/\(getuid())", f.path("/home/fixture/Library/LaunchAgents/example.user.plist")]], "bootstrap_scope")
        }
        try test("callback-denial-prevents-mutation") {
            let f = try Fixture(); let key = try f.add("example.system"); f.runner.jobs[key]!.loaded = false
            try f.expectDenied { try f.verifier.converge(target: target, previous: previous, beforeBootstrap: { throw BrokerFailure.rejected("durability_failure") }) }
            try expect(!f.runner.commands.contains(where: { $0[0] == "bootstrap" }), "callback_bypassed")
        }
        try test("callback-drift-rechecked-before-load") {
            let f = try Fixture(); let key = try f.add("example.system"); f.runner.jobs[key]!.loaded = false
            try f.expectDenied {
                try f.verifier.converge(target: target, previous: previous, beforeBootstrap: {
                    try f.write("/Library/LaunchDaemons/example.system.plist", Data("foreign\n".utf8), mode: 0o644)
                })
            }
            try expect(!f.runner.commands.contains(where: { $0[0] == "bootstrap" }), "drift_bootstrapped")
        }
        for fault in ["foreign-loaded", "permission-unknown", "missing-domain", "disabled", "boot-busy", "boot-pid", "boot-absent", "boot-queued", "boot-never-ran", "boot-runs-unknown", "limited-session", "unknown-key", "mutable-executable"] {
            try test("deny-" + fault) {
                let f = try Fixture()
                let extra: [String: Any] = fault == "limited-session" ? ["LimitLoadToSessionType": "Aqua"] : fault == "unknown-key" ? ["ArbitraryFlag": true] : [:]
                let key = try f.add("example.user", user: true, extra: extra)
                if fault == "foreign-loaded" {
                    f.runner.jobs[key] = .init(path: "/foreign.plist", program: "/bin/sh", args: ["foreign"])
                }
                if fault == "permission-unknown" { f.runner.jobs[key]!.loaded = false; f.runner.unknownMissing = true }
                if fault == "missing-domain" { f.runner.jobs[key]!.loaded = false; f.runner.unavailableDomains.insert("gui/\(getuid())") }
                if fault == "disabled" { f.runner.disabled.insert("example.user") }
                if fault == "boot-busy" { f.runner.jobs["system/" + bootLabel]!.state = "running" }
                if fault == "boot-pid" { f.runner.jobs["system/" + bootLabel]!.pid = 1234 }
                if fault == "boot-absent" { f.runner.jobs["system/" + bootLabel]!.loaded = false }
                if fault == "boot-queued" { f.runner.jobs["system/" + bootLabel]!.state = "waiting" }
                if fault == "boot-never-ran" { f.runner.jobs["system/" + bootLabel]!.runs = 0 }
                if fault == "boot-runs-unknown" { f.runner.jobs["system/" + bootLabel]!.runs = nil }
                if fault == "mutable-executable" { _ = chmod(f.path("/bin/launchctl"), 0o777) }
                try f.expectDenied { try f.converge() }
                try expect(f.callbacks == 0 && !f.runner.commands.contains(where: { $0[0] == "bootstrap" }), "unsafe_mutation")
            }
        }
        try test("previous-only-plist-or-job-retained-denies") {
            let f = try Fixture(); let key = try f.add("example.old", closure: previous)
            try f.expectDenied { try f.converge() }
            try FileManager.default.removeItem(atPath: f.path("/Library/LaunchDaemons/example.old.plist"))
            try f.expectDenied { try f.converge() }
            f.runner.jobs[key]!.loaded = false
            try f.converge()
            try expect(f.callbacks == 0, "removed_job_bootstrapped")
        }
        try test("nonempty-global-agents-refused") {
            let f = try Fixture()
            try f.write(target + "/Library/LaunchAgents/foreign.plist", Data("fixture".utf8))
            try f.expectDenied { try f.verifier.validateInventory(target: target, previous: previous) }
        }
        try test("preactivation-union-admits-owned-old-and-copy-before-load") {
            let f = try Fixture()
            try f.add("example.old", closure: previous)
            let key = try f.add("example.new"); f.runner.jobs[key]!.loaded = false
            try f.verifier.validateInventory(target: target, previous: previous)
            try expect(!f.runner.commands.contains { $0[0] == "bootstrap" }, "preflight_mutated")
        }
        for fault in ["plist", "loaded", "environment"] {
            try test("preactivation-refuses-foreign-" + fault) {
                let f = try Fixture(); let key = try f.add("example.old", closure: previous,
                                                         extra: ["EnvironmentVariables": ["PATH": "/usr/bin:/bin"]])
                if fault == "plist" { try f.write("/Library/LaunchDaemons/example.old.plist", Data("foreign".utf8), mode: 0o644) }
                if fault == "loaded" { f.runner.jobs[key] = .init(path: "/foreign", program: "/bin/sh", args: ["foreign"]) }
                if fault == "environment" { f.runner.jobs[key]!.variables = ["PATH": "/foreign/bin"] }
                try f.expectDenied { try f.verifier.validateInventory(target: target, previous: previous) }
            }
        }
        try test("declared-environment-matches-and-drift-denies") {
            let f = try Fixture(); let key = try f.add("example.env", extra: ["EnvironmentVariables": ["PATH": "/usr/bin:/bin"]])
            f.runner.jobs[key]!.variables["XPC_SERVICE_NAME"] = "example.env"
            try f.converge()
            f.runner.jobs[key]!.variables["PATH"] = "/foreign/bin"
            try f.expectDenied { try f.converge() }
        }
        try test("same-visible-identity-policy-drift-target-installed-denied") {
            let f = try Fixture()
            try f.add("example.policy", closure: previous, extra: ["ThrottleInterval": 10])
            try f.add("example.policy", extra: ["ThrottleInterval": 15])
            try f.expectDenied { try f.verifier.validateInventory(target: target, previous: previous) }
            try f.expectDenied { try f.converge() }
        }
        try test("old-installed-policy-transition-refused-without-mutation") {
            let f = try Fixture()
            try f.add("example.policy", extra: ["ThrottleInterval": 15])
            try f.add("example.policy", closure: previous, extra: ["ThrottleInterval": 10])
            let verifier = f.verifier
            try f.expectDenied { try verifier.validateInventory(target: target, previous: previous) }
            try expect(!f.runner.commands.contains { $0[0] == "bootstrap" }, "ambiguous_policy_mutated")
        }
        try test("visibly-changed-environment-transition-remains-admissible") {
            let f = try Fixture()
            try f.add("example.environment", closure: previous, extra: ["EnvironmentVariables": ["PATH": "/old/bin"]])
            try f.add("example.environment", extra: ["EnvironmentVariables": ["PATH": "/new/bin"]])
            try f.verifier.validateInventory(target: target, previous: previous)
            try f.converge()
            try expect(f.callbacks == 0, "visible_transition_bootstrapped")
        }
        try test("post-bootstrap-policy-ambiguity-remains-refused") {
            let f = try Fixture()
            try f.add("example.policy", closure: previous, extra: ["ThrottleInterval": 10])
            let key = try f.add("example.policy", extra: ["ThrottleInterval": 15])
            f.runner.jobs[key]!.loaded = false
            try f.verifier.validateInventory(target: target, previous: previous)
            try f.expectDenied { try f.converge() }
            try expect(f.callbacks == 1, "absent_policy_not_bootstrapped")
        }
        try test("callback-old-policy-appearance-refused-before-bootstrap") {
            let f = try Fixture()
            try f.add("example.policy", closure: previous, extra: ["ThrottleInterval": 10])
            let key = try f.add("example.policy", extra: ["ThrottleInterval": 15])
            f.runner.jobs[key]!.loaded = false
            try f.expectDenied {
                try f.verifier.converge(target: target, previous: previous, beforeBootstrap: {
                    f.callbacks += 1
                    f.runner.jobs[key]!.loaded = true
                })
            }
            try expect(f.callbacks == 1 && !f.runner.commands.contains { $0[0] == "bootstrap" },
                       "callback_policy_ambiguity_bootstrapped")
        }
        print("PASS \(count) resume launchd tests; mocked launchctl, no native probes")
    }
}
