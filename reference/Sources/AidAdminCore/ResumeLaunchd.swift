import CoreFoundation
import Darwin
import Foundation

/// Narrow repair for the pinned upstream copy-before-load gap. Inputs are the
/// broker's already validated, sealed closures, never CLI-selected plist paths.
/// It cannot unload, enable, replace, or repair a foreign loaded definition.
public final class ResumeLaunchdVerifier {
    private let context: RuntimeContext
    private let runner: CommandRunning
    private let environment: [String: String]
    private let bootLabel = "org.nixos.activate-system"
    private let maximumEntries = 64
    private let maximumFileBytes = 262144

    private struct Job: Equatable {
        let label: String
        let domain: String
        let installed: String
        let bytes: Data
        let program: String
        let arguments: [String]
        let variables: [String: String]
        var key: String { domain + "/" + label }
    }
    private struct Loaded {
        let path: String
        let program: String
        let arguments: [String]
        let state: String
        let hasPID: Bool
        let runs: Int?
        let variables: [String: String]
    }

    public init(context: RuntimeContext, runner: CommandRunning, environment: [String: String]) {
        self.context = context; self.runner = runner; self.environment = environment
    }

    public func validateInventory(target: String, previous: String) throws {
        let wanted = try inventory(target)
        let old = try inventory(previous)
        try validateBootHelper(wanted: wanted, previous: old)
        // Admission precedes upstream activation, which itself can overwrite
        // installed plists and unload jobs. Never delegate foreign cleanup.
        let groups = Dictionary(grouping: wanted + old, by: \.key)
        for key in groups.keys.sorted() {
            let candidates = groups[key]!
            let job = candidates[0]
            let owner = job.domain == "system" ? context.trustedUID : context.realUID
            try parentChain(job.installed, owner: owner)
            var info = stat()
            if lstat(job.installed, &info) == 0 {
                let bytes = try read(job.installed, owner: owner, immutable: false)
                try demand(candidates.contains { $0.bytes == bytes }, "resume_launchd_prestate_foreign_plist")
            } else {
                try demand(errno == ENOENT, "resume_launchd_prestate_plist_unknown")
            }
            try requireEnabledDomain(job.domain, label: job.label)
            if let loaded = try observe(job) {
                try demand(candidates.contains { identityMatches(loaded, $0) }, "resume_launchd_prestate_foreign_job")
                if let desired = wanted.first(where: { $0.key == key }),
                   identityMatches(loaded, desired) {
                    try refuseAmbiguousPolicy(loaded, desired, previous: old)
                }
            }
        }
    }

    public func converge(target: String, previous: String, beforeBootstrap: () throws -> Void) throws {
        let wanted = try inventory(target)
        let old = try inventory(previous)
        try validateBootHelper(wanted: wanted, previous: old)
        // Refuse stale/foreign effects before doing any corrective load.
        for job in old where !wanted.contains(where: { $0.key == job.key }) {
            try requireAbsentFile(job.installed)
            try requireEnabledDomain(job.domain, label: job.label)
            try demand(try observe(job) == nil, "resume_launchd_removed_job_loaded")
        }
        var missing: [Job] = []
        for job in wanted {
            try installedMatches(job)
            try requireEnabledDomain(job.domain, label: job.label)
            if let loaded = try observe(job) {
                try matchesDesired(loaded, job, previous: old)
            } else {
                try demand(job.label != bootLabel, "resume_launchd_boot_helper_absent")
                missing.append(job)
            }
        }
        for job in missing {
                // Durable callback BEFORE every mutation; reread identities after
                // the callback so its own I/O cannot open a stale-input window.
                try beforeBootstrap()
                try demand(try inventory(target) == wanted && inventory(previous) == old,
                           "resume_launchd_inventory_drift")
                try installedMatches(job)
                try requireEnabledDomain(job.domain, label: job.label)
                if let appeared = try observe(job) {
                    try matchesDesired(appeared, job, previous: old)
                    continue
                }
                let result = try command(["bootstrap", job.domain, job.installed])
                try demand(result.status == 0, "resume_launchd_bootstrap_unknown")
                try installedMatches(job)
                guard let loaded = try observe(job) else {
                    throw BrokerFailure.rejected("resume_launchd_bootstrap_not_loaded")
                }
                try matchesDesired(loaded, job, previous: old)
                try requireEnabledDomain(job.domain, label: job.label)
        }
        try demand(try inventory(target) == wanted && inventory(previous) == old,
                   "resume_launchd_inventory_drift")
        for job in wanted {
            try installedMatches(job)
            try requireEnabledDomain(job.domain, label: job.label)
            guard let loaded = try observe(job) else {
                throw BrokerFailure.rejected("resume_launchd_final_missing")
            }
            try matchesDesired(loaded, job, previous: old)
        }
        for job in old where !wanted.contains(where: { $0.key == job.key }) {
            try requireAbsentFile(job.installed)
            try demand(try observe(job) == nil, "resume_launchd_removed_job_loaded")
        }
        try validateBootHelper(wanted: wanted, previous: old)
    }

    private func demand(_ value: @autoclosure () throws -> Bool, _ reason: String) throws {
        if try !value() { throw BrokerFailure.rejected(reason) }
    }

    private func physical(_ path: String) -> String {
        context.rootPrefix == "/" ? path : context.rootPrefix + path
    }

    private func same(_ lhs: stat, _ rhs: stat) -> Bool {
        lhs.st_dev == rhs.st_dev && lhs.st_ino == rhs.st_ino && lhs.st_mode == rhs.st_mode &&
            lhs.st_uid == rhs.st_uid && lhs.st_gid == rhs.st_gid && lhs.st_nlink == rhs.st_nlink &&
            lhs.st_size == rhs.st_size && lhs.st_mtimespec.tv_sec == rhs.st_mtimespec.tv_sec &&
            lhs.st_mtimespec.tv_nsec == rhs.st_mtimespec.tv_nsec &&
            lhs.st_ctimespec.tv_sec == rhs.st_ctimespec.tv_sec && lhs.st_ctimespec.tv_nsec == rhs.st_ctimespec.tv_nsec
    }

    private func read(_ path: String, owner: uid_t, immutable: Bool, executable: Bool = false) throws -> Data {
        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        try demand(fd >= 0, "resume_launchd_file_open")
        defer { close(fd) }
        var before = stat(), after = stat(), named = stat()
        let cap = executable ? 16 * 1048576 : maximumFileBytes
        try demand(fstat(fd, &before) == 0 && before.st_mode & S_IFMT == S_IFREG &&
                   before.st_uid == owner && before.st_mode & (immutable ? 0o222 : 0o022) == 0 &&
                   before.st_mode & 0o7000 == 0 &&
                   (!executable || before.st_mode & 0o111 != 0) &&
                   before.st_size > 0 && before.st_size <= cap &&
                   (immutable || before.st_nlink == 1), "resume_launchd_file_identity")
        var data = Data(), buffer = [UInt8](repeating: 0, count: 8192)
        while data.count <= cap {
            let count = Darwin.read(fd, &buffer, min(buffer.count, cap + 1 - data.count))
            if count == 0 { break }
            if count < 0 && errno == EINTR { continue }
            try demand(count > 0, "resume_launchd_file_read")
            data.append(contentsOf: buffer.prefix(count))
        }
        try demand(data.count == before.st_size && fstat(fd, &after) == 0 && lstat(path, &named) == 0 &&
                   same(before, after) && same(before, named), "resume_launchd_file_drift")
        return data
    }

    private func canonicalStore(_ path: String, directory: Bool) throws -> String {
        guard let pointer = realpath(path, nil) else { throw BrokerFailure.rejected("resume_launchd_store_resolution") }
        defer { free(pointer) }
        let resolved = String(cString: pointer)
        let store = physical("/nix/store")
        try demand(resolved.hasPrefix(store + "/"), "resume_launchd_store_escape")
        var cursor = directory ? resolved : URL(fileURLWithPath: resolved).deletingLastPathComponent().path
        while cursor != store {
            var info = stat()
            try demand(cursor.hasPrefix(store + "/") && lstat(cursor, &info) == 0 &&
                       info.st_mode & S_IFMT == S_IFDIR && info.st_uid == context.trustedUID &&
                       info.st_mode & 0o222 == 0, "resume_launchd_store_parent")
            cursor = URL(fileURLWithPath: cursor).deletingLastPathComponent().path
        }
        return resolved
    }

    private func inventory(_ target: String) throws -> [Job] {
        try demand(target.range(of: "^/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-darwin-system-[A-Za-z0-9._+-]{1,96}$",
                                options: .regularExpression) != nil, "resume_launchd_closure_path")
        _ = try canonicalStore(physical(target), directory: true)
        try demand(context.realUID > 0 && context.callerHome.hasPrefix("/"), "resume_launchd_owner")
        var result: [Job] = []
        for suffix in ["Library/LaunchAgents", "Library/LaunchDaemons", "user/Library/LaunchAgents"] {
            let directory = try canonicalStore(physical(target + "/" + suffix), directory: true)
            let names = try FileManager.default.contentsOfDirectory(atPath: directory).sorted()
            try demand(names.count <= maximumEntries && result.count + names.count <= maximumEntries,
                       "resume_launchd_inventory_size")
            if suffix == "Library/LaunchAgents" {
                try demand(names.isEmpty, "resume_launchd_global_agents_unsupported")
                continue
            }
            for name in names {
                try demand(name.range(of: "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\\.plist$", options: .regularExpression) != nil,
                           "resume_launchd_plist_name")
                let resolved = try canonicalStore(directory + "/" + name, directory: false)
                let bytes = try read(resolved, owner: context.trustedUID, immutable: true)
                let isSystem = suffix == "Library/LaunchDaemons"
                let installed = isSystem ? physical("/Library/LaunchDaemons/" + name) : context.callerHome + "/Library/LaunchAgents/" + name
                let domain = isSystem ? "system" : "gui/\(context.realUID)"
                result.append(try decode(bytes, name: name, installed: installed, domain: domain))
            }
        }
        try demand(Set(result.map(\.key)).count == result.count, "resume_launchd_duplicate_label")
        return result.sorted { $0.key < $1.key }
    }

    private func decode(_ data: Data, name: String, installed: String, domain: String) throws -> Job {
        guard let value = try PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any] else {
            throw BrokerFailure.rejected("resume_launchd_plist_structure")
        }
        let keys: Set<String> = ["Label", "Program", "ProgramArguments", "RunAtLoad", "KeepAlive", "StartInterval", "ThrottleInterval",
            "ProcessType", "StandardOutPath", "StandardErrorPath", "EnvironmentVariables", "SoftResourceLimits",
            "HardResourceLimits", "LowPriorityIO", "Disabled"]
        try demand(Set(value.keys).isSubset(of: keys), "resume_launchd_unsupported_plist_key")
        guard let label = value["Label"] as? String, name == label + ".plist",
              let args = value["ProgramArguments"] as? [String], !args.isEmpty, args.count <= 32,
              args.allSatisfy({ !$0.contains("\n") && !$0.contains("\r") && !$0.utf8.contains(0) &&
                  $0 == $0.trimmingCharacters(in: .whitespaces) && !$0.isEmpty &&
                  $0 != "}" && !$0.hasSuffix(" = {") && $0.utf8.count <= 8192 }) else {
            throw BrokerFailure.rejected("resume_launchd_program_contract")
        }
        for key in ["RunAtLoad", "KeepAlive", "LowPriorityIO", "Disabled"] where value[key] != nil {
            guard let boolean = value[key] as? NSNumber, CFGetTypeID(boolean) == CFBooleanGetTypeID() else {
                throw BrokerFailure.rejected("resume_launchd_boolean_type")
            }
        }
        try demand((value["Disabled"] as? Bool) != true, "resume_launchd_disabled_intent")
        for key in ["StandardOutPath", "StandardErrorPath"] where value[key] != nil {
            guard let path = value[key] as? String, path.hasPrefix("/"),
                  !path.contains("\n"), !path.contains("\r"), !path.utf8.contains(0) else {
                throw BrokerFailure.rejected("resume_launchd_plist_path_type")
            }
        }
        if let type = value["ProcessType"] {
            try demand((type as? String).map { ["Background", "Standard", "Interactive", "Adaptive"].contains($0) } == true,
                       "resume_launchd_process_type")
        }
        for key in ["StartInterval", "ThrottleInterval"] where value[key] != nil {
            try demand(isInteger(value[key]!, minimum: 1), "resume_launchd_interval_type")
        }
        if let environment = value["EnvironmentVariables"] {
            guard let variables = environment as? [String: String], variables.count <= 64,
                  variables.allSatisfy({ $0.key.range(of: "^[A-Za-z_][A-Za-z0-9_]*$", options: .regularExpression) != nil &&
                      !$0.value.utf8.contains(0) && !$0.value.contains("\n") && !$0.value.contains("\r") &&
                      $0.value == $0.value.trimmingCharacters(in: .whitespaces) && $0.value.utf8.count <= 8192 }) else {
                throw BrokerFailure.rejected("resume_launchd_environment_type")
            }
        }
        for key in ["SoftResourceLimits", "HardResourceLimits"] where value[key] != nil {
            let resourceKeys: Set<String> = ["Core", "CPU", "Data", "FileSize", "MemoryLock", "NumberOfFiles",
                                            "NumberOfProcesses", "ResidentSetSize", "Stack"]
            guard let limits = value[key] as? [String: Any], Set(limits.keys).isSubset(of: resourceKeys),
                  limits.values.allSatisfy({ isInteger($0, minimum: 0) }) else {
                throw BrokerFailure.rejected("resume_launchd_resource_limit_type")
            }
        }
        let program = (value["Program"] as? String) ?? args[0]
        try demand(value["Program"] == nil || value["Program"] is String, "resume_launchd_program_type")
        try demand(program.hasPrefix("/") && !program.contains("\n") && !program.contains("\r") &&
                   !program.utf8.contains(0), "resume_launchd_program_path")
        return Job(label: label, domain: domain, installed: installed, bytes: data, program: program, arguments: args,
                   variables: value["EnvironmentVariables"] as? [String: String] ?? [:])
    }

    private func isInteger(_ value: Any, minimum: Int) -> Bool {
        guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(),
              !["f", "d"].contains(String(cString: number.objCType)) else { return false }
        return number.int64Value >= minimum && number.int64Value <= Int64(Int32.max)
    }

    private func parentChain(_ path: String, owner: uid_t) throws {
        let anchor = owner == context.trustedUID && path.hasPrefix(physical("/Library/") )
            ? physical("/Library") : context.callerHome
        var cursor = URL(fileURLWithPath: path).deletingLastPathComponent().path
        while true {
            var info = stat()
            try demand((cursor == anchor || cursor.hasPrefix(anchor + "/")) && lstat(cursor, &info) == 0 &&
                       info.st_mode & S_IFMT == S_IFDIR && info.st_uid == owner && info.st_mode & 0o022 == 0,
                       "resume_launchd_installed_parent")
            if cursor == anchor { break }
            cursor = URL(fileURLWithPath: cursor).deletingLastPathComponent().path
        }
    }

    private func installedMatches(_ job: Job) throws {
        let owner = job.domain == "system" ? context.trustedUID : context.realUID
        try parentChain(job.installed, owner: owner)
        try demand(try read(job.installed, owner: owner, immutable: false) == job.bytes,
                   "resume_launchd_installed_plist_drift")
    }

    private func requireAbsentFile(_ path: String) throws {
        let owner = path.hasPrefix(physical("/Library/")) ? context.trustedUID : context.realUID
        try parentChain(path, owner: owner)
        var info = stat()
        try demand(lstat(path, &info) != 0 && errno == ENOENT, "resume_launchd_removed_plist_present")
    }

    private func command(_ arguments: [String]) throws -> CommandResult {
        let executable = physical("/bin/launchctl")
        var parent = stat()
        try demand(lstat(physical("/bin"), &parent) == 0 && parent.st_mode & S_IFMT == S_IFDIR &&
                   parent.st_uid == context.trustedUID && parent.st_mode & 0o022 == 0,
                   "resume_launchctl_parent_identity")
        let before = try read(executable, owner: context.trustedUID, immutable: false, executable: true)
        let result = try runner.run(executable: executable, arguments: arguments, environment: environment)
        try demand(try read(executable, owner: context.trustedUID, immutable: false, executable: true) == before,
                   "resume_launchctl_executable_drift")
        try demand(result.output.utf8.count <= maximumFileBytes, "resume_launchctl_output_limit")
        return result
    }

    private func requireDomain(_ domain: String) throws {
        let result = try command(["print", domain])
        // Domain listings can exceed the caller's retained output budget. An
        // exact domain header plus settled exit zero is enough for existence;
        // no domain-wide properties are inferred from this prefix.
        try demand(result.status == 0 && result.output.hasPrefix(domain + " = {\n"),
                   "resume_launchd_domain_unavailable")
    }

    private func requireEnabledDomain(_ domain: String, label: String) throws {
        try requireDomain(domain)
        let result = try command(["print-disabled", domain])
        let lines = result.output.split(separator: "\n", omittingEmptySubsequences: true).map { $0.trimmingCharacters(in: .whitespaces) }
        try demand(result.status == 0 && lines.first == "disabled services = {" && lines.last == "}",
                   "resume_launchd_disabled_observation_unknown")
        var seen = Set<String>()
        let expression = try NSRegularExpression(pattern: "^\"([A-Za-z0-9][A-Za-z0-9._-]{0,127})\" => (true|false)$")
        for line in lines.dropFirst().dropLast() {
            guard let match = expression.firstMatch(in: line, range: NSRange(line.startIndex..., in: line)),
                  let nameRange = Range(match.range(at: 1), in: line), let stateRange = Range(match.range(at: 2), in: line) else {
                throw BrokerFailure.rejected("resume_launchd_disabled_observation_unknown")
            }
            let name = String(line[nameRange])
            try demand(seen.insert(name).inserted, "resume_launchd_disabled_duplicate")
            if name == label { try demand(line[stateRange] == "false", "resume_launchd_runtime_disabled") }
        }
    }

    private func observe(_ job: Job) throws -> Loaded? {
        let result = try command(["print", job.key])
        if result.status != 0 {
            let domainText = job.domain == "system" ? "system" : "user gui: \(context.realUID)"
            let error = "Could not find service \"\(job.label)\" in domain for \(domainText)\n"
            try demand(result.status == 113 && (result.output == error || result.output == "Bad request.\n" + error),
                       "resume_launchd_job_observation_unknown")
            try requireDomain(job.domain)
            return nil
        }
        let lines = result.output.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        try demand(lines.first == job.key + " = {", "resume_launchd_loaded_header")
        var depth = 1, values: [String: String] = [:], args: [String] = []
        var inArguments = false, argumentsSeen = false
        var inEnvironment = false, environmentSeen = false, variables: [String: String] = [:]
        for raw in lines.dropFirst() {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.isEmpty { continue }
            try demand(depth > 0, "resume_launchd_loaded_trailing")
            if line == "}" {
                if inArguments && depth == 2 { inArguments = false }
                if inEnvironment && depth == 2 { inEnvironment = false }
                depth -= 1; continue
            }
            if inArguments {
                try demand(depth == 2 && !line.hasSuffix(" = {"), "resume_launchd_arguments_format")
                args.append(line); continue
            }
            if inEnvironment {
                guard depth == 2, let separator = line.range(of: " => ") else {
                    throw BrokerFailure.rejected("resume_launchd_environment_format")
                }
                let key = String(line[..<separator.lowerBound])
                try demand(variables[key] == nil && key.range(of: "^[A-Za-z_][A-Za-z0-9_]*$", options: .regularExpression) != nil,
                           "resume_launchd_environment_duplicate")
                variables[key] = String(line[separator.upperBound...])
                continue
            }
            if line.hasSuffix(" = {") {
                if depth == 1 && line == "arguments = {" {
                    try demand(!argumentsSeen, "resume_launchd_arguments_duplicate")
                    argumentsSeen = true; inArguments = true
                }
                if depth == 1 && line == "environment = {" {
                    try demand(!environmentSeen, "resume_launchd_environment_duplicate")
                    environmentSeen = true; inEnvironment = true
                }
                depth += 1; continue
            }
            if depth == 1, let separator = line.range(of: " = ") {
                let key = String(line[..<separator.lowerBound])
                if ["path", "program", "state", "pid", "runs"].contains(key) {
                    try demand(values[key] == nil, "resume_launchd_loaded_duplicate")
                    values[key] = String(line[separator.upperBound...])
                }
            }
        }
        guard depth == 0, argumentsSeen, let path = values["path"], let program = values["program"],
              let state = values["state"], ["running", "not running", "waiting"].contains(state) else {
            throw BrokerFailure.rejected("resume_launchd_loaded_structure")
        }
        var runs: Int? = nil
        if let value = values["runs"] {
            try demand(value.range(of: "^[0-9]{1,10}$", options: .regularExpression) != nil &&
                       Int(value).map { $0 <= Int32.max } == true, "resume_launchd_runs_format")
            runs = Int(value)
        }
        return Loaded(path: path, program: program, arguments: args, state: state, hasPID: values["pid"] != nil,
                      runs: runs, variables: variables)
    }

    private func identityMatches(_ loaded: Loaded, _ job: Job) -> Bool {
        return loaded.path == job.installed && loaded.program == job.program && loaded.arguments == job.arguments &&
            job.variables.allSatisfy { loaded.variables[$0.key] == $0.value }
    }

    private func refuseAmbiguousPolicy(_ loaded: Loaded, _ job: Job, previous: [Job]) throws {
        // Applied on every desired loaded observation, including post-bootstrap:
        // command success cannot attest non-observable scheduling/resource policy.
        if let prior = previous.first(where: { $0.key == job.key }), prior.bytes != job.bytes,
           identityMatches(loaded, job) && identityMatches(loaded, prior) {
            throw BrokerFailure.rejected("resume_launchd_loaded_policy_ambiguous")
        }
    }

    private func matchesDesired(_ loaded: Loaded, _ job: Job, previous: [Job]) throws {
        try demand(identityMatches(loaded, job),
                   "resume_launchd_loaded_identity_drift")
        try refuseAmbiguousPolicy(loaded, job, previous: previous)
    }

    private func validateBootHelper(wanted: [Job], previous: [Job]) throws {
        let candidates = (wanted + previous).filter { $0.domain == "system" && $0.label == bootLabel }
        try demand(!candidates.isEmpty, "resume_launchd_boot_helper_inventory_missing")
        guard let expected = candidates.first else { return }
        try requireEnabledDomain(expected.domain, label: expected.label)
        guard let loaded = try observe(expected) else { throw BrokerFailure.rejected("resume_launchd_boot_helper_absent") }
        try demand(loaded.state == "not running" && !loaded.hasPID && (loaded.runs ?? 0) >= 1,
                   "resume_launchd_boot_helper_busy")
        let installed = try read(expected.installed, owner: context.trustedUID, immutable: false)
        try parentChain(expected.installed, owner: context.trustedUID)
        try demand(candidates.contains(where: { candidate in
            installed == candidate.bytes && identityMatches(loaded, candidate)
        }), "resume_launchd_boot_helper_identity")
    }
}
