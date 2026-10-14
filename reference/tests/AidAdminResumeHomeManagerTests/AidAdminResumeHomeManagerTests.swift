import AidAdminCore
import Darwin
import Foundation

private func check(_ value: @autoclosure () throws -> Bool, _ reason: String) throws {
    if try !value() { throw BrokerFailure.rejected("test_" + reason) }
}
private func denied(_ action: () throws -> Void) throws -> String {
    do { try action() } catch { return String(describing: error) }
    throw BrokerFailure.rejected("test_expected_denial")
}
private final class NoCommands: CommandRunning {
    var calls = 0
    func run(executable: String, arguments: [String], environment: [String: String]) throws -> CommandResult {
        calls += 1
        throw BrokerFailure.rejected("test_command_forbidden")
    }
}
private final class Fixture {
    let root: String
    let runner = NoCommands()
    let target = "/nix/store/" + String(repeating: "a", count: 32) + "-darwin-system-fixture"
    let wrapper = "/nix/store/" + String(repeating: "b", count: 32) + "-activation-fixture"
    let generation = "/nix/store/" + String(repeating: "c", count: 32) + "-home-manager-generation"
    let fonts = "/nix/store/" + String(repeating: "d", count: 32) + "-home-manager-fonts"
    let marker = "/nix/store/" + String(repeating: "f", count: 32) + "-font-marker"
    let rsync = "/nix/store/" + String(repeating: "g", count: 32) + "-rsync-3.4.4/bin/rsync"
    let home = "/Users/fixture"
    var destination: String { home + "/Library/Fonts/HomeManager" }
    var repairs = 0
    let fm = FileManager.default

    init(emptyFonts: Bool = false) throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("hm-resume-tests-" + UUID().uuidString)
        try fm.createDirectory(at: url, withIntermediateDirectories: true)
        let resolved = realpath(url.path, nil)!
        root = String(cString: resolved); free(resolved)
        try write(target + "/activate", "launchctl asuser \"$(id -u fixture)\" sudo -u fixture --set-home \"${hmDryRunArgs[@]}\" " + wrapper + "\n")
        try write(wrapper, "#!/nix/store/" + String(repeating: "h", count: 32) + "-bash/bin/bash\n\nexec " + generation + "/activate --driver-version 1 >&2\n")
        try write(marker, fonts)
        try write(generation + "/activate", activation())
        try fm.createDirectory(atPath: physical(fonts + "/share/fonts"), withIntermediateDirectories: true)
        try fm.createDirectory(atPath: physical(destination), withIntermediateDirectories: true)
        if !emptyFonts {
            try write(fonts + "/share/fonts/fixture.otf", "font-payload")
            try write(destination + "/fixture.otf", "font-payload", mode: 0o644)
        }
        try chmodStoreDirectories()
    }
    deinit {
        if let enumerator = fm.enumerator(atPath: root + "/nix/store") {
            for case let path as String in enumerator {
                var facts = stat()
                let absolute = root + "/nix/store/" + path
                if lstat(absolute, &facts) == 0 && facts.st_mode & S_IFMT == S_IFDIR { _ = chmod(absolute, 0o755) }
            }
        }
        try? fm.removeItem(atPath: root)
    }
    func physical(_ path: String) -> String { root + path }
    func verifier(physicalHome: Bool = false) -> ResumeHomeManagerVerifier {
        ResumeHomeManagerVerifier(context: RuntimeContext(rootPrefix: root, trustedUID: getuid(),
            realUID: getuid(), effectiveUID: getuid(), callerHome: physicalHome ? physical(home) : home, callerIdentity: "fixture",
            currentExecutablePath: "/fixture-broker"), runner: runner, environment: [:])
    }
    func write(_ path: String, _ text: String, mode: mode_t = 0o444) throws {
        let url = URL(fileURLWithPath: physical(path))
        try fm.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        _ = chmod(url.path, 0o644)
        try Data(text.utf8).write(to: url)
        try check(chmod(url.path, mode) == 0, "fixture_mode")
    }
    func chmodStoreDirectories() throws {
        let enumerator = fm.enumerator(atPath: root + "/nix/store")!
        for case let path as String in enumerator {
            var facts = stat(); let absolute = root + "/nix/store/" + path
            if lstat(absolute, &facts) == 0 && facts.st_mode & S_IFMT == S_IFDIR {
                try check(chmod(absolute, 0o555) == 0, "store_directory_mode")
            }
        }
    }
    func activation() -> String {
        """
        _iNote "Activating %s" "checkFilesChanged"
        _cmp \(marker) \(home)/Library/Fonts/.home-manager-fonts-version \\
          && changedFiles[Library/Fonts/.home-manager-fonts-version]=0 \\
          || changedFiles[Library/Fonts/.home-manager-fonts-version]=1
        _iNote "Activating %s" "linkGeneration"
        # the real activation is never run by these fixtures
        _iNote "Activating %s" "onFilesChange"
        if (( ${changedFiles[Library/Fonts/.home-manager-fonts-version]} == 1 )); then
          if [[ -v DRY_RUN || -v VERBOSE ]]; then
            echo "Running onChange hook for" Library/Fonts/.home-manager-fonts-version
          fi
          if [[ ! -v DRY_RUN ]]; then
            run mkdir -p \(destination)
        run \(rsync) $VERBOSE_ARG -acL --chmod=u+w --delete \\
          \(fonts)/share/fonts/ \(destination)

          fi
        fi

        _iNote "Activating %s" "setupLaunchAgents"
        """
    }
    func converge(_ verifier: ResumeHomeManagerVerifier) throws {
        try verifier.converge(target: target) { self.repairs += 1 }
    }
    func assertReadOnly() throws { try check(runner.calls == 0 && repairs == 0, "no_execution_or_repair") }
}

@main private struct Tests {
    static func main() throws {
        var count = 0
        for empty in [false, true] {
            let fixture = try Fixture(emptyFonts: empty); let verifier = fixture.verifier()
            try verifier.validateInventory(target: fixture.target); try fixture.converge(verifier)
            try fixture.assertReadOnly(); count += 1
        }
        do {
            let fixture = try Fixture(); let verifier = fixture.verifier(physicalHome: true)
            try verifier.validateInventory(target: fixture.target); try fixture.converge(verifier)
            try fixture.assertReadOnly(); count += 1
        }
        for failure in ["missing", "extra", "changed", "mode", "symlink"] {
            let fixture = try Fixture(); let verifier = fixture.verifier()
            try verifier.validateInventory(target: fixture.target)
            if failure == "missing" { try fixture.fm.removeItem(atPath: fixture.physical(fixture.destination)) }
            if failure == "extra" { try fixture.write(fixture.destination + "/owner-font.otf", "foreign-font", mode: 0o644) }
            if failure == "changed" { try fixture.write(fixture.destination + "/fixture.otf", "different-font", mode: 0o644) }
            if failure == "mode" { _ = chmod(fixture.physical(fixture.destination + "/fixture.otf"), 0o666) }
            if failure == "symlink" {
                try fixture.fm.removeItem(atPath: fixture.physical(fixture.destination + "/fixture.otf"))
                try fixture.fm.createSymbolicLink(atPath: fixture.physical(fixture.destination + "/fixture.otf"),
                    withDestinationPath: fixture.physical(fixture.fonts + "/share/fonts/fixture.otf"))
            }
            try check(try denied { try fixture.converge(verifier) } == "resume_hm_fonts_effect_unproven", failure)
            if failure == "extra" {
                try check(try String(contentsOfFile: fixture.physical(fixture.destination + "/owner-font.otf"), encoding: .utf8) == "foreign-font", "foreign_preserved")
            }
            try fixture.assertReadOnly(); count += 1
        }
        for failure in ["custom-hook", "second-hook", "wrapper-user-script", "owner-path", "mutable-script", "marker", "duplicate-wrapper"] {
            let fixture = try Fixture(); let verifier = fixture.verifier()
            switch failure {
            case "custom-hook": try fixture.write(fixture.generation + "/activate", fixture.activation().replacingOccurrences(of: "run mkdir -p", with: "run echo custom; mkdir -p"))
            case "second-hook": try fixture.write(fixture.generation + "/activate", fixture.activation() + "\nchangedFiles[custom]=1\n")
            case "wrapper-user-script": try fixture.write(fixture.wrapper, "#!/bin/sh\nexec /Users/fixture/script\n")
            case "owner-path": try fixture.write(fixture.generation + "/activate", fixture.activation().replacingOccurrences(of: fixture.destination, with: "/Users/other/Library/Fonts/HomeManager"))
            case "mutable-script": _ = chmod(fixture.physical(fixture.generation + "/activate"), 0o644)
            case "marker": try fixture.write(fixture.marker, "foreign-fonts-env")
            default: try fixture.write(fixture.target + "/activate", try String(contentsOfFile: fixture.physical(fixture.target + "/activate"), encoding: .utf8) + fixture.wrapper + "\n")
            }
            _ = try denied { try verifier.validateInventory(target: fixture.target) }
            try fixture.assertReadOnly(); count += 1
        }
        do {
            let fixture = try Fixture(); let verifier = fixture.verifier()
            _ = try denied { try fixture.converge(verifier) }
            try verifier.validateInventory(target: fixture.target)
            try fixture.write(fixture.generation + "/activate", fixture.activation() + "\n# drift\n")
            try check(try denied { try fixture.converge(verifier) } == "resume_hm_inventory_drift", "sealed_script_drift")
            try fixture.assertReadOnly(); count += 1
        }
        for escape in [false, true] {
            let fixture = try Fixture(); let verifier = fixture.verifier()
            let directory = fixture.fonts + "/share/fonts"
            _ = chmod(fixture.physical(directory), 0o755)
            let source = escape ? fixture.destination + "/fixture.otf" : directory + "/fixture.otf"
            try fixture.fm.createSymbolicLink(atPath: fixture.physical(directory + "/alias.otf"),
                withDestinationPath: fixture.physical(source))
            _ = chmod(fixture.physical(directory), 0o555)
            if escape {
                try check(try denied { try verifier.validateInventory(target: fixture.target) } == "resume_hm_store_escape", "store_symlink_escape")
            } else {
                try fixture.write(fixture.destination + "/alias.otf", "font-payload", mode: 0o644)
                try verifier.validateInventory(target: fixture.target); try fixture.converge(verifier)
            }
            try fixture.assertReadOnly(); count += 1
        }
        print("{\"result\":\"pass\",\"tests\":\(count),\"commandsRun\":0,\"repairs\":0}")
    }
}
