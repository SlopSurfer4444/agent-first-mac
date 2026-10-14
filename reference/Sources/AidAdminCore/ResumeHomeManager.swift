import CryptoKit
import Darwin
import Foundation

/// Narrow read-only postcondition for the Darwin fonts onChange hook. Replaying
/// HM can skip this hook after linkGeneration already changed its marker.
/// No arbitrary hook, activation script, or caller-supplied path is executed.
public final class ResumeHomeManagerVerifier {
    private let context: RuntimeContext
    private let runner: CommandRunning
    private let environment: [String: String]
    private var admitted: Inventory?
    private let store = "/nix/store/"
    private let storeName = "[0-9abcdfghijklmnpqrsvwxyz]{32}-[A-Za-z0-9._+-]+"

    private struct Inventory: Equatable {
        let target: String
        let wrapper: String
        let generation: String
        let fonts: String
        let destination: String
        let scripts: [String: String]
        let desired: [String: Entry]
    }
    private struct Entry: Equatable {
        let directory: Bool
        let mode: UInt16
        let digest: String
        let size: Int
    }

    public init(context: RuntimeContext, runner: CommandRunning, environment: [String: String]) {
        self.context = context; self.runner = runner; self.environment = environment
    }

    public func validateInventory(target: String) throws {
        admitted = nil
        admitted = try inventory(target: target)
    }

    public func converge(target: String, beforeRepair: () throws -> Void) throws {
        guard let before = admitted, before.target == target else {
            throw BrokerFailure.rejected("resume_hm_inventory_required")
        }
        let current = try inventory(target: target)
        guard current == before else { throw BrokerFailure.rejected("resume_hm_inventory_drift") }
        // This revision intentionally has no repair authority. In particular,
        // beforeRepair is not called and runner never receives a user script.
        do {
            let actual = try tree(current.destination, desired: false)
            guard actual == current.desired else { throw BrokerFailure.rejected("resume_hm_fonts_effect_unproven") }
        } catch {
            throw BrokerFailure.rejected("resume_hm_fonts_effect_unproven")
        }
    }

    private func inventory(target: String) throws -> Inventory {
        try demand(matches(target, "^" + store + "[0-9abcdfghijklmnpqrsvwxyz]{32}-darwin-system-[A-Za-z0-9._+-]+$"),
                   "resume_hm_target")
        try demand(matches(context.callerIdentity, "^[a-z_][a-z0-9_-]{0,31}$") && context.realUID > 0,
                   "resume_hm_owner")
        let owner = context.callerIdentity
        let home = "/Users/" + owner
        try demand(context.callerHome == home || context.callerHome == physical(home), "resume_hm_owner_home")
        let targetText = try script(target + "/activate")
        let lines = targetText.components(separatedBy: "\n")
        let prefix = "launchctl asuser \"$(id -u " + owner + ")\" sudo -u " + owner + " --set-home \"${hmDryRunArgs[@]}\" "
        let launch = lines.filter { $0.hasPrefix(prefix) }
        let references = captures("(" + store + "[0-9abcdfghijklmnpqrsvwxyz]{32}-activation-[a-z_][a-z0-9_-]*)", in: targetText)
        try demand(launch.count == 1 && references.count == 1, "resume_hm_wrapper_inventory")
        let wrapper = String(launch[0].dropFirst(prefix.count))
        try demand(matches(wrapper, "^" + store + "[0-9abcdfghijklmnpqrsvwxyz]{32}-activation-" + owner + "$"),
                   "resume_hm_wrapper_path")
        let wrapperText = try script(wrapper)
        let wrapperLines = wrapperText.components(separatedBy: "\n").filter { !$0.isEmpty }
        try demand(wrapperLines.count == 2 && matches(wrapperLines[0], "^#!" + store + storeName + "/bin/bash$"),
                   "resume_hm_wrapper_shape")
        let generations = captures("^exec (" + store + "[0-9abcdfghijklmnpqrsvwxyz]{32}-home-manager-generation)/activate --driver-version 1 >&2$", in: wrapperLines[1])
        try demand(generations.count == 1, "resume_hm_generation_inventory")
        let generation = generations[0]
        let activation = try script(generation + "/activate")
        let block = try section("onFilesChange", in: activation)
        let sources = captures("  (" + store + "[0-9abcdfghijklmnpqrsvwxyz]{32}-home-manager-fonts)/share/fonts/ " + home + "/Library/Fonts/HomeManager", in: block)
        let rsyncs = captures("run (" + store + "[0-9abcdfghijklmnpqrsvwxyz]{32}-rsync-[A-Za-z0-9._+-]+/bin/rsync) ", in: block)
        try demand(sources.count == 1 && rsyncs.count == 1, "resume_hm_unknown_onchange")
        let destination = home + "/Library/Fonts/HomeManager"
        let expected = """
        if (( ${changedFiles[Library/Fonts/.home-manager-fonts-version]} == 1 )); then
          if [[ -v DRY_RUN || -v VERBOSE ]]; then
            echo "Running onChange hook for" Library/Fonts/.home-manager-fonts-version
          fi
          if [[ ! -v DRY_RUN ]]; then
            run mkdir -p \(destination)
        run \(rsyncs[0]) $VERBOSE_ARG -acL --chmod=u+w --delete \\
          \(sources[0])/share/fonts/ \(destination)

          fi
        fi
        """
        try demand(block.trimmingCharacters(in: .newlines) == expected, "resume_hm_unknown_onchange")
        let changed = captures("changedFiles\\[([^\\]]+)\\]", in: activation)
        try demand(changed.count == 3 && changed.allSatisfy { $0 == "Library/Fonts/.home-manager-fonts-version" },
                   "resume_hm_unknown_onchange_inventory")
        let checks = try section("checkFilesChanged", in: activation)
        let markers = captures("_cmp (" + store + storeName + ") " + home + "/Library/Fonts/\\.home-manager-fonts-version ", in: checks)
        try demand(markers.count == 1, "resume_hm_font_marker_inventory")
        let marker = try immutableBytes(markers[0], maximum: 4096)
        try demand(String(data: marker, encoding: .utf8) == sources[0], "resume_hm_font_marker_binding")
        let fonts = sources[0] + "/share/fonts"
        return Inventory(target: target, wrapper: wrapper, generation: generation, fonts: fonts,
                         destination: destination,
                         scripts: [target: hash(Data(targetText.utf8)), wrapper: hash(Data(wrapperText.utf8)),
                                   generation: hash(Data(activation.utf8)), markers[0]: hash(marker)],
                         desired: try tree(fonts, desired: true))
    }

    private func section(_ name: String, in text: String) throws -> String {
        let marker = "_iNote \"Activating %s\" \"" + name + "\"\n"
        let pieces = text.components(separatedBy: marker)
        try demand(pieces.count == 2, "resume_hm_section_inventory")
        guard let end = pieces[1].range(of: "\n_iNote \"Activating %s\" ") else {
            throw BrokerFailure.rejected("resume_hm_section_end")
        }
        return String(pieces[1][..<end.lowerBound])
    }

    private func tree(_ root: String, desired: Bool) throws -> [String: Entry] {
        var entries: [String: Entry] = [:]
        var byteCount = 0
        var seenDirectories = Set<String>()
        func visit(_ path: String, relative: String, depth: Int) throws {
            try demand(depth <= 24 && entries.count < 4096, "resume_hm_tree_bound")
            let resolved = desired ? try resolveStore(path) : physical(path)
            if !desired { try validateOwnerAncestors(path) }
            var before = stat()
            try demand(lstat(resolved, &before) == 0 && before.st_uid == (desired ? context.trustedUID : context.realUID),
                       "resume_hm_tree_owner")
            let kind = before.st_mode & S_IFMT
            try demand(kind == S_IFDIR || kind == S_IFREG, "resume_hm_tree_type")
            try demand(before.st_mode & (desired ? 0o222 : 0o022) == 0 && before.st_mode & 0o7000 == 0,
                       "resume_hm_tree_mode")
            let mode = UInt16(before.st_mode & 0o777) | (desired ? 0o200 : 0)
            if kind == S_IFDIR {
                try demand(seenDirectories.insert(resolved).inserted, "resume_hm_tree_cycle")
                let names = try FileManager.default.contentsOfDirectory(atPath: resolved).sorted()
                entries[relative] = Entry(directory: true, mode: mode, digest: "", size: 0)
                for name in names {
                    try demand(!name.contains("/") && name != "." && name != "..", "resume_hm_tree_name")
                    try visit(path + "/" + name, relative: relative + "/" + name, depth: depth + 1)
                }
                try demand(try FileManager.default.contentsOfDirectory(atPath: resolved).sorted() == names,
                           "resume_hm_tree_drift")
            } else {
                try demand(before.st_nlink == 1 || desired, "resume_hm_destination_hardlink")
                let bytes = try stableBytes(resolved, maximum: 16 * 1024 * 1024, uid: before.st_uid)
                byteCount += bytes.count
                try demand(byteCount <= 64 * 1024 * 1024, "resume_hm_tree_bytes")
                entries[relative] = Entry(directory: false, mode: mode, digest: hash(bytes), size: bytes.count)
            }
            var after = stat()
            try demand(lstat(resolved, &after) == 0 && same(before, after), "resume_hm_tree_drift")
        }
        try visit(root, relative: "", depth: 0)
        return entries
    }

    private func script(_ path: String) throws -> String {
        guard let text = String(data: try immutableBytes(path, maximum: 1024 * 1024), encoding: .utf8) else {
            throw BrokerFailure.rejected("resume_hm_script_encoding")
        }
        return text
    }

    private func immutableBytes(_ path: String, maximum: Int) throws -> Data {
        let resolved = try resolveStore(path)
        var facts = stat()
        try demand(lstat(resolved, &facts) == 0 && facts.st_mode & 0o222 == 0 && facts.st_uid == context.trustedUID,
                   "resume_hm_store_mutable")
        return try stableBytes(resolved, maximum: maximum, uid: context.trustedUID)
    }

    private func resolveStore(_ path: String) throws -> String {
        try demand(path.hasPrefix(store) && !path.contains("..") && !path.contains("//"), "resume_hm_store_path")
        guard let pointer = realpath(physical(path), nil) else { throw BrokerFailure.rejected("resume_hm_store_missing") }
        defer { free(pointer) }
        let result = String(cString: pointer)
        try demand(result.hasPrefix(physical(store)), "resume_hm_store_escape")
        // Immutable Nix store ancestors, including symlink resolutions, are
        // trusted objects, not executable paths selected by the owner home.
        var ancestor = URL(fileURLWithPath: result).deletingLastPathComponent().path
        while ancestor != physical("/nix/store") {
            var facts = stat()
            try demand(lstat(ancestor, &facts) == 0 && facts.st_mode & S_IFMT == S_IFDIR &&
                       facts.st_uid == context.trustedUID && facts.st_mode & 0o222 == 0,
                       "resume_hm_store_ancestor")
            ancestor = URL(fileURLWithPath: ancestor).deletingLastPathComponent().path
        }
        return result
    }

    private func validateOwnerAncestors(_ path: String) throws {
        // Core fixtures may carry a physical callerHome; generated HM paths
        // remain logical and receive rootPrefix exactly once.
        let home = "/Users/" + context.callerIdentity
        try demand(path == home || path.hasPrefix(home + "/"), "resume_hm_destination_scope")
        var ancestor = path
        while ancestor != home {
            ancestor = URL(fileURLWithPath: ancestor).deletingLastPathComponent().path
            var facts = stat()
            try demand(lstat(physical(ancestor), &facts) == 0 && facts.st_mode & S_IFMT == S_IFDIR &&
                       facts.st_uid == context.realUID && facts.st_mode & 0o022 == 0,
                       "resume_hm_destination_ancestor")
        }
    }

    private func stableBytes(_ path: String, maximum: Int, uid: uid_t) throws -> Data {
        let fd = Darwin.open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        try demand(fd >= 0, "resume_hm_read_open")
        defer { close(fd) }
        var before = stat()
        try demand(fstat(fd, &before) == 0 && before.st_mode & S_IFMT == S_IFREG &&
                   before.st_uid == uid && before.st_size >= 0 && before.st_size <= maximum,
                   "resume_hm_read_metadata")
        var bytes = Data(count: Int(before.st_size)); var offset = 0
        while offset < bytes.count {
            let n = bytes.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress!.advanced(by: offset), $0.count - offset) }
            try demand(n > 0, "resume_hm_read_short"); offset += n
        }
        var after = stat(); var named = stat()
        try demand(fstat(fd, &after) == 0 && lstat(path, &named) == 0 && same(before, after) && same(after, named),
                   "resume_hm_read_drift")
        return bytes
    }

    private func same(_ a: stat, _ b: stat) -> Bool {
        a.st_dev == b.st_dev && a.st_ino == b.st_ino && a.st_mode == b.st_mode && a.st_uid == b.st_uid &&
        a.st_gid == b.st_gid && a.st_size == b.st_size && a.st_nlink == b.st_nlink &&
        a.st_mtimespec.tv_sec == b.st_mtimespec.tv_sec && a.st_mtimespec.tv_nsec == b.st_mtimespec.tv_nsec &&
        a.st_ctimespec.tv_sec == b.st_ctimespec.tv_sec && a.st_ctimespec.tv_nsec == b.st_ctimespec.tv_nsec
    }
    private func physical(_ path: String) -> String { context.rootPrefix == "/" ? path : context.rootPrefix + path }
    private func hash(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
    private func matches(_ text: String, _ pattern: String) -> Bool { text.range(of: pattern, options: .regularExpression) != nil }
    private func captures(_ pattern: String, in text: String) -> [String] {
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return [] }
        return regex.matches(in: text, range: NSRange(text.startIndex..., in: text)).compactMap {
            guard let range = Range($0.range(at: 1), in: text) else { return nil }; return String(text[range])
        }
    }
    private func demand(_ condition: @autoclosure () throws -> Bool, _ reason: String) throws {
        if try !condition() { throw BrokerFailure.rejected(reason) }
    }
}
