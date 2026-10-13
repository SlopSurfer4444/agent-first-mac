"""Explicit, held, read-only IO for phase5_phase4_health; no native defaults.

Root admits sources and dependencies before calling any method, retains this
owner even on failure, and closes it once. Constructor performs no IO. This is
an observation bracket, not exclusion, a process owner, or execution authority.
Only public root files are readable; sudoers/audit/staging remain metadata-only.
"""

import re
import stat

from lib import phase5_phase4_health as H


P3 = ("acceptance.json", "ceremony-intent-acceptance.json",
      "permissions-acceptance.json", "permissions-apply-verification.json")
PROFILES = "/nix/var/nix/profiles"
SYSTEM = "/run/current-system"
STORE = "/nix/store"
NUMBERED = re.compile(r"system-([1-9][0-9]{0,8})-link")
STORE_PATH = re.compile(r"/nix/store/[A-Za-z0-9._+-]+")
ALIASES = {"/etc": "/private/etc", "/var": "/private/var", "/run": "/private/var/run"}
INTERRUPTS = (KeyboardInterrupt, SystemExit)


def earliest(error):
    """Recover an interruption masked by an admitted dependency's finally."""
    seen, chosen = set(), error
    for _ in range(64):
        if error is None or id(error) in seen:
            break
        seen.add(id(error))
        if isinstance(error, INTERRUPTS):
            chosen = error
        error = error.__context__
    return chosen


class ObserverError(Exception):
    def __init__(self, owner):
        self.private_owner = owner
        super().__init__("phase4_observer_required")


class Observer:
    def __init__(self, *, P4, R, home, uid, budget, syscalls, path_api):
        H.require(H.path(home) and type(uid) is int and uid > 0
                  and callable(path_api) and str(P4.ROOT) == home + "/AIDev/control")
        self.P4, self.R, self.home, self.uid = P4, R, home, uid
        self.budget, self.os, self.Path = budget, syscalls, path_api
        self.control = home + "/AIDev/control"
        self._files = {self.control + "/" + H.P2_FILE,
                       self.control + "/manifests/package-sources.json",
                       *(self.control + "/evidence/phase-3/" + name for name in P3), H.BROKER, H.POLICY}
        self._pins, self._edges, self._readers = {}, {}, []
        self._version, self._current, self._receipt, self._profiles = None, None, None, None
        self._error, self._closed, self.acquisition_pending = None, False, False
        # Collector requires identity, not merely equivalent bound methods.
        self.json, self.digest = self._json, self._digest

    def __repr__(self):
        return "<private Phase 4 observation owner>"

    def _failed(self, error):
        self._error = self.R.earliest(self._error, earliest(error))
        if isinstance(self._error, INTERRUPTS):
            self._error.private_owner = self
            raise self._error from None
        raise ObserverError(self) from None

    def _call(self, function, *args):
        try:
            H.require(not self._closed and self._error is None)
            self.budget.check()
            return function(*args)
        except BaseException as error:
            self._failed(error)

    def _remember(self, path, value):
        if path in self._edges:
            H.require(self._edges[path] == value)
        else:
            H.require(len(self._edges) < 64000)
            self._edges[path] = value

    def _named(self, path, *, absent=False):
        self.budget.check()
        try:
            facts = self.os.lstat(path)
        except FileNotFoundError:
            H.require(absent)
            self._remember(path, None)
            return None
        # Directory activity times/link counts are not a whole-machine freeze.
        stamp = (tuple(getattr(facts, k) for k in ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode", "st_flags"))
                 if stat.S_ISDIR(facts.st_mode) else self.R.file_stamp(facts))
        raw = self.os.readlink(path) if stat.S_ISLNK(facts.st_mode) else None
        self._remember(path, (stamp, raw))
        return facts

    def _parents(self, path):
        parts = path[1:].split("/")
        for count in range(len(parts)):
            prefix = "/" + "/".join(parts[:count])
            facts = self._named(prefix)
            if stat.S_ISLNK(facts.st_mode):
                H.require(prefix in ALIASES and facts.st_uid == 0
                          and self._edges[prefix][1] in (ALIASES[prefix], ALIASES[prefix][1:]))
                # /run is often an alias too: retain its physical parent edges,
                # not only the final current-system link reached through it.
                self._parents(ALIASES[prefix])
                destination = self._named(ALIASES[prefix])
                H.require(stat.S_ISDIR(destination.st_mode) and destination.st_uid == 0)
            else:
                H.require(stat.S_ISDIR(facts.st_mode))

    @staticmethod
    def _physical(path):
        first = "/" + path[1:].split("/")[0]
        return ALIASES.get(first, first) + path[len(first):]

    def _canonical(self, path, *, absent=False):
        self._parents(path)
        facts = self._named(path, absent=absent)
        # Never resolve a substituted leaf to read its destination.
        H.require(facts is None or not stat.S_ISLNK(facts.st_mode))
        parent, leaf = path.rsplit("/", 1)
        canonical_parent = str(self.Path(parent).resolve(strict=True))
        H.require(canonical_parent in (parent, self._physical(parent)))
        canonical = canonical_parent + "/" + leaf
        self._parents(canonical)
        physical = self._named(canonical, absent=absent)
        H.require((facts is None and physical is None) or
                  (facts is not None and physical is not None and self.R.file_stamp(facts) == self.R.file_stamp(physical)))
        return canonical, facts

    @staticmethod
    def _metadata(facts):
        kind = "file" if stat.S_ISREG(facts.st_mode) else "directory" if stat.S_ISDIR(facts.st_mode) else "other"
        return dict(uid=facts.st_uid, gid=facts.st_gid, mode=stat.S_IMODE(facts.st_mode), kind=kind,
                    nlink=facts.st_nlink, symlink=stat.S_ISLNK(facts.st_mode), size=facts.st_size)

    def _file(self, value):
        path = str(value)
        H.require(path in self._files or (self._receipt is not None and path == self._receipt))
        canonical, facts = self._canonical(path)
        H.require(stat.S_ISREG(facts.st_mode))
        if path not in self._pins:
            root, uid = (self.home, self.uid) if path.startswith(self.home + "/") else ("/" + canonical[1:].split("/")[0], 0)
            # Publish the partial admitted SourceFile before its IO constructor.
            pin = object.__new__(self.R.SourceFile)
            pin.fds = []
            self._readers.append(pin)
            self.acquisition_pending = True
            pin.__init__(canonical, root, uid, self.budget, syscalls=self.os, opener=self.R.OwnedParent.open)
            self.acquisition_pending = False
            self._pins[path] = pin
        pin = self._pins[path]
        H.require(pin.path == canonical and pin.stamp == self.R.file_stamp(facts))
        pin.verify()
        self._canonical(path)
        return {**self._metadata(facts), "data": pin.data}

    def file(self, path):
        return self._call(self._file, path)

    def _json(self, path):
        return self._call(lambda: H.parse(self._file(path)["data"]))

    def _digest(self, path):
        return self._call(lambda: H.sha(self._file(path)["data"]))

    def _fixed_metadata(self, value, directory=False, absent=False):
        path = str(value)
        allowed = H.EMERGENCY if absent else tuple(H.DIRECTORIES.values()) if directory else (H.SUDOERS,)
        H.require(path in allowed)
        _, facts = self._canonical(path, absent=absent)
        if absent:
            return facts is None
        row = self._metadata(facts)
        if directory:
            return {key: row[key] for key in ("uid", "gid", "mode", "kind", "symlink")}
        return row

    def metadata(self, path):
        return self._call(self._fixed_metadata, path)

    def directory(self, path):
        return self._call(self._fixed_metadata, path, True)

    def absent(self, path):
        return self._call(self._fixed_metadata, path, False, True)

    def _link(self, path):
        self._parents(path)
        facts = self._named(path)
        H.require(stat.S_ISLNK(facts.st_mode) and facts.st_uid == 0)
        return facts, self._edges[path][1]

    def _store_target(self, path, *, directory=True):
        H.require(type(path) is str and STORE_PATH.fullmatch(path) is not None
                  and path.rsplit("/", 1)[1] not in (".", ".."))
        self._parents(path)
        store = self._named(STORE)
        mode = stat.S_IMODE(store.st_mode)
        # The fixed store parent is not an immutable output or private HOME:
        # its root-owned group-writable mode/group are legitimate and rebound.
        H.require(store.st_uid == 0 and not mode & 0o002)
        facts = self._named(path)
        H.require((stat.S_ISDIR(facts.st_mode) if directory else stat.S_ISREG(facts.st_mode))
                  and facts.st_uid == facts.st_gid == 0 and not facts.st_mode & 0o022
                  and not facts.st_mode & 0o7000)
        H.require(str(self.Path(path).resolve(strict=True)) == path)
        self._named(path)
        return facts

    def _resolve_link(self, path, targets):
        _, raw = self._link(path)
        selected = {row["path"] for row in targets.values()}
        if raw in selected:
            expected = raw
        else:
            reference = PROFILES + "/" + raw if path == H.PROFILE and NUMBERED.fullmatch(raw) else raw
            if reference == H.PROFILE and path == SYSTEM:
                expected = self._resolve_link(H.PROFILE, targets)
            else:
                H.require(reference.startswith(PROFILES + "/"))
                match = NUMBERED.fullmatch(reference[len(PROFILES) + 1:])
                H.require(match is not None and int(match[1]) in targets)
                expected = targets[int(match[1])]["path"]
                _, bound = self._link(reference)
                H.require(bound == expected)
        self._store_target(expected)
        H.require(str(self.Path(path).resolve(strict=True)) == expected)
        self._link(path)
        return expected

    def _version_bytes(self, path, facts):
        H.require(facts.st_nlink == 1 and stat.S_IMODE(facts.st_mode) == 0o444 and 1 <= facts.st_size <= 4096)
        stamp = self.R.file_stamp(facts)
        if self._version is None:
            self.acquisition_pending = True
            descriptor = self.os.open(path, self.R.READ_FLAGS)
            self._version = [descriptor, path, stamp, None]
            self.acquisition_pending = False
        descriptor, held_path, held_stamp, data = self._version
        H.require(path == held_path and stamp == held_stamp and self.R.file_stamp(self.os.fstat(descriptor)) == stamp)
        self.os.lseek(descriptor, 0, 0)
        chunks, size = [], 0
        while True:
            self.budget.check()
            block = self.os.read(descriptor, min(4097 - size, 4096))
            H.require(type(block) is bytes)
            if not block:
                break
            chunks.append(block)
            size += len(block)
            H.require(size <= 4096)
        observed = b"".join(chunks)
        H.require(size == facts.st_size and self.R.file_stamp(self.os.fstat(descriptor)) == stamp
                  and self.R.file_stamp(self._named(path)) == stamp and (data is None or data == observed))
        self._version[3] = observed
        return observed

    def _observe_current(self):
        self._parents(PROFILES + "/system")
        targets = {}
        # Fixed readable profile registry, not root-private audit/staging.
        if self._profiles is None:
            self.acquisition_pending = True
            self._profiles = self.R.OwnedParent.open(PROFILES, "/nix", 0, syscalls=self.os)
            self.acquisition_pending = False
        self._profiles.verify()
        with self.os.scandir(self._profiles.descriptor) as entries:
            count = 0
            for entry in entries:
                self.budget.check()
                count += 1
                H.require(count <= 10000)
                match = NUMBERED.fullmatch(entry.name)
                if match is None:
                    continue
                number = int(match[1])
                _, raw = self._link(PROFILES + "/" + entry.name)
                facts = self._store_target(raw)
                H.require(number not in targets)
                targets[number] = dict(gid=facts.st_gid, kind="directory", mode=stat.S_IMODE(facts.st_mode),
                                       path=raw, substituted=False, uid=facts.st_uid)
        self._profiles.verify()
        profile, system = self._resolve_link(H.PROFILE, targets), self._resolve_link(SYSTEM, targets)
        H.require(profile == system)
        link, version_path = self._link(system + "/darwin-version.json")
        facts = self._store_target(version_path, directory=False)
        H.require(str(self.Path(system + "/darwin-version.json").resolve(strict=True)) == version_path)
        row = dict(profileTarget=profile, systemTarget=system, targets=targets,
            versionLink=dict(gid=link.st_gid, kind="symlink", mode=stat.S_IMODE(link.st_mode), uid=link.st_uid),
            versionFile=dict(gid=facts.st_gid, kind="file", modeWritable=bool(facts.st_mode & 0o022),
                             owner=facts.st_uid, parent=STORE, sizeBounded=1 <= facts.st_size <= 4096),
            versionBytes=self._version_bytes(version_path, facts))
        version = H.current_value(row)
        self._check_edges()
        if self._current is not None:
            H.require(H.exact(self._current, row))
        self._current = H.snapshot(row)
        self._receipt = self.home + "/AIDev/state/phase-4/apply-receipts/" + version["configurationRevision"] + ".json"
        return H.snapshot(row)

    def current(self):
        return self._call(self._observe_current)

    def _check_edges(self):
        for path, value in tuple(self._edges.items()):
            self._named(path, absent=value is None)

    def _verify(self):
        self._check_edges()
        for path in tuple(self._pins):
            self._file(path)
        if self._current is not None:
            self._observe_current()
        self._check_edges()
        return True

    def verify(self):
        return self._call(self._verify)

    def close(self):
        if self._closed:
            return
        self._closed = True
        problem = self._error
        if self._version is not None:
            descriptor, self._version = self._version[0], None
            try:
                self.os.close(descriptor)
            except BaseException as error:
                problem = self.R.earliest(problem, earliest(error))
        if self._profiles is not None:
            profiles, self._profiles = self._profiles, None
            try:
                profiles.close()
            except BaseException as error:
                problem = self.R.earliest(problem, earliest(error))
        while self._readers:
            reader = self._readers.pop()
            try:
                reader.close()
            except BaseException as error:
                problem = self.R.earliest(problem, earliest(error))
        if problem is not None:
            self._failed(problem)
