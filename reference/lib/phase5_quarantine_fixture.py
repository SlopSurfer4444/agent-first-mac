"""One retained PRIVATE quarantine fixture; explicit injected I/O only.

Allocate seven new0700 directories and ten0600 files, never adopt a collision,
retry, remove, or restore anything. The profile is the exact held installed bytes,
not auth/base configuration. This is Part A profile-bytes capability material,
not proof that the installed launcher isolates its normal configuration stack.

Root owns current source/state admission and every process/listener lifetime.
verify checks only this fixture. No native defaults, entrypoint or random names.
mkdir does not return an inode: substitution before its first observation cannot
be distinguished. Checks bind observed boundaries, not continuous filesystem CAS.
All objects survive success/failure; close releases explicit descriptors only.
The fixed empty Git skeleton contains no config/hooks/remotes/templates. Native
Git worktree recognition is a separate caller precondition, never inferred here.
The one pre-created profile-home/tmp directory is a mutable vendor-cache boundary:
its canonical identity, mode and empty envelope stay pinned, but its contents and
child-activity timestamps are not source inputs and are not recursively observed.
Profile siblings and every known fixture/Git file remain exact and immutable.
"""

import hashlib
import re

from lib.phase5_current_quarantine import PROFILE_SHA256, SECRET_LEAVES


MAX_BYTES = 16384
_CONTEXT_LIMIT = 64
_TOKEN = object()
GIT_HEAD = b"ref: refs/heads/codex/quarantine-probe\n"


class FixtureError(Exception):
    def __init__(self, *, private_owner=None):
        self.private_owner = private_owner
        super().__init__("quarantine_fixture_recovery_required")


def _require(condition):
    if condition is not True:
        raise FixtureError() from None


def _interruption(error):
    selected, cursor, seen = error, error, set()
    for _ in range(_CONTEXT_LIMIT):
        if cursor is None or id(cursor) in seen:
            break
        seen.add(id(cursor))
        if isinstance(cursor, (KeyboardInterrupt, SystemExit)):
            selected = cursor
        cursor = cursor.__context__
    return selected


class HeldFixture:
    """PRIVATE retained observation; no cleanup, process or backend export API."""
    def __init__(self, token, home, uid, leaf, profile, paths, backend, syscalls, platform):
        _require(token is _TOKEN)
        self._home, self._uid, self._leaf, self._profile = home, uid, leaf, profile
        self._paths, self._backend, self._os, self._platform = paths, backend, syscalls, platform
        self._parents, self._dirs, self._identities, self._io = [], {}, {}, {}
        self._names_expected, self._initial = {}, {}
        self._closed = self._complete = False
        self._error = None
        self._workspace = home + "/AIDev/quarantine/" + leaf
        self._scratch = home + "/AIDev/scratch/" + leaf

    @property
    def workspace(self):
        return self._workspace

    @property
    def profile_home(self):
        return self._workspace + "/profile-home"

    @property
    def fixture_paths(self):
        result = {leaf: self._workspace + "/" + leaf for leaf in SECRET_LEAVES}
        result.update(visible=self._workspace + "/visible.txt", outside=self._scratch + "/outside.txt")
        return result

    def _failed(self, error):
        self._error = self._paths._prefer_error(self._error, _interruption(error))
        if isinstance(self._error, (KeyboardInterrupt, SystemExit)):
            self._error.private_owner = self
            raise self._error from None
        raise FixtureError(private_owner=self) from None

    def _guard(self, operation):
        try:
            _require(not self._closed and self._error is None)
            return operation()
        except BaseException as error:
            self._failed(error)

    def _directory(self, key):
        _require(not self._closed)
        parent = self._dirs[key]
        self._paths.require_empty_envelope(parent, syscalls=self._os, platform=self._platform)
        _require(self._paths._identity(self._os.fstat(parent.descriptor), directory=True)
                 == self._identities[key])
        return parent

    def _names(self, key):
        parent = self._directory(key)
        first = self._paths._observation(self._os.fstat(parent.descriptor))
        observed = []
        with self._os.scandir(parent.descriptor) as entries:
            for entry in entries:
                _require(len(observed) < 9 and type(entry.name) is str)
                observed.append(entry.name)
        expected = self._names_expected[key]
        _require(len(observed) == len(expected) and set(observed) == expected)
        self._directory(key)
        _require(self._paths._observation(self._os.fstat(parent.descriptor)) == first)

    def _admit_descriptor(self, descriptor):
        facts = self._backend._facts(self._os.fstat(descriptor), self._uid, MAX_BYTES)
        _require(facts[5] == 0o100600 and facts[6] == 0 and facts[7] == 0)
        envelope = self._paths.observe_envelope(descriptor, syscalls=self._os, platform=self._platform)
        _require(envelope.acl_entries == 0 and envelope.xattr_names == ())
        return True

    def _snapshot(self, key, leaf):
        parent = self._directory(key)
        image = self._io[key].snapshot(leaf)
        _require(image.data is not None and image.mode == 0o600)
        descriptor = self._os.open(leaf, self._backend.READ_FLAGS, dir_fd=parent.descriptor)
        descriptors = [descriptor]
        try:
            first = self._backend._facts(self._os.fstat(descriptor), self._uid, MAX_BYTES)
            _require(first[6] == 0)
            _require(self._backend._image(image.data, self._os.fstat(descriptor)) == image)
            envelope = self._paths.observe_envelope(descriptor, syscalls=self._os, platform=self._platform)
            _require(envelope.acl_entries == 0 and envelope.xattr_names == ())
            _require(self._io[key].snapshot(leaf) == image)
            _require(self._backend._facts(self._os.fstat(descriptor), self._uid, MAX_BYTES) == first)
            self._directory(key)
            return image, first
        finally:
            self._paths._close_all(self._os, descriptors)

    def _round(self):
        # Only tmp contents/activity are mutable; still check its held boundary
        # twice. Envelope observations remain stable point-in-time observations.
        first = {key: self._paths._observation(self._os.fstat(parent.descriptor))
                 for key, parent in self._dirs.items() if key != "tmp"}
        for key in self._dirs:
            self._directory(key) if key == "tmp" else self._names(key)
        for (key, leaf), expected in self._initial.items():
            _require(self._snapshot(key, leaf) == expected)
        for key, parent in self._dirs.items():
            if key == "tmp":
                self._directory(key)
            else:
                self._names(key)
                _require(self._paths._observation(self._os.fstat(parent.descriptor)) == first[key])

    def _new_directory(self, key, path, parent, leaf, parent_key=None):
        self._round()
        _require(parent.verify() is not False)
        self._os.mkdir(leaf, 0o700, dir_fd=parent.descriptor)
        expected = self._paths._identity(self._os.stat(leaf, dir_fd=parent.descriptor,
                                                      follow_symlinks=False), directory=True)
        _require(expected[2] == self._uid and expected[4] == 0o40700 and expected[5] == 0)
        child = self._paths.OwnedParent.open(path, self._home, self._uid, syscalls=self._os)
        self._parents.append(child)
        self._dirs[key], self._identities[key], self._names_expected[key] = child, expected, set()
        if parent_key is not None:
            self._names_expected[parent_key].add(leaf)
        self._names(key)
        self._os.fsync(child.descriptor)
        self._os.fsync(parent.descriptor)
        _require(parent.verify() is not False)
        self._names(key)
        self._io[key] = self._backend.DescriptorBackend(child, syscalls=self._os, maximum=MAX_BYTES)

    def _allocate(self):
        roots = []
        for suffix in ("quarantine", "scratch"):
            parent = self._paths.OwnedParent.open(self._home + "/AIDev/" + suffix,
                                                  self._home, self._uid, syscalls=self._os)
            self._parents.append(parent)
            roots.append(parent)
        self._new_directory("workspace", self._workspace, roots[0], self._leaf)
        self._new_directory("scratch", self._scratch, roots[1], self._leaf)
        self._new_directory("profile", self.profile_home, self._dirs["workspace"],
                            "profile-home", "workspace")
        self._new_directory("tmp", self.profile_home + "/tmp", self._dirs["profile"],
                            "tmp", "profile")
        self._new_directory("git", self._workspace + "/.git", self._dirs["workspace"],
                            ".git", "workspace")
        for leaf in ("objects", "refs"):
            self._new_directory("git-" + leaf, self._workspace + "/.git/" + leaf,
                                self._dirs["git"], leaf, "git")
        rows = [("workspace", "visible.txt", b"visible\n")]
        rows += [("workspace", leaf, b"phase5-synthetic-marker\n") for leaf in SECRET_LEAVES]
        rows += [("scratch", "outside.txt", b"outside\n"),
                 ("profile", "quarantine.config.toml", self._profile),
                 ("git", "HEAD", GIT_HEAD)]
        for key, leaf, data in rows:
            self._round()
            image = self._io[key].create_exclusive(leaf, data, 0o600,
                                                  admit_descriptor=self._admit_descriptor)
            self._names_expected[key].add(leaf)
            observed = self._snapshot(key, leaf)
            _require(observed[0] == image and image.data == data)
            self._initial[key, leaf] = observed
        _require(len(self._initial) == 10 and
                 len({pair[0].identity for pair in self._initial.values()}) == 10)
        self._complete = True
        return self._verify()

    def _verify(self):
        _require(self._complete)
        self._round()
        return True

    def verify(self):
        return self._guard(self._verify)

    def close(self):
        selected = self._error
        self._closed = True
        while self._parents:
            parent = self._parents.pop()
            try:
                parent.close()
            except BaseException as error:
                selected = self._paths._prefer_error(selected, _interruption(error))
        if selected is not None:
            self._failed(selected)


def allocate(home, uid, leaf, installed_profile, *, admit_sources, paths, backend, syscalls, platform):
    """Allocate once after explicit source admission; retain partial state on error.

    The caller supplies all implementations (no native defaults). Source admission
    runs before and after allocation; verify() subsequently checks only fixtures.
    """
    try:
        _require(type(home) is str and home.startswith("/Users/") and len(paths._parts(home)) == 2)
        _require(type(uid) is int and 0 < uid < 2 ** 32)
        _require(type(leaf) is str and re.fullmatch(r"phase5-quarantine-task\.[A-Za-z0-9]{6,32}", leaf) is not None)
        _require(type(installed_profile) is bytes and len(installed_profile) <= MAX_BYTES
                 and hashlib.sha256(installed_profile).hexdigest() == PROFILE_SHA256)
        _require(callable(admit_sources) and platform is not None and syscalls is not None)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise FixtureError() from None
    owner = HeldFixture(_TOKEN, home, uid, leaf, installed_profile, paths, backend, syscalls, platform)
    selected = None
    try:
        _require(admit_sources() is True)
        owner._allocate()
    except BaseException as error:
        selected = _interruption(error)
    try:
        _require(admit_sources() is True)
    except BaseException as error:
        selected = paths._prefer_error(selected, _interruption(error))
    if selected is not None:
        owner._failed(selected)
    owner.verify()
    return owner
