"""One explicitly admitted exclusive private sibling allocation, no Store/CLI.

Calling allocate itself requires coordinator authority. Only the fixed existing
transaction parent and caller-supplied new run leaf are used. One mkdir, no
retry, chmod, unlink, cleanup or new-ID loop. Any uncertain result retains names.

mkdir returns no descriptor/inode: replacement before the first post-mkdir
observation cannot be distinguished. Subsequent observed identity/name drift
fails; this is not filesystem CAS or continuous freshness/exclusion. Successful
handoff requires child AND parent fsync and fresh empty/private rechecks.
"""

import os
import re
import stat

from lib.phase5_runtime_paths import OwnedParent, require_empty_envelope, _identity, _observation, _prefer_error


STATE_SUFFIX = "/AIDev/state/codex-transactions"
LEGACY_LEAF = "p5-fa188ec22716bd13c56ae3c11a53e653"
_ADMISSION = object()


class DirectoryError(ValueError):
    """Fixed redacted result; native paths/IDs/errors never escape."""


def _fail():
    raise DirectoryError("runtime_directory_recovery_required") from None


def _release(parents, error=None):
    while parents:
        parent = parents.pop()
        try:
            parent.close()
        except BaseException as caught:
            error = _prefer_error(error, caught)
    return error


def _empty(parent, syscalls):
    if parent.verify() is False:
        _fail()
    with syscalls.scandir(parent.descriptor) as entries:
        if next(iter(entries), None) is not None:
            _fail()
    if parent.verify() is False:
        _fail()


def _check(parents, leaf, expected, syscalls, platform):
    if len(parents) != 2:
        _fail()
    root, child = parents
    if root.verify() is False or child.verify() is False:
        _fail()
    actual = _identity(syscalls.fstat(child.descriptor), directory=True)
    named = _identity(syscalls.stat(leaf, dir_fd=root.descriptor, follow_symlinks=False), directory=True)
    if actual != expected or named != expected:
        _fail()
    require_empty_envelope(child, syscalls=syscalls, platform=platform)
    if root.verify() is False or child.verify() is False:
        _fail()
    if (_identity(syscalls.fstat(child.descriptor), directory=True) != expected
            or _identity(syscalls.stat(leaf, dir_fd=root.descriptor, follow_symlinks=False), directory=True) != expected):
        _fail()


def _fresh(parents, leaf, expected, syscalls, platform):
    # Allocation-only: later Store writes legitimately change these stamps.
    # Include scandir context exit in the same empty/envelope observation.
    root, child = parents
    first = _observation(syscalls.fstat(child.descriptor))
    _check(parents, leaf, expected, syscalls, platform)
    _empty(child, syscalls)
    _check(parents, leaf, expected, syscalls, platform)
    final = _observation(syscalls.fstat(child.descriptor))
    named = _observation(syscalls.stat(leaf, dir_fd=root.descriptor, follow_symlinks=False))
    if first != final or first != named:
        _fail()


class AllocatedParent:
    """PRIVATE owned parent usable by DurableStore after durable fresh handoff.

verify permits later record files (Store owns their names/content), but retains
exact chain/child identity, owner/mode/flags and empty ACL/xattr envelope policy.
No public constructor can assert directory-creation durability. Close explicitly.
"""
    def __init__(self, token, parents, leaf, expected, syscalls, platform):
        if token is not _ADMISSION:
            _fail()
        self._parents, self._leaf, self._expected = parents, leaf, expected
        self._os, self._platform = syscalls, platform

    @property
    def descriptor(self):
        if len(self._parents) != 2:
            _fail()
        return self._parents[1].descriptor

    @property
    def uid(self):
        if len(self._parents) != 2:
            _fail()
        return self._parents[1].uid

    def verify(self):
        try:
            _check(self._parents, self._leaf, self._expected, self._os, self._platform)
        except BaseException as error:
            error = _release(self._parents, error)
            if isinstance(error, Exception):
                _fail()
            raise error from None

    def close(self):
        error = _release(self._parents)
        if error is not None:
            if isinstance(error, Exception):
                _fail()
            raise error

    def __enter__(self):
        self.verify()
        return self

    def __exit__(self, error_type, error, *_):
        if error_type is None:
            self.close()
        else:
            selected = _release(self._parents, error)
            if selected is not error:
                raise selected from None


def allocate(home, uid, run_id, *, syscalls=os, platform=None, parent_open=None):
    """Create once; establish empty/private/durable state before returning.

Existing state parent is required0700; earlier canonical owner ancestors follow
OwnedParent's safe-mode contract. Their ACLs are not required empty or changed.
No existing-state enumeration and no legacy receipt access occur.
"""
    parents = []
    try:
        if (type(home) is not str or not home.startswith("/") or home.endswith("/")
                or type(uid) is not int or not 0 <= uid < 2 ** 32
                or type(run_id) is not str or re.fullmatch(r"p5-[0-9a-f]{32}", run_id) is None
                or run_id == LEGACY_LEAF):
            _fail()
        opener = OwnedParent.open if parent_open is None else parent_open
        root_path = home + STATE_SUFFIX
        root = opener(root_path, home, uid, syscalls=syscalls)
        parents.append(root)
        if root.verify() is False:
            _fail()
        root_identity = _identity(syscalls.fstat(root.descriptor), directory=True)
        if root_identity[2] != uid or root_identity[4] != stat.S_IFDIR | 0o700:
            _fail()
        syscalls.mkdir(run_id, 0o700, dir_fd=root.descriptor)
        expected = _identity(syscalls.stat(run_id, dir_fd=root.descriptor, follow_symlinks=False), directory=True)
        if expected[2] != uid or expected[4] != stat.S_IFDIR | 0o700:
            _fail()
        child = opener(root_path + "/" + run_id, home, uid, syscalls=syscalls)
        parents.append(child)
        _fresh(parents, run_id, expected, syscalls, platform)
        syscalls.fsync(child.descriptor)
        syscalls.fsync(root.descriptor)
        _fresh(parents, run_id, expected, syscalls, platform)
        # No unbracketed filesystem check follows the final freshness round.
        return AllocatedParent(_ADMISSION, parents, run_id, expected, syscalls, platform)
    except BaseException as error:
        error = _release(parents, error)
        if isinstance(error, Exception):
            _fail()
        raise error from None
