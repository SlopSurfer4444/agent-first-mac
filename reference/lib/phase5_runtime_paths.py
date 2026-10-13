"""Owned directory-chain and private metadata observations; no mutation authority.

Opening retains every descriptor from / through the canonical caller-supplied
path. verify() checks those objects AND every named edge, including the root.
Owner/mode policy starts at user_root; earlier ancestors are identity-bound
directories, not claimed to be owner-private. Observations are point-in-time,
not locks against concurrent namespace or ACL changes.

Envelope observation reads no ACL principals or xattr values. It counts extended
ACL entries and lists accessible xattr names (including compression attributes).
An empty observation does not claim visibility of inaccessible kernel metadata.
Directory creation, fsync after creation, source/receipt admission and exclusive
session allocation remain caller-owned. No mkdir, chmod, unlink or retry here.
"""

import ctypes
from dataclasses import dataclass
import errno
import functools
import os
import stat
import sys


_OPEN_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
SAFE_MODES = frozenset((0o700, 0o750, 0o755))
MAX_PATH_BYTES, MAX_COMPONENTS = 1024, 128
MAX_ACL_ENTRIES, MAX_XATTR_BYTES, MAX_XATTR_NAMES = 128, 65536, 256
ACL_TYPE_EXTENDED, ACL_FIRST_ENTRY, ACL_NEXT_ENTRY = 0x100, 0, -1
XATTR_SHOWCOMPRESSION, XATTR_MAXNAMELEN = 0x20, 127
_ADMISSION = object()


class PathsError(ValueError):
    """Native errors, private names and descriptor identities are not public."""


def _fail():
    raise PathsError("runtime_paths_admission_required") from None


def _redacted(function):
    @functools.wraps(function)
    def wrapped(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except Exception:
            _fail()
    return wrapped


def _uint(value, bits=64):
    return type(value) is int and 0 <= value < 2 ** bits


def _fd(value):
    if not _uint(value, 31):
        _fail()
    return value


def _parts(path):
    if (type(path) is not str or not path.startswith("/") or "\0" in path
            or len(path.encode("utf-8")) > MAX_PATH_BYTES):
        _fail()
    parts = tuple(path[1:].split("/"))
    if (not 1 <= len(parts) <= MAX_COMPONENTS
            or any(part in ("", ".", "..") or len(part.encode("utf-8")) > 255
                   for part in parts)):
        _fail()
    return parts


def _identity(facts, *, directory=False):
    fields = tuple(getattr(facts, key) for key in
                   ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode", "st_flags"))
    # Keep acquisition order (including generator exception semantics) and the
    # kind reads below unchanged. Unroll only pure exact-int uint64 validation:
    # this hot path must not pay six Python helper calls per observed object.
    dev, ino, uid, gid, mode, flags = fields
    if (type(dev) is not int or not 0 <= dev < 0x10000000000000000
            or type(ino) is not int or not 0 <= ino < 0x10000000000000000
            or type(uid) is not int or not 0 <= uid < 0x10000000000000000
            or type(gid) is not int or not 0 <= gid < 0x10000000000000000
            or type(mode) is not int or not 0 <= mode < 0x10000000000000000
            or type(flags) is not int or not 0 <= flags < 0x10000000000000000
            or (directory and not stat.S_ISDIR(facts.st_mode))
            or (not directory and not (stat.S_ISDIR(facts.st_mode)
                                       or stat.S_ISREG(facts.st_mode)))):
        _fail()
    return fields


def _observation(facts):
    identity = _identity(facts)
    extra = tuple(getattr(facts, key) for key in
                  ("st_nlink", "st_ctime_ns", "st_mtime_ns"))
    links, ctime, mtime = extra
    # The identity's six exact immutable ints were already validated above.
    if (type(links) is not int or not 0 <= links < 0x10000000000000000
            or type(ctime) is not int or not 0 <= ctime < 0x10000000000000000
            or type(mtime) is not int or not 0 <= mtime < 0x10000000000000000):
        _fail()
    return identity + extra


def _prefer_error(first, later):
    """First interruption wins; absent interruptions, preserve first failure."""
    if isinstance(first, (KeyboardInterrupt, SystemExit)):
        return first
    if first is None or isinstance(later, (KeyboardInterrupt, SystemExit)):
        return later
    return first


def _close_all(syscalls, descriptors):
    # Ownership is removed BEFORE close: an interrupted/failed close is never
    # retried, since the OS may already have released and reused that number.
    active_error = sys.exc_info()[1]
    selected = active_error
    while descriptors:
        descriptor = descriptors.pop()
        try:
            syscalls.close(descriptor)
        except BaseException as error:
            selected = _prefer_error(selected, error)
    if selected is not None and selected is not active_error:
        raise selected


class OwnedParent:
    """Owns the whole opened chain. Consumers borrow descriptor/uid/verify().

    Inputs are canonical absolute str paths; callers convert Path explicitly.
    No supplied descriptor is adopted. close() is idempotent; it closes all our
    handles even when one close fails. No finalizer performs hidden cleanup.
    """

    def __init__(self, token, syscalls, descriptors, identities, parts, root_depth, uid, modes):
        if token is not _ADMISSION:
            _fail()
        self._os, self._fds, self._identities = syscalls, descriptors, identities
        self._parts, self._root_depth = parts, root_depth
        self._uid, self._modes = uid, modes

    @classmethod
    @_redacted
    def open(cls, path, user_root, uid, *, modes=SAFE_MODES, syscalls=os):
        parts, root_parts = _parts(path), _parts(user_root)
        if (not _uint(uid, 32) or parts[:len(root_parts)] != root_parts
                or type(modes) not in (set, frozenset) or not 1 <= len(modes) <= 16
                or any(not _uint(mode, 12) or mode & ~0o777 or mode & 0o22
                       or mode & 0o700 != 0o700 for mode in modes)):
            _fail()
        modes, descriptors, identities = frozenset(modes), [], []
        transferred = False
        try:
            for depth, part in enumerate(("/",) + parts):
                descriptor = (syscalls.open(part, _OPEN_FLAGS) if depth == 0 else
                              syscalls.open(part, _OPEN_FLAGS, dir_fd=descriptors[-1]))
                descriptors.append(descriptor)
                _fd(descriptor)
                identity = _identity(syscalls.fstat(descriptor), directory=True)
                if depth >= len(root_parts) and (identity[2] != uid
                                                  or stat.S_IMODE(identity[4]) not in modes):
                    _fail()
                identities.append(identity)
            instance = cls(_ADMISSION, syscalls, descriptors, tuple(identities),
                           parts, len(root_parts), uid, modes)
            instance.verify()
            transferred = True
            return instance
        finally:
            if not transferred:
                _close_all(syscalls, descriptors)

    @property
    @_redacted
    def descriptor(self):
        if not self._fds:
            _fail()
        return self._fds[-1]

    @property
    def uid(self):
        return self._uid

    @_redacted
    def verify(self):
        if len(self._fds) != len(self._identities) or not self._fds:
            _fail()
        for depth, descriptor in enumerate(self._fds):
            identity = _identity(self._os.fstat(_fd(descriptor)), directory=True)
            named = (self._os.stat("/", follow_symlinks=False) if depth == 0 else
                     self._os.stat(self._parts[depth - 1], dir_fd=self._fds[depth - 1],
                                   follow_symlinks=False))
            if identity != self._identities[depth] or _identity(named, directory=True) != identity:
                _fail()
            if depth >= self._root_depth and (identity[2] != self._uid
                                              or stat.S_IMODE(identity[4]) not in self._modes):
                _fail()

    @_redacted
    def close(self):
        _close_all(self._os, self._fds)

    def __enter__(self):
        try:
            self.verify()
        except BaseException:
            self.close()
            raise
        return self

    def __exit__(self, error_type, error, *_):
        try:
            self.close()
        except BaseException as caught:
            selected = _prefer_error(error, caught)
            if selected is not error:
                raise selected from None


@dataclass(frozen=True, repr=False)
class Envelope:
    """Private bounded summary, intentionally without a field-revealing repr."""

    acl_entries: int
    xattr_names: tuple

    @_redacted
    def __post_init__(self):
        if (not _uint(self.acl_entries) or self.acl_entries > MAX_ACL_ENTRIES
                or type(self.xattr_names) is not tuple or len(self.xattr_names) > MAX_XATTR_NAMES
                or any(type(name) is not str or not name or "\0" in name
                       or len(name.encode("utf-8")) > XATTR_MAXNAMELEN for name in self.xattr_names)
                or tuple(sorted(set(self.xattr_names))) != self.xattr_names):
            _fail()


class DarwinEnvelope:
    """Exact SDK ctypes ABI; loading is lazy and tests inject the entire library.

    acl_get_entry is Darwin's 0-success / -1-EINVAL-end convention, not Linux's
    1-success / 0-end. NULL/ENOENT from acl_get_fd_np denotes no FILESEC_ACL;
    other NULL errors fail closed. An acquired working copy is freed once.
    """

    @_redacted
    def __init__(self, *, library=None, get_errno=ctypes.get_errno,
                 set_errno=ctypes.set_errno, platform=sys.platform):
        if platform != "darwin":
            _fail()
        if library is None:
            library = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
        self._lib, self._errno, self._set_errno = library, get_errno, set_errno
        signatures = (
            ("acl_get_fd_np", [ctypes.c_int, ctypes.c_int], ctypes.c_void_p),
            ("acl_get_entry", [ctypes.c_void_p, ctypes.c_int,
                               ctypes.POINTER(ctypes.c_void_p)], ctypes.c_int),
            ("acl_free", [ctypes.c_void_p], ctypes.c_int),
            ("flistxattr", [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t,
                            ctypes.c_int], ctypes.c_ssize_t),
        )
        for name, arguments, result in signatures:
            function = getattr(library, name)
            function.argtypes, function.restype = arguments, result

    @_redacted
    def acl_count(self, descriptor):
        descriptor = _fd(descriptor)
        self._set_errno(0)
        acl = self._lib.acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED)
        if not acl:
            if acl is None and self._errno() == errno.ENOENT:
                return 0
            _fail()
        try:
            count = 0
            while count <= MAX_ACL_ENTRIES:
                entry = ctypes.c_void_p()
                self._set_errno(0)
                result = self._lib.acl_get_entry(acl, ACL_FIRST_ENTRY if count == 0
                                                  else ACL_NEXT_ENTRY, ctypes.byref(entry))
                if type(result) is not int:
                    _fail()
                if result == -1 and self._errno() == errno.EINVAL:
                    return count
                if result != 0 or not entry.value:
                    _fail()
                count += 1
            _fail()
        finally:
            active_error = sys.exc_info()[1]
            try:
                result = self._lib.acl_free(acl)
                if type(result) is not int or result != 0:
                    _fail()
            except BaseException as caught:
                selected = _prefer_error(active_error, caught)
                if selected is not active_error:
                    raise selected from None

    @_redacted
    def xattr_names(self, descriptor):
        descriptor = _fd(descriptor)
        size = self._lib.flistxattr(descriptor, None, 0, XATTR_SHOWCOMPRESSION)
        if not _uint(size) or size > MAX_XATTR_BYTES:
            _fail()
        # A nonzero buffer even for an initially empty list detects new names.
        buffer = ctypes.create_string_buffer(max(1, size))
        actual = self._lib.flistxattr(descriptor, buffer, len(buffer), XATTR_SHOWCOMPRESSION)
        if type(actual) is not int or actual != size:
            _fail()
        raw = buffer.raw[:size]
        if not raw:
            return ()
        if raw[-1:] != b"\0":
            _fail()
        names = tuple(part.decode("utf-8", errors="strict") for part in raw[:-1].split(b"\0"))
        if len(set(names)) != len(names):
            _fail()
        return Envelope(0, tuple(sorted(names))).xattr_names


@_redacted
def observe_envelope(descriptor, *, syscalls=os, platform=None):
    """Two equal bounded observations bracketed by exact descriptor metadata."""
    descriptor = _fd(descriptor)
    platform = DarwinEnvelope() if platform is None else platform
    first = _observation(syscalls.fstat(descriptor))
    before = Envelope(platform.acl_count(descriptor), platform.xattr_names(descriptor))
    middle = _observation(syscalls.fstat(descriptor))
    after = Envelope(platform.acl_count(descriptor), platform.xattr_names(descriptor))
    final = _observation(syscalls.fstat(descriptor))
    if first != middle or first != final or before != after:
        _fail()
    return after


@_redacted
def require_empty_envelope(parent, *, syscalls=os, platform=None):
    """Admission for a NEW private sibling; never modify an inherited envelope.

    The caller owns parent lifetime and allocation/exclusivity evidence. This
    function proves only observed 0700/current-owner + empty metadata on the
    verified descriptor, not that the directory is new or free of other files.
    """
    descriptor, uid = _fd(parent.descriptor), parent.uid
    if not _uint(uid, 32) or parent.verify() is False:
        _fail()
    first = _identity(syscalls.fstat(descriptor), directory=True)
    if first[2] != uid or first[4] != stat.S_IFDIR | 0o700:
        _fail()
    envelope = observe_envelope(descriptor, syscalls=syscalls, platform=platform)
    if envelope.acl_entries or envelope.xattr_names or parent.verify() is False:
        _fail()
    if (type(parent.descriptor) is not int or parent.descriptor != descriptor
            or type(parent.uid) is not int or parent.uid != uid
            or _identity(syscalls.fstat(descriptor), directory=True) != first):
        _fail()
    return envelope
