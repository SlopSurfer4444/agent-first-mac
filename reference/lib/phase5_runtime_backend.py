"""Borrowed-parent macOS descriptor backend; no opener, journal or authority.

The caller owns the held parent's canonical named-chain verification and its
lifetime. This adapter never opens a parent, closes the borrowed descriptor,
unlinks, retries, compensates or dispatches a lifecycle. Failed creation retains
even a partial staging file. Recovery/retirement belongs to the caller.

Image.seal binds uid, gid, link count, flags and mtime_ns (rename-stable stat
fields), not ACLs, xattrs or creation time. ctime_ns is compared within each
read, not across rename. No confidentiality/ACL preservation, filesystem CAS,
continuous chain exclusion or power-loss durability beyond successful fsync is
claimed. Checks cannot prevent a substitution between observation and rename;
postchecks fail with all remaining names retained. Independent admission must
settle any additional metadata policy before production use.
"""

import ctypes
import functools
import os
import re
import stat
import struct
import sys

from lib.phase5_runtime_transition import ABSENT, Image, MAX_IMAGE_BYTES


RENAME_SWAP = 0x00000002
RENAME_EXCL = 0x00000004
READ_FLAGS = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
CREATE_FLAGS = (os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
                | os.O_NOFOLLOW | os.O_NONBLOCK)


class BackendError(ValueError):
    """Fixed public reason only; native errors and private values do not escape."""


def _fail():
    raise BackendError("runtime_backend_recovery_required") from None


def _redacted(function):
    @functools.wraps(function)
    def wrapped(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except Exception:
            _fail()
    return wrapped


def _uint(value):
    return type(value) is int and 0 <= value < 2 ** 64


def _descriptor(value):
    return type(value) is int and 0 <= value < 2 ** 31


def _leaf(value):
    if (type(value) is not str or value in (".", "..")
            or re.fullmatch(r"[A-Za-z0-9._-]{1,128}", value) is None):
        _fail()
    return value


def _mode(value):
    return (type(value) is int and 0 <= value <= 0o777
            and bool(value & 0o400) and not value & 0o022)


def _facts(value, uid, maximum):
    names = ("st_dev", "st_ino", "st_uid", "st_gid", "st_nlink", "st_mode",
             "st_flags", "st_size", "st_mtime_ns", "st_ctime_ns")
    result = tuple(getattr(value, name) for name in names)
    if (not all(_uint(n) for n in result) or value.st_mode > 0xffff
            or not stat.S_ISREG(value.st_mode)
            or value.st_uid != uid or value.st_nlink != 1
            or value.st_mode & 0o7000 or not _mode(stat.S_IMODE(value.st_mode))
            or value.st_size > maximum):
        _fail()
    return result


def _image(data, value):
    seal = struct.pack("!5Q", value.st_uid, value.st_gid, value.st_nlink,
                       value.st_flags, value.st_mtime_ns)
    return Image(data, (value.st_dev, value.st_ino), stat.S_IMODE(value.st_mode), seal)


def _native_rename(descriptor, source, destination, flag):
    # Apple's SDK sys/stdio.h: renameatx_np(dirfd, leaf, dirfd, leaf, flags).
    # No os.rename/replace fallback on unsupported platforms or filesystems.
    if (sys.platform != "darwin" or not _descriptor(descriptor)
            or type(flag) is not int or flag not in (RENAME_SWAP, RENAME_EXCL)):
        _fail()
    source, destination = _leaf(source), _leaf(destination)
    if source == destination:
        _fail()
    library = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    function = library.renameatx_np
    function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                         ctypes.c_char_p, ctypes.c_uint]
    function.restype = ctypes.c_int
    if function(descriptor, source.encode("ascii"), descriptor,
                destination.encode("ascii"), flag) != 0:
        _fail()


class DescriptorBackend:
    """Capability adapter over ONE borrowed parent and explicitly injected I/O.

    syscalls defaults to os; rename defaults to the strict macOS primitive.
    Tests must inject both. Construction verifies the parent but creates no
    files. The parent must expose descriptor, uid and a raising verify().
    A literal False verification result is rejected as well.
    """

    @_redacted
    def __init__(self, parent, *, syscalls=os, rename=None, maximum=MAX_IMAGE_BYTES):
        if (type(maximum) is not int or not 0 <= maximum <= MAX_IMAGE_BYTES
                or not _descriptor(parent.descriptor)
                or not _uint(parent.uid) or not callable(parent.verify)
                or (rename is not None and not callable(rename))):
            _fail()
        self._parent, self._os = parent, syscalls
        self._descriptor, self._uid = parent.descriptor, parent.uid
        self._maximum = maximum
        self._rename = _native_rename if rename is None else rename
        self._parent_identity = None
        self.verify()

    @_redacted
    def verify(self):
        parent = self._parent
        if (not _descriptor(parent.descriptor) or parent.descriptor != self._descriptor
                or type(parent.uid) is not int or parent.uid != self._uid
                or parent.verify() is False):
            _fail()
        facts = self._os.fstat(self._descriptor)
        fields = (facts.st_dev, facts.st_ino, facts.st_uid, facts.st_gid,
                  facts.st_mode, facts.st_flags)
        if (not all(_uint(n) for n in fields) or facts.st_mode > 0xffff
                or not stat.S_ISDIR(facts.st_mode)
                or facts.st_uid != self._uid or facts.st_mode & 0o7022):
            _fail()
        if self._parent_identity is None:
            self._parent_identity = fields
        elif self._parent_identity != fields:
            _fail()

    @_redacted
    def snapshot(self, leaf):
        leaf = _leaf(leaf)
        self.verify()
        try:
            descriptor = self._os.open(leaf, READ_FLAGS, dir_fd=self._descriptor)
        except FileNotFoundError:
            # Verify absence again without following a newly introduced link.
            try:
                self._os.stat(leaf, dir_fd=self._descriptor, follow_symlinks=False)
            except FileNotFoundError:
                self.verify()
                return ABSENT
            _fail()
        try:
            first = self._os.fstat(descriptor)
            observation = _facts(first, self._uid, self._maximum)
            chunks, count = [], 0
            while count <= self._maximum:
                requested = min(65536, self._maximum + 1 - count)
                chunk = self._os.read(descriptor, requested)
                if type(chunk) is not bytes or len(chunk) > requested:
                    _fail()
                if not chunk:
                    break
                chunks.append(chunk)
                count += len(chunk)
            value = b"".join(chunks)
            final = self._os.fstat(descriptor)
            named = self._os.stat(leaf, dir_fd=self._descriptor, follow_symlinks=False)
            if (_facts(final, self._uid, self._maximum) != observation
                    or _facts(named, self._uid, self._maximum) != observation
                    or len(value) != first.st_size):
                _fail()
            self.verify()
            return _image(value, final)
        finally:
            self._os.close(descriptor)

    @_redacted
    def create_exclusive(self, leaf, data, mode, *, admit_descriptor=None):
        """Optionally admit the new empty FD before writing any payload.

The caller-owned callback must only observe the borrowed FD, never close or
mutate it, and return exactly True. Failure retains the empty staging object.
This is one pre-write observation boundary, not continuous metadata custody.
"""
        leaf = _leaf(leaf)
        if (type(data) is not bytes or len(data) > self._maximum or not _mode(mode)
                or admit_descriptor is not None and not callable(admit_descriptor)):
            _fail()
        self.verify()
        # Stage privately even when the admitted final mode is world-readable.
        descriptor = self._os.open(leaf, CREATE_FLAGS, 0o600, dir_fd=self._descriptor)
        try:
            first = self._os.fstat(descriptor)
            initial_observation = _facts(first, self._uid, self._maximum)
            identity = (first.st_dev, first.st_ino)
            if first.st_size != 0 or first.st_flags != 0:
                _fail()
            if admit_descriptor is not None:
                if admit_descriptor(descriptor) is not True:
                    _fail()
                self.verify()
                if (_facts(self._os.fstat(descriptor), self._uid, self._maximum) != initial_observation
                        or _facts(self._os.stat(leaf, dir_fd=self._descriptor, follow_symlinks=False),
                                  self._uid, self._maximum) != initial_observation):
                    _fail()
            offset = 0
            while offset < len(data):
                self.verify()
                count = self._os.write(descriptor, data[offset:offset + 65536])
                if type(count) is not int or not 0 < count <= min(65536, len(data) - offset):
                    _fail()
                offset += count
            self.verify()
            self._os.fchmod(descriptor, mode)
            self._os.fsync(descriptor)
            final = self._os.fstat(descriptor)
            final_observation = _facts(final, self._uid, self._maximum)
            if ((final.st_dev, final.st_ino) != identity or final.st_size != len(data)
                    or stat.S_IMODE(final.st_mode) != mode or final.st_flags != 0):
                _fail()
            expected = _image(data, final)
            if self.snapshot(leaf) != expected:
                _fail()
            self.sync()
            if (_facts(self._os.fstat(descriptor), self._uid, self._maximum)
                    != final_observation or self.snapshot(leaf) != expected):
                _fail()
            return expected
        finally:
            # On ANY failure, retain the partial file. Never retry close after
            # ambiguity: the descriptor number might already have been reused.
            interrupted = sys.exc_info()[1]
            try:
                self._os.close(descriptor)
            except BaseException:
                if isinstance(interrupted, (KeyboardInterrupt, SystemExit)):
                    raise interrupted from None
                raise

    def swap(self, source, destination):
        return self._move(source, destination, RENAME_SWAP)

    def move_exclusive(self, source, destination):
        return self._move(source, destination, RENAME_EXCL)

    @_redacted
    def _move(self, source, destination, flag):
        source, destination = _leaf(source), _leaf(destination)
        if source == destination:
            _fail()
        before_source, before_destination = self.snapshot(source), self.snapshot(destination)
        if before_source == ABSENT or (flag == RENAME_SWAP) == (before_destination == ABSENT):
            _fail()
        self.verify()
        if self._rename(self._descriptor, source, destination, flag) is not None:
            _fail()
        self.verify()
        expected_source = before_destination if flag == RENAME_SWAP else ABSENT
        if (self.snapshot(source) != expected_source
                or self.snapshot(destination) != before_source):
            _fail()

    @_redacted
    def sync(self):
        self.verify()
        self._os.fsync(self._descriptor)
        self.verify()
