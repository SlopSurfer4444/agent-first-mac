"""Private, fixed-name session records over one borrowed verified parent.

No directory opening/allocation, dispatch, JSON interpretation, rename, unlink,
replacement, retry or compensation. Failed creations retain partial files.
read() proves stable observed bytes, NOT durability. sync_record() freshly binds
exact expected bytes, full file stamp and named parent on every call. A completed
file+directory fsync barrier may be reused only within this Store instance for
the exact same file AND full directory generation. Any error/interrupt discards
all reusable proofs. put_exclusive() always performs the full barrier.
Prior fsync evidence and fresh generation checks remain point-in-time facts,
not continuous exclusion or a way to rehabilitate a substituted record name.

The caller owns the parent's complete named-chain verification and lifetime.
Parent mode is exactly0700; record mode is exactly0600. ACL/xattr confidentiality
is an ADDITIONAL explicit caller admission, not something these mode checks
prove. Stat checks include uid/gid/nlink/mode/flags/size/mtime/ctime, but do not
claim ACL/xattr preservation, continuous exclusion or durability beyond fsync.
"""

import functools
import hashlib
import os
import re
import stat

from lib.phase5_runtime_paths import _close_all


MAX_RECORD_BYTES = 40 * 1024 * 1024
CHUNK_BYTES = 65536
_NAMES = re.compile(
    r"(?:capture|(?:rollback|return)\.(?:ticket\.[0-7]|"
    r"(?:initial|resume)\.(?:intent|failure|terminal|result\.[0-7])))"
)
_READ_FLAGS = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
_CREATE_FLAGS = (os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
                 | os.O_NOFOLLOW | os.O_NONBLOCK)


class StoreError(ValueError):
    """Only a fixed redacted error is public; private/native values stay local."""


def _fail():
    raise StoreError("runtime_store_recovery_required") from None


def _redacted(function):
    @functools.wraps(function)
    def wrapped(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except BaseException as error:
            # A failed observation or ambiguous close cannot preserve a proof.
            if args:
                proofs = getattr(args[0], "_barriers", None)
                if type(proofs) is dict:
                    proofs.clear()
            if isinstance(error, Exception):
                _fail()
            raise
    return wrapped


def _uint(value):
    return type(value) is int and 0 <= value < 2 ** 64


def _descriptor(value):
    return type(value) is int and 0 <= value < 2 ** 31


def _name(value):
    if type(value) is not str or _NAMES.fullmatch(value) is None:
        _fail()
    return value


def _raw(value):
    if type(value) is not bytes or len(value) > MAX_RECORD_BYTES:
        _fail()
    return value


def _file_facts(facts, uid):
    fields = tuple(getattr(facts, key) for key in (
        "st_dev", "st_ino", "st_uid", "st_gid", "st_nlink", "st_mode",
        "st_flags", "st_size", "st_mtime_ns", "st_ctime_ns"))
    if (not all(_uint(value) for value in fields)
            or facts.st_mode != stat.S_IFREG | 0o600
            or facts.st_uid != uid or facts.st_nlink != 1
            or facts.st_size > MAX_RECORD_BYTES):
        _fail()
    return fields


class DurableStore:
    """Fixed session Store API. Tests must explicitly inject fake syscalls.

    The borrowed parent supplies descriptor, uid and raising verify(). A False
    result also fails. No parent descriptor is closed or replaced here.
    """

    @_redacted
    def __init__(self, parent, *, syscalls=os):
        if (not _descriptor(parent.descriptor) or not _uint(parent.uid)
                or not callable(parent.verify)):
            _fail()
        self._parent, self._os = parent, syscalls
        self._descriptor, self._uid = parent.descriptor, parent.uid
        self._parent_identity = None
        self._pins = {}
        self._barriers = {}
        self.verify()

    @_redacted
    def verify(self):
        parent = self._parent
        if (not _descriptor(parent.descriptor) or parent.descriptor != self._descriptor
                or type(parent.uid) is not int or parent.uid != self._uid
                or parent.verify() is False):
            _fail()
        facts = self._os.fstat(self._descriptor)
        fields = tuple(getattr(facts, key) for key in
                       ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode", "st_flags"))
        if (not all(_uint(value) for value in fields)
                or facts.st_mode != stat.S_IFDIR | 0o700 or facts.st_uid != self._uid):
            _fail()
        if self._parent_identity is None:
            self._parent_identity = fields
        elif fields != self._parent_identity:
            _fail()

    def _pin(self, name, identity):
        if name in self._pins and self._pins[name] != identity:
            _fail()
        self._pins[name] = identity

    def _directory_generation(self):
        self.verify()
        facts = self._os.fstat(self._descriptor)
        fields = tuple(getattr(facts, key) for key in (
            "st_dev", "st_ino", "st_uid", "st_gid", "st_nlink", "st_mode",
            "st_flags", "st_size", "st_mtime_ns", "st_ctime_ns"))
        if (not all(_uint(value) for value in fields)
                or facts.st_mode != stat.S_IFDIR | 0o700 or facts.st_uid != self._uid):
            _fail()
        self.verify()
        return fields

    def _read_fd(self, descriptor, name):
        self.verify()
        first = _file_facts(self._os.fstat(descriptor), self._uid)
        self._pin(name, first[:2])
        chunks, count = [], 0
        while count <= MAX_RECORD_BYTES:
            requested = min(CHUNK_BYTES, MAX_RECORD_BYTES + 1 - count)
            chunk = self._os.pread(descriptor, requested, count)
            if type(chunk) is not bytes or len(chunk) > requested:
                _fail()
            if not chunk:
                break
            chunks.append(chunk)
            count += len(chunk)
        raw = b"".join(chunks)
        final = _file_facts(self._os.fstat(descriptor), self._uid)
        named = _file_facts(self._os.stat(name, dir_fd=self._descriptor,
                                         follow_symlinks=False), self._uid)
        if first != final or first != named or len(raw) != first[7]:
            _fail()
        self.verify()
        return raw, final

    @_redacted
    def read(self, name):
        name = _name(name)
        self.verify()
        try:
            descriptor = self._os.open(name, _READ_FLAGS, dir_fd=self._descriptor)
        except FileNotFoundError:
            try:
                self._os.stat(name, dir_fd=self._descriptor, follow_symlinks=False)
            except FileNotFoundError:
                self.verify()
                self._pin(name, None)
                return None
            _fail()
        try:
            return self._read_fd(descriptor, name)[0]
        finally:
            _close_all(self._os, [descriptor])

    def _barrier(self, descriptor, name, expected, creation_envelope=None):
        directory = self._directory_generation()
        raw, first = self._read_fd(descriptor, name)
        if raw != expected or (creation_envelope is not None and first[:7] != creation_envelope):
            _fail()
        if self._directory_generation() != directory:
            _fail()
        proof = first, directory, hashlib.sha256(expected).digest()
        previous = self._barriers.pop(name, None)
        if creation_envelope is not None or previous != proof:
            self.verify()
            self._os.fsync(descriptor)
            self.verify()
            self._os.fsync(self._descriptor)
            self.verify()
        raw, final = self._read_fd(descriptor, name)
        if raw != expected or first != final or self._directory_generation() != directory:
            _fail()
        # Published only after the complete barrier/readback. The public API
        # wrapper also invalidates this proof if the final close fails.
        self._barriers[name] = proof

    @_redacted
    def sync_record(self, name, expected_raw):
        name, expected_raw = _name(name), _raw(expected_raw)
        self.verify()
        descriptor = self._os.open(name, _READ_FLAGS, dir_fd=self._descriptor)
        try:
            self._barrier(descriptor, name, expected_raw)
        finally:
            _close_all(self._os, [descriptor])

    @_redacted
    def put_exclusive(self, name, raw):
        name, raw = _name(name), _raw(raw)
        if name in self._pins and self._pins[name] is not None:
            _fail()
        self.verify()
        descriptor = self._os.open(name, _CREATE_FLAGS, 0o600, dir_fd=self._descriptor)
        try:
            facts = self._os.fstat(descriptor)
            identity = (facts.st_dev, facts.st_ino)
            if not all(_uint(value) for value in identity):
                _fail()
            # The ONLY allowed absence-to-presence pin change is our successful
            # exclusive creation. Retain its identity even if later checks fail.
            self._pins[name] = identity
            first = _file_facts(facts, self._uid)
            if first[6] != 0 or first[7] != 0:
                _fail()
            offset = 0
            while offset < len(raw):
                self.verify()
                count = self._os.write(descriptor, raw[offset:offset + CHUNK_BYTES])
                if type(count) is not int or not 0 < count <= min(CHUNK_BYTES, len(raw) - offset):
                    _fail()
                offset += count
            self._barrier(descriptor, name, raw, first[:7])
        finally:
            # Preserve partial/unknown state. Never retry an ambiguous close:
            # the OS may already have released and reused that descriptor.
            _close_all(self._os, [descriptor])
