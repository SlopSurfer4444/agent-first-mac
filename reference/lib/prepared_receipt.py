"""Descriptor-bound, no-replace publication of a prepared apply receipt.

This is a publication primitive, not source admission or apply authority. The
caller supplies the already validated receipt. All namespace edges from / stay
open and are rechecked; observations detect drift but are not namespace locks.
No existing directory is chmodded, no destination is replaced, and no file is
unlinked: portable stat-then-unlink cannot exclude a replacement race. The
random private staging name is deliberately retained as recovery evidence,
including after publication. Only the exact <commit>.json name is consumable.
"""

import json
import os
from pathlib import Path
import re
import secrets
import stat


class ReceiptError(ValueError):
    """A bounded reason only; filesystem paths and native errors stay private."""


_DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
_SUFFIX = ("AIDev", "state", "phase-4", "apply-receipts")
_MAX_BYTES = 1024 * 1024


def _require(condition, reason):
    if not condition:
        raise ReceiptError(reason)


def _identity(facts):
    return (facts.st_dev, facts.st_ino, facts.st_uid, facts.st_gid,
            facts.st_mode, getattr(facts, "st_flags", 0))


def _retry(function, *args, **kwargs):
    while True:
        try:
            return function(*args, **kwargs)
        except InterruptedError:
            continue


class _Chain:
    def __init__(self, home):
        self.entries = []
        self.home_depth = len(home.parts) - 1
        self.uid = os.getuid()

    def close(self):
        first_error = None
        while self.entries:
            descriptor, *_ = self.entries.pop()
            try:
                # A failed close may have released the fd; never retry it.
                os.close(descriptor)
            except OSError as error:
                first_error = first_error or error
        if first_error is not None:
            raise ReceiptError("receipt_close_failed") from None

    @property
    def descriptor(self):
        return self.entries[-1][0]

    def _policy(self, facts, depth):
        _require(stat.S_ISDIR(facts.st_mode), "receipt_parent_not_directory")
        # Ancestors preceding HOME are identity-bound, not asserted private.
        # This also permits root-owned sticky temporary ancestors in fixtures.
        if depth >= self.home_depth:
            _require(facts.st_uid == self.uid and
                     stat.S_IMODE(facts.st_mode) in (0o700, 0o750, 0o755),
                     "receipt_parent_metadata")
        if depth == self.home_depth + len(_SUFFIX):
            _require(stat.S_IMODE(facts.st_mode) == 0o700,
                     "receipt_directory_not_private")

    def verify(self):
        for depth, (descriptor, name, expected) in enumerate(self.entries):
            facts = os.fstat(descriptor)
            self._policy(facts, depth)
            _require(_identity(facts) == expected, "receipt_parent_drift")
            if depth:
                named = os.stat(name, dir_fd=self.entries[depth - 1][0],
                                follow_symlinks=False)
            else:
                named = os.stat("/", follow_symlinks=False)
            _require(_identity(named) == expected, "receipt_parent_drift")

    def open(self, home):
        root = os.open("/", _DIRECTORY)
        self.entries.append((root, "/", None))
        self.entries[-1] = (root, "/", _identity(os.fstat(root)))
        components = home.parts[1:] + _SUFFIX
        for depth, name in enumerate(components, 1):
            self.verify()
            parent = self.descriptor
            created = False
            if depth > self.home_depth:
                try:
                    os.mkdir(name, mode=0o700, dir_fd=parent)
                    created = True
                except FileExistsError:
                    pass
            child = os.open(name, _DIRECTORY, dir_fd=parent)
            # Own the fd before any potentially failing metadata observation.
            self.entries.append((child, name, None))
            self.entries[-1] = (child, name, _identity(os.fstat(child)))
            self.verify()
            if created:
                _retry(os.fsync, child)
                _retry(os.fsync, parent)
                self.verify()
        self.verify()


def _write_all(descriptor, data):
    offset = 0
    while offset < len(data):
        count = _retry(os.write, descriptor, data[offset:])
        _require(type(count) is int and 0 < count <= len(data) - offset,
                 "receipt_short_write")
        offset += count


def _verify_file(descriptor, directory, name, expected, data, links):
    before = os.fstat(descriptor)
    _require(_identity(before) == expected and stat.S_ISREG(before.st_mode)
             and before.st_uid == os.getuid()
             and stat.S_IMODE(before.st_mode) == 0o400
             and before.st_nlink == links and before.st_size == len(data),
             "receipt_metadata")
    _retry(os.lseek, descriptor, 0, os.SEEK_SET)
    actual = bytearray()
    while len(actual) <= len(data):
        part = _retry(os.read, descriptor, min(65536, len(data) + 1 - len(actual)))
        if not part:
            break
        actual.extend(part)
    _require(bytes(actual) == data, "receipt_content_mismatch")
    after = os.fstat(descriptor)
    named = os.stat(name, dir_fd=directory, follow_symlinks=False)
    stamp = lambda facts: (_identity(facts), facts.st_size, facts.st_nlink,
                           facts.st_mtime_ns, facts.st_ctime_ns)
    _require(stamp(before) == stamp(after) == stamp(named), "receipt_file_drift")


def publish_receipt(home: Path, commit: str, value: dict) -> Path:
    """Publish exact canonical JSON once; failures retain all uncertain names.

    HOME must be an absolute canonical nonsymlink path. Relevant directories
    must be caller-owned safe-mode directories; the receipt directory is0700.
    New directories are0700. Existing metadata is preserved, not repaired.
    A publication failure after link may leave a final name whose ownership or
    bytes are UNKNOWN (including a raced staging replacement). Callers must
    reconcile it, not consume, automatically retry, remove or report it ready.
    """
    _require(isinstance(home, Path) and home.is_absolute() and
             home != Path("/") and ".." not in home.parts and
             len(home.parts) <= 128 and len(str(home).encode()) <= 4096,
             "receipt_home_invalid")
    _require(type(commit) is str and re.fullmatch(r"[0-9a-f]{40}", commit)
             is not None, "receipt_commit_invalid")
    _require(type(value) is dict and value.get("controlCommit") == commit,
             "receipt_value_invalid")
    try:
        data = (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()
    except (TypeError, ValueError, UnicodeError):
        raise ReceiptError("receipt_value_invalid") from None
    _require(len(data) <= _MAX_BYTES, "receipt_value_too_large")
    chain = _Chain(home)
    descriptor = None
    try:
        chain.open(home)
        name = commit + ".json"
        temporary = ".prepared-" + commit + "-" + secrets.token_hex(16) + ".tmp"
        descriptor = os.open(temporary, _FILE, 0o400, dir_fd=chain.descriptor)
        expected = _identity(os.fstat(descriptor))
        chain.verify()
        _write_all(descriptor, data)
        _retry(os.fsync, descriptor)
        _verify_file(descriptor, chain.descriptor, temporary, expected, data, 1)
        chain.verify()
        # linkat is atomic and never replaces an existing destination, even if
        # it appeared after the last observation. Both names use the held fd.
        os.link(temporary, name, src_dir_fd=chain.descriptor,
                dst_dir_fd=chain.descriptor, follow_symlinks=False)
        chain.verify()
        _verify_file(descriptor, chain.descriptor, temporary, expected, data, 2)
        _verify_file(descriptor, chain.descriptor, name, expected, data, 2)
        _retry(os.fsync, descriptor)
        _retry(os.fsync, chain.descriptor)
        _verify_file(descriptor, chain.descriptor, name, expected, data, 2)
        chain.verify()
        return home.joinpath(*_SUFFIX, name)
    except ReceiptError:
        raise
    except OSError:
        raise ReceiptError("receipt_publication_failed") from None
    finally:
        try:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    raise ReceiptError("receipt_close_failed") from None
        finally:
            chain.close()
