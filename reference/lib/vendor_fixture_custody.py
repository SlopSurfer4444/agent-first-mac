"""Private fixed-slot diagnostic custody. No scanning/adoption of old scratch.

Eight outstanding artifact reservations and a measured retained-byte admission
budget, not an OS disk quota. In-flight writes may overshoot; never delete the
overshoot or infer settlement from process/time observations.
"""
import fcntl
import ctypes
import errno
import hashlib
import json
import os
import re
import secrets
import stat
import struct
import copy
from pathlib import Path

from lib import phase5_runtime_paths as paths

SLOTS = 8
MAX_RECORD = 512 * 1024
MAX_BYTES = 64 * 1024 * 1024
MAX_ENTRIES = 8192
MAX_DEPTH = 8
MAX_OUTPUT_ENTRIES = 1024
MAX_OUTPUT_BYTES = 16 * 1024 * 1024
OUTPUT_DIRS = frozenset(("home", "codex", "cwd", "tmp", "schema", "schema/v1",
                         "schema/v2", "codex/tmp", "codex/tmp/arg0"))
NAMESPACE = "vendor-sentinel-custody"
TRANSACTION = 'transaction.json'
MAX_PREPARATIONS = 32
CHILDREN = ("home", "codex", "cwd", "tmp", "schema")
SCHEMAS = ("codex_app_server_protocol.schemas.json", "JSONRPCMessage.json")
STATES = ("reserved", "allocated", "inflight", "retained", "retiring")


class CustodyError(ValueError):
    def __init__(self, reason="fixture_custody_invalid"):
        self.reason_class = reason
        super().__init__(reason)


def need(value, reason="fixture_custody_invalid"):
    if value is not True:
        raise CustodyError(reason)


def identity(info):
    return [info.st_dev, info.st_ino, info.st_uid, info.st_mode]


def stamp(info):
    return [getattr(info, key) for key in ("st_dev", "st_ino", "st_mode", "st_uid",
            "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")]


def namespace_boot():
    """Private kernel boot provenance, not a durable machine identifier."""
    class Timeval(ctypes.Structure):
        _fields_ = [("seconds", ctypes.c_long), ("micros", ctypes.c_int)]
    value = Timeval()
    size = ctypes.c_size_t(ctypes.sizeof(value))
    libc = ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True)
    libc.sysctlbyname.argtypes = (ctypes.c_char_p, ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_size_t), ctypes.c_void_p, ctypes.c_size_t)
    libc.sysctlbyname.restype = ctypes.c_int
    need(libc.sysctlbyname(b'kern.boottime', ctypes.byref(value), ctypes.byref(size), None, 0) == 0
         and size.value == ctypes.sizeof(value) and value.seconds > 0
         and 0 <= value.micros < 1000000)
    return hashlib.sha256(('%d:%d' % (value.seconds, value.micros)).encode()).hexdigest()


def namespace_persistent_identity(fd):
    """Read stable volume/birth identity from a held Darwin descriptor.

    This private metadata is only for the empty custody namespace. It never
    replaces the exact device/inode guards on fixtures or live descriptors.
    No path-based diskutil invocation or permissive unsupported-FS fallback.
    """
    class Attrlist(ctypes.Structure):
        _fields_ = [('count', ctypes.c_uint16), ('reserved', ctypes.c_uint16)] + [
            (name, ctypes.c_uint32) for name in ('common', 'volume', 'directory', 'file', 'fork')]
    libc = ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True)
    libc.fgetattrlist.argtypes = (ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p,
                                ctypes.c_size_t, ctypes.c_ulong)
    libc.fgetattrlist.restype = ctypes.c_int
    def query(common, volume):
        attrs = Attrlist(5, 0, common, volume, 0, 0, 0)
        buffer = ctypes.create_string_buffer(20)
        need(libc.fgetattrlist(fd, ctypes.byref(attrs), buffer, 20, 0) == 0
             and struct.unpack_from('=I', buffer.raw)[0] == 20)
        return buffer.raw[4:]
    volume = query(0, 0x80040000)  # ATTR_VOL_INFO | ATTR_VOL_UUID
    seconds, nanos = struct.unpack('=qq', query(0x200, 0))  # ATTR_CMN_CRTIME
    need(any(volume) and seconds > 0 and 0 <= nanos < 1000000000)
    return {'volume': volume.hex(), 'birth': [seconds, nanos]}


def names(descriptor, maximum=MAX_ENTRIES):
    """Incremental fixed-work listing, never materialize unknown cardinality."""
    result = []
    with os.scandir(descriptor) as entries:
        for entry in entries:
            need(len(result) < maximum, "fixture_capacity_required")
            result.append(entry.name)
    return result


def rename_exclusive(parent, source, target):
    libc = ctypes.CDLL(None, use_errno=True)
    function = libc.renameatx_np
    function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    function.restype = ctypes.c_int
    if function(parent, os.fsencode(source), parent, os.fsencode(target), 4):
        raise OSError(ctypes.get_errno(), 'exclusive_custody_publication_refused')


def preparation_name(name):
    return re.fullmatch(r'\.prepare-[0-9a-f]{32}\.(payload|journal)', name) is not None


class Custody:
    def __init__(self, scratch, home, uid, *, create=True, reconcile=False, envelope=None, checkpoint=None,
                 persistent_identity=None, boot_identity=None):
        self.scratch, self.home, self.uid = scratch, home, uid
        writable = create or reconcile
        self.envelope = envelope or (lambda handle, module: module.require_empty_envelope(handle))
        self.checkpoint = checkpoint or (lambda point: None)
        self.persistent_identity = persistent_identity or namespace_persistent_identity
        self.boot = (boot_identity or namespace_boot)()
        need(type(self.boot) is str and re.fullmatch('[0-9a-f]{64}', self.boot) is not None)
        self.handles, self.lock = [], None
        self.fds, self.close_attempts = [], {}
        self.created = False
        self.mutation_reason = None
        self.pending_metadata = []
        self.namespace_refresh_required = False
        self.namespace_refresh_records = {}
        self.fresh_slots = set()
        self.retirement_slot = None
        self.path = scratch + "/" + NAMESPACE
        try:
            self.parent = paths.OwnedParent.open(scratch, home, uid)
            self._hold(self.parent)
            try:
                os.stat(NAMESPACE, dir_fd=self.parent.descriptor, follow_symlinks=False)
            except FileNotFoundError:
                need(create, "fixture_custody_absent")
                retained = [name for name in names(self.parent.descriptor)
                            if name.startswith('.' + NAMESPACE + '-')]
                need(len(retained) < MAX_PREPARATIONS, 'fixture_preparation_capacity')
                initial = '.' + NAMESPACE + '-' + secrets.token_hex(16)
                os.mkdir(initial, 0o700, dir_fd=self.parent.descriptor)
                self.checkpoint('namespace-prepared')
                self.created = True
                os.fsync(self.parent.descriptor)
                self.directory = paths.OwnedParent.open(scratch + '/' + initial, home, uid)
                self._hold(self.directory)
                self.envelope(self.directory, paths)
                marker = None
            else:
                self.directory = paths.OwnedParent.open(self.path, home, uid)
                self._hold(self.directory)
                self.envelope(self.directory, paths)
                marker, _ = self._read("namespace.json")
                self._namespace_marker(marker, include_lock=False)
            self.lock = os.open("lock", os.O_RDWR | (os.O_CREAT | os.O_EXCL if self.created else 0) | os.O_NOFOLLOW | os.O_CLOEXEC,
                                0o600, dir_fd=self.directory.descriptor)
            self._register(self.lock)
            info = os.fstat(self.lock)
            need(stat.S_ISREG(info.st_mode) and info.st_uid == uid
                 and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1 and info.st_size == 0)
            self.lock_identity = identity(info)
            need(identity(os.stat("lock", dir_fd=self.directory.descriptor, follow_symlinks=False)) == self.lock_identity)
            try:
                fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise CustodyError("fixture_custody_busy") from None
            if self.created:
                os.fsync(self.lock)
                self._write_preparation('namespace.json', self._new_namespace_marker())
                os.fsync(self.directory.descriptor)
                self.checkpoint('namespace-ready')
                self.parent.verify()
                self.directory.verify()
                need(set(names(self.directory.descriptor, 2)) == {'namespace.json', 'lock'})
                self._verify_lock()
                need(self._namespace_marker(self._read('namespace.json')[0], include_lock=True) is False)
                rename_exclusive(self.parent.descriptor, initial, NAMESPACE)
                self.checkpoint('namespace-published')
                os.fsync(self.parent.descriptor)
                self.directory.close()
                self.directory = paths.OwnedParent.open(self.path, home, uid)
                self._hold(self.directory)
                self._verify_lock()
                need(self._namespace_marker(self._read('namespace.json')[0], include_lock=True) is False)
            else:
                if TRANSACTION in names(self.directory.descriptor):
                    if writable:
                        self._recover_transaction()
                    else:
                        self.mutation_reason = 'fixture_metadata_pending'
                # Re-read only after acquiring the named lock: neither a pre-lock
                # marker nor a pre-lock empty-slot observation can admit refresh.
                marker, prior = self._read("namespace.json")
                refresh = self._namespace_marker(marker, include_lock=True)
                if writable and marker['schema'] == 1 and self._record_names() == {'namespace.json', 'lock'}:
                    # Exact legacy identity was verified above. Upgrade only an
                    # empty namespace; never infer identity for a stale marker.
                    refresh = True
                if refresh and not writable:
                    # Observation is not allocation or identity migration. Keep
                    # the verified old marker and expose the affected boundary.
                    self.namespace_refresh_required = True
                elif refresh:
                    present = self._record_names()
                    if present != {'namespace.json', 'lock'}:
                        # Refresh the namespace against the exact unchanged
                        # record closure. Rebinding one fixture must not depend
                        # on settlement or persistent proof of another slot.
                        records = self.records()
                        self.namespace_refresh_records = {str(slot) + '.json': self._read(str(slot) + '.json')[1]
                                                          for slot in records}
                    expected = {'namespace.json', 'lock'} | set(self.namespace_refresh_records)
                    need(present == expected)
                    self.checkpoint('namespace-refresh-ready')
                    self.directory.verify()
                    self._verify_lock()
                    need(self._record_names() == expected)
                    need(self._namespace_marker(marker, include_lock=True) or marker['schema'] == 1)
                    self._publish('namespace.json', self._new_namespace_marker(), prior)
                    installed, _ = self._read('namespace.json')
                    need(self._namespace_marker(installed, include_lock=True) is False)
            os.fsync(self.directory.descriptor)
            allowed = {"namespace.json", "lock"} | {str(slot) + ".json" for slot in range(SLOTS)}
            pending = {name + '.pending' for name in allowed if name != 'lock'}
            observed = set(names(self.directory.descriptor, MAX_ENTRIES))
            preparations = {name for name in observed if preparation_name(name)}
            need(not writable or len(preparations) <= MAX_PREPARATIONS * 2, 'fixture_preparation_capacity')
            need(observed <= allowed | preparations | ((pending | {TRANSACTION}) if not writable else set()))
            self.pending_metadata = sorted(observed & (pending | {TRANSACTION}))
            if self.pending_metadata:
                self.mutation_reason = 'fixture_metadata_pending'
            self.records()
        except BaseException as original:
            try:
                self.close()
            except BaseException as error:
                original.private_custody = self
                original.source_handles_closed = False
                original.custody_close_error = error
            raise original from None

    def _persistent(self, fd):
        value = self.persistent_identity(fd)
        need(type(value) is dict and set(value) == {'volume', 'birth'}
             and type(value['volume']) is str and re.fullmatch('[0-9a-f]{32}', value['volume']) is not None
             and value['volume'] != '0' * 32 and type(value['birth']) is list
             and len(value['birth']) == 2 and all(type(n) is int for n in value['birth'])
             and value['birth'][0] > 0 and 0 <= value['birth'][1] < 1000000000)
        return value

    def _new_namespace_marker(self):
        directory = self._persistent(self.directory.descriptor)
        lock = self._persistent(self.lock)
        need(directory['volume'] == lock['volume'])
        return {'schema': 2, 'identity': identity(os.fstat(self.directory.descriptor)),
                'lock': self.lock_identity, 'boot': self.boot,
                'persistent': {'directory': directory, 'lock': lock}}

    def _namespace_marker(self, marker, *, include_lock):
        need(type(marker) is dict and type(marker.get('schema')) is int)
        if marker['schema'] == 1:
            # Legacy markers have no stable volume/boot proof. Preserve their
            # existing exact-identity semantics; never infer a remount or adopt.
            need(set(marker) == {'schema', 'identity', 'lock'}
                 and marker['identity'] == identity(os.fstat(self.directory.descriptor)))
            if include_lock:
                need(marker['lock'] == self.lock_identity)
            return False
        need(marker['schema'] == 2 and set(marker) == {'schema', 'identity', 'lock', 'boot', 'persistent'}
             and type(marker['boot']) is str and re.fullmatch('[0-9a-f]{64}', marker['boot']) is not None
             and type(marker['persistent']) is dict and set(marker['persistent']) == {'directory', 'lock'})
        changed_boot = marker['boot'] != self.boot
        for key, fd, persistent_key in [('identity', self.directory.descriptor, 'directory')] + (
                [('lock', self.lock, 'lock')] if include_lock else []):
            row = marker[key]
            current = identity(os.fstat(fd))
            need(type(row) is list and len(row) == 4 and all(type(n) is int and n >= 0 for n in row)
                 and (row[1:] == current[1:] if changed_boot else row == current)
                 and marker['persistent'][persistent_key] == self._persistent(fd))
        if include_lock:
            need(marker['persistent']['directory']['volume'] == marker['persistent']['lock']['volume']
                 and marker['identity'][0] == marker['lock'][0])
        return changed_boot

    def _register(self, descriptor):
        need(descriptor not in self.fds)
        self.close_attempts.pop(descriptor, None)
        self.fds.append(descriptor)

    def _close_fd(self, descriptor):
        if descriptor in self.close_attempts:
            error = self.close_attempts[descriptor]
            if error is not None:
                raise error
            return
        self.close_attempts[descriptor] = None
        error, confirmed = None, False
        try:
            os.close(descriptor)
        except BaseException as caught:
            error = caught
        try:
            os.fstat(descriptor)
            error = error or CustodyError()
        except OSError as caught:
            confirmed = caught.errno == errno.EBADF
            if not confirmed:
                error = error or caught
        except BaseException as caught:
            error = error or caught
        if confirmed:
            if descriptor in self.fds:
                self.fds.remove(descriptor)
            for handle in self.handles:
                if descriptor in handle._fds:
                    handle._fds.remove(descriptor)
        if error is not None:
            error.private_custody = self
            error.source_handles_closed = False
            self.close_attempts[descriptor] = error
            raise error

    def _hold(self, handle):
        self.handles.append(handle)
        for descriptor in handle._fds:
            self._register(descriptor)
        def close():
            errors = []
            for descriptor in tuple(handle._fds):
                try:
                    self._close_fd(descriptor)
                except BaseException as error:
                    errors.append(error)
            if errors:
                raise errors[0]
        handle.close = close

    def _read(self, leaf, maximum=MAX_RECORD):
        self.directory.verify()
        self._verify_lock()
        fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                     dir_fd=self.directory.descriptor)
        self._register(fd)
        try:
            info = os.fstat(fd)
            need(stat.S_ISREG(info.st_mode) and info.st_uid == self.uid
                 and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1
                 and 0 < info.st_size <= maximum)
            raw = bytearray()
            while len(raw) <= maximum:
                block = os.read(fd, maximum + 1 - len(raw))
                if not block:
                    break
                raw.extend(block)
            need(len(raw) == info.st_size and stamp(os.fstat(fd)) == stamp(info)
                 and stamp(os.stat(leaf, dir_fd=self.directory.descriptor, follow_symlinks=False)) == stamp(info))
            def pairs(items):
                result = {}
                for key, value in items:
                    need(key not in result)
                    result[key] = value
                return result
            value = json.loads(raw, object_pairs_hook=pairs)
            self.directory.verify()
            return value, (bytes(raw), stamp(info))
        finally:
            self._close_fd(fd)

    def _record_names(self):
        return {name for name in names(self.directory.descriptor)
                if not preparation_name(name) and name != TRANSACTION}

    def _write_preparation(self, leaf, value, maximum=MAX_RECORD):
        raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
        need(len(raw) <= maximum)
        self.directory.verify()
        self._verify_lock()
        fd = os.open(leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=self.directory.descriptor)
        self._register(fd)
        try:
            offset = 0
            while offset < len(raw):
                written = os.write(fd, raw[offset:])
                need(type(written) is int and written > 0)
                offset += written
            os.fsync(fd)
        finally:
            self._close_fd(fd)
        written, observed = self._read(leaf, maximum)
        need(written == json.loads(raw))
        return observed

    def _recover_transaction(self):
        """Reconcile metadata only; never launch a child or retire a fixture."""
        transaction, receipt = self._read(TRANSACTION, MAX_RECORD * 5)
        need(type(transaction) is dict and set(transaction) ==
             {'schema', 'namespace', 'boot', 'leaf', 'candidate', 'before', 'beforePersistent',
              'after', 'afterIdentity', 'afterPersistent', 'records'})
        need(transaction['schema'] == 1 and type(transaction['schema']) is int)
        need(type(transaction['boot']) is str and re.fullmatch('[0-9a-f]{64}', transaction['boot']) is not None)
        cross_boot = transaction['boot'] != self.boot
        leaf, candidate = transaction['leaf'], transaction['candidate']
        need(leaf in {'namespace.json'} | {str(slot) + '.json' for slot in range(SLOTS)})
        need(type(candidate) is str and preparation_name(candidate) and candidate.endswith('.payload'))
        marker, _ = self._read('namespace.json')
        self._namespace_marker(marker, include_lock=True)
        need(transaction['namespace'] == self._new_namespace_marker()['persistent'])
        before, after = transaction['before'], transaction['after']
        need(before is None or (type(before) is list and len(before) == 2 and
             type(before[0]) is str and len(before[0]) <= MAX_RECORD * 2 and
             type(before[1]) is list and len(before[1]) == 8))
        need(type(after) is str and 0 < len(after) <= MAX_RECORD * 2)
        expected = bytes.fromhex(after)
        expected_value = json.loads(expected)
        self._validate_publication(leaf, expected_value,
                                   None if before is None else bytes.fromhex(before[0]))
        need(type(transaction['afterIdentity']) is list and len(transaction['afterIdentity']) == 4)
        # No unrelated legacy pending name may be hidden by a valid transaction.
        need(all(not name.endswith('.pending') for name in names(self.directory.descriptor)))
        try:
            _, current = self._read(leaf)
        except FileNotFoundError:
            current = None
        def same(left, right):
            return left[1:] == right[1:] if cross_boot else left == right
        closure = transaction['records']
        need(type(closure) is dict and set(closure) <= {str(slot) + '.json' for slot in range(SLOTS)})
        if leaf == 'namespace.json':
            need(self._record_names() == {'namespace.json', 'lock'} | set(closure))
            for name, bound in closure.items():
                need(type(bound) is dict and set(bound) == {'sha256', 'stamp', 'persistent'})
                need(type(bound['sha256']) is str and re.fullmatch('[0-9a-f]{64}', bound['sha256']) is not None
                     and type(bound['stamp']) is list and len(bound['stamp']) == 8)
                _, observed = self._read(name)
                need(hashlib.sha256(observed[0]).hexdigest() == bound['sha256'] and same(observed[1], bound['stamp'])
                     and self._file_persistent(name) == bound['persistent'])
        else:
            need(closure == {})
        is_before = (current is None if before is None else
                     current is not None and current[0] == bytes.fromhex(before[0]) and same(current[1], before[1])
                     and self._file_persistent(leaf) == transaction['beforePersistent'])
        is_after = current is not None and current[0] == expected and \
            same(identity(os.stat(leaf, dir_fd=self.directory.descriptor, follow_symlinks=False)), transaction['afterIdentity']) and \
            self._file_persistent(leaf) == transaction['afterPersistent']
        if is_before:
            value, prepared = self._read(candidate)
            need(prepared[0] == expected and value == expected_value and
                 same(identity(os.stat(candidate, dir_fd=self.directory.descriptor, follow_symlinks=False)), transaction['afterIdentity'])
                 and self._file_persistent(candidate) == transaction['afterPersistent'])
            self.directory.verify()
            self._verify_lock()
            need(self._read(TRANSACTION, MAX_RECORD * 5)[1] == receipt)
            # Recheck the exact preimage immediately before publication.
            if before is None:
                rename_exclusive(self.directory.descriptor, candidate, leaf)
            else:
                need(self._read(leaf)[1] == current)
                os.replace(candidate, leaf, src_dir_fd=self.directory.descriptor,
                           dst_dir_fd=self.directory.descriptor)
            self.checkpoint('record-published')
        else:
            need(is_after)
            # Atomic rename cannot leave both names. Preserve a recreated one.
            need(candidate not in names(self.directory.descriptor))
        os.fsync(self.directory.descriptor)
        self.checkpoint('record-durable')
        need(self._read(leaf)[1][0] == expected and
             same(identity(os.stat(leaf, dir_fd=self.directory.descriptor, follow_symlinks=False)), transaction['afterIdentity'])
             and self._file_persistent(leaf) == transaction['afterPersistent'])
        if leaf == 'namespace.json':
            self._namespace_marker(self._read(leaf)[0], include_lock=True)
        else:
            self.records()
        need(self._read(TRANSACTION, MAX_RECORD * 5)[1] == receipt)
        os.unlink(TRANSACTION, dir_fd=self.directory.descriptor)
        os.fsync(self.directory.descriptor)
        self.checkpoint('transaction-cleared')

    def _publish(self, leaf, value, prior):
        need(self.mutation_reason is None, self.mutation_reason or 'fixture_custody_invalid')
        need(leaf in {'namespace.json'} | {str(slot) + '.json' for slot in range(SLOTS)})
        self._validate_publication(leaf, value, None if prior is None else prior[0])
        listed = names(self.directory.descriptor)
        need(TRANSACTION not in listed and all(not name.endswith('.pending') for name in listed))
        need(sum(preparation_name(name) for name in listed) + 2 <= MAX_PREPARATIONS * 2,
             'fixture_preparation_capacity')
        token = secrets.token_hex(16)
        candidate, journal = '.prepare-' + token + '.payload', '.prepare-' + token + '.journal'
        prepared = self._write_preparation(candidate, value)
        self.directory.verify()
        self._verify_lock()
        if prior is not None:
            previous, current = self._read(leaf)
            need(current == prior)
            if leaf == 'namespace.json':
                # Last pre-publication check, after record-written callbacks:
                # no old or newly appeared artifact may be silently rebound.
                need(self._record_names() ==
                     {'namespace.json', 'lock'} | set(self.namespace_refresh_records))
                for name, recorded in self.namespace_refresh_records.items():
                    need(self._read(name)[1] == recorded)
                need(self._namespace_marker(previous, include_lock=True) or previous['schema'] == 1)
                self.directory.verify()
                self._verify_lock()
        transaction = {'schema': 1, 'namespace': self._new_namespace_marker()['persistent'], 'boot': self.boot, 'leaf': leaf,
                       'candidate': candidate, 'before': None if prior is None else [prior[0].hex(), prior[1]],
                       'beforePersistent': None if prior is None else self._file_persistent(leaf),
                       'after': prepared[0].hex(),
                       'afterIdentity': identity(os.stat(candidate, dir_fd=self.directory.descriptor, follow_symlinks=False)),
                       'afterPersistent': self._file_persistent(candidate),
                       'records': {name: {'sha256': hashlib.sha256(bound[0]).hexdigest(), 'stamp': bound[1],
                                          'persistent': self._file_persistent(name)}
                                   for name, bound in self.namespace_refresh_records.items()} if leaf == 'namespace.json' else {}}
        self._write_preparation(journal, transaction, MAX_RECORD * 5)
        self.checkpoint('transaction-prepared')
        rename_exclusive(self.directory.descriptor, journal, TRANSACTION)
        os.fsync(self.directory.descriptor)
        self.checkpoint('transaction-ready')
        # A complete candidate is recoverable before announcing it written.
        # An interruption at this supported boundary cannot accumulate orphan
        # payloads; partial writes before durable intent remain unknown debt.
        self.checkpoint("record-written")
        self._recover_transaction()

    def _validate_publication(self, leaf, value, previous_raw):
        if leaf == 'namespace.json':
            need(type(value) is dict and value.get('schema') == 2)
            self._namespace_marker(value, include_lock=True)
            return
        slot = int(leaf[:-5])
        self._validate_record(value, slot)
        if previous_raw is not None:
            previous = json.loads(previous_raw)
            self._validate_record(previous, slot)
            need(value['token'] == previous['token'] and value['schema'] >= previous['schema'])

    def _file_persistent(self, leaf):
        _, observed = self._read(leaf)
        fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                     dir_fd=self.directory.descriptor)
        self._register(fd)
        try:
            need(stamp(os.fstat(fd)) == observed[1])
            proof = self._persistent(fd)
            need(stamp(os.fstat(fd)) == observed[1] and self._read(leaf)[1] == observed)
            return proof
        finally:
            self._close_fd(fd)

    def _verify_lock(self):
        if self.lock is not None:
            info = os.fstat(self.lock)
            need(identity(info) == self.lock_identity and info.st_nlink == 1 and info.st_size == 0
                 and identity(os.stat("lock", dir_fd=self.directory.descriptor,
                                      follow_symlinks=False)) == self.lock_identity)

    def records(self):
        result = {}
        for slot in range(SLOTS):
            try:
                value, _ = self._read(str(slot) + ".json")
            except FileNotFoundError:
                continue
            self._validate_record(value, slot)
            result[slot] = value
        return result

    def _validate_record(self, value, slot):
        keys = {"schema", "slot", "token", "state", "root", "children", "schemas", "settled", "reason"}
        need(type(value) is dict and type(value.get("schema")) is int
                 and value["schema"] in (1, 2, 3)
                 and set(value) == (keys if value["schema"] == 1 else
                     keys | {"output"} if value['schema'] == 2 else keys | {'output', 'provenance'})
                 and type(value["slot"]) is int and value["slot"] == slot
                 and type(value["token"]) is str and re.fullmatch("[0-9a-f]{32}", value["token"]) is not None
                 and value["state"] in STATES and type(value["settled"]) is bool
                 and type(value["reason"]) is str and len(value["reason"]) <= 64
                 and type(value["children"]) is dict and set(value["children"]) <= set(CHILDREN)
                 and type(value["schemas"]) is dict and set(value["schemas"]) <= set(SCHEMAS))
        identities = ([value["root"]] if value["root"] is not None else []) + list(value["children"].values())
        need(all(type(row) is list and len(row) == 4 and all(type(item) is int and item >= 0 for item in row)
                     and row[2] == self.uid and stat.S_IMODE(row[3]) == 0o700 and stat.S_ISDIR(row[3]) for row in identities))
        need(all(type(row) is list and len(row) == 8 and all(type(item) is int for item in row)
                     for row in value["schemas"].values()))
        if value["schema"] == 2 or (value['schema'] == 3 and value['output'] is not None):
            self._validate_output(value)
        if value['schema'] == 3:
            proof = value['provenance']
            need(type(proof) is dict and set(proof) == {'boot', 'objects'}
                     and type(proof['boot']) is str and re.fullmatch('[0-9a-f]{64}', proof['boot']) is not None
                     and type(proof['objects']) is dict
                     and set(proof['objects']) == set(self._record_rows(value)))
            for row in proof['objects'].values():
                need(type(row) is dict and set(row) == {'volume', 'birth'}
                         and type(row['volume']) is str and re.fullmatch('[0-9a-f]{32}', row['volume']) is not None
                         and row['volume'] != '0' * 32 and type(row['birth']) is list and len(row['birth']) == 2
                         and all(type(n) is int for n in row['birth']) and row['birth'][0] > 0
                         and 0 <= row['birth'][1] < 1000000000)

    def leaf(self, record):
        return "vendor-sentinel-" + record["token"]

    def _record_rows(self, record):
        rows = {'': record['root']} if record['root'] is not None else {}
        rows.update(record['children'])
        rows.update({'schema/' + name: row for name, row in record['schemas'].items()})
        rows.update(record.get('output') or {})
        return rows

    def _observe_record_row(self, record, name, row, *, cross_boot=False, proof=None):
        """Observe only already bound names, through a held no-follow chain."""
        self.parent.verify()
        parts = [self.leaf(record)] + (name.split('/') if name else [])
        held, parent = [], self.parent.descriptor
        try:
            for index, component in enumerate(parts):
                directory = index < len(parts) - 1 or (stat.S_ISDIR(row[3]) if len(row) == 4 else stat.S_ISDIR(row[2]))
                fd = os.open(component, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
                             | (os.O_DIRECTORY if directory else 0), dir_fd=parent)
                self._register(fd)
                held.append((parent, component, fd))
                parent = fd
            facts = os.fstat(fd)
            current = identity(facts) if len(row) == 4 else stamp(facts)
            # Directory timestamps legitimately change during recorded retirement.
            compared = 4 if len(row) == 8 and stat.S_ISDIR(row[2]) and record['state'] == 'retiring' else len(row)
            need(current[1:compared] == row[1:compared] if cross_boot else current[:compared] == row[:compared])
            persistent = self._persistent(fd)
            if proof is not None:
                need(persistent == proof)
            for parent, component, child in held:
                need(identity(os.stat(component, dir_fd=parent, follow_symlinks=False)) == identity(os.fstat(child)))
            self.parent.verify()
            return current, persistent
        finally:
            for _, _, fd in reversed(held):
                self._close_fd(fd)

    def _capture_provenance(self, record):
        return {name: self._observe_record_row(record, name, row)[1]
                for name, row in self._record_rows(record).items()}

    def _verify_provenance(self, record):
        for name, row in self._record_rows(record).items():
            try:
                self._observe_record_row(record, name, row,
                    proof=record['provenance']['objects'][name])
            except FileNotFoundError:
                need(record['state'] == 'retiring')

    def _rebased_record(self, record):
        """A new boot is not settlement; only existing settled proofs can rebind."""
        need(record['schema'] == 3, 'fixture_legacy_identity_required')
        need(record['settled'] is True and record['state'] != 'inflight', 'fixture_settlement_required')
        result = copy.deepcopy(record)
        changed_boot = record['provenance']['boot'] != self.boot
        rows = self._record_rows(record)
        for name, row in rows.items():
            try:
                current, _ = self._observe_record_row(record, name, row, cross_boot=changed_boot,
                                                      proof=record['provenance']['objects'][name])
            except FileNotFoundError:
                need(record['state'] == 'retiring')
                continue
            # Preserve all content/time guards; only the device number changes.
            if name == '': result['root'][0] = current[0]
            if name in result['children']: result['children'][name][0] = current[0]
            if name.startswith('schema/') and name[7:] in result['schemas']:
                result['schemas'][name[7:]][0] = current[0]
            if result['output'] is not None and name in result['output']:
                result['output'][name][0] = current[0]
        if not rows:
            try:
                os.stat(self.leaf(record), dir_fd=self.parent.descriptor, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise CustodyError('fixture_custody_invalid')
        result['provenance']['boot'] = self.boot
        return result

    def _rebase_slot(self, slot):
        leaf = str(slot) + '.json'
        current, prior = self._read(leaf)
        replacement = self._rebased_record(current)
        need(self._read(leaf)[1] == prior and self._rebased_record(current) == replacement)
        if current != replacement:
            self._publish(leaf, replacement, prior)
        return replacement

    def _empty_reservation(self, record):
        return (record['state'] in ('reserved', 'retiring') and record['settled'] is True
                and record['root'] is None and not record['children']
                and not record['schemas'] and record.get('output') is None)

    def reserve(self):
        need(self.mutation_reason is None, self.mutation_reason or 'fixture_custody_invalid')
        need(not self.namespace_refresh_required, 'fixture_namespace_refresh_required')
        records = self.records()
        # Only a pre-launch empty reservation may be retried automatically.
        # Existing retirement supplies durable intent, exact absence and fsync;
        # no mkdir/child, process observation or unknown bytes imply settlement.
        for slot, record in records.items():
            if slot not in self.fresh_slots and self._empty_reservation(record):
                self.retire(slot)
        records = self.records()
        need(len(records) < SLOTS, "fixture_capacity_required")
        need(all(record["settled"] is True for record in records.values()),
             "fixture_settlement_required")
        for slot, record in records.items():
            if record['schema'] == 3:
                self._rebase_slot(slot)
        records = self.records()
        self.census(records)
        slot = next(slot for slot in range(SLOTS) if slot not in records)
        record = {"schema": 3, "slot": slot, "token": secrets.token_hex(16), "state": "reserved",
                  "root": None, "children": {}, "schemas": {}, "settled": True, "reason": "reserved",
                  'output': None, 'provenance': {'boot': self.boot, 'objects': {}}}
        self._publish(str(slot) + ".json", record, None)
        self.checkpoint("reservation-durable")
        self.fresh_slots.add(slot)
        return slot

    def _validate_output(self, record):
        output = record["output"]
        need(record["root"] is not None and set(record["children"]) == set(CHILDREN)
             and set(record["schemas"]) == set(SCHEMAS)
             and type(output) is dict and len(CHILDREN) <= len(output) <= MAX_OUTPUT_ENTRIES)
        total = 0
        for name, row in output.items():
            need(type(name) is str and len(name) <= 300 and len(name.split("/")) <= MAX_DEPTH
                 and type(row) is list and len(row) == 8
                 and all(type(item) is int and item >= 0 for item in row)
                 and row[3] == self.uid and not row[2] & 0o7022)
            if stat.S_ISDIR(row[2]):
                need(name in OUTPUT_DIRS and stat.S_IMODE(row[2]) in (0o700, 0o750, 0o755))
            else:
                need(stat.S_ISREG(row[2]) and row[4] == 1
                     and re.fullmatch(r"schema/(?:v[12]/)?[A-Za-z0-9_.-]{1,250}\.json", name) is not None)
                total += row[5]
        for name in output:
            if "/" in name:
                parent = name.rsplit("/", 1)[0]
                need(parent in output and stat.S_ISDIR(output[parent][2]))
        need(total <= MAX_OUTPUT_BYTES, "fixture_capacity_required")
        for name in CHILDREN:
            need(name in output and [output[name][0], output[name][1], output[name][3], output[name][2]]
                 == record["children"][name])
        for name in SCHEMAS:
            need(output.get("schema/" + name) == record["schemas"][name])

    def _output_envelope(self, fd):
        # The same fixture-only provenance exception as the allocated-directory
        # adapter, but generated files/directories need not have mode 0700.
        envelope = paths.observe_envelope(fd)
        need(envelope.acl_entries == 0
             and set(envelope.xattr_names) <= {"com.apple.provenance"})

    def _output_tree(self, record, expected=None):
        """Bounded descriptor-relative snapshot; no content reads or adoption.

        With an expected manifest, validate the complete tree before deletion.
        Only durable retiring intent permits missing known entries and directory
        timestamps changed by a prior exact removal.
        """
        output, total = {}, 0
        resuming = record["state"] == "retiring"
        def walk(fd, prefix, depth):
            nonlocal total
            need(depth <= MAX_DEPTH, "fixture_capacity_required")
            before = stamp(os.fstat(fd))
            for leaf in names(fd, MAX_OUTPUT_ENTRIES - len(output)):
                name = prefix + leaf
                info = os.stat(leaf, dir_fd=fd, follow_symlinks=False)
                row = stamp(info)
                need(len(output) < MAX_OUTPUT_ENTRIES, "fixture_capacity_required")
                need(info.st_uid == self.uid and not info.st_mode & 0o7022)
                directory = stat.S_ISDIR(info.st_mode)
                if directory:
                    need(name in OUTPUT_DIRS and stat.S_IMODE(info.st_mode) in (0o700, 0o750, 0o755))
                else:
                    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                         and re.fullmatch(r"schema/(?:v[12]/)?[A-Za-z0-9_.-]{1,250}\.json", name) is not None)
                    total += info.st_size
                    need(total <= MAX_OUTPUT_BYTES, "fixture_capacity_required")
                if expected is not None:
                    need(name in expected)
                    previous = expected[name]
                    need((row[:4] == previous[:4]) if directory and resuming else row == previous)
                output[name] = row
                child = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
                                | (os.O_DIRECTORY if directory else 0), dir_fd=fd)
                self._register(child)
                try:
                    need(stamp(os.fstat(child)) == row)
                    self._output_envelope(child)
                    if directory:
                        walk(child, name + "/", depth + 1)
                    need(stamp(os.fstat(child)) == row
                         and stamp(os.stat(leaf, dir_fd=fd, follow_symlinks=False)) == row)
                finally:
                    self._close_fd(child)
            need(stamp(os.fstat(fd)) == before)
        self.parent.verify()
        root = os.open(self.leaf(record), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                       dir_fd=self.parent.descriptor)
        self._register(root)
        try:
            need(identity(os.fstat(root)) == record["root"])
            self._output_envelope(root)
            walk(root, "", 0)
            need(identity(os.stat(self.leaf(record), dir_fd=self.parent.descriptor,
                                  follow_symlinks=False)) == record["root"])
            self.parent.verify()
        finally:
            self._close_fd(root)
        if expected is not None and not resuming:
            need(set(output) == set(expected))
        return output

    def seal_output(self, slot, consumed_schemas):
        """Seal only this process's fresh successful settled allocation.

        The successful observer is the sole caller. CLI retirement never calls
        this method and cannot promote historical schema-1 retained output.
        """
        need(type(slot) is int and slot in self.fresh_slots)
        record = self.records()[slot]
        need((record["schema"] == 1 or (record['schema'] == 3 and record['output'] is None)) and record["state"] == "allocated"
             and record["settled"] is True, "fixture_settlement_required")
        need(type(consumed_schemas) is dict and set(consumed_schemas) == set(SCHEMAS))
        output = self._output_tree(record)
        sealed = {**record, "schema": 2, "schemas": {key: list(value) for key, value in consumed_schemas.items()},
                  "output": output}
        self._validate_output(sealed)
        # Reobserve after the complete snapshot; no removal occurs on refusal.
        self._output_tree(sealed, output)
        self.update(slot, schema=3 if record['schema'] == 3 else 2, schemas=sealed["schemas"], output=output)
        self.fresh_slots.discard(slot)

    def update(self, slot, **changes):
        need(type(slot) is int and 0 <= slot < SLOTS)
        need(not self.namespace_refresh_required or self.retirement_slot == slot,
             'fixture_namespace_refresh_required')
        leaf = str(slot) + ".json"
        record, prior = self._read(leaf)
        updated = {**record, **changes}
        if record['schema'] == 3 and {'root', 'children', 'schemas', 'output'} & set(changes):
            need(updated['schema'] == 3)
            need(set(updated['children']) <= set(CHILDREN) and set(updated['schemas']) <= set(SCHEMAS))
            if updated['output'] is not None:
                self._validate_output(updated)
            updated['provenance'] = {'boot': self.boot, 'objects': self._capture_provenance(updated)}
        self._publish(leaf, updated, prior)

    def census(self, records=None):
        total, count = 0, 0
        def visit(fd, depth):
            nonlocal total, count
            need(depth <= MAX_DEPTH, "fixture_capacity_required")
            with os.scandir(fd) as entries:
                for entry in entries:
                    name = entry.name
                    count += 1
                    need(count <= MAX_ENTRIES, "fixture_capacity_required")
                    info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    need(info.st_uid == self.uid and not info.st_mode & 0o022, "fixture_capacity_required")
                    if stat.S_ISREG(info.st_mode):
                        need(info.st_nlink == 1, "fixture_capacity_required")
                        total += info.st_size
                        need(total <= MAX_BYTES, "fixture_capacity_required")
                    elif stat.S_ISDIR(info.st_mode):
                        child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                        self._register(child)
                        try:
                            need(identity(os.fstat(child)) == identity(info), "fixture_capacity_required")
                            visit(child, depth + 1)
                        finally:
                            self._close_fd(child)
                    else:
                        raise CustodyError("fixture_capacity_required")
        for record in (self.records() if records is None else records).values():
            if record["root"] is None:
                if self._empty_reservation(record):
                    try:
                        os.stat(self.leaf(record), dir_fd=self.parent.descriptor, follow_symlinks=False)
                    except FileNotFoundError:
                        continue
                raise CustodyError("fixture_capacity_required")
            fd = os.open(self.leaf(record), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                         dir_fd=self.parent.descriptor)
            self._register(fd)
            try:
                need(identity(os.fstat(fd)) == record["root"], "fixture_capacity_required")
                visit(fd, 0)
            finally:
                self._close_fd(fd)
        return total, count

    def status(self):
        records = self.records()
        preparations = [name for name in names(self.directory.descriptor) if preparation_name(name)]
        preparation_bytes = sum(os.stat(name, dir_fd=self.directory.descriptor,
            follow_symlinks=False).st_size for name in preparations)
        total, entries, reason = None, None, None
        try:
            total, entries = self.census(records)
        except (CustodyError, OSError) as error:
            reason = (error.reason_class if type(error) is CustodyError else "fixture_capacity_required")
        capacity_reason = self.mutation_reason or (
            'fixture_namespace_refresh_required' if self.namespace_refresh_required else
            'fixture_preparation_capacity' if len(preparations) + 2 > MAX_PREPARATIONS * 2 else
            'fixture_capacity_required' if len(records) >= SLOTS else
            'fixture_settlement_required' if any(not row['settled'] for row in records.values()) else reason)
        return {"scope": "disposable-vendor-fixture-custody", "outstanding": len(records),
                "slots": [{"slot": slot, "settled": value["settled"], "state": value["state"]}
                          for slot, value in records.items()], "maximumReservations": SLOTS,
                "retainedByteAdmissionBudget": MAX_BYTES,
                "retainedBytesObserved": None if total is None else total + preparation_bytes,
                "entriesObserved": None if entries is None else entries + len(preparations),
                "preparationCount": len(preparations), "preparationBytesObserved": preparation_bytes,
                "maximumPreparations": MAX_PREPARATIONS * 2,
                "preparationReason": 'fixture_preparation_recovery_required' if preparations else None,
                "nextAction": ('reconcile-recorded-metadata-before-retry' if self.pending_metadata else
                    'preserve-preparations-for-bounded-recovery' if preparations else
                    'reconcile-retained-child-before-retry' if capacity_reason == 'fixture_settlement_required' else
                    'inspect-custody-status-before-retry' if capacity_reason else None),
                "capacityReason": capacity_reason,
                "pendingMetadataCount": len(self.pending_metadata) + len(preparations),
                "namespaceRefreshRequired": self.namespace_refresh_required,
                "hardDiskQuota": False}

    def release_absent(self, slot):
        need(self.mutation_reason is None, self.mutation_reason or 'fixture_custody_invalid')
        need(not self.namespace_refresh_required or self.retirement_slot == slot,
             'fixture_namespace_refresh_required')
        record, prior = self._read(str(slot) + ".json")
        need(record["settled"] is True and record["state"] == "retiring")
        try:
            os.stat(self.leaf(record), dir_fd=self.parent.descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise CustodyError()
        # Even a resumed already-absent root must make that absence durable
        # before removing its durable reservation.
        os.fsync(self.parent.descriptor)
        need(self._read(str(slot) + ".json")[1] == prior)
        os.unlink(str(slot) + ".json", dir_fd=self.directory.descriptor)
        os.fsync(self.directory.descriptor)

    def _retire_output(self, slot, record):
        observed = self._output_tree(record, record["output"])
        held = {}
        leaf = self.leaf(record)
        def verify(name):
            self.parent.verify()
            parts = name.split("/") if name else []
            for index in range(len(parts) + 1):
                path = "/".join(parts[:index])
                fd = held[path]
                expected = record["root"] if not path else [record["output"][path][key] for key in (0, 1, 3, 2)]
                parent = self.parent.descriptor if not path else held[path.rpartition("/")[0]]
                component = leaf if not path else path.rpartition("/")[2]
                need(identity(os.fstat(fd)) == expected
                     and identity(os.stat(component, dir_fd=parent, follow_symlinks=False)) == expected)
        try:
            root = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                           dir_fd=self.parent.descriptor)
            self._register(root)
            held[""] = root
            verify("")
            for name in sorted((name for name, row in observed.items() if stat.S_ISDIR(row[2])),
                               key=lambda item: (item.count("/"), item)):
                parent, _, component = name.rpartition("/")
                verify(parent)
                fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                             dir_fd=held[parent])
                self._register(fd)
                held[name] = fd
                verify(name)
                self._output_envelope(fd)
            # Revalidate complete closure after opening the held deletion chain.
            self._output_tree(record, record["output"])
            self.update(slot, state="retiring")
            self.checkpoint("retirement-intent")
            for name in sorted(observed, key=lambda item: (-item.count("/"), item)):
                parent, _, component = name.rpartition("/")
                row = record["output"][name]
                verify(parent)
                if stat.S_ISDIR(row[2]):
                    verify(name)
                    self._output_envelope(held[name])
                    need(names(held[name], 0) == [])
                    os.rmdir(component, dir_fd=held[parent])
                    os.fsync(held[parent])
                    self._close_fd(held.pop(name))
                    self.checkpoint("child-retired")
                else:
                    need(stamp(os.stat(component, dir_fd=held[parent], follow_symlinks=False)) == row)
                    fd = os.open(component, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                                 dir_fd=held[parent])
                    self._register(fd)
                    try:
                        need(stamp(os.fstat(fd)) == row)
                        self._output_envelope(fd)
                        verify(parent)
                        need(stamp(os.stat(component, dir_fd=held[parent], follow_symlinks=False)) == row)
                        os.unlink(component, dir_fd=held[parent])
                        os.fsync(held[parent])
                    finally:
                        self._close_fd(fd)
                    self.checkpoint("schema-retired")
            verify("")
            self._output_envelope(root)
            need(names(root, 0) == [])
            os.rmdir(leaf, dir_fd=self.parent.descriptor)
            os.fsync(self.parent.descriptor)
            self.checkpoint("root-retired")
            self.release_absent(slot)
            return {"scope": "disposable-vendor-fixture-custody", "retired": True, "slot": slot}
        finally:
            for fd in reversed(tuple(held.values())):
                self._close_fd(fd)

    def retire(self, slot):
        """Retire only the selected settled slot, preserving unrelated debt."""
        need(self.retirement_slot is None)
        self.retirement_slot = slot
        try:
            return self._retire(slot)
        finally:
            self.retirement_slot = None

    def _retire(self, slot):
        """Explicit restart-capable retirement of a settled exact known set.

        A persisted retiring intent permits missing *known* entries on resume,
        not new entries, changed objects, unknown descendants or inferred child
        death. Empty pre-launch constructor fixtures are also disposable.
        """
        need(self.mutation_reason is None, self.mutation_reason or 'fixture_custody_invalid')
        need(type(slot) is int and 0 <= slot < SLOTS)
        records = self.records()
        need(slot in records)
        record = records[slot]
        need(record["settled"] is True and record["state"] != "inflight",
             "fixture_settlement_required")
        if record['schema'] == 3:
            record = self._rebase_slot(slot)
            self._verify_provenance(record)
        leaf = self.leaf(record)
        try:
            info = os.stat(leaf, dir_fd=self.parent.descriptor, follow_symlinks=False)
        except FileNotFoundError:
            need(record["state"] in ("reserved", "retiring"))
            self.update(slot, state="retiring")
            self.release_absent(slot)
            return {"scope": "disposable-vendor-fixture-custody", "retired": True, "slot": slot}
        need(record["root"] is not None and identity(info) == record["root"])
        if record["schema"] == 2 or (record['schema'] == 3 and record['output'] is not None):
            return self._retire_output(slot, record)
        handles = []
        try:
            root = paths.OwnedParent.open(self.scratch + "/" + leaf, self.home, self.uid)
            self._hold(root)
            handles.append(root)
            need(identity(os.fstat(root.descriptor)) == record["root"])
            self.envelope(root, paths)
            present = set(names(root.descriptor, len(CHILDREN)))
            need(present <= set(record["children"]))
            if record["state"] != "retiring":
                need(present == set(record["children"]))
            children = {}
            for name in sorted(present):
                handle = paths.OwnedParent.open(self.scratch + "/" + leaf + "/" + name,
                                               self.home, self.uid)
                self._hold(handle)
                handles.append(handle)
                need(identity(os.fstat(handle.descriptor)) == record["children"][name])
                self.envelope(handle, paths)
                children[name] = handle
                content = set(names(handle.descriptor, len(SCHEMAS) if name == "schema" else 0))
                if name == "schema":
                    need(content <= set(record["schemas"]))
                    if record["state"] != "retiring":
                        need(content == set(record["schemas"]))
                    for schema in content:
                        need(stamp(os.stat(schema, dir_fd=handle.descriptor, follow_symlinks=False))
                             == record["schemas"][schema])
                else:
                    need(content == set())
            self.update(slot, state="retiring")
            self.checkpoint("retirement-intent")
            for name, handle in children.items():
                for schema in names(handle.descriptor, len(SCHEMAS) if name == "schema" else 0):
                    root.verify()
                    handle.verify()
                    need(stamp(os.stat(schema, dir_fd=handle.descriptor, follow_symlinks=False))
                         == record["schemas"][schema])
                    os.unlink(schema, dir_fd=handle.descriptor)
                    os.fsync(handle.descriptor)
                    self.checkpoint("schema-retired")
                root.verify()
                handle.verify()
                need(names(handle.descriptor, 0) == [])
                os.rmdir(name, dir_fd=root.descriptor)
                os.fsync(root.descriptor)
                self.checkpoint("child-retired")
            root.verify()
            need(names(root.descriptor, 0) == [])
            self.parent.verify()
            os.rmdir(leaf, dir_fd=self.parent.descriptor)
            os.fsync(self.parent.descriptor)
            self.checkpoint("root-retired")
            self.release_absent(slot)
            return {"scope": "disposable-vendor-fixture-custody", "retired": True, "slot": slot}
        finally:
            for handle in reversed(handles):
                handle.close()

    def close(self):
        errors = []
        for descriptor in tuple(reversed(self.fds)):
            try:
                self._close_fd(descriptor)
            except BaseException as error:
                errors.append(error)
        if errors:
            errors[0].private_custody = self
            errors[0].source_handles_closed = False
            raise errors[0]
        self.handles = []
        self.lock = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
