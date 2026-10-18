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


class Custody:
    def __init__(self, scratch, home, uid, *, create=True, envelope=None, checkpoint=None,
                 persistent_identity=None, boot_identity=None):
        self.scratch, self.home, self.uid = scratch, home, uid
        self.envelope = envelope or (lambda handle, module: module.require_empty_envelope(handle))
        self.checkpoint = checkpoint or (lambda point: None)
        self.persistent_identity = persistent_identity or namespace_persistent_identity
        self.boot = (boot_identity or namespace_boot)()
        need(type(self.boot) is str and re.fullmatch('[0-9a-f]{64}', self.boot) is not None)
        self.handles, self.lock = [], None
        self.fds, self.close_attempts = [], {}
        self.created = False
        self.fresh_slots = set()
        self.path = scratch + "/" + NAMESPACE
        try:
            self.parent = paths.OwnedParent.open(scratch, home, uid)
            self._hold(self.parent)
            try:
                os.stat(NAMESPACE, dir_fd=self.parent.descriptor, follow_symlinks=False)
            except FileNotFoundError:
                need(create, "fixture_custody_absent")
                os.mkdir(NAMESPACE, 0o700, dir_fd=self.parent.descriptor)
                self.created = True
                os.fsync(self.parent.descriptor)
                self.directory = paths.OwnedParent.open(self.path, home, uid)
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
                self._publish("namespace.json", self._new_namespace_marker(), None)
            else:
                # Re-read only after acquiring the named lock: neither a pre-lock
                # marker nor a pre-lock empty-slot observation can admit refresh.
                marker, prior = self._read("namespace.json")
                refresh = self._namespace_marker(marker, include_lock=True)
                if create and marker['schema'] == 1 and set(names(self.directory.descriptor, SLOTS + 2)) == {'namespace.json', 'lock'}:
                    # Exact legacy identity was verified above. Upgrade only an
                    # empty namespace; never infer identity for a stale marker.
                    refresh = True
                if refresh:
                    need(set(names(self.directory.descriptor, SLOTS + 2)) == {'namespace.json', 'lock'})
                    need(create, 'fixture_namespace_refresh_required')
                    self.checkpoint('namespace-refresh-ready')
                    self.directory.verify()
                    self._verify_lock()
                    need(set(names(self.directory.descriptor, SLOTS + 2)) == {'namespace.json', 'lock'})
                    need(self._namespace_marker(marker, include_lock=True) or marker['schema'] == 1)
                    self._publish('namespace.json', self._new_namespace_marker(), prior)
                    installed, _ = self._read('namespace.json')
                    need(self._namespace_marker(installed, include_lock=True) is False)
            os.fsync(self.directory.descriptor)
            allowed = {"namespace.json", "lock"} | {str(slot) + ".json" for slot in range(SLOTS)}
            need(set(names(self.directory.descriptor, len(allowed))) <= allowed)
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

    def _read(self, leaf):
        self.directory.verify()
        self._verify_lock()
        fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                     dir_fd=self.directory.descriptor)
        self._register(fd)
        try:
            info = os.fstat(fd)
            need(stat.S_ISREG(info.st_mode) and info.st_uid == self.uid
                 and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1
                 and 0 < info.st_size <= MAX_RECORD)
            raw = bytearray()
            while len(raw) <= MAX_RECORD:
                block = os.read(fd, MAX_RECORD + 1 - len(raw))
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

    def _publish(self, leaf, value, prior):
        raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
        need(len(raw) <= MAX_RECORD)
        self.directory.verify()
        self._verify_lock()
        temporary = leaf + ".pending"
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
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
        written, _ = self._read(temporary)
        need(written == json.loads(raw))
        self.checkpoint("record-written")
        self.directory.verify()
        self._verify_lock()
        if prior is None:
            os.link(temporary, leaf, src_dir_fd=self.directory.descriptor,
                    dst_dir_fd=self.directory.descriptor, follow_symlinks=False)
            os.unlink(temporary, dir_fd=self.directory.descriptor)
        else:
            previous, current = self._read(leaf)
            need(current == prior)
            if leaf == 'namespace.json':
                # Last pre-publication check, after record-written callbacks:
                # no old or newly appeared artifact may be silently rebound.
                need(set(names(self.directory.descriptor, SLOTS + 3)) ==
                     {'namespace.json', 'lock', 'namespace.json.pending'})
                need(self._namespace_marker(previous, include_lock=True) or previous['schema'] == 1)
                self.directory.verify()
                self._verify_lock()
            os.replace(temporary, leaf, src_dir_fd=self.directory.descriptor,
                       dst_dir_fd=self.directory.descriptor)
        self.checkpoint("record-published")
        os.fsync(self.directory.descriptor)
        self.checkpoint("record-durable")

    def _verify_lock(self):
        if self.lock is not None:
            info = os.fstat(self.lock)
            need(identity(info) == self.lock_identity and info.st_nlink == 1 and info.st_size == 0
                 and identity(os.stat("lock", dir_fd=self.directory.descriptor,
                                      follow_symlinks=False)) == self.lock_identity)

    def records(self):
        result = {}
        keys = {"schema", "slot", "token", "state", "root", "children", "schemas", "settled", "reason"}
        for slot in range(SLOTS):
            try:
                value, _ = self._read(str(slot) + ".json")
            except FileNotFoundError:
                continue
            need(type(value) is dict and type(value.get("schema")) is int
                 and value["schema"] in (1, 2)
                 and set(value) == (keys if value["schema"] == 1 else keys | {"output"})
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
            if value["schema"] == 2:
                self._validate_output(value)
            result[slot] = value
        return result

    def leaf(self, record):
        return "vendor-sentinel-" + record["token"]

    def reserve(self):
        records = self.records()
        need(len(records) < SLOTS, "fixture_capacity_required")
        need(all(record["settled"] is True for record in records.values()),
             "fixture_settlement_required")
        self.census(records)
        slot = next(slot for slot in range(SLOTS) if slot not in records)
        record = {"schema": 1, "slot": slot, "token": secrets.token_hex(16), "state": "reserved",
                  "root": None, "children": {}, "schemas": {}, "settled": True, "reason": "reserved"}
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
        need(record["schema"] == 1 and record["state"] == "allocated"
             and record["settled"] is True, "fixture_settlement_required")
        need(type(consumed_schemas) is dict and set(consumed_schemas) == set(SCHEMAS))
        output = self._output_tree(record)
        sealed = {**record, "schema": 2, "schemas": {key: list(value) for key, value in consumed_schemas.items()},
                  "output": output}
        self._validate_output(sealed)
        # Reobserve after the complete snapshot; no removal occurs on refusal.
        self._output_tree(sealed, output)
        self.update(slot, schema=2, schemas=sealed["schemas"], output=output)
        self.fresh_slots.discard(slot)

    def update(self, slot, **changes):
        need(type(slot) is int and 0 <= slot < SLOTS)
        leaf = str(slot) + ".json"
        record, prior = self._read(leaf)
        self._publish(leaf, {**record, **changes}, prior)

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
        total, entries, reason = None, None, None
        try:
            total, entries = self.census(records)
        except (CustodyError, OSError) as error:
            reason = (error.reason_class if type(error) is CustodyError else "fixture_capacity_required")
        return {"scope": "disposable-vendor-fixture-custody", "outstanding": len(records),
                "slots": [{"slot": slot, "settled": value["settled"], "state": value["state"]}
                          for slot, value in records.items()], "maximumReservations": SLOTS,
                "retainedByteAdmissionBudget": MAX_BYTES, "retainedBytesObserved": total,
                "entriesObserved": entries, "capacityReason": reason, "hardDiskQuota": False}

    def release_absent(self, slot):
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
        """Explicit restart-capable retirement of a settled exact known set.

        A persisted retiring intent permits missing *known* entries on resume,
        not new entries, changed objects, unknown descendants or inferred child
        death. Empty pre-launch constructor fixtures are also disposable.
        """
        need(type(slot) is int and 0 <= slot < SLOTS)
        records = self.records()
        need(slot in records)
        record = records[slot]
        need(record["settled"] is True and record["state"] != "inflight",
             "fixture_settlement_required")
        leaf = self.leaf(record)
        try:
            info = os.stat(leaf, dir_fd=self.parent.descriptor, follow_symlinks=False)
        except FileNotFoundError:
            need(record["state"] in ("reserved", "retiring"))
            self.update(slot, state="retiring")
            self.release_absent(slot)
            return {"scope": "disposable-vendor-fixture-custody", "retired": True, "slot": slot}
        need(record["root"] is not None and identity(info) == record["root"])
        if record["schema"] == 2:
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
