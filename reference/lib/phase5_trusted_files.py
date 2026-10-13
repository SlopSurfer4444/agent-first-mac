"""Two transient PRIVATE trusted-task files under one owned scratch child.

All OS/dependency/source admission is explicitly injected. No process, model,
entry point, caller-selected filenames, retry, recursive cleanup or automatic
cleanup exists. Source/schema semantics and genuine child settlement remain
root obligations. Root must exclude an ambiguous/live writer before result or
cleanup. Raw result bytes are exposed only after its affirmative settlement.

Checks bind observed boundaries, not filesystem CAS: mkdir has no atomic
returned inode, and unlink/rmdir have no inode-conditional form. An observed
third state stops deletion. Failures retain the original private context and
remaining names; no lifetime/recovery claim extends past interpreter exit.
"""

from dataclasses import dataclass
import json
import re


MAX_BYTES = 1024 * 1024
NAMES = ("schema.json", "result.json")
_ERROR_CONTEXT_LIMIT = 64


class TrustedFilesError(Exception):
    def __init__(self, *, private_owner=None):
        self.private_owner = private_owner
        super().__init__("trusted_files_recovery_required")


def _require(condition):
    if condition is not True:
        raise TrustedFilesError() from None


@dataclass(frozen=True, repr=False)
class Result:
    data: bytes
    _snapshot: object


class HeldFiles:
    """PRIVATE context; close releases descriptors, never deletes artifacts."""
    def __init__(self, home, uid, leaf, schema, paths, backend, syscalls, platform):
        self._home, self._uid, self._leaf, self._schema = home, uid, leaf, schema
        self._paths, self._backend_module, self._os, self._platform = paths, backend, syscalls, platform
        self._parents, self._initial, self._result = [], {}, None
        self._complete = self._closed = self._cleanup_started = self._removed = False
        self._error = None
        self._directory = home + "/AIDev/scratch/" + leaf

    def _failed(self, error):
        # A dependency's finally-close can mask an earlier interruption, even
        # with another interruption. Recover the deepest observed one without
        # recursing or following an unbounded/cyclic exception context chain.
        selected, cursor, seen = error, error, set()
        for _ in range(_ERROR_CONTEXT_LIMIT):
            if cursor is None or id(cursor) in seen:
                break
            seen.add(id(cursor))
            if isinstance(cursor, (KeyboardInterrupt, SystemExit)):
                selected = cursor
            cursor = cursor.__context__
        self._error = self._paths._prefer_error(self._error, selected)
        if isinstance(self._error, (KeyboardInterrupt, SystemExit)):
            self._error.private_owner = self
            raise self._error from None
        raise TrustedFilesError(private_owner=self) from None

    def _guard(self, operation):
        try:
            return operation()
        except BaseException as error:
            self._failed(error)

    @property
    def directory_path(self):
        return self._directory

    @property
    def schema_path(self):
        return self._directory + "/schema.json"

    @property
    def result_path(self):
        return self._directory + "/result.json"

    def _parent(self):
        _require(not self._closed and len(self._parents) == 2 and not self._removed)
        parent = self._parents[1]
        self._paths.require_empty_envelope(parent, syscalls=self._os, platform=self._platform)
        _require(self._paths._identity(self._os.fstat(parent.descriptor), directory=True) == self._child_identity)
        return parent

    def _names(self, expected):
        parent = self._parent()
        first = self._paths._observation(self._os.fstat(parent.descriptor))
        observed = []
        with self._os.scandir(parent.descriptor) as entries:
            for entry in entries:
                _require(len(observed) < 2)
                observed.append(entry.name)
        _require(set(observed) == set(expected) and len(observed) == len(expected))
        _require(self._paths._observation(self._os.fstat(parent.descriptor)) == first)
        self._parent()

    def _admit_descriptor(self, descriptor):
        envelope = self._paths.observe_envelope(descriptor, syscalls=self._os, platform=self._platform)
        _require(envelope.acl_entries == 0 and envelope.xattr_names == ())
        return True

    def _snapshot(self, name):
        _require(name in NAMES)
        parent = self._parent()
        image = self._io.snapshot(name)
        _require(image.data is not None and image.mode == 0o600 and len(image.data) <= MAX_BYTES)
        descriptor = self._os.open(name, self._backend_module.READ_FLAGS, dir_fd=parent.descriptor)
        descriptors = [descriptor]
        try:
            first = self._backend_module._facts(self._os.fstat(descriptor), self._uid, MAX_BYTES)
            _require(first[6] == 0)
            _require(self._backend_module._image(image.data, self._os.fstat(descriptor)) == image)
            self._admit_descriptor(descriptor)
            _require(self._io.snapshot(name) == image)
            _require(self._backend_module._facts(self._os.fstat(descriptor), self._uid, MAX_BYTES) == first)
            self._parent()
            return image, first
        finally:
            self._paths._close_all(self._os, descriptors)

    def _allocate(self):
        scratch = self._paths.OwnedParent.open(self._home + "/AIDev/scratch", self._home,
                                               self._uid, syscalls=self._os)
        self._parents.append(scratch)
        scratch.verify()
        self._os.mkdir(self._leaf, 0o700, dir_fd=scratch.descriptor)
        self._child_identity = self._paths._identity(self._os.stat(
            self._leaf, dir_fd=scratch.descriptor, follow_symlinks=False), directory=True)
        child = self._paths.OwnedParent.open(self._directory, self._home, self._uid, syscalls=self._os)
        self._parents.append(child)
        self._names(())
        self._os.fsync(child.descriptor)
        self._os.fsync(scratch.descriptor)
        self._names(())
        self._io = self._backend_module.DescriptorBackend(child, syscalls=self._os, maximum=MAX_BYTES)
        for name, raw in zip(NAMES, (self._schema, b"")):
            image = self._io.create_exclusive(name, raw, 0o600, admit_descriptor=self._admit_descriptor)
            self._initial[name] = self._snapshot(name)
            _require(self._initial[name][0] == image)
        _require(self._initial[NAMES[0]][0].identity != self._initial[NAMES[1]][0].identity)
        self._complete = True
        return self.verify_initial()

    def verify_initial(self):
        def verify():
            _require(self._complete and not self._cleanup_started and self._error is None)
            self._names(NAMES)
            _require(all(self._snapshot(name) == self._initial[name] for name in NAMES))
            return True
        return self._guard(verify)

    def result(self, *, child_settled):
        def observe():
            _require(child_settled is True and self._complete and not self._cleanup_started
                     and self._error is None)
            self._names(NAMES)
            _require(self._snapshot(NAMES[0]) == self._initial[NAMES[0]])
            current = self._snapshot(NAMES[1])
            image, first = current
            _require(image.identity == self._initial[NAMES[1]][0].identity
                     and first[:7] == self._initial[NAMES[1]][1][:7])
            _require(self._snapshot(NAMES[0]) == self._initial[NAMES[0]] and self._snapshot(NAMES[1]) == current)
            self._result = Result(image.data, current)
            return self._result
        return self._guard(observe)

    def cleanup(self, observation, *, child_settled):
        """One explicit removal attempt after exact settled image comparison.

A partial removal/close failure leaves remaining state/context retained. No
second cleanup, fallback deletion or compensation follows an uncertain call.
"""
        def remove():
            _require(child_settled is True and self._complete and self._error is None
                     and not self._cleanup_started and observation is self._result
                     and type(observation) is Result)
            expected = {NAMES[0]: self._initial[NAMES[0]], NAMES[1]: observation._snapshot}
            self._names(NAMES)
            _require(all(self._snapshot(name) == image for name, image in expected.items()))
            self._cleanup_started = True
            parent = self._parents[1]
            for name in NAMES:
                self._names(expected)
                _require(all(self._snapshot(leaf) == image for leaf, image in expected.items()))
                self._os.unlink(name, dir_fd=parent.descriptor)
                del expected[name]
                self._io.sync()
                self._names(expected)
            self._names(())
            scratch = self._parents[0]
            scratch.verify()
            parent.verify()
            self._os.rmdir(self._leaf, dir_fd=scratch.descriptor)
            self._removed = True
            self._os.fsync(scratch.descriptor)
            scratch.verify()
            try:
                self._os.stat(self._leaf, dir_fd=scratch.descriptor, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                _require(False)
            self.close()
            return {"filesRemoved": 2, "directoryRemoved": True, "handlesClosed": True,
                    "executionAdmission": False, "phase5Accepted": False}
        return self._guard(remove)

    def close(self):
        selected = self._error
        self._closed = True
        while self._parents:
            parent = self._parents.pop()
            try:
                parent.close()
            except BaseException as error:
                selected = self._paths._prefer_error(selected, error)
        if selected is not None:
            self._failed(selected)


def allocate(home, uid, leaf, schema, *, admit_sources, paths, backend, syscalls, platform):
    """Explicit independent inputs only; no native defaults or random-name retry."""
    try:
        _require(type(home) is str and home.startswith("/Users/")
                 and len(paths._parts(home)) == 2 and type(uid) is int and 0 < uid < 2 ** 32)
        _require(type(leaf) is str and re.fullmatch(r"phase5-trusted-task\.[A-Za-z0-9]{6,32}", leaf) is not None)
        _require(type(schema) is bytes and 0 < len(schema) <= MAX_BYTES and backend.MAX_IMAGE_BYTES >= MAX_BYTES)
        def unique(pairs):
            result = {}
            for key, value in pairs:
                _require(key not in result)
                result[key] = value
            return result
        def invalid_constant(_):
            _require(False)
        document = json.loads(schema.decode("utf-8", "strict"), object_pairs_hook=unique,
                              parse_constant=invalid_constant)
        _require(type(document) is dict and bool(document))
        _require(callable(admit_sources) and admit_sources() is True)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise TrustedFilesError() from None
    owner = HeldFiles(home, uid, leaf, schema, paths, backend, syscalls, platform)
    owner._guard(owner._allocate)
    return owner
