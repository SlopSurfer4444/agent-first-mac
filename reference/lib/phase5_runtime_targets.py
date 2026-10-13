"""Fixed eight current targets: private read-only images and metadata envelopes.

No admission, classifier, Store or dispatch. Caller owns current
guidance/source/integration policy. Nonempty metadata is observed, never erased
or automatically trusted. Envelopes contain bounded ACL counts/xattr names, not
principals or values; they cannot attest inaccessible kernel metadata. Five
leaf-parent envelopes are retained, but HOME/ancestor ACLs are not inspected.
File ctime is additionally pinned for this read-only operation (no rename).
Current owner-selected global guidance may be 0600 or 0644 under ARCHITECTURE
section40; its observed mode is preserved, never normalized. Other modes stay
fixed by the target rows below. Historical receipt modes are not changed.
Checks bind observed boundaries, not continuous filesystem exclusion.
An explicit one-session transition handoff borrows these same held parents.
It adds only fixed-name and empty-file-envelope guards to DescriptorBackend;
Session owns desired images and durable intent. Original read-only checks stay
pinned and must not be used as post-transition observations.
"""

import os
import re

from lib.phase5_runtime_backend import DescriptorBackend, READ_FLAGS, _facts, _image
from lib.phase5_runtime_paths import OwnedParent, observe_envelope, _close_all, _prefer_error
from lib.phase5_runtime_transition import ABSENT, MAX_IMAGE_BYTES, _valid_image


PARENTS = (".codex", ".codex/hooks", ".codex/skills/manage-workstation",
           ".codex/skills/manage-workstation/agents", "AIDev/bin")
ROWS = (("config", 0, "config.toml", 0o600), ("global-agents", 0, "AGENTS.md", 0o600),
        ("quarantine-profile", 0, "quarantine.config.toml", 0o600), ("hooks-definition", 0, "hooks.json", 0o600),
        ("hook-router", 1, "phase5-contract.py", 0o600), ("skill-definition", 2, "SKILL.md", 0o600),
        ("skill-metadata", 3, "openai.yaml", 0o600), ("quarantine-launcher", 4, "codex-quarantine", 0o700))
_ADMISSION = object()


class TargetsError(ValueError):
    """Fixed redacted reason only."""


def _fail():
    raise TargetsError("runtime_targets_observation_required") from None


def _release(parents, error=None):
    while parents:
        parent = parents.pop()
        try:
            parent.close()
        except BaseException as caught:
            error = _prefer_error(error, caught)
    return error


def _parent_envelope(parent, syscalls, platform):
    if parent.verify() is False:
        _fail()
    envelope = observe_envelope(parent.descriptor, syscalls=syscalls, platform=platform)
    if parent.verify() is False:
        _fail()
    return envelope


def _target(parent, backend, identifier, name, mode, syscalls, platform, *, transition=False):
    image = backend.snapshot(name)
    allowed_modes = (0o600, 0o644) if identifier == "global-agents" else (mode,)
    if not _valid_image(image):
        _fail()
    if transition and image == ABSENT:
        parent.verify()
        if backend.snapshot(name) != ABSENT:
            _fail()
        parent.verify()
        return image, None, None
    if image.data is None or (not transition and image.mode not in allowed_modes):
        _fail()
    parent.verify()
    descriptor = syscalls.open(name, READ_FLAGS, dir_fd=parent.descriptor)
    try:
        first = syscalls.fstat(descriptor)
        stamp = _facts(first, parent.uid, MAX_IMAGE_BYTES)
        if _image(image.data, first) != image:
            _fail()
        envelope = observe_envelope(descriptor, syscalls=syscalls, platform=platform)
        second = backend.snapshot(name)
        final = syscalls.fstat(descriptor)
        named = syscalls.stat(name, dir_fd=parent.descriptor, follow_symlinks=False)
        if (not _valid_image(second) or second != image
                or _facts(final, parent.uid, MAX_IMAGE_BYTES) != stamp
                or _facts(named, parent.uid, MAX_IMAGE_BYTES) != stamp):
            _fail()
        parent.verify()
        return image, envelope, stamp
    finally:
        _close_all(syscalls, [descriptor])


class _ReadOnly:
    __slots__ = ("_held", "_index")

    def __init__(self, held, index):
        self._held, self._index = held, index

    def verify(self):
        self._held._verify_parents()

    def snapshot(self, name):
        if type(name) is not str or name != ROWS[self._index][2]:
            self._held.close()
            _fail()
        return self._held._checked(self._index)[0]


class _Transition:
    """Fixed session-name capability; no descriptor ownership or recovery API."""
    __slots__ = ("_held", "_index", "_session", "_target", "_temporary", "_names")

    def __init__(self, held, index, session_id):
        self._held, self._index, self._session = held, index, session_id
        self._target = ROWS[index][2]
        prefixes = tuple(session_id + "-" + action + "-" + str(index) for action in ("rollback", "return"))
        self._temporary = tuple(prefix + "-tmp" for prefix in prefixes)
        self._names = (self._target,) + tuple(prefix + suffix for prefix in prefixes for suffix in ("-tmp", "-rec"))

    def _verify(self):
        if self._held._transition_session != self._session:
            _fail()
        self._held._verify_parents()
        return True

    def verify(self):
        return self._held._guard(self._verify)

    def _name(self, name):
        if type(name) is not str or name not in self._names:
            _fail()

    def _snapshot(self, name):
        self._name(name)
        self._verify()
        if self._index == 1 and name == self._target:
            return self._held._checked(self._index)[0]
        identifier, parent_index, _, mode = ROWS[self._index]
        image, envelope, _ = _target(self._held._parents[parent_index], self._held._backends[parent_index],
            identifier, name, mode, self._held._os, self._held._platform, transition=True)
        if envelope is not None and (envelope.acl_entries != 0 or envelope.xattr_names):
            _fail()
        self._verify()
        return image

    def snapshot(self, name):
        return self._held._guard(lambda: self._snapshot(name))

    def _admit_stage(self, descriptor):
        # The backend lends the newly-created empty FD BEFORE write/chmod.
        # It additionally checks named identity and empty-file facts afterwards.
        self._verify()
        uid = self._held._parents[ROWS[self._index][1]].uid
        stamp = _facts(self._held._os.fstat(descriptor), uid, MAX_IMAGE_BYTES)
        envelope = observe_envelope(descriptor, syscalls=self._held._os, platform=self._held._platform)
        if (envelope.acl_entries != 0 or envelope.xattr_names
                or _facts(self._held._os.fstat(descriptor), uid, MAX_IMAGE_BYTES) != stamp):
            _fail()
        self._verify()
        return True

    def create_exclusive(self, name, data, mode):
        def create():
            self._name(name)
            if self._index == 1 or name not in self._temporary or self._snapshot(name) != ABSENT:
                _fail()
            backend = self._held._backends[ROWS[self._index][1]]
            image = backend.create_exclusive(name, data, mode, admit_descriptor=self._admit_stage)
            if not _valid_image(image) or self._snapshot(name) != image:
                _fail()
            return image
        return self._held._guard(create)

    def _move(self, source, destination, *, swap):
        def move():
            self._name(source)
            self._name(destination)
            if self._index == 1 or not (
                source in self._temporary and destination == self._target
                or not swap and source == self._target and destination in self._temporary):
                _fail()
            before = (self._snapshot(source), self._snapshot(destination))
            backend = self._held._backends[ROWS[self._index][1]]
            operation = backend.swap if swap else backend.move_exclusive
            if operation(source, destination) is not None:
                _fail()
            expected = (before[1] if swap else ABSENT, before[0])
            if (self._snapshot(source), self._snapshot(destination)) != expected:
                _fail()
        return self._held._guard(move)

    def swap(self, source, destination):
        return self._move(source, destination, swap=True)

    def move_exclusive(self, source, destination):
        return self._move(source, destination, swap=False)

    def sync(self):
        def sync():
            before = tuple(self._snapshot(name) for name in self._names)
            self._held._backends[ROWS[self._index][1]].sync()
            if tuple(self._snapshot(name) for name in self._names) != before:
                _fail()
        return self._held._guard(sync)


class HeldTargets:
    """PRIVATE held observation; all read-only bindings borrow this lifetime.

Close explicitly or use a context manager. Any observed failure/interrupt
closes every owned chain. Returned maps are copies; metadata stays private.
"""
    def __init__(self, token, parents, backends, syscalls, platform, parent_envelopes, observations):
        if token is not _ADMISSION:
            _fail()
        self._parents, self._backends, self._os, self._platform = parents, backends, syscalls, platform
        self._parent_envelopes, self._observations = parent_envelopes, observations
        self._transition_session = None

    @property
    def images(self):
        return {row[0]: value[0] for row, value in zip(ROWS, self._observations)}

    @property
    def envelopes(self):
        return {row[0]: value[1] for row, value in zip(ROWS, self._observations)}

    @property
    def parent_envelopes(self):
        return dict(zip(PARENTS, self._parent_envelopes))

    @property
    def metadata_empty(self):
        return {key: value.acl_entries == 0 and not value.xattr_names for key, value in self.envelopes.items()}

    @property
    def parent_metadata_empty(self):
        return {key: value.acl_entries == 0 and not value.xattr_names for key, value in self.parent_envelopes.items()}

    @property
    def bindings(self):
        return {row[0]: (_ReadOnly(self, i), row[2]) for i, row in enumerate(ROWS)}

    def transition_bindings(self, session_id):
        """One explicit transfer after caller-owned current admission/capture.

The returned adapters borrow this holder, never reopen/close its parents, and
do not prove capture or authorize actions. Close/failure invalidates all of
them. Existing read-only bindings and verify remain original-image checks.
"""
        def transfer():
            if (self._transition_session is not None or type(session_id) is not str
                    or re.fullmatch(r"p5-[0-9a-f]{32}", session_id) is None):
                _fail()
            self.verify()
            if not all(self.metadata_empty.values()):
                _fail()
            self._transition_session = session_id
            return {row[0]: (_Transition(self, i, session_id), row[2]) for i, row in enumerate(ROWS)}
        return self._guard(transfer)

    def _guard(self, operation):
        try:
            if len(self._parents) != 5:
                _fail()
            return operation()
        except BaseException as error:
            error = _release(self._parents, error)
            if isinstance(error, Exception):
                _fail()
            raise error from None

    def _verify_parents(self):
        def check():
            for parent, expected in zip(self._parents, self._parent_envelopes):
                if _parent_envelope(parent, self._os, self._platform) != expected:
                    _fail()
        return self._guard(check)

    def _checked(self, index):
        def check():
            self._verify_parents()
            identifier, parent_index, name, mode = ROWS[index]
            value = _target(self._parents[parent_index], self._backends[parent_index], identifier, name, mode, self._os, self._platform)
            if value != self._observations[index]:
                _fail()
            self._verify_parents()
            return value
        return self._guard(check)

    def verify(self):
        def check():
            for _ in range(2):
                for index in range(8):
                    self._checked(index)
            self._verify_parents()
            return True
        return self._guard(check)

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


def observe(home, uid, *, syscalls=os, platform=None, parent_open=None, backend_factory=None):
    """Fixed paths only. I/O/metadata injection is for reviewed adapters/fakes."""
    parents = []
    try:
        if type(home) is not str or not home.startswith("/") or home.endswith("/"):
            _fail()
        opener = OwnedParent.open if parent_open is None else parent_open
        factory = DescriptorBackend if backend_factory is None else backend_factory
        for suffix in PARENTS:
            parents.append(opener(home + "/" + suffix, home, uid, syscalls=syscalls))
        backends = tuple(factory(parent, syscalls=syscalls) for parent in parents)
        parent_envelopes = tuple(_parent_envelope(p, syscalls, platform) for p in parents)
        observations = tuple(_target(parents[p], backends[p], identifier, name, mode, syscalls, platform)
                             for identifier, p, name, mode in ROWS)
        if len(set(value[0].identity for value in observations)) != 8:
            _fail()
        held = HeldTargets(_ADMISSION, parents, backends, syscalls, platform, parent_envelopes, observations)
        held.verify()
        return held
    except BaseException as error:
        error = _release(parents, error)
        if isinstance(error, Exception):
            _fail()
        raise error from None
