"""Read-only observation of ONE retained legacy generation, never a gate/CLI.

Pins below come from bin/phase5-apply-transaction LEGACY_* and the reviewed
manifests/phase5-apply-bundle.json gate.reconciledProduction, not observed input.
No caller digest override or alternate run selection exists. OwnedParent binds
canonical chains; DescriptorBackend binds physical bytes/identity/stat seal.
ACL/xattr admission beyond that backend's seal remains caller-owned. No fsync,
mkdir, config write, legacy loader, production gate or operation is dispatched.
"""

import hashlib
import json
import os
import stat

from lib.phase5_runtime_backend import DescriptorBackend
from lib.phase5_runtime_capture import RECEIPT_KEYS, TARGET_IDS, translate_history
from lib.phase5_runtime_paths import OwnedParent, _prefer_error
from lib.phase5_runtime_transition import _valid_image


LEGACY_RUN_ID = "p5-fa188ec22716bd13c56ae3c11a53e653"
LEGACY_ACCEPTED_COMMIT = "9521f21711b5d6124e295dd02305d3ac966bd6ed"
LEGACY_MANIFEST_SHA256 = "b1b096fe1b9b12b94b753972ffabc64a2dd5628f3fea1ac7cccea5c4052e9896"
LEGACY_RECEIPT_SHA256 = "814275f2ce3e81fb3617f08ee02c4d6a6992670b8b4a175966f4ca2a7b323bf9"
LEGACY_RECEIPT_CORE_SHA256 = "6bb8e7a71b5fcdb83773387f739c5df6101a171253beeab0247715606e32162c"
COMPANION_SHA256 = "09a95e24c47094fed108a4694c884a0320faf2537d4405a0cb9d993815da3495"
OVERLAY_PREIMAGE_SHA256 = "99ab76e732e8ae705578228a1b2ef90b78e28b2c45523ef01cb1a96e568d4964"
OVERLAY_PREIMAGE_LENGTH = 6300
COMPANION = "external-config-overlay.json"
OVERLAY_PREIMAGE = "config-before-overlay-reconciliation"
MAX_RECEIPT_BYTES = 256 * 1024
_ADMISSION = object()


class LegacyError(ValueError):
    """Fixed redacted reason; no private bytes, names, hashes or IDs."""


def _fail():
    raise LegacyError("runtime_legacy_observation_required") from None


def _keys(value, names):
    return type(value) is dict and all(type(k) is str for k in value) and set(value) == set(names)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _fail()
        result[key] = value
    return result


def _json(raw):
    if type(raw) is not bytes or len(raw) > MAX_RECEIPT_BYTES:
        _fail()
    return json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=lambda _: _fail())


def _core(receipt):
    value = _json(json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode())
    for key in ("appliedOrder", "applyResult", "rollbackState", "state"):
        value.pop(key, None)
    for row in value["targets"]:
        row.pop("applied", None)
    for row in value["directories"]:
        row.pop("createdByApply", None)
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _file(backend, name):
    image = backend.snapshot(name)
    if not _valid_image(image) or image.data is None or image.mode != 0o600:
        _fail()
    return image


def _parent(parent, syscalls):
    if parent.verify() is False:
        _fail()
    facts = syscalls.fstat(parent.descriptor)
    if (type(facts.st_mode) is not int or not stat.S_ISDIR(facts.st_mode)
            or stat.S_IMODE(facts.st_mode) != 0o700):
        _fail()


def _names(parent, expected, syscalls):
    _parent(parent, syscalls)
    names = set()
    with syscalls.scandir(parent.descriptor) as entries:
        for entry in entries:
            name = entry.name
            if type(name) is not str or name not in expected or name in names:
                _fail()
            names.add(name)
            if len(names) > len(expected):
                _fail()
    if names != set(expected):
        _fail()
    _parent(parent, syscalls)


def _release(parents, error=None):
    while parents:
        parent = parents.pop()  # Never retry a close that may have released handles.
        try:
            parent.close()
        except BaseException as caught:
            error = _prefer_error(error, caught)
    return error


class HeldLegacy:
    """PRIVATE held observation. Caller must close; failure closes automatically.

Properties return fresh maps/receipt, not mutable admission state. History
contains the original physical snapshots separately from logical-mode Images.
verify() proves only this fixed historical generation, never live readiness.
"""
    def __init__(self, token, parents, backends, syscalls, names, snapshots, before_names, history):
        if token is not _ADMISSION:
            _fail()
        self._parents, self._backends, self._os = parents, backends, syscalls
        self._names, self._snapshots, self._before_names = names, snapshots, before_names
        self._history = history

    @property
    def history(self):
        return self._history

    @property
    def receipt(self):
        return _json(self._snapshots[0]["receipt.json"].data)

    @property
    def companion(self):
        return _json(self._snapshots[0][COMPANION].data)

    @property
    def receipt_image(self):
        return self._snapshots[0]["receipt.json"]

    @property
    def companion_image(self):
        return self._snapshots[0][COMPANION]

    @property
    def overlay_preimage(self):
        return self._snapshots[1][OVERLAY_PREIMAGE]

    @property
    def physical_before(self):
        return {k: self._snapshots[1][name] for k, name in zip(TARGET_IDS, self._before_names)}

    @property
    def physical_after(self):
        return dict(self._snapshots[2])

    def verify(self):
        try:
            if len(self._parents) != 3:
                _fail()
            for _ in range(2):
                for parent, backend, names, snapshots in zip(self._parents, self._backends, self._names, self._snapshots):
                    _names(parent, names, self._os)
                    for name, expected in snapshots.items():
                        if _file(backend, name) != expected:
                            _fail()
                    _names(parent, names, self._os)
            return True
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


def observe(home, uid, *, syscalls=os, parent_open=None, backend_factory=None):
    """Open only the fixed root/preimages/staged below caller's canonical home.

Injection is for reviewed I/O adapters/fakes, not alternate expected evidence.
No raw receipt or historical file is obtained except through held backends.
"""
    parents = []
    try:
        if type(home) is not str or not home.startswith("/") or home.endswith("/"):
            _fail()
        opener = OwnedParent.open if parent_open is None else parent_open
        factory = DescriptorBackend if backend_factory is None else backend_factory
        root = home + "/AIDev/state/codex-transactions/" + LEGACY_RUN_ID
        for path in (root, root + "/preimages", root + "/staged"):
            parent = opener(path, home, uid, syscalls=syscalls)
            parents.append(parent)
            _parent(parent, syscalls)
        backends = tuple(factory(p, syscalls=syscalls, maximum=MAX_RECEIPT_BYTES if i == 0 else 1024 * 1024)
                         for i, p in enumerate(parents))
        root_names = frozenset(("receipt.json", COMPANION, "preimages", "staged"))
        _names(parents[0], root_names, syscalls)
        receipt_image, companion_image = _file(backends[0], "receipt.json"), _file(backends[0], COMPANION)
        if (hashlib.sha256(receipt_image.data).hexdigest() != LEGACY_RECEIPT_SHA256
                or hashlib.sha256(companion_image.data).hexdigest() != COMPANION_SHA256):
            _fail()
        receipt, companion = _json(receipt_image.data), _json(companion_image.data)
        if (not _keys(receipt, RECEIPT_KEYS) or type(receipt["schema"]) is not int or receipt["schema"] != 1
                or receipt["runId"] != LEGACY_RUN_ID or receipt["phase"] != "phase5_codex_contract_apply"
                or receipt["acceptedControlCommit"] != LEGACY_ACCEPTED_COMMIT
                or receipt["sourceCommit"] != LEGACY_ACCEPTED_COMMIT
                or receipt["manifestSHA256"] != LEGACY_MANIFEST_SHA256
                or (receipt["state"], receipt["applyResult"], receipt["rollbackState"]) != ("applied", "applied", "available")
                or _core(receipt) != LEGACY_RECEIPT_CORE_SHA256):
            _fail()
        if (type(companion) is not dict or type(companion.get("schema")) is not int or companion["schema"] != 1
                or companion.get("phase") != "phase5_external_config_overlay" or companion.get("runId") != LEGACY_RUN_ID
                or (companion.get("state"), companion.get("rollbackState")) != ("reconciled", "not-required")
                or companion.get("receiptCoreSHA256") != LEGACY_RECEIPT_CORE_SHA256
                or companion.get("receiptSHA256AtReconciliation") != LEGACY_RECEIPT_SHA256
                or companion.get("configBeforeReconciliationSHA256") != OVERLAY_PREIMAGE_SHA256):
            _fail()
        if (type(receipt["targets"]) is not list or len(receipt["targets"]) != 8
                or [row.get("id") for row in receipt["targets"]] != list(TARGET_IDS)
                or any(type(row["before"]["exists"]) is not bool for row in receipt["targets"])):
            _fail()
        before_names = tuple(row["id"] if row["before"]["exists"] is True else row["id"] + ".absent"
                             for row in receipt["targets"])
        names = (root_names, frozenset(before_names + (OVERLAY_PREIMAGE,)), frozenset(TARGET_IDS))
        for parent, expected in zip(parents, names):
            _names(parent, expected, syscalls)
        snapshots = ({"receipt.json": receipt_image, COMPANION: companion_image},
                     {name: _file(backends[1], name) for name in sorted(names[1])},
                     {name: _file(backends[2], name) for name in TARGET_IDS})
        overlay = snapshots[1][OVERLAY_PREIMAGE]
        if len(overlay.data) != OVERLAY_PREIMAGE_LENGTH or hashlib.sha256(overlay.data).hexdigest() != OVERLAY_PREIMAGE_SHA256:
            _fail()
        before = {k: snapshots[1][name] for k, name in zip(TARGET_IDS, before_names)}
        history = translate_history(receipt, before, snapshots[2])
        held = HeldLegacy(_ADMISSION, parents, backends, syscalls, names, snapshots, before_names, history)
        held.verify()
        return held
    except BaseException as error:
        error = _release(parents, error)
        if isinstance(error, Exception):
            _fail()
        raise error from None
