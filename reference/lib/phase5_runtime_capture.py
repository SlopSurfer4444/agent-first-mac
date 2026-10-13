"""Private, read-only admission-to-capture binding; never a live authority.

Caller opens canonical descriptors and supplies independently reviewed
admit_current(readonly_target_images)->True and recheck_dependencies()->True.
The latter must bind the SAME physical receipt/history/source/integration
generation before and after work. Receipt shape or hashes supplied alongside
bytes are NOT independent legacy/source admission. Neither callback may write
targets, dependencies or configuration; this module does not sandbox callbacks.

readiness never receives a Store and writes nothing. capture exposes only
Session.capture to the caller-owned durable Store; pinned target adapters have
no write methods. NONPASS retains any published capture without retry/deletion;
its mere existence must not be treated as admission. Checks are observed
boundaries, not continuous filesystem exclusion.
"""

from dataclasses import dataclass
import hashlib
import re
from types import MappingProxyType

from lib import phase5_runtime_session as session
from lib.phase5_runtime_compositions import compose
from lib.phase5_runtime_transition import ABSENT, Image, MAX_IMAGE_BYTES, _valid_image


TARGET_IDS = session.TARGET_IDS
RECEIPT_KEYS = frozenset(("acceptedControlCommit", "appliedOrder", "applyResult", "cli",
                          "directories", "generatedSourceHashes", "manifestSHA256", "phase",
                          "rollbackState", "runId", "schema", "sourceCommit", "state", "targets"))


class CaptureError(ValueError):
    """Fixed redacted error, never private input or callback diagnostics."""


@dataclass(frozen=True, repr=False)
class History:
    """PRIVATE tuples in TARGET_IDS order; physical originals remain separate.

Logical Images carry receipt modes, physical custody identities and no physical
seal: they are projections, NOT observed historical target identities/envelopes.
Physical tuples include the actual present absence-marker files when applicable.
"""
    before: tuple
    after: tuple
    physical_before: tuple
    physical_after: tuple


def _fail():
    raise CaptureError("capture_input_invalid") from None


def _keys(value, keys):
    return (type(value) is dict and all(type(k) is str for k in value)
            and set(value) == set(keys))


def _physical(mapping):
    if not _keys(mapping, TARGET_IDS):
        _fail()
    result = tuple(mapping[k] for k in TARGET_IDS)
    if any(not _valid_image(i) or i.data is None or i.mode != 0o600 for i in result):
        _fail()
    return result


def _logical(metadata, physical, *, allow_absent):
    if (not _keys(metadata, ("exists", "linkCount", "mode", "ownerClass", "sha256", "size"))
            or type(metadata["exists"]) is not bool or type(metadata["linkCount"]) is not int
            or type(metadata["size"]) is not int or type(metadata["ownerClass"]) is not str):
        _fail()
    if metadata["exists"] is False:
        if (not allow_absent or metadata != {"exists": False, "linkCount": 0, "mode": None,
                "ownerClass": "absent", "sha256": None, "size": 0}
                or physical.data != b"absent\n"):
            _fail()
        return ABSENT
    if (metadata["linkCount"] != 1 or type(metadata["mode"]) is not str
            or re.fullmatch(r"0[0-7]{3}", metadata["mode"]) is None
            or type(metadata["ownerClass"]) is not str or metadata["ownerClass"] != "current-user"
            or type(metadata["sha256"]) is not str
            or re.fullmatch(r"[0-9a-f]{64}", metadata["sha256"]) is None
            or not 0 <= metadata["size"] <= MAX_IMAGE_BYTES
            or metadata["size"] != len(physical.data)
            or metadata["sha256"] != hashlib.sha256(physical.data).hexdigest()):
        _fail()
    return Image(physical.data, physical.identity, int(metadata["mode"], 8))


def translate_history(receipt, physical_before, physical_after):
    """Pure targeted metadata translation, NOT full receipt/source validation.

Consumes the existing receipt envelope and exact ordered five-key target rows;
full receipt state/core/source admission remains recheck_dependencies' owner.
All historical files are physically 0600, including b'absent\\n' markers.
"""
    try:
        if (not _keys(receipt, RECEIPT_KEYS) or type(receipt["schema"]) is not int
                or receipt["schema"] != 1 or type(receipt["phase"]) is not str
                or receipt["phase"] != "phase5_codex_contract_apply"
                or type(receipt["targets"]) is not list or len(receipt["targets"]) != 8):
            _fail()
        physical_pre, physical_post = _physical(physical_before), _physical(physical_after)
        before, after = [], []
        for index, row in enumerate(receipt["targets"]):
            if (not _keys(row, ("id", "before", "after", "applied", "sourceSHA256"))
                    or type(row["id"]) is not str or row["id"] != TARGET_IDS[index]
                    or type(row["applied"]) is not bool or type(row["sourceSHA256"]) is not str
                    or re.fullmatch(r"[0-9a-f]{64}", row["sourceSHA256"]) is None):
                _fail()
            before.append(_logical(row["before"], physical_pre[index], allow_absent=index != 0))
            after.append(_logical(row["after"], physical_post[index], allow_absent=False))
        return History(tuple(before), tuple(after), physical_pre, physical_post)
    except Exception:
        raise CaptureError("history_translation_invalid") from None


class _Pinned:
    """Only the read interface used by Session.capture; no write delegation."""
    __slots__ = ("_backend", "_name", "_expected")

    def __init__(self, backend, name, expected):
        self._backend, self._name, self._expected = backend, name, expected

    def verify(self):
        self._backend.verify()

    def snapshot(self, name):
        if type(name) is not str or name != self._name:
            _fail()
        actual = self._backend.snapshot(name)
        if not _valid_image(actual) or actual != self._expected:
            _fail()
        return actual


def _report(verdict, count):
    return {"schema": 1, "verdict": verdict, "observedTargets": count,
            "executionAdmission": False, "liveAdmission": False, "phase5Accepted": False,
            "phase6Allowed": False, "cleanupPerformed": False}


def readiness(backends, receipt, physical_before, physical_after, *, admit_current,
              recheck_dependencies):
    return _run(backends, receipt, physical_before, physical_after, admit_current,
                recheck_dependencies, store=None, session_id=None, capture_only=False)


def capture(backends, store, receipt, physical_before, physical_after, *, session_id,
            admit_current, recheck_dependencies):
    return _run(backends, receipt, physical_before, physical_after, admit_current,
                recheck_dependencies, store=store, session_id=session_id, capture_only=True)


def _run(backends, receipt, physical_before, physical_after, admit_current,
         recheck_dependencies, *, store, session_id, capture_only):
    pinned, observed, check_started = None, 0, False
    result = _report("recovery-required", observed)
    try:
        if not callable(admit_current) or not callable(recheck_dependencies):
            _fail()
        check_started = True
        if recheck_dependencies() is not True:
            _fail()
        history = translate_history(receipt, physical_before, physical_after)
        names = session._bindings(backends)
        current = session._observe(backends)
        if any(i.data is None for i in current) or len(set(i.identity for i in current)) != 8:
            _fail()
        observed = 8
        pinned = {k: (_Pinned(backends[k][0], names[i], current[i]), names[i])
                  for i, k in enumerate(TARGET_IDS)}
        admitted_images = MappingProxyType(dict(zip(TARGET_IDS, current)))
        if admit_current(admitted_images) is not True:
            _fail()
        if session._observe(pinned) != current:
            _fail()
        compose(history.before[0].data, history.after[0].data, current[0].data)
        if any((live.data, live.mode) != (old.data, old.mode)
               for live, old in zip(current[2:], history.after[2:])):
            _fail()
        if capture_only:
            captured = session.capture(pinned, store, dict(zip(TARGET_IDS, history.before)),
                                       dict(zip(TARGET_IDS, history.after)), session_id=session_id)
            if captured["verdict"] != "captured":
                _fail()
        result = _report("captured" if capture_only else "ready", observed)
    except Exception:
        result = _report("recovery-required", observed)
    finally:
        # Also run postchecks after an interrupted capture. Never erase a
        # published artifact or make its existence a substitute for admission.
        if check_started:
            try:
                if recheck_dependencies() is not True:
                    _fail()
                if pinned is not None:
                    session._observe(pinned)
            except Exception:
                result = _report("recovery-required", observed)
    return result
