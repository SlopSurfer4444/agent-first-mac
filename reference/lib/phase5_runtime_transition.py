"""Descriptor-backend image transitions, with retained evidence and no unlink.

This is NOT filesystem CAS or continuous exclusion. A name can change after a
check and before rename. We check observed boundaries, retain displaced files
on races, and never compensate an observed unknown state. The caller owns the
durable private ticket/intent, authorization and later evidence retirement.

Backend methods: verify() validates the held parent and its named chain;
snapshot(leaf) returns Image after no-follow, owner/link/envelope checks;
create_exclusive(leaf, bytes, mode) returns its freshly bound Image;
swap(a,b) is descriptor-relative RENAME_SWAP; move_exclusive(a,b) is
RENAME_EXCL; sync() fsyncs the held parent. All names share that descriptor.
No backend method may silently clean up, retry, compensate or delete evidence.
Legacy atomic_install/apply/rollback are deliberately not used.
"""

from dataclasses import dataclass
import re


MAX_IMAGE_BYTES = 1024 * 1024


class TransitionError(ValueError):
    """Fixed redacted error; partial preparation must be retained by the caller."""


@dataclass(frozen=True, repr=False)
class Image:
    data: object
    identity: object
    mode: object
    # Optional private rename-stable metadata binding (e.g. ACL/xattrs/flags).
    # Backend owns its definition; never include rename-varying ctime here.
    seal: bytes = b""

    def __post_init__(self):
        if not _valid_image(self):
            raise TransitionError("transition_image_invalid") from None


def _fields(value, cls, names):
    # Frozen dataclasses can still be partially restored via __new__. Do not
    # consume values (or invoke their equality/repr) until all types are checked.
    if type(value) is not cls:
        return False
    fields = vars(value)
    return (len(fields) == len(names) and all(type(k) is str for k in fields)
            and set(fields) == set(names))


def _valid_image(image):
    if not _fields(image, Image, ("data", "identity", "mode", "seal")):
        return False
    if type(image.seal) is not bytes or len(image.seal) > 16384:
        return False
    if image.data is None:
        return image.identity is None and image.mode is None and image.seal == b""
    return (type(image.data) is bytes and len(image.data) <= MAX_IMAGE_BYTES
            and type(image.identity) is tuple and len(image.identity) == 2
            and all(type(n) is int and n >= 0 for n in image.identity)
            and type(image.mode) is int and 0 <= image.mode <= 0o777)


ABSENT = Image(None, None, None)


@dataclass(frozen=True, repr=False)
class Ticket:
    target: str
    temporary: str
    recovery: str
    source: Image
    destination: Image
    noop: bool


def _names(target, temporary, recovery):
    names = (target, temporary, recovery)
    return (all(type(n) is str and re.fullmatch(r"[A-Za-z0-9._-]{1,128}", n)
                and n not in (".", "..") for n in names) and len(set(names)) == 3)


def _valid_ticket(ticket):
    valid = (_fields(ticket, Ticket, ("target", "temporary", "recovery", "source",
                                      "destination", "noop"))
            and _names(ticket.target, ticket.temporary, ticket.recovery)
            and _valid_image(ticket.source) and _valid_image(ticket.destination)
            and type(ticket.noop) is bool)
    if not valid:
        return False
    source, destination = ticket.source, ticket.destination
    if ticket.noop:
        return source == destination
    return (not (source.data == destination.data and source.mode == destination.mode)
            and (source == ABSENT or destination == ABSENT
                 or source.identity != destination.identity))


def _read(backend, ticket):
    backend.verify()
    names = (ticket.target, ticket.temporary, ticket.recovery)
    first = tuple(backend.snapshot(n) for n in names)
    backend.verify()
    second = tuple(backend.snapshot(n) for n in names)
    backend.verify()
    if (any(not _valid_image(x) for x in first + second) or first != second):
        raise TransitionError("transition_observation_changed") from None
    return second


def _state(ticket, images):
    target, temporary, recovery = images
    source, destination = ticket.source, ticket.destination
    if ticket.noop:
        return "origin" if images == (source, ABSENT, ABSENT) else "unknown"
    if recovery != ABSENT:
        if source == ABSENT and images == (ABSENT, ABSENT, destination):
            return "recovered"
        return "unknown"
    if source == ABSENT:
        origin, finished = (ABSENT, destination, ABSENT), (destination, ABSENT, ABSENT)
    elif destination == ABSENT:
        origin, finished = (source, ABSENT, ABSENT), (ABSENT, source, ABSENT)
    else:
        origin, finished = (source, destination, ABSENT), (destination, source, ABSENT)
    return "origin" if images == origin else "destination" if images == finished else "unknown"


def _report(verdict, reason):
    return {"schema": 1, "verdict": verdict, "reason": reason,
            "executionAdmission": False, "cleanupPerformed": False}


def prepare(backend, *, target, temporary, recovery, source, destination_bytes, mode):
    """Create only an exclusive owned staging image; never change target.

The returned Ticket is PRIVATE. Persist it with transition intent before
calling transition. Preparation failure retains any partial staging object;
it must not be retried against the same names or blindly cleaned up.
"""
    if (not _names(target, temporary, recovery) or not _valid_image(source)
            or (destination_bytes is None and mode is not None)
            or (destination_bytes is not None and
                (type(destination_bytes) is not bytes or len(destination_bytes) > MAX_IMAGE_BYTES
                 or type(mode) is not int or not 0 <= mode <= 0o777))):
        raise TransitionError("transition_input_invalid") from None
    shell = Ticket(target, temporary, recovery, source, ABSENT, False)
    try:
        if _read(backend, shell) != (source, ABSENT, ABSENT):
            raise TransitionError("transition_prepare_conflict")
        noop = source.data == destination_bytes and source.mode == mode
        if noop:
            destination = source
        elif destination_bytes is None:
            destination = ABSENT
        else:
            destination = backend.create_exclusive(temporary, destination_bytes, mode)
            if (not _valid_image(destination) or destination.data != destination_bytes
                    or destination.mode != mode or destination.identity == source.identity):
                raise TransitionError("transition_staging_invalid")
        ticket = Ticket(target, temporary, recovery, source, destination, noop)
        if _state(ticket, _read(backend, ticket)) != "origin":
            raise TransitionError("transition_prepare_conflict")
        backend.sync()
        return ticket
    except Exception:
        raise TransitionError("transition_preparation_recovery_required") from None


def classify(backend, ticket):
    """Redacted observation only; origin/destination are not execution rights."""
    if not _valid_ticket(ticket):
        return _report("recovery-required", "ticket-invalid")
    try:
        state = _state(ticket, _read(backend, ticket))
        return _report(state if state != "unknown" else "recovery-required",
                       "known-images" if state != "unknown" else "unknown-image")
    except Exception:
        return _report("recovery-required", "observation-failed")


def transition(backend, ticket):
    """One forward rename at most; no implicit compensation or retry."""
    return _operate(backend, ticket, returning=False)


def recover(backend, ticket):
    """Explicit compensation to this ticket's origin, only from known images.

This does not select a transaction recovery direction: the caller's durable
intent must authorize compensation. Retained staging/displaced files remain.
"""
    return _operate(backend, ticket, returning=True)


def _operate(backend, ticket, returning):
    if not _valid_ticket(ticket):
        return _report("recovery-required", "ticket-invalid")
    try:
        state = _state(ticket, _read(backend, ticket))
        if state == "unknown":
            return _report("recovery-required", "unknown-image")
        if (ticket.noop or (returning and state in ("origin", "recovered"))
                or (not returning and state == "destination")):
            # An earlier rename may have succeeded but failed to sync. A known
            # image alone cannot close that interruption as a successful noop.
            backend.sync()
            if _state(ticket, _read(backend, ticket)) != state:
                return _report("recovery-required", "post-sync-drift")
            return _report("noop", "already-at-destination" if state == "destination"
                           else "known-images")
        if not returning and state == "recovered":
            return _report("recovery-required", "new-transition-required")
        backend.verify()
        if ticket.source != ABSENT and ticket.destination != ABSENT:
            backend.swap(ticket.temporary, ticket.target)
        elif ticket.source == ABSENT:
            if returning:
                backend.move_exclusive(ticket.target, ticket.recovery)
            else:
                backend.move_exclusive(ticket.temporary, ticket.target)
        else:
            if returning:
                backend.move_exclusive(ticket.temporary, ticket.target)
            else:
                backend.move_exclusive(ticket.target, ticket.temporary)
        backend.sync()
        after = _state(ticket, _read(backend, ticket))
        expected = "recovered" if returning and ticket.source == ABSENT else (
            "origin" if returning else "destination")
        if after != expected:
            return _report("recovery-required", "post-transition-drift")
        return _report("recovered" if returning else "completed", "known-images")
    except Exception:
        # Rename may have happened. Do not guess, reverse, unlink or retry.
        return _report("recovery-required", "transition-interrupted")
