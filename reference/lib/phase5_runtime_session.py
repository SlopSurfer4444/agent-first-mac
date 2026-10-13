"""Fixed eight-target PRIVATE successor lifecycle; no filesystem or dispatch.

Caller owns independent legacy/source/integration/current-guidance admission,
sibling allocation and descriptor opening. Backends map TARGET_IDS to
(transition backend, target leaf). Store.verify() checks its held binding;
read(name) returns stable private bytes or None and binds present object
identity for subsequent reads/barriers. sync_record(name, expected_raw) must
freshly verify that same descriptor-bound object, exact bytes, full file stamp
and complete named parent chain on EVERY call. Its object AND parent fsync
barrier may be reused only with a completed in-instance proof for the identical
full file AND directory generation (including directory ctime/mtime/size/link
count); fresh same-FD readback and named checks remain mandatory. First, changed
or unknown generations require both fsyncs. Any failure/interrupt invalidates
reusable proof; substitution or uncertain durability raises without cleanup.
The barrier call remains mandatory even for readable records retained after an
uncertain earlier write; cached bytes or an inode/name alone never satisfy it.
put_exclusive(name, bytes)
must exclusively create, fully write and durably sync object AND parent before
returning, retaining the newly created object's identity binding for subsequent
reads/barriers. Uncertain writes raise, retain evidence, and never replace a record.
Store channel cap is 40 MiB (24 base64 Images); individual Images stay <=1 MiB.

One capture, one rollback, one return, and at most one explicit resume per
action. No cleanup, implicit retry or compensation. This is not a generic
journal, authorization, filesystem CAS, or continuous exclusion mechanism.
"""

import base64
import json
import re

from lib.phase5_runtime_compositions import compose
from lib.phase5_runtime_transition import (
    ABSENT, Image, Ticket, _valid_image, _valid_ticket, classify, prepare, transition,
)


TARGET_IDS = ("config", "global-agents", "quarantine-profile", "hooks-definition",
              "hook-router", "skill-definition", "skill-metadata", "quarantine-launcher")
MAX_RECORD_BYTES = 40 * 1024 * 1024


class SessionError(ValueError):
    """Fixed redacted failure only."""


def _fail():
    raise SessionError("session_invalid") from None


def _keys(value, names):
    return (type(value) is dict and all(type(k) is str for k in value)
            and set(value) == set(names))


def _public(verdict, reason, completed=0):
    return {"schema": 1, "verdict": verdict, "reason": reason, "completedTargets": completed,
            "executionAdmission": False, "liveAdmission": False, "phase5Accepted": False,
            "phase6Allowed": False, "cleanupPerformed": False}


def _encode(value):
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False) + "\n").encode("ascii")
    if len(raw) > MAX_RECORD_BYTES:
        _fail()
    return raw


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _fail()
        result[key] = value
    return result


def _image(image):
    if not _valid_image(image):
        _fail()
    return {"data": None if image.data is None else base64.b64encode(image.data).decode("ascii"),
            "identity": None if image.identity is None else list(image.identity),
            "mode": image.mode, "seal": base64.b64encode(image.seal).decode("ascii")}


def _unimage(value):
    if not _keys(value, ("data", "identity", "mode", "seal")):
        _fail()
    if (value["data"] is not None and type(value["data"]) is not str
            or type(value["seal"]) is not str
            or value["identity"] is not None and type(value["identity"]) is not list):
        _fail()
    image = Image(None if value["data"] is None else base64.b64decode(value["data"], validate=True),
                  None if value["identity"] is None else tuple(value["identity"]), value["mode"],
                  base64.b64decode(value["seal"], validate=True))
    if _image(image) != value:
        _fail()
    return image


def _images(values):
    if type(values) is not list or len(values) != 8:
        _fail()
    return tuple(_unimage(v) for v in values)


class _Records:
    # Only this session's fixed names, bounded bytes, and exact readback pins.
    def __init__(self, store):
        self.store, self.pins = store, {}

    def get(self, name):
        self.store.verify()
        raw = self.store.read(name)
        self.store.verify()
        if raw is not None and (type(raw) is not bytes or len(raw) > MAX_RECORD_BYTES):
            _fail()
        if name in self.pins and raw != self.pins[name]:
            _fail()
        if raw is not None:
            self.store.sync_record(name, raw)
        self.store.verify()
        second = self.store.read(name)
        self.store.verify()
        if (second is not None and type(second) is not bytes) or second != raw:
            _fail()
        self.pins[name] = raw
        if raw is None:
            return None
        value = json.loads(raw, object_pairs_hook=_pairs)
        if _encode(value) != raw:
            _fail()
        return value

    def put(self, name, value):
        if self.get(name) is not None:
            _fail()
        raw = _encode(value)
        self.store.put_exclusive(name, raw)
        self.pins[name] = raw
        if self.get(name) != value:
            _fail()

    def check(self):
        for name in tuple(self.pins):
            self.get(name)


def _bindings(backends):
    if not _keys(backends, TARGET_IDS):
        _fail()
    names = []
    for identifier in TARGET_IDS:
        value = backends[identifier]
        if (type(value) is not tuple or len(value) != 2 or type(value[1]) is not str
                or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", value[1])
                or value[1] in (".", "..")):
            _fail()
        names.append(value[1])
    return names


def _observe(backends):
    def once():
        result = []
        for identifier in TARGET_IDS:
            backend, name = backends[identifier]
            backend.verify()
            image = backend.snapshot(name)
            backend.verify()
            if not _valid_image(image):
                _fail()
            result.append(image)
        return tuple(result)
    first, second = once(), once()
    if first != second:
        _fail()
    return second


def _capture_record(records, backends):
    value = records.get("capture")
    if (not _keys(value, ("schema", "session", "names", "before", "after", "current"))
            or type(value["schema"]) is not int or value["schema"] != 1
            or type(value["session"]) is not str
            or not re.fullmatch(r"p5-[0-9a-f]{32}", value["session"])
            or value["names"] != _bindings(backends)):
        _fail()
    before, after, current = (_images(value[k]) for k in ("before", "after", "current"))
    if (before[0].data is None or any(i.data is None for i in after + current)
            or len(set(i.identity for i in current)) != 8):
        _fail()
    config = compose(before[0].data, after[0].data, current[0].data)
    rollback = [(config["rollback"], current[0].mode), (current[1].data, current[1].mode)]
    for old, applied, live in zip(before[2:], after[2:], current[2:]):
        if (live.data, live.mode) != (applied.data, applied.mode):
            _fail()
        rollback.append((old.data, old.mode))
    return value, current, tuple(rollback)


def capture(backends, store, historical_before, historical_after, *, session_id):
    """Adoption-only: captures target bytes; creates no target/staging object."""
    try:
        if not _keys(historical_before, TARGET_IDS) or not _keys(historical_after, TARGET_IDS):
            _fail()
        records = _Records(store)
        value = {"schema": 1, "session": session_id, "names": _bindings(backends),
                 "before": [_image(historical_before[k]) for k in TARGET_IDS],
                 "after": [_image(historical_after[k]) for k in TARGET_IDS],
                 "current": [_image(i) for i in _observe(backends)]}
        # Validate before persisting capture; use the same strict reader path.
        class Candidate:
            def get(self, name):
                return value
        _, current, _ = _capture_record(Candidate(), backends)
        if _observe(backends) != current:
            _fail()
        records.put("capture", value)
        records.check()
        if _observe(backends) != current:
            _fail()
        return _public("captured", "known-images", 8)
    except Exception:
        return _public("recovery-required", "capture-failed")


def _ticket_name(action, index):
    return action + ".ticket." + str(index)


def _ticket(records, action, index, capture_value, pre, desired):
    value = records.get(_ticket_name(action, index))
    if value is None:
        return None
    if not _keys(value, ("target", "temporary", "recovery", "source", "destination", "noop")):
        _fail()
    ticket = Ticket(value["target"], value["temporary"], value["recovery"],
                    _unimage(value["source"]), _unimage(value["destination"]), value["noop"])
    prefix = capture_value["session"] + "-" + action + "-" + str(index)
    if (not _valid_ticket(ticket) or ticket.target != capture_value["names"][index]
            or ticket.temporary != prefix + "-tmp" or ticket.recovery != prefix + "-rec"
            or ticket.source != pre[index]
            or (ticket.destination.data, ticket.destination.mode) != desired[index]):
        _fail()
    return ticket


def _ticket_value(ticket):
    return {"target": ticket.target, "temporary": ticket.temporary, "recovery": ticket.recovery,
            "source": _image(ticket.source), "destination": _image(ticket.destination),
            "noop": ticket.noop}


def _intent(value, action, pre):
    return (_keys(value, ("schema", "action", "pre"))
            and type(value["schema"]) is int and value["schema"] == 1
            and type(value["action"]) is str and value["action"] == action
            and _images(value["pre"]) == pre)


def _step(value):
    if (not _keys(value, ("schema", "succeeded")) or type(value["schema"]) is not int
            or value["schema"] != 1 or type(value["succeeded"]) is not bool):
        _fail()
    return value["succeeded"]


def _auxiliary(backends, tickets):
    for identifier, ticket in zip(TARGET_IDS, tickets):
        backend = backends[identifier][0]
        expected = (ABSENT if ticket.noop or ticket.source == ABSENT else ticket.source, ABSENT)
        for _ in range(2):
            backend.verify()
            images = tuple(backend.snapshot(n) for n in (ticket.temporary, ticket.recovery))
            backend.verify()
            if any(not _valid_image(i) for i in images) or images != expected:
                _fail()


def _completed(backends, records, action, capture_value, pre, desired):
    # A failed first attempt stays immutable; only a distinct resume can finish.
    terminal = records.get(action + ".resume.terminal")
    attempt = "resume"
    if terminal is None:
        attempt = "initial"
        terminal = records.get(action + ".initial.terminal")
    if (not _keys(terminal, ("schema", "completed", "images"))
            or type(terminal["schema"]) is not int or terminal["schema"] != 1
            or terminal["completed"] is not True):
        _fail()
    if (not _intent(records.get(action + ".initial.intent"), action, pre)
            or not _intent(records.get(action + "." + attempt + ".intent"), action, pre)
            or records.get(action + "." + attempt + ".failure") is not None):
        _fail()
    images = _images(terminal["images"])
    tickets = [_ticket(records, action, i, capture_value, pre, desired) for i in range(8)]
    if any(t is None for t in tickets) or images != tuple(t.destination for t in tickets):
        _fail()
    for i in range(8):
        if not _step(records.get(action + "." + attempt + ".result." + str(i))):
            _fail()
    _auxiliary(backends, tickets)
    return images


def _state_images(backends, records, value, current, rollback, state):
    if type(state) is not str or state not in ("current", "rollback", "return"):
        _fail()
    if state == "current":
        if any(records.get(a + ".initial.intent") is not None for a in ("rollback", "return")):
            _fail()
        return current
    rolled = _completed(backends, records, "rollback", value, current, rollback)
    if state == "rollback":
        return rolled
    return _completed(backends, records, "return", value, rolled, tuple((i.data, i.mode) for i in current))


def verify(backends, store, *, state="current", _sync=False):
    """Exact observation; unlike noop, verification alone is not a sync barrier."""
    try:
        if type(_sync) is not bool:
            _fail()
        records = _Records(store)
        value, current, rollback = _capture_record(records, backends)
        if state == "rollback" and records.get("return.initial.intent") is not None:
            _fail()
        expected = _state_images(backends, records, value, current, rollback, state)
        if _observe(backends) != expected:
            _fail()
        if _sync:
            for identifier in TARGET_IDS:
                backends[identifier][0].sync()
        records.check()
        # Barriers can overlap auxiliary drift even when all target bytes are
        # unchanged. Revalidate the completed action and its retained dependency.
        if _state_images(backends, records, value, current, rollback, state) != expected:
            _fail()
        if _observe(backends) != expected:
            _fail()
        return _public("noop" if _sync else "verified", "known-images", 8)
    except Exception:
        return _public("recovery-required", "verification-failed")


def noop(backends, store, *, state="current"):
    return verify(backends, store, state=state, _sync=True)


def _known(backends, records, action, value, pre, desired):
    images, tickets, gap = [], [], False
    for i, identifier in enumerate(TARGET_IDS):
        ticket = _ticket(records, action, i, value, pre, desired)
        saved = [records.get(action + "." + attempt + ".result." + str(i))
                 for attempt in ("initial", "resume")]
        succeeded = [_step(result) for result in saved if result is not None]
        if ticket is None:
            if succeeded:
                _fail()
            gap = True
            images.append(pre[i])
        else:
            if gap:
                _fail()
            result = classify(backends[identifier][0], ticket)
            if result["verdict"] not in ("origin", "destination"):
                _fail()
            images.append(ticket.source if result["verdict"] == "origin" else ticket.destination)
            # A durable success must not regress even to an otherwise known origin.
            if any(succeeded) and images[-1] != ticket.destination:
                _fail()
            if not any(succeeded):
                gap = True
        tickets.append(ticket)
    if _observe(backends) != tuple(images):
        _fail()
    records.check()
    return tuple(images), tickets


def rollback(backends, store, *, resume=False):
    return _run(backends, store, "rollback", resume)


def return_current(backends, store, *, resume=False):
    return _run(backends, store, "return", resume)


def _run(backends, store, action, resume):
    records, started, completed = _Records(store), False, 0
    attempt = "resume" if resume is True else "initial"
    terminal_name = action + "." + attempt + ".terminal"
    try:
        if type(resume) is not bool:
            _fail()
        value, current, rolled = _capture_record(records, backends)
        pre = current if action == "rollback" else _state_images(backends, records, value, current, rolled, "rollback")
        desired = rolled if action == "rollback" else tuple((i.data, i.mode) for i in current)
        intent = {"schema": 1, "action": action, "pre": [_image(i) for i in pre]}
        initial = records.get(action + ".initial.intent")
        if resume:
            if not _intent(initial, action, pre):
                _fail()
            _known(backends, records, action, value, pre, desired)
        elif initial is not None or _observe(backends) != pre:
            _fail()
        if (records.get(action + "." + attempt + ".intent") is not None
                or records.get(action + "." + attempt + ".failure") is not None
                or records.get(terminal_name) is not None):
            _fail()
        started = True
        records.put(action + "." + attempt + ".intent", intent)
        for i, identifier in enumerate(TARGET_IDS):
            if action == "return":
                _completed(backends, records, "rollback", value, current, rolled)
            _, tickets = _known(backends, records, action, value, pre, desired)
            ticket = tickets[i]
            if ticket is None:
                prefix = value["session"] + "-" + action + "-" + str(i)
                ticket = prepare(backends[identifier][0], target=value["names"][i],
                                 temporary=prefix + "-tmp", recovery=prefix + "-rec",
                                 source=pre[i], destination_bytes=desired[i][0], mode=desired[i][1])
                records.put(_ticket_name(action, i), _ticket_value(ticket))
            _known(backends, records, action, value, pre, desired)
            result = transition(backends[identifier][0], ticket)
            succeeded = result["verdict"] in ("completed", "noop")
            records.put(action + "." + attempt + ".result." + str(i),
                        {"schema": 1, "succeeded": succeeded})
            if not succeeded:
                _fail()
            completed += 1
        images, tickets = _known(backends, records, action, value, pre, desired)
        if images != tuple(t.destination for t in tickets):
            _fail()
        if action == "return":
            _completed(backends, records, "rollback", value, current, rolled)
        records.check()
        if _observe(backends) != images:
            _fail()
        records.put(terminal_name, {"schema": 1, "completed": True, "images": [_image(i) for i in images]})
        # Publication can itself overlap drift. Preserve the immutable terminal
        # on failure, but append the separate failure checked by _completed.
        after_images, _ = _known(backends, records, action, value, pre, desired)
        if after_images != images:
            _fail()
        if action == "return":
            _completed(backends, records, "rollback", value, current, rolled)
        records.check()
        if _observe(backends) != images:
            _fail()
        return _public("completed", "known-images", 8)
    except Exception:
        if started:
            try:
                records.put(action + "." + attempt + ".failure",
                            {"schema": 1, "reason": "interrupted", "completedTargets": completed})
            except Exception:
                pass
            try:
                if records.get(terminal_name) is None:
                    records.put(terminal_name, {"schema": 1, "completed": False, "images": None})
            except Exception:
                pass  # Uncertain store failure is retained, never overwritten.
        return _public("recovery-required", "session-interrupted", completed)
