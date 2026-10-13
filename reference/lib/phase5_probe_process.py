"""Bounded private mechanics over an explicitly injected admitted catalog owner.

Root owns exact Launch/source/target admission around EACH call. This module
does not import a historical runner, choose a model, create files or provide an
entry point. Supplying dependencies does not confer operation authority.

catalog._Session is the sole direct-child/pipe settlement owner. Inject its
coherent clock/I/O as well when testing; clock below must share its monotonic
timebase. Exactly one owner.close is attempted. Its accepted idempotent FileIO
close behavior is unchanged. No process group/descendant supervision, retry,
hard kernel deadline or recovery across interpreter exit is claimed. Popen
raising before returning a handle leaves UNKNOWN, even if owner.process is None.
"""

from dataclasses import dataclass
import math
import os
import time


MAX_BYTES = 4 * 1024 * 1024
REASONS = frozenset(("invalid_arguments", "launch_not_admitted", "launch_changed",
                     "launch_failed", "deadline_exceeded", "output_limit",
                     "unexpected_eof", "protocol_malformed", "server_error",
                     "write_failed", "process_settlement_failed"))


class ProbeProcessError(Exception):
    """Only closed reason/settlement metadata; never print private_owner."""
    def __init__(self, reason, *, private_owner=None, child_settled=True):
        self.reason_class = reason if type(reason) is str and reason in REASONS else "protocol_malformed"
        self.private_owner = private_owner
        self.child_settled = child_settled
        self.settlement_failed = child_settled is not True
        super().__init__(self.reason_class)

    def public(self):
        return {"reasonClass": self.reason_class, "childSettled": self.child_settled,
                "executionAdmission": False, "phase5Accepted": False, "phase6Allowed": False}


@dataclass(frozen=True, repr=False)
class DiscoveryResult:
    hooks: object
    skills: object
    captured_bytes: int
    notifications: int
    stderr_empty: bool

    def public(self):
        return _public("discovery", self.captured_bytes, self.stderr_empty, self.notifications)


@dataclass(frozen=True, repr=False)
class CommandResult:
    returncode: int
    stdout: bytes
    stderr: bytes

    def public(self):
        value = _public("command", len(self.stdout) + len(self.stderr), not self.stderr, 0)
        value["exitZero"] = self.returncode == 0
        return value


def _public(kind, count, stderr_empty, notifications):
    return {"schema": 1, "kind": kind, "capturedBytes": count,
            "notificationCount": notifications, "stderrEmpty": stderr_empty,
            "streamsEOF": True, "childSettled": True, "executionAdmission": False,
            "phase5Accepted": False, "phase6Allowed": False}


def _require(value, reason="invalid_arguments"):
    if value is not True:
        raise ProbeProcessError(reason) from None


def _finite(value):
    return type(value) in (int, float) and math.isfinite(value)


def _earliest(first, later):
    if isinstance(first, (KeyboardInterrupt, SystemExit)):
        return first
    return later if first is None or isinstance(later, (KeyboardInterrupt, SystemExit)) else first


def _snapshot(launch):
    argv, environment, cwd = launch.argv, launch.environment, launch.cwd
    _require(type(argv) is tuple and 1 <= len(argv) <= 256
             and all(type(arg) is str and arg and "\0" not in arg for arg in argv))
    _require(type(cwd) is str and 1 < len(cwd) <= 4096 and cwd.startswith("/")
             and all(part not in ("", ".", "..") for part in cwd[1:].split("/"))
             and "\0" not in cwd)
    if type(environment) is tuple:
        _require(len(environment) <= 256 and all(type(row) is tuple and len(row) == 2
                                               for row in environment))
        _require(all(type(row[0]) is str for row in environment)
                 and len({row[0] for row in environment}) == len(environment))
        environment = dict(environment)
    _require(type(environment) is dict and len(environment) <= 256)
    _require(all(type(key) is str and type(value) is str and 0 < len(key) <= 256
                 and len(value) <= 16384 and "=" not in key and "\0" not in key + value
                 for key, value in environment.items()))
    _require(sum(len(arg.encode("utf-8")) for arg in argv)
             + sum(len((key + value).encode("utf-8")) for key, value in environment.items()) <= MAX_BYTES)
    return argv, dict(environment), cwd


def _check_budget(budget):
    _require(budget.check() is not False, "deadline_exceeded")


def _prepare(launch, budget, maximum, admit_launch, catalog, process_factory, clock):
    try:
        _require(_finite(maximum) and 0 < maximum <= 180)
        _require(callable(admit_launch) and callable(process_factory) and callable(clock)
                 and callable(catalog._Session) and callable(budget.check) and callable(budget.command))
        snapshot = _snapshot(launch)
        _check_budget(budget)
        _require(admit_launch(launch) is True, "launch_not_admitted")
        _require(_snapshot(launch) == snapshot, "launch_changed")
        duration = budget.command(maximum)
        _require(_finite(duration) and 2.0 < duration <= maximum, "deadline_exceeded")
        now = clock()
        _require(_finite(now) and _finite(now + duration) and now + duration > now)
        return snapshot, now + duration
    except (KeyboardInterrupt, SystemExit):
        raise
    except ProbeProcessError:
        raise
    except Exception:
        raise ProbeProcessError("invalid_arguments") from None


def _settle(owner, deadline, failed, primary, spawn, budget, clock):
    settled, problem, close_error = None, None, None
    try:
        settled, problem = owner.close(deadline, failed)
        _require(type(settled) is bool)
    except BaseException as error:
        settled, close_error = None, error
    # An absent handle after Popen was entered does not prove absence of a child.
    settled = True if settled is True and not (spawn[0] and not spawn[1]) else None
    primary = _earliest(primary, owner.interruption)
    primary = _earliest(primary, close_error)
    try:
        _check_budget(budget)
        now = clock()
        _require(_finite(now) and now <= deadline, "deadline_exceeded")
    except BaseException as error:
        primary = _earliest(primary, error)
    if isinstance(primary, (KeyboardInterrupt, SystemExit)):
        primary.private_owner = owner if settled is not True else None
        primary.child_settled = settled
        primary.settlement_failed = settled is not True
        raise primary from None
    if settled is not True:
        raise ProbeProcessError("process_settlement_failed", private_owner=owner,
                                child_settled=None) from None
    if primary is not None or problem:
        reason = (getattr(primary, "reason_class", None) if primary is not None else problem)
        if type(reason) is not str or reason not in REASONS:
            reason = "launch_failed" if not spawn[1] else "protocol_malformed"
        raise ProbeProcessError(reason) from None


def _start(owner, snapshot, process_factory, spawn):
    argv, environment, cwd = snapshot
    def popen(arguments, **kwargs):
        _require(not spawn[0] and "cwd" not in kwargs)
        spawn[0] = True
        process = process_factory(arguments, cwd=cwd, **kwargs)
        _require(process is not None, "launch_failed")
        # Publish to the sole settlement owner BEFORE claiming acquisition.
        # A return-event interrupt can prevent _Session.start's assignment.
        owner.process = process
        spawn[1] = True
        return process
    owner.start(argv, environment, popen)


def discovery(launch, budget, *, admit_launch, catalog, process_factory, clock=time.monotonic):
    """Fixed initialize/initialized/hooks/list/skills/list; total<=20s, settle2s.

Result shapes beyond dictionary envelopes are the root's independent consumer.
The catalog owner enforces its admitted shared4MiB/notification/protocol bounds.
"""
    snapshot, deadline = _prepare(launch, budget, 20.0, admit_launch, catalog, process_factory, clock)
    _require(len(snapshot[0]) >= 2 and snapshot[0][1] == "app-server")
    owner, primary, spawn = catalog._Session(deadline - 2.0), None, [False, False]
    try:
        _start(owner, snapshot, process_factory, spawn)
        initialize = {"id": 0, "method": "initialize", "params": {
            "capabilities": {"experimentalApi": True},
            "clientInfo": {"name": "phase5-trusted-probe-validator", "version": "1"}}}
        _require(type(owner.request((initialize,), 0)) is dict, "protocol_malformed")
        _check_budget(budget)
        hooks = owner.request(({"method": "initialized", "params": {}},
                               {"id": 1, "method": "hooks/list", "params": {"cwds": [snapshot[2]]}}), 1)
        _check_budget(budget)
        skills = owner.request(({"id": 2, "method": "skills/list",
                                  "params": {"cwds": [snapshot[2]], "forceReload": False}},), 2)
        _require(type(hooks) is dict and type(skills) is dict, "protocol_malformed")
    except BaseException as error:
        primary = error
    _settle(owner, deadline, primary is not None, primary, spawn, budget, clock)
    _require(type(owner.total) is int and 0 <= owner.total <= MAX_BYTES, "output_limit")
    return DiscoveryResult(hooks, skills, owner.total, owner.notifications, not owner.stderr_nonempty)


def command(launch, budget, maximum_seconds, *, admit_launch, catalog, process_factory,
            clock=time.monotonic, read=os.read):
    """Raw byte channels, direct exit AND EOF; nonzero exit remains private data."""
    _require(callable(read))
    snapshot, deadline = _prepare(launch, budget, maximum_seconds, admit_launch, catalog, process_factory, clock)
    owner, primary, spawn = catalog._Session(deadline - 2.0), None, [False, False]
    output, size, returncode = {"stdout": bytearray(), "stderr": bytearray()}, 0, None
    try:
        _start(owner, snapshot, process_factory, spawn)
        owner.streams["stdin"].close()
        while owner.eof != {"stdout", "stderr"} or owner.process.poll() is None:
            _check_budget(budget)
            remaining = deadline - 2.0 - clock()
            _require(_finite(remaining) and remaining > 0, "deadline_exceeded")
            for key, _ in owner.selector.select(min(0.05, remaining)):
                _require(key.data in output, "protocol_malformed")
                requested = min(65536, MAX_BYTES + 1 - size)
                try:
                    chunk = read(owner.streams[key.data].fileno(), requested)
                except (BlockingIOError, InterruptedError):
                    continue
                _require(type(chunk) is bytes and len(chunk) <= requested, "protocol_malformed")
                if not chunk:
                    owner.selector.unregister(owner.streams[key.data])
                    owner.eof.add(key.data)
                else:
                    size += len(chunk)
                    _require(size <= MAX_BYTES, "output_limit")
                    output[key.data].extend(chunk)
                _require(clock() < deadline - 2.0, "deadline_exceeded")
        returncode = owner.process.returncode
        _require(type(returncode) is int and -2 ** 31 <= returncode < 2 ** 31, "protocol_malformed")
    except BaseException as error:
        primary = error
    # Already drained/reaped on success. Do not ask RPC cleanup to parse bytes or
    # reject a useful nonzero exit; it still owns all handles and child cleanup.
    _settle(owner, deadline, True, primary, spawn, budget, clock)
    return CommandResult(returncode, bytes(output["stdout"]), bytes(output["stderr"]))
