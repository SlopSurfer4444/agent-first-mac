"""Opt-in native five-parent/eight-target handoff over one synthetic HOME.

PREPARE ONLY until the coordinator reviews the exact source/dependencies and
admits one invocation under an external 60-second signal boundary. The root
must already be one newly allocated, empty, owned0700 direct-scratch directory
named phase5-targets-native.<6-16 alnum>. Missing/invalid opt-in never opens it.

Only fixed synthetic children are created; all artifacts, including partial
ones, are retained. No actual owner config/history, CLI, model, signing tool,
network, installed source or production dispatcher is accessed. This exercises
the real target handoff and Session/Store/directory implementations, NOT current
runtime/source/legacy admission. Observations do not prove continuous exclusion
or power-loss durability beyond the implementations' successful fsync checks.
"""

import json
import os
from pathlib import Path
import re
import sys
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from lib import phase5_runtime_directory as directory
from lib import phase5_runtime_session as session
from lib import phase5_runtime_targets as targets
from lib.phase5_runtime_backend import DescriptorBackend, _facts
from lib.phase5_runtime_paths import OwnedParent, _observation, require_empty_envelope
from lib.phase5_runtime_store import DurableStore
from lib.phase5_runtime_transition import ABSENT, Image, MAX_IMAGE_BYTES


OWNER_HOME = "/Users/example-user"
FIXTURE_PATTERN = re.compile(
    r"/Users/example-user/AIDev/scratch/phase5-targets-native\.[A-Za-z0-9]{6,16}")
RUN_ID = "p5-" + "b" * 32
DIRECTORIES = (
    ".codex", ".codex/hooks", ".codex/skills",
    ".codex/skills/manage-workstation", ".codex/skills/manage-workstation/agents",
    "AIDev", "AIDev/bin", "AIDev/state", "AIDev/state/codex-transactions",
    "before", "after",
)
BEFORE_CONFIG = b'approval_policy = "on-request"\nsandbox_mode = "workspace-write"\n'
APPLIED_CONFIG = b'approval_policy = "never"\nsandbox_mode = "danger-full-access"\n'
OWNER_SUFFIX = (b'# synthetic current owner comment\n'
                b'[projects."/synthetic/project"]\ntrust_level = "trusted"\n'
                b'[plugins."synthetic-plugin"]\nenabled = true\n')
CURRENT_CONFIG = APPLIED_CONFIG + OWNER_SUFFIX
# Independent fixture expectation: do not call the composition implementation
# to manufacture the result against which that implementation is checked.
ROLLBACK_CONFIG = BEFORE_CONFIG + OWNER_SUFFIX


def require(condition):
    if not condition:
        raise ValueError("native_targets_fixture_assertion") from None


def valid_root(value):
    # Do not resolve/normalize a supplied path into an admitted spelling.
    return type(value) is str and FIXTURE_PATTERN.fullmatch(value) is not None


def report():
    return {"schema": 1, "probe": "phase5-owned-native-targets",
            "verdict": "NOT_RUN", "stage": "opt-in", "checkCount": 0,
            "targetCount": 0, "targetParentCount": 0, "historicalFileCount": 0,
            "noopChecks": 0, "transitionHandoffs": 0,
            "setupComplete": False, "cycleComplete": False,
            "historicalImagesPreserved": False, "currentGuidancePreserved": False,
            "currentConfigReturnedExactly": False, "allCurrentBytesModesReturned": False,
            "noopImagesUnchanged": False, "handlesClosed": False,
            "fixtureWriteAttempted": False, "interrupted": False,
            "setupSeconds": None, "cycleSeconds": None, "closeSeconds": None,
            "durationSeconds": None, "cleanupPerformed": False,
            "retryAttempted": False, "compensationAttempted": False,
            "ownerConfigurationRead": False, "ownerConfigurationWrite": False,
            "runtimeAdmissionProven": False, "legacyAdmissionProven": False,
            "executionAdmission": False, "phase5PassClaimed": False,
            "phase6Authorized": False}


def _empty_private(parent):
    parent.verify()
    first = _observation(os.fstat(parent.descriptor))
    require_empty_envelope(parent)
    with os.scandir(parent.descriptor) as entries:
        require(next(iter(entries), None) is None)
    require_empty_envelope(parent)
    require(_observation(os.fstat(parent.descriptor)) == first)
    parent.verify()


def _prefer_error(first, later):
    # Preserve the earliest interruption; an ordinary error cannot hide one.
    return later if first is None or (isinstance(first, Exception)
                                     and not isinstance(later, Exception)) else first


def _close(handles):
    # Close every owned chain once, even if an earlier close is interrupted.
    # Remove ownership before calling close; do not retry an ambiguous close.
    failure = None
    while handles:
        handle = handles.pop()
        try:
            handle.close()
        except BaseException as error:
            failure = _prefer_error(failure, error)
    if failure is not None:
        raise failure from None


def _construct(fixture, uid, root, handles, result):
    parents = {"": root}
    for suffix in DIRECTORIES:
        parent_name, _, leaf = suffix.rpartition("/")
        parent = parents[parent_name]
        parent.verify()
        result["fixtureWriteAttempted"] = True
        os.mkdir(leaf, 0o700, dir_fd=parent.descriptor)
        parent.verify()
        child = OwnedParent.open(fixture + "/" + suffix, fixture, uid, modes={0o700})
        handles.append(child)
        _empty_private(child)
        os.fsync(child.descriptor)
        os.fsync(parent.descriptor)
        _empty_private(child)
        parent.verify()
        parents[suffix] = child

    target_io = tuple(DescriptorBackend(parents[suffix]) for suffix in targets.PARENTS)
    before_io, after_io = (DescriptorBackend(parents[name]) for name in ("before", "after"))
    before, after, initial = {}, {}, {}
    for index, (identifier, parent_index, leaf, mode) in enumerate(targets.ROWS):
        if identifier == "config":
            old, applied, current = BEFORE_CONFIG, APPLIED_CONFIG, CURRENT_CONFIG
        elif identifier == "global-agents":
            old, applied, current = (b"synthetic historical guidance\n",
                                     b"synthetic old applied guidance\n",
                                     b"synthetic current owner guidance\n")
        else:
            old = None if index % 2 == 0 else ("before-" + identifier).encode("ascii")
            applied = current = ("applied-" + identifier).encode("ascii")
        # Physical custody files always0600, including the absence markers.
        physical_before = before_io.create_exclusive(identifier, b"absent\n" if old is None else old, 0o600)
        physical_after = after_io.create_exclusive(identifier, applied, 0o600)
        require(physical_before.mode == physical_after.mode == 0o600)
        # Logical historical modes are a separate explicit fixture projection;
        # do not pretend a0700 launcher was observed as a0700 custody file.
        before[identifier] = (ABSENT if old is None else
                              Image(physical_before.data, physical_before.identity, mode))
        after[identifier] = Image(physical_after.data, physical_after.identity, mode)
        current_mode = 0o644 if identifier == "global-agents" else mode
        initial[identifier] = target_io[parent_index].create_exclusive(leaf, current, current_mode)
    return parents, before_io, after_io, before, after, initial


def _history(io, parent):
    observations = {}
    for identifier in session.TARGET_IDS:
        parent.verify()
        first = _facts(os.stat(identifier, dir_fd=parent.descriptor, follow_symlinks=False),
                       parent.uid, MAX_IMAGE_BYTES)
        image = io.snapshot(identifier)
        final = _facts(os.stat(identifier, dir_fd=parent.descriptor, follow_symlinks=False),
                       parent.uid, MAX_IMAGE_BYTES)
        require(first == final and image.data is not None and image.mode == 0o600)
        parent.verify()
        observations[identifier] = (image, first)
    return observations


def _images(bindings):
    return {identifier: adapter.snapshot(leaf) for identifier, (adapter, leaf) in bindings.items()}


def _unchanged_checks(bindings, store, state, expected, result):
    for function, verdict in ((session.verify, "verified"), (session.noop, "noop")):
        require(_images(bindings) == expected)
        require(function(bindings, store, state=state)["verdict"] == verdict)
        require(_images(bindings) == expected)
        result["checkCount"] += 1
        if verdict == "noop":
            result["noopChecks"] += 1


def run(fixture, result=None):
    """No import/default execution enters this exclusively opt-in I/O function."""
    result = report() if result is None else result
    require(valid_root(fixture))
    require(sys.platform == "darwin")
    uid = os.getuid()
    require(type(uid) is int and 0 < uid < 2 ** 32)
    require(tuple(row[0] for row in targets.ROWS) == session.TARGET_IDS)
    require(len(targets.PARENTS) == 5 and len(targets.ROWS) == 8)
    handles, active_error = [], None
    started = time.monotonic()
    cycle_started = None
    result["stage"] = "root-admission"
    try:
        root = OwnedParent.open(fixture, OWNER_HOME, uid)
        handles.append(root)
        _empty_private(root)
        result["stage"] = "setup"
        parents, before_io, after_io, before, after, initial = _construct(
            fixture, uid, root, handles, result)
        original_before = _history(before_io, parents["before"])
        original_after = _history(after_io, parents["after"])
        require(len(original_before) == len(original_after) == 8)
        require(before["quarantine-profile"] == before["hook-router"] == before["skill-metadata"] == ABSENT)
        require(initial["global-agents"].mode == 0o644)
        result["setupComplete"] = True
        result["historicalFileCount"] = 16
        result["setupSeconds"] = round(time.monotonic() - started, 3)
        cycle_started = time.monotonic()

        result["stage"] = "target-observation"
        held = targets.observe(fixture, uid)
        handles.append(held)
        require(held.images == initial and all(held.metadata_empty.values()))
        result["targetCount"], result["targetParentCount"] = len(held.images), len(held.parent_envelopes)
        readonly = held.bindings
        result["stage"] = "allocation"
        allocated = directory.allocate(fixture, uid, RUN_ID)
        handles.append(allocated)
        store = DurableStore(allocated)
        result["stage"] = "capture"
        require(session.capture(readonly, store, before, after, session_id=RUN_ID)["verdict"] == "captured")
        require(_images(readonly) == initial)
        result["checkCount"] += 1
        result["stage"] = "handoff"
        bindings = held.transition_bindings(RUN_ID)
        result["transitionHandoffs"] = 1
        require(set(bindings) == set(session.TARGET_IDS))

        result["stage"] = "current"
        _unchanged_checks(bindings, store, "current", initial, result)
        result["stage"] = "rollback"
        require(session.rollback(bindings, store, resume=False)["verdict"] == "completed")
        rolled = _images(bindings)
        require(rolled["global-agents"] == initial["global-agents"])
        require(rolled["config"].data == ROLLBACK_CONFIG and rolled["config"].mode == initial["config"].mode)
        for identifier in session.TARGET_IDS[2:]:
            require((rolled[identifier].data, rolled[identifier].mode)
                    == (before[identifier].data, before[identifier].mode))
        result["checkCount"] += 1
        result["stage"] = "rolled"
        _unchanged_checks(bindings, store, "rollback", rolled, result)
        result["stage"] = "return"
        require(session.return_current(bindings, store, resume=False)["verdict"] == "completed")
        returned = _images(bindings)
        for identifier in session.TARGET_IDS:
            require((returned[identifier].data, returned[identifier].mode)
                    == (initial[identifier].data, initial[identifier].mode))
        require(returned["global-agents"] == initial["global-agents"])
        result["checkCount"] += 1
        result["stage"] = "returned"
        _unchanged_checks(bindings, store, "return", returned, result)
        result["stage"] = "preservation"
        require(_history(before_io, parents["before"]) == original_before)
        require(_history(after_io, parents["after"]) == original_after)
        root.verify()
        require(result["checkCount"] == 9 and result["noopChecks"] == 3)
        result.update(cycleComplete=True, historicalImagesPreserved=True,
                      currentGuidancePreserved=True, currentConfigReturnedExactly=True,
                      allCurrentBytesModesReturned=True, noopImagesUnchanged=True)
    except BaseException as error:
        active_error = error
        raise
    finally:
        ended = time.monotonic()
        if cycle_started is None:
            result["setupSeconds"] = round(ended - started, 3)
        else:
            result["cycleSeconds"] = round(ended - cycle_started, 3)
        # The first failed lifecycle stage stays visible. A close-only failure
        # must not leave a PASS or silently replace an earlier interruption.
        if active_error is None:
            result["stage"] = "close"
        close_started = time.monotonic()
        try:
            _close(handles)
            result["handlesClosed"] = True
        except BaseException as error:
            selected = _prefer_error(active_error, error)
            if selected is not active_error:
                raise selected from None
        finally:
            result["closeSeconds"] = round(time.monotonic() - close_started, 3)
            result["durationSeconds"] = round(time.monotonic() - started, 3)
    result.update(verdict="PASS", stage="completed")
    return result


def pure_interrupt_checks():
    """Explicit source-only regression entrypoint; all filesystem I/O is fake."""
    from types import SimpleNamespace
    from unittest.mock import patch

    class Handle:
        def __init__(self, failure=None):
            self.failure, self.closed = failure, 0

        def close(self):
            self.closed += 1
            if self.failure is not None:
                raise self.failure

    def expect(operation, expected, handles):
        try:
            operation()
        except BaseException as caught:
            require(caught is expected)
        else:
            require(False)
        require(all(handle.closed == 1 for handle in handles))

    first_interrupt = KeyboardInterrupt()
    handles = [Handle(), Handle(SystemExit(7)), Handle(first_interrupt), Handle(ValueError())]
    owned = list(handles)
    expect(lambda: _close(owned), first_interrupt, handles)
    require(not owned)

    cases = (
        (ValueError(), (SystemExit(7), ValueError()), "close"),
        (KeyboardInterrupt(), (ValueError(), SystemExit(7)), "operation"),
        (SystemExit(7), (KeyboardInterrupt(), ValueError()), "operation"),
        (ValueError(), (ValueError(), ValueError()), "operation"),
    )
    for operation_error, close_errors, priority in cases:
        handles = [Handle(), *(Handle(error) for error in reversed(close_errors))]

        def construct(_fixture, _uid, _root, owned, _result):
            owned.extend(handles[1:])
            raise operation_error

        replacements = {"os": SimpleNamespace(getuid=lambda: 501),
                        "sys": SimpleNamespace(platform="darwin"),
                        "time": SimpleNamespace(monotonic=lambda: 1.0),
                        "OwnedParent": SimpleNamespace(open=lambda *_args: handles[0]),
                        "_empty_private": lambda _parent: None, "_construct": construct}
        expected = close_errors[0] if priority == "close" else operation_error
        with patch.dict(globals(), replacements):
            expect(lambda: run(OWNER_HOME + "/AIDev/scratch/phase5-targets-native.Abc123"),
                   expected, handles)
    return {"pureInterruptChecks": 5, "nativeFixtureRun": False}


def main(argv=None):
    arguments = sys.argv[1:] if argv is None else argv
    result = report()
    # Fixed grammar avoids argparse echoing arbitrary caller input to evidence.
    if type(arguments) is not list or not arguments:
        print(json.dumps(result, sort_keys=True))
        return 2
    if len(arguments) != 2 or arguments[0] != "--fixture-root" or not valid_root(arguments[1]):
        result.update(verdict="REJECTED", stage="opt-in")
        print(json.dumps(result, sort_keys=True))
        return 2
    try:
        run(arguments[1], result)
    except BaseException as error:
        result["verdict"] = "FAIL_RETAINED"
        result["interrupted"] = not isinstance(error, Exception)
        print(json.dumps(result, sort_keys=True))
        if not isinstance(error, Exception):
            # Keep the original interrupt object for the root-owned boundary.
            raise
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
