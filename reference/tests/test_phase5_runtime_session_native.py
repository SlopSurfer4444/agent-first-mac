"""Opt-in eight-target lifecycle using only a new owned synthetic fixture.

Root must review all dependencies and impose a30-second outer deadline.
All created objects are retained. No owner settings, Codex, model, historical
receipt, install or production dispatcher is accessed. This is not live admission.
"""

import argparse
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import sys
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from lib.phase5_runtime_backend import DescriptorBackend
from lib.phase5_runtime_store import DurableStore
from lib.phase5_runtime_transition import ABSENT
from lib import phase5_runtime_session as session


def require(condition):
    if not condition:
        raise ValueError("native_session_fixture_assertion") from None


def reader_module():
    loader = importlib.machinery.SourceFileLoader(
        "phase5_session_fixture_directory_reader", str(ROOT / "bin/phase5-apply-transaction"))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    sys.modules[loader.name] = module
    loader.exec_module(module)
    return module


def run(fixture):
    account_home = Path(pwd.getpwuid(os.getuid()).pw_dir)
    require(fixture.is_absolute() and fixture.parent == account_home / "AIDev/scratch")
    require(re.fullmatch(r"phase5-session-native\.[A-Za-z0-9]{6,16}", fixture.name) is not None)
    reader = reader_module()
    handles = []
    started = time.monotonic()
    root = reader.open_directory(fixture, os.getuid(), {0o700}, account_home)
    handles.append(root)
    try:
        require(not root.names())
        parents = {}
        for name in ("targets", "historical-before", "historical-after", "journal"):
            root.verify()
            os.mkdir(name, 0o700, dir_fd=root.descriptor)
            os.fsync(root.descriptor)
            child = reader.DirectoryHandle.child(root, name, {0o700})
            require(child is not None)
            handles.append(child)
            parents[name] = child
        current_io = DescriptorBackend(parents["targets"])
        before_io = DescriptorBackend(parents["historical-before"])
        after_io = DescriptorBackend(parents["historical-after"])
        store = DurableStore(parents["journal"])
        before, after, initial, backends = {}, {}, {}, {}
        historical_config = b'approval_policy = "on-request"\nsandbox_mode = "workspace-write"\n'
        applied_config = b'approval_policy = "never"\nsandbox_mode = "danger-full-access"\n'
        current_config = (applied_config + b'# current owner comment\n'
                          b'[projects."/synthetic/project"]\ntrust_level = "trusted"\n'
                          b'[plugins."synthetic-plugin"]\nenabled = true\n')
        for index, identifier in enumerate(session.TARGET_IDS):
            mode = 0o755 if identifier == "quarantine-launcher" else 0o600
            if identifier == "config":
                old, applied, current = historical_config, applied_config, current_config
            elif identifier == "global-agents":
                old, applied, current = b"historical guidance", b"old applied guidance", b"current owner guidance"
            else:
                old = None if index % 2 == 0 else ("before-" + identifier).encode("ascii")
                applied = current = ("applied-" + identifier).encode("ascii")
            before[identifier] = (ABSENT if old is None else
                                  before_io.create_exclusive(identifier, old, mode))
            after[identifier] = after_io.create_exclusive(identifier, applied, mode)
            initial[identifier] = current_io.create_exclusive(identifier, current, mode)
            backends[identifier] = (current_io, identifier)

        def targets():
            return {name: current_io.snapshot(name) for name in session.TARGET_IDS}

        def check_historical():
            require({name: before_io.snapshot(name) for name in session.TARGET_IDS} == before)
            require({name: after_io.snapshot(name) for name in session.TARGET_IDS} == after)

        checks = 0
        value = session.capture(backends, store, before, after, session_id="p5-" + "a" * 32)
        require(value["verdict"] == "captured" and targets() == initial)
        checks += 1
        for function in (session.verify, session.noop):
            snapshot = targets()
            require(function(backends, store)["verdict"] in ("verified", "noop"))
            require(targets() == snapshot)
            checks += 1
        require(session.rollback(backends, store)["verdict"] == "completed")
        rolled = targets()
        require(rolled["global-agents"] == initial["global-agents"])
        require(rolled["config"].data == current_config.replace(b'"never"', b'"on-request"', 1)
                .replace(b'"danger-full-access"', b'"workspace-write"', 1))
        for identifier in session.TARGET_IDS[2:]:
            require((rolled[identifier].data, rolled[identifier].mode)
                    == (before[identifier].data, before[identifier].mode))
        checks += 1
        for function in (session.verify, session.noop):
            require(function(backends, store, state="rollback")["verdict"] in ("verified", "noop"))
            require(targets() == rolled)
            checks += 1
        require(session.return_current(backends, store)["verdict"] == "completed")
        returned = targets()
        for identifier in session.TARGET_IDS:
            require((returned[identifier].data, returned[identifier].mode)
                    == (initial[identifier].data, initial[identifier].mode))
        require(returned["global-agents"] == initial["global-agents"])
        checks += 1
        for function in (session.verify, session.noop):
            require(function(backends, store, state="return")["verdict"] in ("verified", "noop"))
            require(targets() == returned)
            checks += 1
        check_historical()
        root.verify()
        return {"schema": 1, "probe": "phase5-owned-native-session", "verdict": "PASS",
                "checkCount": checks, "targetCount": 8,
                "historicalImagesPreserved": True, "currentGuidancePreserved": True,
                "currentConfigReturnedExactly": True, "cleanupPerformed": False,
                "ownerConfigurationRead": False, "ownerConfigurationWrite": False,
                "executionAdmission": False, "phase5PassClaimed": False,
                "phase6Authorized": False,
                "durationSeconds": round(time.monotonic() - started, 3)}
    finally:
        for handle in reversed(handles):
            handle.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-root", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        result = run(arguments.fixture_root)
    except Exception:
        result = {"schema": 1, "probe": "phase5-owned-native-session", "verdict": "FAIL_RETAINED",
                  "cleanupPerformed": False, "executionAdmission": False,
                  "phase5PassClaimed": False, "phase6Authorized": False}
    print(json.dumps(result, sort_keys=True))
    return 0 if result["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
