"""Explicit owned-fixture native smoke. Never runs without --fixture-root.

Caller allocates one empty0700 directory immediately under AIDev/scratch,
reviews source and imposes an outer deadline. This program retains every
created object, including failures; it never reads owner config or runs Codex.
It tests Darwin rename semantics, not production authorization or ACL policy.
"""

import argparse
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from lib.phase5_runtime_backend import BackendError, DescriptorBackend
from lib.phase5_runtime_transition import prepare, recover, transition


def require(condition):
    if not condition:
        raise ValueError("native_fixture_assertion") from None


def load_reader():
    # Definitions only: no legacy entrypoint, validator or transaction runs.
    loader = importlib.machinery.SourceFileLoader(
        "phase5_native_fixture_directory_reader", str(ROOT / "bin/phase5-apply-transaction"))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    sys.modules[loader.name] = module
    loader.exec_module(module)
    return module


def run(fixture):
    account = __import__("pwd").getpwuid(os.getuid())
    scratch = Path(account.pw_dir) / "AIDev/scratch"
    require(fixture.is_absolute() and fixture.parent == scratch)
    require(re.fullmatch(r"phase5-successor-native\.[A-Za-z0-9]{6,16}", fixture.name) is not None)
    reader = load_reader()
    parent = reader.open_directory(fixture, os.getuid(), {0o700}, Path(account.pw_dir))
    try:
        require(not parent.names())
        backend = DescriptorBackend(parent)
        cases = 0

        for key, before, after in (
            ("replace", b"old", b"new"),
            ("create", None, b"new"),
            ("remove", b"old", None),
            ("same", b"same", b"same"),
            ("absent", None, None),
        ):
            if before is not None:
                backend.create_exclusive(key, before, 0o600)
            source = backend.snapshot(key)
            ticket = prepare(backend, target=key, temporary=key + "-stage",
                             recovery=key + "-retained", source=source,
                             destination_bytes=after, mode=None if after is None else 0o600)
            forward = transition(backend, ticket)
            require(forward["verdict"] in ("completed", "noop"))
            require(forward["executionAdmission"] is False)
            require(backend.snapshot(key).data == after)
            reverse = recover(backend, ticket)
            require(reverse["verdict"] in ("recovered", "noop"))
            require(backend.snapshot(key) == source)
            cases += 1

        original = backend.create_exclusive("collision", b"keep", 0o600)
        failed = False
        try:
            backend.create_exclusive("collision", b"replace-forbidden", 0o600)
        except BackendError:
            failed = True
        require(failed and backend.snapshot("collision") == original)
        cases += 1

        # These deliberately unsafe names point only to other owned fixture
        # objects. No owner target/path is ever used as a link destination.
        os.symlink("collision", "symlink", dir_fd=parent.descriptor)
        os.link("collision", "hardlink", src_dir_fd=parent.descriptor,
                dst_dir_fd=parent.descriptor, follow_symlinks=False)
        # System Python on this Mac has no mkfifo(dir_fd=...). This isolated,
        # single-threaded test process can bind cwd to the held fixture FD;
        # never replace this with a pathname fallback or use it in the backend.
        cwd_descriptor = os.open(".", reader.DIRECTORY_FLAGS)
        try:
            parent.verify()
            os.fchdir(parent.descriptor)
            os.mkfifo("fifo", 0o600)
            parent.verify()
        finally:
            try:
                os.fchdir(cwd_descriptor)
            finally:
                os.close(cwd_descriptor)
        for leaf in ("symlink", "hardlink", "fifo"):
            failed = False
            try:
                backend.snapshot(leaf)
            except BackendError:
                failed = True
            require(failed)
            cases += 1

        backend.sync()
        names = parent.names()
        require(set(names) == {"replace", "replace-stage", "create-retained",
                               "remove", "same", "collision", "symlink", "hardlink", "fifo"})
        parent.verify()
        return {"schema": 1, "probe": "phase5-owned-native-backend",
                "verdict": "PASS", "caseCount": cases,
                "retainedObjectCount": len(names), "cleanupPerformed": False,
                "ownerConfigurationRead": False, "ownerConfigurationWrite": False,
                "executionAdmission": False, "phase5PassClaimed": False,
                "phase6Authorized": False}
    finally:
        parent.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-root", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        result = run(arguments.fixture_root)
    except Exception:
        result = {"schema": 1, "probe": "phase5-owned-native-backend",
                  "verdict": "FAIL_RETAINED", "cleanupPerformed": False,
                  "executionAdmission": False, "phase5PassClaimed": False,
                  "phase6Authorized": False}
    print(json.dumps(result, sort_keys=True))
    return 0 if result["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
