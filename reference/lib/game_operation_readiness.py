"""Game lifecycle's scoped diagnostic bridge; no subprocess or live authority.

The adapter owns fixed targets, held locks, owner/prefix checks and recovery.
The shared operation diagnostic borrows those actual callbacks and holds the
admitted source. Its native budget/custody errors propagate without an outer
120-second process timeout, retry, rollback or fabricated settlement.
"""
import importlib.machinery
import importlib.util
from pathlib import Path
import sys
import os
import stat


def ready(control, commit, operation, *, checks, target_guard, extra_paths=None):
    control = Path(control)
    if str(control) not in sys.path:
        sys.path.insert(0, str(control))
    from lib.user_operation_readiness import require_scoped_operation_ready
    return require_scoped_operation_ready(control, operation, commit,
                                         checks=checks, target_guard=target_guard,
                                         extra_paths=extra_paths)


def load(control):
    """Fixed canonical library, selected only after caller exact-source check."""
    path = Path(control) / "lib/game_operation_readiness.py"
    loader = importlib.machinery.SourceFileLoader("game_operation_readiness", str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def bound(snapshot):
    """A real target snapshot supplies before/after drift checking, never PASS."""
    before = snapshot()
    def guard():
        return snapshot() == before
    return guard


def metadata(paths):
    """Bound fixed target nodes without opening profiles, logs or auth bytes."""
    result=[]
    for path in paths:
        path=Path(path)
        for parent in reversed(path.parents):
            facts=parent.lstat()
            if not stat.S_ISDIR(facts.st_mode) or facts.st_uid not in (0,os.getuid()) or facts.st_mode&0o022:
                raise RuntimeError('operation_target_parent')
        try:facts=path.lstat()
        except FileNotFoundError:result.append(None);continue
        if facts.st_uid not in (0,os.getuid()) or facts.st_mode&0o022:
            raise RuntimeError('operation_target_owner')
        result.append((facts.st_dev,facts.st_ino,facts.st_mode,facts.st_uid,facts.st_size,
                       facts.st_mtime_ns,facts.st_ctime_ns,os.readlink(path) if stat.S_ISLNK(facts.st_mode) else None))
    return tuple(result)
