"""Owner-authorized user helpers: affected source, target, recovery; no root."""
from pathlib import Path
from lib.operation_checks import DEPENDENCIES, evaluate, require
from lib import scoped_source_admission as source


def require_scoped_operation_ready(control, operation, commit, *, checks, target_guard,
                                   extra_paths=()):
    root = Path(control)
    require(root == Path.home() / "AIDev/control" and root == root.resolve(strict=True),
            "operation_canonical_source")
    require(operation in DEPENDENCIES and operation not in ("nix-prepare", "root-apply")
            and type(checks) is dict, "operation_unknown")
    result = None
    def observe(head, *, source_guard):
        nonlocal result
        require(head == commit, "operation_commit_drift")
        result = evaluate(operation, head, checks=checks, source_guard=source_guard,
                          target_guard=target_guard)
        return result
    entrypoints = source.callable_paths(root, (*checks.values(), target_guard, observe))
    source.run(root, observe, entrypoints=entrypoints, extra_paths=extra_paths, expected_commit=commit)
    require(result is not None, "operation_source_unobserved")
    return result
