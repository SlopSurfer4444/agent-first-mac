"""Operation-bound candidate diagnostics; never a root or native-consent grant.

The closed dependency map belongs to reviewed source, not caller evidence.
Callbacks are the owning adapter's actual observations, not receipt booleans.
Source and target are checked around every relevant observation. There is no
TTL cache. A same-user process able to replace this code is outside its threat
boundary; native permissions and the installed typed broker remain authoritative.
"""
import importlib.machinery
from pathlib import Path
from lib.operation_checks import DEPENDENCIES, evaluate, require


def require_operation_ready(control, operation, commit, *, checks, target_guard,
                            execution=True):
    """Check canonical admitted source, scoped observations and retained live gate.

    execution=False is preparation/diagnosis only. execution=True additionally
    requires the existing fresh full doctor; this source candidate does not
    install or select a relaxed live gate. Native consent callbacks mean an
    actually verified existing grant/unchanged boundary, never a fabricated one.
    """
    require(type(execution) is bool, "operation_execution_mode")
    root = Path(control)
    require(root.is_absolute() and root == root.resolve(strict=True)
            and root == Path.home() / "AIDev/control",
            "operation_canonical_source")
    doctor = importlib.machinery.SourceFileLoader(
        "operation_current_doctor", str(root / "bin/current-doctor")).load_module()
    from lib import current_doctor_native
    result = None
    def observe(head, *, source_guard):
        nonlocal result
        require(head == commit, "operation_commit_drift")
        result = evaluate(operation, commit, checks=checks,
                          source_guard=source_guard, target_guard=target_guard)
        return True
    value = current_doctor_native.native(doctor, True, operation_check=observe)
    value = doctor.public_report(value, git_only=True)
    require(value["verdict"] == "GIT_ONLY_VALID" and value["integratedMain"] is True
            and result is not None, "operation_source_unadmitted")
    if execution:
        # Retain full rollout readiness; no marker or caller-supplied flag can
        # approve the replacement policy. Recheck target and exact commit while
        # source is held by the full run, including its final source recheck.
        value = current_doctor_native.native(doctor, False, operation_check=observe)
        value = doctor.public_report(value, git_only=False)
        require(value["verdict"] == "PASS" and value["integratedMain"] is True
                and value["currentSentinelReady"] is True, "operation_live_gate")
        require(target_guard() is True, "operation_target_drift")
        result["liveGateSatisfied"] = True
    return result


def require_scoped_operation_ready(control, operation, commit, *, checks, target_guard):
    """Legacy source-admitted route retained for callers not yet migrated.

    Connected user helpers use user_operation_readiness directly so this
    historical/full-doctor import graph is not their runtime dependency.
    Root preparation and explicit history audit retain their existing gates.
    """
    return require_operation_ready(control, operation, commit, checks=checks,
                                   target_guard=target_guard, execution=False)
