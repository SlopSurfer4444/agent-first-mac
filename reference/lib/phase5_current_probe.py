"""One root-admitted probe inside a held current-state observation.

No entry point, native defaults, imports of a historical runner, source loader,
capture/store, retry, rollback or deletion. Root independently admits this module,
readiness definitions, exact source closure and the fixed work callback before
calling connected. The callback owns its process/fixture lifetimes; it receives
the still-held observations and a guard, not execution authority.

An exceptional native return is conservatively unconfirmed even without a
process handle. Failure retains private context; JSON never transfers custody.
Successful observations are not continuous exclusion or future admission.
"""

from dataclasses import dataclass, field


SELF = "lib/phase5_current_probe.py"
OPERATIONS = frozenset(("discovery", "trusted-task", "quarantine"))


@dataclass(repr=False)
class Context:
    targets: object = None
    legacy: object = None
    runtime: object = None
    work_result: object = None
    primary: object = None
    failures: list = field(default_factory=list)
    pending_owner: object = None
    pending_acquisition: object = None
    pending_native: object = None
    native_settled: bool = True
    handles_closed: bool = True


class ProbeError(Exception):
    def __init__(self, report, context):
        self.report, self.private_context = report, context
        self.private_owner = context.pending_owner
        self.settlement_failed = not context.native_settled
        super().__init__("current_probe_required")


def public(verdict="closed", *, operation=None, stage="closed", invoked=False,
           unchanged=False, settled=True, closed=True):
    return {"schema": 1, "verdict": verdict, "operation": operation,
            "stage": stage, "workInvoked": invoked, "currentStateUnchanged": unchanged,
            "nativeChildrenSettled": settled, "handlesClosed": closed,
            "targetMutationAttempted": False, "executionAdmission": False,
            "phase5Accepted": False, "phase6Allowed": False}


def connected(readiness, home, uid, *, operation=None, source_closure=None,
              recheck_sources=None, runtime_factory=None, target_observer=None,
              legacy_observer=None, work=None, accept_work=None, budget=None):
    """Root callbacks are trusted, explicit and separately source-admitted.

work(context, guard) runs exactly once, after current admission and signature
attestation, before final signature/state checks and release of the same owners.
It must guard each consequential child and settle its complete private scope.
Its return stays private; only accept_work(result) is consumed as a verdict.
"""
    if (type(operation) is not str or operation not in OPERATIONS
            or type(source_closure) is not tuple or SELF not in source_closure
            or any(type(p) is not str for p in source_closure)
            or len(set(source_closure)) != len(source_closure)
            or not all(callable(f) for f in (recheck_sources, runtime_factory,
                target_observer, legacy_observer, work, accept_work)) or budget is None):
        return public()
    R, context = readiness, Context()
    stage, failure_stage, invoked, guard_failed = "source-bind", None, False, False
    active, final_verified, initial_admitted = True, False, False

    def failure(error):
        nonlocal failure_stage
        if not any(error is previous for previous in context.failures):
            context.failures.append(error)
        context.primary = R.earliest(context.primary, error)
        if failure_stage is None:
            failure_stage = stage
        owner = getattr(error, "private_owner", None)
        if owner is None and context.runtime is not None:
            owner = getattr(context.runtime, "pending_owner", None)
        if context.pending_owner is None and owner is not None:
            context.pending_owner = owner
        if (owner is not None or context.pending_native is not None
                or getattr(error, "settlement_failed", False) is not False):
            context.native_settled = False
        if context.pending_acquisition is not None:
            context.handles_closed = False

    def guard():
        nonlocal guard_failed
        try:
            R.require(active is True)
            budget.check()
            R.require(set(R.SOURCE_CLOSURE) <= set(source_closure))
            R.require(recheck_sources(source_closure) is True)
            for held in (context.targets, context.legacy, context.runtime):
                if held is not None:
                    R.require(held.verify() is True)
            budget.check()
            return True
        except BaseException as error:
            guard_failed = True
            # A callback catching this exception cannot erase the observation
            # or its original interruption/private owner from the outer scope.
            failure(error)
            raise

    def acquire(name, factory, *arguments):
        context.pending_acquisition = name
        owner = factory(*arguments)
        R.require(owner is not None and all(owner is not other for other in
                  (context.targets, context.legacy, context.runtime)))
        setattr(context, name, owner)
        context.pending_acquisition = None

    def native(name, function):
        context.pending_native = name
        value = function()
        context.pending_native = None
        return value

    def admitted(images):
        return R.admit_current_round(images, home=home, runtime=context.runtime,
            metadata_empty=context.targets.metadata_empty, recheck_dependencies=guard)

    try:
        guard()
        stage = "target-read"
        acquire("targets", target_observer, home, uid)
        stage = "history-read"
        acquire("legacy", legacy_observer, home, uid)
        stage = "collect"
        acquire("runtime", runtime_factory, home, uid, budget)
        native("collect", context.runtime.collect)
        guard()
        stage = "admission"
        checked = R.capture.readiness(context.targets.bindings, context.legacy.receipt,
            context.legacy.physical_before, context.legacy.physical_after,
            admit_current=admitted, recheck_dependencies=guard)
        R.require(type(checked) is dict and checked.get("verdict") == "ready")
        initial_admitted = True
        stage = "attestation"
        R.require(native("attestation", context.runtime.final_attest) is True)
        guard()
        stage, invoked = "work", True
        context.work_result = native("work", lambda: work(context, guard))
        guard()
        R.require(context.primary is None)
        R.require(accept_work(context.work_result) is True)
        stage = "final-attestation"
        R.require(native("attestation", context.runtime.final_attest) is True)
    except BaseException as error:
        failure(error)
    finally:
        stage = "final-recheck"
        try:
            guard()
            final_verified = initial_admitted and not guard_failed
        except BaseException as error:
            failure(error)
        active, stage = False, "close"
        for held in (context.runtime, context.legacy, context.targets):
            if held is not None:
                try:
                    held.close()
                except BaseException as error:
                    context.handles_closed = False
                    failure(error)
        try:
            budget.check()
        except BaseException as error:
            final_verified = False
            failure(error)
    report = public("completed" if context.primary is None else "needs-review",
        operation=operation, stage=failure_stage or "final-recheck", invoked=invoked,
        unchanged=final_verified, settled=context.native_settled, closed=context.handles_closed)
    if context.primary is not None:
        if isinstance(context.primary, (KeyboardInterrupt, SystemExit)):
            context.primary.probe_report = report
            context.primary.private_context = context
            context.primary.private_owner = context.pending_owner
            context.primary.settlement_failed = not context.native_settled
            raise context.primary from None
        raise ProbeError(report, context) from None
    return report
