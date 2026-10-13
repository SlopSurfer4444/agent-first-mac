"""Root-injected, one-operation recovery source admission; no entry point.

Root must independently bind the complete bootstrap before importing this module
or the readiness definitions providing SourceFile/Budget. Supply that admitted
SourceFile as source_factory(relative): this module has no default reader,
importer, runtime, clock, signal handler or native operation. The independently
declared closure/managed tuple and hash map are root's reviewed intent, not a
manifest inferred from an untrusted checkout. The loaded caller must agree.

All operation source observations, including recovery/directory/store, are held
before caller_loader() and rechecked through connected's callback. Runtime's
separate existing pins are unchanged. Root supplies the finite outer signal
boundary and retains exceptions/outcomes in its interactive owning process.
Closing source handles neither settles a native child nor removes artifacts.
No retry, compensation, automatic exit, persistence, or model dispatch occurs.
"""

import re


SELF = "lib/phase5_recovery_admission.py"
CONTRACT = "manifests/codex-contract.json"
REQUIRED = frozenset(("bin/phase5-current-recovery", "bin/phase5-current-readiness",
                     "lib/phase5_runtime_directory.py", "lib/phase5_runtime_store.py"))
STAGES = frozenset(("closed", "source-bind", "target-read", "history-read", "collect",
    "admission", "attestation", "allocation", "store", "capture", "handoff", "current-noop",
    "rollback", "rollback-noop", "return", "return-noop", "current-admission", "final-recheck", "close"))
FLAGS = ("allocationAttempted", "targetMutationAttempted", "captureConfirmed",
         "returnConfirmed", "nativeChildrenSettled", "executionAdmission", "liveAdmission",
         "phase5Accepted", "phase6Allowed", "cleanupPerformed")
AUTHORITY = FLAGS[5:]


class AdmissionError(Exception):
    """Only the fixed message is public; retain outcome privately in-process."""
    def __init__(self, outcome):
        self.admission_outcome = outcome
        self.private_owner, self.private_session = outcome.private_owner, outcome.private_session
        self.settlement_failed = not outcome.public["nativeChildrenSettled"]
        super().__init__("recovery_admission_required")


class Outcome:
    def __init__(self):
        self.public = None
        self.primary = self.caller_exception = self.private_owner = self.private_session = None
        self.sources, self.errors = [], []
        self.pending_source = None

    def __repr__(self):
        return "<private recovery admission outcome>"


def _require(condition):
    if condition is not True:
        raise ValueError("recovery_admission_required") from None


def _first(first, later):
    if isinstance(first, (KeyboardInterrupt, SystemExit)):
        return first
    return later if first is None or isinstance(later, (KeyboardInterrupt, SystemExit)) else first


def _paths(value):
    _require(type(value) is tuple and 1 <= len(value) <= 40)
    _require(all(type(path) is str and 0 < len(path) <= 1024
                 and re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*", path) is not None
                 and not any(part in (".", "..") for part in path.split("/")) for path in value))
    _require(len(set(value)) == len(value))
    return value


def _report(value):
    keys = {"schema", "verdict", "stage", "state", "completedStages", *FLAGS}
    _require(type(value) is dict and set(value) == keys)
    _require(type(value["schema"]) is int and value["schema"] == 1)
    _require(type(value["verdict"]) is str and value["verdict"] in ("closed", "completed", "recovery-required"))
    _require(type(value["stage"]) is str and value["stage"] in STAGES)
    _require(type(value["state"]) is str and value["state"] in ("unknown", "current", "rollback"))
    _require(type(value["completedStages"]) is int and 0 <= value["completedStages"] <= 32)
    _require(all(type(value[key]) is bool for key in FLAGS)
             and all(value[key] is False for key in AUTHORITY))
    return {key: value[key] for key in ("schema", "verdict", "stage", "state", "completedStages", *FLAGS)}


def run(*, source_hashes, source_closure, managed_sources, source_factory, caller_loader,
        home, uid, operation, run_id, runtime_factory, budget):
    """Exactly one explicit connected operation; no inferred or default admission.

source_factory(relative) returns one newly held admitted SourceFile. The exact
hash map also includes this adapter and the contract/managed source. All factories
are separately root-admitted; fake tests inject all native-facing capabilities.
Failure raises with admission_outcome; KI/SystemExit preserves the same object.
The private original caller exception/context survives later postcheck/close errors.
"""
    outcome = Outcome()
    stage, failure_stage, caller_report, operation_started = "source-bind", None, None, False
    sources_unchanged, handles_closed, settled = False, True, True
    source_check_failed = False
    expected = None

    def failure(error):
        nonlocal settled, failure_stage
        outcome.errors.append(error)
        outcome.primary = _first(outcome.primary, error)
        if failure_stage is None:
            failure_stage = stage
        owner = getattr(error, "private_owner", None)
        if outcome.private_owner is None and owner is not None:
            outcome.private_owner = owner
        if (owner is not None or isinstance(error, (KeyboardInterrupt, SystemExit))
                or getattr(error, "settlement_failed", False) is not False):
            settled = False

    def recheck(closure):
        nonlocal source_check_failed
        try:
            _require(type(closure) is tuple and closure == source_closure)
            budget.check()
            _require(len(outcome.sources) == len(expected))
            for relative, source in outcome.sources:
                _require(source.verify() is True and source.digest == expected[relative])
            budget.check()
            return True
        except BaseException:
            source_check_failed = True
            raise

    try:
        source_closure, managed_sources = _paths(source_closure), _paths(managed_sources)
        required = set(source_closure) | set(managed_sources) | {SELF, CONTRACT}
        _require(REQUIRED <= set(source_closure) and len(required) <= 40)
        _require(type(source_hashes) is dict and set(source_hashes) == required)
        _require(all(type(digest) is str and re.fullmatch(r"[0-9a-f]{64}", digest) is not None
                     for digest in source_hashes.values()))
        expected = dict(source_hashes)
        _require(all(callable(factory) for factory in (source_factory, caller_loader, runtime_factory)))
        _require(type(home) is str and home.startswith("/") and not home.endswith("/")
                 and type(uid) is int and 0 <= uid < 2 ** 32)
        _require(type(operation) is str and operation in ("capture-noop", "rollback-return")
                 and type(run_id) is str and re.fullmatch(r"p5-[0-9a-f]{32}", run_id) is not None)
        budget.check()
        for relative in sorted(expected):
            outcome.pending_source = relative
            source = source_factory(relative)
            _require(all(source is not previous for _, previous in outcome.sources))
            outcome.sources.append((relative, source))  # Own before any subsequent check.
            outcome.pending_source = None
            _require(source.digest == expected[relative])
            budget.check()
        recheck(source_closure)
        stage = "caller-load"
        caller = caller_loader()
        _require(caller.SOURCE_CLOSURE == source_closure
                 and tuple(caller.R.MANAGED.values()) == managed_sources)
        recheck(source_closure)
        stage, operation_started, settled = "operation", True, False
        try:
            value = caller.connected(home, uid, operation=operation, run_id=run_id,
                runtime_factory=runtime_factory, recheck_source_closure=recheck, budget=budget)
        except BaseException as error:
            outcome.caller_exception = error
            failure(error)
            outcome.private_session = getattr(error, "private_session", None)
            value = getattr(error, "recovery_report", getattr(error, "report", None))
            if isinstance(error, caller.RecoveryError):
                caller_report = _report(value)
                settled = (caller_report["nativeChildrenSettled"] is True
                           and error.settlement_failed is False and error.private_owner is None
                           and getattr(outcome.private_session, "settlement_confirmed", None) is True)
        else:
            caller_report = _report(value)
            settled = caller_report["nativeChildrenSettled"]
            _require(caller_report["verdict"] == "completed" and settled is True)
        if caller_report is None and outcome.caller_exception is not None:
            # A valid interrupt report is historical progress, not settlement proof.
            try:
                caller_report = _report(value)
            except Exception:
                pass
    except BaseException as error:
        failure(error)
    finally:
        if outcome.pending_source is not None:
            handles_closed = False  # Constructor failure never proves no acquired FD.
        stage = "source-postcheck"
        try:
            if expected is not None:
                recheck(source_closure)
                sources_unchanged = not source_check_failed
        except BaseException as error:
            failure(error)
        stage = "source-close"
        for _, source in reversed(outcome.sources):
            try:
                source.close()
            except BaseException as error:
                handles_closed = False
                failure(error)
        stage = "final-budget"
        try:
            budget.check()
        except BaseException as error:
            failure(error)
    outcome.public = {"schema": 1, "verdict": "completed" if outcome.primary is None else "needs-review",
        "stage": failure_stage or "completed", "operationStarted": operation_started, "sourcesUnchanged": sources_unchanged,
        "sourceHandlesClosed": handles_closed, "nativeChildrenSettled": settled,
        "callerReport": caller_report, **dict.fromkeys(AUTHORITY, False)}
    if isinstance(outcome.primary, (KeyboardInterrupt, SystemExit)):
        outcome.primary.admission_outcome = outcome
        outcome.primary.private_owner, outcome.primary.private_session = outcome.private_owner, outcome.private_session
        outcome.primary.settlement_failed = not settled
        raise outcome.primary from None
    if outcome.primary is not None:
        raise AdmissionError(outcome) from None
    return outcome
