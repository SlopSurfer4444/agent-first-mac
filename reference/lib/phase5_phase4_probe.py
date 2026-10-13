"""Explicit bounded Phase4 caller. No native defaults, entry point or mutation.

Root supplies reviewed modules, exact source bindings, IO and process factories.
An uncertain native child retains all remaining owners in the original caller;
neither a public report nor interpreter exit transfers those private handles.
"""

from types import SimpleNamespace


def require(value):
    if value is not True:
        raise ValueError("phase4_probe_required") from None


class Outcome:
    def __init__(self):
        self.sources, self.errors, self.calls = [], [], []
        self.observer = self.primary = self.private_owner = self.public = None
        self.source_error = self.helper_report = None
        self.pending = False
        self.closed = True
        self.bound = False

    def __repr__(self):
        return "<private Phase4 probe outcome>"


class ProbeError(Exception):
    def __init__(self, outcome):
        self.outcome, self.private_owner = outcome, outcome.private_owner
        self.settlement_failed = outcome.pending
        super().__init__("phase4_probe_required")


def plan(arguments, *, H, P4, io):
    """Closed read surface; receipt-derived arguments are independently rebound."""
    require(type(arguments) is list and all(type(a) is str for a in arguments))
    args, prefix = tuple(arguments), tuple(P4.GIT)
    if args[:len(prefix)] == prefix:
        tail = args[len(prefix):]
        fixed = {
            ("rev-parse", "HEAD"), ("branch", "--show-current"),
            ("status", "--porcelain=v1", "--untracked-files=all"),
            ("show", H.P2 + ":" + H.P2_FILE), ("rev-parse", H.P2 + "^"),
            ("show", "-s", "--format=%an%x00%ae%x00%cn%x00%ce%x00%s", H.P2),
            ("diff-tree", "--no-commit-id", "--name-status", "-r", H.P2),
            ("merge-base", "--is-ancestor", H.P2_PARENT, H.BASE),
            ("merge-base", "--is-ancestor", H.P2, H.BASE),
        }
        if tail not in fixed:
            revision = H.current_value(io.current())["configurationRevision"]
            require(tail in {
                ("cat-file", "-e", revision + "^{commit}"),
                ("cat-file", "-t", revision + "^{commit}"),
                ("merge-base", "--is-ancestor", "a2a607956745ca9a3f85960b3da0b98463a33880", revision),
                ("merge-base", "--is-ancestor", revision, "HEAD"),
                ("rev-parse", revision + "^{tree}"),
            })
        return "git", 8.0
    fixed = {
        ("/usr/bin/sudo", "-n", H.BROKER, "doctor-root", "--json"): "root-doctor",
        ("/usr/bin/sudo", "-n", H.BROKER, "unknown"): "root-denial",
        ("/usr/bin/sudo", "-n", "/usr/bin/true"): "sudo-true-denial",
        ("/usr/bin/sudo", "-n", "-v"): "sudo-validate-denial",
        ("/bin/ps", "-axo", "comm="): "process-list",
    }
    if args in fixed:
        return fixed[args], 8.0
    require(args[:3] == ("/nix/var/nix/profiles/default/bin/nix-store", "--query", "--hash")
            and len(args) == 4)
    current = io.current()
    H.current_value(current)
    require(args == ("/nix/var/nix/profiles/default/bin/nix-store", "--query", "--hash", current["systemTarget"]))
    return "nix-query", 20.0


def run(*, R, H, P4, O, Observer, home, uid, budget, bindings,
        source_factory, process_factory, syscalls, path_api, clock, read):
    """Call once after root source admission; return only after known closure."""
    state = Outcome()
    control, stage = home + "/AIDev/control", "source"

    def fail(error):
        state.errors.append(error)
        state.primary = R.earliest(state.primary, error)
        owner = getattr(error, "private_owner", None)
        if state.private_owner is None and owner is not None:
            state.private_owner = owner
        # This caller owns every child. The injected helper marks any exception
        # after entering runner conservatively unconfirmed, including a failed
        # prelaunch guard or an already-settled byte parser. Its wrapper flag
        # cannot overwrite the actual runner's known direct-child disposition.
        # Unknown transport entry keeps pending=True inside runner itself.
        if owner is not None:
            state.pending = True

    def guard():
        if state.source_error is not None:
            raise state.source_error
        try:
            budget.check()
            for held in state.sources:
                require(held.verify() is True)
            if state.observer is not None:
                require(state.observer.verify() is True)
        except BaseException as error:
            state.source_error = error
            raise
        return True

    def runner(arguments, cwd=control, environment=None):
        require(not state.pending and str(cwd) == control)
        expected_env = {"HOME": home, "LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin", "TMPDIR": "/tmp"}
        require(environment is None or H.exact(environment, expected_env))
        kind, seconds = plan(arguments, H=H, P4=P4, io=state.observer)
        require(len(state.calls) < 40 and (kind == "git" or kind not in state.calls))
        if kind == "git":
            expected_env.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
                "GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0", "GIT_NO_LAZY_FETCH": "1",
                "GIT_NO_REPLACE_OBJECTS": "1"})
        launch = SimpleNamespace(argv=tuple(arguments), cwd=control, environment=expected_env)
        expected = (launch.argv, launch.cwd, dict(expected_env))
        def admit(value):
            require((value.argv, value.cwd, value.environment) == expected)
            return guard()
        guard()
        state.calls.append(kind)
        state.pending = True
        try:
            result = O.command(launch, budget, seconds, admit_launch=admit, catalog=R.catalog,
                process_factory=process_factory, clock=clock, read=read)
        except BaseException as error:
            if getattr(error, "settlement_failed", None) is False:
                state.pending = False
            fail(error)
            raise
        state.pending = False
        # Fixed probes produce one stream. Do not invent interleaving when both
        # channels contain bytes; P4's original merged-stream semantics matter.
        require(type(result.returncode) is int and type(result.stdout) is bytes
                and type(result.stderr) is bytes and not (result.stdout and result.stderr))
        guard()
        return SimpleNamespace(returncode=result.returncode,
                               stdout=(result.stdout + result.stderr).decode("utf-8", "strict"))

    try:
        require(H.path(home) and type(uid) is int and uid > 0 and str(P4.ROOT) == control)
        require(type(bindings) is dict and 1 <= len(bindings) <= 64
                and all(H.path(p) and type(h) is str and len(h) == 64 for p, h in bindings.items()))
        for path, expected in bindings.items():
            state.closed = False
            held = source_factory(path)
            state.sources.append(held)
            state.closed = True
            require(held.verify() is True and held.digest == expected)
        state.bound = True
        stage = "observer"
        state.closed = False
        state.observer = Observer(P4=P4, R=R, home=home, uid=uid, budget=budget,
                                  syscalls=syscalls, path_api=path_api)
        state.closed = True
        P4.run, P4.strict_json, P4.digest = runner, state.observer.json, state.observer.digest
        stage = "component"
        def admit_dependencies(p4, io, callback):
            require(p4 is P4 and io is state.observer and callback is runner
                    and p4.run is runner and p4.strict_json is io.json and p4.digest is io.digest)
            return guard()
        report = H.collect(P4=P4, control=control, home=home, uid=uid,
            runner=runner, io=state.observer, budget=budget,
            admit_dependencies=admit_dependencies, recheck=guard)
        require(H.exact(report, H.public(complete=True, historical2=True,
                                        historical3=True, stable=True)))
        state.helper_report = report
        stage = "final-recheck"
        guard()
    except BaseException as error:
        fail(error)
    finally:
        # Unknown child custody keeps observer/source owners in this outcome.
        # No new native dispatch, forced process-group cleanup or retry.
        if not state.pending:
            if state.observer is not None:
                try:
                    state.observer.close()
                except BaseException as error:
                    state.closed = False
                    fail(error)
            for held in reversed(state.sources):
                try:
                    held.close()
                except BaseException as error:
                    state.closed = False
                    fail(error)
        else:
            state.closed = False
        try:
            budget.check()
        except BaseException as error:
            fail(error)
    passed = state.primary is None and state.closed and not state.pending
    state.public = {"schema": 1, "probe": "phase5-phase4-bounded-probe",
        "verdict": "CURRENT_PHASE4_COMPONENT_HEALTH" if passed else "NEEDS_REVIEW",
        "componentReport": state.helper_report, "sourceHandlesClosed": state.closed,
        "nativeChildrenSettled": not state.pending,
        "sourceBindingsUnchanged": state.bound and state.source_error is None,
        "commandCount": len(state.calls), "sourceCount": len(state.sources),
        "failureStage": None if passed else stage, "systemMutationsPerformed": False,
        "phase5Accepted": False, "phase6Allowed": False}
    if state.primary is not None:
        if isinstance(state.primary, (KeyboardInterrupt, SystemExit)):
            state.primary.phase4_probe_outcome = state
            state.primary.private_owner = state.private_owner
            state.primary.settlement_failed = state.pending
            raise state.primary from None
        raise ProbeError(state) from None
    return state.public
