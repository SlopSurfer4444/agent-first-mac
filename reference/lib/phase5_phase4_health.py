"""Injected Phase 4 component observation, not the obsolete CLI topology gate.

No native imports/default observer, entry point, process owner, mutation, or
historical replay. Root admits P4 source and its explicit runner/IO bindings and
retains physical source/generation handles around this bounded composition.
"""

import hashlib
import json
import re


BASE = "96d11eba6f89e080281f5e6faf91c60bd65e0a66"
P2 = "2fdbd7e7419fc049565f87b29a21b7dd1838a754"
P2_PARENT = "e7beb60fb985ab053ab04f3de2ee379316126659"
P2_FILE = "evidence/phase-2/acceptance.json"
P2_HASH = "3032fa9bd817ebc16d9917ae413b298469eeb998630d861164e030f1a1d811e6"
P2_METADATA = ("Codex", "codex@local.invalid", "Codex", "codex@local.invalid", "Accept Phase 2 L2 baseline")
P2_CHANGES = {"AGENTS.md": "M", "ARCHITECTURE.md": "M", "README.md": "M",
    "bin/check-phase2a": "M", "bin/phase2-doctor": "M", P2_FILE: "A",
    "manifests/package-sources.json": "M", "manifests/workstation.json": "M"}
PROFILE = "/nix/var/nix/profiles/system"
BROKER = "/usr/local/libexec/aid-admin"
POLICY = "/etc/agent-first-mac/aid-admin-policy.json"
SUDOERS = "/etc/sudoers.d/agent-first-mac-aid-admin"
DIRECTORIES = {"audit": "/var/log/agent-first-mac/aid-admin", "staging": "/var/db/agent-first-mac/staging"}
EMERGENCY = ("/etc/agent-first-mac/aid-admin.disabled", "/etc/agent-first-mac/aid-admin.disabled.new",
             "/etc/sudoers.d/agent-first-mac-aid-admin.disabled")
AUTHORITY = ("executionAdmission", "applyAuthorized", "rootMutationAuthorized", "phase5Accepted", "phase6Allowed")


def require(value):
    if value is not True:
        raise ValueError("phase4_component_health_required") from None


def sha(data):
    return hashlib.sha256(data).hexdigest()


def commit(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{40}", value) is not None


def path(value):
    return (type(value) is str and 1 < len(value) <= 4096 and value.startswith("/")
            and "\0" not in value and all(p not in ("", ".", "..") for p in value[1:].split("/")))


def snapshot(value, depth=0):
    """Detach only bounded exact builtins; no object copying hooks."""
    require(depth <= 12)
    if type(value) in (str, bytes):
        require(len(value) <= 4 * 1024 * 1024)
        return value
    if type(value) in (bool, int) or value is None:
        return value
    require(type(value) in (dict, list, tuple) and len(value) <= 10000)
    if type(value) is dict:
        require(all(type(k) in (str, int) for k in value))
        return {k: snapshot(v, depth + 1) for k, v in value.items()}
    return type(value)(snapshot(v, depth + 1) for v in value)


def exact(a, b):
    if type(a) is not type(b):
        return False
    if type(a) is dict:
        return set(a) == set(b) and all(exact(a[k], b[k]) for k in a)
    if type(a) in (list, tuple):
        return len(a) == len(b) and all(exact(x, y) for x, y in zip(a, b))
    return a == b


def parse(data):
    require(type(data) is bytes and len(data) <= 4 * 1024 * 1024)
    def pairs(rows):
        value = {}
        for key, item in rows:
            require(key not in value)
            value[key] = item
        return value
    def invalid(_):
        raise ValueError("phase4_component_health_required")
    return json.loads(data.decode("utf-8", "strict"), object_pairs_hook=pairs, parse_constant=invalid)


def file_value(value, *, uid, mode=None, size=None, maximum=4 * 1024 * 1024, digest=None):
    require(type(value) is dict and set(value) == {"data", "uid", "gid", "mode", "kind", "nlink", "symlink", "size"})
    require(all(type(value[k]) is int and value[k] >= 0 for k in ("uid", "gid", "mode", "nlink", "size"))
            and value["uid"] == uid and value["kind"] == "file" and type(value["kind"]) is str
            and value["symlink"] is False and value["nlink"] == 1
            and 0 <= value["mode"] <= 0o777 and not value["mode"] & 0o022
            and (mode is None or value["mode"] == mode)
            and type(value["data"]) is bytes and 1 <= len(value["data"]) == value["size"] <= maximum
            and (size is None or value["size"] == size)
            and (digest is None or sha(value["data"]) == digest))
    return value["data"]


def sudoers_metadata(value):
    require(type(value) is dict and set(value) == {"uid", "gid", "mode", "kind", "nlink", "symlink", "size"})
    require(exact(value, {"uid": 0, "gid": 0, "mode": 0o440, "kind": "file",
                          "nlink": 1, "symlink": False, "size": 122}))


def current_value(value):
    require(type(value) is dict and set(value) == {"profileTarget", "systemTarget", "targets",
                                                 "versionLink", "versionFile", "versionBytes"})
    targets = value["targets"]
    require(type(targets) is dict and 2 <= len(targets) <= 10000 and all(type(n) is int and n > 0 for n in targets))
    for row in targets.values():
        require(type(row) is dict and set(row) == {"gid", "kind", "mode", "path", "substituted", "uid"})
        require(type(row["uid"]) is int and type(row["gid"]) is int and row["uid"] == row["gid"] == 0
                and type(row["mode"]) is int and 0 <= row["mode"] <= 0o777 and not row["mode"] & 0o022
                and type(row["kind"]) is str and row["kind"] == "directory" and row["substituted"] is False
                and path(row["path"]) and re.fullmatch(r"/nix/store/[A-Za-z0-9._+-]+", row["path"]) is not None)
    require(path(value["profileTarget"]) and value["systemTarget"] == value["profileTarget"]
            and type(value["systemTarget"]) is str
            and value["profileTarget"] in [row["path"] for row in targets.values()]
            and 2 in targets and 3 in targets)
    require(exact(value["versionLink"], {"gid": 0, "kind": "symlink", "mode": 0o755, "uid": 0})
            and exact(value["versionFile"], {"gid": 0, "kind": "file", "modeWritable": False,
                "owner": 0, "parent": "/nix/store", "sizeBounded": True})
            and type(value["versionBytes"]) is bytes and 1 <= len(value["versionBytes"]) <= 4096)
    version = parse(value["versionBytes"])
    require(type(version) is dict and set(version) == {"configurationRevision", "darwinLabel", "darwinRevision", "nixpkgsRevision"}
            and all(type(v) is str for v in version.values()) and commit(version["configurationRevision"]))
    return version


def public(*, complete=False, historical2=False, historical3=False, stable=False, settled=True, stage=None):
    return {"schema": 1, "probe": "phase5-phase4-component-health",
        "verdict": "CURRENT_PHASE4_COMPONENT_HEALTH" if complete else "NEEDS_REVIEW",
        "historicalPhase2Accepted": historical2, "historicalPhase3Accepted": historical3,
        "phase2LiveDoctorExecuted": False, "historicalPhase4CLIExecuted": False,
        "currentPhase4Health": complete, "sourceAndStateChecksStable": stable,
        "nativeChildrenSettled": settled, "failureStage": stage,
        "systemMutationsPerformed": False, **{k: False for k in AUTHORITY}}


class Outcome:
    def __init__(self):
        self.primary = self.private_owner = self.public = None
        self.errors, self.observations = [], []
        self.facts = None

    def __repr__(self):
        return "<private Phase 4 component health outcome>"


class HealthError(Exception):
    def __init__(self, outcome):
        self.outcome, self.private_owner = outcome, outcome.private_owner
        self.settlement_failed = not outcome.public["nativeChildrenSettled"]
        super().__init__("phase4_component_health_required")


def collect(*, P4, control, home, uid, runner, io, budget, admit_dependencies, recheck):
    """Root-owned capabilities only; see the companion dependency contract.

P4.run/strict_json/digest MUST be these explicitly bound runner/io callbacks.
The unmodified validator body is never patched to supply passing assertions.
Every observed snapshot is re-observed; recheck additionally binds its actual
held descriptor generation. Root closes those handles and owns process custody.
"""
    outcome = Outcome()
    stage, failure_stage = "dependencies", None
    historical2 = historical3 = stable = complete = False
    settled, admitted = True, False

    def failure(error):
        nonlocal failure_stage, settled
        outcome.errors.append(error)
        if outcome.primary is None or (not isinstance(outcome.primary, (KeyboardInterrupt, SystemExit))
                                      and isinstance(error, (KeyboardInterrupt, SystemExit))):
            outcome.primary = error
        if failure_stage is None:
            failure_stage = stage
        owner = getattr(error, "private_owner", None)
        if outcome.private_owner is None and owner is not None:
            outcome.private_owner = owner
        if owner is not None or getattr(error, "settlement_failed", False) is not False:
            settled = False

    def observe(kind, *arguments):
        budget.check()
        value = snapshot(getattr(io, kind)(*arguments))
        outcome.observations.append((kind, arguments, snapshot(value)))
        return value

    def command(arguments, *, maximum=16384, codes=(0,)):
        nonlocal settled
        budget.check()
        settled = False
        result = runner(list(arguments), cwd=control, environment=environment)
        # Runner returns only after its direct child/streams are settled; on
        # ambiguous launch/cleanup it MUST raise with retained private owner.
        require(type(result.returncode) is int and type(result.stdout) is str
                and len(result.stdout.encode("utf-8")) <= maximum)
        settled = True
        require(result.returncode in codes)
        budget.check()
        return result

    def git(*args, maximum=65536):
        return command((*P4.GIT, *args), maximum=maximum).stdout.rstrip("\n")

    try:
        require(path(home) and control == home + "/AIDev/control" and type(control) is str
                and type(uid) is int and uid > 0 and callable(runner)
                and callable(admit_dependencies) and callable(recheck))
        require(str(P4.ROOT) == control and P4.run is runner
                and P4.strict_json is io.json and P4.digest is io.digest)
        require(all(callable(getattr(io, name)) for name in ("file", "metadata", "directory", "absent", "current", "json", "digest")))
        environment = {"HOME": home, "LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin", "TMPDIR": "/tmp"}
        require(admit_dependencies(P4, io, runner) is True and recheck() is True)
        admitted = True
        stage = "baseline"
        require(git("rev-parse", "HEAD") == BASE and git("branch", "--show-current") == "main"
                and git("status", "--porcelain=v1", "--untracked-files=all") == "")
        stage = "phase2-history"
        raw = file_value(observe("file", control + "/" + P2_FILE), uid=uid, maximum=16384, digest=P2_HASH)
        require(git("show", P2 + ":" + P2_FILE).encode() + b"\n" == raw)
        require(git("rev-parse", P2 + "^") == P2_PARENT)
        metadata = git("show", "-s", "--format=%an%x00%ae%x00%cn%x00%ce%x00%s", P2).split("\0")
        require(tuple(metadata) == P2_METADATA)
        changes = git("diff-tree", "--no-commit-id", "--name-status", "-r", P2).splitlines()
        expected_changes = sorted(kind + "\t" + name for name, kind in P2_CHANGES.items())
        require(sorted(changes) == expected_changes)
        for ancestor in (P2_PARENT, P2):
            git("merge-base", "--is-ancestor", ancestor, BASE)
        value = parse(raw)
        require(type(value) is dict and type(value.get("schema")) is int and value["schema"] == 1
                and exact(value["gate"], {"l2_claimed": True, "next_gate": "phase3_permissions_preparation_not_started",
                    "phase2_complete": True, "phase3_authorized": False, "verdict": "PASS"})
                and value["independent_review"]["reviewed_head"] == P2_PARENT
                and value["integration"]["main_head_before_acceptance_record"] == P2_PARENT)
        historical2 = True
        stage = "phase3-history"
        require(P4.validate_phase3_evidence() is True)
        historical3 = True
        stage = "generation"
        current = observe("current")
        version = current_value(current)
        target = current["profileTarget"]
        receipt_path = home + "/AIDev/state/phase-4/apply-receipts/" + version["configurationRevision"] + ".json"
        receipt = parse(file_value(observe("file", receipt_path), uid=uid, mode=0o400, maximum=4096))
        require(type(receipt) is dict and set(receipt) == {"controlCommit", "controlTree", "policyHash", "reviewed",
                                                        "schema", "targetSystemNarHash", "targetSystemPath"}
                and type(receipt["schema"]) is int and receipt["schema"] == 1 and receipt["reviewed"] is True
                and commit(receipt["controlTree"]) and receipt["controlCommit"] == version["configurationRevision"]
                and type(receipt["controlCommit"]) is str and receipt["targetSystemPath"] == target
                and type(receipt["targetSystemPath"]) is str and type(receipt["policyHash"]) is str
                and type(receipt["targetSystemNarHash"]) is str and 1 <= len(receipt["targetSystemNarHash"]) <= 512)
        stage = "artifacts"
        for name, mode, size, expected in ((BROKER, 0o555, 483712, P4.BROKER_SHA256),
            (POLICY, 0o444, 1617, P4.POLICY_SHA256)):
            file_value(observe("file", name), uid=0, mode=mode, size=size, digest=expected)
        # Ordinary-user metadata only. Root's typed doctor attests content; no
        # read of the root:wheel0440 sudoers or root0400 installation record.
        sudoers_metadata(observe("metadata", SUDOERS))
        directories = {name: observe("directory", location) for name, location in DIRECTORIES.items()}
        for value in directories.values():
            require(exact(value, {"gid": 0, "kind": "directory", "mode": 0o700, "symlink": False, "uid": 0}))
        require(all(observe("absent", p) is True for p in EMERGENCY))
        stage = "root-health"
        root = command(("/usr/bin/sudo", "-n", BROKER, "doctor-root", "--json"))
        unknown = command(("/usr/bin/sudo", "-n", BROKER, "unknown"), maximum=4096, codes=(64,))
        generic = command(("/usr/bin/sudo", "-n", "/usr/bin/true"), maximum=4096, codes=tuple(range(1, 256)))
        validate = command(("/usr/bin/sudo", "-n", "-v"), maximum=4096, codes=tuple(range(1, 256)))
        command_facts = snapshot(P4.current_main_command_facts(root, unknown, generic, validate))
        expected_root = {"checks": {"emergency_disable_absent": True, "installed_artifact_attestation": True,
            "installed_contract": True, "policy_hash": True}, "command": "doctor-root", "problems": [],
            "readOnly": True, "schema": 1, "systemMutationsPerformed": False, "verdict": "ROOT_CONTRACT_READY"}
        require(exact(parse(root.stdout.encode()), expected_root))
        stage = "generation"
        nar = command(("/nix/var/nix/profiles/default/bin/nix-store", "--query", "--hash", target), maximum=4096).stdout.strip()
        processes = command(("/bin/ps", "-axo", "comm="), maximum=1024 * 1024).stdout
        targets = current["targets"]
        facts = {"artifacts": {"broker": True, "policy": True, "sudoers": True}, "directories": directories,
            "emergencyEnabled": True, "genericSudoDenied": command_facts["genericSudoDenied"],
            "historicalTargets": {"generation2PathSHA256": sha(targets[2]["path"].encode()),
                                  "generation3PathSHA256": sha(targets[3]["path"].encode())},
            "narHash": nar, "phase2Accepted": historical2, "phase3Accepted": historical3,
            "processes": P4.current_main_process_names(processes), "profileTarget": target, "receipt": receipt,
            "receiptFile": {"kind": "file", "mode": 0o400, "nlink": 1, "owner": "caller", "sizeBounded": True, "symlink": False},
            "rootDoctor": command_facts["rootDoctor"],
            "target": next(row for row in targets.values() if row["path"] == target), "targets": targets,
            "unknownCommandDenied": command_facts["unknownCommandDenied"],
            "versionFile": current["versionFile"], "versionLink": current["versionLink"], "versionValue": version}
        outcome.facts = snapshot(facts)
        stage = "validation"
        settled = False  # P4's exact validator also uses the injected Git runner
        checked = P4.validate_current_main_facts(facts, P4.ROOT, runner_route=False)
        settled = True
        require(type(checked) is dict and checked.get("result") == "pass"
                and type(checked.get("caseCount")) is int and checked["caseCount"] == 15
                and exact(facts, outcome.facts))
        complete = True
    except BaseException as error:
        failure(error)
    finally:
        stage = "final-recheck"
        if admitted:
            post_ok = True
            for kind, arguments, expected in outcome.observations:
                try:
                    require(exact(snapshot(getattr(io, kind)(*arguments)), expected))
                except BaseException as error:
                    post_ok = False
                    failure(error)
            try:
                require(recheck() is True)
                if settled:
                    require(git("rev-parse", "HEAD") == BASE and git("branch", "--show-current") == "main"
                            and git("status", "--porcelain=v1", "--untracked-files=all") == "")
                stable = post_ok
            except BaseException as error:
                failure(error)
        try:
            budget.check()
        except BaseException as error:
            failure(error)
    outcome.public = public(complete=complete and outcome.primary is None, historical2=historical2,
        historical3=historical3, stable=stable, settled=settled, stage=failure_stage)
    if outcome.primary is not None:
        if isinstance(outcome.primary, (KeyboardInterrupt, SystemExit)):
            outcome.primary.phase4_health_outcome = outcome
            outcome.primary.private_owner = outcome.private_owner
            outcome.primary.settlement_failed = not settled
            raise outcome.primary from None
        raise HealthError(outcome) from None
    return outcome.public
