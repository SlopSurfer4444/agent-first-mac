"""One fixed owner guidance target; no generic skill/config or root writer.

Reuse the accepted descriptor, durable record and atomic exchange primitives.
Custody is cooperative same-user safety, not a hostile same-user sandbox.
"""
import argparse
import fcntl
import os
from pathlib import Path
import pwd
import stat
from lib import harness_offramp as H

ROOT = Path(__file__).resolve().parents[1]
TARGET = (".codex", "skills", "manage-workstation")
NAME = "SKILL.md"
STAGE = ".workstation-guidance-owner-first-v1"
STATE = ("AIDev", "state", "workstation-guidance-delivery")
OPERATION = "owner-first-v1"
PREIMAGE = "0c7da6b0f97d96d15d9c982440cfd56a415c38329f4d2d5b3dc431d6a16cd8e5"
POSTIMAGE = "0ce75fb90e30b2e7fc75be98756f29671e7054c46d0667dfb413a7a8c661d59c"
RECORDS = {"prestate.json", "before", "after", "intent.json", "rollback.json"}
ACTIONS = ("plan", "status", "apply", "recover", "rollback")


def source():
    manifest = H.parse((ROOT / "manifests/workstation-guidance-delivery.json").read_bytes())
    expected = {"schema": 1, "owner": "control", "scope": "owner-first-manage-workstation-guidance",
        "source": "skills/manage-workstation/SKILL.md", "target": "$HOME/.codex/skills/manage-workstation/SKILL.md",
        "preimageSha256": PREIMAGE, "postimageSha256": POSTIMAGE, "mode": "0600",
        "recoverySuffix": "/".join(STATE + (OPERATION,)),
        "readiness": "fresh-full-current-doctor-PASS-then-held-source",
        "operation": "one-fixed-guidance-file-atomic-exchange",
        "recovery": "Exact recorded inodes and images only; retain unknown state without inverse."}
    H.require(H.wire(manifest) == H.wire(expected), "guidance_manifest")
    raw = (ROOT / expected["source"]).read_bytes()
    H.require(0 < len(raw) <= H.LIMIT and H.digest(raw) == POSTIMAGE, "guidance_source")
    return manifest, raw


def read(directory, name):
    raw, identity = H.read_at(directory, name, True)
    # Exchange changes ctime; inode, owner, group, mode, links, size and mtime
    # remain identity-bound, alongside exact content.
    return raw, list(identity[:8])


def record(directory, name):
    return H.parse(read(directory, name)[0])


def stamp(value):
    H.require(type(value) is list and len(value) == 8 and all(type(v) is int for v in value), "record_identity")


def execute(home, action, *, admission, source_guard=lambda: True, checkpoint=lambda _: None):
    H.require(action in ACTIONS, "action")
    manifest, after = source()
    dirs = []
    try:
        target = H.Directory(home, TARGET); dirs.append(target)
        before, before_id = read(target, NAME)
        digest = H.digest(before)
        def report(status):
            return {"schema": 1, "status": status, "scope": "one-managed-guidance-file",
                "recoveryMaterialRemoved": False, "nativeTrustChanged": False, "rootOperationsPerformed": False,
                "otherSkillsChanged": False, "futureSessionDiscoveryProven": False}
        observed = "PREDECESSOR" if digest == manifest["preimageSha256"] else \
            "SUCCESSOR_BYTES_UNVERIFIED" if before == after else "UNKNOWN"
        if action == "plan":
            return report(observed)
        mutable = action not in ("plan", "status")
        if mutable:
            H.require(callable(admission) and source_guard() is True, "source_guard_required")
            H.require(observed != "UNKNOWN", "unknown_target")
        try:
            custody = H.Directory(home, STATE, create=action == "apply" and observed == "PREDECESSOR")
        except FileNotFoundError:
            if action == "status": return report(observed)
            raise H.OfframpError("missing_recovery") from None
        dirs.append(custody)
        H.require(stat.S_IMODE(os.fstat(custody.fd).st_mode) == 0o700, "private_state_mode")
        fcntl.flock(custody.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            recovery = H.Directory(home, STATE + (OPERATION,), create=action == "apply" and observed == "PREDECESSOR")
        except FileNotFoundError:
            if action == "status": return report(observed)
            raise H.OfframpError("missing_recovery") from None
        dirs.append(recovery)
        H.require(stat.S_IMODE(os.fstat(recovery.fd).st_mode) == 0o700, "private_recovery_mode")

        def guard():
            for d in dirs: d.verify()
            H.require(source_guard() is True and source() == (manifest, after), "source_drift")
            H.require(set(os.listdir(recovery.fd)) <= RECORDS, "unknown_recovery_material")
            return True

        def validate_prestate():
            value = record(recovery, "prestate.json")
            H.require(type(value) is dict and set(value) == {"schema", "before", "preimageSha256", "postimageSha256"}
                and type(value["schema"]) is int and value["schema"] == 1
                and value["preimageSha256"] == manifest["preimageSha256"]
                and value["postimageSha256"] == manifest["postimageSha256"], "prestate_record")
            stamp(value["before"])
            return value

        def validate_intent():
            prestate = validate_prestate()
            value = record(recovery, "intent.json")
            H.require(type(value) is dict and set(value) == {"schema", "before", "after", "stage"}
                and type(value["schema"]) is int and value["schema"] == 1
                and value["before"] == prestate["before"] and value["stage"] == STAGE, "intent_record")
            stamp(value["before"]); stamp(value["after"])
            old = read(recovery, "before")[0]
            H.require(H.digest(old) == manifest["preimageSha256"]
                and read(recovery, "after")[0] == after, "backup_drift")
            return value, old

        def position(intent, old):
            current = read(target, NAME); staged = read(target, STAGE)
            if (current, staged) == ((old, intent["before"]), (after, intent["after"])): return 0
            if (current, staged) == ((after, intent["after"]), (old, intent["before"])): return 1
            raise H.OfframpError("unknown_target_or_displaced")

        def reverse_recorded():
            if "rollback.json" not in os.listdir(recovery.fd): return False
            value = record(recovery, "rollback.json")
            H.require(H.wire(value) == H.wire({"schema": 1, "direction": "rollback"}), "rollback_record")
            return True

        if action == "status":
            guard()
            if "intent.json" not in os.listdir(recovery.fd):
                return report("PREPARATION_INCOMPLETE")
            intent, old = validate_intent()
            pos = position(intent, old); reverse = reverse_recorded()
            guard()
            return report("ROLLED_BACK" if reverse and pos == 0 else
                "INSTALLED" if not reverse and pos == 1 else "RECOVERY_REQUIRED")

        def work():
            guard()
            if "prestate.json" not in os.listdir(recovery.fd):
                H.require(action == "apply" and not os.listdir(recovery.fd), "unknown_preparation")
                H.require(read(target, NAME) == (before, before_id)
                    and digest == manifest["preimageSha256"], "unknown_predecessor")
                H.require(not H.has_file(target, STAGE), "unknown_stage")
                H.write_record(recovery, "prestate.json", H.wire({"schema": 1, "before": before_id,
                    "preimageSha256": manifest["preimageSha256"], "postimageSha256": manifest["postimageSha256"]}))
                checkpoint("prestate-recorded")
            prestate = validate_prestate()
            if "intent.json" not in os.listdir(recovery.fd):
                H.require(not reverse_recorded(), "rollback_without_intent")
                current, ident = read(target, NAME)
                H.require(ident == prestate["before"] and H.digest(current) == manifest["preimageSha256"], "preparation_target_drift")
                for name, raw in (("before", current), ("after", after)):
                    guard()
                    if name not in os.listdir(recovery.fd): H.write_record(recovery, name, raw)
                    H.require(read(recovery, name)[0] == raw, "backup_drift")
                    checkpoint(name + "-recorded")
                guard()
                # Without the published intent an existing stage has no bound
                # inode identity. Even matching bytes cannot establish custody.
                H.require(not H.has_file(target, STAGE), "unbound_stage_retained")
                H.write_new(target, STAGE, after, 0o600)
                staged, stage_id = read(target, STAGE)
                H.require(staged == after and read(target, NAME) == (current, ident), "stage_or_target_drift")
                checkpoint("staged")
                H.write_record(recovery, "intent.json", H.wire({"schema": 1, "before": ident, "after": stage_id, "stage": STAGE}))
                checkpoint("prepared")
            intent, old = validate_intent()
            pos = position(intent, old)
            reverse = reverse_recorded()
            H.require(not (reverse and action == "apply"), "rollback_already_recorded")
            if action == "rollback" and not reverse:
                guard(); position(intent, old)
                H.write_record(recovery, "rollback.json", H.wire({"schema": 1, "direction": "rollback"}))
                reverse = True
                checkpoint("rollback-recorded")
            desired = 0 if reverse else 1
            guard(); pos = position(intent, old)
            changed = pos != desired
            if changed:
                H.swap(target, STAGE, NAME)
            # A prior exchange/record can be visible after its fsync failed.
            # Known-state recovery re-establishes durability even on a no-op.
            os.fsync(target.fd)
            if changed:
                checkpoint("restored" if reverse else "published")
            H.require(position(intent, old) == desired, "publication_unverified")
            os.fsync(recovery.fd)
            os.fsync(custody.fd)
            guard()
            return report("ROLLED_BACK" if reverse else "INSTALLED" if changed else "UNCHANGED")
        return admission(work, guard)
    finally:
        for d in reversed(dirs): d.close()


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=ACTIONS)
    args = parser.parse_args(arguments)
    try:
        home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        H.require(os.getuid() > 0 and ROOT == home / "AIDev/control" and Path.cwd() == ROOT, "canonical_source_required")
        from lib.workstation_maintenance_delivery import admitted_source
        if args.action in ("plan", "status"):
            result = execute(home, args.action, admission=None)
        else:
            admitted_source(ROOT, full=True)
            results = []
            def run(head, *, source_guard):
                H.require(source_guard() is True, "source_drift")
                def admission(work, guard):
                    H.require(source_guard() is True and guard(), "source_drift")
                    value = work()
                    H.require(source_guard() is True and guard(), "source_drift")
                    return value
                results.append(execute(home, args.action, admission=admission, source_guard=source_guard))
                H.require(source_guard() is True, "source_drift")
                return True
            admitted_source(ROOT, full=False, operation_check=run)
            H.require(len(results) == 1, "source_unadmitted")
            result = results[0]
        print(H.wire(result).decode()); return 0
    except Exception as error:
        print(H.wire({"schema": 1, "status": "REFUSED", "reason": str(error) if isinstance(error, H.OfframpError)
            else "guidance_unavailable", "unknownStateRetained": True}).decode())
        return 1
