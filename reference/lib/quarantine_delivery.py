"""Fixed two-file quarantine delivery, with recoverable fail-closed ordering.

No native trust/config.json, model, root, application or arbitrary target writes.
Cooperative same-user custody, not a security boundary against code replacement.
"""
import argparse
import fcntl
import os
from pathlib import Path
import pwd
import re
import stat
import sys
sys.dont_write_bytecode = True
from lib import harness_offramp as H

ROOT = Path(__file__).resolve().parents[1]
STATE = ("AIDev", "state", "quarantine-delivery")
ROWS = (
    ("launcher", ("AIDev", "bin"), "codex-quarantine", 0o700,
     "bin/codex-quarantine", "tests/fixtures/phase5-quarantine-before-current-cli.zsh"),
    ("profile", (".codex",), "quarantine.config.toml", 0o600,
     "codex/quarantine.config.toml", "tests/fixtures/phase5-quarantine-before-temp-deny.config.toml"),
)

def read(directory, name, mode):
    directory.verify()
    fd = os.open(name, H.FILE_FLAGS, dir_fd=directory.fd)
    try:
        s = os.fstat(fd)
        H.require(stat.S_ISREG(s.st_mode) and s.st_uid == os.getuid()
                  and s.st_nlink == 1 and stat.S_IMODE(s.st_mode) == mode
                  and 0 < s.st_size < 65536, "target_metadata")
        raw = os.read(fd, 65536)
        H.require(len(raw) == s.st_size and H.identity(os.fstat(fd)) == H.identity(s)
                  == H.identity(os.stat(name, dir_fd=directory.fd, follow_symlinks=False)), "target_drift")
        directory.verify()
        return raw, list(H.identity(s)[:8])
    finally:
        os.close(fd)

def sources():
    manifest = H.parse((ROOT / "manifests/quarantine-boundary-successor.json").read_bytes())
    values = {}
    for key, _, _, _, current, previous in ROWS:
        old, new = (ROOT / previous).read_bytes(), (ROOT / current).read_bytes()
        H.require(H.digest(old) == manifest["predecessor"][key + "Sha256"], "predecessor_source")
        row = next(row for row in manifest["deliverySet"] if row["source"] == current)
        H.require(H.digest(new) == row["sha256"], "successor_source")
        values[key] = (old, new)
    return values

def record(directory, name):
    return H.parse(H.read_at(directory, name, True)[0])

def execute(home, action, operation, *, admission, checkpoint=lambda _: None, source_guard=lambda: True):
    H.require(action in ("plan", "status", "apply", "recover", "rollback"), "action")
    H.require(type(operation) is str and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,47}", operation) is not None, "operation")
    images = sources()
    dirs = []; targets = {}
    try:
        for key, relative, name, mode, *_ in ROWS:
            d = H.Directory(home, relative); dirs.append(d)
            targets[key] = (d, name, mode)
        def observe():
            return {key: read(d, name, mode) for key, (d, name, mode) in targets.items()}
        def report(status):
            return {"schema": 1, "status": status, "nativeTrustChanged": False,
                    "installedStackProven": False, "recoveryRetained": True}
        pre = observe()
        if action in ("plan", "status"):
            # Read-only does not create private directories or claim ownership.
            kind = "PREDECESSOR" if all(pre[k][0] == images[k][0] for k in images) else \
                "SUCCESSOR_BYTES_UNVERIFIED" if all(pre[k][0] == images[k][1] for k in images) else "MIXED_OR_UNKNOWN"
            return report(kind)
        custody = H.Directory(home, STATE, create=True); dirs.append(custody)
        H.require(stat.S_IMODE(os.fstat(custody.fd).st_mode) == 0o700, "private_state_mode")
        fcntl.flock(custody.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        recovery = H.Directory(home, STATE + (operation,), create=action == "apply"); dirs.append(recovery)
        H.require(stat.S_IMODE(os.fstat(recovery.fd).st_mode) == 0o700, "private_recovery_mode")
        def guard():
            for d in dirs: d.verify()
            H.require(source_guard() is True, "source_drift")
            return True
        def work():
            guard()
            exists = H.has_file(recovery, "intent.json")
            if not exists:
                H.require(action == "apply", "missing_intent")
                H.require(observe() == pre, "prestate_drift")
                H.require(all(pre[k][0] == images[k][0] for k in images), "unknown_predecessor")
                prepared = {}
                for key, (d, name, mode) in targets.items():
                    guard()
                    stage = ".quarantine-delivery-" + operation + "-" + key
                    H.write_new(d, stage, images[key][1], mode)
                    raw, ident = read(d, stage, mode)
                    H.require(raw == images[key][1], "stage_drift")
                    H.write_record(recovery, key + "-before", images[key][0])
                    H.write_record(recovery, key + "-after", images[key][1])
                    prepared[key] = {"before": pre[key][1], "after": ident, "stage": stage}
                H.require(observe() == pre, "prestate_drift")
                H.write_record(recovery, "intent.json", H.wire({"schema": 1, "targets": prepared}))
                checkpoint("prepared")
            intent = record(recovery, "intent.json")
            H.require(type(intent) is dict and set(intent) == {"schema", "targets"}
                      and type(intent["schema"]) is int and intent["schema"] == 1
                      and type(intent["targets"]) is dict and set(intent["targets"]) == set(images), "intent")
            for key in images:
                row = intent["targets"][key]
                H.require(type(row) is dict and set(row) == {"before", "after", "stage"}
                    and row["stage"] == ".quarantine-delivery-" + operation + "-" + key
                    and all(type(row[n]) is list and len(row[n]) == 8
                        and all(type(v) is int for v in row[n]) for n in ("before", "after")), "intent")
                for i, suffix in enumerate(("before", "after")):
                    H.require(H.read_at(recovery, key + "-" + suffix, True)[0] == images[key][i], "image_drift")
            reverse = H.has_file(recovery, "rollback.json")
            if reverse:
                H.require(record(recovery, "rollback.json") == {"schema": 1, "direction": "rollback"}, "rollback_intent")
                H.require(action != "apply", "rollback_recorded_use_new_operation")
            if action == "rollback" and not reverse:
                # Bind rollback direction durably before the first reversed exchange.
                H.write_record(recovery, "rollback.json", H.wire({"schema": 1, "direction": "rollback"}))
                reverse = True
                checkpoint("rollback-recorded")
            def position(key):
                d, name, mode = targets[key]; row = intent["targets"][key]
                current, ident = read(d, name, mode)
                staged, sid = read(d, row["stage"], mode)
                old, new = images[key]
                if (current, ident, staged, sid) == (old, row["before"], new, row["after"]): return 0
                if (current, ident, staged, sid) == (new, row["after"], old, row["before"]): return 1
                raise H.OfframpError("unknown_displaced_or_target")
            positions = {k: position(k) for k in images}
            # New launcher first: it rejects old profile. Rollback profile first:
            # the new launcher refuses until the old launcher is restored last.
            H.require(not (positions["launcher"] == 0 and positions["profile"] == 1), "unsafe_pair_state")
            desired = 0 if reverse else 1
            order = ("profile", "launcher") if reverse else ("launcher", "profile")
            for key in order:
                guard()
                for other in images: position(other)
                if position(key) != desired:
                    d, name, _ = targets[key]
                    H.swap(d, intent["targets"][key]["stage"], name)
                    os.fsync(d.fd)
                    checkpoint(key + ("-restored" if reverse else "-published"))
                    H.require(position(key) == desired, "publication_unverified")
            H.require(all(position(k) == desired for k in images), "pair_unverified")
            guard()
            return report("ROLLED_BACK" if reverse else "INSTALLED")
        return admission(work, guard)
    finally:
        for d in reversed(dirs): d.close()

def main(arguments=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=("plan", "status", "apply", "recover", "rollback"))
    p.add_argument("--operation", default="owner-first-quarantine")
    args = p.parse_args(arguments)
    try:
        home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        H.require(ROOT == home / "AIDev/control" and Path.cwd() == ROOT, "canonical_source_required")
        from lib.workstation_maintenance_delivery import admitted_source
        if args.action in ("plan", "status"):
            result = execute(home, args.action, args.operation, admission=None)
        else:
            # Before even creating recovery directories, require full readiness.
            # Keep accepted source held across preparation and all publication.
            admitted_source(ROOT, full=True)
            result = []
            def run(head, *, source_guard):
                def admission(work, guard):
                    H.require(source_guard() is True and guard(), "source_drift")
                    value = work()
                    H.require(source_guard() is True and guard(), "source_drift")
                    return value
                H.require(source_guard() is True, "source_drift")
                result.append(execute(home, args.action, args.operation, admission=admission, source_guard=source_guard))
                H.require(source_guard() is True, "source_drift")
                return True
            admitted_source(ROOT, full=False, operation_check=run)
            H.require(len(result) == 1, "source_unadmitted")
            result = result[0]
        print(H.wire(result).decode()); return 0
    except Exception as e:
        print(H.wire({"schema": 1, "status": "REFUSED", "reason": str(e) if isinstance(e, H.OfframpError) else "operation_unavailable"}).decode())
        return 1
