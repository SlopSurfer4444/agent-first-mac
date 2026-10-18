"""Exact-owned hook retirement and reversible user-hook off-ramp.

Private images stay in owner-private recovery storage. No config.toml, native
trust, applications, profiles, Nix generations or root policy are written.
Exact-owned passive skill/link objects may be moved recoverably. The fixture
adapter is deliberately independent of a machine doctor; the live adapter
requires canonical admitted source and affected target/recovery observations.
Independent protected-policy acceptance and native permissions remain separate.
"""
import argparse
import sys
sys.dont_write_bytecode = True
import ctypes
from dataclasses import dataclass
import fcntl
import hashlib
import importlib.machinery
import json
import os
from pathlib import Path
import secrets
import stat
import tempfile
import re

LIMIT = 256 * 1024
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
RECOVERY = ("AIDev", "state", "harness-offramp")
RETIRED = ("legacyPreToolUse", "legacyStop", "staticSessionStart")
ACTIONS = ("retire", "disable", "remove")
ROOT = Path(__file__).resolve().parents[1]
RETAINED_SCOPE = ("historical-evidence", "private-recovery", "applications", "game-data",
                  "profiles", "credentials", "native-trust", "owner-global-guidance",
                  "nix-profiles-and-store", "skill-companion-metadata")
RESIDUAL_SCOPE = ("owner-authenticated-root-disable", "typed-root-binary-removal",
                  "home-manager-source-retirement")
_legacy = importlib.machinery.SourceFileLoader(
    "harness_json", str(ROOT / "bin/aid-sessionstart")).load_module()


class OfframpError(ValueError):
    """A bounded reason; never include private paths or hook bodies."""


def require(condition, reason="offramp_refused"):
    if condition is not True:
        raise OfframpError(reason)


def parse(raw):
    try:
        return _legacy.parse_json(raw)
    except Exception:
        raise OfframpError("json_refused") from None


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      allow_nan=False, ensure_ascii=True).encode("ascii")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def definitions(manifest, historical):
    require(type(manifest) is dict and set(manifest) == {
        "schema", "owner", "scope", "historicalManifestSha256", "definitions", "passive"})
    require(type(manifest["schema"]) is int and manifest["schema"] == 1
            and manifest["owner"] == "control"
            and manifest["scope"] == "exact-owned-harness-hooks")
    require(type(historical) is bytes
            and digest(historical) == manifest["historicalManifestSha256"],
            "historical_manifest_drift")
    static = parse(historical)
    _legacy._definition(static)
    result = manifest["definitions"]
    require(type(result) is dict and set(result) == {
        "legacyPreToolUse", "legacyStop", "dynamicSessionStart"})
    expected = {
        "legacyPreToolUse": ("PreToolUse", "warn", 5, "Checking workstation routing", "^Bash$"),
        "legacyStop": ("Stop", "verify", 15, "Checking control handoff", None),
        "dynamicSessionStart": ("SessionStart", "context", 10,
                                "Routing workstation contract", "startup|resume|clear|compact"),
    }
    detached = {}
    for name, (event, mode, timeout, status, matcher) in expected.items():
        group = {"hooks": [{"type": "command", "command":
                 '/usr/bin/python3 "$HOME/AIDev/control/codex/hooks/phase5-contract.py" ' + mode,
                 "timeout": timeout, "statusMessage": status}]}
        if matcher is not None:
            group["matcher"] = matcher
        require(wire(result[name]) == wire({"event": event, "definition": group}),
                "owned_definition_source_drift")
        detached[name] = (event, group)
    detached["staticSessionStart"] = ("SessionStart", static["definition"])
    return detached


def spans(raw):
    """Lexical intervals after strict bounded parsing; never reserialize input."""
    parse(raw)
    result = {}
    def space(i):
        while i < len(raw) and raw[i] in b" \t\r\n":
            i += 1
        return i
    def string(i):
        i += 1
        while raw[i] != 34:
            i += 2 if raw[i] == 92 else 1
        return i + 1
    def walk(i, path):
        i = space(i)
        start = i
        if raw[i] == 34:
            return string(i)
        if raw[i] == 123:
            i = space(i + 1)
            while raw[i] != 125:
                end = string(i)
                key = json.loads(raw[i:end])
                i = space(walk(space(end) + 1, path + (key,)))
                if raw[i] != 44:
                    break
                i = space(i + 1)
            return i + 1
        if raw[i] == 91:
            i = space(i + 1)
            items, commas = [], []
            while raw[i] != 93:
                begin = i
                end = walk(i, path + (len(items),))
                items.append((begin, end))
                i = space(end)
                if raw[i] != 44:
                    break
                commas.append(i)
                i = space(i + 1)
            result[path] = (start, i + 1, items, commas)
            return i + 1
        while i < len(raw) and raw[i] not in b" \t\r\n,]}":
            i += 1
        return i
    walk(0, ())
    return result


def replace_spans(raw, edits):
    cursor, chunks = 0, []
    for start, end, value in sorted(edits):
        require(cursor <= start <= end <= len(raw), "span_overlap")
        chunks.extend((raw[cursor:start], value))
        cursor = end
    chunks.append(raw[cursor:])
    return b"".join(chunks)


def owned_like(group, defs):
    statuses = {g["hooks"][0]["statusMessage"] for _, g in defs.values()}
    commands = {g["hooks"][0]["command"] for _, g in defs.values()}
    pending = [group]
    while pending:
        item = pending.pop()
        if type(item) is dict:
            if type(item.get("statusMessage")) is str and item["statusMessage"] in statuses:
                return True
            command = item.get("command")
            if type(command) is str and (command in commands or "phase5-contract.py" in command):
                return True
            if any(item.get(k) == "vendor-sentinel-sessionstart-context"
                   for k in ("id", "item_id", "itemId")):
                return True
            pending.extend(item.values())
        elif type(item) is list:
            pending.extend(item)
    return False


@dataclass(frozen=True, repr=False)
class HookPlan:
    action: str
    before: bytes
    after: bytes
    events: tuple
    removed: int

    def __repr__(self):
        return "<private harness hook plan>"

    def public_report(self):
        return {"schema": 1, "status": "PLANNED" if self.removed else "NOOP",
                "action": self.action, "removedGroups": self.removed,
                "nativeTrustChanged": False, "payloadsChanged": False,
                "rootState": "SEPARATE_OWNER_AUTHENTICATED_HANDOFF"}


def build_plan(before, manifest, historical, action="retire"):
    require(action in ACTIONS, "action_refused")
    defs = definitions(manifest, historical)
    selected = set(RETIRED if action == "retire" else defs)
    value = parse(before)
    require(type(value) is dict and type(value.get("hooks")) is dict, "hook_shape")
    locations, counts, edits, events = spans(before), {}, [], []
    expected = parse(before)
    for event, groups in value["hooks"].items():
        require(type(groups) is list and all(type(g) is dict for g in groups), "hook_shape")
        removed = set()
        for index, group in enumerate(groups):
            matches = [name for name, (e, d) in defs.items()
                       if event == e and wire(group) == wire(d)]
            if matches:
                name = matches[0]
                counts[name] = counts.get(name, 0) + 1
                require(counts[name] == 1, "owned_definition_duplicate")
                if name in selected:
                    removed.add(index)
            elif owned_like(group, defs):
                raise OfframpError("owned_definition_unknown")
        if not removed:
            continue
        events.append(event)
        _, _, items, commas = locations[("hooks", event)]
        retained = [i for i in range(len(groups)) if i not in removed]
        # Keep one existing separator for each adjacent pair of survivors.
        kept_commas = {commas[a] for a, _ in zip(retained, retained[1:])}
        edits.extend((a, b, b"") for i, (a, b) in enumerate(items) if i in removed)
        edits.extend((c, c + 1, b"") for c in commas if c not in kept_commas)
        expected["hooks"][event] = [g for i, g in enumerate(groups) if i not in removed]
    after = replace_spans(before, edits)
    require(parse(after) == expected, "postimage_invalid")
    return HookPlan(action, before, after, tuple(events), sum(
        counts.get(name, 0) for name in selected))


def restore_plan(current, plan):
    """Restore exact event-array preimages, preserving all other current bytes.

    Concurrent changes in an affected event array refuse restoration. Never
    restore a whole historical config or its native trust records.
    """
    require(type(plan) is HookPlan, "recovery_plan")
    now, before, after = spans(current), spans(plan.before), spans(plan.after)
    edits = []
    for event in plan.events:
        key = ("hooks", event)
        require(key in now, "recovery_affected_drift")
        a, b, *_ = now[key]
        x, y, *_ = after[key]
        u, v, *_ = before[key]
        require(current[a:b] in (plan.after[x:y], plan.before[u:v]), "recovery_affected_drift")
        if current[a:b] != plan.before[u:v]:
            edits.append((a, b, plan.before[u:v]))
    result = replace_spans(current, edits)
    parse(result)
    return result


def identity(facts):
    return (facts.st_dev, facts.st_ino, facts.st_uid, facts.st_gid, facts.st_mode,
            facts.st_nlink, facts.st_size, facts.st_mtime_ns, facts.st_ctime_ns)


def dir_identity(facts):
    return (facts.st_dev, facts.st_ino, facts.st_uid, facts.st_gid, facts.st_mode)


class Directory:
    def __init__(self, home, relative, create=False):
        self.entries = []
        home = Path(home)
        require(home.is_absolute() and home == home.resolve(strict=True), "home_path")
        try:
            fd = os.open("/", DIR_FLAGS)
            self.entries.append((fd, "/", dir_identity(os.fstat(fd))))
            parts = home.parts[1:] + tuple(relative)
            for depth, name in enumerate(parts, 1):
                self.verify()
                if create and depth > len(home.parts) - 1:
                    try:
                        os.mkdir(name, 0o700, dir_fd=self.fd)
                        os.fsync(self.fd)
                    except FileExistsError:
                        pass
                child = os.open(name, DIR_FLAGS, dir_fd=self.fd)
                facts = os.fstat(child)
                self.entries.append((child, name, dir_identity(facts)))
                if depth >= len(home.parts) - 1:
                    require(facts.st_uid == os.getuid() and
                            stat.S_IMODE(facts.st_mode) in (0o700, 0o750, 0o755),
                            "directory_metadata")
            self.verify()
        except Exception:
            self.close()
            raise

    @property
    def fd(self):
        return self.entries[-1][0]

    def verify(self):
        for i, (fd, name, expected) in enumerate(self.entries):
            require(dir_identity(os.fstat(fd)) == expected, "directory_drift")
            named = os.stat(name if i else "/", dir_fd=self.entries[i - 1][0] if i else None,
                            follow_symlinks=False)
            require(dir_identity(named) == expected, "directory_drift")

    def close(self):
        while self.entries:
            os.close(self.entries.pop()[0])


def read_at(directory, name, private=False, *, allow_empty=False):
    directory.verify()
    fd = os.open(name, FILE_FLAGS, dir_fd=directory.fd)
    try:
        facts = os.fstat(fd)
        require(stat.S_ISREG(facts.st_mode) and facts.st_uid == os.getuid()
                and facts.st_nlink == 1 and (0 if allow_empty else 1) <= facts.st_size <= LIMIT
                and stat.S_IMODE(facts.st_mode) in ((0o600,) if private else (0o600, 0o644)),
                "file_metadata")
        raw = os.read(fd, LIMIT + 1)
        require(len(raw) == facts.st_size, "file_read")
        require(identity(os.fstat(fd)) == identity(facts)
                == identity(os.stat(name, dir_fd=directory.fd, follow_symlinks=False)),
                "file_drift")
        directory.verify()
        return raw, identity(facts)
    finally:
        os.close(fd)


def native_snapshot(directory):
    """Observe optional native configuration without creating or parsing it.

    Absent and empty files are valid owner states, not missing permission.
    Unsafe objects and changes during a read remain refusals.
    """
    if not has_file(directory, "config.toml"):
        directory.verify()
        return None
    return read_at(directory, "config.toml", allow_empty=True)


def write_new(directory, name, raw, mode=0o600):
    directory.verify()
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 mode, dir_fd=directory.fd)
    try:
        os.fchmod(fd, mode)
        view = memoryview(raw)
        while view:
            n = os.write(fd, view)
            require(n > 0, "file_write")
            view = view[n:]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.fsync(directory.fd)
    directory.verify()


def rename(directory, left, right, flag):
    # macOS atomic exchange retains the displaced inode until verified. No
    # stat-then-overwrite fallback is allowed on unsupported platforms.
    libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    function = libc.renameatx_np
    function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                         ctypes.c_char_p, ctypes.c_uint]
    function.restype = ctypes.c_int
    require(function(directory.fd, os.fsencode(left), directory.fd,
                     os.fsencode(right), flag) == 0, "atomic_rename_failed")


def swap(directory, left, right):
    rename(directory, left, right, 2)


def write_record(directory, name, raw):
    """Publish a complete fsynced record atomically, never a partial final name.

    Interrupted preparation retains its private staging file; the authoritative
    active/publication name appears only after all bytes are durable. No replace
    and no unlink cleanup are allowed for ambiguous private staging objects.
    """
    stage = ".prepared-" + secrets.token_hex(16)
    write_new(directory, stage, raw)
    actual, stamp = read_at(directory, stage, True)
    require(actual == raw, "record_staging_drift")
    rename(directory, stage, name, 4)
    os.fsync(directory.fd)
    actual, installed = read_at(directory, name, True)
    require(actual == raw and installed[:8] == stamp[:8], "record_publication_drift")


PASSIVE_PATHS = {"aidLink": ("AIDev", "bin", "aid"),
                 "workstationSkill": (".codex", "skills", "manage-workstation", "SKILL.md")}


def passive_metadata(directory, name, kind):
    directory.verify()
    facts = os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
    require(facts.st_uid == os.getuid() and facts.st_nlink == 1, "passive_metadata")
    if kind == "link":
        require(stat.S_ISLNK(facts.st_mode), "passive_metadata")
        raw = os.fsencode(os.readlink(name, dir_fd=directory.fd))
        require(0 < len(raw) <= 4096, "passive_metadata")
        require(identity(os.stat(name, dir_fd=directory.fd, follow_symlinks=False)) == identity(facts),
                "passive_drift")
        return raw, identity(facts)
    return read_at(directory, name)


def passive_preflight(home, manifest, recovery=None, *, restore=False, link_witness=None,
                      operation="hooks"):
    """Unknown passive objects remain externally owned; never adopt by presence.

    A stable aid link is HomeManager-owned. Its exact private expected link text
    and an actual owning-source observation must be supplied together by that
    adapter; a pathname prefix or a caller Boolean is not a witness. Native live
    CLI has no invented witness and therefore retains that link explicitly.
    """
    source = manifest["passive"]
    require(type(source) is dict and set(source) == set(PASSIVE_PATHS), "passive_source")
    require(source["aidLink"] == {"target": "AIDev/bin/aid", "owner": "HomeManager",
        "ownership": "exact private link witness plus source-owner observation; unknown links retained"},
        "passive_source")
    skill = source["workstationSkill"]
    require(type(skill) is dict and set(skill) == {"target", "sha256"}
            and skill["target"] == ".codex/skills/manage-workstation/SKILL.md"
            and type(skill["sha256"]) is list and 1 <= len(skill["sha256"]) <= 8
            and all(type(h) is str and re.fullmatch(r"[0-9a-f]{64}", h) for h in skill["sha256"]),
            "passive_source")
    rows = []
    for identifier, relative in PASSIVE_PATHS.items():
        kind = "link" if identifier == "aidLink" else "file"
        stage = ".harness-offramp-" + (recovery.entries[-1][1] if recovery else operation) + "-" + identifier
        if restore:
            raw, _ = read_at(recovery, identifier + ".json", True)
            record = parse(raw)
            require(type(record) is dict and set(record) == {"schema", "status", "kind", "sha256"}
                    and type(record["schema"]) is int and record["schema"] == 1
                    and record["kind"] == kind and record["status"] in (
                        "OWNED", "ABSENT", "RETAINED_EXTERNAL"), "passive_recovery_record")
            status = record["status"]
            if status != "OWNED":
                rows.append({"id": identifier, "status": status, "kind": kind,
                             "stage": stage, "before": None, "stamp": None})
                continue
            directory = Directory(home, relative[:-1])
            try:
                try:
                    current, current_stamp = passive_metadata(directory, relative[-1], kind)
                except FileNotFoundError:
                    pass
                else:
                    require(digest(current) == record["sha256"], "passive_restore_collision")
                    try:
                        os.stat(stage, dir_fd=directory.fd, follow_symlinks=False)
                    except FileNotFoundError:
                        rows.append({"id": identifier, "status": "NOT_RETIRED", "kind": kind,
                                     "stage": stage, "before": current, "stamp": current_stamp})
                        continue
                    raise OfframpError("passive_restore_collision")
                original, stamp = passive_metadata(directory, stage, kind)
                require(digest(original) == record["sha256"], "passive_recovery_drift")
            finally:
                directory.close()
            rows.append({"id": identifier, "status": status, "kind": kind,
                         "stage": stage, "before": original, "stamp": stamp})
            continue
        status, original, stamp = "RETAINED_EXTERNAL", None, None
        try:
            directory = Directory(home, relative[:-1])
        except FileNotFoundError:
            status = "ABSENT"
        else:
            try:
                try:
                    original, stamp = passive_metadata(directory, relative[-1], kind)
                except FileNotFoundError:
                    status = "ABSENT"
                except OfframpError:
                    status = "RETAINED_EXTERNAL"
                else:
                    if kind == "file" and digest(original) in skill["sha256"]:
                        status = "OWNED"
                    elif kind == "link" and link_witness is not None:
                        require(type(link_witness) is tuple and len(link_witness) == 2
                                and type(link_witness[0]) is bytes and callable(link_witness[1]),
                                "link_witness")
                        if original == link_witness[0] and link_witness[1]() is True:
                            status = "OWNED"
            finally:
                directory.close()
        rows.append({"id": identifier, "status": status, "kind": kind,
                     "stage": stage, "before": original, "stamp": stamp,
                     "link_witness": link_witness if identifier == "aidLink" else None})
    return rows


def passive_apply(home, rows, recovery, *, restore=False):
    reports = []
    for row in rows:
        identifier, status, kind = row["id"], row["status"], row["kind"]
        if status == "OWNED":
            relative = PASSIVE_PATHS[identifier]
            directory = Directory(home, relative[:-1])
            try:
                name = row["stage"] if restore else relative[-1]
                raw, stamp = passive_metadata(directory, name, kind)
                require(raw == row["before"] and stamp == row["stamp"], "passive_preimage_drift")
                witness = row.get("link_witness")
                if witness is not None:
                    require(witness[1]() is True, "link_owner_drift")
                # Atomic no-replace move retains the actual inode beside its
                # original parent; no destructive unlink or recursive cleanup.
                destination = relative[-1] if restore else row["stage"]
                rename(directory, name, destination, 4)
                os.fsync(directory.fd)
                try:
                    raw, facts = passive_metadata(directory, destination, kind)
                    require(raw == row["before"] and facts[:8] == stamp[:8], "passive_postimage_drift")
                except Exception:
                    # If a source changed between observation and atomic move,
                    # put the actual displaced object back without replacing a
                    # concurrent third state. On collision both objects remain.
                    try:
                        rename(directory, destination, name, 4)
                        os.fsync(directory.fd)
                    except Exception:
                        pass
                    raise OfframpError("passive_recovery_required") from None
                status = "RESTORED" if restore else "RETIRED_RECOVERABLY"
            finally:
                directory.close()
        reports.append({"id": identifier, "status": status})
    return reports


def publish(directory, before, stamp, after, recovery, *, restoring=False,
            mutation_guard=None, before_publish=None, after_publish=None):
    stage = ".harness-offramp-" + secrets.token_hex(16)
    write_new(directory, stage, after, stat.S_IMODE(stamp[4]))
    staged, stage_stamp = read_at(directory, stage)
    require(staged == after, "staging_drift")
    intent = "restoration-publication.json" if restoring else "publication.json"
    verified = "restoration-verified.json" if restoring else "publication-verified.json"
    write_record(recovery, intent, wire({"schema": 1, "stage": stage,
        "beforeSha256": digest(before), "afterSha256": digest(after),
        "beforeIdentity": list(stamp), "stagedIdentity": list(stage_stamp)}))
    if before_publish:
        before_publish()
    require(mutation_guard is None or mutation_guard() is True, "custody_drift")
    current, current_stamp = read_at(directory, "hooks.json")
    require(current == before and current_stamp == stamp, "preimage_drift")
    directory.verify()
    swap(directory, stage, "hooks.json")
    os.fsync(directory.fd)
    try:
        displaced, displaced_stamp = read_at(directory, stage)
        # rename changes ctime; all other recorded identity/content remains.
        require(displaced == before and displaced_stamp[:8] == stamp[:8], "swap_preimage_drift")
        if after_publish:
            after_publish()
        installed, installed_stamp = read_at(directory, "hooks.json")
        require(installed == after and installed_stamp[:8] == stage_stamp[:8], "postimage_drift")
    except Exception:
        # Return displaced state only if our own exact inode still occupies the
        # target. An unrelated third state is never overwritten by rollback.
        try:
            current, facts = read_at(directory, "hooks.json")
            if current == after and facts[:8] == stage_stamp[:8]:
                swap(directory, stage, "hooks.json")
                os.fsync(directory.fd)
        except Exception:
            pass
        raise OfframpError("recovery_required") from None
    # Retain exact displaced preimage rather than stat/unlink a replaced name.
    # Private staging names are recovery-critical, not ordinary evidence.
    write_record(recovery, verified, wire({"schema": 1, "status": "VERIFIED"}))
    return stage


def has_file(directory, name):
    directory.verify()
    try:
        os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False


def interrupted_publication(target, recovery, plan):
    """Reconcile custody before trusting an initial planned preimage.

    Unknown displaced bytes remain bound to a durable private stage name and
    refuse stale restoration. Never turn an unverified exchange into success.
    """
    if not has_file(recovery, "publication.json"):
        return "PREPARED_NO_PUBLICATION"
    raw, _ = read_at(recovery, "publication.json", True)
    record = parse(raw)
    require(type(record) is dict and set(record) == {"schema", "stage", "beforeSha256",
            "afterSha256", "beforeIdentity", "stagedIdentity"}
            and type(record["schema"]) is int and record["schema"] == 1
            and type(record["stage"]) is str and re.fullmatch(
                r"\.harness-offramp-[0-9a-f]{32}", record["stage"]) is not None
            and record["beforeSha256"] == digest(plan.before)
            and record["afterSha256"] == digest(plan.after)
            and all(type(record[key]) is list and len(record[key]) == 9
                    and all(type(v) is int for v in record[key])
                    for key in ("beforeIdentity", "stagedIdentity")), "publication_record")
    displaced, stamp = read_at(target, record["stage"])
    if displaced == plan.after and stamp[:8] == tuple(record["stagedIdentity"][:8]):
        return "PUBLICATION_NOT_APPLIED"
    require(displaced == plan.before and stamp[:8] == tuple(record["beforeIdentity"][:8]),
            "publication_displaced_unknown_handoff")
    if has_file(recovery, "publication-verified.json"):
        marker, _ = read_at(recovery, "publication-verified.json", True)
        require(wire(parse(marker)) == wire({"schema": 1, "status": "VERIFIED"}), "publication_record")
        return "VERIFIED"
    return "UNVERIFIED_EXACT_PREIMAGE"


def interrupted_restoration(target, recovery):
    """Never hide an interrupted restore's displaced third state as success."""
    if not has_file(recovery, "restoration-publication.json"):
        return None
    raw, _ = read_at(recovery, "restoration-publication.json", True)
    record = parse(raw)
    require(type(record) is dict and set(record) == {"schema", "stage", "beforeSha256",
            "afterSha256", "beforeIdentity", "stagedIdentity"}
            and type(record["schema"]) is int and record["schema"] == 1
            and type(record["stage"]) is str and re.fullmatch(
                r"\.harness-offramp-[0-9a-f]{32}", record["stage"]) is not None
            and all(type(record[key]) is str and re.fullmatch(r"[0-9a-f]{64}", record[key])
                    for key in ("beforeSha256", "afterSha256"))
            and all(type(record[key]) is list and len(record[key]) == 9
                    and all(type(v) is int for v in record[key])
                    for key in ("beforeIdentity", "stagedIdentity")), "restoration_record")
    displaced, stamp = read_at(target, record["stage"])
    if digest(displaced) == record["afterSha256"] and stamp[:8] == tuple(record["stagedIdentity"][:8]):
        return "RESTORATION_NOT_APPLIED"
    require(digest(displaced) == record["beforeSha256"]
            and stamp[:8] == tuple(record["beforeIdentity"][:8]),
            "restoration_displaced_unknown_handoff")
    return "RESTORATION_EXACT_PREIMAGE"


def _sources():
    return (parse((ROOT / "manifests/harness-hook-retirement.json").read_bytes()),
            (ROOT / "manifests/sessionstart-exposure.json").read_bytes())


def default_cycle(home, owner, action):
    """Select a default cycle without skipping an unfinished operation.

    Explicit caller IDs never enter this route. Completed journals remain
    immutable; a new disable gets the next numbered directory after restore.
    """
    operation = "hooks"
    for number in range(2, 10002):
        if not has_file(owner, operation):
            return operation
        prior = Directory(home, RECOVERY + (operation,))
        try:
            if not has_file(prior, "restored.json"):
                return operation
            raw, _ = read_at(prior, "restored.json", True)
            require(wire(parse(raw)) == wire({"schema": 1, "status": "RESTORED"}), "recovery_record")
            require(has_file(prior, "active.json"),
                    "recovery_record_incomplete")
        finally:
            prior.close()
        following = "hooks-" + str(number)
        if not has_file(owner, following) and action == "restore":
            return operation
        operation = following
    raise OfframpError("recovery_cycle_limit")


def execute(home, action, *, admission, operation="hooks", link_witness=None,
            plan_action="remove", before_publish=None, after_publish=None):
    """Actual scoped file adapter. Admission is an owning operation observer,
    not a caller Boolean. Use execute_fixture or execute_live, not direct calls
    as evidence of production authorization. Recovery journal is append-only.
    """
    require(action in ACTIONS + ("restore", "status", "plan"), "action_refused")
    require(plan_action in ACTIONS, "action_refused")
    require(operation is None or type(operation) is str and re.fullmatch(r"[a-z][a-z0-9-]{0,47}", operation) is not None,
            "operation_id")
    require(callable(admission), "admission_required")
    manifest, historical = _sources()
    target = Directory(home, (".codex",))
    recovery = None
    recovery_owner = None
    lock = None
    try:
        before, stamp = read_at(target, "hooks.json")
        if action in ("status", "plan"):
            scope = "disable" if action == "status" else plan_action
            report = build_plan(before, manifest, historical, scope).public_report()
            report["readOnly"] = True
            report["sourceAdmissionChecked"] = False
            report["machineMutationAuthorized"] = False
            if scope == "remove":
                rows = passive_preflight(home, manifest, link_witness=link_witness, operation=operation or "hooks")
                report["passiveTargets"] = [{"id": row["id"], "status": row["status"]} for row in rows]
                report["globalGuidance"] = "RETAINED_EXTERNAL_GUIDE"
                report["harnessRemovalComplete"] = False
                report["retainedScope"] = list(RETAINED_SCOPE)
                report["residualScope"] = list(RESIDUAL_SCOPE)
            return report
        recovery_owner = Directory(home, RECOVERY, create=True)
        require(stat.S_IMODE(os.fstat(recovery_owner.fd).st_mode) == 0o700, "recovery_not_private")
        lock = os.open("custody.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                       0o600, dir_fd=recovery_owner.fd)
        facts = os.fstat(lock)
        require(stat.S_ISREG(facts.st_mode) and facts.st_nlink == 1
                and facts.st_uid == os.getuid() and stat.S_IMODE(facts.st_mode) == 0o600,
                "custody_metadata")
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise OfframpError("operation_busy") from None
        custody_identity = identity(facts)
        def custody_guard():
            try:
                recovery_owner.verify()
                return identity(os.fstat(lock)) == custody_identity == identity(os.stat(
                    "custody.lock", dir_fd=recovery_owner.fd, follow_symlinks=False))
            except Exception:
                return False
        require(custody_guard(), "custody_drift")
        if operation is None:
            operation = default_cycle(home, recovery_owner, action)
        def reported(report):
            return dict(report, operationId=operation)
        recovery = Directory(home, RECOVERY + (operation,), create=True)
        require(stat.S_IMODE(os.fstat(recovery.fd).st_mode) == 0o700, "recovery_not_private")
        before, stamp = read_at(target, "hooks.json")
        if action == "restore":
            if not has_file(recovery, "active.json"):
                require(not any(has_file(recovery, name) for name in (
                    "publication.json", "applied.json", "restoration-publication.json")),
                    "recovery_record_incomplete")
                return reported({"schema": 1, "status": "PREPARATION_ABORTED_NO_MUTATION",
                        "targetChanged": False, "recoveryRetained": True,
                        "newOperationRequired": True, "nativeTrustChanged": False})
            journal, _ = read_at(recovery, "active.json", True)
            record = parse(journal)
            require(type(record) is dict and set(record) == {
                "schema", "action", "beforeSha256", "afterSha256", "events", "removed"}
                and type(record["schema"]) is int and record["schema"] == 1
                and type(record["action"]) is str and record["action"] in ACTIONS
                and type(record["removed"]) is int and 0 <= record["removed"] <= 4
                and type(record["events"]) is list and len(record["events"]) <= 3
                and all(type(event) is str and event in ("SessionStart", "PreToolUse", "Stop")
                        for event in record["events"])
                and len(record["events"]) == len(set(record["events"])), "recovery_record")
            original, _ = read_at(recovery, "before.json", True)
            post, _ = read_at(recovery, "after.json", True)
            require(digest(original) == record["beforeSha256"] and digest(post) == record["afterSha256"],
                    "recovery_corrupt")
            plan = build_plan(original, manifest, historical, record["action"])
            require(plan.after == post and list(plan.events) == record["events"]
                    and plan.removed == record["removed"], "recovery_corrupt")
            outcome = interrupted_publication(target, recovery, plan)
            if outcome == "PUBLICATION_NOT_APPLIED":
                return reported({"schema": 1, "status": outcome, "targetChanged": False,
                        "recoveryRetained": True, "newOperationRequired": True,
                        "nativeTrustChanged": False})
            restoration_outcome = interrupted_restoration(target, recovery)
            if restoration_outcome == "RESTORATION_NOT_APPLIED":
                return reported({"schema": 1, "status": restoration_outcome, "targetChanged": False,
                        "recoveryRetained": True, "targetedRecoveryRequired": True,
                        "nativeTrustChanged": False})
            after = restore_plan(before, plan)
        else:
            plan = build_plan(before, manifest, historical, action)
            if plan.removed == 0 and action != "remove":
                return reported(plan.public_report())
            after = plan.after
        passive = passive_preflight(home, manifest, recovery, restore=action == "restore",
                                    link_witness=link_witness) if (
            action == "remove" or action == "restore" and plan.action == "remove") else []
        already_restored = action == "restore" and after == before and not any(
            r["status"] == "OWNED" for r in passive)
        if already_restored and has_file(recovery, "restored.json"):
            marker, _ = read_at(recovery, "restored.json", True)
            require(wire(parse(marker)) == wire({"schema": 1, "status": "RESTORED"}),
                    "recovery_record")
            report = plan.public_report()
            report["status"] = "ALREADY_RESTORED"
            return reported(report)
        def guard():
            try:
                current, current_stamp = read_at(target, "hooks.json")
                recovery.verify()
                return custody_guard() and current == before and current_stamp == stamp
            except Exception:
                return False
        if action != "restore":
            # Never overwrite a prior uncertain operation; explicit recovery
            # precedes another lifecycle. Preimage is durable BEFORE mutation.
            write_new(recovery, "before.json", before)
            write_new(recovery, "after.json", after)
            for row in passive:
                write_new(recovery, row["id"] + ".json", wire({"schema": 1,
                    "status": row["status"], "kind": row["kind"], "sha256":
                    digest(row["before"]) if row["before"] is not None else None}))
            # The durable active record is published LAST, only after the
            # entire recovery closure. Its absence proves preparation stopped
            # before any hook publication or passive move could begin.
            write_record(recovery, "active.json", wire({"schema": 1, "action": action,
                "beforeSha256": digest(before), "afterSha256": digest(after),
                "events": list(plan.events), "removed": plan.removed}))
        def recovery_guard():
            try:
                original, _ = read_at(recovery, "before.json", True)
                post, _ = read_at(recovery, "after.json", True)
                saved, _ = read_at(recovery, "active.json", True)
                record = parse(saved)
                return original == plan.before and post == plan.after and wire(record) == wire({
                    "schema": 1, "action": plan.action, "beforeSha256": digest(plan.before),
                    "afterSha256": digest(plan.after), "events": list(plan.events), "removed": plan.removed})
            except Exception:
                return False
        admission(guard, recovery_guard)
        require(guard() and recovery_guard(), "preimage_drift")
        if already_restored:
            # Publication can have completed before its completion marker.
            # Reconcile exact restored bytes and retained recovery under the
            # ordinary guards; do not leave the default cycle permanently busy.
            write_record(recovery, "restored.json", wire({"schema": 1, "status": "RESTORED"}))
            report = plan.public_report()
            report["status"] = "ALREADY_RESTORED"
            return reported(report)
        if after != before:
            publish(target, before, stamp, after, recovery, restoring=action == "restore", before_publish=before_publish,
                    after_publish=after_publish, mutation_guard=lambda: custody_guard() and recovery_guard())
        passive_reports = passive_apply(home, passive, recovery, restore=action == "restore")
        write_record(recovery, "restored.json" if action == "restore" else "applied.json",
                  wire({"schema": 1, "status": "RESTORED" if action == "restore" else "APPLIED"}))
        report = plan.public_report()
        report["status"] = "RESTORED" if action == "restore" else "APPLIED"
        if action == "remove":
            report["status"] = "USER_HARNESS_REMOVAL_PARTIAL"
        report["nativeTrustRestored"] = False
        report["passiveTargets"] = passive_reports
        report["harnessRemovalComplete"] = False
        report["globalGuidance"] = "RETAINED_EXTERNAL_GUIDE"
        report["retainedScope"] = list(RETAINED_SCOPE)
        report["residualScope"] = list(RESIDUAL_SCOPE)
        return reported(report)
    finally:
        if lock is not None:
            os.close(lock)
        if recovery is not None:
            recovery.close()
        if recovery_owner is not None:
            recovery_owner.close()
        target.close()


def execute_fixture(home, action, **seams):
    """Synthetic temporary homes only; no ambient HOME, apps or doctor probes."""
    home = Path(home)
    require(home.is_absolute() and home == home.resolve(strict=True)
            and home != Path.home().resolve()
            and any(root in home.parents for root in (
                Path(tempfile.gettempdir()).resolve(), Path("/private/tmp"))), "fixture_home")
    result = execute(home, action, admission=lambda guard, recovery: require(
        guard() and recovery(), "fixture_drift"), **seams)
    result["fixtureOnly"] = True
    result["machineMutationAuthorized"] = False
    return result


def execute_live(action, commit, operation="hooks", plan_action="remove"):
    """Explicit owner-requested off-ramp after protected source acceptance.

    This candidate cannot approve its own canonical source; the independent
    current-source admission engine must accept the affected committed inputs.
    Unrelated vendor health, invocation cwd and native config content are not
    hook ownership or consent observations. Nothing edits native consent.
    """
    from lib.user_operation_readiness import require_scoped_operation_ready
    home = Path.home()
    require(ROOT == home / "AIDev/control", "canonical_source")
    def admission(guard, recovery_guard):
        require_scoped_operation_ready(ROOT, "harness-disable", commit, checks={
            "owned-target": guard, "recovery": recovery_guard}, target_guard=guard,
            extra_paths=("manifests/harness-hook-retirement.json", "manifests/sessionstart-exposure.json"))
        require(guard() and recovery_guard(), "preimage_drift")
    return execute(home, action, admission=admission, operation=operation, plan_action=plan_action)


def main(arguments=None, emit=print):
    class Parser(argparse.ArgumentParser):
        def error(self, message):
            raise OfframpError("arguments_refused")
    try:
        parser = Parser()
        parser.add_argument("action", choices=ACTIONS + ("restore", "status", "plan"))
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument("--fixture-home", type=Path)
        group.add_argument("--live-commit")
        parser.add_argument("--operation", default=None)
        parser.add_argument("--scope", choices=ACTIONS, default="remove")
        args = parser.parse_args(arguments)
        report = execute_fixture(args.fixture_home, args.action, operation=args.operation,
                                 plan_action=args.scope) if args.fixture_home else execute_live(
            args.action, args.live_commit, args.operation, args.scope)
        code = 0
    except Exception as error:
        from lib import scoped_source_admission as source
        report = {"schema": 1, "status": "REFUSED", "reason":
                  str(error) if isinstance(error, OfframpError) else "operation_refused"}
        if isinstance(error, source.SourceError):
            report.update(source.public_failure(error))
        code = 1
    emit(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return code
