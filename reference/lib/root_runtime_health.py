"""Release-bound root component observation, never an install/apply executor.

Historical Phase 4 collectors remain unchanged. Only the fixed typed broker
doctor is executed; root-private contents are attested by it, not read here.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import pwd
import stat

from lib import root_delivery as delivery
from lib.bounded_command import bounded
from lib.scoped_source_admission import SourceError

ROOT = Path(__file__).resolve().parents[1]
BROKER = "/usr/local/libexec/aid-admin"
POLICY = "/etc/agent-first-mac/aid-admin-policy.json"
ATTESTATION = "/etc/agent-first-mac/aid-admin-install.json"
SUDOERS = "/etc/sudoers.d/agent-first-mac-aid-admin"
COMMAND = ("/usr/bin/sudo", "-n", BROKER, "doctor-root", "--json")
ABSENCES = ("/etc/agent-first-mac/aid-admin.disabled", SUDOERS + ".disabled")
DIRECTORIES = ("/var/db/agent-first-mac/staging", "/var/log/agent-first-mac/aid-admin")


class HealthError(ValueError):
    pass


def require(condition, reason):
    if condition is not True:
        raise HealthError(reason)


def strict_json(raw):
    require(type(raw) is bytes and 0 < len(raw) <= 16384, "root_doctor_output")
    def pairs(rows):
        value = {}
        for key, item in rows:
            require(key not in value, "root_doctor_output")
            value[key] = item
        return value
    try:
        return json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(HealthError("root_doctor_output")))
    except (ValueError, UnicodeError, RecursionError):
        raise HealthError("root_doctor_output") from None


def exact_file(value, pin, mode, *, content):
    require(type(value) is dict and set(value) == {"uid", "gid", "mode", "kind", "nlink", "size", "data"},
            "root_metadata")
    require(all(type(value[k]) is int for k in ("uid", "gid", "mode", "nlink", "size"))
            and value["uid"] == value["gid"] == 0 and value["mode"] == mode
            and value["kind"] == "file" and value["nlink"] == 1
            and value["size"] == pin["size"], "root_metadata")
    if content:
        require(type(value["data"]) is bytes and len(value["data"]) == pin["size"]
                and hashlib.sha256(value["data"]).hexdigest() == pin["sha256"], "root_artifact_binding")
    else:
        require(value["data"] is None, "root_private_content_not_allowed")


def inspect_installed(contract, *, observe, runner, paired_guard, source_guard,
                      allow_predecessor=False):
    """Pure seam; observations are actual bytes/metadata, never PASS receipts."""
    require(type(allow_predecessor) is bool, "root_mode")
    require(source_guard() is True and paired_guard() is True, "root_source_or_pair_drift")
    observed = []
    def read(kind, path):
        value = observe(kind, path)
        observed.append((kind, path, copy.deepcopy(value)))
        return value
    broker = read("file", BROKER)
    selected = None
    for name in ("successor", "predecessor") if allow_predecessor else ("successor",):
        pin = contract[name]["broker"]
        if type(broker) is dict and type(broker.get("data")) is bytes and len(broker["data"]) == pin["size"] \
                and hashlib.sha256(broker["data"]).hexdigest() == pin["sha256"]:
            selected = name
            break
    require(selected is not None, "root_broker_unrecognized")
    pins = contract[selected]
    exact_file(broker, pins["broker"], 0o555, content=True)
    exact_file(read("file", POLICY), pins["policy"], 0o444, content=True)
    exact_file(read("metadata", ATTESTATION), pins["attestation"], 0o400, content=False)
    exact_file(read("metadata", SUDOERS), pins["sudoers"], 0o440, content=False)
    for path in DIRECTORIES:
        value = read("directory", path)
        require(type(value) is dict and set(value) == {"uid", "gid", "mode", "kind"}
                and all(type(value[k]) is int for k in ("uid", "gid", "mode"))
                and value == {"uid": 0, "gid": 0, "mode": 0o700, "kind": "directory"}, "root_directory")
    for path in ABSENCES:
        require(read("absent", path) is True, "root_disabled_or_unknown")
    require(source_guard() is True and paired_guard() is True, "root_source_or_pair_drift")
    result = runner(COMMAND)
    require(type(result) is tuple and len(result) == 4 and result[3] is True,
            "root_doctor_process_unsettled")
    code, stdout, stderr, _ = result
    require(type(code) is int and code == 0 and type(stderr) is bytes and stderr == b"", "root_doctor_failed")
    # Both exact broker pins in this release implement the journal-aware
    # five-check protocol. The older four-check predecessor belonged to the
    # preceding release; accepting it here would omit settlement evidence.
    checks = {key: True for key in ("emergency_disable_absent", "installed_artifact_attestation",
                                   "installed_contract", "operation_settled", "policy_hash")}
    expected = {"checks": checks, "command": "doctor-root", "problems": [], "readOnly": True,
                "schema": 1, "systemMutationsPerformed": False, "verdict": "ROOT_CONTRACT_READY"}
    value = strict_json(stdout)
    # JSON True and integer 1 are equal in Python; compare canonical encodings.
    require(json.dumps(value, sort_keys=True) == json.dumps(expected, sort_keys=True), "root_doctor_contract")
    for kind, path, before in observed:
        require(observe(kind, path) == before, "root_observation_drift")
    require(source_guard() is True and paired_guard() is True, "root_source_or_pair_drift")
    return {"schema": 1, "scope": "ROOT_RUNTIME_COMPONENT", "verdict": "ROOT_RUNTIME_READY" if selected == "successor" else "PREDECESSOR_READY",
            "releaseObserved": selected, "pairedEmergencyRetained": True,
            "rootPrivateConsistencyAttestedByTypedDoctor": True,
            "expectedPrivatePolicyHashVerified": False, "rootOwnedStateTrustAssumed": True,
            "operationJournalSettled": value["checks"]["operation_settled"],
            "nativeAuthenticationExercised": False, "emergencyActionsExecuted": False,
            "wholeMachineHealth": False, "installationAuthorized": False,
            "readOnly": True, "systemMutationsPerformed": False, "childSettled": True}


class NativeObservation:
    """Hold public files; recheck exact identity and known OS alias parents."""
    def __init__(self):
        self.held = {}
        self.named = {}

    @staticmethod
    def stamp(info):
        return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
                info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

    def parents(self, path):
        physical = "/private" + path if path.startswith(("/etc/", "/var/")) else path
        if physical != path:
            alias = "/" + path.split("/")[1]
            info = os.lstat(alias)
            require(stat.S_ISLNK(info.st_mode) and info.st_uid == 0
                    and os.readlink(alias) in ("private" + alias, "/private" + alias), "root_parent_alias")
        for parent in reversed(Path(physical).parents):
            info = os.lstat(parent)
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                    "root_parent_metadata")
            stamp = (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)
            require(self.named.setdefault(str(parent), stamp) == stamp, "root_parent_drift")
        return physical

    def observe(self, kind, path):
        physical = self.parents(path)
        try:
            info = os.lstat(physical)
        except FileNotFoundError:
            require(kind == "absent", "root_file_absent")
            return True
        if kind == "absent":
            return False
        if kind == "directory":
            require(stat.S_ISDIR(info.st_mode), "root_directory")
            identity = (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)
            require(self.named.setdefault(("directory", physical), identity) == identity,
                    "root_directory_drift")
            return {"uid": info.st_uid, "gid": info.st_gid, "mode": stat.S_IMODE(info.st_mode), "kind": "directory"}
        require(stat.S_ISREG(info.st_mode), "root_file_type")
        stamp = self.stamp(info)
        require(self.named.setdefault(physical, stamp) == stamp, "root_file_drift")
        data = None
        if kind == "file":
            require(path in (BROKER, POLICY), "root_public_read_scope")
            if physical not in self.held:
                self.held[physical] = os.open(physical, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
            fd = self.held[physical]
            require(self.stamp(os.fstat(fd)) == stamp and 0 < info.st_size <= 32 * 1024 * 1024, "root_file_drift")
            os.lseek(fd, 0, os.SEEK_SET)
            chunks, count = [], 0
            while count <= info.st_size:
                block = os.read(fd, min(65536, info.st_size + 1 - count))
                if not block:
                    break
                count += len(block)
                chunks.append(block)
            data = b"".join(chunks)
            require(len(data) == info.st_size and self.stamp(os.fstat(fd)) == stamp
                    and self.stamp(os.lstat(physical)) == stamp, "root_file_drift")
        return {"uid": info.st_uid, "gid": info.st_gid, "mode": stat.S_IMODE(info.st_mode),
                "kind": "file", "nlink": info.st_nlink, "size": info.st_size, "data": data}

    def close(self):
        for fd in self.held.values():
            os.close(fd)
        self.held.clear()


def native_health(release, home, uid, source_guard, allow_predecessor=False):
    require(uid > 0 and uid == os.getuid() and home == pwd.getpwuid(uid).pw_dir, "root_owner_identity")
    observer = NativeObservation()
    def paired():
        delivery.verify_durable(release, home, uid)
        return True
    try:
        return inspect_installed(delivery.health_contract(release), observe=observer.observe,
            runner=lambda argv: bounded(list(argv), timeout=15, limit=16384),
            paired_guard=paired, source_guard=source_guard, allow_predecessor=allow_predecessor)
    finally:
        observer.close()


def native():
    uid = os.getuid()
    home = pwd.getpwuid(uid).pw_dir
    require(uid > 0 and ROOT == Path(home) / "AIDev/control" and ROOT.resolve(strict=True) == ROOT,
            "root_canonical_source")
    reports = []
    def inspect(head, *, source_guard):
        del head
        reports.append(native_health(delivery.load_release(ROOT), home, uid, source_guard))
        return True
    delivery.admitted_source(operation_check=inspect, entrypoint='bin/root-runtime-doctor')
    require(len(reports) == 1, "root_source_unadmitted")
    return reports[0]


def main(arguments, *, inspect=native, emit=print):
    if arguments not in ([], ["--json"]):
        emit(json.dumps({"schema": 1, "scope": "ROOT_RUNTIME_COMPONENT", "verdict": "BLOCKED", "reason": "usage", "systemMutationsPerformed": False}))
        return 2
    try:
        report = inspect()
        emit(json.dumps(report, sort_keys=True))
        return 0
    except Exception as error:
        # Never expose native output, owner identities, private paths or errors.
        reason = str(error) if isinstance(error, HealthError) else "root_runtime_unverified"
        value = {"schema": 1, "scope": "ROOT_RUNTIME_COMPONENT", "verdict": "BLOCKED", "reason": reason, "readOnly": True, "systemMutationsPerformed": False}
        if isinstance(error, SourceError):
            from lib.scoped_source_admission import public_failure
            value.update(public_failure(error))
        emit(json.dumps(value, sort_keys=True))
        return 1
