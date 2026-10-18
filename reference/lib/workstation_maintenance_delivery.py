"""One fixed user LaunchAgent. No model, network, root or arbitrary executor.

The owner coordinates native heartbeat settlement/pause before installation.
Private journaling and observation use the same existing nonblocking flock.
This is a cooperative same-user lifecycle, not an adversarial security boundary.
"""
import hashlib
import importlib.machinery
import json
import os
from pathlib import Path
import plistlib
import pwd
import re
import stat
import ctypes
import errno
import copy
import resource
if __package__ == "lib":
    from lib.bounded_command import bounded
else:
    # The installed cycle loads this existing module from its lib search path.
    from bounded_command import bounded

LABEL = "com.aidev.workstation-maintenance"
PLIST = LABEL + ".plist"
RETIRED = PLIST + ".retired"
JOURNAL = "schedule-ownership.json"
PAYLOAD = "schedule-payload.plist"
CYCLE = "deterministic-cycle.json"
MAX_RECORD = 32768
MAX_EVENTS = 128
SCHEDULED_OPEN_FILES = 2048
MANIFEST = "manifests/workstation-maintenance.json"
ROOT = Path(__file__).resolve().parents[1]
SOURCE_FILES = ("bin/workstation-maintenance-cycle", "bin/workstation-drift-snapshot",
    "lib/workstation_maintenance_delivery.py", "lib/productivity_ownership.py", MANIFEST,
    "manifests/productivity-baseline.json", "manifests/phase3-capabilities.json",
    "manifests/codex-contract.json", "manifests/rustdesk-mac-controller.json",
    "manifests/tailscale-windows-host-m1.json", "manifests/windows-app-rdp-client.json",
    "manifests/amnezia-desktop.json", "manifests/gametomac.json")
PHASES = {"preparing", "prepared", "published", "starting", "starting-unknown", "installed", "remove-prepared", "stopping", "stopping-unknown", "stopped", "retiring", "removed"}
NOTIFICATION = 'display notification "Workstation observation needs attention. Check the AIDev maintenance status." with title "AIDev maintenance"'


class Fault(ValueError):
    pass


def need(value, reason="state_unavailable"):
    if value is not True:
        raise Fault(reason)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def parse(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result, "duplicate_key")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def ident(facts):
    return [facts.st_dev, facts.st_ino]


def rename_exclusive(fd, source, target):
    # macOS provides atomic no-replace rename: unlike link+unlink, interruption
    # cannot leave an otherwise-valid private record with two hard links.
    libc = ctypes.CDLL(None, use_errno=True)
    try:
        function = libc.renameatx_np
    except AttributeError:
        raise Fault("exclusive_rename_unavailable") from None
    function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    function.restype = ctypes.c_int
    if function(fd, os.fsencode(source), fd, os.fsencode(target), 4) != 0:
        code = ctypes.get_errno()
        raise OSError(code, "exclusive publication refused")


def output(operation, status, *, phase=None, notification="not_attempted"):
    return {"schema": 1, "operation": operation, "status": status, "phase": phase,
        "exitCode": 0 if status in {"PLANNED", "INSTALLED", "REMOVED", "UNCHANGED"} else 3 if status == "BUSY" else 1,
        "modelInvocations": 0, "notificationOutcome": notification,
        "readOnly": operation in {"plan", "status"},
        "notificationDelivered": False, "scheduledOriginClaimed": False,
        "rootOperationsPerformed": False, "oldHeartbeatModified": False}


def payload(home):
    return plistlib.dumps({"Label": LABEL, "ProgramArguments": ["/usr/bin/python3", "-I", "-B",
        str(Path(home) / "AIDev/control/bin/workstation-maintenance-cycle"), "scheduled", "--json"],
        "StartCalendarInterval": {"Hour": 12, "Minute": 0}, "RunAtLoad": True,
        "KeepAlive": False, "ProcessType": "Background", "StandardOutPath": "/dev/null",
        "StandardErrorPath": "/dev/null"}, fmt=plistlib.FMT_XML, sort_keys=True)


def sources(root):
    values = {}
    for name in SOURCE_FILES:
        path = Path(root) / name
        facts = path.lstat()
        need(stat.S_ISREG(facts.st_mode) and not facts.st_mode & 0o022 and facts.st_size <= 262144, "source_unavailable")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            held = os.fstat(fd)
            raw = os.read(fd, 262145)
            need(ident(held) == ident(facts) and len(raw) == held.st_size and
                (held.st_mtime_ns, held.st_ctime_ns, held.st_size) ==
                (os.fstat(fd).st_mtime_ns, os.fstat(fd).st_ctime_ns, os.fstat(fd).st_size), "source_drift")
            values[name] = sha(raw)
        finally:
            os.close(fd)
    manifest = parse((Path(root) / MANIFEST).read_bytes())
    need(type(manifest) is dict and type(manifest.get("schema")) is int and manifest["schema"] == 1 and
        manifest.get("label") == LABEL and manifest.get("calendar") == {"Hour": 12, "Minute": 0} and
        manifest.get("runAtLoad") is True and manifest.get("keepAlive") is False and
        manifest.get("latestCycleLimit") == MAX_RECORD and
        manifest.get("attemptedEventLimit") == 128, "manifest_drift")
    return values


class Files:
    """Fixed records under the held private observation parent; no raw paths out."""
    def __init__(self, store):
        self.store, self.fd, self.uid = store, store.directory, store.uid

    def read(self, name, *, fd=None, links=1):
        need(name in {JOURNAL, PAYLOAD, CYCLE, PLIST, RETIRED}, "fixed_target")
        self.store.verify()
        parent = self.fd if fd is None else fd
        try:
            leaf = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        except FileNotFoundError:
            return None
        try:
            facts = os.fstat(leaf)
            need(stat.S_ISREG(facts.st_mode) and facts.st_uid == self.uid and
                1 <= facts.st_nlink <= links and stat.S_IMODE(facts.st_mode) == 0o600 and
                facts.st_size <= MAX_RECORD, "unsafe_owned_file")
            raw = os.read(leaf, MAX_RECORD + 1)
            final = os.fstat(leaf)
            need(len(raw) == facts.st_size and
                (ident(facts), facts.st_size, facts.st_mtime_ns, facts.st_ctime_ns) ==
                (ident(final), final.st_size, final.st_mtime_ns, final.st_ctime_ns), "file_drift")
            named = os.stat(name, dir_fd=parent, follow_symlinks=False)
            need(ident(named) == ident(facts), "file_drift")
            return raw, ident(facts)
        finally:
            os.close(leaf)

    def create_payload(self, raw):
        leaf = os.open(PAYLOAD, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=self.fd)
        try:
            offset = 0
            while offset < len(raw):
                count = os.write(leaf, raw[offset:])
                need(count > 0, "write_incomplete")
                offset += count
            os.fsync(leaf)
            os.lseek(leaf, 0, os.SEEK_SET)
            need(os.read(leaf, MAX_RECORD) == raw, "write_readback")
            stamp = ident(os.fstat(leaf))
            self.store.verify()
        finally:
            os.close(leaf)
        os.fsync(self.fd)
        return stamp

    def finish_preparation(self, expected, stage):
        # Only the journal-reserved PRIVATE staging slot can be completed from
        # an exact canonical payload prefix. No public/user plist is adopted.
        need(expected.startswith(stage[0]), "incomplete_private_preparation")
        leaf = os.open(PAYLOAD, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.fd)
        try:
            need(ident(os.fstat(leaf)) == stage[1] and os.fstat(leaf).st_nlink == 1, "private_payload_drift")
            need(os.read(leaf, MAX_RECORD) == stage[0], "private_payload_drift")
            offset = len(stage[0])
            while offset < len(expected):
                count = os.write(leaf, expected[offset:])
                need(count > 0, "write_incomplete")
                offset += count
            os.fsync(leaf)
            os.lseek(leaf, 0, os.SEEK_SET)
            need(os.read(leaf, MAX_RECORD) == expected, "write_readback")
            self.store.verify()
            return stage[1]
        finally:
            os.close(leaf)

    def write(self, name, value, previous):
        need(name in {JOURNAL, CYCLE}, "fixed_record")
        raw = encoded(value)
        need(len(raw) <= MAX_RECORD and self.read(name) == previous, "record_drift")
        temporary = ".maintenance-publish-" + os.urandom(8).hex()
        leaf = os.open(temporary, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=self.fd)
        stamp = ident(os.fstat(leaf))
        published = False
        try:
            offset = 0
            while offset < len(raw):
                count = os.write(leaf, raw[offset:])
                need(count > 0, "write_incomplete")
                offset += count
            os.fsync(leaf)
            os.lseek(leaf, 0, os.SEEK_SET)
            need(os.read(leaf, MAX_RECORD + 1) == raw, "write_readback")
            self.store.verify()
            need(self.read(name) == previous and ident(os.stat(temporary, dir_fd=self.fd, follow_symlinks=False)) == stamp, "record_drift")
            if previous is None:
                rename_exclusive(self.fd, temporary, name)
            else:
                os.replace(temporary, name, src_dir_fd=self.fd, dst_dir_fd=self.fd)
            published = True
            os.fsync(self.fd)
            result = self.read(name)
            need(result is not None and result[0] == raw, "record_readback")
            return result
        finally:
            if not published:
                try:
                    if ident(os.stat(temporary, dir_fd=self.fd, follow_symlinks=False)) == stamp:
                        os.unlink(temporary, dir_fd=self.fd)
                except FileNotFoundError:
                    pass
            os.close(leaf)


class AgentParent:
    def __init__(self, home, uid, create=False, expected_home=None):
        self.edges, self.fds, self.uid = [], [], uid
        try:
            parent = os.open(home, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            self.fds.append(parent)
            need(os.fstat(parent).st_uid == uid and not os.fstat(parent).st_mode & 0o022, "unsafe_agent_parent")
            need(expected_home is None or ident(os.fstat(parent)) == expected_home, "agent_parent_drift")
            for name in ("Library", "LaunchAgents"):
                try:
                    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
                except FileNotFoundError:
                    need(create, "agent_parent_missing")
                    os.mkdir(name, 0o700, dir_fd=parent)
                    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
                facts = os.fstat(child)
                need(facts.st_uid == uid and not facts.st_mode & 0o022, "unsafe_agent_parent")
                self.edges.append((parent, name, child, ident(facts)))
                self.fds.append(child)
                parent = child
            self.fd = parent
        except BaseException:
            self.close()
            raise

    def verify(self):
        for descriptor in self.fds:
            facts = os.fstat(descriptor)
            need(facts.st_uid == self.uid and not facts.st_mode & 0o022, "unsafe_agent_parent")
        for parent, name, child, stamp in self.edges:
            need(ident(os.fstat(child)) == stamp and ident(os.stat(name, dir_fd=parent, follow_symlinks=False)) == stamp, "agent_parent_drift")

    def close(self):
        while self.fds:
            os.close(self.fds.pop())


def journal_valid(value, home):
    need(type(value) is dict and set(value) == {"schema", "phase", "payloadHash", "payloadIdentity", "sources"}, "journal_malformed")
    need(type(value["schema"]) is int and value["schema"] == 1 and value["phase"] in PHASES and
        value["payloadHash"] == sha(payload(home)), "journal_malformed")
    stamp = value["payloadIdentity"]
    need(stamp is None or type(stamp) is list and len(stamp) == 2 and all(type(v) is int and v >= 0 for v in stamp), "journal_malformed")
    need(value["phase"] == "preparing" or stamp is not None, "journal_malformed")
    need(type(value["sources"]) is dict and set(value["sources"]) == set(SOURCE_FILES) and
        all(type(v) is str and re.fullmatch("[0-9a-f]{64}", v) for v in value["sources"].values()), "journal_malformed")
    return value


class Schedule:
    def __init__(self, store, root, home, runner, *, fault=lambda boundary: None, create=False):
        self.files, self.root, self.home, self.runner, self.fault = Files(store), Path(root), Path(home), runner, fault
        store.verify()
        held_home = ident(os.fstat(store.fds[len(Path(home).parts) - 1]))
        self.parent = AgentParent(home, store.uid, create, expected_home=held_home)
        self.raw, self.row = None, None
        try:
            self.raw = self.files.read(JOURNAL)
            if self.raw is not None:
                self.row = journal_valid(parse(self.raw[0]), home)
        except BaseException:
            self.parent.close()
            raise

    def close(self):
        self.parent.close()

    def save(self, phase):
        if hasattr(self, "source_guard"):
            need(self.source_guard() is True, "current_source_drift")
        self.row["phase"] = phase
        self.raw = self.files.write(JOURNAL, self.row, self.raw)
        self.fault(phase)
        # Journal publication/checkpoint may outlive the previous source check.
        # Do not continue into public target publication or native dispatch with
        # changed source; the durable phase remains recoverable, not cleared.
        if hasattr(self, "source_guard"):
            need(self.source_guard() is True, "current_source_drift")

    def owned(self, *, required=True):
        self.parent.verify()
        stage = self.files.read(PAYLOAD, links=2)
        target = self.files.read(PLIST, fd=self.parent.fd, links=2)
        need(self.row is not None and stage is not None and stage[0] == payload(self.home) and
             stage[1] == self.row["payloadIdentity"], "payload_unowned")
        if target is None:
            need(not required, "owned_target_missing")
        else:
            need(target == stage, "target_unowned")
        return target

    def observe(self):
        return self.runner("observe", self.home)

    def install(self):
        if self.row is not None and self.row["phase"] == "removed":
            self.owned(required=False)
            need(self.files.read(PLIST, fd=self.parent.fd) is None and self.observe() == "ABSENT", "schedule_collision_or_unknown")
            stage = self.files.read(PAYLOAD, links=2)
            retired = self.files.read(RETIRED, fd=self.parent.fd, links=2)
            need(retired == stage, "retired_target_unowned")
            self.row["sources"] = sources(self.root)
            self.save("prepared")
            return self.recover()
        if self.row is None:
            need(self.files.read(PLIST, fd=self.parent.fd) is None and self.observe() == "ABSENT", "schedule_collision_or_unknown")
            need(self.files.read(PAYLOAD, links=2) is None, "private_payload_unowned")
            self.row = {"schema": 1, "phase": "preparing", "payloadHash": sha(payload(self.home)),
                "payloadIdentity": None, "sources": sources(self.root)}
            self.save("preparing")
        else:
            need(self.row["phase"] == "installed", "explicit_recovery_required")
            self.owned()
            need(self.observe() == "PRESENT", "loaded_schedule_unknown")
            self.row["sources"] = sources(self.root)
            self.save("installed")
            return output("install", "INSTALLED", phase="installed")
        return self.recover()

    def recover(self):
        need(self.row is not None, "ownership_missing")
        phase = self.row["phase"]
        need(phase not in {"starting-unknown", "stopping-unknown"}, "native_custody_unsettled")
        if phase in {"remove-prepared", "stopping", "stopped", "retiring"}:
            return self.remove(recover=True)
        if phase == "removed":
            need(self.files.read(PLIST, fd=self.parent.fd) is None and self.observe() == "ABSENT", "removed_state_drift")
            return output("recover", "REMOVED", phase=phase)
        if phase != "installed":
            need(sources(self.root) == self.row["sources"], "source_drift")
        if phase == "preparing":
            stage = self.files.read(PAYLOAD, links=2)
            # This private namespace was reserved before preparing payload bytes.
            # Never adopt any public plist or an unexpected/partial private file.
            need(self.files.read(PLIST, fd=self.parent.fd) is None, "target_unowned")
            if stage is None:
                stamp = self.files.create_payload(payload(self.home))
            else:
                stamp = self.files.finish_preparation(payload(self.home), stage)
            self.row["payloadIdentity"] = stamp
            self.save("prepared")
            phase = "prepared"
        if phase == "prepared":
            target = self.owned(required=False)
            if target is None:
                need(self.observe() == "ABSENT", "schedule_collision_or_unknown")
                self.parent.verify(); self.files.store.verify()
                retired = self.files.read(RETIRED, fd=self.parent.fd, links=2)
                if retired is not None:
                    need(retired == self.files.read(PAYLOAD, links=2), "retired_target_unowned")
                    rename_exclusive(self.parent.fd, RETIRED, PLIST)
                else:
                    os.link(PAYLOAD, PLIST, src_dir_fd=self.files.fd, dst_dir_fd=self.parent.fd, follow_symlinks=False)
                os.fsync(self.parent.fd)
                self.fault("target-published")
            self.owned()
            self.save("published")
            phase = "published"
        if phase in {"published", "starting", "installed"}:
            self.owned()
            observed = self.observe()
            need(observed in {"PRESENT", "ABSENT"}, "loaded_schedule_unknown")
            if observed == "ABSENT":
                self.save("starting")
                # Durable untrusted custody precedes dispatch. Interpreter
                # death during Popen/native execution cannot permit replay.
                self.save("starting-unknown")
                result = self.runner("bootstrap", self.home)
                if result in {"SETTLED", "UNKNOWN"}: self.save("starting")
                self.fault("bootstrap-returned")
                need(result == "SETTLED" and self.observe() == "PRESENT", "bootstrap_outcome_unknown")
            self.save("installed")
            return output("recover", "INSTALLED", phase="installed")
        raise Fault("journal_malformed")

    def remove(self, recover=False):
        need(self.row is not None, "ownership_missing")
        if self.row["phase"] == "removed":
            need(self.files.read(PLIST, fd=self.parent.fd) is None and self.observe() == "ABSENT", "removed_state_drift")
            return output("remove", "REMOVED", phase="removed")
        need(self.row["phase"] == "installed" or recover and self.row["phase"] in {"remove-prepared", "stopping", "stopped", "retiring"}, "explicit_recovery_required")
        self.owned(required=self.row["phase"] not in {"stopped", "retiring"})
        if self.row["phase"] == "installed":
            self.row["sources"] = sources(self.root)
            self.save("remove-prepared")
        if self.row["phase"] not in {"stopped", "retiring"}:
            observed = self.observe()
            need(observed in {"PRESENT", "ABSENT"}, "loaded_schedule_unknown")
            if observed == "PRESENT":
                self.save("stopping")
                self.save("stopping-unknown")
                result = self.runner("bootout", self.home)
                if result in {"SETTLED", "UNKNOWN"}: self.save("stopping")
                self.fault("bootout-returned")
                need(result == "SETTLED" and self.observe() == "ABSENT", "bootout_outcome_unknown")
            self.save("stopped")
        target = self.owned(required=False)
        if target is not None:
            self.parent.verify(); self.files.store.verify()
            need(self.files.read(PLIST, fd=self.parent.fd, links=2) == target, "target_drift")
            need(self.files.read(RETIRED, fd=self.parent.fd, links=2) is None, "retired_collision")
            self.save("retiring")
            rename_exclusive(self.parent.fd, PLIST, RETIRED)
            os.fsync(self.parent.fd)
            self.fault("target-removed")
        stage = self.files.read(PAYLOAD, links=2)
        need(stage is not None and stage[0] == payload(self.home) and stage[1] == self.row["payloadIdentity"], "payload_unowned")
        retired = self.files.read(RETIRED, fd=self.parent.fd, links=2)
        if retired != stage:
            # A concurrent uncooperative replacement is preserved, not deleted.
            if retired is not None and self.files.read(PLIST, fd=self.parent.fd, links=2) is None:
                rename_exclusive(self.parent.fd, RETIRED, PLIST)
                os.fsync(self.parent.fd)
            raise Fault("retired_target_unowned")
        need(self.observe() == "ABSENT", "removed_schedule_unknown")
        # Keep both exact backing links and journal as recovery evidence.
        self.save("removed")
        return output("remove", "REMOVED", phase="removed")


def runner(operation, home):
    uid = os.getuid()
    domain = "gui/" + str(uid)
    path = str(Path(home) / "Library/LaunchAgents" / PLIST)
    command = {"observe": ["/bin/launchctl", "print", domain + "/" + LABEL],
        "bootstrap": ["/bin/launchctl", "bootstrap", domain, path],
        "bootout": ["/bin/launchctl", "bootout", domain + "/" + LABEL]}[operation]
    code, stdout, stderr, settled = bounded(command, timeout=10)
    if not settled:
        return "UNKNOWN_CUSTODY"
    if code is None:
        return "UNKNOWN"
    if operation != "observe":
        return "SETTLED" if code == 0 else "UNKNOWN"
    if code == 0:
        text = stdout.decode("utf-8", "replace")
        script = str(Path(home) / "AIDev/control/bin/workstation-maintenance-cycle")
        paths = re.findall(r"^\s*path = (.+)$", text, re.MULTILINE)
        programs = re.findall(r"^\s*program = (.+)$", text, re.MULTILINE)
        blocks = re.findall(r"^\s*arguments = \{\s*\n(.*?)^\s*\}", text, re.MULTILINE | re.DOTALL)
        argv = [line.strip() for line in blocks[0].splitlines() if line.strip()] if len(blocks) == 1 else []
        return "PRESENT" if paths == [path] and programs == ["/usr/bin/python3"] and argv == ["/usr/bin/python3", "-I", "-B", script, "scheduled", "--json"] else "UNKNOWN"
    error = stderr.decode("utf-8", "replace").strip()
    return "ABSENT" if code in {3, 113} and ("Could not find service" in error or "No such process" in error) else "UNKNOWN"


def admitted_source(root, *, full, operation_check=None):
    from lib import scoped_source_admission as source
    return source.observe(root, full=full, operation_check=operation_check,
                          extra_paths=SOURCE_FILES)


def native_schedule(operation):
    need(operation in {"plan", "install", "remove", "recover", "status"}, "fixed_operation")
    uid, home = os.getuid(), Path(pwd.getpwuid(os.getuid()).pw_dir)
    store, schedule = None, None
    def perform(source_guard=None):
        nonlocal store, schedule
        need(uid > 0 and ROOT == home / "AIDev/control", "canonical_source_required")
        D = importlib.machinery.SourceFileLoader("maintenance_schedule_store", str(ROOT / "bin/workstation-drift-snapshot")).load_module()
        try:
            store = D.Store(str(home), uid, operation in {"install", "recover"})
        except D.Fault as error:
            if operation not in {"plan", "status"} or error.reason != "state_missing":
                raise
            # Missing private state is not a reason to manufacture it during a
            # plan. Still require actual fixed-label absence and no public file.
            parent = None
            try:
                try:
                    parent = AgentParent(home, uid)
                except Fault as absent:
                    need(str(absent) == "agent_parent_missing", "unsafe_agent_parent")
                if parent is not None:
                    try: os.stat(PLIST, dir_fd=parent.fd, follow_symlinks=False)
                    except FileNotFoundError: pass
                    else: raise Fault("target_unowned")
                need(runner("observe", home) == "ABSENT", "schedule_collision_or_unknown")
                sources(ROOT)
                return output(operation, "PLANNED")
            finally:
                if parent is not None: parent.close()
        schedule = Schedule(store, ROOT, home, runner, create=operation in {"install", "recover"})
        if operation in {"plan", "status"}:
            if schedule.row is None:
                need(schedule.files.read(PLIST, fd=schedule.parent.fd) is None and schedule.observe() == "ABSENT", "schedule_collision_or_unknown")
                return output(operation, "PLANNED")
            schedule.owned(required=schedule.row["phase"] != "removed")
            phase = schedule.row["phase"]
            state = "INSTALLED" if phase == "installed" and schedule.observe() == "PRESENT" else "REMOVED" if phase == "removed" and schedule.observe() == "ABSENT" else "RECOVERY_REQUIRED"
            return output(operation, state, phase=phase)
        need(callable(source_guard) and source_guard() is True, "current_source_drift")
        schedule.source_guard = source_guard
        value = getattr(schedule, operation)()
        need(source_guard() is True, "current_source_drift")
        value["operation"] = operation
        return value
    try:
        if operation in {"plan", "status"}:
            return perform()
        result = []
        def mutation(head, *, source_guard):
            need(callable(source_guard) and source_guard() is True, "current_source_drift")
            result.append(perform(source_guard))
            return True
        # Hold actual catalog inputs BEFORE Schedule consumes their bytes or
        # creates private state, then preserve the same guard through mutation.
        admitted_source(ROOT, full=False, operation_check=mutation)
        need(len(result) == 1, "source_unadmitted")
        return result[0]
    except Exception as error:
        from lib import scoped_source_admission as source
        result = output(operation, "BUSY" if str(error) == "busy" else "RECOVERY_REQUIRED" if schedule and schedule.row else "UNAVAILABLE", phase=schedule.row["phase"] if schedule and schedule.row else None)
        if isinstance(error, source.SourceError):
            result.update(source.public_failure(error))
        return result
    finally:
        if schedule is not None: schedule.close()
        if store is not None: store.close()


def cycle_valid(value):
    need(type(value) is dict and set(value) == {"schema", "latest", "eventId", "notification", "attemptedEvents"} and
        type(value["schema"]) is int and value["schema"] == 1 and type(value["latest"]) is dict and
        (value["eventId"] is None or type(value["eventId"]) is str and re.fullmatch("[0-9a-f]{64}", value["eventId"])) and
        value["notification"] in {"not_attempted", "reserved_unknown", "command_accepted_unverified", "unavailable", "capacity_exhausted"}, "cycle_malformed")
    events = value["attemptedEvents"]
    need(type(events) is list and len(events) <= MAX_EVENTS and
         all(type(event) is str and re.fullmatch("[0-9a-f]{64}", event) for event in events) and
         len(set(events)) == len(events) and
         (value["eventId"] is None or value["eventId"] in events), "cycle_malformed")
    latest = value["latest"]
    need(type(latest.get("schema")) is int and latest["schema"] == 1 and
         latest.get("operation") == "scheduled" and type(latest.get("status")) is str and
         latest.get("modelInvocations") == 0 and type(latest.get("actionable")) is bool and
         latest.get("scheduledOriginClaimed") is False and type(latest.get("observation")) is dict and
         type(latest.get("exitCode")) is int and latest["exitCode"] in {0, 1}, "cycle_malformed")
    return value


def notify():
    code, _, _, settled = bounded(["/usr/bin/osascript", "-e", NOTIFICATION], timeout=5, limit=1024)
    if not settled:
        return "reserved_unknown"
    return "command_accepted_unverified" if code == 0 else "unavailable"


def prepare_scheduled_limits():
    """Budget this process's held source descriptors within its inherited hard limit.

    launchd commonly starts with a soft limit of 256. Accepted-current custody
    holds a leaf descriptor for every reviewed source until the callback ends;
    do not weaken that custody or modify launchd/global limits to fit the job.
    """
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    unlimited = resource.RLIM_INFINITY
    need(type(soft) is int and type(hard) is int and
         (soft == unlimited or soft >= 0) and (hard == unlimited or hard >= 0),
         "file_descriptor_limit_unavailable")
    if soft != unlimited and soft < SCHEDULED_OPEN_FILES:
        need(hard == unlimited or hard >= SCHEDULED_OPEN_FILES,
             "file_descriptor_limit_unavailable")
        resource.setrlimit(resource.RLIMIT_NOFILE, (SCHEDULED_OPEN_FILES, hard))
    current_soft, current_hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    need(current_hard == hard and (current_soft == unlimited or current_soft >= SCHEDULED_OPEN_FILES),
         "file_descriptor_limit_unavailable")
    return True


def scheduled_native(D, *, build_report, now, source_gate=None, notifier=notify):
    try:
        prepare_scheduled_limits()
    except (OSError, ValueError):
        result = output("scheduled", "UNAVAILABLE")
        result.update(sourceAdmission=False, runSourceAccepted=False, installedHealthChecked=False,
                      fileDescriptorBudgetReady=False, failureReason="file_descriptor_limit_unavailable")
        return result
    uid, home = os.getuid(), Path(pwd.getpwuid(os.getuid()).pw_dir)
    holder, context = [], {}
    def before(store):
        need(uid > 0 and ROOT == home / "AIDev/control", "canonical_source_required")
        schedule = Schedule(store, ROOT, home, runner)
        try:
            need(schedule.row is not None and schedule.row["phase"] == "installed", "schedule_not_installed")
            schedule.owned()
            need(schedule.files.read(RETIRED, fd=schedule.parent.fd, links=2) is None, "retired_collision")
            # Settled scheduling follows freshly admitted current source, not
            # a permanent snapshot of the install-time application catalogue.
            need(context["source_guard"]() is True, "current_source_drift")
        finally:
            schedule.close()
    def after(report, store):
        need(context["source_guard"]() is True, "current_source_drift")
        before(store)  # Recheck exact owned plist and safe parents after sampling.
        value = build_report(report)
        value.update(operation="scheduled", exitCode=0 if not value["actionable"] else 1,
                     scheduleInstalledByHelper=False, scheduledOriginClaimed=False)
        files = Files(store)
        previous = files.read(CYCLE)
        old = cycle_valid(parse(previous[0])) if previous else None
        event = value.get("event")
        event_id = event["id"] if event is not None else None
        record = {"schema": 1, "latest": value, "eventId": old["eventId"] if old else None,
                  "notification": old["notification"] if old else "not_attempted",
                  "attemptedEvents": list(old["attemptedEvents"]) if old else []}
        # The reservation belongs to its event, not the notification channel.
        # A crashed/unknown A must not mute unrelated B. Retain a bounded recent
        # attempt window: this is notification deduplication, not an audit log
        # or proof that a historical command was delivered/settled.
        fresh = event_id is not None and event_id not in record["attemptedEvents"]
        if fresh:
            record["attemptedEvents"] = record["attemptedEvents"][-(MAX_EVENTS - 1):]
            record["attemptedEvents"].append(event_id)
            record.update(eventId=event_id, notification="reserved_unknown")
        previous = files.write(CYCLE, record, previous)
        if fresh:
            # Reservation is durable before native notification. A crash can
            # lose a notification, never claim it delivered or duplicate blindly.
            record["notification"] = notifier()
            need(record["notification"] in {"reserved_unknown", "command_accepted_unverified", "unavailable"}, "notification_unknown")
            files.write(CYCLE, record, previous)
        # Outcome is for the last attempted event, not any deduplicated older
        # event that happens to recur now. Never turn unknown A into accepted A
        # because intervening B's notification command completed.
        outcome = record["notification"] if event_id is None or event_id == record["eventId"] else "not_attempted"
        value.update(notificationOutcome=outcome, notificationEventId=record["eventId"],
                     notificationDelivered=False)
        holder.append(value)
        need(context["source_guard"]() is True, "current_source_drift")
    def admitted_operation(head, *, source_guard):
        need(callable(source_guard) and source_guard() is True, "current_source_drift")
        context["source_guard"] = source_guard
        base_classifier = D.source_classifier(ROOT)
        def classified(previous, current):
            if previous is None:
                return base_classifier(previous, current)
            a, b = copy.deepcopy(previous), copy.deepcopy(current)
            # Current receipt proves this present plist, not ownership of a
            # historical removed .retired object. Keep that deletion UNKNOWN.
            key, lifecycle_keys = "user-launch-agents", {sha(os.fsencode(PLIST))}
            sa, sb = a["scopes"][key], b["scopes"][key]
            affected = {item for item in lifecycle_keys if sa["entries"].get(item) != sb["entries"].get(item)}
            for item in lifecycle_keys:
                sa["entries"].pop(item, None); sb["entries"].pop(item, None)
            if affected and sa["present"] is sb["present"] and sa["entries"] == sb["entries"]:
                sb["root"] = sa["root"]
            summary = base_classifier(a, b)
            # Receipt-verified own lifecycle metadata is a non-actionable
            # observation outside payload-catalog coverage, not an inferred
            # actor or acceptance of any unrelated service.
            summary["externalObserved"] += len(affected)
            return summary
        context["observed"] = D.native("capture", preflight=before, consumer=after, classifier=classified)
        need(source_guard() is True, "current_source_drift")
        return True
    try:
        if source_gate is None:
            admitted_source(ROOT, full=False, operation_check=admitted_operation)
        else:
            source_gate(admitted_operation)
        need("observed" in context, "source_unadmitted")
    except Exception as error:
        from lib import scoped_source_admission as source
        result = output("scheduled", "UNAVAILABLE")
        result.update(sourceAdmission=False, runSourceAccepted=False, installedHealthChecked=False)
        if isinstance(error, source.SourceError):
            result.update(source.public_failure(error))
        return result
    observed = context["observed"]
    if holder and holder[0]["observation"] == observed:
        return dict(holder[0], runSourceAccepted=True, freshSourceVerification="accepted-current-git-only", fullDoctorRun=False)
    result = output("scheduled", "BUSY" if observed["status"] == "SKIPPED_BUSY" else "UNAVAILABLE",
                    notification=holder[0]["notificationOutcome"] if holder else "not_attempted")
    result.update(observation=observed, sourceAdmission=False, installedHealthChecked=False,
                  runSourceAccepted=True, freshObservation=False, actionable=True, fullDoctorRun=False)
    return result
