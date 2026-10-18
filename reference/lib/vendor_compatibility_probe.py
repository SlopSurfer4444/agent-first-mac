"""Scoped offline capability observation; never a workstation updater.

No entry point: the current doctor/root supplies admitted source custody and
the unchanged Phase5 readiness/process dependencies. Only a fresh owned fixture
is writable by capability children. Signature/Gatekeeper inspection is a
separate host attestation, not represented as an offline vendor CLI probe.
Unsettled children are retained on the original exception; no automatic retry.
"""

import hashlib
import importlib.machinery
import errno
import os
from pathlib import Path
import re
import stat
import secrets
import sys
from types import SimpleNamespace

from lib import phase5_runtime_paths as paths
from lib import vendor_fixture_custody as custody_policy


APP = "/Applications/ChatGPT.app"
# The packaged bin/codex is a shell wrapper. Execute its actual Mach-O target
# directly so the sandbox still admits exactly one executable and no shell.
# The outer app strict resource seal covers these bytes; SourceFile retains and
# rechecks this exact file and its complete directory chain around attestation.
CLI = APP + "/Contents/Resources/codex-cli/CodexCLI.app/Contents/MacOS/codex"
ASAR = APP + "/Contents/Resources/app.asar"
VENDOR_FILES = frozenset((CLI, ASAR))
VENDOR_MAX_SOURCE = 1024 * 1024 * 1024
SAFE_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"
SCHEMA_LEAF = "codex_app_server_protocol.schemas.json"
ENVELOPE_LEAF = "JSONRPCMessage.json"
FEATURE_KEYS = (
    "apps", "browser_use", "browser_use_external", "browser_use_full_cdp_access",
    "computer_use", "in_app_browser", "plugins", "remote_plugin",
    "skill_mcp_dependency_install",
)
MAX_SCHEMA = 4 * 1024 * 1024
REASONS = frozenset(("source_changed", "fixture_invalid", "signature_invalid",
    "cli_identity_invalid", "command_failed", "schema_output_invalid",
    "capabilities_incompatible", "process_unsettled", "probe_failed",
    "fixture_capacity_required", "fixture_custody_invalid", "fixture_custody_busy",
    "fixture_settlement_required", "fixture_metadata_pending", "fixture_preparation_capacity",
    "fixture_preparation_recovery_required", "fixture_namespace_refresh_required",
    "fixture_legacy_identity_required"))


class ProbeError(Exception):
    def __init__(self, reason, *, private_owner=None):
        self.reason_class = reason if reason in REASONS else "probe_failed"
        self.private_owner = private_owner
        self.child_settled = True if private_owner is None else None
        self.settlement_failed = private_owner is not None
        self.private_diagnostics = None
        self.retained_sources = ()
        super().__init__(self.reason_class)


def require(value, reason):
    if value is not True:
        raise ProbeError(reason) from None


def prefer(first, later):
    if isinstance(first, (KeyboardInterrupt, SystemExit)):
        return first
    return later if first is None or isinstance(later, (KeyboardInterrupt, SystemExit)) else first


def close_handles(handles):
    """Attempt each owned handle once; caller retains objects on uncertainty."""
    errors = []
    for handle in reversed(handles):
        try:
            handle.close()
        except BaseException as error:
            errors.append(error)
    selected = None
    for error in errors:
        selected = prefer(selected, error)
    if selected is not None:
        selected.close_errors = tuple(errors)
        raise selected from None


def install_closer(owner, attribute):
    """Publish a one-attempt closer before a reused FD constructor enters.

Confirmed EBADF releases an FD record; every uncertain FD stays explicitly
registered. A repeated close returns the retained outcome without retrying OS
close. Root may reconcile uncertainty, but this adapter never guesses/retries.
"""
    owner._sentinel_close_attempted = False
    owner._sentinel_close_error = None
    def close():
        if owner._sentinel_close_attempted:
            if owner._sentinel_close_error is not None:
                raise owner._sentinel_close_error from None
            return
        owner._sentinel_close_attempted = True
        active, errors = sys.exc_info()[1], []
        for descriptor in tuple(getattr(owner, attribute, ())):
            try:
                os.close(descriptor)
            except BaseException as error:
                errors.append(error)
            confirmed = False
            try:
                os.fstat(descriptor)
                errors.append(ProbeError("source_changed"))
            except OSError as error:
                if error.errno == errno.EBADF:
                    confirmed = True
                else:
                    errors.append(error)
            except BaseException as error:
                errors.append(error)
            if confirmed:
                getattr(owner, attribute).remove(descriptor)
        if errors:
            selected = active
            for error in errors:
                selected = prefer(selected, error)
            selected.close_errors = tuple(errors)
            selected.source_handles_closed = False
            selected.retained_sources = getattr(selected, "retained_sources", ()) + (owner,)
            owner._sentinel_close_error = selected
            raise selected from None
    owner.close = close
    return owner


def safe_path(value):
    return (type(value) is str and len(value) <= 4096 and value.startswith("/")
            and re.fullmatch(r"/[A-Za-z0-9_./-]+", value) is not None
            and all(part not in ("", ".", "..") for part in value[1:].split("/")))


def isolation_profile(fixture):
    """Default-deny data/IPC/network boundary, independent of CLI sandbox flags.

Metadata is readable but user file data, keychain/auth IPC and networking have
no allow rule. No user preference service, SecurityServer, trustd or URL opener.
Opendirectory libinfo resolves POSIX user metadata only. System code and this
signed app are readable; execution is restricted to the exact signed CLI.
"""
    require(safe_path(fixture), "fixture_invalid")
    return '\n'.join((
        '(version 1)', '(deny default)',
        '(allow process-exec (literal "' + CLI + '"))',
        '(allow process-fork)', '(allow signal (target same-sandbox))',
        '(allow process-info* (target same-sandbox))', '(allow sysctl-read)',
        '(allow file-read-metadata)',
        # Darwin dyld ignition opens the root directory before loading the CLI.
        # Literal root permits that directory only, not descendant file data.
        '(allow file-read-data (literal "/"))',
        '(allow file-read* (subpath "/System") (subpath "/usr/lib")',
        ' (subpath "/Library/Apple/System/Library")',
        ' (subpath "/private/var/db/dyld") (subpath "' + APP + '")',
        ' (literal "/dev/null") (literal "/dev/random") (literal "/dev/urandom")',
        ' (literal "/private/etc/localtime") (subpath "' + fixture + '"))',
        '(allow file-write* (subpath "' + fixture + '") (literal "/dev/null"))',
        '(allow mach-lookup (global-name "com.apple.system.opendirectoryd.libinfo"))',
    ))


def environment(fixture):
    require(safe_path(fixture), "fixture_invalid")
    return {"HOME": fixture + "/home", "CODEX_HOME": fixture + "/codex",
            "TMPDIR": fixture + "/tmp", "PATH": SAFE_PATH, "LANG": "C",
            "LC_ALL": "C", "SHELL": "/bin/zsh"}


def commands(fixture):
    """Finite no-thread/no-turn/no-login/no-catalog-export CLI surface."""
    require(safe_path(fixture), "fixture_invalid")
    overrides = ("-c", 'cli_auth_credentials_store="file"',
                 "-c", "analytics.enabled=false")
    flags = tuple(item for key in FEATURE_KEYS for item in ("-c", "features." + key + "=false"))
    return (
        ("version", (CLI, "--version")),
        ("exec_help", (CLI, "exec", "--help")),
        ("mcp_list_help", (CLI, "mcp", "list", "--help")),
        ("app_server_help", (CLI, "app-server", "--help")),
        ("features", (CLI, "features", "list") + overrides + flags),
        ("schema", (CLI, "app-server", "generate-json-schema", "--out", fixture + "/schema") + overrides),
    )


class FixtureEnvelope:
    """Ignore only macOS provenance bookkeeping in newly allocated fixtures.

    This is not an installation/adoption policy. ACLs and every other xattr
    remain visible to the unchanged empty-envelope admission. Never read or
    remove attribute values, and never reuse this adapter for user payloads.
    """
    def __init__(self, platform):
        self.platform = platform

    def acl_count(self, descriptor):
        return self.platform.acl_count(descriptor)

    def xattr_names(self, descriptor):
        names = paths.Envelope(0, self.platform.xattr_names(descriptor)).xattr_names
        return tuple(name for name in names if name != "com.apple.provenance")


def require_fixture_envelope(parent, paths, *, platform=None):
    platform = paths.DarwinEnvelope() if platform is None else platform
    return paths.require_empty_envelope(parent, platform=FixtureEnvelope(platform))


class FixtureDisposition:
    """One private retained artifact handoff, never a cleanup/quota authority.

    The original failure consumer owns diagnosis and any separately validated
    retirement. Unknown/failed contents cannot be evicted by age or by parsing
    a public PASS/error report. Only the exact allocated owner is handed off.
    """
    actions = ("inspect-private-owner", "preserve-for-diagnosis")

    def __init__(self, owner, reason, *, child_settled, handles_closed):
        self.owner = owner
        self.reason = reason if reason in REASONS else "probe_failed"
        self.consumer = "current-doctor/root-recovery"
        self.child_settled = child_settled
        self.handles_closed = handles_closed
        self.diagnosis_consumed = False

    def inspect_private_owner(self):
        return self.owner

    def preserve_for_diagnosis(self, *, diagnostics_consumed=False):
        require(type(diagnostics_consumed) is bool, "fixture_invalid")
        self.diagnosis_consumed = diagnostics_consumed
        # Completion of diagnosis is not proof that deletion is safe. The same
        # exact owner and failed/unknown contents remain retained.
        return self.owner


class Fixture:
    """Fresh 0700 root and owned child boundaries; never adopted.

Only schema/cache contents may change. No credential material is seeded.
Retaining a failed fixture avoids recursive cleanup over vendor-written paths.
"""
    def __init__(self, scratch, home, uid, paths, *, custody_factory=custody_policy.Custody):
        self.handles = []
        self.path = None
        self.allocated = False
        self.schema_identities = {}
        self.child_identities = {}
        self.custody, self.slot = None, None
        self.uid, self.paths = uid, paths
        try:
            parent = paths.OwnedParent.open(scratch, home, uid)
            self.handles.append(parent)
            install_closer(parent, "_fds")
            require(parent.verify() is not False, "fixture_invalid")
            self.custody = custody_factory(scratch, home, uid, envelope=require_fixture_envelope)
            if self.custody is not None:
                self.slot = self.custody.reserve()
                leaf = self.custody.leaf(self.custody.records()[self.slot])
            else:
                leaf = "vendor-sentinel-" + secrets.token_hex(16)
            self.path = scratch + "/" + leaf
            os.mkdir(leaf, 0o700, dir_fd=parent.descriptor)
            self.allocated = True
            if self.custody is not None:
                self.custody.update(self.slot, root=custody_policy.identity(os.stat(leaf,
                    dir_fd=parent.descriptor, follow_symlinks=False)), state="allocated")
            parent.verify()
            self.root = paths.OwnedParent.open(self.path, home, uid)
            self.handles.append(self.root)
            install_closer(self.root, "_fds")
            require_fixture_envelope(self.root, paths)
            require(custody_policy.names(self.root.descriptor, 0) == [], "fixture_invalid")
            for leaf in ("home", "codex", "cwd", "tmp", "schema"):
                os.mkdir(leaf, 0o700, dir_fd=self.root.descriptor)
                self.child_identities[leaf] = custody_policy.identity(os.stat(leaf,
                    dir_fd=self.root.descriptor, follow_symlinks=False))
                if self.custody is not None:
                    self.custody.update(self.slot, children=dict(self.child_identities))
                child = paths.OwnedParent.open(self.path + "/" + leaf, home, uid)
                self.handles.append(child)
                install_closer(child, "_fds")
                require_fixture_envelope(child, paths)
                require(custody_policy.names(child.descriptor, 0) == [], "fixture_invalid")
            self.verify()
        except BaseException as original:
            selected = original
            try:
                self.close()
            except BaseException as error:
                selected = prefer(selected, error)
                selected.source_handles_closed = False
                selected.constructor_errors = (original, error)
            # Directory custody survives even a successful descriptor close.
            # A retained artifact is not the same claim as an open descriptor.
            selected.private_fixture = self
            selected.retained_sources = getattr(selected, "retained_sources", ()) + (self,)
            raise selected from None

    def verify(self):
        require(self.path is not None and len(self.handles) == 7, "fixture_invalid")
        for handle in self.handles:
            require(handle.verify() is not False, "fixture_invalid")
        for handle in self.handles[1:]:
            facts = os.fstat(handle.descriptor)
            require(facts.st_uid == self.uid and stat.S_IMODE(facts.st_mode) == 0o700,
                    "fixture_invalid")
            require_fixture_envelope(handle, self.paths)
        return True

    def schema(self, leaf=SCHEMA_LEAF):
        require(type(leaf) is str and leaf in (SCHEMA_LEAF, ENVELOPE_LEAF), "schema_output_invalid")
        self.verify()
        handle = self.handles[-1]
        descriptor = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                             dir_fd=handle.descriptor)
        primary, result = None, None
        try:
            before = os.fstat(descriptor)
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                    and before.st_uid == self.uid and not before.st_mode & 0o022
                    and 0 < before.st_size <= MAX_SCHEMA, "schema_output_invalid")
            chunks, total = [], 0
            while True:
                block = os.read(descriptor, min(65536, MAX_SCHEMA + 1 - total))
                if not block:
                    break
                chunks.append(block)
                total += len(block)
                require(total <= MAX_SCHEMA, "schema_output_invalid")
            after = os.fstat(descriptor)
            named = os.stat(leaf, dir_fd=handle.descriptor, follow_symlinks=False)
            keys = ("st_dev", "st_ino", "st_mode", "st_uid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
            stamp = lambda info: tuple(getattr(info, key) for key in keys)
            require(stamp(before) == stamp(after) == stamp(named) and total == before.st_size,
                    "schema_output_invalid")
            self.verify()
            result = b"".join(chunks)
            self.schema_identities[leaf] = stamp(after)
        except BaseException as error:
            primary = error
        finally:
            try:
                os.close(descriptor)
            except BaseException as error:
                primary = prefer(primary, error)
                primary.retained_schema_descriptor = descriptor
                primary.source_handles_closed = False
        if primary is not None:
            raise primary from None
        return result

    def retire(self):
        """Retire only the exact successful consumed fixture, never sweep scratch.

        Caller invokes this after command settlement, final attestation and
        other source closure. Unknown output, changed identity or metadata is a
        retained diagnostic, not authority to recursively remove vendor data.
        No age/prefix cleanup, symlink following or adoption occurs here.
        """
        self.verify()
        if self.custody is not None:
            # The two consumed schemas are capability evidence, not the whole
            # generated bundle. Seal the bounded output of this fresh, settled
            # fixture before asking the restart-capable owner to retire it.
            # Legacy retained fixtures cannot enter seal_output's allocated
            # state; their unrecorded descendants are never adopted here.
            try:
                self.custody.seal_output(self.slot, dict(self.schema_identities))
            except custody_policy.CustodyError:
                return False
            self.custody.retire(self.slot)
            self.slot = None
            return True
        parent, root = self.handles[:2]
        leaves = ("home", "codex", "cwd", "tmp", "schema")
        schema = self.handles[-1]
        try:
            if set(custody_policy.names(root.descriptor, len(leaves))) != set(leaves):
                return False
            if any(custody_policy.names(handle.descriptor, 0) for handle in self.handles[2:-1]):
                return False
            if (set(self.schema_identities) != {SCHEMA_LEAF, ENVELOPE_LEAF}
                    or set(custody_policy.names(schema.descriptor, 2)) != set(self.schema_identities)):
                return False
        except custody_policy.CustodyError:
            return False
        keys = ("st_dev", "st_ino", "st_mode", "st_uid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        def exact(leaf):
            facts = os.stat(leaf, dir_fd=schema.descriptor, follow_symlinks=False)
            return tuple(getattr(facts, key) for key in keys) == self.schema_identities[leaf]
        if not all(exact(leaf) for leaf in self.schema_identities):
            return False
        if self.custody is not None:
            self.custody.update(self.slot, state="retiring", schemas=dict(self.schema_identities))
        # Validate the entire known set before the first removal. Each deletion
        # is descriptor-relative and rechecks the held chain/identity. This is
        # not filesystem CAS against an uncooperative same-user writer.
        for leaf in self.schema_identities:
            self.verify()
            require(exact(leaf), "fixture_invalid")
            os.unlink(leaf, dir_fd=schema.descriptor)
            os.fsync(schema.descriptor)
        remaining = list(self.handles[2:])
        for leaf, handle in zip(leaves, self.handles[2:]):
            parent.verify()
            root.verify()
            for pending in remaining:
                pending.verify()
                require_fixture_envelope(pending, self.paths)
            require(custody_policy.names(handle.descriptor, 0) == [], "fixture_invalid")
            os.rmdir(leaf, dir_fd=root.descriptor)
            os.fsync(root.descriptor)
            # Removed child chains cannot be checked again. Release each owned
            # handle immediately and exclude it from remaining chain checks.
            handle.close()
            remaining.remove(handle)
        root.verify()
        require(custody_policy.names(root.descriptor, 0) == [], "fixture_invalid")
        parent.verify()
        os.rmdir(Path(self.path).name, dir_fd=parent.descriptor)
        os.fsync(parent.descriptor)
        if self.custody is not None:
            self.custody.release_absent(self.slot)
            self.slot = None
        return True

    def close(self):
        primary = None
        try:
            close_handles(self.handles)
            self.handles = []
        except BaseException as error:
            primary = error
        if self.custody is not None:
            try:
                if self.slot is not None:
                    if self.custody.records()[self.slot]["state"] != "retiring":
                        self.custody.update(self.slot, state="retained", reason="retained_for_diagnosis",
                                            schemas=dict(self.schema_identities))
            except BaseException as error:
                primary = prefer(primary, error)
            try:
                self.custody.close()
                self.custody = None
            except BaseException as error:
                primary = prefer(primary, error)
        if primary is not None:
            raise primary from None


def vendor_source_type(readiness):
    """Sentinel-only 1 GiB streamed bound for the two sealed vendor files.

The immutable readiness reader has a 512 MiB cap. Reuse its constructor,
held descriptor, complete path-chain rechecks, verify and close lifecycle;
retain its _read checks exactly with this explicit bound and no buffering.
No other source or kept-data read receives the expanded bound.
"""
    class VendorSourceFile(readiness.SourceFile):
        def __init__(self, path, root, uid, budget, *, keep=False,
                     syscalls=os, opener=paths.OwnedParent.open):
            require(str(path) in VENDOR_FILES and str(root) == APP and keep is False,
                    "source_changed")
            super().__init__(path, root, uid, budget, keep=False,
                             syscalls=syscalls, opener=opener)

        def _read(self, parent):
            require(self.path in VENDOR_FILES and self.root == APP and self.keep is False,
                    "source_changed")
            self.budget.check()
            descriptor = self.fds[0]
            facts = self.os.fstat(descriptor)
            maximum = VENDOR_MAX_SOURCE
            readiness.require(stat.S_ISREG(facts.st_mode) and facts.st_uid == self.uid
                    and facts.st_nlink == 1 and not facts.st_mode & 0o022
                    and not facts.st_mode & 0o7000
                    and 0 <= facts.st_size <= maximum and readiness.file_stamp(facts) == self.stamp)
            parent.verify()
            self.os.lseek(descriptor, 0, os.SEEK_SET)
            digest, size = hashlib.sha256(), 0
            while True:
                self.budget.check()
                block = self.os.read(descriptor, min(65536, maximum + 1 - size))
                if not block:
                    break
                size += len(block)
                readiness.require(size <= maximum)
                digest.update(block)
            named = self.os.stat(Path(self.path).name, dir_fd=parent.descriptor, follow_symlinks=False)
            readiness.require(readiness.file_stamp(self.os.fstat(descriptor)) == self.stamp
                    and readiness.file_stamp(named) == self.stamp and size == facts.st_size
                    and tuple(parent._identities) == self.chain)
            parent.verify()
            return None, digest.hexdigest()
    return VendorSourceFile


def observe(*, root, home, uid, budget, source_guard, readiness, process, policy,
            fixture_consumer=None):
    """One scoped observation. Caller must bind this source and dependencies.

Deadline/output/child ownership reuses phase5_probe_process/catalog. Successful
return proves source/fixture descriptors closed and direct children settled,
not descendant supervision, a hard kernel deadline, or entire machine health.
"""
    require(callable(source_guard), "source_changed")
    require(fixture_consumer is None or callable(fixture_consumer), "fixture_invalid")
    sources, fixture, app = [], None, None
    primary = None
    operation_error = None
    result = None
    stage = "source_changed"
    require(source_guard() is True, "source_changed")
    P = importlib.machinery.SourceFileLoader("sentinel_vendor_attestation", str(Path(root) / "bin/phase5-preflight")).load_module()
    last_command = None
    assessment = None
    close_errors = []
    signing_errors = []

    def source(path, source_root, source_uid, *, keep=True):
        cls = vendor_source_type(readiness) if str(path) in VENDOR_FILES else readiness.SourceFile
        item = cls.__new__(cls)
        sources.append(item)
        install_closer(item, "fds")
        cls.__init__(item, path, source_root, source_uid, budget, keep=keep)
        return item

    def guard():
        budget.check()
        require(source_guard() is True, "source_changed")
        if app is not None:
            app.recheck()
        for item in sources:
            require(item.verify() is True, "source_changed")
        if fixture is not None:
            fixture.verify()
        return True

    def command(argv, *, isolated):
        nonlocal last_command
        if isolated:
            args = ("/usr/bin/sandbox-exec", "-p", isolation_profile(fixture.path)) + tuple(argv)
            env, cwd = environment(fixture.path), fixture.path + "/cwd"
        else:
            args, env, cwd = tuple(argv), {"PATH": SAFE_PATH, "LANG": "C", "LC_ALL": "C"}, root
        launch = SimpleNamespace(argv=args, environment=env, cwd=cwd)
        expected = (args, dict(env), cwd)
        def admit(value):
            require((value.argv, value.environment, value.cwd) == expected, "command_failed")
            return guard()
        if fixture is not None and getattr(fixture, "custody", None) is not None:
            fixture.custody.update(fixture.slot, state="inflight", settled=False)
        try:
            value = process.command(launch, budget, 25.0, admit_launch=admit,
                catalog=readiness.catalog, process_factory=readiness.catalog.subprocess.Popen)
        except BaseException as error:
            # Only the process owner's explicit settled observation can finish
            # the durable command obligation; ordinary exceptions infer nothing.
            if (fixture is not None and getattr(fixture, "custody", None) is not None
                    and getattr(error, "child_settled", None) is True
                    and getattr(error, "private_owner", None) is None):
                try:
                    fixture.custody.update(fixture.slot, state="allocated", settled=True)
                except BaseException as later:
                    error.custody_settlement_error = later
                    if getattr(later, "source_handles_closed", True) is not True:
                        error.source_handles_closed = False
            raise
        if fixture is not None and getattr(fixture, "custody", None) is not None:
            fixture.custody.update(fixture.slot, state="allocated", settled=True)
        last_command = (tuple(argv), value)
        guard()
        return value

    try:
        guard()
        # Publish before __init__: constructor failure still has an actual owner.
        observer_type = P._AppBundleObservation
        app = observer_type.__new__(observer_type)
        install_closer(app, "descriptors")
        observer_type.__init__(app, Path(APP))
        owner = app.bound_metadata[0][2]
        require(owner in (0, uid), "cli_identity_invalid")
        cli = source(CLI, APP, owner, keep=False)
        require(bool(cli.stamp[4] & 0o111), "cli_identity_invalid")
        source(ASAR, APP, owner, keep=False)
        contract_file = source(Path(root) / "manifests/codex-contract.json", home, uid)
        contract = readiness.strict_json(contract_file.data)
        def attest(argv, environment=None):
            del environment
            try:
                value = command(argv, isolated=False)
                return SimpleNamespace(returncode=value.returncode,
                    stdout=(value.stdout + value.stderr).decode("utf-8", "strict"))
            except BaseException as error:
                signing_errors.append(error)
                raise
        P.run = attest
        # Borrow the same real held app, never allocate a second hidden owner.
        def borrow(bundle):
            require(str(bundle) == APP, "cli_identity_invalid")
            return SimpleNamespace(plist_bytes=app.plist_bytes, recheck=app.recheck, close=lambda: None)
        P._AppBundleObservation = borrow
        def attestation():
            value = P.app_attestation(contract)
            if signing_errors:
                selected = None
                for error in signing_errors:
                    selected = prefer(selected, error)
                raise selected from None
            require(type(value) is str, "signature_invalid")
            return value
        stage = "signature_invalid"
        app_version = attestation()
        stage = "fixture_invalid"
        # Publish the allocated owner before initialization can create a root
        # and fail. Constructor exceptions must not turn it into lost scratch.
        fixture = Fixture.__new__(Fixture)
        Fixture.__init__(fixture, home + "/AIDev/scratch", home, uid, paths)
        outputs = {}
        stage = "command_failed"
        for name, argv in commands(fixture.path):
            value = command(argv, isolated=True)
            require(value.returncode == 0, "command_failed")
            # Bounded stderr is diagnostic, not the consumed success contract.
            # Command status and parsed stdout/schema still decide compatibility;
            # no diagnostic bytes become public evidence.
            outputs[name] = value.stdout
        stage = "schema_output_invalid"
        schema_raw = fixture.schema()
        envelopes_raw = fixture.schema(ENVELOPE_LEAF)
        schema = policy.parse_schema(schema_raw)
        envelopes = policy.parse_schema(envelopes_raw)
        stage = "capabilities_incompatible"
        assessment = policy.assess_capabilities(
            version=outputs["version"], exec_help=outputs["exec_help"],
            mcp_list_help=outputs["mcp_list_help"], app_server_help=outputs["app_server_help"],
            features=outputs["features"], schema=schema, envelopes=envelopes)
        require(assessment.get("compatible") is True, "capabilities_incompatible")
        require(P.version_at_or_above(outputs["version"].decode("utf-8").strip(),
                                    contract["cli"]["observedVersion"]), "cli_identity_invalid")
        stage = "signature_invalid"
        require(attestation() == app_version, "signature_invalid")
        guard()
        result = {"status": "PASS", "scope": "signed-vendor-offline-capabilities",
                  "reasonCodes": [], "childSettled": True, "sourceHandlesClosed": True,
                  "capabilityCommands": len(commands(fixture.path)),
                  "cliSha256": cli.digest, "schemaSha256": hashlib.sha256(schema_raw).hexdigest(),
                  "envelopesSha256": hashlib.sha256(envelopes_raw).hexdigest(),
                  "appVersion": app_version, "checks": assessment["checks"],
                  "modelRequests": 0, "userConfigurationWrites": 0,
                  "sessionStartInstalled": False, "phase6Allowed": False}
    except BaseException as error:
        primary = error
        operation_error = error
    finally:
        pending_owner = getattr(primary, "private_owner", None)
        # Unresolved child custody owns these live guards until root reconciles it.
        if pending_owner is None:
            for item in tuple(reversed(sources)) + (app,):
                if item is not None:
                    try:
                        item.close()
                    except BaseException as error:
                        close_errors.append(error)
                        primary = prefer(primary, error)
            if fixture is not None:
                if primary is None:
                    try:
                        stage = "fixture_invalid"
                        result["fixtureRetired"] = fixture.retire()
                    except BaseException as error:
                        operation_error = error
                        primary = prefer(primary, error)
                try:
                    fixture.close()
                except BaseException as error:
                    close_errors.append(error)
                    primary = prefer(primary, error)
    if primary is not None:
        # Preserve the actual process owner and original interruption. Do not
        # turn missing/ambiguous settlement into a retry or a successful result.
        failure = primary if (isinstance(primary, (KeyboardInterrupt, SystemExit))
            or getattr(primary, "private_owner", None) is not None) else ProbeError(getattr(primary, "reason_class", stage))
        failure.private_diagnostics = (stage, last_command, assessment, primary, tuple(close_errors))
        failure.private_fixture = fixture
        all_errors = (operation_error,) + tuple(signing_errors) + tuple(close_errors)
        inherited = tuple(owner for error in all_errors if error is not None
                          for owner in getattr(error, "retained_sources", ()))
        failure.retained_sources = inherited + (tuple(sources) + (fixture, app) if close_errors or pending_owner is not None else ())
        failure.source_handles_closed = (not close_errors and pending_owner is None
            and all(getattr(error, "source_handles_closed", True) is True for error in all_errors if error is not None))
        failure.private_errors = all_errors
        failure.child_settled = True if pending_owner is None else None
        failure.private_fixture_disposition = (FixtureDisposition(fixture,
            getattr(failure, "reason_class", stage), child_settled=failure.child_settled,
            handles_closed=failure.source_handles_closed) if fixture is not None else None)
        # The original exception always owns its private handoff. An optional
        # consumer must never replace or suppress that failure.
        raise failure from None
    if not result.get("fixtureRetired", False) and fixture_consumer is not None:
        disposition = FixtureDisposition(fixture, "fixture_invalid",
            child_settled=True, handles_closed=True)
        try:
            fixture_consumer(disposition)
        except BaseException as error:
            error.private_fixture = fixture
            error.private_fixture_disposition = disposition
            error.retained_sources = getattr(error, "retained_sources", ()) + (fixture,)
            error.source_handles_closed = True
            error.child_settled = True
            raise
    return result
