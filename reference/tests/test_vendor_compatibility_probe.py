"""No vendor, signing, sandbox or model processes: connected injected tests."""

import json
import hashlib
import ast
import inspect
import os
import stat
import errno
import tempfile
from pathlib import Path
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch

from lib import vendor_compatibility_probe as V


FIXTURE = "/Users/fixture/AIDev/scratch/vendor-sentinel-test"
DIRECT_CLI = "/Applications/ChatGPT.app/Contents/Resources/codex-cli/CodexCLI.app/Contents/MacOS/codex"
LEGACY_CLI = "/Applications/ChatGPT.app/Contents/Resources/codex"
WRAPPER_CLI = "/Applications/ChatGPT.app/Contents/Resources/codex-cli/bin/codex"


class FixtureEnvelopeTests(unittest.TestCase):
    def check_envelope(self, names=(), acl=0, mode=0o700, generic=False):
        from lib import phase5_runtime_paths as P
        with tempfile.TemporaryDirectory(dir="/private/tmp") as directory:
            directory = os.path.realpath(directory)
            os.chmod(directory, mode)
            parent = P.OwnedParent.open(directory, directory, os.getuid())
            try:
                platform = NS(acl_count=lambda fd: acl, xattr_names=lambda fd: names)
                if generic:
                    return P.require_empty_envelope(parent, platform=platform)
                return V.require_fixture_envelope(parent, P, platform=platform)
            finally:
                parent.close()

    def test_new_fixture_accepts_empty_or_provenance_only(self):
        for names in ((), ("com.apple.provenance",)):
            self.assertEqual(self.check_envelope(names).xattr_names, ())

    def test_unknown_and_quarantine_metadata_still_fail(self):
        for names in (("com.apple.quarantine",), ("user.untrusted",),
                      ("com.apple.provenance", "com.apple.quarantine")):
            with self.subTest(names=names), self.assertRaises(V.paths.PathsError):
                self.check_envelope(names)

    def test_acl_or_wrong_mode_still_fail_even_with_provenance(self):
        for options in ({"acl": 1}, {"mode": 0o755}):
            with self.subTest(options=options), self.assertRaises(V.paths.PathsError):
                self.check_envelope(("com.apple.provenance",), **options)

    def test_malformed_metadata_is_not_filtered_into_acceptance(self):
        for names in (["com.apple.provenance"], ("com.apple.provenance",) * 2,
                      (None,), ("",)):
            with self.subTest(names=names), self.assertRaises(V.paths.PathsError):
                self.check_envelope(names)

    def test_generic_payload_policy_still_rejects_provenance(self):
        with self.assertRaises(V.paths.PathsError):
            self.check_envelope(("com.apple.provenance",), generic=True)

    def test_connected_fixture_constructor_and_later_unknown_attribute(self):
        names = [("com.apple.provenance",)]
        platform = NS(acl_count=lambda fd: 0, xattr_names=lambda fd: names[0])
        with tempfile.TemporaryDirectory(dir="/private/tmp") as directory:
            directory = os.path.realpath(directory)
            os.chmod(directory, 0o700)
            with patch.object(V.paths, "DarwinEnvelope", return_value=platform):
                fixture = V.Fixture(directory, directory, os.getuid(), V.paths, custody_factory=lambda *a, **k: None)
                try:
                    self.assertTrue(fixture.verify())
                    self.assertEqual(len(fixture.handles), 7)
                    names[0] = ("com.apple.provenance", "com.apple.quarantine")
                    with self.assertRaises(V.paths.PathsError):
                        fixture.verify()
                finally:
                    fixture.close()

    def test_metadata_drift_between_observations_rejects(self):
        observations = iter(((), ("com.apple.quarantine",)))
        platform = NS(acl_count=lambda fd: 0,
                      xattr_names=lambda fd: next(observations))
        with tempfile.TemporaryDirectory(dir="/private/tmp") as directory:
            directory = os.path.realpath(directory)
            parent = V.paths.OwnedParent.open(directory, directory, os.getuid())
            try:
                with self.assertRaises(V.paths.PathsError):
                    V.require_fixture_envelope(parent, V.paths, platform=platform)
            finally:
                parent.close()


class PlanTests(unittest.TestCase):
    def test_packaged_macho_is_the_only_executable_allowed(self):
        self.assertEqual(V.CLI, DIRECT_CLI)
        profile = V.isolation_profile(FIXTURE)
        execution_rules = [line for line in profile.splitlines() if "process-exec" in line]
        self.assertEqual(execution_rules, ['(allow process-exec (literal "' + DIRECT_CLI + '"))'])
        for forbidden in (LEGACY_CLI, WRAPPER_CLI, "/bin/sh", "/bin/zsh"):
            self.assertNotIn('(literal "' + forbidden + '")', profile)
        self.assertTrue(all(argv[0] == DIRECT_CLI for _, argv in V.commands(FIXTURE)))

    def test_profile_starts_closed_and_never_allows_network_or_security_service(self):
        profile = V.isolation_profile(FIXTURE)
        self.assertIn("(deny default)", profile)
        for forbidden in ("allow default", "allow network", "SecurityServer", "securityd",
                          "trustd", "cfprefsd", "user-preference", '(subpath "/Users")'):
            self.assertNotIn(forbidden, profile)
        self.assertIn('(allow process-exec (literal "' + V.CLI + '"))', profile)

    def test_dyld_root_directory_read_does_not_allow_descendant_data(self):
        profile = V.isolation_profile(FIXTURE)
        self.assertIn('(allow file-read-data (literal "/"))', profile)
        self.assertNotIn('(subpath "/")', profile)
        self.assertNotIn('(allow file-read*)', profile)
        self.assertNotIn('(allow file-read-data)', profile)
        self.assertNotIn('(allow file-map-executable)', profile)
        self.assertEqual(profile.count('(literal "/")'), 1)

    def test_profile_rejects_path_injection_and_noncanonical_paths(self):
        for path in (None, True, "/", "/tmp/../home", "/tmp//a", '/tmp/a") (allow default)',
                     "/tmp/a\nb", "/tmp/a\\b"):
            with self.subTest(path=path), self.assertRaises(V.ProbeError):
                V.isolation_profile(path)

    def test_environment_does_not_inherit_owner_or_credentials(self):
        env = V.environment(FIXTURE)
        self.assertEqual(set(env), {"HOME", "CODEX_HOME", "TMPDIR", "PATH", "LANG", "LC_ALL", "SHELL"})
        for key in ("HOME", "CODEX_HOME", "TMPDIR"):
            self.assertTrue(env[key].startswith(FIXTURE + "/"))

    def test_commands_are_finite_non_model_queries(self):
        rows = V.commands(FIXTURE)
        self.assertEqual([name for name, _ in rows],
                         ["version", "exec_help", "mcp_list_help", "app_server_help", "features", "schema"])
        for _, argv in rows:
            self.assertEqual(argv[0], V.CLI)
            self.assertNotIn("login", argv)
            self.assertNotIn("--trust", argv)
        self.assertEqual(rows[1][1], (V.CLI, "exec", "--help"))
        self.assertIn('cli_auth_credentials_store="file"', rows[-1][1])
        for key in V.FEATURE_KEYS:
            self.assertIn("features." + key + "=false", rows[-2][1])


class FixtureRetirementTests(unittest.TestCase):
    def fixture(self, directory):
        os.chmod(directory, 0o700)
        fixture = V.Fixture(directory, directory, os.getuid(), V.paths, custody_factory=lambda *a, **k: None)
        for leaf in (V.SCHEMA_LEAF, V.ENVELOPE_LEAF):
            target = Path(fixture.path) / "schema" / leaf
            target.write_bytes(b'{"public":"fixture"}')
            target.chmod(0o600)
            fixture.schema(leaf)
        return fixture

    def test_constructor_collision_is_retained_without_claiming_allocation(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as directory:
            os.chmod(directory, 0o700)
            token = "a" * 32
            foreign = Path(directory) / ("vendor-sentinel-" + token)
            foreign.mkdir(mode=0o700)
            (foreign / "foreign").write_bytes(b"preserve")
            owner = V.Fixture.__new__(V.Fixture)
            with patch.object(V.secrets, "token_hex", return_value=token):
                with self.assertRaises(FileExistsError) as caught:
                    V.Fixture.__init__(owner, directory, directory, os.getuid(), V.paths, custody_factory=lambda *a, **k: None)
            self.assertFalse(owner.allocated)
            self.assertIs(caught.exception.private_fixture, owner)
            self.assertIn(owner, caught.exception.retained_sources)
            self.assertEqual((foreign / "foreign").read_bytes(), b"preserve")

    def test_success_retires_only_exact_owned_consumed_fixture_and_repeat_is_bounded(self):
        platform = NS(acl_count=lambda fd: 0, xattr_names=lambda fd: ())
        with tempfile.TemporaryDirectory(dir="/private/tmp") as directory, patch.object(V.paths, "DarwinEnvelope", return_value=platform):
            for _ in range(3):
                fixture = self.fixture(directory)
                try:
                    self.assertTrue(fixture.retire())
                    self.assertFalse(Path(fixture.path).exists())
                finally:
                    fixture.close()
                self.assertEqual(os.listdir(directory), [])

    def test_unknown_entries_and_symlinks_remain_wholly_untouched(self):
        platform = NS(acl_count=lambda fd: 0, xattr_names=lambda fd: ())
        for mutation in ("root-file", "schema-file", "cache-file", "symlink", "replaced-schema"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory(dir="/private/tmp") as directory, patch.object(V.paths, "DarwinEnvelope", return_value=platform):
                fixture = self.fixture(directory)
                root = Path(fixture.path)
                target = root / "schema" / V.SCHEMA_LEAF
                if mutation == "root-file":
                    (root / "foreign").write_bytes(b"foreign")
                elif mutation == "schema-file":
                    (root / "schema" / "foreign.json").write_bytes(b"foreign")
                elif mutation == "cache-file":
                    (root / "codex" / "foreign").write_bytes(b"foreign")
                elif mutation == "symlink":
                    target.unlink()
                    target.symlink_to(root / "schema" / V.ENVELOPE_LEAF)
                else:
                    target.write_bytes(b"changed")
                try:
                    before = sorted(str(path.relative_to(root)) for path in root.rglob("*"))
                    self.assertFalse(fixture.retire())
                    self.assertEqual(before, sorted(str(path.relative_to(root)) for path in root.rglob("*")))
                    self.assertTrue((root / "schema" / V.ENVELOPE_LEAF).exists())
                finally:
                    fixture.close()

    def test_directory_swap_denies_without_removing_outside_data(self):
        platform = NS(acl_count=lambda fd: 0, xattr_names=lambda fd: ())
        with tempfile.TemporaryDirectory(dir="/private/tmp") as directory, patch.object(V.paths, "DarwinEnvelope", return_value=platform):
            fixture = self.fixture(directory)
            root = Path(fixture.path)
            original = root / "codex"
            original.rename(root / "saved-codex")
            original.mkdir(mode=0o700)
            (original / "foreign").write_bytes(b"foreign")
            try:
                with self.assertRaises(Exception):
                    fixture.retire()
                self.assertEqual((original / "foreign").read_bytes(), b"foreign")
                self.assertTrue((root / "schema" / V.SCHEMA_LEAF).exists())
            finally:
                fixture.close()

    def test_retirement_close_uncertainty_keeps_actual_descriptor_owner(self):
        platform = NS(acl_count=lambda fd: 0, xattr_names=lambda fd: ())
        with tempfile.TemporaryDirectory(dir="/private/tmp") as directory, patch.object(V.paths, "DarwinEnvelope", return_value=platform):
            fixture = self.fixture(directory)
            handle = fixture.handles[2]
            descriptor = handle.descriptor
            actual_close = os.close
            attempted = []
            def close(fd):
                attempted.append(fd)
                if fd == descriptor:
                    raise OSError("synthetic uncertain close")
                actual_close(fd)
            try:
                with patch.object(os, "close", side_effect=close):
                    with self.assertRaises(OSError) as caught:
                        fixture.retire()
                    self.assertFalse(caught.exception.source_handles_closed)
                    self.assertIn(handle, caught.exception.retained_sources)
                    self.assertIn(descriptor, handle._fds)
                    with self.assertRaises(OSError):
                        fixture.close()
                    self.assertEqual(attempted.count(descriptor), 1)
                    self.assertTrue(os.fstat(descriptor))
            finally:
                # Explicit test-owner reconciliation, never adapter retry.
                actual_close(descriptor)
                handle._fds.remove(descriptor)


class Harness:
    def __init__(self):
        self.calls, self.sources, self.apps = [], [], []
        self.guard_count = 0
        self.guard_failure = False
        self.fail_command = None
        self.close_failure = False
        self.command_exception = None
        self.stderr = b""
        self.source_reads = 0
        self.missing_sources = set()
        self.changed_source = None
        self.assessment = {"compatible": True, "checks": {"schema": True}, "reasonCodes": []}
        harness = self

        class App:
            def __init__(self, path):
                self.bound_metadata = [(0, 0, 501)]
                self.descriptors = []
                self.plist_bytes = b"fixture-plist"
                self.closed = False
                harness.apps.append(self)
            def recheck(self):
                return None
            def close(self):
                self.closed = True

        class Source:
            def __init__(self, path, *args, **kwargs):
                self.path, self.root, self.keep = str(path), str(args[0]), kwargs.get("keep", True)
                self.closed = False
                self.fds = []
                self.stamp = (0, 0, 0, 0, 0o100755)
                self.digest = "a" * 64
                self.data = b'{"cli":{"observedVersion":"codex-cli 0.1.0"}}'
                harness.sources.append(self)
                if self.path in harness.missing_sources:
                    raise FileNotFoundError(self.path)
            def verify(self):
                harness.source_reads += 1
                return self.path != harness.changed_source
            def close(self):
                if harness.close_failure:
                    raise OSError("synthetic-close")
                self.closed = True

        class Fixture:
            path = FIXTURE
            def __init__(self, *args):
                self.closed = False
                harness.fixture = self
            def verify(self):
                return True
            def schema(self, leaf=V.SCHEMA_LEAF):
                return b'{"definitions":{}}'
            def retire(self):
                self.retired = True
                return True
            def close(self):
                self.closed = True
                if harness.close_failure:
                    raise harness.close_failure if isinstance(harness.close_failure, BaseException) else OSError("fixture close")

        self.fixture_class = Fixture
        self.preflight = NS(_AppBundleObservation=App,
            app_attestation=self.attest, version_at_or_above=lambda a, b: True)
        self.readiness = NS(SourceFile=Source, strict_json=json.loads,
            earliest=lambda a, b: b if a is None else a,
            catalog=NS(subprocess=NS(Popen=lambda *a, **k: None)))
        self.process = NS(command=self.command)
        self.policy = NS(parse_schema=json.loads, assess_capabilities=lambda **kwargs: self.assessment)
        self.budget = NS(check=lambda: None)

    def guard(self):
        self.guard_count += 1
        return not self.guard_failure

    def attest(self, contract):
        self.preflight.run(("/usr/bin/codesign", "-dvv", V.APP))
        return "26.905.11957"

    def command(self, launch, budget, maximum, **kwargs):
        self.calls.append(launch)
        self.asserted = kwargs["admit_launch"](launch)
        if self.command_exception is not None:
            raise self.command_exception
        is_fail = self.fail_command is not None and self.fail_command in launch.argv
        return NS(returncode=1 if is_fail else 0,
                  stdout=b"private command output" if is_fail else b"codex-cli 0.200.0\n", stderr=self.stderr)

    def observe(self, **options):
        with patch.object(V.importlib.machinery, "SourceFileLoader") as loader, \
                patch.object(V, "Fixture", self.fixture_class):
            loader.return_value.load_module.return_value = self.preflight
            return V.observe(root="/Users/fixture/AIDev/control", home="/Users/fixture", uid=501,
                budget=self.budget, source_guard=self.guard, readiness=self.readiness,
                process=self.process, policy=self.policy, **options)


class ConnectedTests(unittest.TestCase):
    def test_complete_generated_bundle_retires_and_next_probe_can_run(self):
        """Exercise the real filesystem owner, with inert injected CLI output.

        The two consumed schemas are a subset of the 317-file vendor bundle;
        successful repeated observations must not accumulate slot reservations.
        """
        from lib import vendor_fixture_custody as C
        actual_fixture = V.Fixture
        platform = NS(acl_count=lambda fd: 0, xattr_names=lambda fd: ())
        with tempfile.TemporaryDirectory(dir="/private/tmp") as directory, \
                patch.object(V.paths, "DarwinEnvelope", return_value=platform):
            for _ in range(3):
                h = Harness()
                class LocalFixture(actual_fixture):
                    def __init__(self, *args):
                        h.fixture = self
                        super().__init__(directory, directory, os.getuid(), V.paths)
                h.fixture_class = LocalFixture
                original = h.process.command
                def command(launch, *args, **kwargs):
                    if 'generate-json-schema' in launch.argv:
                        root = Path(h.fixture.path)
                        (root / 'codex' / 'tmp').mkdir(mode=0o755)
                        (root / 'codex' / 'tmp' / 'arg0').mkdir(mode=0o755)
                        for version in ('v1', 'v2'):
                            (root / 'schema' / version).mkdir(mode=0o755)
                        leaves = list(C.SCHEMAS)
                        leaves += ['Extra%d.json' % i for i in range(35)]
                        leaves += ['v1/Type%d.json' % i for i in range(140)]
                        leaves += ['v2/Type%d.json' % i for i in range(140)]
                        self.assertEqual(len(leaves), 317)
                        for leaf in leaves:
                            target = root / 'schema' / leaf
                            target.write_bytes(b'{"definitions":{}}')
                            target.chmod(0o644)
                    return original(launch, *args, **kwargs)
                h.process.command = command
                result = h.observe()
                self.assertEqual(result['status'], 'PASS')
                self.assertTrue(result['fixtureRetired'])
                self.assertFalse(Path(h.fixture.path).exists())
                with C.Custody(directory, directory, os.getuid(), envelope=lambda *a: None) as custody:
                    self.assertEqual(custody.status()['outstanding'], 0)

    def test_constructor_envelope_failure_after_allocation_retains_exact_owner(self):
        actual_fixture = V.Fixture
        with tempfile.TemporaryDirectory(dir="/private/tmp") as directory:
            os.chmod(directory, 0o700)
            h = Harness()
            class ConstructorFixture(actual_fixture):
                def __init__(self, *args):
                    h.fixture = self
                    super().__init__(directory, directory, os.getuid(), V.paths, custody_factory=lambda *a, **k: None)
            h.fixture_class = ConstructorFixture
            with patch.object(V, "require_fixture_envelope", side_effect=V.ProbeError("fixture_invalid")):
                with self.assertRaises(V.ProbeError) as caught:
                    h.observe()
            error = caught.exception
            self.assertEqual(error.reason_class, "fixture_invalid")
            self.assertIs(error.private_fixture, h.fixture)
            self.assertIn(h.fixture, error.retained_sources)
            self.assertTrue(error.source_handles_closed)
            self.assertEqual(h.fixture.handles, [])
            self.assertTrue(Path(h.fixture.path).is_dir())
            self.assertEqual(len(os.listdir(directory)), 1)
            self.assertEqual(len(h.calls), 1)  # signing only; no capability launch
            disposition = error.private_fixture_disposition
            self.assertIs(disposition.inspect_private_owner(), h.fixture)
            self.assertEqual(disposition.consumer, "current-doctor/root-recovery")
            self.assertEqual(disposition.actions, ("inspect-private-owner", "preserve-for-diagnosis"))
            self.assertIs(disposition.preserve_for_diagnosis(diagnostics_consumed=True), h.fixture)
            self.assertTrue(disposition.diagnosis_consumed)
            self.assertTrue(Path(h.fixture.path).is_dir())
            self.assertNotIn(h.fixture.path, str(error))

    def test_unknown_success_handoff_is_private_not_in_public_parser_result(self):
        h = Harness()
        h.fixture_class.retire = lambda fixture: False
        captures = []
        result = h.observe(fixture_consumer=captures.append)
        self.assertFalse(result["fixtureRetired"])
        self.assertEqual(len(captures), 1)
        self.assertIs(captures[0].inspect_private_owner(), h.fixture)
        self.assertTrue(captures[0].child_settled and captures[0].handles_closed)
        self.assertNotIn(FIXTURE, repr(result))
        self.assertTrue(h.fixture.closed)

    def test_private_handoff_consumer_failure_keeps_exact_artifact(self):
        h = Harness()
        h.fixture_class.retire = lambda fixture: False
        original = KeyboardInterrupt()
        def consumer(disposition):
            raise original
        with self.assertRaises(KeyboardInterrupt) as caught:
            h.observe(fixture_consumer=consumer)
        self.assertIs(caught.exception, original)
        self.assertIs(original.private_fixture, h.fixture)
        self.assertIs(original.private_fixture_disposition.owner, h.fixture)
        self.assertIn(h.fixture, original.retained_sources)
        self.assertTrue(original.source_handles_closed)

    def test_unsettled_failure_private_disposition_retains_live_fixture(self):
        h = Harness()
        child = object()
        original = V.ProbeError("process_unsettled", private_owner=child)
        command = h.process.command
        def fail_capability(launch, *args, **kwargs):
            if launch.argv[0] == "/usr/bin/sandbox-exec":
                h.command_exception = original
            return command(launch, *args, **kwargs)
        h.process.command = fail_capability
        with self.assertRaises(V.ProbeError) as caught:
            h.observe()
        self.assertIs(caught.exception, original)
        self.assertIs(original.private_owner, child)
        self.assertIs(original.private_fixture_disposition.owner, h.fixture)
        self.assertIsNone(original.private_fixture_disposition.child_settled)
        self.assertFalse(original.private_fixture_disposition.handles_closed)
        self.assertFalse(h.fixture.closed)

    def test_success_stderr_is_private_and_does_not_override_consumed_semantics(self):
        h = Harness()
        h.stderr = b"benign future vendor diagnostic\n"
        result = h.observe()
        self.assertEqual(result["status"], "PASS")
        self.assertTrue(result["fixtureRetired"])
        self.assertNotIn("diagnostic", repr(result))
        h = Harness()
        h.stderr = b"benign diagnostic\n"
        h.assessment = {"compatible": False}
        with self.assertRaises(V.ProbeError):
            h.observe()
        self.assertFalse(getattr(h.fixture, "retired", False))

    def test_every_launch_admission_and_postcommand_boundary_detects_drift(self):
        # Both signing commands and all six capability commands use admission.
        for boundary in ("admission", "postcommand"):
            for command_index in range(8):
                with self.subTest(boundary=boundary, command=command_index):
                    h = Harness()
                    original = h.process.command
                    def drift(launch, *args, **kwargs):
                        selected = len(h.calls) == command_index
                        if selected and boundary == "admission":
                            h.guard_failure = True
                        value = original(launch, *args, **kwargs)
                        if selected and boundary == "postcommand":
                            h.guard_failure = True
                        return value
                    h.process.command = drift
                    with self.assertRaises(V.ProbeError):
                        h.observe()
                    self.assertEqual(len(h.calls), command_index + 1)
                    self.assertFalse(getattr(getattr(h, "fixture", None), "retired", False))

    def test_connected_owned_disk_read_counts_drop_without_skipping_final_guard(self):
        from tests.test_phase5_current_readiness import R
        # Reconstruct just the removed historical preguard in memory, so both
        # counters measure connected reader calls instead of extrapolating.
        tree = ast.parse(inspect.getsource(V.observe))
        command = next(node for node in tree.body[0].body
                       if isinstance(node, ast.FunctionDef) and node.name == "command")
        command.body.insert(1, ast.Expr(ast.Call(ast.Name("guard", ast.Load()), [], [])))
        ast.fix_missing_locations(tree)
        namespace = {}
        exec(compile(tree, "historical-preguard-fixture", "exec"), V.__dict__, namespace)
        baseline = namespace["observe"]
        with tempfile.TemporaryDirectory(dir="/private/tmp") as directory:
            os.chmod(directory, 0o700)
            for leaf in ("cli", "asar", "contract"):
                target = Path(directory) / leaf
                target.write_bytes(b'{"cli":{"observedVersion":"codex-cli 0.1.0"}}')
                target.chmod(0o700)
            class LocalSource(R.SourceFile):
                def __init__(self, path, root, uid, budget, *, keep=True):
                    leaf = "cli" if str(path) == V.CLI else "asar" if str(path) == V.ASAR else "contract"
                    super().__init__(Path(directory) / leaf, directory, os.getuid(), budget, keep=keep)
            actual = os.read
            for observer, guards, count in ((baseline, 27, 78), (V.observe, 19, 54)):
                h = Harness()
                h.readiness.SourceFile = LocalSource
                reads = []
                def read(descriptor, maximum):
                    block = actual(descriptor, maximum)
                    if block:
                        reads.append(len(block))
                    return block
                with patch.object(V, "observe", observer), patch.object(V, "vendor_source_type", return_value=LocalSource), patch.object(os, "read", side_effect=read):
                    result = h.observe()
                self.assertEqual(result["status"], "PASS")
                self.assertEqual(len(h.calls), 8)
                self.assertEqual(h.guard_count, guards)
                self.assertEqual(len(reads), count)

    def test_missing_old_cli_and_wrapper_do_not_affect_direct_probe(self):
        h = Harness()
        h.missing_sources = {LEGACY_CLI, WRAPPER_CLI}
        result = h.observe()
        self.assertEqual(result["status"], "PASS")
        self.assertIn(DIRECT_CLI, [source.path for source in h.sources])
        self.assertTrue(h.missing_sources.isdisjoint(source.path for source in h.sources))
        capability_calls = [launch for launch in h.calls if launch.argv[0] == "/usr/bin/sandbox-exec"]
        self.assertEqual(len(capability_calls), 6)
        self.assertTrue(all(launch.argv[3] == DIRECT_CLI for launch in capability_calls))

    def test_missing_direct_cli_fails_before_signing_or_capability_execution(self):
        h = Harness()
        h.missing_sources = {DIRECT_CLI}
        with self.assertRaises(V.ProbeError) as caught:
            h.observe()
        self.assertEqual(str(caught.exception), "source_changed")
        self.assertEqual(h.calls, [])
        self.assertEqual([source.path for source in h.sources], [DIRECT_CLI])
        self.assertTrue(caught.exception.source_handles_closed)
        self.assertTrue(h.sources[0]._sentinel_close_attempted)

    def test_direct_cli_drift_after_first_capability_command_stops_probe(self):
        h = Harness()
        original = h.process.command
        def drift(launch, *args, **kwargs):
            result = original(launch, *args, **kwargs)
            if launch.argv[0] == "/usr/bin/sandbox-exec":
                h.changed_source = DIRECT_CLI
            return result
        h.process.command = drift
        with self.assertRaises(V.ProbeError) as caught:
            h.observe()
        self.assertEqual(str(caught.exception), "source_changed")
        self.assertEqual(len(h.calls), 2)
        self.assertEqual(h.calls[-1].argv[3:], (DIRECT_CLI, "--version"))
        self.assertTrue(caught.exception.source_handles_closed)
        self.assertTrue(h.fixture.closed)
        self.assertTrue(all(source._sentinel_close_attempted for source in h.sources))

    def test_pass_calls_real_connected_guard_and_closes_all(self):
        h = Harness()
        result = h.observe()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(len(h.calls), 8)
        self.assertGreater(h.guard_count, 7)
        self.assertTrue(all(source._sentinel_close_attempted and source.fds == [] for source in h.sources))
        self.assertTrue(h.fixture.closed and all(app.descriptors == [] for app in h.apps))
        for launch in h.calls[1:-1]:
            self.assertEqual(launch.argv[:2], ("/usr/bin/sandbox-exec", "-p"))
            self.assertEqual(launch.environment, V.environment(FIXTURE))
            self.assertEqual(launch.cwd, FIXTURE + "/cwd")

    def test_source_refusal_precedes_loading_vendor_adapter_or_any_process(self):
        h = Harness()
        h.guard_failure = True
        with self.assertRaises(V.ProbeError):
            h.observe()
        self.assertEqual(h.calls, [])
        self.assertEqual(h.sources, [])

    def test_command_failure_redacted_but_private_diagnostic_retained(self):
        h = Harness()
        h.fail_command = "--version"
        with self.assertRaises(V.ProbeError) as caught:
            h.observe()
        self.assertEqual(str(caught.exception), "command_failed")
        self.assertNotIn("private command output", str(caught.exception))
        self.assertEqual(caught.exception.private_diagnostics[1][1].stdout, b"private command output")
        self.assertTrue(caught.exception.source_handles_closed)
        self.assertIs(caught.exception.child_settled, True)
        self.assertEqual(len(h.calls), 2)

    def test_policy_nonpass_is_not_promoted(self):
        h = Harness()
        h.assessment = {"compatible": False, "reasonCodes": ["schema_shape_unproven"]}
        with self.assertRaises(V.ProbeError) as caught:
            h.observe()
        self.assertEqual(str(caught.exception), "capabilities_incompatible")
        self.assertEqual(caught.exception.private_diagnostics[2], h.assessment)

    def test_cleanup_failure_retains_actual_sources(self):
        h = Harness()
        h.close_failure = True
        with self.assertRaises(V.ProbeError) as caught:
            h.observe()
        self.assertFalse(caught.exception.source_handles_closed)
        self.assertIs(caught.exception.retained_sources[0], h.sources[0])

    def test_unknown_process_owner_never_lost_or_retried(self):
        h = Harness()
        owner = object()
        error = V.ProbeError("process_unsettled", private_owner=owner)
        h.command_exception = error
        with self.assertRaises(V.ProbeError) as caught:
            h.observe()
        self.assertIs(caught.exception, error)
        self.assertIs(caught.exception.private_owner, owner)
        self.assertIsNone(caught.exception.child_settled)
        self.assertEqual(len(h.calls), 1)

    def test_original_interruption_preserved(self):
        h = Harness()
        error = KeyboardInterrupt()
        h.command_exception = error
        with self.assertRaises(KeyboardInterrupt) as caught:
            h.observe()
        self.assertIs(caught.exception, error)

    def test_swallowed_signing_exception_keeps_real_unsettled_owner(self):
        h = Harness()
        owner = object()
        error = V.ProbeError("process_unsettled", private_owner=owner)
        h.command_exception = error
        def swallow(contract):
            try:
                return h.attest(contract)
            except Exception:
                return None
        h.preflight.app_attestation = swallow
        with self.assertRaises(V.ProbeError) as caught:
            h.observe()
        self.assertIs(caught.exception, error)
        self.assertIs(caught.exception.private_owner, owner)
        self.assertFalse(caught.exception.source_handles_closed)
        self.assertTrue(caught.exception.retained_sources)
        self.assertTrue(all(not source._sentinel_close_attempted for source in h.sources))
        self.assertEqual(len(h.calls), 1)

    def test_changed_final_signature_prevents_pass(self):
        h = Harness()
        count = [0]
        def change(contract):
            count[0] += 1
            return "26.905.11957" if count[0] == 1 else "26.906.0"
        h.preflight.app_attestation = change
        with self.assertRaises(V.ProbeError) as caught:
            h.observe()
        self.assertEqual(str(caught.exception), "signature_invalid")
        self.assertEqual(count[0], 2)

    def test_later_cleanup_interrupt_retains_original_exception_and_owner(self):
        h = Harness()
        owner = object()
        original = V.ProbeError("schema_output_invalid")
        original.retained_sources = (owner,)
        original.source_handles_closed = False
        def fail(**kwargs):
            raise original
        h.policy.assess_capabilities = fail
        later = KeyboardInterrupt()
        h.close_failure = later
        with self.assertRaises(KeyboardInterrupt) as caught:
            h.observe()
        self.assertIs(caught.exception, later)
        self.assertIn(original, caught.exception.private_errors)
        self.assertIn(owner, caught.exception.retained_sources)
        self.assertFalse(caught.exception.source_handles_closed)


class VendorSourceTests(unittest.TestCase):
    def fixture(self, data=b"public fixture", path=V.ASAR):
        from tests.test_phase5_current_readiness import R, L
        fake = L.FakeOS()
        for part in (Path(path), *Path(path).parents):
            if part != Path(path):
                fake.add(str(part), directory=True, mode=0o755)
        fake.add(path, data)
        def lseek(descriptor, offset, whence):
            self.assertEqual((offset, whence), (0, os.SEEK_SET))
            fake.handles[descriptor][2] = 0
        fake.lseek = lseek
        return fake, V.vendor_source_type(R), R

    def test_production_bound_is_one_gib_and_old_reader_remains_unchanged(self):
        fake, adapter, readiness = self.fixture()
        self.assertEqual(V.VENDOR_MAX_SOURCE, 1024 * 1024 * 1024)
        self.assertEqual(readiness.MAX_SOURCE, 512 * 1024 * 1024)
        self.assertTrue(issubclass(adapter, readiness.SourceFile))
        self.assertIs(adapter.verify, readiness.SourceFile.verify)
        self.assertIs(adapter.close, readiness.SourceFile.close)

    def test_streamed_exact_bound_hashes_without_buffering_and_rechecks_fd(self):
        for path in V.VENDOR_FILES:
            with self.subTest(path=path), patch.object(V, "VENDOR_MAX_SOURCE", 32):
                fake, adapter, readiness = self.fixture(b"x" * 32, path)
                pin = adapter(path, V.APP, 501, NS(check=lambda: None), syscalls=fake)
                self.assertEqual(len(fake.handles), 1)
                self.assertIsNone(pin.data)
                self.assertEqual(pin.digest, hashlib.sha256(b"x" * 32).hexdigest())
                self.assertTrue(pin.verify())
                pin.close()
                self.assertEqual(fake.handles, {})

    def test_size_over_bound_fails_before_read_and_closes_constructor_fd(self):
        fake, adapter, readiness = self.fixture(b"x" * 33)
        with patch.object(V, "VENDOR_MAX_SOURCE", 32), self.assertRaises(readiness.ReadinessError):
            adapter(V.ASAR, V.APP, 501, NS(check=lambda: None), syscalls=fake)
        self.assertNotIn(("read", V.ASAR), fake.calls)
        self.assertEqual(fake.handles, {})

    def test_larger_stream_than_declared_size_fails_at_bound_without_buffering(self):
        fake, adapter, readiness = self.fixture(b"x" * 32)
        original_fstat = fake.fstat
        def declared_size(descriptor):
            facts = original_fstat(descriptor)
            if stat.S_ISREG(facts.st_mode):
                facts.st_size = 31
            return facts
        fake.fstat = declared_size
        with patch.object(V, "VENDOR_MAX_SOURCE", 31), self.assertRaises(readiness.ReadinessError):
            adapter(V.ASAR, V.APP, 501, NS(check=lambda: None), syscalls=fake)
        self.assertIn(("read", V.ASAR), fake.calls)
        self.assertEqual(fake.handles, {})

    def test_short_stream_fails_declared_size_comparison(self):
        fake, adapter, readiness = self.fixture(b"x" * 30)
        original_fstat = fake.fstat
        def declared_size(descriptor):
            facts = original_fstat(descriptor)
            if stat.S_ISREG(facts.st_mode):
                facts.st_size = 31
            return facts
        fake.fstat = declared_size
        with patch.object(V, "VENDOR_MAX_SOURCE", 32), self.assertRaises(readiness.ReadinessError):
            adapter(V.ASAR, V.APP, 501, NS(check=lambda: None), syscalls=fake)
        self.assertEqual(fake.handles, {})

    def test_adapter_rejects_non_vendor_path_wrong_root_and_kept_data(self):
        for path, root, keep in ((V.ASAR + "-decoy", V.APP, False),
                                 (V.ASAR, "/Applications", False),
                                 (V.ASAR, V.APP, True)):
            fake, adapter, readiness = self.fixture(path=path)
            with self.subTest(path=path, root=root, keep=keep), self.assertRaises(V.ProbeError):
                adapter(path, root, 501, NS(check=lambda: None), keep=keep, syscalls=fake)
            self.assertEqual(fake.handles, {})

    def test_hash_named_metadata_and_complete_chain_drift_fail_recheck(self):
        for change in (
            lambda fs: fs.nodes[V.ASAR].update(data=b"mutant fixture"),
            lambda fs: fs.nodes[V.ASAR].update(st_ctime_ns=88),
            lambda fs: fs.nodes[V.APP].update(st_ino=999),
            lambda fs: fs.nodes.__setitem__(V.ASAR, {**fs.nodes[V.ASAR], "st_ino": 12345}),
        ):
            fake, adapter, readiness = self.fixture()
            pin = adapter(V.ASAR, V.APP, 501, NS(check=lambda: None), syscalls=fake)
            change(fake)
            with self.assertRaises(Exception):
                pin.verify()
            pin.close()
            self.assertEqual(fake.handles, {})

    def test_file_type_owner_links_write_and_privileged_modes_fail_before_read(self):
        for field, value in (("st_mode", stat.S_IFIFO | 0o600),
                             ("st_mode", stat.S_IFLNK | 0o600),
                             ("st_mode", stat.S_IFREG | 0o777),
                             ("st_mode", stat.S_IFREG | 0o4755),
                             ("st_uid", 502), ("st_nlink", 2)):
            fake, adapter, readiness = self.fixture()
            fake.nodes[V.ASAR][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(Exception):
                adapter(V.ASAR, V.APP, 501, NS(check=lambda: None), syscalls=fake)
            self.assertNotIn(("read", V.ASAR), fake.calls)
            self.assertEqual(fake.handles, {})


class CleanupTests(unittest.TestCase):
    def test_uncertain_fd_remains_owned_without_retry(self):
        owner = NS(descriptors=[71, 72])
        V.install_closer(owner, "descriptors")
        attempted = []
        def close(fd):
            attempted.append(fd)
            if fd == 71:
                raise OSError("close")
        def facts(fd):
            if fd == 71:
                return NS()
            raise OSError(errno.EBADF, "closed")
        with patch.object(V.os, "close", side_effect=close), patch.object(V.os, "fstat", side_effect=facts):
            with self.assertRaises(OSError) as first:
                owner.close()
            with self.assertRaises(OSError) as second:
                owner.close()
        self.assertIs(first.exception, second.exception)
        self.assertEqual(attempted, [71, 72])
        self.assertEqual(owner.descriptors, [71])
        self.assertIn(owner, first.exception.retained_sources)

    def test_fd_verification_interruption_does_not_replace_constructor_interrupt(self):
        owner = NS(descriptors=[71, 72])
        V.install_closer(owner, "descriptors")
        attempted = []
        original = KeyboardInterrupt()
        with patch.object(V.os, "close", side_effect=lambda fd: attempted.append(fd)), \
                patch.object(V.os, "fstat", side_effect=SystemExit()):
            try:
                raise original
            except KeyboardInterrupt:
                with self.assertRaises(KeyboardInterrupt) as caught:
                    owner.close()
            with self.assertRaises(KeyboardInterrupt):
                owner.close()
        self.assertIs(caught.exception, original)
        self.assertEqual(attempted, [71, 72])
        self.assertEqual(owner.descriptors, [71, 72])

    def test_all_handles_attempted_and_first_interruption_retained(self):
        seen = []
        original = KeyboardInterrupt()
        def handle(name, error):
            def close():
                seen.append(name)
                if error is not None:
                    raise error
            return NS(close=close)
        handles = [handle("parent", OSError()), handle("root", SystemExit()), handle("child", original)]
        with self.assertRaises(KeyboardInterrupt) as caught:
            V.close_handles(handles)
        self.assertIs(caught.exception, original)
        self.assertEqual(seen, ["child", "root", "parent"])
        self.assertEqual(len(caught.exception.close_errors), 3)

    def test_schema_close_cannot_replace_original_interruption(self):
        fixture = V.Fixture.__new__(V.Fixture)
        fixture.uid = 501
        fixture.handles = [NS(descriptor=9)]
        fixture.verify = lambda: True
        original = KeyboardInterrupt()
        with patch.object(V.os, "open", return_value=42), \
                patch.object(V.os, "fstat", side_effect=original), \
                patch.object(V.os, "close", side_effect=OSError("close")):
            with self.assertRaises(KeyboardInterrupt) as caught:
                fixture.schema()
        self.assertIs(caught.exception, original)
        self.assertEqual(caught.exception.retained_schema_descriptor, 42)
        self.assertFalse(caught.exception.source_handles_closed)


if __name__ == "__main__":
    unittest.main()
