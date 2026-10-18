"""Native filesystem primitives on explicit private fixtures only; no CLI/model."""
from pathlib import Path
import os
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lib import quarantine_delivery as Q

class DeliveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="quarantine-delivery-test.", dir="/private/tmp")
        self.home = Path(self.temp.name)
        self.images = Q.sources()
        for key, rel, name, mode, *_ in Q.ROWS:
            parent = self.home.joinpath(*rel); parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            path = parent/name; path.write_bytes(self.images[key][0]); path.chmod(mode)
    def tearDown(self): self.temp.cleanup()
    def path(self, key):
        row = next(row for row in Q.ROWS if row[0] == key)
        return self.home.joinpath(*row[1], row[2])
    def run_action(self, action, hook=lambda _: None):
        return Q.execute(self.home, action, "fixture", admission=lambda work, guard: work(), checkpoint=hook)
    def assert_pair(self, index):
        for k in self.images: self.assertEqual(self.path(k).read_bytes(), self.images[k][index])
    def test_read_only_plan_creates_no_recovery(self):
        self.assertEqual(self.run_action("plan")["status"], "PREDECESSOR")
        self.assertFalse(self.home.joinpath(*Q.STATE).exists())
    def test_apply_noop_rollback_recover(self):
        self.assertEqual(self.run_action("apply")["status"], "INSTALLED")
        self.assert_pair(1)
        inode = self.path("launcher").stat().st_ino
        self.assertEqual(self.run_action("apply")["status"], "INSTALLED")
        self.assertEqual(self.path("launcher").stat().st_ino, inode)
        self.assertEqual(self.run_action("rollback")["status"], "ROLLED_BACK")
        self.assert_pair(0)
        self.assertEqual(self.run_action("recover")["status"], "ROLLED_BACK")
        with self.assertRaises(Q.H.OfframpError): self.run_action("apply")
    def test_unknown_target_preserved(self):
        target = self.path("profile"); target.write_bytes(b"owner modified")
        with self.assertRaises(Q.H.OfframpError): self.run_action("apply")
        self.assertEqual(target.read_bytes(), b"owner modified")
    def test_symlink_refused(self):
        target = self.path("profile"); target.rename(target.with_suffix(".old")); target.symlink_to(target.with_suffix(".old"))
        with self.assertRaises(OSError): self.run_action("apply")
    def test_wrong_mode_refused(self):
        self.path("profile").chmod(0o644)
        with self.assertRaises(Q.H.OfframpError): self.run_action("apply")
    def test_historical_launcher_mode_preserved(self):
        manifest = Q.H.parse((Q.ROOT / "manifests/phase5-apply-bundle.json").read_bytes())
        def matches(obj):
            if isinstance(obj, dict):
                if obj.get("id") == "quarantine-launcher": yield obj
                for value in obj.values(): yield from matches(value)
            elif isinstance(obj, list):
                for value in obj: yield from matches(value)
        row, = matches(manifest)
        self.assertEqual(row["installMode"], "0700")
        self.assertEqual(Q.ROWS[0][3], int(row["installMode"], 8))
        self.run_action("apply")
        self.assertEqual(self.path("launcher").stat().st_mode & 0o777, 0o700)
        self.run_action("rollback")
        self.assertEqual(self.path("launcher").stat().st_mode & 0o777, 0o700)
    def test_widened_launcher_mode_refused(self):
        self.path("launcher").chmod(0o755)
        with self.assertRaises(Q.H.OfframpError): self.run_action("apply")
    def test_apply_crash_each_boundary_recover(self):
        for boundary in ("prepared", "launcher-published", "profile-published"):
            with self.subTest(boundary=boundary):
                # Independent process models abrupt death without exception cleanup.
                pid = os.fork()
                if pid == 0:
                    self.run_action("apply", lambda p: os._exit(73) if p == boundary else None)
                    os._exit(74)
                self.assertEqual(os.waitpid(pid, 0)[1] >> 8, 73)
                self.assertEqual(self.run_action("recover")["status"], "INSTALLED")
                self.assert_pair(1)
                self.tearDown(); self.setUp()
    def test_rollback_crash_each_boundary_recover(self):
        for boundary in ("rollback-recorded", "profile-restored", "launcher-restored"):
            with self.subTest(boundary=boundary):
                self.run_action("apply")
                pid = os.fork()
                if pid == 0:
                    self.run_action("rollback", lambda p: os._exit(73) if p == boundary else None)
                    os._exit(74)
                self.assertEqual(os.waitpid(pid, 0)[1] >> 8, 73)
                self.assertEqual(self.run_action("recover")["status"], "ROLLED_BACK")
                self.assert_pair(0)
                self.tearDown(); self.setUp()
    def test_same_bytes_new_inode_refuses_rollback(self):
        self.run_action("apply")
        p = self.path("profile"); alternate = p.with_suffix(".replacement")
        alternate.write_bytes(p.read_bytes()); alternate.chmod(0o600); alternate.replace(p)
        with self.assertRaises(Q.H.OfframpError): self.run_action("rollback")
        self.assert_pair(1)
    def test_unknown_displaced_preserved(self):
        self.run_action("apply")
        stage = self.path("profile").parent/".quarantine-delivery-fixture-profile"
        stage.write_bytes(b"unknown recovery")
        with self.assertRaises(Q.H.OfframpError): self.run_action("rollback")
        self.assertEqual(stage.read_bytes(), b"unknown recovery")
        self.assert_pair(1)
    def test_successor_without_receipt_not_adopted(self):
        for k in self.images: self.path(k).write_bytes(self.images[k][1])
        self.assertEqual(self.run_action("status")["status"], "SUCCESSOR_BYTES_UNVERIFIED")
        with self.assertRaises(Q.H.OfframpError): self.run_action("apply")
    def test_operation_is_not_path(self):
        with self.assertRaises(Q.H.OfframpError):
            Q.execute(self.home, "apply", "../outside", admission=lambda f,g:f())
    def test_live_wrapper_holds_source_and_returns_true_callback(self):
        from lib import scoped_source_admission as D
        calls = []
        canonical = Path(Q.pwd.getpwuid(os.getuid()).pw_dir)/"AIDev/control"
        def admitted(root, *, full=False, operation_check=None, extra_paths=()):
            self.assertFalse(full, 'unrelated full vendor gate')
            self.assertIn("manifests/quarantine-boundary-successor.json", extra_paths)
            calls.append("full" if full else "held")
            if operation_check:
                self.assertIs(operation_check("a" * 40, source_guard=lambda: True), True)
        def execute(home, action, operation, *, admission, source_guard):
            calls.append("execute")
            self.assertTrue(source_guard())
            return admission(lambda: {"schema": 1, "status": "INSTALLED"}, lambda: True)
        with patch.object(Q, "ROOT", canonical), patch.object(Q.Path, "cwd", return_value=canonical), \
             patch.object(D, "observe", admitted), patch.object(Q, "execute", execute), patch("builtins.print"):
            self.assertEqual(Q.main(["apply"]), 0)
        self.assertEqual(calls, ["held", "execute"])
    def test_source_admission_failure_never_calls_delivery(self):
        from lib import scoped_source_admission as D
        canonical = Path(Q.pwd.getpwuid(os.getuid()).pw_dir)/"AIDev/control"
        with patch.object(Q, "ROOT", canonical), patch.object(Q.Path, "cwd", return_value=canonical), \
             patch.object(D, "observe", side_effect=RuntimeError("not ready")), \
             patch.object(Q, "execute") as execute, patch("builtins.print"):
            self.assertEqual(Q.main(["apply"]), 1)
            execute.assert_not_called()

    def test_connected_held_gate_without_vendor_preserves_unknown_targets(self):
        from lib import scoped_source_admission as D
        from types import SimpleNamespace as NS
        canonical = self.home / 'AIDev/control'
        canonical.mkdir(parents=True, mode=0o700, exist_ok=True)
        calls = []
        source_ok = [False]
        def admitted(root, *, full=False, operation_check, extra_paths=()):
            self.assertIs(full, False, 'unrelated vendor sentinel requested')
            calls.append(full)
            if not source_ok[0]:
                raise D.SourceError('affected_source_uncommitted')
            self.assertIs(operation_check('a' * 40, source_guard=lambda: True), True)
            return {'verdict': 'SOURCE_VALID'}
        with patch.object(Q, 'ROOT', canonical), patch.object(Q.Path, 'cwd', return_value=canonical), \
                patch.object(Q.pwd, 'getpwuid', return_value=NS(pw_dir=str(self.home))), \
                patch.object(Q, 'sources', return_value=self.images), \
                patch.object(D, 'observe', side_effect=admitted), patch('builtins.print'):
            with patch.object(Q, 'execute') as execute:
                self.assertEqual(Q.main(['apply']), 1)
                execute.assert_not_called()
            source_ok[0] = True
            self.path('profile').write_bytes(b'owner changed')
            self.assertEqual(Q.main(['apply']), 1)
            self.assertEqual(self.path('profile').read_bytes(), b'owner changed')
            self.path('profile').write_bytes(self.images['profile'][0])
            self.assertEqual(Q.main(['apply']), 0)
            self.assert_pair(1)
        self.assertEqual(calls, [False, False, False])

    def test_source_failure_reports_closed_reason_and_one_next_action(self):
        canonical = Path(Q.pwd.getpwuid(os.getuid()).pw_dir) / "AIDev/control"
        for reason, expected in (("affected_source_uncommitted", "affected_source_uncommitted"),
                                 ("private/path/secret", "source_admission_failed")):
            with self.subTest(reason=reason), patch.object(Q, "ROOT", canonical), \
                    patch.object(Q.Path, "cwd", return_value=canonical), \
                    patch.object(Q.source, "observe", side_effect=Q.source.SourceError(reason)), \
                    patch("builtins.print") as emit, patch.object(Q, "execute") as execute:
                self.assertEqual(Q.main(["apply"]), 1)
                result = Q.H.parse(emit.call_args.args[0].encode())
                self.assertEqual(result["reason"], expected)
                self.assertIsInstance(result["nextAction"], str)
                self.assertNotIn("private/path", emit.call_args.args[0])
                execute.assert_not_called()

if __name__ == "__main__": unittest.main()
