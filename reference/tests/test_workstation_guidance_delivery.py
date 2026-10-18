"""Private non-root filesystem fixtures only; no live guidance or native probes."""
import copy
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lib import workstation_guidance_delivery as G


class GuidanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="guidance-test.", dir="/private/tmp")
        self.home = Path(self.temp.name)
        self.path = self.home.joinpath(*G.TARGET, G.NAME)
        self.path.parent.mkdir(parents=True, mode=0o700)
        self.old, self.new = b"old exact guidance\n", b"new exact guidance\n"
        self.path.write_bytes(self.old); self.path.chmod(0o600)
        self.original_inode = self.path.stat().st_ino
        actual, _ = G.source()
        self.manifest = copy.deepcopy(actual)
        self.manifest.update(preimageSha256=G.H.digest(self.old), postimageSha256=G.H.digest(self.new))
        self.mock_source = patch.object(G, "source", return_value=(self.manifest, self.new))
        self.mock_source.start()
        self.recovery = self.home.joinpath(*G.STATE, G.OPERATION)
        self.stage = self.path.parent / G.STAGE

    def tearDown(self):
        self.mock_source.stop(); self.temp.cleanup()

    def run_action(self, action, checkpoint=lambda _: None, source_guard=lambda: True):
        return G.execute(self.home, action, admission=lambda work, guard: work(),
            checkpoint=checkpoint, source_guard=source_guard)

    def crash(self, action, boundary):
        pid = os.fork()
        if pid == 0:
            self.run_action(action, lambda point: os._exit(73) if point == boundary else None)
            os._exit(74)
        self.assertEqual(os.waitpid(pid, 0)[1] >> 8, 73)

    def test_production_source_and_manifest_exact(self):
        self.mock_source.stop()
        try:
            manifest, after = G.source()
            self.assertEqual(manifest["preimageSha256"], G.PREIMAGE)
            self.assertEqual(G.H.digest(after), G.POSTIMAGE)
            self.assertEqual(manifest["mode"], "0600")
        finally: self.mock_source.start()

    def test_plan_status_do_not_create_state(self):
        for action in ("plan", "status"):
            self.assertEqual(self.run_action(action)["status"], "PREDECESSOR")
        self.assertFalse(self.home.joinpath(*G.STATE).exists())
        self.assertEqual(self.path.stat().st_ino, self.original_inode)

    def test_apply_status_noop_rollback_exact_inode_and_private_backup(self):
        self.assertEqual(self.run_action("apply")["status"], "INSTALLED")
        self.assertEqual(self.path.read_bytes(), self.new)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.recovery / "before").read_bytes(), self.old)
        self.assertEqual(self.stage.stat().st_ino, self.original_inode)
        installed = self.path.stat().st_ino
        backup = (self.recovery / "before").stat().st_ino
        self.assertEqual(self.run_action("apply")["status"], "UNCHANGED")
        self.assertEqual(self.path.stat().st_ino, installed)
        self.assertEqual((self.recovery / "before").stat().st_ino, backup)
        self.assertEqual(self.run_action("status")["status"], "INSTALLED")
        self.assertEqual(self.run_action("rollback")["status"], "ROLLED_BACK")
        self.assertEqual(self.path.read_bytes(), self.old)
        self.assertEqual(self.path.stat().st_ino, self.original_inode)
        self.assertEqual(self.run_action("recover")["status"], "ROLLED_BACK")
        with self.assertRaises(G.H.OfframpError): self.run_action("apply")
        for p in self.recovery.iterdir(): self.assertEqual(p.stat().st_mode & 0o777, 0o600)

    def test_unknown_target_and_wrong_mode_are_untouched(self):
        self.path.write_bytes(b"foreign guidance")
        inode = self.path.stat().st_ino
        with self.assertRaises(G.H.OfframpError): self.run_action("apply")
        self.assertEqual(self.path.read_bytes(), b"foreign guidance")
        self.assertEqual(self.path.stat().st_ino, inode)
        self.assertFalse(self.home.joinpath(*G.STATE).exists())
        self.path.write_bytes(self.old); self.path.chmod(0o644)
        with self.assertRaises(G.H.OfframpError): self.run_action("apply")
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o644)

    def test_symlink_hardlink_fifo_and_parent_symlink_refused(self):
        foreign = self.home / "foreign"; foreign.write_bytes(self.old); foreign.chmod(0o600)
        self.path.unlink(); self.path.symlink_to(foreign)
        with self.assertRaises(OSError): self.run_action("apply")
        self.path.unlink(); os.link(foreign, self.path)
        with self.assertRaises(G.H.OfframpError): self.run_action("apply")
        self.path.unlink(); os.mkfifo(self.path, 0o600)
        with self.assertRaises(G.H.OfframpError): self.run_action("apply")
        self.path.unlink(); self.path.write_bytes(self.old); self.path.chmod(0o600)
        parent = self.path.parent; displaced = parent.with_name("retained")
        parent.rename(displaced); parent.symlink_to(displaced)
        with self.assertRaises(OSError): self.run_action("apply")
        self.assertEqual(foreign.read_bytes(), self.old)

    def test_successor_bytes_without_custody_not_adopted(self):
        self.path.write_bytes(self.new)
        self.assertEqual(self.run_action("status")["status"], "SUCCESSOR_BYTES_UNVERIFIED")
        with self.assertRaises(G.H.OfframpError): self.run_action("apply")
        self.assertFalse(self.home.joinpath(*G.STATE).exists())

    def test_crash_known_preparation_and_publication_recover(self):
        for point in ("prestate-recorded", "before-recorded", "after-recorded", "prepared", "published"):
            with self.subTest(point=point):
                self.crash("apply", point)
                self.assertIn(self.run_action("recover")["status"], ("INSTALLED", "UNCHANGED"))
                self.assertEqual(self.path.read_bytes(), self.new)
                self.assertEqual(self.run_action("status")["status"], "INSTALLED")
                self.tearDown(); self.setUp()

    def test_crash_unbound_stage_preserved_without_adoption(self):
        self.crash("apply", "staged")
        before = self.stage.read_bytes(), self.stage.stat().st_ino
        with self.assertRaisesRegex(G.H.OfframpError, "unbound_stage_retained"):
            self.run_action("recover")
        self.assertEqual((self.stage.read_bytes(), self.stage.stat().st_ino), before)
        self.assertEqual(self.path.read_bytes(), self.old)

    def test_same_bytes_foreign_stage_after_prestate_not_adopted(self):
        self.crash("apply", "prestate-recorded")
        self.stage.write_bytes(self.new); self.stage.chmod(0o600)
        inode = self.stage.stat().st_ino
        with self.assertRaisesRegex(G.H.OfframpError, "unbound_stage_retained"):
            self.run_action("recover")
        self.assertEqual(self.stage.stat().st_ino, inode)
        self.assertEqual(self.path.stat().st_ino, self.original_inode)

    def test_racing_foreign_target_preserved_after_exchange_without_inverse(self):
        real_swap = G.H.swap
        foreign_inode = []
        def racing(directory, left, right):
            alternate = self.path.with_name("race")
            alternate.write_bytes(b"foreign concurrent bytes"); alternate.chmod(0o600)
            foreign_inode.append(alternate.stat().st_ino)
            alternate.replace(self.path)
            real_swap(directory, left, right)
        with patch.object(G.H, "swap", racing), self.assertRaisesRegex(G.H.OfframpError, "unknown_target_or_displaced"):
            self.run_action("apply")
        self.assertEqual(self.path.read_bytes(), self.new)
        self.assertEqual(self.stage.read_bytes(), b"foreign concurrent bytes")
        self.assertEqual(self.stage.stat().st_ino, foreign_inode[0])
        with self.assertRaises(G.H.OfframpError): self.run_action("recover")
        self.assertEqual((self.recovery / "before").read_bytes(), self.old)

    def test_rollback_crash_follows_recorded_direction(self):
        for point in ("rollback-recorded", "restored"):
            with self.subTest(point=point):
                self.run_action("apply"); self.crash("rollback", point)
                self.assertEqual(self.run_action("recover")["status"], "ROLLED_BACK")
                self.assertEqual(self.path.read_bytes(), self.old)
                self.assertEqual(self.path.stat().st_ino, self.original_inode)
                self.tearDown(); self.setUp()

    def test_replacement_same_bytes_or_changed_displaced_refuses_inverse(self):
        self.run_action("apply")
        alternate = self.path.with_name("new-inode"); alternate.write_bytes(self.new); alternate.chmod(0o600)
        alternate.replace(self.path)
        with self.assertRaises(G.H.OfframpError): self.run_action("rollback")
        self.assertEqual(self.path.read_bytes(), self.new)
        self.stage.write_bytes(b"foreign displaced")
        with self.assertRaises(G.H.OfframpError): self.run_action("recover")
        self.assertEqual(self.stage.read_bytes(), b"foreign displaced")

    def test_unknown_backup_or_preparation_material_retained(self):
        self.run_action("apply")
        (self.recovery / "before").write_bytes(b"foreign backup")
        with self.assertRaises(G.H.OfframpError): self.run_action("rollback")
        self.assertEqual((self.recovery / "before").read_bytes(), b"foreign backup")
        self.assertEqual(self.path.read_bytes(), self.new)
        (self.recovery / ".prepared-interrupted").write_bytes(b"partial record")
        with self.assertRaisesRegex(G.H.OfframpError, "unknown_recovery_material"):
            self.run_action("recover")

    def test_source_drift_before_mutation_and_after_exchange_preserves_context(self):
        with self.assertRaises(G.H.OfframpError): self.run_action("apply", source_guard=lambda: False)
        self.assertFalse(self.home.joinpath(*G.STATE).exists())
        okay = [True]
        def checkpoint(point):
            if point == "published": okay[0] = False
        with self.assertRaises(G.H.OfframpError): self.run_action("apply", checkpoint, lambda: okay[0])
        self.assertEqual(self.path.read_bytes(), self.new)
        self.assertEqual(self.stage.read_bytes(), self.old)
        self.assertEqual(self.run_action("recover")["status"], "UNCHANGED")

    def test_visible_exchange_with_fsync_failure_recovery_reestablishes_durability(self):
        real_swap, real_fsync = G.H.swap, G.os.fsync
        exchanged = [False]
        def swap(*args):
            real_swap(*args); exchanged[0] = True
        def fsync(fd):
            if exchanged[0]: raise OSError("synthetic durability failure")
            return real_fsync(fd)
        with patch.object(G.H, "swap", swap), patch.object(G.os, "fsync", fsync), self.assertRaises(OSError):
            self.run_action("apply")
        self.assertEqual(self.path.read_bytes(), self.new)
        self.assertEqual(self.stage.read_bytes(), self.old)
        with patch.object(G.os, "fsync", wraps=real_fsync) as sync:
            self.assertEqual(self.run_action("recover")["status"], "UNCHANGED")
            self.assertGreaterEqual(sync.call_count, 3)

    def test_foreign_stage_before_preparation_preserved(self):
        self.stage.write_bytes(self.new); self.stage.chmod(0o600)
        inode = self.stage.stat().st_ino
        with self.assertRaisesRegex(G.H.OfframpError, "unknown_stage"):
            self.run_action("apply")
        self.assertEqual(self.stage.stat().st_ino, inode)
        self.assertEqual(self.path.read_bytes(), self.old)

    def test_held_source_before_execute_and_failure_stops(self):
        from lib import workstation_maintenance_delivery as D
        canonical = Path(G.pwd.getpwuid(os.getuid()).pw_dir) / "AIDev/control"
        calls = []
        def admitted(root, *, full, operation_check=None):
            calls.append("full" if full else "held")
            if operation_check: self.assertIs(operation_check("a" * 40, source_guard=lambda: True), True)
        def execute(home, action, *, admission, source_guard):
            calls.append("execute")
            return admission(lambda: {"status": "INSTALLED"}, lambda: True)
        with patch.object(G, "ROOT", canonical), patch.object(G.Path, "cwd", return_value=canonical), \
             patch.object(D, "admitted_source", admitted), patch.object(G, "execute", execute), patch("builtins.print"):
            self.assertEqual(G.main(["apply"]), 0)
        self.assertEqual(calls, ["held", "execute"])
        with patch.object(G, "ROOT", canonical), patch.object(G.Path, "cwd", return_value=canonical), \
             patch.object(D, "admitted_source", side_effect=RuntimeError("blocked")), \
             patch.object(G, "execute") as execute_mock, patch("builtins.print"):
            self.assertEqual(G.main(["apply"]), 1); execute_mock.assert_not_called()


class SuccessorGuidanceTests(GuidanceTests):
    """Run the same crash, foreign-state and inode suite on the new namespace."""
    def setUp(self):
        super().setUp()
        self.recovery = self.home.joinpath(*G.STATE, G.SUCCESSOR)
        self.stage = self.path.parent / ".workstation-guidance-scoped-readiness-v1"

    def run_action(self, action, checkpoint=lambda _: None, source_guard=lambda: True):
        return G.execute(self.home, action, admission=lambda work, guard: work(),
            checkpoint=checkpoint, source_guard=source_guard, operation=G.SUCCESSOR)

    def test_production_source_and_manifest_exact(self):
        self.mock_source.stop()
        try:
            manifest, raw = G.source(G.SUCCESSOR)
            self.assertEqual(manifest["preimageSha256"], G.POSTIMAGE)
            self.assertEqual(G.H.digest(raw), G.SUCCESSOR_HASH)
            self.assertEqual(manifest["recoverySuffix"], "/".join(G.STATE + (G.SUCCESSOR,)))
            legacy, before = G.source()
            self.assertEqual(G.H.digest(before), G.POSTIMAGE)
            self.assertEqual(legacy["source"], "skills/manage-workstation/SKILL.md")
        finally: self.mock_source.start()

    def test_scoped_cli_uses_held_source_only_and_denies_failed_source(self):
        from lib import workstation_maintenance_delivery as D
        canonical = Path(G.pwd.getpwuid(os.getuid()).pw_dir) / "AIDev/control"
        calls = []
        def admitted(root, *, full, operation_check=None):
            self.assertFalse(full, "unrelated vendor health must not be invoked")
            calls.append("held")
            self.assertIs(operation_check("a" * 40, source_guard=lambda: True), True)
        def execute(home, action, *, admission, source_guard, operation):
            self.assertEqual(operation, G.SUCCESSOR)
            calls.append("execute")
            return admission(lambda: {"status": "INSTALLED"}, lambda: True)
        with patch.object(G, "ROOT", canonical), patch.object(G.Path, "cwd", return_value=canonical), \
             patch.object(D, "admitted_source", admitted), patch.object(G, "execute", execute), patch("builtins.print"):
            self.assertEqual(G.main(["apply"], operation=G.SUCCESSOR), 0)
        self.assertEqual(calls, ["held", "execute"])
        with patch.object(G, "ROOT", canonical), patch.object(G.Path, "cwd", return_value=canonical), \
             patch.object(D, "admitted_source", side_effect=RuntimeError("unaccepted source")), \
             patch.object(G, "execute") as execute_mock, patch("builtins.print"):
            self.assertEqual(G.main(["apply"], operation=G.SUCCESSOR), 1)
            execute_mock.assert_not_called()

    def test_closed_cli_rejects_override_and_unknown_operation(self):
        for args in (["apply", "--home", "/tmp"], ["apply", "--operation", G.OPERATION],
                     ["apply", "--source", "other"], ["apply", "--hash", "a" * 64]):
            with self.subTest(args=args), patch("sys.stderr"), self.assertRaises(SystemExit):
                G.main(args, operation=G.SUCCESSOR)
        with self.assertRaisesRegex(G.H.OfframpError, "fixed_operation"):
            G.execute(self.home, "apply", admission=lambda work, guard: work(), operation="arbitrary")

    def test_both_operations_share_lock_and_preserve_target_on_contention(self):
        custody = G.H.Directory(self.home, G.STATE, create=True)
        try:
            G.fcntl.flock(custody.fd, G.fcntl.LOCK_EX | G.fcntl.LOCK_NB)
            for operation in (G.OPERATION, G.SUCCESSOR):
                with self.subTest(operation=operation), self.assertRaises(BlockingIOError):
                    G.execute(self.home, "apply", admission=lambda work, guard: work(), operation=operation)
                self.assertEqual(self.path.read_bytes(), self.old)
                self.assertEqual(self.path.stat().st_ino, self.original_inode)
                self.assertFalse(self.home.joinpath(*G.STATE, operation).exists())
        finally:
            custody.close()

    def test_legacy_custody_survives_successor_and_sequential_rollback(self):
        old_manifest = copy.deepcopy(self.manifest)
        middle = self.new
        latest = b"scoped guidance successor\n"
        new_manifest = copy.deepcopy(self.manifest)
        new_manifest.update(preimageSha256=G.H.digest(middle), postimageSha256=G.H.digest(latest))
        G.source.side_effect = lambda operation=G.OPERATION: \
            (old_manifest, middle) if operation == G.OPERATION else (new_manifest, latest)
        def operate(action, operation):
            return G.execute(self.home, action, admission=lambda work, guard: work(), operation=operation)
        self.assertEqual(operate("apply", G.OPERATION)["status"], "INSTALLED")
        middle_inode = self.path.stat().st_ino
        old_recovery = self.home.joinpath(*G.STATE, G.OPERATION)
        old_stage = self.path.parent / G.STAGE
        snapshot = {p.name: (p.read_bytes(), p.stat().st_ino) for p in old_recovery.iterdir()}
        displaced = old_stage.read_bytes(), old_stage.stat().st_ino
        self.assertEqual(operate("apply", G.SUCCESSOR)["status"], "INSTALLED")
        self.assertEqual(operate("apply", G.SUCCESSOR)["status"], "UNCHANGED")
        self.assertEqual(operate("status", G.SUCCESSOR)["status"], "INSTALLED")
        with self.assertRaises(G.H.OfframpError): operate("rollback", G.OPERATION)
        self.assertEqual(self.path.read_bytes(), latest)
        self.assertEqual(snapshot, {p.name: (p.read_bytes(), p.stat().st_ino) for p in old_recovery.iterdir()})
        self.assertEqual(displaced, (old_stage.read_bytes(), old_stage.stat().st_ino))
        self.assertEqual(operate("rollback", G.SUCCESSOR)["status"], "ROLLED_BACK")
        self.assertEqual((self.path.read_bytes(), self.path.stat().st_ino), (middle, middle_inode))
        self.assertEqual(operate("status", G.OPERATION)["status"], "INSTALLED")
        self.assertEqual(operate("rollback", G.OPERATION)["status"], "ROLLED_BACK")
        self.assertEqual((self.path.read_bytes(), self.path.stat().st_ino), (self.old, self.original_inode))
        self.assertEqual(operate("status", G.OPERATION)["status"], "ROLLED_BACK")
        self.assertTrue(self.recovery.exists())


if __name__ == "__main__": unittest.main()
