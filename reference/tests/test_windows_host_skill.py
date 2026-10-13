"""Disposable real-Git fixtures; no installed skill, SSH, or root operations."""
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
loader = importlib.machinery.SourceFileLoader("windows_host_skill", str(REPO / "bin/windows-host-skill"))
spec = importlib.util.spec_from_loader(loader.name, loader)
skill = importlib.util.module_from_spec(spec)
loader.exec_module(skill)


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        # A workspace-private fixture avoids system temporary symlink/writable
        # ancestors while exercising the real no-follow directory walker.
        self.temp = tempfile.TemporaryDirectory(prefix=".windows-skill-test-", dir=REPO)
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.root = self.home / "AIDev/control"
        self.parent = self.home / ".codex/skills"
        self.parent.mkdir(parents=True)
        self.root.mkdir(parents=True)
        for name in (skill.SOURCE, skill.MANIFEST, skill.HELPER):
            destination = self.root / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes((REPO / name).read_bytes())
        self.git("init", "-b", "main")
        self.git("config", "user.name", "Fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        self.commit = self.save()
        self.target = self.parent / skill.NAME
        self.adapter = object.__new__(skill.Native)
        self.adapter.uid = os.getuid()
        self.adapter.home = self.home
        self.adapter.root = self.root
        self.adapter.mutation_started = False

    def git(self, *args):
        return subprocess.check_output(["/usr/bin/git", "-C", str(self.root), *args], stderr=subprocess.DEVNULL).decode().strip()

    def save(self):
        self.git("add", ".")
        self.git("commit", "-m", "Fixture")
        return self.git("rev-parse", "HEAD")

    def run_command(self, *args):
        output = []
        self.adapter.mutation_started = False
        code = skill.main(list(args), adapter_factory=lambda: self.adapter, emit=output.append)
        return code, json.loads(output[0])

    def test_prepare_status_apply_and_idempotence(self):
        self.assertEqual(self.run_command("prepare")[1]["status"], "ABSENT")
        self.assertFalse(self.target.exists())
        self.assertEqual(self.run_command("status")[0], 1)
        code, result = self.run_command("apply", self.commit)
        self.assertEqual(code, 0)
        self.assertTrue(result["changed"])
        before = {p.name: (p.read_bytes(), p.stat().st_ino, p.stat().st_mtime_ns) for p in self.target.iterdir()}
        code, result = self.run_command("apply", self.commit, "--json")
        self.assertEqual(code, 0)
        self.assertFalse(result["changed"])
        self.assertEqual(self.run_command("status")[1]["status"], "INSTALLED_EXACT")
        self.assertEqual(before, {p.name: (p.read_bytes(), p.stat().st_ino, p.stat().st_mtime_ns) for p in self.target.iterdir()})

    def test_unmanaged_empty_directory_is_collision(self):
        self.target.mkdir()
        self.assertEqual(self.run_command("apply", self.commit)[0], 1)
        self.assertEqual(list(self.target.iterdir()), [])

    def test_unmanaged_exact_skill_is_not_adopted(self):
        self.target.mkdir()
        (self.target / "SKILL.md").write_bytes((self.root / skill.SOURCE).read_bytes())
        self.assertEqual(self.run_command("apply", self.commit)[0], 1)
        self.assertFalse((self.target / skill.RECEIPT).exists())

    def test_target_symlink_never_followed(self):
        outside = self.home / "outside"
        outside.mkdir()
        self.target.symlink_to(outside, target_is_directory=True)
        self.assertEqual(self.run_command("apply", self.commit)[0], 1)
        self.assertEqual(list(outside.iterdir()), [])

    def test_parent_symlink_never_followed(self):
        old = self.home / "old-skills"
        self.parent.rename(old)
        self.parent.symlink_to(old, target_is_directory=True)
        self.assertEqual(self.run_command("apply", self.commit)[0], 1)
        self.assertEqual(list(old.iterdir()), [])

    def test_installed_bytes_receipt_and_extra_file_drift(self):
        self.assertEqual(self.run_command("apply", self.commit)[0], 0)
        installed = self.target / "SKILL.md"
        raw = installed.read_bytes()
        installed.write_bytes(raw + b"drift")
        self.assertEqual(self.run_command("apply", self.commit)[0], 1)
        self.assertEqual(installed.read_bytes(), raw + b"drift")
        installed.write_bytes(raw)
        receipt = self.target / skill.RECEIPT
        receipt.write_text('{}')
        self.assertEqual(self.run_command("status")[0], 1)

    def test_hardlinked_installed_file_rejected(self):
        self.assertEqual(self.run_command("apply", self.commit)[0], 0)
        os.link(self.target / "SKILL.md", self.home / "linked")
        self.assertEqual(self.run_command("status")[0], 1)

    def test_extra_file_and_mode_drift_rejected(self):
        self.assertEqual(self.run_command("apply", self.commit)[0], 0)
        (self.target / "extra").write_text("preserve")
        self.assertEqual(self.run_command("status")[0], 1)
        self.assertEqual((self.target / "extra").read_text(), "preserve")

    def test_installed_mode_drift_rejected(self):
        self.assertEqual(self.run_command("apply", self.commit)[0], 0)
        (self.target / "SKILL.md").chmod(0o644)
        self.assertEqual(self.run_command("status")[0], 1)

    def test_committed_source_symlink_rejected(self):
        source = self.root / skill.SOURCE
        source.rename(self.home / "external-skill")
        source.symlink_to(self.home / "external-skill")
        commit = self.save()
        self.assertEqual(self.run_command("apply", commit)[0], 1)
        self.assertFalse(self.target.exists())

    def test_receipt_failure_retains_only_new_skill(self):
        write = self.adapter.write
        def fail_receipt(fd, name, raw):
            if name == skill.RECEIPT:
                raise OSError("fixture failure")
            return write(fd, name, raw)
        with patch.object(self.adapter, "write", side_effect=fail_receipt):
            code, result = self.run_command("apply", self.commit)
        self.assertEqual(code, 1)
        self.assertEqual(result["status"], "RECOVERY_REQUIRED")
        self.assertEqual({p.name for p in self.target.iterdir()}, {"SKILL.md"})
        self.assertEqual(self.run_command("status")[0], 1)

    def test_commit_dirty_branch_and_source_link_gates(self):
        self.assertEqual(self.run_command("apply", "0" * 40)[0], 1)
        self.git("checkout", "-b", "candidate")
        self.assertEqual(self.run_command("prepare")[0], 1)
        self.git("checkout", "main")
        (self.root / "untracked").write_text("drift")
        self.assertEqual(self.run_command("apply", self.commit)[0], 1)
        self.assertFalse(self.target.exists())

    def test_committed_hash_mismatch_rejected(self):
        (self.root / skill.SOURCE).write_text("changed")
        commit = self.save()
        self.assertEqual(self.run_command("apply", commit)[0], 1)
        self.assertFalse(self.target.exists())

    def test_skip_worktree_source_drift_rejected(self):
        self.git("update-index", "--skip-worktree", skill.SOURCE)
        (self.root / skill.SOURCE).write_text("hidden drift")
        self.assertEqual(self.git("status", "--porcelain"), "")
        self.assertEqual(self.run_command("apply", self.commit)[0], 1)
        self.assertFalse(self.target.exists())

    def test_partial_failure_is_retained_and_blocks_retry(self):
        with patch.object(self.adapter, "write", side_effect=OSError("fixture failure")):
            code, result = self.run_command("apply", self.commit)
        self.assertEqual(code, 1)
        self.assertEqual(result["status"], "RECOVERY_REQUIRED")
        self.assertTrue(result["changed"])
        self.assertTrue(self.target.is_dir())
        self.assertEqual(self.run_command("apply", self.commit)[0], 1)

    def test_manifest_exact_type_and_duplicate_keys(self):
        path = self.root / skill.MANIFEST
        manifest = json.loads(path.read_text())
        manifest["schema"] = True
        path.write_text(json.dumps(manifest))
        commit = self.save()
        self.assertEqual(self.run_command("apply", commit)[0], 1)
        with self.assertRaises(skill.Blocked):
            skill.decode(b'{"schema":1,"schema":1}')

    def test_cli_has_no_path_or_environment_override(self):
        for args in (["apply", self.commit, "--root", str(self.root)], ["status", "--home", str(self.home)], ["remove"]):
            with self.subTest(args=args):
                factory = unittest.mock.Mock()
                self.assertEqual(skill.main(args, adapter_factory=factory, emit=lambda _: None), 2)
                factory.assert_not_called()
        with patch.dict(os.environ, {"HOME": str(self.home), "CODEX_HOME": str(self.home)}):
            with self.assertRaises(skill.Blocked):
                skill.Native()  # Real user canonical path, not fixture overrides.


if __name__ == "__main__":
    unittest.main()
