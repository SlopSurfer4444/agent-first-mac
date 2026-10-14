"""Source-only SessionStart tests over owned directories and real Git fixtures."""
import contextlib
import importlib.machinery
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "codex/hooks/phase5-contract.py"
loader = importlib.machinery.SourceFileLoader("project_boundary_hook", str(SOURCE))
H = importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name, loader))
loader.exec_module(H)


class ProjectContextTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="project-context-fixture-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.home = self.root / "owner"
        self.control = self.home / "AIDev/control"
        self.control_worktree = self.home / "AIDev/worktrees/control/review"
        self.quarantine = self.home / "AIDev/quarantine/unknown input"
        self.external = self.root / "outside AIDev/project with spaces"
        self.worktree = self.root / "outside AIDev/read only worktree"
        self.generic = self.root / "ordinary directory"
        self.registry = self.control / "manifests/trusted-repos.json"
        for directory in (self.control, self.control_worktree, self.quarantine,
                          self.external, self.generic, self.registry.parent):
            directory.mkdir(parents=True, exist_ok=True)
        self.env = {"HOME": str(self.home), "PATH": "/usr/bin:/bin", "LANG": "C",
                    "LC_ALL": "C", "GIT_CONFIG_GLOBAL": "/dev/null",
                    "GIT_CONFIG_NOSYSTEM": "1", "GIT_TERMINAL_PROMPT": "0",
                    "GIT_AUTHOR_NAME": "Fixture", "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
                    "GIT_COMMITTER_NAME": "Fixture", "GIT_COMMITTER_EMAIL": "fixture@example.invalid"}
        self.git("init", "--quiet", "-b", "main")
        (self.external / "README.md").write_text("fixture only\n")
        self.git("add", "README.md")
        self.git("commit", "--quiet", "-m", "fixture")
        self.git("worktree", "add", "--quiet", "-b", "review", str(self.worktree))

    def git(self, *args):
        result = subprocess.run(["/usr/bin/git", "-c", "core.hooksPath=/dev/null",
                                 "-c", "core.fsmonitor=false", *args],
                                cwd=self.external, env=self.env, stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=8)
        self.assertEqual(result.returncode, 0, "fixture Git setup failed")

    def context(self, cwd, **kwargs):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), \
                patch.object(H, "trusted_roots", side_effect=AssertionError("registry consulted")), \
                patch.object(H, "strict_json", side_effect=AssertionError("registry read")), \
                patch.object(H, "git_root", side_effect=AssertionError("Git consulted")), \
                patch.object(H.subprocess, "run", side_effect=AssertionError("command executed")):
            H.context({"cwd": cwd}, home=self.home, registry_path=self.registry, **kwargs)
        report = json.loads(output.getvalue())
        self.assertEqual(set(report), {"hookSpecificOutput"})
        hook = report["hookSpecificOutput"]
        self.assertEqual(set(hook), {"hookEventName", "additionalContext"})
        self.assertEqual(hook["hookEventName"], "SessionStart")
        self.assertLess(len(output.getvalue().encode()), 2048)
        self.assertNotIn(str(self.root), output.getvalue())
        return hook["additionalContext"]

    def neutral(self, path):
        message = self.context(str(path))
        for text in ("grants no repository trust or permissions", "read/edit",
                     "repo-local development", "closest repository/AGENTS.md",
                     "native permission policy", "unknown external code",
                     "quarantine/sandbox", "$manage-workstation"):
            self.assertIn(text, message)
        self.assertNotIn("registered as trusted", message)
        self.assertNotIn("Control intent", message)
        return message

    def test_outside_aidev_repo_spaces_worktree_and_generic_directory_share_neutral_context(self):
        expected = self.neutral(self.external)
        self.assertEqual(self.neutral(self.worktree), expected)
        self.assertEqual(self.neutral(self.generic), expected)
        subdir = self.external / "nested folder"
        subdir.mkdir()
        self.assertEqual(self.neutral(subdir), expected)

    def test_absent_malformed_stale_duplicate_and_unreadable_registry_never_affect_startup(self):
        expected = self.neutral(self.external)
        values = (b"not JSON", b'{"schema":1,"repositories":[]}',
                  b'{"schema":1,"schema":2,"repositories":[]}',
                  json.dumps({"schema": 1, "repositories": [{"canonicalRoot": "$HOME/missing"}]}).encode())
        for raw in values:
            with self.subTest(raw=raw):
                self.registry.write_bytes(raw)
                self.assertEqual(self.neutral(self.external), expected)
                self.assertEqual(self.neutral(self.worktree), expected)
                self.assertEqual(self.registry.read_bytes(), raw)
        self.registry.chmod(0)
        try:self.assertEqual(self.neutral(self.generic), expected)
        finally:self.registry.chmod(0o600)
        self.registry.unlink()
        self.assertEqual(self.neutral(self.worktree), expected)
        self.assertFalse(self.registry.exists())

    def test_read_only_worktree_is_not_written_or_interrogated(self):
        paths = list(self.worktree.iterdir())
        before = {path.name: path.read_bytes() for path in paths}
        modes = {path: path.stat().st_mode & 0o777 for path in paths}
        for path in paths:path.chmod(0o400)
        self.worktree.chmod(0o500)
        try:
            self.neutral(self.worktree)
            self.assertEqual({path.name: path.read_bytes() for path in paths}, before)
            self.assertEqual(set(self.worktree.iterdir()), set(paths))
        finally:
            self.worktree.chmod(0o700)
            for path, mode in modes.items():path.chmod(mode)

    def test_control_quarantine_and_canonical_aliases_keep_separate_guidance(self):
        for path in (self.control, self.control_worktree):
            message = self.context(str(path))
            self.assertIn("Control source can affect live hooks", message)
            self.assertIn("ARCHITECTURE.md", message)
            self.assertIn("docs/harness-operations.md", message)
            self.assertIn("Source-only work needs no live doctor", message)
            self.assertNotIn("independent review", message)
        message = self.context(str(self.quarantine))
        self.assertIn("This input is quarantined", message)
        self.assertIn("do not use secrets, user MCP/apps", message)
        for target in (self.control, self.quarantine):
            alias = self.root / (target.name + " alias")
            alias.symlink_to(target, target_is_directory=True)
            self.assertEqual(self.context(str(alias)), self.context(str(target)))
        for relative in ("AIDev/control-other", "AIDev/worktrees/control-other", "AIDev/quarantine-other"):
            sibling = self.home / relative
            sibling.mkdir(parents=True)
            self.neutral(sibling)

    def test_git_metadata_cannot_promote_external_cwd_into_control(self):
        self.git("config", "core.worktree", str(self.control))
        self.neutral(self.external)
        self.assertNotIn("Control intent", self.context(str(self.external)))

    def test_missing_malformed_relative_and_oversized_cwd_are_bounded_nonblocking(self):
        file = self.root / "file"
        file.write_text("fixture")
        for value in (None, True, 1, [], {}, "", "relative", str(self.root / "missing"),
                      str(file), "/null\x00path", "/new\nline", "/del\x7fpath", "/" + "x" * 4097):
            with self.subTest(value=value):
                self.assertIn("Working-directory context is unavailable", self.context(value))
        with patch.object(H.Path, "resolve", side_effect=PermissionError("private detail")):
            message = self.context(str(self.external))
        self.assertIn("context is unavailable", message)
        self.assertNotIn("private detail", message)
        with patch.object(H.os, "access", return_value=False):
            self.assertIn("context is unavailable", self.context(str(self.external)))

    def test_context_main_missing_or_nonstring_cwd_keeps_bounded_output(self):
        for value in ({"hook_event_name": "SessionStart"},
                      {"hook_event_name": "SessionStart", "cwd": []}):
            output = io.StringIO()
            with patch.object(H.sys, "argv", [str(SOURCE), "context"]), \
                    patch.object(H.sys, "stdin", io.StringIO(json.dumps(value))), \
                    contextlib.redirect_stdout(output):
                H.main()
            self.assertNotIn("continue", json.loads(output.getvalue()))
            self.assertIn("context is unavailable", output.getvalue())
        for operation in ("warn", "verify"):
            with patch.object(H.sys, "argv", [str(SOURCE), operation]), \
                    patch.object(H.sys, "stdin", side_effect=AssertionError("legacy stdin read")), \
                    patch.object(H, "canonical_home", side_effect=AssertionError("home read")), \
                    patch.object(H.subprocess, "run", side_effect=AssertionError("command executed")):
                self.assertIsNone(H.main())

    def test_legacy_policing_direct_calls_are_inert_for_dirty_or_local_work(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), \
                patch.object(H, "zone", side_effect=AssertionError("registry route queried")), \
                patch.object(H, "canonical_home", side_effect=AssertionError("home read")), \
                patch.object(H.subprocess, "run", side_effect=AssertionError("Git queried")):
            for command in ("cargo install --path . --root ./fixture-tools", "gem install --install-dir ./vendor",
                            "brew install fixture", "sudo installer -pkg fixture.pkg -target /", "x" * 40000):
                self.assertFalse(H.workstation_bypass(command))
                H.warn({"tool_name": "Bash", "tool_input": {"command": command}})
            for value in ({}, None, {"cwd": str(self.control), "dirty": True}):
                H.verify(value, home=self.home, registry_path=self.registry)
        self.assertEqual(output.getvalue(), "")

    def test_successor_definition_has_one_dynamic_context_and_no_policing(self):
        value = json.loads((ROOT / "codex/hooks.json").read_text())
        self.assertEqual(set(value["hooks"]), {"SessionStart"})
        definitions = value["hooks"]["SessionStart"]
        self.assertEqual(len(definitions), 1)
        commands = definitions[0]["hooks"]
        self.assertEqual(len(commands), 1)
        self.assertTrue(commands[0]["command"].endswith('" context'))
        self.assertNotIn("printf", commands[0]["command"])

    def test_candidate_cli_sessionstart_is_neutral_without_installed_hook_execution(self):
        result = subprocess.run([sys.executable, "-B", str(SOURCE), "context"],
                                input=json.dumps({"hook_event_name": "SessionStart", "cwd": str(self.external)}),
                                text=True, capture_output=True, env=self.env, timeout=5)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, "")
        self.assertEqual(set(json.loads(result.stdout)), {"hookSpecificOutput"})
        self.assertIn("grants no repository trust or permissions", result.stdout)
        self.assertNotIn(str(self.external), result.stdout)

    def test_malformed_and_oversized_event_payload_is_bounded_nonblocking(self):
        for raw in ("not JSON", "[]", "{" * 80, "x" * (H.EVENT_LIMIT + 1)):
            output = io.StringIO()
            source = io.StringIO(raw)
            with patch.object(H.sys, "argv", [str(SOURCE), "context"]), \
                    patch.object(H.sys, "stdin", source), contextlib.redirect_stdout(output):
                self.assertIsNone(H.main())
            self.assertLessEqual(source.tell(), H.EVENT_LIMIT + 1)
            message = json.loads(output.getvalue())["hookSpecificOutput"]["additionalContext"]
            self.assertIn("context is unavailable", message)
            self.assertLess(len(output.getvalue()), 700)
            self.assertNotIn("continue", json.loads(output.getvalue()))

    def test_disposable_or_external_context_creates_no_control_lifecycle(self):
        before = {str(p.relative_to(self.root)): p.read_bytes()
                  for p in self.root.rglob("*") if p.is_file()}
        self.neutral(self.external)
        self.neutral(self.worktree)
        self.neutral(self.generic)
        self.assertEqual(before, {str(p.relative_to(self.root)): p.read_bytes()
                                  for p in self.root.rglob("*") if p.is_file()})
        self.assertEqual(list(self.registry.parent.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
