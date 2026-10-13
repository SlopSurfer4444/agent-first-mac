"""Read-only checker tests over owned Git fixtures; no live trust/network use."""

import contextlib
import copy
import importlib.machinery
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader(name, loader))
    loader.exec_module(module)
    return module


C = load("repo_trust_checker", ROOT / "bin/check-repo-trust")
H = load("repo_trust_existing_hook", ROOT / "codex/hooks/phase5-contract.py")
REMOTE = "https://github.com/example/fixture-project.git"
REPO_ID = "fixture-project"
WORKTREE_ID = "fixture-project-review"


class RepoTrustTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="aid-repo-trust-test-")
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name).resolve() / "owner"
        self.home.mkdir(mode=0o700)
        self.primary = self.home / "AIDev/repos/fixture-project"
        self.linked = self.home / "AIDev/worktrees/fixture-project/review"
        self.control = self.home / "AIDev/control"
        self.registry_path = self.control / "manifests/trusted-repos.json"
        self.primary.mkdir(parents=True)
        self.registry_path.parent.mkdir(parents=True)
        self.linked.parent.mkdir(parents=True)
        self.env = {"HOME": str(self.home), "PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
            "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1", "GIT_TERMINAL_PROMPT": "0",
            "GIT_AUTHOR_NAME": "Fixture", "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
            "GIT_COMMITTER_NAME": "Fixture", "GIT_COMMITTER_EMAIL": "fixture@example.invalid"}
        self.git(self.primary, "init", "--quiet", "-b", "main")
        (self.primary / "README.md").write_text("fixture\n")
        self.git(self.primary, "add", "README.md")
        self.git(self.primary, "commit", "--quiet", "-m", "fixture adoption")
        self.adopted = self.git(self.primary, "rev-parse", "HEAD").strip().decode()
        self.git(self.primary, "remote", "add", "origin", REMOTE)
        self.git(self.primary, "worktree", "add", "--quiet", "-b", "codex/review", str(self.linked))
        self.common = self.primary / ".git"
        self.admin = Path((self.linked / ".git").read_text()[8:].strip())
        self.registry = {"schema": 1, "repositories": [
            {"id": "control", "canonicalRoot": "$HOME/AIDev/control", "provenance": "reviewed-control",
             "trust": "trusted-control", "route": "trusted", "adoptedCommit": self.adopted},
            {"id": REPO_ID, "canonicalRoot": "$HOME/AIDev/repos/fixture-project", "provenance": "reviewed-clone",
             "trust": "trusted-repo", "route": "trusted", "adoptedCommit": self.adopted},
            {"id": WORKTREE_ID, "canonicalRoot": "$HOME/AIDev/worktrees/fixture-project/review",
             "provenance": "reviewed-clone", "trust": "trusted-repo", "route": "trusted",
             "adoptedCommit": self.adopted}]}
        self.save_registry()

    def git(self, root, *args):
        result = subprocess.run(("/usr/bin/git", "--no-pager", "-c", "core.hooksPath=/dev/null",
            "-c", "core.fsmonitor=false", *args), cwd=root, env=self.env,
            stdin=subprocess.DEVNULL, capture_output=True, timeout=8, check=False)
        self.assertEqual(result.returncode, 0, "fixture Git setup failed")
        return result.stdout

    def save_registry(self):
        self.registry_path.write_text(json.dumps(self.registry))

    def check(self, **kwargs):
        return C.inspect(REPO_ID, WORKTREE_ID, REMOTE, home=self.home, uid=os.getuid(),
                         registry_path=self.registry_path, **kwargs)

    def rejects(self, reason=None):
        with self.assertRaises((C.CheckError, OSError)) as caught:
            self.check()
        if reason:
            self.assertEqual(str(caught.exception), reason)

    def advance(self, root, label):
        (root / "README.md").write_text(label + "\n")
        self.git(root, "add", "README.md")
        self.git(root, "commit", "--quiet", "-m", label)

    def test_primary_and_linked_identity_pass_without_writes(self):
        before = {path: path.read_bytes() for path in (self.registry_path, self.common / "config",
                  self.common / "HEAD", self.linked / ".git", self.admin / "commondir", self.admin / "gitdir")}
        result = self.check()
        self.assertEqual(result["result"], "pass")
        self.assertTrue(result["primaryVerified"] and result["linkedVerified"]
                        and result["adoptedAncestorVerified"] and result["childrenSettled"])
        self.assertFalse(result["trustChanged"] or result["networkAccessed"])
        self.assertEqual(before, {path: path.read_bytes() for path in before})
        self.assertNotIn(str(self.home), json.dumps(result))
        self.assertNotIn(REMOTE, json.dumps(result))
        self.assertNotIn(self.adopted, json.dumps(result))

    def test_success_does_not_capture_callers_handled_exception(self):
        try:
            raise RuntimeError("unrelated caller failure")
        except RuntimeError:
            self.assertEqual(self.check()["result"], "pass")

    def test_both_heads_may_advance_after_adoption(self):
        self.advance(self.primary, "primary descendant")
        self.advance(self.linked, "linked descendant")
        self.assertNotEqual(self.git(self.primary, "rev-parse", "HEAD").strip().decode(), self.adopted)
        self.assertNotEqual(self.git(self.linked, "rev-parse", "HEAD").strip().decode(), self.adopted)
        self.assertEqual(self.check()["result"], "pass")

    def test_packed_branch_refs_are_supported(self):
        self.git(self.primary, "pack-refs", "--all", "--prune")
        self.assertEqual(self.check()["result"], "pass")

    def test_detached_linked_head_still_requires_adopted_ancestry(self):
        self.git(self.linked, "checkout", "--quiet", "--detach", self.adopted)
        self.assertEqual(self.check()["result"], "pass")

    def test_wrong_origin_is_rejected(self):
        self.git(self.primary, "remote", "set-url", "origin", "https://github.com/example/other.git")
        self.rejects("origin_mismatch")

    def test_duplicate_origin_values_are_rejected(self):
        self.git(self.primary, "config", "--add", "remote.origin.url", REMOTE)
        self.rejects("origin_mismatch")

    def test_missing_adopted_object_is_rejected(self):
        self.registry["repositories"][1]["adoptedCommit"] = "f" * 40
        self.save_registry()
        self.rejects()

    def test_adopted_object_must_itself_be_a_commit(self):
        self.git(self.primary, "tag", "-a", "adoption-tag", "-m", "not a commit object")
        self.registry["repositories"][1]["adoptedCommit"] = self.git(
            self.primary, "rev-parse", "adoption-tag").strip().decode()
        self.save_registry()
        self.rejects("adopted_commit_missing")

    def test_adopted_commit_must_be_ancestor_not_just_present(self):
        self.git(self.linked, "checkout", "--quiet", "--orphan", "unrelated")
        self.advance(self.linked, "unrelated root")
        self.rejects("adopted_commit_not_ancestor")

    def test_primary_git_pointer_is_not_an_accepted_primary(self):
        original = self.common.with_name("retained-git")
        self.common.rename(original)
        self.common.write_text("gitdir: " + str(original) + "\n")
        self.rejects()

    def test_missing_primary_git_is_rejected_before_execution(self):
        self.common.rename(self.common.with_name("retained-git"))
        with patch.object(C.subprocess, "Popen", side_effect=AssertionError("must not execute")):
            self.rejects()

    def test_primary_git_symlink_is_rejected(self):
        original = self.common.with_name("retained-git")
        self.common.rename(original)
        self.common.symlink_to(original, target_is_directory=True)
        self.rejects()

    def test_linked_git_directory_cannot_impersonate_worktree(self):
        (self.linked / ".git").unlink()
        (self.linked / ".git").mkdir()
        self.rejects()

    def test_foreign_linked_pointer_is_rejected_before_git_execution(self):
        (self.linked / ".git").write_text("gitdir: " + str(self.home / "foreign/.git/worktrees/review") + "\n")
        with patch.object(C.subprocess, "Popen", side_effect=AssertionError("must not execute")):
            self.rejects("foreign_worktree_pointer")

    def test_linked_pointer_symlink_is_rejected(self):
        pointer = self.linked / ".git"
        saved = self.linked / "saved-pointer"
        pointer.rename(saved)
        pointer.symlink_to(saved)
        self.rejects()

    def test_foreign_commondir_is_rejected(self):
        (self.admin / "commondir").write_text(str(self.home / "foreign/.git") + "\n")
        self.rejects("foreign_common_directory")

    def test_bad_backlink_is_rejected(self):
        (self.admin / "gitdir").write_text(str(self.linked.parent / "sibling/.git") + "\n")
        self.rejects("worktree_backlink_mismatch")

    def test_missing_backlink_is_rejected(self):
        (self.admin / "gitdir").unlink()
        self.rejects()

    def test_symlinked_backlink_and_admin_directory_are_rejected(self):
        target = self.admin / "gitdir"
        original = self.admin / "saved-backlink"
        target.rename(original)
        target.symlink_to(original)
        self.rejects()
        target.unlink()
        original.rename(target)
        old_admin = self.admin.with_name("retained-admin")
        self.admin.rename(old_admin)
        self.admin.symlink_to(old_admin, target_is_directory=True)
        self.rejects()

    def test_unsafe_writable_directory_or_file_is_rejected(self):
        self.primary.chmod(0o777)
        self.rejects("unsafe_metadata")
        self.primary.chmod(0o755)
        (self.common / "config").chmod(0o666)
        self.rejects("unsafe_metadata")

    def test_wrong_owner_and_hardlinked_metadata_are_rejected(self):
        with self.assertRaisesRegex(C.CheckError, "unsafe_metadata"):
            C.inspect(REPO_ID, WORKTREE_ID, REMOTE, home=self.home, uid=os.getuid() + 1,
                      registry_path=self.registry_path)
        os.link(self.common / "config", self.home / "config-hardlink")
        self.rejects("unsafe_metadata")

    def test_symlinked_branch_reference_is_rejected(self):
        reference = self.common / "refs/heads/main"
        target = self.home / "foreign-ref"
        reference.rename(target)
        reference.symlink_to(target)
        self.rejects()

    def test_registry_symlink_or_duplicate_json_key_is_rejected(self):
        raw = self.registry_path.read_bytes()
        self.registry_path.write_bytes(raw[:-1] + b',"schema":1}')
        self.rejects("invalid_registry")
        saved = self.registry_path.with_name("saved-registry.json")
        self.registry_path.rename(saved)
        self.registry_path.symlink_to(saved)
        self.rejects()

    def test_indirection_files_and_config_includes_fail_closed(self):
        for path in (self.common / "commondir", self.common / "info/grafts",
                     self.common / "objects/info/alternates"):
            with self.subTest(path=path.name):
                path.write_text("foreign\n")
                self.rejects("unsupported_git_indirection")
                path.unlink()
        self.git(self.primary, "config", "include.path", str(self.home / "never-read-config"))
        self.rejects("unsupported_git_config")

    def test_metadata_drift_during_command_is_rejected(self):
        original = subprocess.Popen
        changed = False
        def factory(*args, **kwargs):
            nonlocal changed
            if not changed:
                (self.admin / "gitdir").write_text("changed\n")
                changed = True
            return original(*args, **kwargs)
        with self.assertRaisesRegex(C.CheckError, "metadata_changed"):
            self.check(process_factory=factory)

    def test_commands_have_sanitized_environment_and_read_only_vectors(self):
        original = subprocess.Popen
        seen = []
        def factory(argv, **kwargs):
            seen.append(argv)
            self.assertEqual(argv[:len(C.Git.PREFIX)], C.Git.PREFIX)
            self.assertEqual(kwargs["env"]["GIT_CONFIG_GLOBAL"], "/dev/null")
            self.assertEqual(kwargs["env"]["GIT_CONFIG_NOSYSTEM"], "1")
            self.assertEqual(kwargs["env"]["GIT_ALLOW_PROTOCOL"], "")
            self.assertNotIn("SSH_AUTH_SOCK", kwargs["env"])
            self.assertTrue(kwargs["start_new_session"] and kwargs["close_fds"])
            self.assertIn(argv[len(C.Git.PREFIX)], ("config", "rev-parse", "cat-file", "merge-base"))
            return original(argv, **kwargs)
        self.assertEqual(self.check(process_factory=factory)["result"], "pass")
        self.assertEqual(len(seen), 15)
        self.assertEqual(seen[0][len(C.Git.PREFIX):], ("config", "--no-includes", "--file",
                         str(self.common / "config"), "--null", "--list"))

    def test_ambient_git_configuration_cannot_supply_identity(self):
        poison = {"GIT_DIR": str(self.home / "foreign"), "GIT_WORK_TREE": str(self.home / "foreign"),
                  "GIT_CONFIG_GLOBAL": str(self.home / "never-read-global"),
                  "GIT_OBJECT_DIRECTORY": str(self.home / "foreign"),
                  "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "remote.origin.url",
                  "GIT_CONFIG_VALUE_0": "https://github.com/example/foreign.git"}
        with patch.dict(os.environ, poison):
            self.assertEqual(self.check()["result"], "pass")

    def test_actual_hook_neutral_project_context_and_control_separation(self):
        self.assertEqual(H.zone(self.primary, home=self.home, registry_path=self.registry_path), "trusted_repo")
        self.assertEqual(H.zone(self.linked, home=self.home, registry_path=self.registry_path), "trusted_repo")
        self.assertEqual(H.zone(self.control, home=self.home, registry_path=self.registry_path), "control")
        sibling = self.linked.parent / "unknown"
        self.git(self.primary, "worktree", "add", "--quiet", "-b", "unknown", str(sibling))
        self.assertEqual(H.zone(sibling, home=self.home, registry_path=self.registry_path), "unknown_git")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            H.context({"cwd": str(sibling)}, home=self.home, registry_path=self.registry_path)
        report = json.loads(output.getvalue())
        self.assertNotIn("continue", report)
        self.assertIn("grants no repository trust", report["hookSpecificOutput"]["additionalContext"])

    def test_registry_roles_never_promote_selected_root_to_control(self):
        self.registry["repositories"][1]["trust"] = "trusted-control"
        self.save_registry()
        self.rejects("invalid_registry")
        self.registry["repositories"][1]["trust"] = "trusted-repo"
        self.registry["repositories"][2]["canonicalRoot"] = "$HOME/AIDev/worktrees/control"
        self.save_registry()
        self.rejects("selected_root_role_mismatch")

    def test_invalid_cli_input_never_invokes_operation_or_echoes_remote(self):
        for args in ([], ["--repo-id", "../outside"],
                     ["--repo-id", REPO_ID, "--worktree-id", WORKTREE_ID, "--remote", "https://secret@github.com/x/y"],
                     ["--repo-id", REPO_ID, "--worktree-id", WORKTREE_ID, "--remote", REMOTE, "--registry", "override"]):
            with self.subTest(args=args):
                output = []
                result = C.main(args + ["--json"], operation=lambda *a: self.fail("unexpected execution"), emit=output.append)
                self.assertEqual(result, 2)
                self.assertEqual(json.loads(output[0])["reason"], "invalid_arguments")
                self.assertNotIn("secret", output[0])

    def test_pure_selection_types_paths_duplicates_and_missing_ids(self):
        for mutate in (lambda r: r.update({"schema": True}),
                       lambda r: r["repositories"].append(copy.deepcopy(r["repositories"][1])),
                       lambda r: r["repositories"][1].update({"adoptedCommit": "0" * 40}),
                       lambda r: r["repositories"][1].update({"canonicalRoot": "$HOME/AIDev/repos/../control"}),
                       lambda r: r["repositories"].pop()):
            with self.subTest(mutate=mutate):
                value = copy.deepcopy(self.registry)
                mutate(value)
                with self.assertRaises(C.CheckError):
                    C.validate_registry(json.dumps(value).encode(), REPO_ID, WORKTREE_ID, REMOTE)

    def test_total_budget_fails_closed_before_git_launch(self):
        with patch.object(C, "MAX_TOTAL", 1):
            self.rejects("total_size_limit")

    def test_deadline_fails_before_launch(self):
        with patch.object(C, "DEADLINE_SECONDS", -1), \
                patch.object(C.subprocess, "Popen", side_effect=AssertionError("must not execute")):
            self.rejects("deadline_exceeded")


class GitCleanupTests(unittest.TestCase):
    """Exercise termination failures without signalling any real process."""
    class Child:
        pid = 424242

        def __init__(self, output=b"", *, hold_open=False, wait_fails=False, exited=False):
            self.returncode = 0 if exited else None
            self.wait_fails = wait_fails
            self.waits = []
            self.writers = []
            streams = []
            for data in (output, b""):
                reader, writer = os.pipe()
                streams.append(os.fdopen(reader, "rb"))
                if data:
                    os.write(writer, data)
                if hold_open:
                    self.writers.append(writer)
                else:
                    os.close(writer)
            self.stdout, self.stderr = streams

        def poll(self):
            return self.returncode

        def wait(self, timeout):
            self.waits.append(timeout)
            if self.wait_fails:
                raise subprocess.TimeoutExpired("fixed fixture Git", timeout)
            self.returncode = -9
            return self.returncode

        def close(self):
            for stream in (self.stdout, self.stderr):
                stream.close()
            for writer in self.writers:
                os.close(writer)

    def run_child(self, child, *, signal_error=None, timeout=False):
        self.addCleanup(child.close)
        with tempfile.TemporaryDirectory(prefix="aid-repo-trust-cleanup-") as temporary:
            home = Path(temporary).resolve()
            guard = C.Guard(home, os.getuid())
            try:
                with patch.object(C.os, "killpg", side_effect=signal_error) as kill, \
                        patch.object(C, "MAX_OUTPUT", 1), \
                        patch.object(C, "COMMAND_SECONDS", 0.01 if timeout else 1.0):
                    with self.assertRaises(C.CheckError) as caught:
                        C.Git(guard, lambda *a, **kw: child).read(home, "config", "--null", "--list")
                self.assertTrue(child.stdout.closed and child.stderr.closed)
                return caught.exception, kill.call_count
            finally:
                guard.close()

    def test_output_limit_kills_and_reaps_owned_mock_child(self):
        child = self.Child(b"oversized")
        error, signals = self.run_child(child)
        self.assertEqual(error.reason, "git_output_limit")
        self.assertTrue(error.child_settled)
        self.assertEqual(signals, 1)
        self.assertEqual(child.waits, [1.0])

    def test_already_exited_child_is_not_signalled(self):
        child = self.Child(b"oversized", exited=True)
        error, signals = self.run_child(child)
        self.assertEqual(error.reason, "git_output_limit")
        self.assertTrue(error.child_settled)
        self.assertEqual(signals, 0)
        self.assertEqual(child.waits, [])

    def test_timeout_kills_and_reaps_owned_mock_child(self):
        child = self.Child(hold_open=True)
        error, signals = self.run_child(child, timeout=True)
        self.assertEqual(error.reason, "git_timeout")
        self.assertTrue(error.child_settled)
        self.assertEqual(signals, 1)
        self.assertEqual(child.waits, [1.0])

    def test_exited_parent_with_open_pipes_does_not_claim_settlement(self):
        child = self.Child(hold_open=True, exited=True)
        error, signals = self.run_child(child, timeout=True)
        self.assertEqual(error.reason, "git_timeout")
        self.assertFalse(error.child_settled)
        self.assertEqual(signals, 0)

    def test_denied_signal_is_not_retried_and_still_reaps_and_closes(self):
        child = self.Child(b"oversized")
        error, signals = self.run_child(child, signal_error=PermissionError("denied"))
        self.assertEqual(error.reason, "git_output_limit")
        self.assertFalse(error.child_settled)
        self.assertEqual(error.cleanup_errors[0][0], "git_signal_denied")
        self.assertEqual(signals, 1)
        self.assertEqual(child.waits, [1.0])
        output = []
        def fail(*args):
            raise error
        code = C.main(["--repo-id", REPO_ID, "--worktree-id", WORKTREE_ID,
                       "--remote", REMOTE, "--json"], operation=fail, emit=output.append)
        self.assertEqual(code, 1)
        self.assertFalse(json.loads(output[0])["childrenSettled"])

    def test_incomplete_reap_is_fail_closed_and_streams_close(self):
        child = self.Child(b"oversized", wait_fails=True)
        error, signals = self.run_child(child)
        self.assertEqual(error.reason, "git_output_limit")
        self.assertFalse(error.child_settled)
        self.assertEqual(error.cleanup_errors[0][0], "git_settlement_failed")
        self.assertEqual(signals, 1)


class CleanupCascadeTests(unittest.TestCase):
    """Connected main/inspect/Git/Guard failures with no process or filesystem IO."""
    @staticmethod
    def guard():
        guard = object.__new__(C.Guard)
        guard.home = Path("/fixture-owner")
        guard.uid = 501
        guard.deadline = C.time.monotonic() + 30
        guard.total = 0
        guard.files = {"one": (90001, (), b""), "two": (90002, (), b"")}
        guard.directories = {"three": (90003, ())}
        guard.absent = set()
        return guard

    def exercise(self, original=None, faults=None):
        faults = {} if faults is None else faults
        events = []
        def event(name):
            events.append(name)
            if name in faults:
                raise faults[name]
        guard = self.guard()
        common = guard.home / "AIDev/repos/fixture-project/.git"
        linked = guard.home / "AIDev/worktrees/fixture-project/review"
        admin = common / "worktrees/review"
        rows = [{"id": ident, "canonicalRoot": root, "provenance": provenance,
                 "trust": trust, "route": "trusted", "adoptedCommit": "a" * 40}
                for ident, root, provenance, trust in (
                    ("control", "$HOME/AIDev/control", "reviewed-control", "trusted-control"),
                    (REPO_ID, "$HOME/AIDev/repos/fixture-project", "reviewed-clone", "trusted-repo"),
                    (WORKTREE_ID, "$HOME/AIDev/worktrees/fixture-project/review", "reviewed-clone", "trusted-repo"))]
        raw = {guard.home / "AIDev/control/manifests/trusted-repos.json":
                   json.dumps({"schema": 1, "repositories": rows}).encode(),
               common / "config": b"", linked / ".git": ("gitdir: " + str(admin) + "\n").encode(),
               admin / "commondir": b"../..\n", admin / "gitdir": (str(linked / ".git") + "\n").encode()}
        guard.read = lambda path, *a: raw[Path(path)]
        guard.directory = lambda *a: None
        guard.missing = lambda *a: None
        guard.recheck = lambda: None

        class Stream:
            def __init__(self, name, fd):
                self.name, self.fd = name, fd
            def fileno(self):
                return self.fd
            def close(self):
                event(self.name + "_close")

        class Child:
            pid = 424242
            returncode = None
            stdout, stderr = Stream("stdout", 80001), Stream("stderr", 80002)
            def poll(self):
                event("poll")
                return self.returncode
            def wait(self, timeout):
                event("wait")
                self.returncode = 0
                return 0

        class Selector:
            def __init__(self):
                self.items = {}
            def register(self, stream, mask, index):
                self.items[stream] = SimpleNamespace(fileobj=stream, data=index)
            def unregister(self, stream):
                del self.items[stream]
            def get_map(self):
                return self.items
            def select(self, timeout):
                if original is not None:
                    raise original
                return [(key, None) for key in self.items.values()]
            def close(self):
                event("selector_close")

        def factory(*args, **kwargs):
            event("launch")
            return Child()
        def operation(*args):
            return C.inspect(*args, home=guard.home, uid=501, process_factory=factory)
        output, escaped, status = [], None, None
        with patch.object(C, "Guard", return_value=guard), \
                patch.object(C, "hold_head"), \
                patch.object(C.selectors, "DefaultSelector", Selector), \
                patch.object(C.os, "set_blocking"), \
                patch.object(C.os, "read", return_value=b""), \
                patch.object(C.os, "killpg", side_effect=lambda *a: event("signal")), \
                patch.object(C.os, "close", side_effect=lambda fd: event("fd_" + str(fd))):
            try:
                status = C.main(["--repo-id", REPO_ID, "--worktree-id", WORKTREE_ID,
                                 "--remote", REMOTE, "--json"], operation=operation, emit=output.append)
            except BaseException as error:
                escaped = error
        self.assertEqual(guard.files, {})
        self.assertEqual(guard.directories, {})
        return status, output, escaped, events

    def assert_all_cleanup(self, events):
        for name in ("selector_close", "poll", "wait", "stdout_close", "stderr_close",
                     "fd_90001", "fd_90002", "fd_90003"):
            self.assertIn(name, events)

    def test_original_unsettled_failure_survives_guard_close_failure_and_interruption(self):
        original = C.CheckError("git_settlement_failed", child_settled=False)
        status, output, escaped, events = self.exercise(original, {
            "fd_90001": OSError("private close detail"), "fd_90002": KeyboardInterrupt()})
        self.assertEqual(status, 1)
        self.assertIsNone(escaped)
        report = json.loads(output[0])
        self.assertEqual(report["reason"], original.reason)
        self.assertFalse(report["childrenSettled"])
        self.assertFalse(original.child_settled)
        self.assertNotIn("private", output[0])
        self.assert_all_cleanup(events)

    def test_selector_close_failure_cannot_skip_later_cleanup(self):
        status, output, escaped, events = self.exercise(faults={
            "selector_close": OSError("selector detail"), "poll": KeyboardInterrupt(),
            "stdout_close": OSError("stream detail"), "stderr_close": SystemExit(7),
            "fd_90001": OSError("descriptor detail")})
        self.assertEqual(status, 1)
        self.assertIsNone(escaped)
        self.assertEqual(json.loads(output[0])["reason"], "git_selector_close_failed")
        self.assertFalse(json.loads(output[0])["childrenSettled"])
        self.assert_all_cleanup(events)

    def test_original_interruptions_survive_combined_cleanup_failures(self):
        for original in (KeyboardInterrupt(), SystemExit(9)):
            with self.subTest(interruption=type(original).__name__):
                status, output, escaped, events = self.exercise(original, {
                    "selector_close": OSError("selector"), "poll": OSError("poll"),
                    "wait": SystemExit(2), "stdout_close": KeyboardInterrupt(),
                    "stderr_close": OSError("stream"), "fd_90001": KeyboardInterrupt(),
                    "fd_90002": OSError("descriptor")})
                self.assertIs(escaped, original)
                self.assertIsNone(status)
                self.assertEqual(output, [])
                self.assertFalse(original.child_settled)
                self.assertNotIn("signal", events)
                self.assert_all_cleanup(events)

    def test_guard_close_attempts_each_fd_after_first_interruption(self):
        for original in (KeyboardInterrupt(), SystemExit(6)):
            with self.subTest(interruption=type(original).__name__):
                guard = self.guard()
                with patch.object(C.os, "close", side_effect=[original, OSError("close"), None]) as close:
                    with self.assertRaises(BaseException) as caught:
                        guard.close()
                self.assertIs(caught.exception, original)
                self.assertEqual([call.args[0] for call in close.call_args_list], [90001, 90002, 90003])
                self.assertEqual(guard.files, {})
                self.assertEqual(guard.directories, {})

    def test_launch_interruption_keeps_unresolved_status_through_guard_failure(self):
        original = KeyboardInterrupt()
        status, output, escaped, events = self.exercise(faults={
            "launch": original, "selector_close": OSError("selector"),
            "fd_90001": SystemExit(1), "fd_90002": OSError("descriptor")})
        self.assertIs(escaped, original)
        self.assertFalse(original.child_settled)
        self.assertIsNone(status)
        self.assertEqual(output, [])
        self.assertNotIn("signal", events)
        self.assertNotIn("poll", events)
        for name in ("selector_close", "fd_90001", "fd_90002", "fd_90003"):
            self.assertIn(name, events)

    def test_partial_metadata_open_keeps_original_interruption_when_close_fails(self):
        for method in ("directory", "read"):
            with self.subTest(method=method):
                guard = self.guard()
                original = KeyboardInterrupt()
                if method == "read":
                    guard.directory = lambda *a: 90000
                with patch.object(C.os, "open", return_value=90004), \
                        patch.object(C.os, "fstat", side_effect=original), \
                        patch.object(C.os, "close", side_effect=OSError("close")) as close:
                    with self.assertRaises(KeyboardInterrupt) as caught:
                        getattr(guard, method)(guard.home)
                self.assertIs(caught.exception, original)
                close.assert_called_once_with(90004)


if __name__ == "__main__":
    unittest.main()
