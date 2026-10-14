"""Pure temporary Git fixtures; no installed programs or owner state."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import export_reference as E


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="reference-export-tests-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.git("init", "-q")
        self.names = ["lib/sample.py"]
        self.write("lib/sample.py", "# synthetic-owner synthetic-host\nvalue = 1\n")
        self.redactions = self.root / "private-redactions.json"
        self.redactions.write_text(json.dumps({"replacements": [["synthetic-owner", "example-user"], ["synthetic-host", "windows-host"]], "denyTerms": ["synthetic-owner", "synthetic-host"]}))
        self.commit()

    def git(self, *args):
        env = {**os.environ, "GIT_AUTHOR_NAME": "Example", "GIT_COMMITTER_NAME": "Example",
               "GIT_AUTHOR_EMAIL": "test@example.test", "GIT_COMMITTER_EMAIL": "test@example.test"}
        return subprocess.check_output(["/usr/bin/git", "-C", str(self.repo), *args], env=env, stderr=subprocess.DEVNULL)

    def write(self, name, content):
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)

    def commit(self):
        self.git("add", ".")
        self.git("commit", "-qm", "fixture")
        self.sha = self.git("rev-parse", "HEAD").decode().strip()

    def run_export(self, names=None, destination="output", commit=None):
        allow = self.root / "allow.json"
        allow.write_text(json.dumps(self.names if names is None else names))
        return E.export(self.repo, commit or self.sha, self.root / destination, self.redactions, allow)

    def test_committed_only_deterministic_modes_provenance(self):
        self.write("lib/sample.py", "SECRET checkout must not be read")
        first = self.run_export()
        second = self.run_export(destination="second")
        self.assertEqual(first, second)
        self.assertEqual(set(first), {"sourceCommit", "allowlistDigest", "redactionsDigest", "outputHashes"})
        self.assertNotIn(str(self.repo), json.dumps(first))
        output = self.root / "output/reference/lib/sample.py"
        self.assertEqual(output.read_text(), "# example-user windows-host\nvalue = 1\n")
        self.assertEqual(output.stat().st_mode & 0o777, 0o644)

    def test_unsafe_paths_and_categories(self):
        for name in ("../lib/sample.py", "/lib/sample.py", "lib//sample.py", "lib/./sample.py",
                     "lib/.git/config", "docs/a", "manifests/a.schema.json", "tests/fixtures/a", "lib/a\nb"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.run_export([name])
        self.assertFalse((self.root / "output").exists())

    def test_existing_destination_untouched(self):
        path = self.root / "output"
        path.mkdir()
        (path / "keep").write_text("keep")
        with self.assertRaises(ValueError):
            self.run_export()
        self.assertEqual((path / "keep").read_text(), "keep")

    def test_fixture_implementation_names_allowed(self):
        for name in ("lib/vendor_fixture_custody.py", "tests/test_vendor_fixture_custody.py"):
            self.write(name, "# fixture implementation\n")
        self.commit()
        self.run_export(["lib/vendor_fixture_custody.py", "tests/test_vendor_fixture_custody.py"])

    def test_missing_commit_abbreviated_and_missing_file(self):
        for sha in ("0" * 40, self.sha[:10], "HEAD"):
            with self.assertRaises(ValueError):
                self.run_export(commit=sha)
        with self.assertRaises(ValueError):
            self.run_export(["lib/missing.py"])

    def test_symlink_and_submodule_mode(self):
        (self.repo / "lib/link").symlink_to("sample.py")
        self.commit()
        with self.assertRaises(ValueError):
            self.run_export(["lib/link"])
        self.git("update-index", "--add", "--cacheinfo", "160000," + self.sha + ",lib/sub")
        self.git("commit", "-qm", "gitlink")
        self.sha = self.git("rev-parse", "HEAD").decode().strip()
        with self.assertRaises(ValueError):
            self.run_export(["lib/sub"])

    def test_collisions_duplicates_casefold(self):
        for name in ("lib/example-user", "lib/synthetic-owner", "lib/A", "lib/a"):
            self.write(name, "safe\n")
        self.commit()
        for names in (["lib/sample.py"] * 2, ["lib/example-user"]):
            with self.assertRaises(ValueError):
                self.run_export(names)
        # Case-only paths cannot coexist on all filesystems: validate tree fixture.
        original = E.git
        def fake(source, *args):
            if args[0] == "ls-tree":
                blob = self.git("rev-parse", self.sha + ":lib/sample.py").strip()
                return b"100644 blob " + blob + b"\tlib/A\0" + b"100644 blob " + blob + b"\tlib/a\0"
            return original(source, *args)
        with patch.object(E, "git", fake), self.assertRaises(ValueError):
            self.run_export(["lib/A", "lib/a"])

    def test_secrets_identifiers_and_named_examples(self):
        for value in ("ghp_" + "A" * 36, "-----BEGIN OPENSSH PRIVATE KEY-----",
                      "owner@private.org", "100.64.0.1", "aa:bb:cc:dd:ee:ff",
                      "12345678-1234-1234-1234-123456789abc", 'api_key="this-is-not-a-test-key"'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                E.scan(value)
        E.scan("test@example.test 127.0.0.1 0.0.0.0 192.0.2.3")

    def test_rejection_precedes_destination_creation(self):
        self.write("lib/sample.py", "ghp_" + "A" * 36)
        self.commit()
        with self.assertRaises(ValueError):
            self.run_export()
        self.assertFalse((self.root / "output").exists())

    def test_vendor_unchanged_or_rejected(self):
        self.write("vendor/license", "license\n")
        self.commit()
        self.run_export(["vendor/license"])
        self.assertEqual((self.root / "output/reference/vendor/license").read_bytes(), b"license\n")
        self.write("vendor/license", "synthetic-owner")
        self.commit()
        with self.assertRaises(ValueError):
            self.run_export(["vendor/license"], "rejected")

    def test_known_transform_requires_exact_anchor(self):
        name = "tests/test_vendor_compatibility_policy.py"
        self.write(name, "def test_version_equivalent_to_accepted_comparator_and_manifest_floor():\n" + E.OLD_FLOOR)
        self.commit()
        self.run_export([name])
        self.assertIn(E.NEW_FLOOR, (self.root / "output/reference" / name).read_text())
        self.write(name, "changed")
        self.commit()
        with self.assertRaises(ValueError):
            self.run_export([name], "drift")

    def test_binary_size_and_output_symlink(self):
        self.write("lib/sample.py", "x\0y")
        self.commit()
        with self.assertRaises(ValueError):
            self.run_export()
        (self.root / "output").symlink_to(self.root / "absent")
        with self.assertRaises(ValueError):
            self.run_export()
        with patch.object(E, "MAX_BLOB", 1), self.assertRaises(ValueError):
            self.run_export(destination="bounded")

    def test_git_disables_lazy_fetch(self):
        class Result:
            returncode = 0
            stdout = b"commit"
        with patch.object(E.subprocess, "run", return_value=Result()) as run:
            E.git(self.repo, "cat-file", "-t", self.sha)
        self.assertEqual(run.call_args.kwargs["env"]["GIT_NO_LAZY_FETCH"], "1")

    def test_exact_private_exception_and_drift(self):
        self.write("lib/sample.py", 'value = "100.64.0.1"\n')
        self.commit()
        rules = json.loads(self.redactions.read_text())
        rules["exceptions"] = [{"path": "lib/sample.py", "literal": "100.64.0.1", "class": "synthetic-fixture"}]
        self.redactions.write_text(json.dumps(rules))
        self.run_export()
        rules["exceptions"][0]["literal"] = "100.64.0.2"
        self.redactions.write_text(json.dumps(rules))
        with self.assertRaises(ValueError):
            self.run_export(destination="drift")


if __name__ == "__main__":
    unittest.main()
