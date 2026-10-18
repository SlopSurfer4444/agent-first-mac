"""Actual committed delivery closures on cloned source; no workstation calls."""
import importlib.machinery
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


class DeliveryClosureTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="delivery-closure.", dir="/private/tmp")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "source"
        subprocess.run(["/usr/bin/git", "clone", "--quiet", "--no-hardlinks", str(ROOT), str(self.root)],
                       check=True, capture_output=True, timeout=30)
        self.source = importlib.machinery.SourceFileLoader(
            "delivery_closure_source", str(self.root / "lib/scoped_source_admission.py")).load_module()
        self.cache_flags = patch.multiple(sys, dont_write_bytecode=True, pycache_prefix="/dev/null")
        self.cache_flags.start(); self.addCleanup(self.cache_flags.stop)

    def observe(self, entrypoint, data):
        paths = []
        source = self.source
        original = source.Held
        class Capture(original):
            def __init__(self, root, path, expected):
                paths.append(path)
                super().__init__(root, path, expected)
        with patch.object(source, "Held", Capture):
            with source.admitted_source(self.root, entrypoints=(entrypoint,), data_paths=(),
                                        opaque_paths=data) as (_, guard):
                self.assertIs(guard(), True)
        self.assertLess(len(paths), 64, "delivery unexpectedly pulled an unrelated history graph")
        self.assertNotIn("lib/workstation_maintenance_delivery.py", paths)
        self.assertNotIn("bin/current-doctor", paths)
        self.assertFalse(any(path.startswith("evidence/") for path in paths))
        self.assertTrue(set(data) <= set(paths))
        return paths

    def test_quarantine_only_consumed_manifest_and_images(self):
        data = ("manifests/quarantine-boundary-successor.json", "bin/codex-quarantine",
                "codex/quarantine.config.toml", "tests/fixtures/phase5-quarantine-before-current-cli.zsh",
                "tests/fixtures/phase5-quarantine-before-temp-deny.config.toml")
        unused = self.root / "lib/workstation_maintenance_delivery.py"
        unused.write_bytes(unused.read_bytes() + b"\n# unrelated uncommitted scheduler edit\n")
        paths = self.observe("lib/quarantine_delivery.py", data)
        self.assertIn("lib/harness_offramp.py", paths)
        target = self.root / "codex/quarantine.config.toml"
        target.write_bytes(target.read_bytes() + b"\n# actual input drift\n")
        with self.assertRaisesRegex(self.source.SourceError, "affected_source_uncommitted"):
            self.observe("lib/quarantine_delivery.py", data)

    def test_guidance_selected_generation_does_not_reopen_bootstrap(self):
        data = ("manifests/workstation-guidance-successor.json", "skills/manage-workstation/SKILL.md")
        historical = self.root / "manifests/workstation-guidance-delivery.json"
        historical.write_bytes(historical.read_bytes() + b"\n")
        paths = self.observe("lib/workstation_guidance_delivery.py", data)
        self.assertNotIn("manifests/workstation-guidance-delivery.json", paths)
        target = self.root / "skills/manage-workstation/SKILL.md"
        target.write_bytes(target.read_bytes() + b"\nActual input drift\n")
        with self.assertRaisesRegex(self.source.SourceError, "affected_source_uncommitted"):
            self.observe("lib/workstation_guidance_delivery.py", data)

    def test_actual_readonly_cli_entrypoints_bind_before_local_imports(self):
        entries = ("quarantine-delivery", "workstation-guidance-delivery", "workstation-guidance-successor",
                   "workstation-maintenance-cycle", "aid-harness-offramp", "rustdesk-ssh-tunnel",
                   "codex-windows-host-ssh-app-server-holder")
        for entry in entries:
            with self.subTest(entry=entry):
                result = subprocess.run(["/usr/bin/python3", "-B", str(self.root / "bin" / entry), "--help"],
                    cwd=self.root.parent, env={"PATH": "/usr/bin:/bin", "HOME": str(self.root.parent), "LC_ALL": "C"},
                    capture_output=True, text=True, timeout=20)
                self.assertEqual(result.returncode, 2 if entry == "workstation-maintenance-cycle" else 0,
                                 result.stdout + result.stderr)
                self.assertNotIn("BLOCKED", result.stdout)

    def test_prelude_never_executes_future_or_package_shadow(self):
        marker = self.root.parent / "shadow-executed"
        canary = "open(" + repr(str(marker)) + ", 'w').write('unexpected')\nraise RuntimeError('fixture shadow executed')\n"
        for path in ("bin/__future__.py", "bin/argparse.py", "ast.py", "lib/__init__.py"):
            (self.root / path).write_text(canary)
        for entry in ("quarantine-delivery", "workstation-guidance-delivery", "workstation-guidance-successor",
                      "workstation-maintenance-cycle", "aid-harness-offramp", "rustdesk-ssh-tunnel",
                      "codex-windows-host-ssh-app-server-holder"):
            with self.subTest(entry=entry):
                result = subprocess.run(["/usr/bin/python3", "-B", str(self.root / "bin" / entry), "--help"],
                    cwd=self.root.parent, env={"PATH": "/usr/bin:/bin", "HOME": str(self.root.parent), "LC_ALL": "C"},
                    capture_output=True, text=True, timeout=20)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(marker.exists(), result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
