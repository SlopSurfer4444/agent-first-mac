"""Actual fresh root entrypoints, help/usage only; no native root observation."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class RootEntrypointTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='root-entrypoints-')
        self.root = Path(self.temp.name).resolve() / 'control'
        subprocess.run(['/usr/bin/git', 'clone', '--no-hardlinks', '--quiet', str(ROOT), str(self.root)],
            check=True, capture_output=True, timeout=30)

    def tearDown(self):
        self.temp.cleanup()

    def invoke(self, name):
        return subprocess.run([sys.executable, '-B', 'bin/' + name, '--help'],
            cwd=self.root, capture_output=True, text=True, timeout=15)

    def test_actual_entrypoints_reexec_before_help_or_usage(self):
        delivery = self.invoke('root-delivery')
        self.assertEqual(delivery.returncode, 0, delivery.stderr + delivery.stdout)
        self.assertIn('inventory,retire', delivery.stdout)
        health = self.invoke('root-runtime-doctor')
        self.assertEqual(health.returncode, 2, health.stderr + health.stdout)
        report = json.loads(health.stdout)
        self.assertEqual(report['reason'], 'usage')
        self.assertIs(report['systemMutationsPerformed'], False)

    def test_initial_stdlib_and_package_shadow_never_execute(self):
        for name in ('bin/pathlib.py', 'lib/__init__.py'):
            marker = self.root / 'shadow-executed'
            shadow = self.root / name
            self.assertFalse(shadow.exists())
            shadow.write_text('open(' + repr(str(marker)) + ', "w").write("executed")\n')
            try:
                for entry in ('root-delivery', 'root-runtime-doctor'):
                    with self.subTest(shadow=name, entry=entry):
                        result = self.invoke(entry)
                        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
                        self.assertIn('source_import_shadow', result.stdout)
                        self.assertFalse(marker.exists(), 'untrusted preamble dependency executed')
            finally:
                shadow.unlink()


if __name__ == '__main__':
    unittest.main()
