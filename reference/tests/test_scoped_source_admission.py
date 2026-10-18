"""Real Git/descriptor probes; synthetic user-owned tree, no native mutation."""
import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import sys
import py_compile
from unittest.mock import patch

from lib import scoped_source_admission as S


class SourceTests(unittest.TestCase):
    def setUp(self):
        # Model the executable bootstrap explicitly, independently of command
        # flags or another test module's imports. Restore caller state afterward.
        for name, value in (("dont_write_bytecode", True), ("pycache_prefix", "/dev/null")):
            bootstrap = patch.object(sys, name, value)
            bootstrap.start()
            self.addCleanup(bootstrap.stop)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        (self.root/'lib').mkdir()
        (self.root/'bin').mkdir()
        (self.root/'manifests').mkdir()
        shutil.copyfile(S.__file__, self.root/'lib/scoped_source_admission.py')
        (self.root/'lib/helper.py').write_text('def later():\n    from lib import deferred\n')
        (self.root/'lib/deferred.py').write_text('VALUE = 1\n')
        (self.root/'bin/example').write_text('#!/usr/bin/python3\nfrom lib import helper\nMANIFEST = "manifests/example.json"\n')
        (self.root/'manifests/example.json').write_text('{"sourceFiles": {"bin/later": "pin"}}')
        (self.root/'bin/later').write_text('#!/usr/bin/python3\nVALUE = 2\n')
        (self.root/'README.md').write_text('ordinary owner notes\n')
        self.git('init', '-q')
        self.git('config', 'user.name', 'Fixture')
        self.git('config', 'user.email', 'fixture@example.invalid')
        self.git('add', '.')
        self.git('commit', '-qm', 'fixture')
        spec = importlib.util.spec_from_file_location('fixture_scoped_source', self.root/'lib/scoped_source_admission.py')
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)

    def git(self, *args):
        return subprocess.check_output(['/usr/bin/git', '-C', str(self.root), *args], stderr=subprocess.DEVNULL)

    def run_source(self, callback=None, **kwargs):
        return self.module.run(self.root, callback or (lambda head, source_guard: source_guard()),
                               entrypoints=('bin/example',), **kwargs)

    def test_dirty_readme_untracked_note_and_unrelated_commit_are_not_dependencies(self):
        (self.root/'README.md').write_text('owner unfinished work\n')
        (self.root/'note.md').write_text('untracked\n')
        def callback(head, source_guard):
            self.git('add', 'note.md')
            self.git('commit', '-qm', 'unrelated')
            return source_guard()
        self.assertTrue(self.run_source(callback))

    def test_deferred_import_and_manifest_dynamic_helper_are_dependencies(self):
        for path in ('lib/deferred.py', 'bin/later', 'manifests/example.json'):
            original = (self.root/path).read_bytes()
            (self.root/path).write_bytes(original + b'\n# changed\n')
            with self.subTest(path=path), self.assertRaisesRegex(self.module.SourceError, 'affected_source_uncommitted'):
                self.run_source()
            (self.root/path).write_bytes(original)

    def test_source_as_data_is_held_without_dormant_imports_and_imports_promote(self):
        historical = self.root/'lib/history.py'
        historical.write_text('from lib import historical_dependency\n')
        dependency = self.root/'lib/historical_dependency.py'
        dependency.write_text('VALUE = 1\n')
        entry = self.root/'bin/example'
        original = entry.read_text()
        entry.write_text(original + 'HISTORY: "source-data-only" = ("lib/history.py",)\n')
        self.git('add', 'lib/history.py', 'lib/historical_dependency.py', 'bin/example')
        self.git('commit', '-qm', 'historical data')
        dependency.write_text('VALUE = 2\n')
        self.assertTrue(self.run_source())
        historical.write_text('from lib import historical_dependency\n# changed\n')
        with self.assertRaisesRegex(self.module.SourceError, 'affected_source_uncommitted'):
            self.run_source()
        historical.write_text('from lib import historical_dependency\n')
        entry.write_text(entry.read_text() + 'from lib import history\n')
        self.git('add', 'bin/example'); self.git('commit', '-qm', 'actual import')
        with self.assertRaisesRegex(self.module.SourceError, 'affected_source_uncommitted'):
            self.run_source()

    def test_untracked_package_and_stdlib_shadow_reject(self):
        for path in ('lib/__init__.py', 'ast.py', 'bin/ast.py', 'lib/helper.so',
                     'lib/helper.cpython-313-darwin.so', 'lib/helper.pyc', 'lib/ast.py',
                     'lib/helper/__init__.py'):
            (self.root/path).parent.mkdir(parents=True, exist_ok=True)
            (self.root/path).write_text('raise Exception("unexpected execution")\n')
            with self.subTest(path=path), self.assertRaisesRegex(self.module.SourceError, 'source_import_shadow'):
                self.run_source()
            (self.root/path).unlink()

    def test_historical_manifest_strings_are_not_executable_edges(self):
        entry = self.root/'bin/example'
        entry.write_text('#!/usr/bin/python3\nPOLICY: "source-data-only" = "manifests/example.json"\n')
        self.git('add', 'bin/example'); self.git('commit', '-qm', 'historical policy input')
        helper = self.root/'bin/later'
        helper.write_text('#!/usr/bin/python3\nVALUE = 99\n')
        self.assertTrue(self.run_source())
        manifest = self.root/'manifests/example.json'
        original = manifest.read_bytes()
        manifest.write_bytes(original + b'\n')
        with self.assertRaisesRegex(self.module.SourceError, 'affected_source_uncommitted'):
            self.run_source()
        manifest.write_bytes(original)
        with self.assertRaisesRegex(self.module.SourceError, 'affected_source_uncommitted'):
            self.run_source(extra_paths=('bin/later',))

    def test_own_source_drift_and_commit_drift_block(self):
        def callback(head, source_guard):
            (self.root/'lib/deferred.py').write_text('VALUE = 3\n')
            self.git('add', 'lib/deferred.py')
            self.git('commit', '-qm', 'affected')
            return source_guard()
        with self.assertRaisesRegex(self.module.SourceError, 'affected_source_drift'):
            self.run_source(callback)

    def test_symlink_source_refused(self):
        (self.root/'lib/deferred.py').unlink()
        (self.root/'lib/deferred.py').symlink_to('helper.py')
        with self.assertRaises(OSError):
            self.run_source()

    def test_operation_commit_mismatch_prevents_callback(self):
        with self.assertRaisesRegex(self.module.SourceError, 'source_commit_mismatch'):
            self.run_source(lambda *args, **kwargs: self.fail('callback ran'), expected_commit='0'*40)

    def test_unchecked_hash_cache_cannot_replace_committed_deferred_code(self):
        target = self.root/'lib/deferred.py'
        target.write_text('VALUE = 999\n')
        cache = self.root/'lib/__pycache__'/('deferred.' + sys.implementation.cache_tag + '.pyc')
        py_compile.compile(str(target), cfile=str(cache), doraise=True,
                           invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH)
        target.write_text('VALUE = 1\n')
        def callback(head, source_guard):
            spec = importlib.util.spec_from_file_location('committed_deferred', target)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            source_guard()
            return module.VALUE
        self.assertEqual(self.run_source(callback), 1)

    def test_tracked_alternate_module_and_new_hardlink_are_not_ignored(self):
        (self.root/'bin/ast.py').write_text('VALUE = 1\n')
        self.git('add', 'bin/ast.py'); self.git('commit', '-qm', 'alternate')
        (self.root/'bin/ast.py').write_text('VALUE = 2\n')
        with self.assertRaisesRegex(self.module.SourceError, 'affected_source_uncommitted'):
            self.run_source()
        (self.root/'bin/ast.py').write_text('VALUE = 1\n')
        def callback(head, source_guard):
            import os
            os.link(self.root/'lib/deferred.py', self.root/'second-link')
            return source_guard()
        with self.assertRaisesRegex(self.module.SourceError, 'affected_source_drift'):
            self.run_source(callback)

    def test_repeated_publication_guards_do_not_repeat_git_observation(self):
        original = self.module.git
        commands = []
        def counted(*args):
            commands.append(args[1:])
            return original(*args)
        def callback(head, source_guard):
            before = len(commands)
            for _ in range(35): self.assertTrue(source_guard())
            self.assertEqual(len(commands), before)
            return True
        with patch.object(self.module, 'git', side_effect=counted):
            self.assertTrue(self.run_source(callback))
        self.assertEqual(len(commands), 4)  # initial commit/tree and final commit/tree


if __name__ == '__main__':
    unittest.main()
