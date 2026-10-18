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
        (self.root/'bin/example').write_text('#!/usr/bin/python3\nfrom lib import helper\nMANIFEST = "manifests/example.json"\ndef read_manifest():\n    return MANIFEST\n')
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

    def test_unused_path_literal_does_not_create_dependency(self):
        (self.root/'lib/unrelated.py').write_text('VALUE = 1\n')
        entry = self.root/'bin/example'
        entry.write_text(entry.read_text() + '\nUNUSED = "lib/unrelated.py"\n"lib/unrelated.py"\n')
        self.git('add', 'lib/unrelated.py', 'bin/example'); self.git('commit', '-qm', 'unrelated reference')
        (self.root/'lib/unrelated.py').write_text('VALUE = 2\n')
        self.assertTrue(self.run_source())

    def test_named_source_data_declaration_does_not_discover_history(self):
        entry = self.root/'bin/example'
        entry.write_text('#!/usr/bin/python3\nPOLICY = "manifests/example.json"\nHISTORY: "source-data-only" = (POLICY,)\ndef read_policy():\n    return POLICY\n')
        self.git('add', 'bin/example'); self.git('commit', '-qm', 'named opaque data')
        (self.root/'bin/later').write_text('VALUE = 99\n')
        self.assertTrue(self.run_source())
        (self.root/'manifests/example.json').write_text('{}\n')
        with self.assertRaisesRegex(self.module.SourceError, 'affected_source_uncommitted'):
            self.run_source()

    def test_unresolved_data_declaration_rejects_instead_of_silently_ignoring(self):
        entry = self.root/'bin/example'
        entry.write_text('#!/usr/bin/python3\nHISTORY: "source-data-only" = (UNKNOWN,)\n')
        self.git('add', 'bin/example'); self.git('commit', '-qm', 'unresolved opaque input')
        with self.assertRaisesRegex(self.module.SourceError, 'source_data_declaration_invalid'):
            self.run_source()

    def test_ambiguous_and_forward_data_names_refuse_wrong_input_binding(self):
        declarations = (
            'POLICY = "manifests/example.json"\nHISTORY: "source-data-only" = (POLICY,)\nPOLICY = "README.md"\n',
            'HISTORY: "source-data-only" = (POLICY,)\nPOLICY = "manifests/example.json"\n',
            'POLICY = "manifests/example.json"\ndef read():\n    POLICY = "README.md"\n    HISTORY: "source-data-only" = (POLICY,)\n',
            'POLICY = "manifests/example.json"\nif True:\n    POLICY = "README.md"\nHISTORY: "source-data-only" = (POLICY,)\n',
            'POLICY = "manifests/example.json"\nPOLICY: str = "README.md"\nHISTORY: "source-data-only" = (POLICY,)\n',
            'POLICY = "manifests/example.json"\nfrom lib import helper as POLICY\nHISTORY: "source-data-only" = (POLICY,)\n',
        )
        for declaration in declarations:
            (self.root/'bin/example').write_text('#!/usr/bin/python3\n' + declaration)
            self.git('add', 'bin/example'); self.git('commit', '-qm', 'ambiguous data binding')
            with self.assertRaisesRegex(self.module.SourceError, 'source_data_declaration_invalid'):
                self.run_source(data_paths=())

    def test_nested_context_and_checks_share_one_git_observation(self):
        commands = []
        original = self.module.git
        def counted(*args):
            commands.append(args[1:])
            return original(*args)
        with patch.object(self.module, 'git', side_effect=counted):
            with self.module.admitted_source(self.root, entrypoints=('bin/example',)) as (head, guard):
                with patch.object(self.module, 'require_execution', return_value=True):
                    for _ in range(5):
                        self.assertTrue(self.module.check(self.root, head, entrypoints=('bin/example',)))
                self.assertEqual(len(commands), 2)
                self.assertTrue(guard())
                with self.module.admitted_source(self.root, opaque_paths=('README.md',)):
                    self.assertTrue(guard())
                with self.assertRaisesRegex(self.module.SourceError, 'source_entry_untracked'):
                    with self.module.admitted_source(self.root, opaque_paths=('unknown',)):
                        self.fail('untracked input admitted')
        self.assertEqual(len(commands), 4)

    def test_live_check_refuses_unbound_execution(self):
        with self.assertRaisesRegex(self.module.SourceError, 'source_execution_unbound'):
            self.module.check(self.root, self.git('rev-parse', 'HEAD').decode().strip(),
                              entrypoints=('bin/example',))

    def test_a_loaded_callback_then_b_committed_is_not_accepted_as_execution(self):
        path = self.root/'lib/callback.py'
        path.write_text('def callback(head, source_guard):\n    return "A"\n')
        self.git('add', 'lib/callback.py'); self.git('commit', '-qm', 'callback A')
        spec = importlib.util.spec_from_file_location('callback_fixture', path)
        loaded = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(loaded)
        path.write_text('def callback(head, source_guard):\n    return "B"\n')
        self.git('add', 'lib/callback.py'); self.git('commit', '-qm', 'callback B')
        with self.assertRaisesRegex(self.module.SourceError, 'source_execution_unbound'):
            self.module.run(self.root, loaded.callback)

    def test_public_failure_is_closed_and_path_free(self):
        for error in (ValueError('/private/owner'), self.module.SourceError('/private/owner')):
            report = self.module.public_failure(error)
            self.assertEqual(report['reason'], 'source_admission_failed')
            self.assertNotIn('/private', str(report))
        self.assertEqual(self.module.public_failure(self.module.SourceError('affected_source_drift'))['reason'],
                         'affected_source_drift')

    def test_explicit_data_selection_holds_selected_and_nested_not_other_variant(self):
        (self.root/'manifests/other.json').write_text('{}\n')
        (self.root/'manifests/nested.json').write_text('{}\n')
        (self.root/'manifests/example.json').write_text('{"required": "manifests/nested.json"}\n')
        entry = self.root/'bin/example'
        entry.write_text('#!/usr/bin/python3\ndef selected(which):\n    return "manifests/example.json" if which else "manifests/other.json"\n')
        self.git('add', 'manifests', 'bin/example'); self.git('commit', '-qm', 'selected data')
        (self.root/'manifests/other.json').write_text('{"unrelated": true}\n')
        self.assertTrue(self.run_source(data_paths=('manifests/example.json',)))
        with patch.object(self.module, 'require_execution', return_value=True):
            self.assertTrue(self.module.check(self.root, self.git('rev-parse', 'HEAD').decode().strip(),
                entrypoints=('bin/example',), data_paths=(),
                opaque_paths=('manifests/example.json', 'manifests/nested.json')))
        for path in ('manifests/example.json', 'manifests/nested.json'):
            original = (self.root/path).read_bytes()
            (self.root/path).write_bytes(original + b'\n')
            with self.assertRaisesRegex(self.module.SourceError, 'affected_source_uncommitted'):
                self.run_source(data_paths=('manifests/example.json',))
            (self.root/path).write_bytes(original)

    def test_dynamic_opaque_inputs_are_held_and_real_imports_promote(self):
        (self.root/'lib/history.py').write_text('from lib import historical_dependency\n')
        (self.root/'lib/historical_dependency.py').write_text('VALUE = 1\n')
        self.git('add', 'lib/history.py', 'lib/historical_dependency.py')
        self.git('commit', '-qm', 'opaque inputs')
        (self.root/'lib/historical_dependency.py').write_text('VALUE = 2\n')
        with self.module.admitted_source(self.root, entrypoints=('bin/example',),
                                        opaque_paths=('lib/history.py',)) as (_, guard):
            self.assertTrue(guard())
        entry = self.root/'bin/example'
        entry.write_text(entry.read_text() + '\nfrom lib import history\n')
        self.git('add', 'bin/example'); self.git('commit', '-qm', 'import promotes opaque input')
        with self.assertRaisesRegex(self.module.SourceError, 'affected_source_uncommitted'):
            with self.module.admitted_source(self.root, entrypoints=('bin/example',),
                                            opaque_paths=('lib/history.py',)):
                self.fail('import drift admitted')


if __name__ == '__main__':
    unittest.main()
