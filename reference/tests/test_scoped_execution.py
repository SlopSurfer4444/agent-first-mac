"""Prototype executable binding: subprocess fixtures only, no native changes."""
import json
from pathlib import Path
import py_compile
import subprocess
import sys
import unittest
from tests import test_scoped_source_admission as fixtures


BOOTSTRAP = r'''
import sys, pathlib
sys.dont_write_bytecode = True
sys.pycache_prefix = '/dev/null'
root = pathlib.Path(sys.argv.pop(1))
sys.path.insert(0, str(root))
from lib import scoped_source_admission as source
try:
    source.execute_entrypoint(root, 'bin/example')
except source.SourceError as error:
    print(source.public_failure(error)['reason'])
    raise SystemExit(73)
'''


class ExecutionTests(unittest.TestCase):
    setUp = fixtures.SourceTests.setUp
    git = fixtures.SourceTests.git

    def entry(self, text):
        (self.root/'bin/example').write_text('#!/usr/bin/python3\n' + text)
        self.git('add', 'bin/example'); self.git('commit', '-qm', 'entry fixture')

    def launch(self, bootstrap=BOOTSTRAP):
        return subprocess.run([sys.executable, '-I', '-B', '-c', bootstrap,
                               str(self.root), 'argument'], capture_output=True, text=True)

    def test_entry_metadata_imports_and_systemexit(self):
        self.entry('import sys, json\nfrom lib import deferred\n'
                   'print(json.dumps([__name__, __file__, sys.argv[-1], deferred.VALUE]))\n'
                   'raise SystemExit(0)\n')
        result = self.launch()
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertEqual(json.loads(result.stdout), ['__main__', str(self.root/'bin/example'), 'argument', 1])

    def test_preloaded_dependency_is_rejected_before_entry_effect(self):
        self.entry('from lib import deferred\nprint("ENTRY_EFFECT")\n')
        bootstrap = BOOTSTRAP.replace('try:\n', 'from lib import deferred\ntry:\n')
        result = self.launch(bootstrap)
        self.assertEqual(result.returncode, 73, result.stderr)
        self.assertEqual(result.stdout.strip(), 'source_execution_unbound')

    def test_a_loaded_b_committed_is_rejected(self):
        self.entry('from lib import deferred\nprint(deferred.VALUE)\n')
        bootstrap = BOOTSTRAP.replace('try:\n', '''from lib import deferred
import subprocess
(root/'lib/deferred.py').write_text('VALUE = 2\\n')
subprocess.run(['/usr/bin/git', '-C', str(root), 'add', 'lib/deferred.py'], check=True)
subprocess.run(['/usr/bin/git', '-C', str(root), 'commit', '-qm', 'B'], check=True)
try:
''')
        result = self.launch(bootstrap)
        self.assertEqual(result.returncode, 73, result.stderr)
        self.assertEqual(result.stdout.strip(), 'source_execution_unbound')

    def test_unchecked_pyc_is_not_executed(self):
        self.entry('from lib import deferred\nprint(deferred.VALUE)\n')
        target = self.root/'lib/deferred.py'
        target.write_text('VALUE = 999\n')
        cache = self.root/'lib/__pycache__'/('deferred.' + sys.implementation.cache_tag + '.pyc')
        py_compile.compile(str(target), cfile=str(cache), doraise=True,
                           invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH)
        target.write_text('VALUE = 1\n')
        result = self.launch()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), '1')

    def test_loaded_transient_dependency_cannot_hide_by_restoring_disk(self):
        self.entry('''import importlib.machinery
from pathlib import Path
original = importlib.machinery.SourceFileLoader.get_code
def race(loader, fullname):
    if fullname == 'lib.deferred':
        path = Path(loader.path)
        before = path.read_bytes()
        path.write_text('VALUE = 99\\nprint("BAD_EFFECT")\\n')
        try:
            return original(loader, fullname)
        finally:
            path.write_bytes(before)
    return original(loader, fullname)
importlib.machinery.SourceFileLoader.get_code = race
from lib import deferred
print('ENTRY_EFFECT')
''')
        result = self.launch()
        self.assertEqual(result.returncode, 73, result.stderr)
        self.assertEqual(result.stdout.strip(), 'source_execution_drift')

    def test_different_executable_code_with_local_filename_is_rejected(self):
        for filename in (str(self.root/'bin/example'), str(self.root/'lib/deferred.py')):
            with self.subTest(filename=filename):
                self.entry('exec(compile("print(\\\"BAD_EFFECT\\\")", ' + repr(filename) + ', "exec"))\n')
                result = self.launch()
                self.assertEqual(result.returncode, 73, result.stderr)
                self.assertNotIn('BAD_EFFECT', result.stdout)
                self.assertIn('source_execution_', result.stdout)

    def test_audit_hook_cleanup_after_success_and_exception(self):
        for body in ('raise ValueError("fixture")\n', 'pass\n'):
            self.entry(body)
            bootstrap = BOOTSTRAP[:BOOTSTRAP.index('try:\n')] + '''
before = sys.modules['__main__']
argv = sys.argv[:]
try:
    source.execute_entrypoint(root, 'bin/example')
except ValueError:
    pass
assert source._EXECUTION.get() is None and source._ACTIVE.get() is None
assert sys.modules['__main__'] is before and sys.argv == argv
exec(compile('print("AFTER_WINDOW")', str(root/'unknown.py'), 'exec'))
'''
            result = self.launch(bootstrap)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), 'AFTER_WINDOW')

    def test_repeated_windows_install_one_hook_and_restore_after_source_failure(self):
        self.entry('pass\n')
        bootstrap = BOOTSTRAP[:BOOTSTRAP.index('try:\n')] + '''
original = sys.addaudithook
calls = []
def counted(hook):
    calls.append(hook)
    original(hook)
sys.addaudithook = counted
source.execute_entrypoint(root, 'bin/example')
source.execute_entrypoint(root, 'bin/example')
assert len(calls) == 1
assert source._EXECUTION.get() is None and source._ACTIVE.get() is None
print('ONE_HOOK')
'''
        result = self.launch(bootstrap)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), 'ONE_HOOK')

    def test_suppressed_audit_registration_refuses_execution(self):
        self.entry('print("BAD_EFFECT")\n')
        bootstrap = BOOTSTRAP.replace('try:\n', '''
def deny(event, args):
    if event == 'sys.addaudithook':
        raise RuntimeError('fixture refusal')
sys.addaudithook(deny)
try:
''')
        result = self.launch(bootstrap)
        self.assertEqual(result.returncode, 73, result.stderr)
        self.assertEqual(result.stdout.strip(), 'source_execution_unbound')

    def test_worker_import_is_compared_in_process_wide_window(self):
        self.entry('''import threading, importlib.machinery
original = importlib.machinery.SourceFileLoader.get_code
def race(loader, fullname):
    if fullname == 'lib.deferred':
        return compile('VALUE = 99\\nprint("BAD_EFFECT")', loader.path, 'exec')
    return original(loader, fullname)
importlib.machinery.SourceFileLoader.get_code = race
def worker():
    try:
        from lib import deferred
    except RuntimeError:
        pass
thread = threading.Thread(target=worker)
thread.start()
thread.join()
''')
        result = self.launch()
        self.assertEqual(result.returncode, 73, result.stderr)
        self.assertEqual(result.stdout.strip(), 'source_execution_drift')

    def test_real_reexec_selects_verifier_before_payload_imports(self):
        self.entry('''import sys
if not globals().get('__source_bound__'):
    import posix
    posix.execv(sys.executable, [sys.executable, '-I', '-S', '-B',
        __file__.rsplit('/', 2)[0] + '/lib/scoped_source_admission.py', __file__, '[]', *sys.argv[1:]])
from pathlib import Path
from lib import deferred
from lib.scoped_source_admission import require_execution
assert require_execution(Path(__file__).resolve().parents[1])
print(deferred.VALUE, sys.flags.isolated, sys.flags.no_site, sys.argv[-1])
''')
        result = subprocess.run([sys.executable, str(self.root/'bin/example'), 'argument'],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertEqual(result.stdout.strip(), '1 1 1 argument')

    def test_initial_and_selected_verifier_imports_cannot_execute_repo_shadows(self):
        self.entry('''import sys
if not globals().get('__source_bound__'):
    import posix
    posix.execv(sys.executable, [sys.executable, '-I', '-S', '-B',
        __file__.rsplit('/', 2)[0] + '/lib/scoped_source_admission.py', __file__, '[]', *sys.argv[1:]])
import argparse
from lib import deferred
print('ENTRY_EFFECT')
''')
        for path in ('ast.py', 'lib/__init__.py', 'bin/argparse.py'):
            with self.subTest(path=path):
                shadow = self.root/path
                shadow.write_text('print("UNTRACKED_PRE_GUARD_EFFECT")\n')
                result = subprocess.run([sys.executable, str(self.root/'bin/example')],
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
                self.assertNotIn('UNTRACKED_PRE_GUARD_EFFECT', result.stdout)
                self.assertNotIn('ENTRY_EFFECT', result.stdout)
                self.assertEqual(json.loads(result.stdout)['reason'], 'source_import_shadow')
                shadow.unlink()

    def test_bootstrap_filesystem_refusal_is_bounded_without_traceback(self):
        self.entry('''import sys
if not globals().get('__source_bound__'):
    import posix
    posix.execv(sys.executable, [sys.executable, '-I', '-S', '-B',
        __file__.rsplit('/', 2)[0] + '/lib/scoped_source_admission.py', __file__, '[]', *sys.argv[1:]])
from lib import deferred
''')
        (self.root/'lib/deferred.py').unlink()
        (self.root/'lib/deferred.py').symlink_to('helper.py')
        result = subprocess.run([sys.executable, str(self.root/'bin/example')],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout)['reason'], 'source_admission_failed')
        self.assertEqual(result.stderr, '')
        self.assertNotIn(str(self.root), result.stdout)

    def assert_bounded_failure(self, result, reason='source_admission_failed'):
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, '')
        self.assertEqual(json.loads(result.stdout), {
            'verdict': 'BLOCKED', 'reason': reason,
            'affectedScope': 'affected-user-helper-source',
            'nextAction': 'review_affected_source_and_retry'})
        self.assertNotIn(str(self.root), result.stdout)

    def test_actual_shell_cli_missing_head_has_bounded_preverifier_failure(self):
        # This is the real mutation-route bootstrap, not a replacement test entry.
        shell = self.root/'bin/shell-nofile'
        shell.write_bytes((Path(fixtures.S.__file__).resolve().parents[1]
                           /'bin/shell-nofile').read_bytes())
        self.git('add', 'bin/shell-nofile')
        self.git('commit', '-qm', 'actual shell fixture')
        self.git('symbolic-ref', 'HEAD', 'refs/heads/review-missing')
        result = subprocess.run([sys.executable, str(shell), 'apply', '--help'],
                                capture_output=True, text=True)
        self.assert_bounded_failure(result)

    def test_missing_selected_verifier_has_bounded_preverifier_failure(self):
        self.git('rm', '--cached', 'lib/scoped_source_admission.py')
        self.git('commit', '-qm', 'selected tree without verifier')
        result = subprocess.run([sys.executable, '-I', '-S', '-B',
                                str(self.root/'lib/scoped_source_admission.py'),
                                str(self.root/'bin/example'), '[]'],
                                capture_output=True, text=True)
        self.assert_bounded_failure(result)

    def test_initial_script_argument_and_reexec_errors_are_bounded(self):
        script = str(self.root/'lib/scoped_source_admission.py')
        for args, reason in (([], 'source_admission_failed'),
                             ([str(self.root/'bin/example'), '{'], 'source_admission_failed'),
                             ([str(self.root/'elsewhere/example'), '[]'], 'source_root_invalid'),
                             ([str(self.root/'missing/bin/example'), '[]'], 'source_admission_failed')):
            with self.subTest(args=args):
                result = subprocess.run([sys.executable, '-I', '-S', '-B', script, *args],
                                        capture_output=True, text=True)
                self.assert_bounded_failure(result, reason)
        # Exercise an actual execv failure after successful first-stage parsing.
        probe = ('import runpy, sys\n'
                 'script = sys.argv.pop(1)\n'
                 'sys.executable = "/nonexistent/source-bootstrap-interpreter"\n'
                 'runpy.run_path(script, run_name="__main__")\n')
        result = subprocess.run([sys.executable, '-I', '-S', '-B', '-c', probe,
                                script, str(self.root/'bin/example'), '[]'],
                                capture_output=True, text=True)
        self.assert_bounded_failure(result)


if __name__ == '__main__':
    unittest.main()
