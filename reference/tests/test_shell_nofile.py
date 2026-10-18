import os, pwd, resource, runpy, subprocess, sys, tempfile, unittest
from pathlib import Path
from unittest import mock
M = runpy.run_path(str(Path(__file__).resolve().parents[1]/'bin/shell-nofile'))

class ShellNofile(unittest.TestCase):
    def test_all_shell_routes_use_user_source_scope(self):
        for route in ('gate', 'integration_gate', 'block_migration_gate'):
            with self.subTest(route=route), tempfile.TemporaryDirectory() as d:
                root = Path(d); control = root/'AIDev/control'
                fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    if route == 'block_migration_gate': M['transaction'](fd, 'apply', 'a'*40)
                    with mock.patch.dict(M[route].__globals__, {
                        'HOME': root, 'HERE': control, 'CONTROL': control,
                        '__file__': str(control/'bin/shell-nofile')}), \
                         mock.patch('lib.user_operation_readiness.require_scoped_operation_ready',
                                    return_value='scoped') as ready:
                        args = ('a'*40, fd)
                        if route == 'gate': args += ('apply',)
                        elif route == 'integration_gate': args += ('integrate',)
                        self.assertEqual(M[route](*args), 'scoped')
                        self.assertTrue(ready.call_args.kwargs['target_guard']())
                finally: os.close(fd)

    def test_explicit_legacy_block_migration_preserves_outside_edits_and_receipt(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
            try:
                M['transaction'](fd, 'apply', 'a'*40)
                target = root/'.zshrc'; original_inode = target.stat().st_ino
                receipt = (root/M['RECEIPT']).read_bytes()
                before = b'# owner prefix\n' + M['PAYLOAD'] + b'export OWNER=1\n'
                target.write_bytes(before)
                self.assertEqual(M['migrate_block'](fd, 'b'*40), 'BLOCK_MIGRATED')
                self.assertEqual(target.read_bytes(), before.replace(M['PAYLOAD'], M['BLOCK']))
                self.assertFalse((root/M['RECEIPT']).exists())
                backups = list(root.glob('.aid-shell-recovery-*'))
                self.assertEqual(len(backups), 2)
                old_target = next(p for p in backups if not p.name.endswith('.receipt'))
                self.assertEqual(old_target.read_bytes(), before)
                self.assertEqual(old_target.stat().st_ino, original_inode)
                self.assertEqual(Path(str(old_target)+'.receipt').read_bytes(), receipt)
                self.assertEqual(M['migrate_block'](fd, 'b'*40), 'UNCHANGED')
                self.assertEqual(M['integrate'](fd, 'unintegrate'), 'UNINTEGRATED')
                self.assertEqual(target.read_bytes(), b'# owner prefix\nexport OWNER=1\n')
            finally: os.close(fd)

    def test_legacy_block_migration_refuses_ambiguous_or_replaced_target(self):
        for variation in ('duplicate', 'edited-fragment', 'replaced-inode', 'schema1-edited'):
            with self.subTest(variation=variation), tempfile.TemporaryDirectory() as d:
                root = Path(d); fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    M['transaction'](fd, 'apply', 'a'*40); target = root/'.zshrc'
                    if variation == 'duplicate': target.write_bytes(M['PAYLOAD']*2)
                    elif variation == 'edited-fragment': target.write_bytes(M['PAYLOAD'].replace(b'4096', b'8192'))
                    elif variation == 'replaced-inode':
                        replacement = root/'replacement'; replacement.write_bytes(M['PAYLOAD']); os.replace(replacement, target)
                    else:
                        import json
                        receipt = root/M['RECEIPT']; value = json.loads(receipt.read_text())
                        value['schema'] = 1; value.pop('targetIdentity'); receipt.write_text(json.dumps(value))
                        target.write_bytes(M['PAYLOAD'] + b'# owner\n')
                    before = {p.name: p.read_bytes() for p in root.iterdir()}
                    with self.assertRaises(RuntimeError): M['migrate_block'](fd, 'b'*40)
                    self.assertEqual(before, {p.name: p.read_bytes() for p in root.iterdir()})
                finally: os.close(fd)

    def test_legacy_block_migration_schema1_exact_pair(self):
        import json
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
            try:
                M['transaction'](fd, 'apply', 'a'*40)
                receipt = root/M['RECEIPT']; value = json.loads(receipt.read_text())
                value['schema'] = 1; value.pop('targetIdentity'); receipt.write_text(json.dumps(value))
                self.assertEqual(M['migrate_block'](fd, 'b'*40), 'BLOCK_MIGRATED')
            finally: os.close(fd)

    def test_legacy_migration_preserves_concurrent_target_and_receipt(self):
        for surface in ('target', 'receipt'):
            with self.subTest(surface=surface), tempfile.TemporaryDirectory() as d:
                root = Path(d); fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    M['transaction'](fd, 'apply', 'a'*40)
                    real = M['exchange_startup'] if surface == 'target' else M['rename_exclusive']
                    def concurrent(*args):
                        if surface == 'target': (root/'.zshrc').write_bytes(b'# concurrent owner\n')
                        elif args[1] == M['RECEIPT']: (root/M['RECEIPT']).write_bytes(b'unknown receipt bytes\n')
                        return real(*args)
                    key = 'exchange_startup' if surface == 'target' else 'rename_exclusive'
                    with mock.patch.dict(M['migrate_block'].__globals__, {key: concurrent}):
                        with self.assertRaises(RuntimeError): M['migrate_block'](fd, 'b'*40)
                    expected = b'# concurrent owner\n' if surface == 'target' else b'unknown receipt bytes\n'
                    self.assertIn(expected, [p.read_bytes() for p in root.iterdir()])
                    self.assertTrue((root/M['JOURNAL']).exists())
                finally: os.close(fd)

    def test_legacy_migration_refuses_journal_path_escape(self):
        import json
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
            try:
                M['transaction'](fd, 'apply', 'a'*40)
                with mock.patch.dict(M['migrate_block'].__globals__, {'exchange_startup': mock.Mock(side_effect=RuntimeError('interrupted'))}):
                    with self.assertRaisesRegex(RuntimeError, 'interrupted'): M['migrate_block'](fd, 'b'*40)
                journal = root/M['JOURNAL']; j = json.loads(journal.read_bytes()); j['stage'] = '../foreign'
                journal.write_text(json.dumps(j))
                before = {p.name: p.read_bytes() for p in root.iterdir()}
                with self.assertRaisesRegex(RuntimeError, 'journal_drift'): M['migrate_block'](fd, 'b'*40)
                self.assertEqual(before, {p.name: p.read_bytes() for p in root.iterdir()})
            finally: os.close(fd)

    def test_legacy_block_migration_fresh_process_recovery(self):
        script = '''
import os, runpy, sys
m = runpy.run_path(sys.argv[1]); fd = os.open(sys.argv[2], os.O_RDONLY | os.O_DIRECTORY)
point = sys.argv[3]
for name in ('exchange_startup', 'retain_preimage', 'rename_exclusive', 'unlink_owned'):
    real = m[name]
    def wrap(*args, _name=name, _real=real, **kwargs):
        # rename_exclusive is also used by retain_preimage; only fault receipt.
        selected = _name != 'rename_exclusive' or args[1] == m['RECEIPT']
        if selected and point == 'before:' + _name: os._exit(73)
        value = _real(*args, **kwargs)
        if selected and point == 'after:' + _name: os._exit(73)
        return value
    m['migrate_block'].__globals__[name] = wrap
try: print(m['migrate_block'](fd, 'b'*40))
finally: os.close(fd)
'''
        for name in ('exchange_startup', 'retain_preimage', 'rename_exclusive', 'unlink_owned'):
            for timing in ('before', 'after'):
                with self.subTest(point=timing+':'+name), tempfile.TemporaryDirectory() as d:
                    root = Path(d); fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
                    try:
                        M['transaction'](fd, 'apply', 'a'*40)
                        target = root/'.zshrc'; target.write_bytes(M['PAYLOAD'] + b'# owner\n')
                        result = subprocess.run([sys.executable, '-c', script, str(Path(__file__).resolve().parents[1]/'bin/shell-nofile'), d, timing+':'+name], capture_output=True, text=True)
                        self.assertEqual(result.returncode, 73, result.stderr)
                        if (root/M['JOURNAL']).exists(): self.assertEqual(M['transaction'](fd, 'status', None), 'RECOVERY_REQUIRED')
                        result = subprocess.run([sys.executable, '-c', script, str(Path(__file__).resolve().parents[1]/'bin/shell-nofile'), d, 'none'], capture_output=True, text=True)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertEqual(target.read_bytes(), M['BLOCK'] + b'# owner\n')
                        self.assertFalse((root/M['JOURNAL']).exists())
                        self.assertFalse((root/M['RECEIPT']).exists())
                        self.assertEqual(len(list(root.glob('.aid-shell-recovery-*'))), 2)
                    finally: os.close(fd)

    def test_main_ordinary_commands_dispatch_without_owner_file_collision(self):
        import contextlib, io, json
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); (root/'.zshrc').write_text('# owner\n')
            (root/'.zprofile').write_text('# owner profile\n')
            gates = []
            globals_ = M['main'].__globals__
            with mock.patch.dict(globals_, {'HOME': root, 'integration_gate': lambda *args: gates.append(args[2])}), mock.patch.dict(os.environ, {'ZDOTDIR': ''}):
                for operation, expected in (('status', 'ABSENT'), ('apply', 'INTEGRATED'), ('status', 'INSTALLED'), ('apply', 'UNCHANGED'), ('rollback', 'UNINTEGRATED')):
                    out = io.StringIO()
                    with mock.patch.object(sys, 'argv', ['shell-nofile', operation, '--commit', 'a'*40]), contextlib.redirect_stdout(out):
                        M['main']()
                    self.assertEqual(json.loads(out.getvalue())['verdict'], expected)
            self.assertEqual(gates, ['integrate', 'unintegrate'])
            self.assertEqual((root/'.zshrc').read_text(), '# owner\n')

    def test_print_snippet_coexists_with_owner_configuration(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for name in ('.zshrc', '.zshenv', '.zprofile', '.aid-shell-nofile-operation.json'):
                (root/name).write_text('# unrelated owner content\n')
            before = {p.name: (p.read_bytes(), p.stat().st_ino) for p in root.iterdir()}
            result = subprocess.run([sys.executable, str(Path(__file__).resolve().parents[1]/'bin/shell-nofile'), 'print-snippet'],
                                    env={**os.environ, 'ZDOTDIR': d}, capture_output=True, text=True, check=True)
            self.assertEqual(result.stderr, '')
            self.assertEqual(result.stdout.split('\n', 1)[1], M['PAYLOAD'].decode().split('\n', 1)[1])
            self.assertIn('Owner-managed', result.stdout)
            self.assertEqual(before, {p.name: (p.read_bytes(), p.stat().st_ino) for p in root.iterdir()})

    def test_block_lifecycle_preserves_owner_content_and_edits(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); target = root/'.zshrc'
            original = b'# owner configuration without trailing newline'
            target.write_bytes(original); target.chmod(0o640)
            (root/'.zprofile').write_text('# existing profile\n')
            (root/'.zshenv').write_text('# existing environment\n')
            fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
            try:
                self.assertEqual(M['integrate'](fd, 'integrate'), 'INTEGRATED')
                self.assertEqual(target.read_bytes(), original + M['BLOCK'])
                self.assertEqual(target.stat().st_mode & 0o777, 0o640)
                self.assertEqual(M['integrate'](fd, 'integrate'), 'UNCHANGED')
                target.write_bytes(target.read_bytes() + b'# later owner edit\n')
                self.assertEqual(M['integrate'](fd, 'unintegrate'), 'UNINTEGRATED')
                self.assertEqual(target.read_bytes(), original + b'\n# later owner edit\n')
                self.assertEqual(M['integrate'](fd, 'unintegrate'), 'UNCHANGED')
            finally: os.close(fd)

    def test_block_refuses_drift_symlink_and_legacy_state(self):
        for content in (M['BLOCK'].replace(b'4096', b'8192'), M['BLOCK']*2):
            with tempfile.TemporaryDirectory() as d:
                target = Path(d)/'.zshrc'; target.write_bytes(content)
                fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    with self.assertRaisesRegex(RuntimeError, 'managed_block_drift'): M['integrate'](fd, 'unintegrate')
                    self.assertEqual(target.read_bytes(), content)
                finally: os.close(fd)
        with tempfile.TemporaryDirectory() as d:
            fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
            try:
                M['transaction'](fd, 'apply', 'a'*40)
                with self.assertRaisesRegex(RuntimeError, 'legacy_installation'): M['integrate'](fd, 'integrate')
            finally: os.close(fd)

    def test_block_race_preserves_new_owner_content(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d)/'.zshrc'; target.write_text('# original\n')
            fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with self.assertRaisesRegex(RuntimeError, 'startup_file_drift'):
                    M['integrate'](fd, 'integrate', lambda: target.write_text('# concurrent owner\n'))
                self.assertEqual(target.read_text(), '# concurrent owner\n')
                self.assertEqual([p.name for p in Path(d).iterdir()], ['.zshrc'])
            finally: os.close(fd)

    def test_block_final_boundary_edit_is_retained_not_deleted(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); target = root/'.zshrc'; target.write_text('# original\n')
            real = M['exchange_startup']
            def concurrent(fd, pending):
                target.write_text('# last instant owner edit\n')
                return real(fd, pending)
            fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with mock.patch.dict(M['integrate'].__globals__, {'exchange_startup': concurrent}):
                    with self.assertRaisesRegex(RuntimeError, 'startup_concurrent_edit_preserved:'):
                        M['integrate'](fd, 'integrate')
                retained = list(root.glob('.aid-shell-block-*'))
                self.assertEqual(len(retained), 1)
                self.assertEqual(retained[0].read_text(), '# last instant owner edit\n')
            finally: os.close(fd)

    def test_block_retains_original_inode_for_late_editor_write(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); target = root/'.zshrc'; target.write_text('# original\n')
            original_fd = os.open(target, os.O_WRONLY)
            real = M['retain_preimage']
            def late_write(fd, pending):
                os.ftruncate(original_fd, 0)
                os.write(original_fd, b'# editor wrote after verification\n')
                os.fsync(original_fd)
                return real(fd, pending)
            fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with mock.patch.dict(M['integrate'].__globals__, {'retain_preimage': late_write}):
                    self.assertEqual(M['integrate'](fd, 'integrate'), 'INTEGRATED')
                recovery = list(root.glob('.aid-shell-recovery-*'))
                self.assertEqual(len(recovery), 1)
                self.assertEqual(recovery[0].read_bytes(), b'# editor wrote after verification\n')
                self.assertEqual(recovery[0].stat().st_ino, os.fstat(original_fd).st_ino)
                self.assertEqual(M['integrate'](fd, 'integrate'), 'UNCHANGED')
            finally:
                os.close(fd); os.close(original_fd)

    @unittest.skipUnless(sys.platform == 'darwin', 'macOS metadata preservation')
    def test_block_preserves_macos_xattrs_and_acl(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d)/'.zshrc'; target.write_text('# owner\n')
            subprocess.run(['/usr/bin/xattr', '-w', 'com.example.afm-test', 'owner-metadata', str(target)], check=True)
            subprocess.run(['/bin/chmod', '+a', f'user:{pwd.getpwuid(os.getuid()).pw_name} allow read', str(target)], check=True)
            acl_before = subprocess.check_output(['/bin/ls', '-le', str(target)], text=True).splitlines()[1:]
            fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
            try:
                for operation in ('integrate', 'unintegrate'):
                    M['integrate'](fd, operation)
                    self.assertEqual(subprocess.check_output(['/usr/bin/xattr', '-p', 'com.example.afm-test', str(target)], text=True).strip(), 'owner-metadata')
                    self.assertEqual(subprocess.check_output(['/bin/ls', '-le', str(target)], text=True).splitlines()[1:], acl_before)
            finally: os.close(fd)

    def test_block_crash_publication_is_atomic(self):
        for after in (False, True):
            with self.subTest(after=after), tempfile.TemporaryDirectory() as d:
                target = Path(d)/'.zshrc'; target.write_bytes(b'# owner\n')
                script = '''
import os, runpy, sys
m = runpy.run_path(sys.argv[1]); real = m['exchange_startup']
def replace(*args, **kwargs):
    if sys.argv[3] == 'True': real(*args, **kwargs)
    os._exit(73)
m['integrate'].__globals__['exchange_startup'] = replace
fd = os.open(sys.argv[2], os.O_RDONLY | os.O_DIRECTORY)
m['integrate'](fd, 'integrate')
'''
                result = subprocess.run([sys.executable, '-c', script, str(Path(__file__).resolve().parents[1]/'bin/shell-nofile'), d, str(after)])
                self.assertEqual(result.returncode, 73)
                self.assertEqual(target.read_bytes(), b'# owner\n' + (M['BLOCK'] if after else b''))
                fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    with self.assertRaisesRegex(RuntimeError, 'startup_stage_inspection_required:'):
                        M['integrate'](fd, 'unintegrate')
                    retained = list(Path(d).glob('.aid-shell-block-*'))
                    self.assertEqual(len(retained), 1)
                    self.assertEqual(retained[0].read_bytes(), b'# owner\n' + (b'' if after else M['BLOCK']))
                finally: os.close(fd)

    def test_lifecycle_and_drift(self):
        with tempfile.TemporaryDirectory() as d:
            fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
            try:
                transaction = M['transaction']; commit = 'a'*40
                self.assertEqual(transaction(fd, 'status', None), 'ABSENT')
                self.assertEqual(transaction(fd, 'apply', commit), 'INSTALLED')
                self.assertEqual(transaction(fd, 'apply', commit), 'INSTALLED')
                p = Path(d)/'.zshrc'; p.write_bytes(p.read_bytes()+b'# owner edit\n')
                with self.assertRaisesRegex(RuntimeError, 'target_drift'): transaction(fd, 'rollback', commit)
                p.write_bytes(M['PAYLOAD'])
                self.assertEqual(transaction(fd, 'rollback', commit), 'REMOVED')
                self.assertEqual(list(Path(d).iterdir()), [])
            finally: os.close(fd)

    def test_collisions(self):
        for name in ('.zshrc', '.zshenv', '.zprofile'):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as d:
                p = Path(d)/name; p.write_text('# owned elsewhere\n')
                fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    with self.assertRaises(RuntimeError): M['transaction'](fd, 'apply', 'a'*40)
                    self.assertEqual(p.read_text(), '# owned elsewhere\n')
                    self.assertEqual(len(list(Path(d).iterdir())), 1)
                finally: os.close(fd)

    def test_symlink_collision(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d)/'.zshrc').symlink_to('/nonexistent')
            fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with self.assertRaises(OSError): M['transaction'](fd, 'apply', 'a'*40)
            finally: os.close(fd)

    def test_real_zsh_limits(self):
        # Execute the actual startup bytes, including native zsh <-> syntax.
        for soft, hard, expected in ((256,8192,4096),(8192,8192,8192),(256,512,256),(resource.RLIM_INFINITY,resource.RLIM_INFINITY,resource.RLIM_INFINITY)):
            with self.subTest(soft=soft,hard=hard), tempfile.TemporaryDirectory() as d:
                p=Path(d)/'startup'; p.write_bytes(M['PAYLOAD'])
                def limits(): resource.setrlimit(resource.RLIMIT_NOFILE, (soft,hard))
                result=subprocess.run(['/bin/zsh','-dfc','source "$1"; print -r -- "$(ulimit -Sn) $(ulimit -Hn)"','zsh',str(p)], preexec_fn=limits,capture_output=True,text=True,check=True)
                display = lambda value: 'unlimited' if value == resource.RLIM_INFINITY else str(value)
                self.assertEqual(result.stdout.strip(), f'{display(expected)} {display(hard)}')
                self.assertEqual(result.stderr, '')

if __name__ == '__main__': unittest.main()
