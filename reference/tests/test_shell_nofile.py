import os, resource, runpy, subprocess, tempfile, unittest
from pathlib import Path
M = runpy.run_path(str(Path(__file__).resolve().parents[1]/'bin/shell-nofile'))

class ShellNofile(unittest.TestCase):
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
