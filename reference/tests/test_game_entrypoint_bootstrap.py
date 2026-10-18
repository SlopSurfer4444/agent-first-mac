"""Canonical source CLI binds before local imports; installed play stays standalone."""
import ast
import os
from pathlib import Path
import pwd
import posix
import sys
import unittest
from unittest.mock import patch

from lib import scoped_source_admission as source

ROOT=Path(__file__).resolve().parents[1]
CONTROL=Path(pwd.getpwuid(os.getuid()).pw_dir)/'AIDev/control'
NAMES=('game-native-admission-update','game-app-launcher-update','game-launch-reliability-update',
       'games-runtime-update','games-hub','game-app-launchers','ds3-runtime')


class Bootstrap(unittest.TestCase):
    def prefix(self,name):
        tree=ast.parse((ROOT/'bin'/name).read_bytes())
        tree.body=tree.body[:next(i for i,node in enumerate(tree.body) if isinstance(node,(ast.FunctionDef,ast.ClassDef)))]
        return compile(tree,name,'exec')

    def test_every_canonical_cli_reexecs_before_local_helpers(self):
        for name in NAMES:
            with self.subTest(name=name),patch.object(posix,'execv',side_effect=SystemExit(77)) as reexec:
                original=list(sys.path)
                try:
                    with self.assertRaises(SystemExit) as raised:
                        exec(self.prefix(name),{'__name__':'__main__','__file__':str(CONTROL/'bin'/name)})
                    self.assertEqual(raised.exception.code,77)
                    reexec.assert_called_once_with(sys.executable,[sys.executable,'-I','-S','-B',str(CONTROL/'lib/scoped_source_admission.py'),str(CONTROL/'bin'/name),'[]',*sys.argv[1:]])
                finally:sys.path[:]=original

    def test_installed_ds3_and_hub_do_not_import_source_engine(self):
        for name in ('ds3-runtime','games-hub'):
            with self.subTest(name=name),patch.object(posix,'execv',side_effect=AssertionError('installed Git coupling')):
                scope={'__name__':'__main__','__file__':str(Path('/synthetic-installed')/name)}
                exec(self.prefix(name),scope)
                self.assertNotIn('reexec_entrypoint',scope)


if __name__=='__main__':unittest.main()
