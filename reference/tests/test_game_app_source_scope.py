"""Fresh bound execution of real launcher update/readiness against private fixtures."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import unittest
import test_game_app_updates as updates

ROOT=Path(__file__).resolve().parents[1]
DRIVER='''#!/usr/bin/python3
import contextlib,io,importlib.machinery,importlib.util,json,sys
from pathlib import Path
from unittest.mock import patch
from lib import scoped_source_admission as source
root=Path(__file__).resolve().parents[1]
loader=importlib.machinery.SourceFileLoader('fixture_updater',str(root/'bin/game-app-launcher-update'))
u=importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name,loader));loader.exec_module(u)
home=root.parents[1];h=u.h
h.HOME=home;h.HERE=root;h.CONTROL=root;h.HUB=home/'hub';h.DS3=home/'ds3'
commit=source._ACTIVE.get()[1]
git_before=len(source.fixture_git_calls)
candidate=sys.argv[1]
def invoke(*args):
    sys.argv=[str(root/'bin/game-app-launcher-update'),*args]
    output=io.StringIO()
    with contextlib.redirect_stdout(output):u.main()
    return json.loads(output.getvalue())
with patch.object(Path,'home',return_value=home):
    first=invoke('install',commit,candidate)
    second=invoke('install',commit,candidate)
    invoke('rollback',commit,commit)
    third=invoke('install',commit,candidate)
    assert first['changed'] and not second['changed'] and third['changed']
    print(json.dumps({'scope':sorted(source._ACTIVE.get()[2]),'changedNoopRollbackReturn':True,
                      'nestedGitCalls':len(source.fixture_git_calls)-git_before}))
'''
RUNNER='''import importlib.util,json,sys
from pathlib import Path
root=Path(sys.argv[1]);sys.path.insert(0,str(root))
sys.dont_write_bytecode=True;sys.pycache_prefix='/dev/null'
spec=importlib.util.spec_from_file_location('lib.scoped_source_admission',root/'lib/scoped_source_admission.py')
source=importlib.util.module_from_spec(spec);sys.modules[spec.name]=source;spec.loader.exec_module(source)
calls=[];actual=source.git
def counted(*args):
    calls.append(args[1:]);return actual(*args)
source.git=counted
source.fixture_git_calls=calls
sys.argv=[str(root/'bin/fixture-launcher-scope'),sys.argv[2]]
source.execute_entrypoint(root,'bin/fixture-launcher-scope')
print(json.dumps({'gitCalls':len(calls)}))
'''

class ActualSourceScope(unittest.TestCase):
    def setUp(self):
        self.fixture=updates.UpdateTests();self.fixture.setUp()
        f=self.fixture.fixture;self.root=f.home/'AIDev/control';self.root.parent.mkdir()
        (self.root.parent/'state').mkdir(mode=0o700)
        subprocess.run(['git','clone','-q','--no-hardlinks',str(ROOT),str(self.root)],check=True)
        self.paths=['bin/game-app-launcher-update','bin/game-app-launchers','lib/game_app_files.py','lib/game_app_routes.json',
                    'lib/game_operation_readiness.py','lib/scoped_source_admission.py',
                    'lib/user_operation_readiness.py','lib/operation_checks.py']
        for rel in self.paths:shutil.copyfile(ROOT/rel,self.root/rel)
        for rel in ('manifests/game-app-launchers.json','manifests/game-app-launcher-errors.json','bin/game-app-launcher.m'):
            shutil.copyfile(f.source/rel,self.root/rel);self.paths.append(rel)
        (self.root/'bin/fixture-launcher-scope').write_text(DRIVER)
        self.paths.append('bin/fixture-launcher-scope')
        subprocess.run(['git','add','--',*self.paths],cwd=self.root,check=True)
        subprocess.run(['git','-c','user.name=Fixture','-c','user.email=fixture@example.invalid',
                        'commit','-qm','fixture selected launcher inputs'],cwd=self.root,check=True)
        receipt=updates.T.h.load(f.ds3/'receipt.json');receipt['owner']='control-ds3-marshal-fix'
        updates.T.h.write_image(f.ds3/'receipt.json',updates.T.h.jb(receipt))
        self.before={k:updates.T.h.image(p) for k,p in updates.u.targets().items()}
    def tearDown(self):self.fixture.tearDown()
    def execute(self):
        return subprocess.run([sys.executable,'-I','-S','-B','-c',RUNNER,str(self.root),
                               str(self.fixture.fixture.candidate)],text=True,capture_output=True)
    def test_real_update_uses_one_git_snapshot_and_ignores_foreign_source(self):
        for rel in ('bin/ds3-runtime','bin/games-hub'):
            with (self.root/rel).open('a') as stream:stream.write('\n# unrelated owner edit\n')
        result=self.execute();self.assertEqual(result.returncode,0,result.stderr+result.stdout)
        evidence=[json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual(evidence[-1],{'gitCalls':4}) # entry + final committed identity
        self.assertEqual(evidence[0]['nestedGitCalls'],0)
        self.assertTrue(evidence[0]['changedNoopRollbackReturn'])
        for rel in ('bin/ds3-runtime','bin/games-hub','bin/game-app-launchers'):
            self.assertNotIn(rel,evidence[0]['scope'])
    def test_relevant_shared_code_and_policy_drift_fail_before_targets(self):
        for rel in ('lib/game_app_files.py','lib/game_app_routes.json','manifests/game-app-launcher-errors.json'):
            with self.subTest(path=rel):
                path=self.root/rel;before=path.read_bytes();path.write_bytes(before+b'\n')
                result=self.execute();path.write_bytes(before)
                self.assertNotEqual(result.returncode,0)
                self.assertIn('affected_source_uncommitted',result.stderr)
                self.assertEqual({k:updates.T.h.image(p) for k,p in updates.u.targets().items()},self.before)

if __name__=='__main__':unittest.main()
