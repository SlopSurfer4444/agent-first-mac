"""Bounded file transaction tests; no Wine, doctor or live profile access."""
import importlib.machinery, importlib.util, json, tempfile, unittest
from pathlib import Path
from unittest.mock import patch
P=Path(__file__).resolve().parents[1]
loader=importlib.machinery.SourceFileLoader('ds3_follow_runtime',str(P/'bin/ds3-runtime'))
spec=importlib.util.spec_from_loader(loader.name,loader); h=importlib.util.module_from_spec(spec); loader.exec_module(h)

class FollowTransactionTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.base=Path(self.tmp.name).resolve(); self.home=self.base/'home'; self.root=self.home/'runtime'; self.source=self.base/'source'; self.candidate=self.base/'candidate'
        for p in (self.home/'Games',self.root/'borderless',self.source/'manifests',self.source/'bin',self.candidate): p.mkdir(parents=True,exist_ok=True)
        self.patches=[patch.object(h,k,v) for k,v in {'HOME':self.home,'ROOT':self.root,'HERE':self.source,'PREFIX':self.root/'prefix'}.items()]
        for p in self.patches:p.start()
        self.old={'owner':'control-ds3-marshal-fix','aspectFit':True}; self.receipt={'runtimeTreeSha256':'a'*64}; self.br={}
        self.helper={'sourceSha256':h.digest_bytes(b'helper source')}
        for name,target in h.follow_targets().items(): target.write_bytes(h.shortcut_bytes('play-1080') if name=='fallback' else ('old '+name).encode()); target.chmod(0o600)
        for name in h.BORDERLESS_FILES: (self.candidate/name).write_bytes(('new '+name).encode())
        (self.source/'bin/ds3-runtime').write_bytes(b'new lifecycle'); (self.source/'bin/ds3-play').write_bytes(b'new launcher'); (self.source/h.BORDERLESS_SOURCE).write_bytes(b'helper source'); (self.source/h.BORDERLESS_MANIFEST).write_bytes(b'new manifest')
        (self.source/h.FOLLOW_POLICY).write_bytes(h.json_bytes(dict(schema=1,id='ds3-follow-upgrade',owner=self.old['owner'],previousManifestSha256=h.sha(self.root/'manifest.json'),previousBorderlessManifestSha256=h.sha(self.root/'borderless/manifest.json'))))
        self.before={k:p.read_bytes() for k,p in h.follow_targets().items()}
        self.patches += [patch.object(h,'source_gate'),patch.object(h,'inactive'),patch.object(h,'verify_installed',return_value=(self.old,self.receipt)),patch.object(h,'verify_borderless',return_value=({},self.br)),patch.object(h,'borderless_manifest',return_value=self.helper),patch.object(h,'borderless_candidate'),patch.object(h,'borderless_binding')]
        for p in self.patches[4:]: p.start()
    def tearDown(self):
        for p in reversed(self.patches):p.stop()
        self.tmp.cleanup()
    def test_apply_preserves_resolution_and_bridge_then_rollback(self):
        untouched=self.root/'game-config'; untouched.write_bytes(b'owner resolution')
        result=h.upgrade_follow('b'*40,self.candidate)
        self.assertTrue(result['changed']); self.assertEqual(untouched.read_bytes(),b'owner resolution'); self.assertFalse(h.follow_targets()['fallback'].exists())
        receipt=json.loads((self.root/'receipt.json').read_bytes()); self.assertEqual(receipt['runtimeTreeSha256'],'a'*64)
        h.follow_restore(self.root/('.follow-upgrade-'+'b'*40),h.follow_targets())
        self.assertEqual({k:p.read_bytes() for k,p in h.follow_targets().items()},self.before)
        h.follow_restore(self.root/('.follow-upgrade-'+'b'*40),h.follow_targets())
    def test_partial_apply_failure_restores_all(self):
        original=h.os.replace; calls=[0]
        def fail_once(src,dst):
            calls[0]+=1
            if calls[0]==4: raise OSError('injected')
            return original(src,dst)
        with patch.object(h.os,'replace',side_effect=fail_once):
            with self.assertRaises(OSError): h.upgrade_follow('b'*40,self.candidate)
        self.assertEqual({k:p.read_bytes() for k,p in h.follow_targets().items()},self.before)
    def test_foreign_fallback_rejected_before_mutation(self):
        h.follow_targets()['fallback'].write_bytes(b'custom shortcut')
        with self.assertRaisesRegex(RuntimeError,'follow_shortcut_drift'):h.upgrade_follow('b'*40,self.candidate)
        self.assertEqual(h.follow_targets()['lifecycle'].read_bytes(),self.before['lifecycle'])
    def test_rollback_rejects_drift_before_restoring_any_file(self):
        h.upgrade_follow('b'*40,self.candidate); h.follow_targets()['launcher'].write_bytes(b'owner changed')
        before={k:p.read_bytes() if p.exists() else None for k,p in h.follow_targets().items()}
        with self.assertRaisesRegex(RuntimeError,'follow_rollback_drift'): h.follow_restore(self.root/('.follow-upgrade-'+'b'*40),h.follow_targets())
        self.assertEqual({k:p.read_bytes() if p.exists() else None for k,p in h.follow_targets().items()},before)
    def test_verified_noop(self):
        h.upgrade_follow('b'*40,self.candidate)
        self.old=json.loads((self.root/'manifest.json').read_bytes())
        with patch.object(h,'verify_installed',return_value=(self.old,self.receipt)):
            self.assertFalse(h.upgrade_follow('b'*40,self.candidate)['changed'])
    def test_single_launcher_inventory(self):
        self.assertEqual(len(h.shortcuts({'aspectFit':True})),3)
        self.assertEqual(len(h.shortcuts({'aspectFit':True,'singleLauncher':True})),2)

if __name__=='__main__': unittest.main()
