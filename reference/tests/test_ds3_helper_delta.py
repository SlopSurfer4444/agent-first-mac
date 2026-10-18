"""Helper deltas use current native binding, never copy native/archive payloads."""
import copy
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

import test_ds3_launch_renderer as launch

m = launch.m


class HelperDelta(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        launch.LaunchRenderer.setUpClass()
        cls.legacy_source=subprocess.check_output(['git','show','ec05bc98cc61ab0e6e2cde960a08fc55607ce6ca:bin/ds3-runtime'],cwd=launch.SOURCE)

    def setUp(self):
        self.f = launch.LaunchRenderer('run')
        # Keep fixture parents independent from a quarantined /private/tmp
        # source clone. Real no-follow directory checks remain active.
        with patch.object(launch.legacy,'SCRIPT',Path(tempfile.gettempdir()).resolve()/'fixture/bin/ds3-runtime'):
            self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        # Deliver the actual unchanged schema8 reader, not this candidate.
        shutil.rmtree(self.f.tx)
        self.f.files['ds3-runtime']=self.legacy_source
        self.f.refresh_provenance();self.f.policy['candidateFiles']=self.f.hashes(self.f.files)
        self.f.after=m.renderer_after(self.f.before,self.f.modes,self.f.files,self.f.policy,self.f.commit,self.f.rows)
        self.f.make_transaction()
        m.renderer_run(self.f.tx, 'after')
        self.native = self.f.facts(path for path in self.f.f.root.rglob('*')
                                  if path.is_file() and ('runtime' in path.parts or path.name == 'save.dat'))
        self.history = self.f.facts(path for path in self.f.f.root.rglob('*')
                                   if path.is_file() and any(part.startswith(('.launch-renderer-', '.admitted-renderer-', '.native-')) for part in path.parts))
        self.binding = json.loads(self.f.after['manifest'])['rendererOverride']
        self.base = copy.deepcopy(self.f.policy['nativeAdmissionBase'])

    def prepare(self, number):
        f=self.f
        f.before=f.capture(m.renderer_targets({'schema':10}))
        f.modes={name:path.stat().st_mode&0o777 for name,path in m.renderer_targets({'schema':10}).items()}
        f.files={name:f.before['lifecycle' if name=='ds3-runtime' else next(key for key,value in m.RENDERER_LAUNCH_FILES.items() if value==name)]+('\n# helper delta %d\n'%number).encode()
                 for name in ('ds3-runtime',*m.RENDERER_LAUNCH_FILES.values())}
        f.policy={'schema':10,'id':'ds3-renderer-update','owner':'control-ds3-marshal-fix',
                  'candidateFiles':f.hashes(f.files),'previousManifestSha256':m.digest_bytes(f.before['manifest']),
                  'previousEffectiveLifecycleSha256':m.digest_bytes(f.before['lifecycle']),
                  'nativeAdmissionBase':self.base,'rendererBinding':self.binding,
                  'launchAdmission':{key:m.digest_bytes(f.before[key]) for key in m.RENDERER_LAUNCH_FILES}}
        f.commit=('%040x'%(number+100))
        f.rows=m.renderer_rows()
        f.after=m.renderer_after(f.before,f.modes,f.files,f.policy,f.commit,f.rows)
        f.tx=m.renderer_transaction(f.commit,helper=True)
        f.make_transaction()

    def verify(self, side):
        f=self.f
        f.assert_images(f.after if side=='after' else f.before)
        self.assertEqual(f.facts(self.native),self.native)
        self.assertEqual(f.facts(self.history),self.history)
        current=json.loads((m.ROOT/'manifest.json').read_bytes())
        self.assertEqual(current['rendererOverride'],self.binding)
        if 'helperOverride' in current:
            with patch.object(m,'ADMISSION_SHA',m.sha(m.HOME/'AIDev/bin/game-launch-admission')):
                m.renderer_verify_binding(current)

    def test_seventeen_updates_no_native_archive_copies_no_history_replay(self):
        for number in range(17):
            with self.subTest(number=number):
                self.prepare(number)
                self.assertEqual(len(m.renderer_targets(self.f.policy)),9)
                self.assertEqual(len(list(self.f.tx.iterdir())),20)  # source directory + record + 18 images
                self.assertEqual(set(path.name for path in (self.f.tx/'source').iterdir()),set(self.f.files))
                with patch.object(m,'renderer_admission_snapshots',side_effect=AssertionError('history replay')), \
                     patch.object(m,'renderer_admission_ancestry',side_effect=AssertionError('history replay')):
                    for side in ('after','before','after'):
                        self.assertTrue(m.renderer_run(self.f.tx,side))
                        self.assertFalse(m.renderer_run(self.f.tx,side))
                        self.verify(side)

    def test_each_publication_interruption_recovers_both_directions(self):
        self.prepare(0)
        for direction in ('after','before'):
            for name in self.f.before:
                if self.f.before[name]==self.f.after[name]:continue
                for boundary in ('intent:','published:'):
                    with self.subTest(direction=direction,name=name,boundary=boundary):
                        m.renderer_run(self.f.tx,'before' if direction=='after' else 'after')
                        def fail(label):
                            if label==boundary+name:raise SystemExit(77)
                        with patch.object(m,'renderer_checkpoint',side_effect=fail),self.assertRaises(SystemExit):
                            m.renderer_run(self.f.tx,direction)
                        m.renderer_run(self.f.tx,direction,recover=True)
                        self.verify(direction)

    def test_native_policy_preimage_and_third_state_refused(self):
        self.prepare(0)
        for key in ('previousManifestSha256','previousEffectiveLifecycleSha256'):
            p=dict(self.f.policy,**{key:'f'*64})
            with self.assertRaisesRegex(RuntimeError,'renderer_helper_predecessor'):
                m.renderer_after(self.f.before,self.f.modes,self.f.files,p,self.f.commit,self.f.rows)
        p=copy.deepcopy(self.f.policy);p['rendererBinding']['nativeRuntimeHashes'][m.METAL]='f'*64
        with self.assertRaisesRegex(RuntimeError,'renderer_helper_predecessor'):
            m.renderer_after(self.f.before,self.f.modes,self.f.files,p,self.f.commit,self.f.rows)
        path=m.ROOT/'ds3-runtime';path.write_bytes(b'foreign')
        with self.assertRaisesRegex(RuntimeError,'renderer_target_drift'):
            m.renderer_run(self.f.tx,'after')
        self.assertEqual(path.read_bytes(),b'foreign')

    def test_ds3_binding_ignores_foreign_hub_cs2_but_not_shared_admission(self):
        self.prepare(0);m.renderer_run(self.f.tx,'after')
        current=json.loads(self.f.after['manifest'])
        with patch.object(m,'ADMISSION_SHA',m.sha(m.HOME/'AIDev/bin/game-launch-admission')):
            for name,path in m.renderer_launch_targets().items():
                if name=='launchHelper':continue
                path.write_bytes(b'foreign unrelated launcher')
            m.renderer_verify_binding(current)
            (m.HOME/'AIDev/bin/game-launch-admission').write_bytes(b'foreign shared admission')
            with self.assertRaisesRegex(RuntimeError,'renderer_helper_endpoint'):
                m.renderer_verify_binding(current)

    def test_current_prefix_pairs_and_native_policy_drift_refused_without_history(self):
        self.prepare(0);m.renderer_run(self.f.tx,'after')
        current=json.loads(self.f.after['manifest'])
        with patch.object(m,'ADMISSION_SHA',m.sha(m.HOME/'AIDev/bin/game-launch-admission')):
            for relative in (m.RENDERER_PREFIX,m.DXGI_PREFIX):
                path=m.PREFIX/relative;raw=path.read_bytes();mode=path.stat().st_mode&0o777
                path.write_bytes(b'foreign prefix')
                with self.assertRaisesRegex(RuntimeError,'renderer_prefix_drift'):m.installed_native_binding(current)
                path.write_bytes(raw);path.chmod(mode^0o100)
                with self.assertRaisesRegex(RuntimeError,'renderer_prefix_drift'):m.installed_native_binding(current)
                path.chmod(mode)
            p=copy.deepcopy(self.f.policy);p['nativeAdmissionBase']['images']['receipt']='f'*64
            with self.assertRaisesRegex(RuntimeError,'renderer_helper_native_policy'):m.renderer_admission_guard(p,lambda:None)

    def test_legacy_reader_accepts_first_rollback(self):
        self.prepare(0);m.renderer_run(self.f.tx,'after');m.renderer_run(self.f.tx,'before')
        old=self.f.old_reader(self.f.before['lifecycle'],'helper_delta_rollback')
        old.renderer_verify_binding(json.loads(self.f.before['manifest']))
        old.renderer_pending_guard()


if __name__=='__main__':unittest.main()
