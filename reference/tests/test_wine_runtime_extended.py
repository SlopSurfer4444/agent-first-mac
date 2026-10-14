"""Five fixed runtime payloads through the real engine and native adapter in fixtures."""
import copy
import importlib.machinery
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
import test_wine_runtime_overlay as legacy
import test_games_runtime_update as adapter
w=legacy.w
COMMIT=legacy.COMMIT
NEW={w.PE32:b'new pe32',w.PE:b'new pe64',w.UNIX:b'new matching unix',w.OLE32:b'new ole32',w.OLE64:b'new ole64'}

class Fixture(legacy.Fixture):
    def __init__(self):
        super().__init__()
        for name in ('hub','ds3'):
            for rel in (w.OLE32,w.OLE64):self.put(name+'/runtime/'+rel,b'old '+rel.encode())
            receipt=w.decode(self.root.read(name+'/receipt.json')[0])
            receipt['runtimeTreeSha256']=w.tree_hash(w.tree_rows(self.root,name+'/runtime'))
            self.put(name+'/receipt.json',w.encode(receipt))
        dr=w.decode(self.root.read('ds3/receipt.json')[0]);br=w.decode(self.root.read('ds3/borderless/receipt.json')[0])
        br['baseRuntimeTreeSha256']=dr['runtimeTreeSha256'];self.put('ds3/borderless/receipt.json',w.encode(br))
        for rel,data in NEW.items():self.put('payload/'+w.RUNTIME_PAYLOADS[rel],data)
        policy=w.decode(self.root.read('payload/policy.json')[0]);policy['schema']=2;policy.pop('desiredPEHashes')
        policy['desiredRuntimeHashes']={rel:w.digest(data) for rel,data in NEW.items()}
        self.policy_sha=w.digest(w.encode(policy));self.put('payload/policy.json',w.encode(policy))
        self.pins=policy['desiredRuntimeHashes']
    def plan(self):
        result=w.build(self.root,COMMIT,self.pins[w.PE32],self.pins[w.PE],self.policy_sha,runtime_sha256=self.pins)
        self.plan_sha=result['planSha256'];return result
    def images(self):return {key:self.root.read(rel) for key,rel in w.EXTENDED_TARGETS.items()}

class EngineTests(unittest.TestCase):
    def setUp(self):self.f=Fixture();self.addCleanup(self.f.close)
    def test_five_file_apply_noop_rollback_return_preserves_bindings_and_modes(self):
        before=self.f.images();rows={name:w.tree_rows(self.f.root,name+'/runtime') for name in ('hub','ds3')}
        self.f.plan();self.assertTrue(self.f.tx().run('after')['changed']);self.assertFalse(self.f.tx().run('after')['changed'])
        for name in ('hub','ds3'):
            for rel,data in NEW.items():self.assertEqual(self.f.root.read(name+'/runtime/'+rel)[0],data)
            for row in w.tree_rows(self.f.root,name+'/runtime'):
                if row[0] not in NEW:self.assertIn(row,rows[name])
            for key in ('controllerOverlay','profilePolicy','aspectFit','aspectPolicySha256','graphicsPolicy','candidateSha256','donorSha256','sourceCriticalHashes','sourceHubManifestSha256'):
                old=w.decode(before[name+'.manifest'][0]);new=w.decode(self.f.root.read(name+'/manifest.json')[0])
                if key in old:self.assertEqual(old[key],new[key])
            old=w.decode(before[name+'.receipt'][0]);new=w.decode(self.f.root.read(name+'/receipt.json')[0])
            for key in set(old)-{'commit','manifestSha256','runtimeTreeSha256','lifecycleSha256'}:self.assertEqual(old[key],new[key])
        self.assertEqual(w.decode(self.f.root.read('ds3/manifest.json')[0])['schema'],3)
        self.assertTrue(self.f.tx().run('before')['changed']);self.assertEqual(before,self.f.images())
        self.assertFalse(self.f.tx().run('before')['changed']);self.assertTrue(self.f.tx().run('after')['changed'])
    def test_each_journal_stage_and_target_boundary_recovers_both_directions(self):
        with patch.object(legacy,'Fixture',Fixture):legacy.Tests.test_every_target_journal_and_stage_interruption_recovers(self)
    def test_os_replace_interruptions_both_directions(self):
        with patch.object(legacy,'Fixture',Fixture):legacy.Tests.test_os_replace_interruption_before_and_after_each_write(self)
    def test_each_added_path_missing_or_link_or_foreign_bytes_blocks_without_publication(self):
        for name in ('hub','ds3'):
            for rel in (w.UNIX,w.OLE32,w.OLE64):
                p=self.f.path/name/'runtime'/rel;data=p.read_bytes();mode=p.stat().st_mode&0o777
                p.unlink();p.symlink_to('/not-readable')
                with self.assertRaises((OSError,w.Blocked)):self.f.plan()
                self.assertFalse(self.f.root.exists('state/transaction'))
                p.unlink();self.f.put(name+'/runtime/'+rel,data,mode)
        for rel in NEW:
            p=self.f.path/'payload'/w.RUNTIME_PAYLOADS[rel];original=p.read_bytes();p.write_bytes(b'foreign')
            with self.assertRaisesRegex(w.Blocked,'payload_pin_mismatch'):self.f.plan()
            p.write_bytes(original);self.assertFalse(self.f.root.exists('state/transaction'))
    def test_new_scope_cannot_change_metal_or_prefix_and_drift_preserves_targets(self):
        pins=dict(self.f.pins);pins[w.METAL]='0'*64
        with self.assertRaisesRegex(w.Blocked,'runtime_payload_scope'):w.build(self.f.root,COMMIT,pins[w.PE32],pins[w.PE],self.f.policy_sha,runtime_sha256=pins)
        real=self.f.root.read
        def deny_profile(rel,**kwargs):
            self.assertNotIn('/profiles/',rel);return real(rel,**kwargs)
        with patch.object(self.f.root,'read',deny_profile):self.f.plan();self.f.tx().run('after');self.f.tx().run('before')
        self.f.put('ds3/runtime/'+w.OLE64,b'independent successor');before=self.f.images()
        with self.assertRaises(w.Blocked):self.f.tx().run('after')
        self.assertEqual(before,self.f.images())
    def test_pe_only_successor_cannot_drop_existing_five_path_override_scope(self):
        self.f.plan();self.f.tx().run('after')
        policy=w.decode(self.f.root.read('payload/policy.json')[0]);policy['schema']=1
        policy['desiredPEHashes']={w.PE32:self.f.pins[w.PE32],w.PE:self.f.pins[w.PE]};policy.pop('desiredRuntimeHashes')
        hmraw=self.f.root.read('hub/manifest.json')[0];dmraw=self.f.root.read('ds3/manifest.json')[0]
        policy['previousHubManifestSha256']=w.digest(hmraw);policy['previousDS3ManifestSha256']=w.digest(dmraw)
        policy['previousHubCriticalHashes']=w.decode(hmraw)['criticalHashes']
        raw=w.encode(policy);self.f.put('payload/policy.json',raw)
        with self.assertRaisesRegex(w.Blocked,'runtime_scope_downgrade'):
            w.build(self.f.root,COMMIT,self.f.pins[w.PE32],self.f.pins[w.PE],w.digest(raw),publish=False)
    def test_schema3_selector_and_hub_status_reject_scope_or_ancestry_drift(self):
        self.f.plan();self.f.tx().run('after')
        for rel in ('manifests/ds3-source-hub-v1.json','manifests/wine-runtime-overlay.json','manifests/games-hub.json','bin/ds3-runtime'):
            src={'manifests/ds3-source-hub-v1.json':'payload/source-hub-v1.json','manifests/wine-runtime-overlay.json':'payload/policy.json','manifests/games-hub.json':'hub/manifest.json','bin/ds3-runtime':'payload/ds3-runtime'}[rel]
            self.f.put('control/'+rel,self.f.root.read(src)[0],0o700 if rel.startswith('bin') else 0o600)
        def load(name,path):
            loader=importlib.machinery.SourceFileLoader(name,str(path));spec=importlib.util.spec_from_loader(name,loader);h=importlib.util.module_from_spec(spec);loader.exec_module(h);return h
        h=load('ds3_extended',self.f.path/'ds3/ds3-runtime');mp=self.f.path/'ds3/manifest.json';good=mp.read_bytes()
        with patch.object(h,'CONTROL',self.f.path/'control'):
            m=h.manifest(mp);self.assertEqual(set(m['runtimeOverrides']),set(NEW))
            for mutate in ('missing','extra','legacy','ancestry'):
                bad=copy.deepcopy(m)
                if mutate=='missing':bad['runtimeOverrides'].pop(w.OLE32)
                if mutate=='extra':bad['runtimeOverrides'][w.METAL]='0'*64
                if mutate=='legacy':bad['schema']=2
                if mutate=='ancestry':bad['sourceCriticalHashes'][w.METAL]='0'*64
                mp.write_bytes(w.encode(bad))
                with self.assertRaises(RuntimeError):h.manifest(mp)
            mp.write_bytes(good)
        g=load('hub_extended',Path(__file__).resolve().parents[1]/'bin/games-hub')
        with patch.object(g,'HERE',self.f.path/'control'):
            hub=w.decode(self.f.root.read('hub/manifest.json')[0]);g.verify_overlay_manifest(hub)
            hub['criticalHashes'][w.UNIX]='0'*64
            with self.assertRaises(RuntimeError):g.verify_overlay_manifest(hub)

class AdapterTests(unittest.TestCase):
    command=adapter.Tests.command
    once=adapter.Tests.once
    images=adapter.Tests.images
    readiness=adapter.Tests.readiness
    def setUp(self):
        with patch.object(adapter,'Fixture',Fixture):adapter.Tests.setUp(self)
        policy=w.decode(self.f.root.read('payload/policy.json')[0]);self.pins=policy['desiredRuntimeHashes']
        hub=w.decode(self.f.root.read('hub/manifest.json')[0]);hub['criticalHashes'].update(self.pins);hub['runtimeOverlayPolicySha256']=self.f.policy_sha
        self.f.put('control/manifests/games-hub.json',w.encode(hub))
        for rel,data in NEW.items():self.f.put('payload/candidate/'+w.RUNTIME_PAYLOADS[rel],data)
        provenance=w.decode(self.f.root.read('payload/candidate/build-provenance.json')[0]);provenance['schema']=2;provenance.pop('peHashes');provenance['runtimeHashes']=self.pins
        self.f.put('payload/candidate/build-provenance.json',w.encode(provenance))
        self.definition['schema']=2
        self.definition['candidateFiles']={name:w.digest(self.f.root.read('payload/candidate/'+name)[0]) for name in adapter.a.EXTENDED_CANDIDATE_FILES}
        self.f.put('control/manifests/wine-runtime-update.json',w.encode(self.definition))
    def test_actual_native_adapter_plan_apply_rollback_noops_and_return(self):
        adapter.Tests.test_plan_is_read_only_then_exact_apply_noop_rollback_return(self)
    def test_actual_adapter_missing_extra_mismatch_provenance_before_namespace(self):
        before=self.images();a=adapter.a;good=w.encode(self.definition)
        for kind in ('missing','extra','hash'):
            bad=copy.deepcopy(self.definition)
            if kind=='missing':bad['candidateFiles'].pop('oleacc-i386.dll')
            if kind=='extra':bad['candidateFiles']['xinput.dll']='0'*64
            if kind=='hash':bad['candidateFiles']['winemac-x86_64.so']='0'*64
            self.f.put('control/manifests/wine-runtime-update.json',w.encode(bad))
            with self.assertRaises(a.Blocked):a.operate('plan',COMMIT)
            self.assertEqual(before,self.images());self.assertFalse((self.f.path/'state/wine-runtime-overlay').exists())
        self.f.put('control/manifests/wine-runtime-update.json',good)
        prov=self.f.path/'payload/candidate/build-provenance.json';bad=w.decode(prov.read_bytes());bad['runtimeHashes'][w.UNIX]='0'*64;prov.write_bytes(w.encode(bad))
        self.definition['candidateFiles']['build-provenance.json']=w.digest(prov.read_bytes());self.f.put('control/manifests/wine-runtime-update.json',w.encode(self.definition))
        with self.assertRaisesRegex(a.Blocked,'candidate_provenance_binding'):a.operate('plan',COMMIT)
        self.assertEqual(before,self.images())
    def test_archive_applied_retains_old_exact_plan_and_targets_without_rebinding(self):
        a=adapter.a;pin=self.once('plan')['planSha256'];self.once('apply',pin=pin)
        before=self.images();oldpolicy=self.f.root.read('payload/policy.json')[0]
        self.source_blobs[a.POLICY]=oldpolicy
        self.source_blobs['manifests/ds3-source-hub-v1.json']=self.f.root.read('payload/source-hub-v1.json')[0]
        self.head='c'*40
        # A successor source guard is deliberately different; transaction
        # guards must bind its real historical source, never current bytes.
        policy=w.decode(oldpolicy);policy['previousHubManifestSha256']=w.digest(b'distinct successor preimage')
        changed=w.encode(policy);self.definition['overlayPolicySha256']=w.digest(changed)
        self.f.put('control/manifests/wine-runtime-overlay.json',changed)
        hub=w.decode(self.f.root.read('hub/manifest.json')[0]);hub['runtimeOverlayPolicySha256']=w.digest(changed)
        self.f.put('control/manifests/games-hub.json',w.encode(hub))
        self.f.put('control/manifests/wine-runtime-update.json',w.encode(self.definition))
        with patch.object(a,'exclusive_rename',adapter.a.exclusive_rename):
            result=self.once('archive-applied',commit=self.head,pin=pin,old=COMMIT)
        self.assertEqual(result['state'],'APPLIED_TRANSACTION_ARCHIVED');self.assertFalse(result['oldTransactionRebound'])
        self.assertEqual(before,self.images());self.assertFalse((self.f.path/'state'/a.NAMESPACE).exists())
        archive=self.f.path/'state'/a.ARCHIVES/(COMMIT+'-'+pin)
        self.assertTrue((archive/'transaction/plan.json').is_file())
        self.assertEqual(w.decode((archive/'transaction/plan.json').read_bytes())['acceptedCommit'],COMMIT)
    def test_archive_applied_unknown_target_or_backup_or_stage_preserves_namespace(self):
        a=adapter.a;pin=self.once('plan')['planSha256'];self.once('apply',pin=pin)
        self.source_blobs[a.POLICY]=self.f.root.read('payload/policy.json')[0]
        self.source_blobs['manifests/ds3-source-hub-v1.json']=self.f.root.read('payload/source-hub-v1.json')[0]
        self.head='c'*40
        for rel in ('hub/runtime/'+w.OLE64,'state/'+a.NAMESPACE+'/transaction/hub.ole64.before'):
            p=self.f.path/rel;old=p.read_bytes();p.write_bytes(b'foreign');before=self.images()
            with self.assertRaises(RuntimeError):a.operate('archive-applied',self.head,pin,COMMIT)
            self.assertEqual(before,self.images());self.assertTrue((self.f.path/'state'/a.NAMESPACE).exists());p.write_bytes(old)
        engine=a.load_engine();root=a.make_root(engine)
        try:stage=root.stage_name('state/transaction/journal.json')
        finally:root.close()
        self.f.put('state/'+a.NAMESPACE+'/'+stage.removeprefix('state/'),b'foreign stage')
        before=self.images()
        with self.assertRaises(RuntimeError):a.operate('archive-applied',self.head,pin,COMMIT)
        self.assertEqual(before,self.images());self.assertTrue((self.f.path/'state'/a.NAMESPACE).exists())
    def test_archive_final_gate_receipt_and_unrelated_runtime_drift_retains_namespace(self):
        a=adapter.a;pin=self.once('plan')['planSha256'];self.once('apply',pin=pin)
        self.source_blobs[a.POLICY]=self.f.root.read('payload/policy.json')[0]
        self.source_blobs['manifests/ds3-source-hub-v1.json']=self.f.root.read('payload/source-hub-v1.json')[0]
        self.head='c'*40;original=a.local_gate
        for rel in ('hub/receipt.json','hub/runtime/'+w.METAL):
            p=self.f.path/rel;data=p.read_bytes();calls=0
            def gate(*args):
                nonlocal calls
                value=original(*args);calls+=1
                if calls==4:p.write_bytes(b'changed at last gate')
                return value
            with patch.object(a,'local_gate',gate):
                with self.assertRaises(RuntimeError):a.operate('archive-applied',self.head,pin,COMMIT)
            self.assertTrue((self.f.path/'state'/a.NAMESPACE).exists());p.write_bytes(data)
    def test_added_runtime_target_is_held_across_scoped_dependency_observation(self):
        a=adapter.a;target=self.f.path/'hub/runtime'/w.OLE32
        for recovery in (False,True):
            with self.subTest(recovery=recovery):
                if recovery:
                    pin=self.once('plan')['planSha256'];self.once('apply',pin=pin)
                before=target.read_bytes();original=self.readiness
                def observed(commit,operation,checks,target_guard):
                    self.assertEqual(operation,'wine-recovery' if recovery else 'wine-install')
                    connected=dict(checks);owner=connected['payload-owner']
                    def drift():owner();target.write_bytes(b'foreign added-path successor');return True
                    connected['payload-owner']=drift
                    return original(commit,operation,connected,target_guard)
                try:
                    with patch.object(a,'operation_ready',observed):
                        with self.assertRaisesRegex(a.Blocked,'operation_target_drift|target_unknown_drift'):
                            a.operate('recover' if recovery else 'plan',COMMIT,pin if recovery else None)
                    self.assertEqual(target.read_bytes(),b'foreign added-path successor')
                    if not recovery:self.assertFalse((self.f.path/'state'/a.NAMESPACE).exists())
                finally:target.write_bytes(before)
