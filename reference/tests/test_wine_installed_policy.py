"""Actual helper/engine closure tests; every write stays in disposable fixtures."""
import copy
import importlib.machinery
import importlib.util
from pathlib import Path
import shutil
import unittest
from unittest.mock import patch
import test_wine_runtime_extended as extended
import test_wine_runtime_overlay as legacy
w=legacy.w

class Fixture(extended.Fixture):
    def __init__(self):
        super().__init__()
        # The bootstrap's two complete exact images are prerequisites, not
        # arbitrary optional targets. Model the already reviewed schema3 side.
        super().plan();self.tx().run('after')
        self.put('ds3/policy-source/overlay-policy.json',self.root.read('payload/policy.json')[0])
        self.put('ds3/policy-source/source-hub-v1.json',self.root.read('payload/source-hub-v1.json')[0])
        (self.path/'ds3/policy-source').chmod(0o700)
        self.next_generation()
    def next_generation(self):
        shutil.rmtree(self.path/'state/transaction')
        policy=w.decode(self.root.read('payload/policy.json')[0])
        # Distinct, executable helper bytes prove the before side restores its
        # own lifecycle binding, rather than accidentally sharing one helper.
        lifecycle=self.root.read('payload/ds3-runtime')[0]+b'\n# fixture successor generation\n'
        self.put('payload/ds3-runtime',lifecycle,0o700);policy['lifecycleSha256']=w.digest(lifecycle)
        hmraw=self.root.read('hub/manifest.json')[0];dmraw=self.root.read('ds3/manifest.json')[0]
        policy.update(previousHubManifestSha256=w.digest(hmraw),previousDS3ManifestSha256=w.digest(dmraw),previousHubCriticalHashes=w.decode(hmraw)['criticalHashes'])
        self.put('payload/policy.json',w.encode(policy));self.policy_sha=w.digest(w.encode(policy))
    def plan(self):
        result=w.build(self.root,legacy.COMMIT,self.pins[w.PE32],self.pins[w.PE],self.policy_sha,runtime_sha256=self.pins,installed_policy_source=True)
        self.plan_sha=result['planSha256'];return result
    def images(self):return {key:self.root.read(rel) for key,rel in w.POLICY_SOURCE_TARGETS.items()}
    def helper(self):
        path=self.path/'ds3/ds3-runtime';loader=importlib.machinery.SourceFileLoader('ds3_installed_policy',str(path))
        spec=importlib.util.spec_from_loader(loader.name,loader);h=importlib.util.module_from_spec(spec);loader.exec_module(h)
        h.ROOT=self.path/'ds3';h.SOURCE=self.path/'hub';h.CONTROL=self.path/'unavailable-canonical';h.HERE=self.path/'ds3';h.HOME=self.path/'home';h.PREFIX=h.ROOT/'profiles/ds3'
        (h.ROOT/'logs').mkdir(exist_ok=True)
        resolver=h.HOME/'AIDev/bin/ds3-play';resolver.parent.mkdir(parents=True,exist_ok=True)
        if not resolver.is_symlink():resolver.symlink_to(h.ROOT/'ds3-play')
        return h
    def verified(self):
        h=self.helper()
        # Authentication/save contents and graphical/UI inventory are outside
        # this policy test; all actual runtime/receipt/helper checks still run.
        with patch.object(h,'snapshot',return_value={}),patch.object(h,'verify_app_shortcuts'):
            return h.verify_installed()

class Tests(unittest.TestCase):
    def setUp(self):self.f=Fixture();self.addCleanup(self.f.close)
    def test_launch_predecessor_cannot_weaken_schema4_or_nonpolicy_scope(self):
        before=self.f.root.read('ds3/ds3-runtime')[0]
        args=(self.f.root,legacy.COMMIT,self.f.pins[w.PE32],self.f.pins[w.PE],self.f.policy_sha)
        with self.assertRaisesRegex(w.Blocked,'installed_policy_predecessor_scope'):
            w.build(*args,runtime_sha256=self.f.pins,predecessor_lifecycle=before)
        self.f.plan();self.f.tx().run('after');self.f.next_generation()
        args=(self.f.root,legacy.COMMIT,self.f.pins[w.PE32],self.f.pins[w.PE],self.f.policy_sha)
        with self.assertRaisesRegex(w.Blocked,'installed_policy_predecessor_scope'):
            w.build(*args,runtime_sha256=self.f.pins,installed_policy_source=True,predecessor_lifecycle=before)
        self.assertFalse(self.f.root.exists('state/transaction'))
    def test_first_forward_generation_keeps_all_runtime_bytes_and_legacy_limit(self):
        before=self.f.images();self.f.plan();self.f.tx().run('after')
        m,r=self.f.verified();self.assertEqual(m['schema'],4)
        for key,image in before.items():
            if '/runtime/' in w.POLICY_SOURCE_TARGETS[key]:self.assertEqual(image,self.f.images()[key])
        self.f.tx().run('before');self.assertEqual(self.f.images(),before)
        # First migration's older helper/schema3 still depends on canonical
        # policy. This is documented, never silently promoted to schema4.
        with self.assertRaises(FileNotFoundError):self.f.verified()
        self.f.tx().run('after');self.f.verified()
    def test_two_schema4_generations_verify_both_sides_without_canonical_source(self):
        self.f.plan();self.f.tx().run('after');first=self.f.images();self.f.verified()
        self.f.next_generation();self.f.plan();self.assertTrue(self.f.tx().run('after')['changed']);second=self.f.images()
        self.f.verified();self.assertFalse(self.f.tx().run('after')['changed'])
        self.assertNotEqual(first['ds3.policy-source'],second['ds3.policy-source'])
        self.f.tx().run('before');self.assertEqual(first,self.f.images());self.f.verified()
        self.assertFalse(self.f.tx().run('before')['changed']);self.f.tx().run('after');self.assertEqual(second,self.f.images());self.f.verified()
        # The independent DS3 selector does not waive the hub's separate
        # canonical source equality after restoring its historical manifest.
        self.f.put('control/manifests/games-hub.json',second['hub.manifest'][0])
        path=Path(__file__).resolve().parents[1]/'bin/games-hub';loader=importlib.machinery.SourceFileLoader('hub_installed_policy',str(path))
        spec=importlib.util.spec_from_loader(loader.name,loader);hub=importlib.util.module_from_spec(spec);loader.exec_module(hub)
        hub.ROOT=self.f.path/'hub';hub.HERE=self.f.path/'control'
        self.f.tx().run('before');self.f.verified()
        with self.assertRaisesRegex(RuntimeError,'installed_manifest_drift'):hub.status()
    def test_content_mode_inventory_and_scope_tampering_are_refused(self):
        self.f.plan();self.f.tx().run('after');h=self.f.helper();mp=h.ROOT/'manifest.json'
        for rel in ('ds3/policy-source/overlay-policy.json','ds3/policy-source/source-hub-v1.json','ds3/ds3-runtime','hub/manifest.json'):
            p=self.f.path/rel;good=p.read_bytes();p.write_bytes(b'{}')
            with self.assertRaises(RuntimeError):h.manifest(mp)
            p.write_bytes(good)
        ps=h.ROOT/'policy-source';(ps/'extra.json').write_bytes(b'{}')
        with self.assertRaisesRegex(RuntimeError,'installed_policy_inventory'):h.manifest(mp)
        (ps/'extra.json').unlink();ps.chmod(0o755)
        with self.assertRaisesRegex(RuntimeError,'installed_policy_inventory'):h.manifest(mp)
        ps.chmod(0o700);p=ps/'overlay-policy.json';p.chmod(0o644)
        with self.assertRaisesRegex(RuntimeError,'installed_policy_mode'):h.manifest(mp)
        p.chmod(0o600);good=p.read_bytes();p.unlink();p.symlink_to(ps/'source-hub-v1.json')
        with self.assertRaisesRegex(RuntimeError,'unsafe_file'):h.manifest(mp)
        p.unlink();self.f.put('ds3/policy-source/overlay-policy.json',good)
        with self.assertRaisesRegex(RuntimeError,'schema4_manifest_scope'):self._scope(h,mp)
        self.f.verified()
    def test_installed_hub_identity_and_inherited_critical_map_are_exact(self):
        self.f.plan();self.f.tx().run('after');h=self.f.helper();mp=h.ROOT/'manifest.json'
        p=h.SOURCE/'manifest.json';raw=p.read_bytes();hub=w.decode(raw)
        for key,value in (('id','foreign'),('owner','foreign'),('criticalHashes',{k:v for k,v in hub['criticalHashes'].items() if k != w.METAL})):
            bad=copy.deepcopy(hub);bad[key]=value;p.write_bytes(w.encode(bad))
            with self.assertRaisesRegex(RuntimeError,'installed_policy_hub_binding'):h.manifest(mp)
        p.write_bytes(raw);self.f.verified()
    def _scope(self,h,mp):
        p=mp.parent/'copied-manifest.json';p.write_bytes(mp.read_bytes());return h.manifest(p)
    def test_engine_rejects_unknown_bootstrap_and_scope_downgrade_before_state(self):
        p=self.f.path/'ds3/policy-source/overlay-policy.json';good=p.read_bytes();p.write_bytes(b'{}')
        with self.assertRaisesRegex(w.Blocked,'installed_policy_schema'):self.f.plan()
        self.assertFalse(self.f.root.exists('state/transaction'));p.write_bytes(good)
        self.f.plan();self.f.tx().run('after');self.f.next_generation()
        with self.assertRaisesRegex(w.Blocked,'installed_policy_scope_downgrade'):
            w.build(self.f.root,legacy.COMMIT,self.f.pins[w.PE32],self.f.pins[w.PE],self.f.policy_sha,runtime_sha256=self.f.pins,publish=False)
    def test_policy_directory_drift_after_plan_blocks_apply_and_noop(self):
        self.f.plan();before=self.f.images();ps=self.f.path/'ds3/policy-source'
        for applied in (False,True):
            if applied:self.f.tx().run('after');before=self.f.images()
            (ps/'foreign').write_bytes(b'not declared')
            with self.assertRaisesRegex(w.Blocked,'installed_policy_inventory'):self.f.tx().run('after')
            self.assertEqual(before,self.f.images());(ps/'foreign').unlink();ps.chmod(0o750)
            with self.assertRaisesRegex(w.Blocked,'installed_policy_inventory'):self.f.tx().run('after')
            self.assertEqual(before,self.f.images());ps.chmod(0o700)
    def test_each_added_metadata_publication_boundary_recovers_exact_direction(self):
        self.f.plan();self.f.tx().run('after');self.f.next_generation();self.f.plan()
        before=self.f.images();keys=('ds3.policy-source','ds3.source-hub')
        for side in ('after','before'):
            for key in keys:
                for prefix in ('staged:','before-replace:','replaced:'):
                    marker=prefix+w.POLICY_SOURCE_TARGETS[key]
                    def event(name):
                        if name==marker:raise legacy.Interrupted()
                    # The original ancestry bytes may be unchanged. The policy
                    # file is the materially changing target in this successor.
                    if self.f.tx().images[key]['before']==self.f.tx().images[key]['after']:continue
                    self.f.tx().run('before' if side=='after' else 'after')
                    with self.assertRaises(legacy.Interrupted):self.f.tx(event=event).run(side)
                    self.f.tx().run('before' if side=='after' else 'after',recover=True)
                    self.f.verified();self.assertTrue(self.f.tx().side(side))
                    self.f.tx().run('before' if side=='after' else 'after')
        self.f.tx().run('before');self.assertEqual(before,self.f.images());self.f.verified()

if __name__=='__main__':unittest.main()
