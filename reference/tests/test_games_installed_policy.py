"""The actual owner adapter's fixed bootstrap and schema4 route in owned fixtures."""
import shutil
import unittest
from pathlib import Path
from unittest.mock import patch
import test_games_runtime_update as legacy
import test_wine_runtime_extended as extended
w=legacy.w;a=legacy.a

class Tests(unittest.TestCase):
    command=legacy.Tests.command
    readiness=legacy.Tests.readiness
    once=legacy.Tests.once
    images=legacy.Tests.images
    def setUp(self):
        extended.AdapterTests.setUp(self)
        # Install schema3 through the real fixed adapter before modelling an
        # accepted source successor. No machine data is accessed by this fixture.
        pin=self.once('plan')['planSha256'];self.once('apply',pin=pin)
        self.before=self.images()
        self.old_policy=self.f.root.read('control/manifests/wine-runtime-overlay.json')[0]
        self.source_blobs[a.POLICY]=self.old_policy
        self.source_blobs['manifests/ds3-source-hub-v1.json']=self.f.root.read('payload/source-hub-v1.json')[0]
        self.source_blobs['bin/ds3-runtime']=self.f.root.read('ds3/ds3-runtime')[0]
        # Archival has its own actual transaction tests. Here the retained old
        # fixture namespace is copied aside to make the bootstrap prerequisite.
        shutil.move(self.f.path/'state/wine-runtime-overlay',self.f.path/'retained-old-transaction')
        hm=self.f.root.read('hub/manifest.json')[0];dm=self.f.root.read('ds3/manifest.json')[0]
        policy=w.decode(self.old_policy);policy.update(previousHubManifestSha256=w.digest(hm),previousDS3ManifestSha256=w.digest(dm),previousHubCriticalHashes=w.decode(hm)['criticalHashes'])
        raw=w.encode(policy);self.f.put('control/manifests/wine-runtime-overlay.json',raw)
        hub=w.decode(hm);hub['runtimeOverlayPolicySha256']=w.digest(raw);self.f.put('control/manifests/games-hub.json',w.encode(hub))
        self.definition.update(schema=3,overlayPolicySha256=w.digest(raw));self.f.put('control/manifests/wine-runtime-update.json',w.encode(self.definition))
        self.f.put('control/bin/ds3-policy-source-bootstrap',(Path(__file__).resolve().parents[1]/'bin/ds3-policy-source-bootstrap').read_bytes(),0o700)
        self.head='c'*40
    def bootstrap(self):return self.once('bootstrap-policy-source',commit=self.head)
    def test_fixed_bootstrap_preserves_current_candidate_and_routes_schema4_exactly(self):
        result=self.bootstrap();self.assertTrue(result['changed']);self.assertTrue(result['installedGenerationUnchanged']);self.assertEqual(self.before,self.images())
        self.assertFalse(self.bootstrap()['changed'])
        root=self.f.path/'ds3/policy-source';self.assertEqual(root.joinpath('overlay-policy.json').read_bytes(),self.old_policy)
        pin=self.once('plan',commit=self.head)['planSha256'];self.once('apply',commit=self.head,pin=pin)
        self.assertEqual(w.decode(self.f.root.read('ds3/manifest.json')[0])['schema'],4)
        self.assertFalse(self.once('apply',commit=self.head,pin=pin)['changed'])
        result=self.once('rollback',commit=self.head,pin=pin);self.assertTrue(result['sourceRollbackSuccessorRequired']);self.assertEqual(self.before,self.images())
        self.once('return',commit=self.head,pin=pin)
        # No rerun of the one-time bootstrap against a later policy image.
        with self.assertRaisesRegex(a.Blocked,'bootstrap_requires_archived_transaction'):self.bootstrap()
    def test_bootstrap_rejects_nonancestor_historical_drift_or_active_prefix(self):
        self.ancestor=False
        with self.assertRaisesRegex(a.Blocked,'bootstrap_source_not_ancestor'):self.bootstrap()
        self.ancestor=True;good=self.source_blobs[a.POLICY];self.source_blobs[a.POLICY]=b'{}'
        with self.assertRaisesRegex(a.Blocked,'bootstrap_historical_binding'):self.bootstrap()
        self.source_blobs[a.POLICY]=good;self.active=True
        with self.assertRaisesRegex(a.Blocked,'prefix_active'):self.bootstrap()
        self.assertEqual(self.before,self.images());self.assertFalse((self.f.path/'ds3/policy-source').exists())
    def test_future_schema4_rollback_reports_ds3_independence_but_preserves_hub_requirement(self):
        self.bootstrap();old_commit=self.head;oldpin=self.once('plan',commit=old_commit)['planSha256']
        self.once('apply',commit=old_commit,pin=oldpin);before=self.images()
        self.source_blobs[a.POLICY]=self.f.root.read('control/manifests/wine-runtime-overlay.json')[0]
        policy=w.decode(self.source_blobs[a.POLICY]);hmraw=self.f.root.read('hub/manifest.json')[0];dmraw=self.f.root.read('ds3/manifest.json')[0]
        policy.update(previousHubManifestSha256=w.digest(hmraw),previousDS3ManifestSha256=w.digest(dmraw),previousHubCriticalHashes=w.decode(hmraw)['criticalHashes'])
        raw=w.encode(policy);self.f.put('control/manifests/wine-runtime-overlay.json',raw)
        hub=w.decode(hmraw);hub['runtimeOverlayPolicySha256']=w.digest(raw);self.f.put('control/manifests/games-hub.json',w.encode(hub))
        self.definition['overlayPolicySha256']=w.digest(raw);self.f.put('control/manifests/wine-runtime-update.json',w.encode(self.definition));self.head='d'*40
        self.once('archive-applied',commit=self.head,pin=oldpin,old=old_commit)
        pin=self.once('plan',commit=self.head)['planSha256'];self.once('apply',commit=self.head,pin=pin)
        result=self.once('rollback',commit=self.head,pin=pin)
        self.assertTrue(result['sourceRollbackSuccessorRequired']);self.assertTrue(result['ds3RuntimePolicySourceIndependent']);self.assertEqual(before,self.images())
    def test_plan_requires_real_bootstrap_and_retains_fixed_candidate_provenance(self):
        with self.assertRaises(FileNotFoundError):self.once('plan',commit=self.head)
        self.bootstrap();prov=self.f.path/'payload/candidate/build-provenance.json';good=prov.read_bytes();bad=w.decode(good);bad['schema']=3
        prov.write_bytes(w.encode(bad));self.definition['candidateFiles']['build-provenance.json']=w.digest(prov.read_bytes());self.f.put('control/manifests/wine-runtime-update.json',w.encode(self.definition))
        with self.assertRaisesRegex(a.Blocked,'candidate_provenance_binding'):self.once('plan',commit=self.head)
        self.assertEqual(self.before,self.images());self.assertFalse((self.f.path/'state/wine-runtime-overlay').exists())
    def test_directory_guard_is_rechecked_after_prefix_probe(self):
        self.bootstrap();original=a.inactive;ps=self.f.path/'ds3/policy-source'
        def drift(root,policy):
            original(root,policy);ps.chmod(0o750)
        with patch.object(a,'inactive',drift):
            # The adapter loads its own source-bound engine module instance.
            with self.assertRaisesRegex(RuntimeError,'installed_policy_inventory'):self.once('plan',commit=self.head)
        self.assertEqual(self.before,self.images());self.assertFalse((self.f.path/'state/wine-runtime-overlay').exists())

if __name__=='__main__':unittest.main()
