"""Coherent launch/overlay ordering using both real fixed-path adapters."""
import contextlib
import shutil
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from lib import game_delivery_bridge as bridge
from lib import operation_readiness as readiness
from test_game_launch_reliability_update import Tests as LaunchFixture, u, COMMIT, P
from test_wine_runtime_extended import Fixture as OverlayFixture, NEW, w
from test_games_runtime_update import a


class DeliveryOrder(LaunchFixture):
    downstream = False
    def setUp(self):
        super().setUp()
        f = OverlayFixture()
        self.addCleanup(f.close)
        # Produce a genuine prior schema3 installed generation and journal.
        old_lifecycle = b'previous installed lifecycle'
        f.put('payload/ds3-runtime', old_lifecycle, 0o700)
        old_policy = w.decode(f.root.read('payload/policy.json')[0])
        old_policy['lifecycleSha256'] = w.digest(old_lifecycle)
        f.put('payload/policy.json', w.encode(old_policy))
        f.policy_sha = w.digest(w.encode(old_policy))
        for name in ('hub', 'ds3'):
            receipt = w.decode(f.root.read(name + '/receipt.json')[0])
            receipt.update(appPolicySha256=w.digest(self.old_native_raw),
                           appLaunchers=self.receipts[name]['appLaunchers'])
            f.put(name + '/receipt.json', w.encode(receipt))
        if self.downstream:
            # Production chronology: applied launch first, then a distinct
            # overlay changes exactly its lifecycle and two receipt endpoints.
            for name in ('hub', 'ds3'):
                shutil.copytree(f.path / name, self.mapping[name], dirs_exist_ok=True,
                                symlinks=True, copy_function=shutil.copy2)
                (self.mapping[name] / 'profiles' / ('prince' if name == 'hub' else 'ds3')).mkdir(mode=0o700, exist_ok=True)
            self.definition['previousFiles'] = {k:self.image(v) for k,v in u.TARGETS.items()}
            self.definition['guards'] = {rel:self.image(rel) for rel in u.GUARDS}
            self.definition['servers'] = {name:self.image(name+'/runtime/engine/bin/wineserver') for name in ('hub','ds3','cs2')}
            self.put('source/' + u.POLICY, u.encode(self.definition))
            self.old_launch_commit = 'c' * 40
            self.head = self.old_launch_commit
            self.old_launch_pin = u.operate('plan', self.old_launch_commit)['planSha256']
            u.operate('apply', self.old_launch_commit, self.old_launch_pin)
            self.old_launch_policy = self.path('source/' + u.POLICY).read_bytes()
            self.old_launch_native = self.path('source/' + u.NATIVE_POLICY).read_bytes()
            self.head = COMMIT
            for name in ('hub', 'ds3'):
                for leaf in ('receipt.json', 'games-play' if name == 'hub' else 'ds3-runtime'):
                    shutil.copy2(self.mapping[name] / leaf, f.path / name / leaf)
            # Prepare a genuinely different next-wave launch closure.
            for key, rel in u.SOURCES.items():
                raw = self.path('source/' + rel).read_bytes() + b' next wave'
                self.put('source/' + rel, raw, 0o755)
                self.put('candidate/' + u.CANDIDATE_FILES[key], raw,
                         self.definition['desiredFiles'][key]['mode'])
                self.definition['sourceFiles'][rel] = u.digest(raw)
                self.definition['desiredFiles'][key] = self.image('candidate/' + u.CANDIDATE_FILES[key])
            self.definition['previousNativePolicySha256'] = u.digest(self.native_raw)
        if hasattr(self, 'intermediate_overlay'):
            old_policy = self.intermediate_overlay(f, old_policy)
        # Fixture engine uses its own isolated transaction namespace first.
        self.old_commit = 'b' * 40
        self.old_overlay_pin = w.build(f.root, self.old_commit, f.pins[w.PE32], f.pins[w.PE],
            f.policy_sha, runtime_sha256=f.pins, source_only=False)['planSha256']
        w.Transaction(f.root, self.old_overlay_pin, source_only=False,
                      gate=lambda _: {'sourceAccepted':True,'doctorReady':True,'prefixesInactive':True}).run('after')
        self.old_policy = f.root.read('payload/policy.json')[0]
        self.old_source = f.root.read('payload/source-hub-v1.json')[0]
        self.old_lifecycle = old_lifecycle
        for name in ('hub', 'ds3'):
            shutil.copytree(f.path / name, self.mapping[name], dirs_exist_ok=True,
                            symlinks=True, copy_function=shutil.copy2,
                            ignore=shutil.ignore_patterns('profiles') if self.downstream else None)
            receipt = w.decode(self.path(name + '/receipt.json').read_bytes())
            if not self.downstream:
                receipt.update(appPolicySha256=w.digest(self.old_native_raw),
                               appLaunchers=self.receipts[name]['appLaunchers'])
            self.put(name + '/receipt.json', w.encode(receipt))
        self.put('state/' + a.NAMESPACE + '/owner.json', a.OWNER_BYTES)
        shutil.copytree(f.path / 'state/transaction', self.mapping['state'] / a.NAMESPACE / 'transaction',
                        copy_function=shutil.copy2)
        # The prior installed helper is explicit, not an invented absence.
        if not self.downstream:
            self.put('aid-bin/game-launch-admission', b'previous admission', 0o600)
        desired_lifecycle = self.path('source/bin/ds3-runtime').read_bytes()
        for name in ('hub', 'ds3'):
            prefix = self.mapping[name] / 'profiles' / ('prince' if name == 'hub' else 'ds3')
            prefix.mkdir(mode=0o700, exist_ok=True)
        self.guards = {rel:self.image(rel) for rel in u.GUARDS}
        self.definition['previousFiles'] = {key:self.image(rel) for key, rel in u.TARGETS.items()}
        self.definition['guards'] = self.guards
        self.definition['servers'] = {name:self.image(name + '/runtime/engine/bin/wineserver')
                                      for name in ('hub', 'ds3', 'cs2')}
        self.put('source/' + u.POLICY, u.encode(self.definition))
        if not self.downstream:
            self.pin = u.operate('plan', COMMIT)['planSha256']
        for rel in ('bin/games-runtime-update', 'bin/ds3-policy-source-bootstrap',
                    'lib/game_delivery_bridge.py'):
            self.put('source/' + rel, (P / rel).read_bytes(), 0o700)
        self.put('source/manifests/ds3-source-hub-v1.json', self.old_source)
        hm = w.decode(self.path('hub/manifest.json').read_bytes())
        dm = w.decode(self.path('ds3/manifest.json').read_bytes())
        policy = dict(old_policy, previousHubManifestSha256=w.digest(w.encode(hm)),
                      previousDS3ManifestSha256=w.digest(w.encode(dm)),
                      previousHubCriticalHashes=hm['criticalHashes'],
                      lifecycleSha256=w.digest(desired_lifecycle))
        policy_raw = w.encode(policy)
        self.put('source/manifests/wine-runtime-overlay.json', policy_raw)
        self.put('source/manifests/games-hub.json', w.encode(dict(hm,
                 runtimeOverlayPolicySha256=w.digest(policy_raw))))
        self.runtime_candidate = self.home / 'runtime-candidate'
        self.runtime_candidate.mkdir(mode=0o700)
        files = {w.RUNTIME_PAYLOADS[rel]:data for rel, data in NEW.items()}
        files.update({'wine-source.tar.gz':b'sources', 'source.patch':b'patch', 'LGPL-NOTICE.txt':b'notice'})
        files['build-provenance.json'] = w.encode({'schema':2,
            'runtimeHashes':policy['desiredRuntimeHashes'],
            'sourceArchiveSha256':w.digest(files['wine-source.tar.gz']),
            'patchSha256':w.digest(files['source.patch']), 'upstreamCommit':None, 'installed':False})
        for name, raw in files.items():
            path = self.runtime_candidate / name
            path.write_bytes(raw)
            path.chmod(0o600)
        self.delivery = {'schema':3, 'id':'wine-runtime-update', 'owner':'control-games-hub',
            'overlayPolicySha256':w.digest(policy_raw),
            'candidateFiles':{name:w.digest(raw) for name, raw in files.items()},
            'requiredLaunchAdmissionSha256':self.definition['desiredFiles']['helper']['sha256']}
        self.put('source/manifests/wine-runtime-update.json', w.encode(self.delivery))
        values = {'HOME':self.home, 'CONTROL':self.source,
                  'SOURCE_PATH':self.source/'bin/games-runtime-update',
                  'HUB':self.mapping['hub'], 'DS3':self.mapping['ds3'],
                  'STATE':self.mapping['state'], 'CANDIDATE':self.runtime_candidate,
                  'ADMISSION':self.path('aid-bin/game-launch-admission')}
        for key, value in values.items():
            p = patch.object(a, key, value); p.start(); self.addCleanup(p.stop)
        p = patch.object(a, 'operation_ready', self.overlay_readiness)
        p.start(); self.addCleanup(p.stop)
        p = patch.object(a, 'launch_bridge', self.fixture_bridge)
        p.start(); self.addCleanup(p.stop)
        self.history = {'manifests/wine-runtime-overlay.json':self.old_policy,
                        'manifests/ds3-source-hub-v1.json':self.old_source,
                        'bin/ds3-runtime':self.old_lifecycle}

    def command(self, argv, **kwargs):
        if argv[0] == '/usr/bin/git' and 'cat-file' in argv:
            return SimpleNamespace(returncode=0, stdout=b'commit\n')
        if argv[0] == '/usr/bin/git' and argv[-2] == 'show':
            if self.downstream and argv[-1] == self.old_launch_commit + ':' + u.POLICY:
                return SimpleNamespace(returncode=0, stdout=self.old_launch_policy)
            if self.downstream and argv[-1] == self.old_launch_commit + ':' + u.NATIVE_POLICY:
                return SimpleNamespace(returncode=0, stdout=self.old_launch_native)
            return SimpleNamespace(returncode=0, stdout=self.history[argv[-1].split(':', 1)[1]])
        if argv[-1] == '-w' and str(argv[0]).endswith('wineserver'):
            return SimpleNamespace(returncode=0, stdout=b'')
        return super().command(argv, **kwargs)

    def overlay_readiness(self, commit, operation, checks, target_guard):
        return readiness.evaluate(operation, commit, checks=checks, target_guard=target_guard,
            source_guard=lambda:self.head == commit and self.branch == 'main' and not self.dirty)

    @contextlib.contextmanager
    def fixture_bridge(self, root, commit, phase):
        with patch.object(bridge, '_load', return_value=u):
            with bridge.launch_bridge(self.source, root, commit, phase=phase) as proof:
                yield proof

    def test_order_bootstrap_launch_overlay_and_reverse_rollback(self):
        before = self.images()
        # Settle and retain a real prior launch generation before bootstrap
        # consumes the current launch predecessor contract.
        self.head = self.old_commit
        old_launch_pin = u.operate('plan', self.old_commit)['planSha256']
        u.operate('apply', self.old_commit, old_launch_pin)
        u.operate('rollback', self.old_commit, old_launch_pin)
        self.head = COMMIT
        self.assertTrue(u.operate('archive-settled', COMMIT, old_launch_pin,
                                 old_commit=self.old_commit)['changed'])
        self.assertTrue(a.operate('archive-applied', COMMIT, self.old_overlay_pin,
                                 self.old_commit)['changed'])
        self.assertTrue((self.mapping['state'] / u.ARCHIVES /
                         (self.old_commit + '-' + old_launch_pin)).is_dir())
        self.assertTrue((self.mapping['state'] / a.ARCHIVES /
                         (self.old_commit + '-' + self.old_overlay_pin)).is_dir())
        result = a.operate('bootstrap-policy-source', COMMIT)
        self.assertTrue(result['changed'])
        self.assertEqual(self.path('ds3/policy-source/overlay-policy.json').read_bytes(), self.old_policy)
        self.assertTrue(u.operate('apply', COMMIT, self.pin)['changed'])
        plan = a.operate('plan', COMMIT)
        self.assertTrue(a.operate('apply', COMMIT, plan['planSha256'])['changed'])
        self.assertFalse(a.operate('apply', COMMIT, plan['planSha256'])['changed'])
        self.assertEqual(w.decode(self.path('ds3/manifest.json').read_bytes())['schema'], 4)
        for name in ('hub', 'ds3'):
            for rel, raw in NEW.items():
                self.assertEqual(self.path(name + '/runtime/' + rel).read_bytes(), raw)
        self.assertTrue(a.operate('rollback', COMMIT, plan['planSha256'])['changed'])
        self.assertTrue(u.operate('rollback', COMMIT, self.pin)['changed'])
        self.assertEqual(self.images(), before)
        # First schema3 rollback retains its documented source dependency;
        # nothing promotes old policy bytes into current accepted source.
        self.assertEqual(w.decode(self.path('ds3/manifest.json').read_bytes())['schema'], 3)
        self.assertEqual(self.path('ds3/policy-source/overlay-policy.json').read_bytes(), self.old_policy)
        self.assertNotEqual(self.path('source/manifests/wine-runtime-overlay.json').read_bytes(), self.old_policy)

    def test_order_launch_before_bootstrap_refuses_without_policy_publication(self):
        a.operate('archive-applied', COMMIT, self.old_overlay_pin, self.old_commit)
        u.operate('apply', COMMIT, self.pin)
        before = self.images()
        with self.assertRaisesRegex(a.Blocked, 'bootstrap_historical_binding'):
            a.operate('bootstrap-policy-source', COMMIT)
        self.assertEqual(self.images(), before)
        self.assertFalse(self.path('ds3/policy-source').exists())

    def test_order_predecessor_cannot_admit_a_different_successor_helper(self):
        before = self.images()
        self.delivery['requiredLaunchAdmissionSha256'] = '0' * 64
        self.put('source/manifests/wine-runtime-update.json', w.encode(self.delivery))
        with self.assertRaisesRegex(a.Blocked, 'launch_admission_successor_disagreement'):
            a.operate('archive-applied', COMMIT, self.old_overlay_pin, self.old_commit)
        self.assertEqual(self.images(), before)
        self.assertTrue((self.mapping['state'] / a.NAMESPACE / 'transaction').is_dir())
        self.assertFalse(self.path('ds3/policy-source').exists())


class DownstreamOrder(DeliveryOrder):
    downstream = True

    def command(self, argv, **kwargs):
        if argv[0] == '/usr/bin/git' and 'cat-file' in argv:
            return SimpleNamespace(returncode=0 if argv[-1] in (COMMIT, 'b'*40, 'c'*40) else 1,
                                   stdout=b'commit\n')
        if argv[0] == '/usr/bin/git' and 'merge-base' in argv:
            rank = {'c'*40:0, 'b'*40:1, COMMIT:2}
            valid = argv[-2] in rank and argv[-1] in rank and rank[argv[-2]] <= rank[argv[-1]]
            return SimpleNamespace(returncode=0 if valid else 1, stdout=b'')
        return super().command(argv, **kwargs)

    def archive_launch(self):
        return u.operate('archive-settled', COMMIT, self.old_launch_pin,
                         old_commit=self.old_launch_commit)

    def assert_archive_refused(self):
        before = self.images()
        with self.assertRaises((RuntimeError, OSError, ValueError)):
            self.archive_launch()
        self.assertEqual(self.images(), before)
        self.assertTrue((self.mapping['state'] / u.NAMESPACE / 'transaction').is_dir())

    def rebind_overlay_plan(self, value):
        # Keep the envelope internally consistent so rejection must inspect
        # ancestry/cross-transaction linkage, not only a stale journal hash.
        rel = 'state/' + a.NAMESPACE + '/transaction/'
        raw = w.encode(value)
        self.put(rel + 'plan.json', raw)
        journal = w.decode(self.path(rel + 'journal.json').read_bytes())
        journal['planSha256'] = w.digest(raw)
        self.put(rel + 'journal.json', w.encode(journal))

    def test_downstream_complete_history_and_new_wave(self):
        before = self.images()
        namespace = self.mapping['state'] / u.NAMESPACE / 'transaction'
        for key in ('ds3.lifecycle', 'hub.receipt', 'ds3.receipt'):
            self.assertNotEqual(self.path(u.TARGETS[key]).read_bytes(),
                                (namespace / (key+'.after')).read_bytes())
        self.assertTrue(self.archive_launch()['changed'])
        self.pin = u.operate('plan', COMMIT)['planSha256']
        self.assertTrue(a.operate('archive-applied', COMMIT, self.old_overlay_pin,
                                 self.old_commit)['changed'])
        a.operate('bootstrap-policy-source', COMMIT)
        u.operate('apply', COMMIT, self.pin)
        plan = a.operate('plan', COMMIT)
        a.operate('apply', COMMIT, plan['planSha256'])
        self.assertFalse(a.operate('apply', COMMIT, plan['planSha256'])['changed'])
        self.assertEqual(w.decode(self.path('ds3/manifest.json').read_bytes())['schema'], 4)
        for name in ('hub', 'ds3'):
            for rel, raw in NEW.items():
                self.assertEqual(self.path(name + '/runtime/' + rel).read_bytes(), raw)
        a.operate('rollback', COMMIT, plan['planSha256'])
        u.operate('rollback', COMMIT, self.pin)
        self.assertEqual(self.images(), before)
        self.assertEqual(w.decode(self.path('ds3/manifest.json').read_bytes())['schema'], 3)
        self.assertNotEqual(self.path('source/manifests/wine-runtime-overlay.json').read_bytes(), self.old_policy)
        for owner, commit, pin in ((u, self.old_launch_commit, self.old_launch_pin),
                                   (a, self.old_commit, self.old_overlay_pin)):
            self.assertTrue((self.mapping['state'] / owner.ARCHIVES / (commit+'-'+pin)).is_dir())

    def test_downstream_missing_overlay_refused(self):
        source = self.mapping['state'] / a.NAMESPACE
        source.rename(self.mapping['state'] / 'retained-missing-overlay')
        self.assert_archive_refused()

    def test_downstream_forged_overlay_commit_refused(self):
        rel = 'state/' + a.NAMESPACE + '/transaction/plan.json'
        value = w.decode(self.path(rel).read_bytes())
        value['acceptedCommit'] = 'f'*40
        self.rebind_overlay_plan(value)
        self.assert_archive_refused()

    def test_downstream_before_link_tampering_refused(self):
        rel = 'state/' + a.NAMESPACE + '/transaction/ds3.lifecycle.before'
        self.put(rel, b'forged before lifecycle', 0o700)
        value = w.decode(self.path('state/' + a.NAMESPACE + '/transaction/plan.json').read_bytes())
        value['targets']['ds3.lifecycle']['before']['sha256'] = w.digest(b'forged before lifecycle')
        self.rebind_overlay_plan(value)
        self.assert_archive_refused()

    def test_downstream_joint_forged_link_cannot_replace_historical_launch_intent(self):
        raw = b'joint forged lifecycle'
        launch_rel = 'state/' + u.NAMESPACE + '/transaction/'
        overlay_rel = 'state/' + a.NAMESPACE + '/transaction/'
        self.put(launch_rel + 'ds3.lifecycle.after', raw, 0o700)
        launch = w.decode(self.path(launch_rel + 'plan.json').read_bytes())
        launch['targets']['ds3.lifecycle']['after']['sha256'] = w.digest(raw)
        encoded = w.encode(launch)
        self.old_launch_pin = w.digest(encoded)
        self.put(launch_rel + 'plan.json', encoded)
        journal = w.decode(self.path(launch_rel + 'journal.json').read_bytes())
        journal['planSha256'] = self.old_launch_pin
        self.put(launch_rel + 'journal.json', w.encode(journal))
        self.put(overlay_rel + 'ds3.lifecycle.before', raw, 0o700)
        overlay = w.decode(self.path(overlay_rel + 'plan.json').read_bytes())
        overlay['targets']['ds3.lifecycle']['before']['sha256'] = w.digest(raw)
        self.rebind_overlay_plan(overlay)
        self.assert_archive_refused()

    def test_downstream_third_state_refused(self):
        self.put('ds3/ds3-runtime', b'foreign third state', 0o700)
        self.assert_archive_refused()

    def test_downstream_unsettled_overlay_refused(self):
        rel = 'state/' + a.NAMESPACE + '/transaction/journal.json'
        value = w.decode(self.path(rel).read_bytes())
        value['phase'] = 'applying'
        value['intent'] = 'ds3.lifecycle'
        self.put(rel, w.encode(value))
        self.assert_archive_refused()

    def test_downstream_extra_stage_refused(self):
        self.put('state/' + a.NAMESPACE + '/transaction/foreign.stage', b'unknown')
        self.assert_archive_refused()


class ArchivedChainOrder(DownstreamOrder):
    middle_commit = 'd' * 40

    def intermediate_overlay(self, f, extended_policy):
        hm=w.decode(f.root.read('hub/manifest.json')[0]);dm=w.decode(f.root.read('ds3/manifest.json')[0])
        lifecycle=f.root.read('ds3/ds3-runtime')[0]
        originals={name:f.root.read('payload/'+name) for name in ('winemac-i386.drv','winemac-x86_64.drv','ds3-runtime','policy.json')}
        desired={w.PE32:w.digest(b'middle pe32'),w.PE:w.digest(b'middle pe64')}
        policy=dict(extended_policy,schema=1,desiredPEHashes=desired,lifecycleSha256=w.digest(lifecycle))
        del policy['desiredRuntimeHashes']
        f.put('payload/policy.json',w.encode(policy));f.put('payload/ds3-runtime',lifecycle,0o700)
        f.put('payload/winemac-i386.drv',b'middle pe32');f.put('payload/winemac-x86_64.drv',b'middle pe64')
        self.middle_history={'manifests/wine-runtime-overlay.json':w.encode(policy),
                             'manifests/ds3-source-hub-v1.json':f.root.read('payload/source-hub-v1.json')[0],
                             'bin/ds3-runtime':lifecycle}
        self.middle_pin=w.build(f.root,self.middle_commit,desired[w.PE32],desired[w.PE],w.digest(w.encode(policy)),source_only=False)['planSha256']
        w.Transaction(f.root,self.middle_pin,source_only=False,gate=lambda _: {'sourceAccepted':True,'doctorReady':True,'prefixesInactive':True}).run('after')
        self.middle_dir=self.mapping['state']/a.ARCHIVES/(self.middle_commit+'-'+self.middle_pin)
        self.put('state/'+a.ARCHIVES+'/owner.json',a.ARCHIVE_OWNER_BYTES)
        self.middle_dir.mkdir(mode=0o700)
        (self.middle_dir/'owner.json').write_bytes(a.OWNER_BYTES);(self.middle_dir/'owner.json').chmod(0o600)
        shutil.copytree(f.path/'state/transaction',self.middle_dir/'transaction',copy_function=shutil.copy2)
        shutil.rmtree(f.path/'state/transaction')
        for name,(raw,mode) in originals.items():f.put('payload/'+name,raw,mode)
        hm=w.decode(f.root.read('hub/manifest.json')[0]);dm=w.decode(f.root.read('ds3/manifest.json')[0])
        policy=dict(extended_policy,previousHubManifestSha256=w.digest(w.encode(hm)),
                    previousDS3ManifestSha256=w.digest(w.encode(dm)),previousHubCriticalHashes=hm['criticalHashes'])
        f.put('payload/policy.json',w.encode(policy));f.policy_sha=w.digest(w.encode(policy))
        return policy

    def command(self,argv,**kwargs):
        if argv[0]=='/usr/bin/git':
            if 'cat-file' in argv and argv[-1]==self.middle_commit:return SimpleNamespace(returncode=0,stdout=b'commit\n')
            if argv[-2]=='show' and argv[-1].startswith(self.middle_commit+':'):
                return SimpleNamespace(returncode=0,stdout=self.middle_history[argv[-1].split(':',1)[1]])
            if 'merge-base' in argv:
                ranks={self.old_launch_commit:0,self.middle_commit:1,self.old_commit:2,COMMIT:3}
                good=argv[-2] in ranks and argv[-1] in ranks and ranks[argv[-2]]<=ranks[argv[-1]]
                return SimpleNamespace(returncode=0 if good else 1,stdout=b'')
        return super().command(argv,**kwargs)

    def test_chain_complete(self):
        self.assertTrue(self.archive_launch()['changed'])

    def test_chain_gap(self):
        shutil.rmtree(self.middle_dir)
        self.assert_archive_refused()

    def test_chain_prepared_cannot_supply_link(self):
        p=self.middle_dir/'transaction/journal.json';j=w.decode(p.read_bytes());j['phase']='prepared';p.write_bytes(w.encode(j))
        self.assert_archive_refused()

    def test_chain_backup_tamper(self):
        (self.middle_dir/'transaction/hub.pe32.after').write_bytes(b'tamper')
        self.assert_archive_refused()

    def test_chain_backup_mode_tamper(self):
        (self.middle_dir/'transaction/hub.pe32.after').chmod(0o700)
        self.assert_archive_refused()

    def test_chain_mutation_before_rename(self):
        def mutate(event):
            if event=='before-archive':(self.middle_dir/'transaction/hub.pe32.after').write_bytes(b'tamper')
        with self.assertRaises(RuntimeError):
            u.operate('archive-settled',COMMIT,self.old_launch_pin,mutate,old_commit=self.old_launch_commit)
        self.assertTrue((self.mapping['state']/u.NAMESPACE/'transaction').is_dir())

    def rebind_middle(self, plan):
        raw=w.encode(plan);(self.middle_dir/'transaction/plan.json').write_bytes(raw)
        p=self.middle_dir/'transaction/journal.json';j=w.decode(p.read_bytes());j['planSha256']=w.digest(raw);p.write_bytes(w.encode(j))
        renamed=self.middle_dir.parent/(self.middle_commit+'-'+w.digest(raw));self.middle_dir.rename(renamed);self.middle_dir=renamed

    def test_chain_other_overlap_tamper(self):
        p=self.middle_dir/'transaction/hub.pe32.after';p.write_bytes(b'forged but rebound')
        plan=w.decode((self.middle_dir/'transaction/plan.json').read_bytes())
        plan['targets']['hub.pe32']['after']['sha256']=w.digest(p.read_bytes());self.rebind_middle(plan)
        self.assert_archive_refused()

    def test_chain_runtime_rows_tamper(self):
        plan=w.decode((self.middle_dir/'transaction/plan.json').read_bytes())
        plan['runtimeRows']['hub']['after'][0][2]='0'*64;self.rebind_middle(plan)
        self.assert_archive_refused()

    def test_chain_ambiguous(self):
        neighbor=self.middle_dir.parent/('e'*40+'-'+'f'*64);shutil.copytree(self.middle_dir,neighbor)
        self.assert_archive_refused()

    def test_chain_malformed_archive(self):
        (self.middle_dir/'transaction/plan.json').write_bytes(b'[]')
        with self.assertRaisesRegex(u.Blocked,'downstream_archive_schema'):self.archive_launch()

    def test_chain_wrong_ancestry(self):
        original=self.command
        def command(argv,**kwargs):
            if 'merge-base' in argv and self.middle_commit in argv:
                return SimpleNamespace(returncode=1,stdout=b'')
            return original(argv,**kwargs)
        with patch.object(u.subprocess,'run',side_effect=command):self.assert_archive_refused()

    def test_chain_prepared_neighbor_not_used(self):
        neighbor=self.middle_dir.parent/('e'*40+'-'+'f'*64)
        shutil.copytree(self.middle_dir,neighbor)
        p=neighbor/'transaction/journal.json';j=w.decode(p.read_bytes());j['phase']='prepared';p.write_bytes(w.encode(j))
        self.assertTrue(self.archive_launch()['changed'])

def load_tests(loader, tests, pattern):
    return unittest.TestSuite([DeliveryOrder(name) for name in loader.getTestCaseNames(DeliveryOrder)
                              if name.startswith('test_order_')] +
                             [DownstreamOrder(name) for name in loader.getTestCaseNames(DownstreamOrder)
                              if name.startswith('test_downstream_')] +
                             [ArchivedChainOrder(name) for name in loader.getTestCaseNames(ArchivedChainOrder)
                              if name.startswith('test_chain_')])
