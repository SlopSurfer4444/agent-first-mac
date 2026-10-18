"""Scoped bridge and experiment isolation; only synthetic layouts/observations."""
from pathlib import Path
import hashlib
import json
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from lib import game_operation_readiness as game
from lib import operation_readiness as operation
from lib import user_operation_readiness as user_operation


class ReadinessTests(unittest.TestCase):
    def test_current_successor_and_retained_overlay_have_separate_hash_closures(self):
        root=Path(__file__).resolve().parents[1]
        def digest(path):return hashlib.sha256((root/path).read_bytes()).hexdigest()
        launch=json.loads((root/'manifests/game-launch-reliability.json').read_text())
        # The old launch/overlay intent is retained evidence. The installed
        # renderer successor owns the current helper closure instead of
        # rewriting those historical delivery generations on every change.
        renderer=json.loads((root/'manifests/ds3-renderer-update.json').read_text())
        self.assertEqual(renderer['schema'],8)
        for name in ('ds3-runtime','game-launch-admission','games-play','cs2-play'):
            self.assertEqual(digest('bin/'+name),renderer['candidateFiles'][name],name)
        self.assertEqual(launch['schema'],2);self.assertEqual(launch['receiptPreimages'],'observed-owned')
        self.assertIsNotNone(launch['previousFiles']['helper'])
        helper=digest('bin/game-launch-admission')
        for path in ('bin/games-play','bin/cs2-play','bin/ds3-runtime'):self.assertIn(helper,(root/path).read_text())
        overlay=json.loads((root/'manifests/wine-runtime-overlay.json').read_text())
        delivery=json.loads((root/'manifests/wine-runtime-update.json').read_text())
        hub=json.loads((root/'manifests/games-hub.json').read_text())
        self.assertEqual(overlay['lifecycleSha256'],launch['sourceFiles']['bin/ds3-runtime'])
        self.assertEqual(delivery['requiredLaunchAdmissionSha256'],helper)
        self.assertEqual(delivery['overlayPolicySha256'],digest('manifests/wine-runtime-overlay.json'))
        self.assertEqual(hub['runtimeOverlayPolicySha256'],delivery['overlayPolicySha256'])
        self.assertEqual(overlay['schema'],2);self.assertIn(delivery['schema'],(2,3))
        desired=overlay['desiredRuntimeHashes'];self.assertEqual(len(desired),5)
        self.assertTrue(all(hub['criticalHashes'].get(path)==value for path,value in desired.items()))
        self.assertEqual(len(delivery['candidateFiles']),9)

    def test_versioned_runtime_json_schemas_keep_exact_legacy_and_extended_sets(self):
        root=Path(__file__).resolve().parents[1]
        for name,payload,counts in (('wine-runtime-overlay',('desiredPEHashes','desiredRuntimeHashes'),(2,5)),('wine-runtime-update',('candidateFiles','candidateFiles','candidateFiles'),(6,9,9))):
            schema=json.loads((root/('manifests/'+name+'.schema.json')).read_text())
            branches=schema['oneOf'];self.assertEqual(len(branches),len(counts))
            for index,branch in enumerate(branches):
                self.assertEqual(branch['properties']['schema'],{'type':'integer','const':index+1})
                self.assertEqual(set(branch['required']),set(branch['properties']))
                self.assertIs(branch['additionalProperties'],False)
                declared=branch['properties'][payload[index]]
                self.assertEqual(len(declared['required']),counts[index])
                self.assertEqual(set(declared['required']),set(declared['properties']))
                self.assertIs(declared['additionalProperties'],False)

    def test_bridge_borrows_budget_and_preserves_unknown_child_custody(self):
        class Unknown(RuntimeError):
            settlement_failed = True
        error=Unknown('process_settlement_failed');owner=object();error.private_owner=owner
        callbacks={'payload-owner':lambda:True,'recovery':lambda:True}
        def near_budget(control,name,commit,**kwargs):
            self.assertEqual(control,Path('/fixture/control'))
            self.assertEqual(name,'wine-recovery');self.assertIs(kwargs['checks'],callbacks)
            # The actual provider owns its remaining 180-second budget and
            # settlement. There is no independent caller subprocess deadline.
            raise error
        with patch.object(user_operation,'require_scoped_operation_ready',side_effect=near_budget),patch.object(subprocess,'run',side_effect=AssertionError('outer diagnostic child forbidden')):
            with self.assertRaises(Unknown) as caught:
                game.ready(Path('/fixture/control'),'a'*40,'wine-recovery',checks=callbacks,target_guard=lambda:True)
        self.assertIs(caught.exception,error);self.assertIs(caught.exception.private_owner,owner)
        self.assertTrue(caught.exception.settlement_failed)

    def test_connected_scope_checks_and_bound_target_reject_drift(self):
        with tempfile.TemporaryDirectory() as scratch:
            target=Path(scratch)/'target';target.write_bytes(b'before')
            binding=game.bound(target.read_bytes)
            def corrupt():target.write_bytes(b'foreign');return True
            with self.assertRaisesRegex(RuntimeError,'operation_target_drift'):
                operation.evaluate('wine-recovery','a'*40,checks={'payload-owner':corrupt,'recovery':lambda:True},source_guard=lambda:True,target_guard=binding)
            self.assertEqual(target.read_bytes(),b'foreign')

    def test_false_or_nonboolean_dependency_and_unknown_operation_cannot_grant_scope(self):
        for value in (False,1,None):
            with self.subTest(value=value),self.assertRaisesRegex(RuntimeError,'operation_dependency_payload-owner'):
                operation.evaluate('wine-recovery','a'*40,checks={'payload-owner':lambda:value,'recovery':lambda:True},source_guard=lambda:True,target_guard=lambda:True)


class ExperimentIsolationTests(unittest.TestCase):
    def test_live_shaped_root_even_with_marker_cannot_select_fixture_executor(self):
        import importlib.machinery,importlib.util
        source=Path(__file__).resolve().parents[1]/'bin/wine-runtime-overlay'
        loader=importlib.machinery.SourceFileLoader('offline_wine_isolation',str(source))
        module=importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name,loader));loader.exec_module(module)
        with tempfile.TemporaryDirectory() as scratch:
            live=Path(scratch)/'Library/Application Support/Adapted Games'
            live.mkdir(parents=True);(live/'.fixture-only').write_bytes(module.MARKER)
            sentinel=live/'private-save';sentinel.write_bytes(b'opaque owner bytes')
            with self.assertRaisesRegex(module.Blocked,'fixture_root_required'):module.Root(live)
            alias=Path(tempfile.gettempdir())/('wine-overlay-fixture-alias-'+Path(scratch).name)
            alias.symlink_to(live,target_is_directory=True)
            try:
                with self.assertRaisesRegex(module.Blocked,'fixture_root_required'):module.Root(alias)
            finally:alias.unlink()
            self.assertEqual(sentinel.read_bytes(),b'opaque owner bytes')


class DS3ConnectedReadinessTests(unittest.TestCase):
    def setUp(self):
        import test_ds3_runtime as fixture
        self.fixture=fixture.DS3Tests();self.fixture.setUp();self.addCleanup(self.fixture.tearDown);self.h=fixture.h
        self.calls=[];self.commit='a'*40
        def command(argv,timeout=600,env=None):
            self.calls.append([str(x) for x in argv])
            if str(argv[0])=='/usr/bin/git':
                tail=argv[-2:];value=self.commit if tail==['rev-parse','HEAD'] else 'main' if tail==['branch','--show-current'] else ''
                return (value+'\n').encode() if value else b''
            self.assertEqual(str(argv[0]),str(self.fixture.source/'runtime/engine/bin/wineserver'))
            self.assertEqual(argv[-1],'-w');return b''
        def scoped(control,commit,name,**kwargs):
            return operation.evaluate(name,commit,source_guard=lambda:True,**kwargs)
        self.context=patch.object(self.h,'readiness_bridge',return_value=game);self.context.start();self.addCleanup(self.context.stop)
        self.runner=patch.object(self.h,'run',side_effect=command);self.runner.start();self.addCleanup(self.runner.stop)
        self.provider=patch.object(game,'ready',side_effect=scoped);self.provider.start();self.addCleanup(self.provider.stop)
        self.file=patch.dict(self.h.__dict__,{'__file__':str(self.fixture.control/'bin/ds3-runtime')});self.file.start();self.addCleanup(self.file.stop)
        # This group exercises adapter target/owner callbacks, not repository
        # admission. Its synthetic source was never a committed Git checkout.
        # Bind the replacement at the actual new source-check seam; the real
        # closure engine has its own hostile repository fixtures.
        from lib import scoped_source_admission
        def admitted(control,commit,*,entrypoints,extra_paths=()):
            self.assertEqual(control,self.fixture.control)
            self.assertEqual(commit,self.commit)
            self.assertEqual(entrypoints,('bin/ds3-runtime',))
        self.admitted=patch.object(scoped_source_admission,'check',side_effect=admitted)
        self.admitted.start();self.addCleanup(self.admitted.stop)

    def test_initial_install_scope_exercises_bound_source_owner_and_prefix_without_vendor(self):
        self.h.source_gate(self.commit,'install',self.fixture.candidate)
        self.assertTrue(any(row[-1]=='-w' for row in self.calls))
        self.assertFalse(any('current-doctor' in row[0] for row in self.calls))
        self.assertFalse(self.fixture.root.exists())

    def test_bad_donor_code_is_denied_before_any_install_mutation(self):
        target=self.fixture.source/'runtime/engine/bin/wineserver';target.write_bytes(b'foreign code')
        with self.assertRaisesRegex(RuntimeError,'source_runtime_drift'):self.h.source_gate(self.commit,'install',self.fixture.candidate)
        self.assertFalse(self.fixture.root.exists());self.assertEqual(target.read_bytes(),b'foreign code')
    def test_completed_install_journal_does_not_pin_later_owner_profile_changes(self):
        self.fixture.installed()
        target=self.fixture.prefix/'user.reg';target.write_bytes(target.read_bytes()+b'\nowner changed current profile\n')
        before=target.read_bytes()
        self.h.source_gate(self.commit,'retire')
        self.assertEqual(target.read_bytes(),before)
    def test_completed_retire_scope_preserves_later_archive_owner_data(self):
        self.fixture.installed()
        with patch.object(self.h,'inactive'):self.h.retire(self.commit)
        archive=self.fixture.root.with_name(self.fixture.root.name+' retired '+self.commit[:12]);target=archive/'profiles/ds3/user.reg'
        target.write_bytes(target.read_bytes()+b'\nowner changed archived data\n');before=target.read_bytes()
        self.assertFalse(self.h.recover(self.commit)['changed'])
        self.assertEqual(target.read_bytes(),before)


if __name__=='__main__':unittest.main()
