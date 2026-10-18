"""Immutable asset publication with isolated HOME and fake signature acceptance."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('native_admission_assets', ROOT / 'lib/game_native_admission_assets.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class Assets(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='.asset-fixture-', dir=ROOT)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.home = self.root / 'home'
        self.home.mkdir(mode=0o700)
        (self.home / 'AIDev').mkdir(mode=0o700)
        self.ds3 = self.home / 'Library/Application Support/Adapted Games DS3'
        self.ds3.mkdir(parents=True, mode=0o700)
        self.payload = self.root / 'payload'
        self.payload.mkdir(mode=0o700)
        self.intent = {'schema': 1, 'owner': m.OWNER, 'id': 'game-native-launch-admission',
                       'companions': {}, 'nativeRoute': {'durableRelativePath': 'native/' + m.APP,
                                                       'bundleFiles': {}}}
        self.original = {}
        for prefix, modes, rows in [('companions/', m.COMPANIONS, self.intent['companions']),
                                    ('native/' + m.APP + '/', m.BUNDLE, self.intent['nativeRoute']['bundleFiles'])]:
            for name, mode in modes.items():
                raw = ('reviewed bytes ' + prefix + name).encode()
                path = self.payload / (prefix + name)
                path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                path.write_bytes(raw)
                path.chmod(mode)
                rows[name] = {'sha256': m.sha(raw), 'mode': mode}
                self.original[path] = raw
        self.events = []
        self.guards = []
        self.commit = 'a' * 40
        patcher = patch.object(m, 'HOME', self.home)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.real_signature = m.verify_signature
        patcher = patch.object(m, 'verify_signature', side_effect=self.signature)
        self.signature_mock = patcher.start()
        self.addCleanup(patcher.stop)

    def signature(self, app):
        self.assertIn('.native-admission-assets-stage', str(app))
        for rel, row in self.intent['nativeRoute']['bundleFiles'].items():
            self.assertEqual(m.sha((app / rel).read_bytes()), row['sha256'])

    def guard(self):
        self.guards.append('guard')

    def publish(self, event=None, commit=None):
        return m.publish(self.intent, self.payload, commit or self.commit,
                         self.guard, event or self.events.append)

    def test_publish_verify_noop_private_modes_and_retained_first_commit(self):
        self.assertTrue(self.publish()['changed'])
        verified = m.verify_assets(self.intent)
        self.assertEqual(set(verified['receipts']), {'companions', 'native'})
        self.assertGreater(len(self.guards), 10)
        self.assertEqual(self.signature_mock.call_count, 1)
        files, namespaces = m.layout(self.intent)
        for namespace, parent, name, stage, expected in namespaces:
            final = parent / name
            self.assertEqual(final.stat().st_mode & 0o777, 0o700)
            self.assertFalse((parent / stage).exists())
            receipt = json.loads((final / 'receipt.json').read_bytes())
            self.assertEqual(receipt['acceptedCommit'], self.commit)
            self.assertEqual(receipt['payloadFiles'], files)
            for rel, row in expected.items():
                self.assertEqual((final / rel).stat().st_mode & 0o777, row['mode'])
                self.assertEqual(m.sha((final / rel).read_bytes()), row['sha256'])
        self.assertEqual((self.home / 'AIDev/lib').stat().st_mode & 0o777, 0o700)
        before = {p: p.read_bytes() for p in self.home.rglob('*') if p.is_file()}
        self.assertFalse(self.publish(commit='b' * 40)['changed'])
        self.assertEqual(self.signature_mock.call_count, 1)
        self.assertEqual(before, {p: p.read_bytes() for p in self.home.rglob('*') if p.is_file()})
        for path, raw in self.original.items():
            self.assertEqual(path.read_bytes(), raw)

    def test_unknown_final_and_unknown_stage_preserved_before_any_asset_publication(self):
        for stage in (False, True):
            with self.subTest(stage=stage):
                name = '.native-admission-assets-stage' if stage else 'native'
                namespace = self.ds3 / name
                namespace.mkdir(mode=0o700)
                (namespace / 'owner-choice').write_bytes(b'preserve')
                with self.assertRaises((m.Blocked, FileNotFoundError)):
                    self.publish()
                self.assertEqual((namespace / 'owner-choice').read_bytes(), b'preserve')
                self.assertFalse((self.home / 'AIDev/lib').exists())
                shutil.rmtree(namespace)

    def test_every_owned_checkpoint_resumes_and_ownerless_stage_refuses(self):
        self.publish()
        cuts = list(self.events)
        _, namespaces = m.layout(self.intent)
        for cut in cuts:
            for _, parent, name, stage, _ in namespaces:
                for leaf in (name, stage):
                    if (parent / leaf).exists():
                        shutil.rmtree(parent / leaf)
            if (self.home / 'AIDev/lib').exists():
                (self.home / 'AIDev/lib').rmdir()
            fired = []
            def fault(label):
                if label == cut and not fired:
                    fired.append(label)
                    raise SystemExit(77)
            with self.subTest(cut=cut), self.assertRaises(SystemExit):
                self.publish(fault)
            self.assertTrue(fired)
            if cut.endswith(':stage-created'):
                with self.assertRaises(FileNotFoundError):
                    self.publish()
                self.assertFalse((self.ds3 / 'native').exists())
            else:
                self.publish()
                m.verify_assets(self.intent)

    def test_third_states_modes_receipts_and_extra_inventory_refused(self):
        self.publish()
        base = self.home / 'AIDev/lib/game-launch-admission'
        path = base / 'bridge.py'
        raw = path.read_bytes()
        path.write_bytes(b'foreign')
        with self.assertRaisesRegex(m.Blocked, 'file_drift'):
            self.publish()
        self.assertEqual(path.read_bytes(), b'foreign')
        path.write_bytes(raw)
        path.chmod(0o644)
        with self.assertRaisesRegex(m.Blocked, 'unsafe_file'):
            m.verify_assets(self.intent)
        path.chmod(0o600)
        extra = base / 'new-directory'
        extra.mkdir(mode=0o700)
        with self.assertRaisesRegex(m.Blocked, 'directory_inventory'):
            self.publish()
        extra.rmdir()
        receipt = base / 'receipt.json'
        saved = receipt.read_bytes()
        receipt.write_bytes(saved + b' ')
        with self.assertRaisesRegex(m.Blocked, 'receipt_bytes'):
            self.publish()
        self.assertEqual(receipt.read_bytes(), saved + b' ')

    def test_payload_drift_links_and_incomplete_intent_refuse_without_assets(self):
        path = self.payload / 'companions/bridge.py'
        raw = path.read_bytes()
        path.write_bytes(b'changed')
        with self.assertRaisesRegex(m.Blocked, 'file_drift'):
            self.publish()
        path.write_bytes(raw)
        original = path.with_name('original')
        path.rename(original)
        path.symlink_to(original)
        with self.assertRaises((m.Blocked, OSError)):
            self.publish()
        path.unlink()
        original.rename(path)
        before = copy.deepcopy(self.intent)
        del self.intent['companions']['native-identity/prefix_probe']
        with self.assertRaisesRegex(m.Blocked, 'companion_scope'):
            self.publish()
        self.intent = before
        self.assertFalse((self.home / 'AIDev/lib').exists())

    def test_signature_failure_leaves_owned_stage_and_no_app_or_code_publication(self):
        self.signature_mock.side_effect = m.Blocked('signature refusal')
        with self.assertRaisesRegex(m.Blocked, 'signature refusal'):
            self.publish()
        self.assertFalse((self.ds3 / 'native').exists())
        self.assertTrue((self.ds3 / '.native-admission-assets-stage/receipt.json').is_file())
        self.assertFalse((self.home / 'AIDev/lib/game-launch-admission').exists())
        self.assertTrue((self.home / 'AIDev/lib/.game-launch-admission-assets-stage/receipt.json').is_file())
        self.signature_mock.side_effect = self.signature
        self.publish()
        m.verify_assets(self.intent)

    def test_guard_refusal_and_publication_collision_preserve_unknown_namespace(self):
        def guard():
            raise m.Blocked('source guard refusal')
        with self.assertRaisesRegex(m.Blocked, 'source guard refusal'):
            m.publish(self.intent, self.payload, self.commit, guard, self.events.append)
        self.assertFalse((self.home / 'AIDev/lib').exists())
        def event(label):
            if label == 'assets:companions:file:native-identity/prefix_probe':
                namespace = self.home / 'AIDev/lib/game-launch-admission'
                namespace.mkdir(mode=0o700)
                (namespace / 'preserve').write_bytes(b'owner')
        with self.assertRaises(OSError):
            self.publish(event)
        self.assertEqual((self.home / 'AIDev/lib/game-launch-admission/preserve').read_bytes(), b'owner')
        self.assertTrue((self.home / 'AIDev/lib/.game-launch-admission-assets-stage/receipt.json').is_file())

    def test_signature_command_fixed_and_nonzero_exit_refused(self):
        import subprocess
        with patch.object(subprocess, 'run', return_value=subprocess.CompletedProcess([], 1)) as run:
            with self.assertRaisesRegex(m.Blocked, 'bundle_signature'):
                self.real_signature(self.payload / 'native' / m.APP)
        self.assertEqual(run.call_args.args[0][:3], ['/usr/bin/codesign', '--verify', '--strict'])

    def test_retry_retains_one_first_commit_after_first_namespace_published(self):
        def fault(label):
            if label == 'assets:companions:published':
                raise SystemExit(77)
        with self.assertRaises(SystemExit):
            self.publish(fault)
        result = self.publish(commit='b' * 40)
        self.assertTrue(result['changed'])
        self.assertEqual({receipt['acceptedCommit'] for receipt in result['receipts'].values()}, {self.commit})

    def test_malformed_canonical_receipts_are_not_adopted(self):
        self.publish()
        path = self.home / 'AIDev/lib/game-launch-admission/receipt.json'
        raw = path.read_bytes()
        receipt = json.loads(raw)
        receipt['schema'] = True
        path.write_bytes(m.encode(receipt))
        with self.assertRaisesRegex(m.Blocked, 'receipt_bytes'):
            self.publish()
        receipt = json.loads(raw)
        receipt['payloadFiles']['companions/bridge.py']['mode'] = 384.0
        path.write_bytes(m.encode(receipt))
        with self.assertRaisesRegex(m.Blocked, 'receipt_bytes'):
            self.publish()

    def test_final_guard_change_to_stage_is_refused_before_promotion(self):
        fired = []
        def guard():
            companion = self.home / 'AIDev/lib/.game-launch-admission-assets-stage'
            native = self.ds3 / '.native-admission-assets-stage'
            if (companion / 'native-identity/probe').is_file() and (native / m.APP / 'Contents/_CodeSignature/CodeResources').is_file() and not fired:
                fired.append(True)
                (companion / 'foreign').write_bytes(b'preserve')
        with self.assertRaisesRegex(m.Blocked, 'unknown_inventory'):
            m.publish(self.intent, self.payload, self.commit, guard, self.events.append)
        self.assertTrue(fired)
        self.assertFalse((self.home / 'AIDev/lib/game-launch-admission').exists())
        self.assertFalse((self.ds3 / 'native').exists())


class GenerationTwo(unittest.TestCase):
    def setUp(self):
        fixture = Assets('run')
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.f = fixture
        fixture.publish()
        self.old_companions = fixture.home / 'AIDev/lib/game-launch-admission'
        self.old_native = fixture.ds3 / 'native'
        self.old = self.snapshot_old()
        self.intent = copy.deepcopy(fixture.intent)
        self.intent['companionGeneration'] = 2
        self.intent['assetPredecessor'] = {
            'acceptedCommit': fixture.commit,
            'intentSha256': m.sha(m.encode(fixture.intent)),
            'companionReceiptSha256': m.sha((self.old_companions / 'receipt.json').read_bytes()),
            'nativeReceiptSha256': m.sha((self.old_native / 'receipt.json').read_bytes()),
        }
        self.payload = fixture.root / 'payload-v2'
        shutil.copytree(fixture.payload, self.payload)
        for rel in m.COMPANIONS:
            path = self.payload / 'companions' / rel
            raw = b'generation two: ' + path.read_bytes()
            path.write_bytes(raw)
            self.intent['companions'][rel]['sha256'] = m.sha(raw)
        self.final = fixture.home / 'AIDev/lib/game-launch-admission-v2'
        self.stage = fixture.home / 'AIDev/lib/.game-launch-admission-v2-assets-stage'
        self.commit = 'b' * 40
        self.events = []
        fixture.signature_mock.reset_mock()
        fixture.signature_mock.side_effect = self.signature

    def snapshot_old(self):
        result = {}
        for root in (self.old_companions, self.old_native):
            for path in (root, *root.rglob('*')):
                info = path.lstat()
                result[path] = (m._facts(info), path.read_bytes() if path.is_file() else None)
        return result

    def signature(self, app):
        self.assertEqual(app, self.payload / 'native' / m.APP)
        for rel, row in self.intent['nativeRoute']['bundleFiles'].items():
            self.assertEqual(m.sha((app / rel).read_bytes()), row['sha256'])

    def publish(self, event=None, guard=None, commit=None):
        return m.publish(self.intent, self.payload, commit or self.commit,
                         guard or self.f.guard, event or self.events.append)

    def test_success_noop_and_verification_preserve_both_original_namespaces(self):
        result = self.publish()
        self.assertTrue(result['changed'])
        self.assertEqual(self.f.signature_mock.call_count, 1)
        self.assertEqual(self.old, self.snapshot_old())
        self.assertFalse(self.stage.exists())
        files, namespaces = m.layout(self.intent)
        self.assertEqual(len(namespaces), 1)
        self.assertEqual(namespaces[0][2], 'game-launch-admission-v2')
        self.assertEqual(result['receipts']['companions']['acceptedCommit'], self.commit)
        self.assertEqual(result['receipts']['companions']['payloadFiles'], files)
        self.assertEqual(result['receipts']['native']['acceptedCommit'], self.f.commit)
        for rel, row in self.intent['companions'].items():
            self.assertEqual(m.sha((self.final / rel).read_bytes()), row['sha256'])
        self.assertEqual(m.verify_assets(self.intent), {key: value for key, value in result.items() if key != 'changed'})
        # The payload is still verified on a no-op, but no immutable file changes.
        self.f.signature_mock.side_effect = lambda app: self.assertEqual(app, self.payload / 'native' / m.APP)
        before = {path: m._facts(path.lstat()) for path in self.final.rglob('*')}
        self.assertFalse(self.publish(commit='c' * 40)['changed'])
        self.assertEqual(before, {path: m._facts(path.lstat()) for path in self.final.rglob('*')})
        self.assertEqual(self.old, self.snapshot_old())

    def test_predecessor_receipt_pin_commit_policy_and_canonical_schema_are_required(self):
        original = copy.deepcopy(self.intent['assetPredecessor'])
        for key, value in [('acceptedCommit', 'c' * 40), ('intentSha256', 'f' * 64),
                           ('companionReceiptSha256', 'f' * 64), ('nativeReceiptSha256', 'f' * 64)]:
            with self.subTest(key=key):
                self.intent['assetPredecessor'] = dict(original, **{key: value})
                with self.assertRaisesRegex(m.Blocked, 'predecessor_receipt'):
                    self.publish()
                self.assertFalse(self.stage.exists())
        self.intent['assetPredecessor'] = original
        receipt_path = self.old_companions / 'receipt.json'
        raw = receipt_path.read_bytes()
        for mutate in (lambda receipt: receipt.update(schema=True),
                       lambda receipt: receipt['payloadFiles']['companions/bridge.py'].update(mode=384.0)):
            receipt = json.loads(raw)
            mutate(receipt)
            changed = m.encode(receipt)
            receipt_path.write_bytes(changed)
            self.intent['assetPredecessor']['companionReceiptSha256'] = m.sha(changed)
            with self.assertRaisesRegex(m.Blocked, 'predecessor_(receipt_binding|payload_policy)'):
                self.publish()
            self.assertFalse(self.stage.exists())
        receipt_path.write_bytes(raw)

    def test_original_companion_app_and_inventory_drift_refuse_before_v2_stage(self):
        for path in (self.old_companions / 'bridge.py', self.old_native / m.APP / 'Contents/MacOS/wine'):
            raw = path.read_bytes()
            path.write_bytes(b'third state')
            with self.assertRaisesRegex(m.Blocked, 'file_drift'):
                self.publish()
            self.assertEqual(path.read_bytes(), b'third state')
            self.assertFalse(self.stage.exists())
            path.write_bytes(raw)
        extra = self.old_native / 'unknown'
        extra.write_bytes(b'preserve')
        with self.assertRaisesRegex(m.Blocked, 'unknown_inventory'):
            self.publish()
        self.assertEqual(extra.read_bytes(), b'preserve')
        self.assertFalse(self.stage.exists())

    def test_new_app_must_equal_original_and_full_payload_signature_still_required(self):
        row = self.intent['nativeRoute']['bundleFiles']['Contents/MacOS/wine']
        old = row['sha256']
        row['sha256'] = 'f' * 64
        with self.assertRaisesRegex(m.Blocked, 'predecessor_native_changed'):
            self.publish()
        row['sha256'] = old
        path = self.payload / 'native' / m.APP / 'Contents/MacOS/wine'
        raw = path.read_bytes()
        path.write_bytes(b'payload app changed')
        with self.assertRaisesRegex(m.Blocked, 'file_drift'):
            self.publish()
        path.write_bytes(raw)
        self.f.signature_mock.side_effect = m.Blocked('signature refused')
        with self.assertRaisesRegex(m.Blocked, 'signature refused'):
            self.publish()
        self.assertFalse(self.stage.exists())
        self.assertFalse(self.final.exists())
        self.assertEqual(self.old, self.snapshot_old())

    def test_v2_interruption_checkpoints_resume_without_touching_original_assets(self):
        self.publish()
        cuts = list(self.events)
        shutil.rmtree(self.final)
        for cut in cuts:
            fired = []
            def fault(label):
                if label == cut and not fired:
                    fired.append(True)
                    raise SystemExit(77)
            with self.subTest(cut=cut), self.assertRaises(SystemExit):
                self.publish(event=fault)
            if cut.endswith(':stage-created'):
                with self.assertRaises(FileNotFoundError):
                    self.publish()
                shutil.rmtree(self.stage)
            else:
                self.f.signature_mock.side_effect = lambda app: None
                self.publish(commit='c' * 40)
                verified = m.verify_assets(self.intent)
                self.assertEqual(verified['receipts']['companions']['acceptedCommit'], self.commit)
                shutil.rmtree(self.final)
            self.assertEqual(self.old, self.snapshot_old())

    def test_old_root_drift_inside_guard_blocks_before_v2_promotion(self):
        path = self.old_companions / 'bridge.py'
        fired = []
        def guard():
            if (self.stage / 'native-identity/probe').is_file() and not fired:
                fired.append(True)
                path.write_bytes(b'changed inside caller guard')
        with self.assertRaisesRegex(m.Blocked, 'file_drift'):
            self.publish(guard=guard)
        self.assertTrue(fired)
        self.assertFalse(self.final.exists())
        self.assertEqual(path.read_bytes(), b'changed inside caller guard')
        self.assertTrue(self.stage.exists())

    def test_generation_two_receipt_requires_a_successor_commit(self):
        self.publish()
        path = self.final / 'receipt.json'
        receipt = json.loads(path.read_bytes())
        receipt['acceptedCommit'] = self.f.commit
        path.write_bytes(m.encode(receipt))
        with self.assertRaisesRegex(m.Blocked, 'successor_commit_required'):
            m.verify_assets(self.intent)
        with self.assertRaisesRegex(m.Blocked, 'successor_commit_required'):
            self.publish()

    def test_unknown_v2_namespace_or_stage_and_other_generations_refuse(self):
        for path in (self.final, self.stage):
            path.mkdir(mode=0o700)
            (path / 'owner-choice').write_bytes(b'preserve')
            with self.assertRaises((m.Blocked, FileNotFoundError)):
                self.publish()
            self.assertEqual((path / 'owner-choice').read_bytes(), b'preserve')
            self.assertEqual(self.old, self.snapshot_old())
            shutil.rmtree(path)
        for value in (True, 1, 3, 2.0, '2'):
            self.intent['companionGeneration'] = value
            with self.assertRaisesRegex(m.Blocked, 'companion_generation'):
                self.publish()


if __name__ == '__main__':
    unittest.main()
