"""Independent schema5 transaction tests: synthetic HOME, never launches Wine."""
import copy
import json
import unittest
from unittest.mock import patch
import test_ds3_admission_renderer as admitted

m = admitted.m
NTDLL = 'engine/lib/wine/x86_64-unix/ntdll.so'

class NtdllSuccessor(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        admitted.AdmissionRenderer.setUpClass()

    def setUp(self):
        self.f = admitted.AdmissionRenderer('run')
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        m.renderer_run(self.f.tx, 'after')
        self.original_tx = self.f.tx
        self.original_approval = m.HOME / 'AIDev/state/ds3-native-launch-approval.json'
        self.original_approval_bytes = self.original_approval.read_bytes()
        self.prepare('5', b'first ntdll successor')

    def prepare(self, revision, ntdll):
        f = self.f
        current = json.loads((f.root / 'manifest.json').read_bytes())
        f.before = {name: path.read_bytes() for name, path in m.renderer_targets({'schema': 5}).items()}
        f.modes = {name: path.stat().st_mode & 0o777 for name, path in m.renderer_targets({'schema': 5}).items()}
        f.files = dict(f.files, **{'ntdll.so': ntdll, 'd3d11.dll': f.before['runtime'],
                                 'winemac.so': f.before['nativeWinemac'], 'winemetal.so': f.before['nativeMetal']})
        provenance = json.loads(f.files['provenance.json'])
        provenance.update(nativeRuntimeHashes={rel: m.digest_bytes(f.files[name]) for rel, name in m.RENDERER_NATIVE.values()})
        f.files['provenance.json'] = m.json_bytes(provenance)
        f.policy = dict(f.policy, schema=5, previousRendererSha256=m.renderer_hash(current),
                        previousNativeRuntimeHashes=m.renderer_native_hashes(current),
                        previousManifestSha256=m.digest_bytes(f.before['manifest']),
                        previousEffectiveLifecycleSha256=m.digest_bytes(f.before['lifecycle']),
                        candidateFiles={name: m.digest_bytes(raw) for name, raw in f.files.items()})
        f.commit = revision * 40
        f.rows = m.renderer_rows()
        f.after = m.renderer_after(f.before, f.modes, f.files, f.policy, f.commit, f.rows)
        f.tx = m.renderer_transaction(f.commit, native=True, admission=True)
        f.make_transaction()

    def endpoint(self, images):
        self.f.assert_images(images)
        approval = json.loads(self.original_approval.read_bytes())
        key = str(self.f.root / 'runtime' / NTDLL)
        self.assertEqual(approval['files'][key], m.digest_bytes(images['nativeNtdll']))
        original = json.loads(self.original_approval_bytes)
        approval['files'][key] = original['files'][key]
        self.assertEqual(approval, original)
        for path, expected in self.f.protected.items():
            if path != self.original_approval:
                self.assertEqual((path.read_bytes(), path.stat().st_mode & 0o777), expected)
        m.renderer_verify_binding(json.loads(images['manifest']))

    def test_apply_noop_rollback_return(self):
        f = self.f
        self.assertTrue(m.renderer_run(f.tx, 'after'))
        self.endpoint(f.after)
        self.assertFalse(m.renderer_run(f.tx, 'after'))
        self.assertTrue(m.renderer_run(f.tx, 'before'))
        self.endpoint(f.before)
        self.assertFalse(m.renderer_run(f.tx, 'before'))
        self.assertTrue(m.renderer_run(f.tx, 'after'))
        self.endpoint(f.after)

    def test_chained_successor_restores_immediate_approval(self):
        f = self.f
        m.renderer_run(f.tx, 'after')
        first_tx = f.tx
        first_approval = self.original_approval.read_bytes()
        self.prepare('6', b'second ntdll successor')
        self.assertNotEqual(f.policy['previousNativeRuntimeHashes'][NTDLL],
                            f.policy['nativeAdmissionBase']['intent']['preserveRuntimeHashes'][NTDLL])
        m.renderer_run(f.tx, 'after')
        self.endpoint(f.after)
        snapshot = {p: p.read_bytes() for p in m.renderer_targets(f.policy).values()}
        with self.assertRaises(RuntimeError):
            m.renderer_run(first_tx, 'before')
        self.assertEqual(snapshot, {p: p.read_bytes() for p in snapshot})
        m.renderer_run(f.tx, 'before')
        self.endpoint(f.before)
        self.assertEqual(self.original_approval.read_bytes(), first_approval)
        m.renderer_run(f.tx, 'after')
        self.endpoint(f.after)

    def test_recovery_each_intent_and_publication_both_directions(self):
        f = self.f
        changed = [name for name in f.before if f.before[name] != f.after[name]]
        self.assertIn('nativeNtdll', changed)
        self.assertIn('nativeApproval', changed)
        for direction in ('after', 'before'):
            for name in changed:
                for boundary in ('intent:', 'published:'):
                    with self.subTest(direction=direction, name=name, boundary=boundary):
                        m.renderer_run(f.tx, 'before' if direction == 'after' else 'after')
                        fired = []
                        def fault(label):
                            if label == boundary + name and not fired:
                                fired.append(True)
                                raise SystemExit(77)
                        with patch.object(m, 'renderer_checkpoint', side_effect=fault):
                            with self.assertRaises(SystemExit):
                                m.renderer_run(f.tx, direction)
                        self.assertTrue(fired)
                        m.renderer_run(f.tx, direction, recover=True)
                        self.endpoint(f.after if direction == 'after' else f.before)

    def test_other_native_or_graphics_delta_rejected(self):
        for name in ('d3d11.dll', 'winemac.so', 'winemetal.so'):
            policy = copy.deepcopy(self.f.policy)
            policy['candidateFiles'][name] = 'f' * 64
            with self.subTest(name=name), self.assertRaisesRegex(RuntimeError, 'renderer_ntdll_only_scope'):
                m.renderer_policy_validate(policy)

    def test_approval_third_state_at_publication_is_retained(self):
        f = self.f
        fired = []
        def fault(label):
            if label == 'intent:nativeApproval':
                fired.append(True)
                self.original_approval.write_bytes(b'owner modified approval')
        with patch.object(m, 'renderer_checkpoint', side_effect=fault):
            with self.assertRaises(RuntimeError):
                m.renderer_run(f.tx, 'after')
        self.assertTrue(fired)
        self.assertEqual(self.original_approval.read_bytes(), b'owner modified approval')
        with self.assertRaises(RuntimeError):
            m.renderer_run(f.tx, 'after', recover=True)
        self.assertEqual(self.original_approval.read_bytes(), b'owner modified approval')

    def test_forged_approval_field_rejected_during_derivation(self):
        f = self.f
        for field, value in (('target', '/tmp/foreign-game.exe'), ('loader', '/tmp/foreign-loader'),
                             ('bundleIdentifier', 'foreign.bundle'), ('schema', 3)):
            before = dict(f.before)
            approval = json.loads(before['nativeApproval'])
            approval[field] = value
            before['nativeApproval'] = admitted.bridge.json_bytes(approval)
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                m.renderer_after(before, f.modes, f.files, f.policy, f.commit, f.rows)

    def test_pending_launch_at_ntdll_intent_retains_all_before_images(self):
        f = self.f
        pending = self.f.home / 'AIDev/state/game-launch-pending.json'
        def fault(label):
            if label == 'intent:nativeNtdll':
                f.put(pending, m.json_bytes({'schema': 1, 'route': 'ds3', 'phase': 'prepared',
                                           'children': [], 'request': 'a' * 32, 'goal': 'game'}))
        with patch.object(m, 'renderer_checkpoint', side_effect=fault):
            with self.assertRaisesRegex(RuntimeError, 'pending_launch_requires_recovery'):
                m.renderer_run(f.tx, 'after')
        f.assert_images(f.before)

    def test_chained_predecessor_image_tamper_blocks_before_write(self):
        f = self.f
        m.renderer_run(f.tx, 'after')
        first_tx = f.tx
        self.prepare('6', b'second ntdll successor')
        target = first_tx / 'nativeApproval.after'
        snapshot = {p: p.read_bytes() for p in m.renderer_targets(f.policy).values()}
        target.write_bytes(b'foreign retained approval')
        with self.assertRaises(RuntimeError):
            m.renderer_run(f.tx, 'after')
        self.assertEqual(snapshot, {p: p.read_bytes() for p in snapshot})

    def test_original_admission_tamper_refuses_before_writes(self):
        f = self.f
        target = f.admission_directory / 'manifest.after'
        before = {p: p.read_bytes() for p in m.renderer_targets(f.policy).values()}
        target.write_bytes(b'corrupted original admission')
        with self.assertRaises(RuntimeError):
            m.renderer_run(f.tx, 'after')
        self.assertEqual(before, {p: p.read_bytes() for p in before})

if __name__ == '__main__':
    unittest.main()
