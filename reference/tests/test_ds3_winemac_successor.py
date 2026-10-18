"""Winemac-only successor over DXGI ancestry; synthetic HOME only."""
import copy
import json
import unittest
from unittest.mock import patch
import test_ds3_dxgi_successor as dx
m = dx.m

class WinemacSuccessor(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        dx.DxgiSuccessor.setUpClass()

    def setUp(self):
        self.dx = dx.DxgiSuccessor('run')
        self.dx.setUp()
        self.addCleanup(self.dx.doCleanups)
        self.f = self.dx.f
        m.renderer_run(self.f.tx, 'after')
        self.dxgi_tx = self.f.tx
        self.prepare('7', b'winemac client extent fix')
        self.fixed = {key: self.f.before[key] for key in ('runtime', 'prefix', 'dxgiRuntime', 'dxgiPrefix', 'nativeNtdll', 'nativeMetal', 'nativeApproval')}

    def prepare(self, revision, winemac):
        f = self.f
        current = json.loads((f.root / 'manifest.json').read_bytes())
        f.before = {key: path.read_bytes() for key, path in m.renderer_targets({'schema': 7}).items()}
        f.modes = {key: path.stat().st_mode & 0o777 for key, path in m.renderer_targets({'schema': 7}).items()}
        f.files = dict(f.files, **{'winemac.so': winemac, 'dxgi.dll': f.before['dxgiRuntime'],
                                 'd3d11.dll': f.before['runtime'], 'ntdll.so': f.before['nativeNtdll'],
                                 'winemetal.so': f.before['nativeMetal']})
        provenance = json.loads(f.files['provenance.json'])
        provenance['nativeRuntimeHashes'] = {rel: m.digest_bytes(f.files[name]) for rel, name in m.RENDERER_NATIVE.values()}
        f.files['provenance.json'] = m.json_bytes(provenance)
        f.policy = dict(f.policy, schema=7, previousRendererSha256=m.renderer_hash(current),
                        previousDxgiSha256=m.renderer_dxgi_hash(current),
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
        self.dx.nt.endpoint(images)
        for name, raw in self.fixed.items():
            self.assertEqual(images[name], raw, name)
        self.assertEqual(json.loads(images['receipt'])['runtimeTreeSha256'], m.code_tree(self.f.root / 'runtime'))
        current = json.loads(images['manifest'])
        self.assertEqual(m.renderer_dxgi_hash(current), m.digest_bytes(self.fixed['dxgiRuntime']))

    def test_apply_noop_rollback_return_preserves_dxgi_and_approval(self):
        f = self.f
        self.assertEqual(len(m.renderer_targets(f.policy)), 13)
        m.renderer_policy_validate(f.policy)
        for side in ('after', 'before', 'after'):
            self.assertTrue(m.renderer_run(f.tx, side))
            self.endpoint(f.after if side == 'after' else f.before)
            self.assertFalse(m.renderer_run(f.tx, side))
            self.assertFalse(m.renderer_run(f.tx, side, recover=True))

    def test_successor_chain_and_immediate_rollback(self):
        f = self.f
        m.renderer_run(f.tx, 'after')
        first_tx = f.tx
        first_winemac = f.after['nativeWinemac']
        self.prepare('8', b'next winemac extent fix')
        m.renderer_run(f.tx, 'after')
        self.endpoint(f.after)
        snapshot = {path: path.read_bytes() for path in m.renderer_targets(f.policy).values()}
        with self.assertRaises(RuntimeError):
            m.renderer_run(first_tx, 'before')
        self.assertEqual(snapshot, {path: path.read_bytes() for path in snapshot})
        m.renderer_run(f.tx, 'before')
        self.endpoint(f.before)
        self.assertEqual(f.before['nativeWinemac'], first_winemac)
        m.renderer_run(f.tx, 'after')
        self.endpoint(f.after)

    def test_mixed_changes_rejected(self):
        for name in ('dxgi.dll', 'd3d11.dll', 'ntdll.so', 'winemetal.so'):
            policy = copy.deepcopy(self.f.policy)
            policy['candidateFiles'][name] = 'f' * 64
            with self.subTest(name=name), self.assertRaisesRegex(RuntimeError, 'renderer_winemac_only_scope'):
                m.renderer_policy_validate(policy)

    def test_winemac_intent_and_publication_recovery_both_directions(self):
        f = self.f
        for direction in ('after', 'before'):
            for boundary in ('intent:', 'published:'):
                with self.subTest(direction=direction, boundary=boundary):
                    m.renderer_run(f.tx, 'before' if direction == 'after' else 'after')
                    fired = []
                    def fault(label):
                        if label == boundary + 'nativeWinemac' and not fired:
                            fired.append(True)
                            raise SystemExit(77)
                    with patch.object(m, 'renderer_checkpoint', side_effect=fault):
                        with self.assertRaises(SystemExit):
                            m.renderer_run(f.tx, direction)
                    self.assertTrue(fired)
                    m.renderer_run(f.tx, direction, recover=True)
                    self.endpoint(f.after if direction == 'after' else f.before)

    def test_foreign_winemac_at_intent_is_retained(self):
        f = self.f
        target = m.renderer_targets(f.policy)['nativeWinemac']
        def fault(label):
            if label == 'intent:nativeWinemac':
                target.write_bytes(b'foreign winemac')
        with patch.object(m, 'renderer_checkpoint', side_effect=fault):
            with self.assertRaises(RuntimeError):
                m.renderer_run(f.tx, 'after')
        self.assertEqual(target.read_bytes(), b'foreign winemac')
        with self.assertRaises(RuntimeError):
            m.renderer_run(f.tx, 'after', recover=True)
        for name, raw in self.fixed.items():
            self.assertEqual(m.renderer_targets(f.policy)[name].read_bytes(), raw)

if __name__ == '__main__':
    unittest.main()
