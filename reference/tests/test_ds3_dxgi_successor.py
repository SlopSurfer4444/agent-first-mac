"""Exact DXGI successor transaction tests; isolated HOME, no native execution."""
import copy
import json
import unittest
from unittest.mock import patch
import test_ds3_ntdll_successor as nt
import test_ds3_renderer as legacy
m = nt.m

class DxgiSuccessor(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        nt.NtdllSuccessor.setUpClass()

    def setUp(self):
        original = legacy.Renderer.setUp
        def with_dxgi(f):
            original(f)
            raw = b'original dxgi'
            manifest = json.loads(f.before['manifest'])
            manifest['sourceCriticalHashes'][m.DXGI_REL] = m.digest_bytes(raw)
            f.before['manifest'] = m.json_bytes(manifest)
            (f.root / 'manifest.json').write_bytes(f.before['manifest'])
            for path in (f.root / 'runtime' / m.DXGI_REL, m.PREFIX / m.DXGI_PREFIX):
                path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                path.write_bytes(raw)
                path.chmod(0o644)
        self.nt = nt.NtdllSuccessor('run')
        with patch.object(legacy.Renderer, 'setUp', with_dxgi):
            self.nt.setUp()
        self.addCleanup(self.nt.doCleanups)
        self.f = self.nt.f
        m.renderer_run(self.f.tx, 'after')
        self.ntdll_tx = self.f.tx
        self.prepare('6', b'DXGI mode count fix')
        self.fixed = {name: self.f.before[name] for name in ('runtime', 'prefix', 'nativeWinemac', 'nativeMetal', 'nativeNtdll', 'nativeApproval')}

    def prepare(self, revision, dxgi):
        f = self.f
        current = json.loads((f.root / 'manifest.json').read_bytes())
        f.before = {name: p.read_bytes() for name, p in m.renderer_targets({'schema': 6}).items()}
        f.modes = {name: p.stat().st_mode & 0o777 for name, p in m.renderer_targets({'schema': 6}).items()}
        f.files = dict(f.files, **{'dxgi.dll': dxgi, 'ntdll.so': f.before['nativeNtdll'],
                                 'd3d11.dll': f.before['runtime'], 'winemac.so': f.before['nativeWinemac'],
                                 'winemetal.so': f.before['nativeMetal']})
        provenance = json.loads(f.files['provenance.json'])
        provenance.update(dxgiSha256=m.digest_bytes(dxgi), nativeRuntimeHashes={rel: m.digest_bytes(f.files[name]) for rel, name in m.RENDERER_NATIVE.values()})
        f.files['provenance.json'] = m.json_bytes(provenance)
        f.policy = dict(f.policy, schema=6, previousRendererSha256=m.renderer_hash(current),
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
        self.nt.endpoint(images)
        self.assertEqual(images['dxgiRuntime'], images['dxgiPrefix'])
        for name, raw in self.fixed.items():
            self.assertEqual(images[name], raw, name)
        for name in ('dxgiRuntime', 'dxgiPrefix'):
            self.assertEqual(m.renderer_targets(self.f.policy)[name].stat().st_mode & 0o777, 0o644)
        manifest = json.loads(images['manifest'])
        self.assertEqual(m.renderer_dxgi_hash(manifest), m.digest_bytes(images['dxgiRuntime']))
        self.assertEqual(manifest['sourceCriticalHashes'][m.DXGI_REL], m.digest_bytes(b'original dxgi'))
        receipt = json.loads(images['receipt'])
        self.assertEqual(receipt['runtimeTreeSha256'], m.code_tree(self.f.root / 'runtime'))

    def test_apply_noop_rollback_return_exact_closure(self):
        f = self.f
        self.assertEqual(len(m.renderer_targets(f.policy)), 13)
        m.renderer_policy_validate(f.policy)
        for side in ('after', 'before', 'after'):
            self.assertTrue(m.renderer_run(f.tx, side))
            self.endpoint(f.after if side == 'after' else f.before)
            self.assertFalse(m.renderer_run(f.tx, side))

    def test_second_dxgi_successor_and_immediate_rollback(self):
        f = self.f
        m.renderer_run(f.tx, 'after')
        first = f.tx
        self.prepare('7', b'second dxgi fix')
        m.renderer_run(f.tx, 'after')
        self.endpoint(f.after)
        with self.assertRaises(RuntimeError):
            m.renderer_run(first, 'before')
        m.renderer_run(f.tx, 'before')
        self.endpoint(f.before)
        self.assertEqual(f.before['dxgiRuntime'], b'DXGI mode count fix')
        m.renderer_run(f.tx, 'after')
        self.endpoint(f.after)

    def test_both_dxgi_copy_faults_recover_both_directions(self):
        f = self.f
        for direction in ('after', 'before'):
            for name in ('dxgiRuntime', 'dxgiPrefix'):
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

    def test_mixed_graphics_and_native_rejected(self):
        for name in ('d3d11.dll', 'ntdll.so', 'winemac.so', 'winemetal.so'):
            policy = copy.deepcopy(self.f.policy)
            policy['candidateFiles'][name] = 'f' * 64
            with self.subTest(name=name), self.assertRaises(RuntimeError):
                m.renderer_policy_validate(policy)

    def test_each_copy_drift_retained_before_any_writes(self):
        f = self.f
        targets = m.renderer_targets(f.policy)
        for name in ('dxgiRuntime', 'dxgiPrefix'):
            raw = targets[name].read_bytes()
            targets[name].write_bytes(b'foreign owner bytes')
            snapshot = {p: p.read_bytes() for p in targets.values()}
            with self.subTest(name=name), self.assertRaises(RuntimeError):
                m.renderer_run(f.tx, 'after')
            self.assertEqual(snapshot, {p: p.read_bytes() for p in snapshot})
            targets[name].write_bytes(raw)

    def test_schema5_successor_refused_after_dxgi(self):
        f = self.f
        m.renderer_run(f.tx, 'after')
        current = json.loads(f.after['manifest'])
        policy = copy.deepcopy(f.policy)
        policy.update(schema=5, previousManifestSha256=m.digest_bytes(f.after['manifest']),
                      previousEffectiveLifecycleSha256=m.digest_bytes(f.after['lifecycle']))
        del policy['previousDxgiSha256']
        del policy['candidateFiles']['dxgi.dll']
        before = {k: v for k, v in f.after.items() if not k.startswith('dxgi')}
        with self.assertRaisesRegex(RuntimeError, 'renderer_dxgi_successor_required'):
            m.renderer_after(before, f.modes, f.files, policy, '8' * 40, m.renderer_rows())
        self.endpoint(f.after)

if __name__ == '__main__':
    unittest.main()
