"""Native successors of repeated helper-only updates, with real fixture files."""
import copy
import json
import shutil
import unittest
from unittest.mock import patch

import test_ds3_helper_delta as helper

m = helper.m


class HelperNativeSuccessor(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        helper.HelperDelta.setUpClass()

    def setUp(self):
        self.delta = helper.HelperDelta('run')
        self.delta.setUp()
        self.addCleanup(self.delta.doCleanups)
        self.f = self.delta.f
        self.native_policy = copy.deepcopy(self.f.policy)
        self.native_files = dict(self.f.files)
        self.current_source = (helper.launch.SOURCE / 'bin/ds3-runtime').read_bytes()
        self.helper_transactions = []

    def prepare_helper(self, number):
        current = json.loads((m.ROOT / 'manifest.json').read_bytes())
        self.delta.binding = current['rendererOverride']
        self.delta.prepare(number)
        f = self.f
        # Exercise the actual helper-aware reader after rollback, not historical
        # schema8 source with a comment appended by the lightweight base fixture.
        shutil.rmtree(f.tx)
        f.files['ds3-runtime'] = self.current_source + ('\n# helper successor %d\n' % number).encode()
        f.policy['candidateFiles'] = f.hashes(f.files)
        f.after = m.renderer_after(f.before, f.modes, f.files, f.policy, f.commit, f.rows)
        f.make_transaction()
        self.helper_transactions.append(f.tx)

    def apply_helpers(self, count=17):
        for number in range(count):
            self.prepare_helper(number)
            self.assertTrue(m.renderer_run(self.f.tx, 'after'))

    def prepare_native(self, schema):
        f = self.f
        targets = m.renderer_targets({'schema': schema})
        f.before = f.capture(targets)
        f.modes = {key: path.stat().st_mode & 0o777 for key, path in targets.items()}
        current = json.loads(f.before['manifest'])
        f.files = {name: raw for name, raw in self.native_files.items()
                   if name not in m.RENDERER_LAUNCH_FILES.values()}
        f.files.update({'d3d11.dll': f.before['runtime'], 'dxgi.dll': f.before['dxgiRuntime'],
                        'ds3-runtime': self.current_source + ('\n# native successor %d\n' % schema).encode()})
        f.files.update({filename: f.before[key] for key, (_, filename) in m.RENDERER_NATIVE.items()})
        changed = 'winemac.so' if schema == 7 else 'd3d11.dll'
        f.files[changed] += b' native-only successor'
        f.refresh_provenance()
        f.policy = dict(self.native_policy, schema=schema,
                        previousRendererSha256=m.renderer_hash(current),
                        previousDxgiSha256=m.renderer_dxgi_hash(current),
                        previousNativeRuntimeHashes=m.renderer_native_hashes(current),
                        previousManifestSha256=m.digest_bytes(f.before['manifest']),
                        previousEffectiveLifecycleSha256=m.digest_bytes(f.before['lifecycle']),
                        candidateFiles=f.hashes(f.files),
                        helperPredecessor={'descriptor': current['helperOverride'],
                                           'launchAdmission': {key: m.sha(path) for key, path
                                                               in m.renderer_launch_targets().items()
                                                               if key in m.RENDERER_LAUNCH_FILES}})
        f.policy.pop('launchAdmission', None)
        f.commit = str(schema) * 40
        f.rows = m.renderer_rows()
        f.after = m.renderer_after(f.before, f.modes, f.files, f.policy, f.commit, f.rows)
        f.tx = m.renderer_transaction(f.commit, admission=schema == 7, d3d=schema == 9)
        f.make_transaction()

    def preserved(self):
        paths = list(m.renderer_launch_targets().values()) + [m.PREFIX / 'save.dat']
        for path in m.ROOT.rglob('*'):
            if path.is_file() and any(part.startswith(('.helper-renderer-', '.launch-renderer-',
                                                      '.admitted-renderer-', '.native-', '.d3d-renderer-'))
                                      for part in path.relative_to(m.ROOT).parts):
                paths.append(path)
        return self.f.facts(paths)

    def assert_current_reader(self, manifest):
        raw = (m.ROOT / 'ds3-runtime').read_bytes()
        reader = self.f.old_reader(raw, 'helper_native_successor_reader')
        reader.ADMISSION_SHA = m.sha(m.HOME / 'AIDev/bin/game-launch-admission')
        stale_helpers = set(self.helper_transactions[:-1])
        real_read = reader.renderer_read

        def no_helper_history(path):
            self.assertFalse(path in stale_helpers, 'installed reader replayed superseded helper history')
            return real_read(path)

        with patch.object(reader, 'renderer_read', side_effect=no_helper_history):
            reader.renderer_verify_binding(manifest)
            reader.installed_native_binding(manifest)
            reader.renderer_pending_guard()
            self.assertEqual(reader.native_admission_lifecycle(manifest), m.digest_bytes(raw))

    def roundtrip(self, schema):
        self.apply_helpers()
        old_helper = self.helper_transactions[-1]
        fixed = self.preserved()
        self.prepare_native(schema)
        f = self.f
        native_tx = f.tx
        self.assertEqual(len(m.renderer_targets(f.policy)), 13)
        self.assertNotIn('helperOverride', json.loads(f.after['manifest']))
        stale_helpers = set(self.helper_transactions[:-1])
        real_read = m.renderer_read

        def no_helper_history(path):
            self.assertFalse(path in stale_helpers, 'native successor replayed superseded helper history')
            return real_read(path)

        with patch.object(m, 'ADMISSION_SHA', m.sha(m.HOME / 'AIDev/bin/game-launch-admission')), \
             patch.object(m, 'renderer_read', side_effect=no_helper_history):
            for side in ('after', 'before', 'after'):
                with self.subTest(schema=schema, side=side):
                    self.assertTrue(m.renderer_run(native_tx, side))
                    self.assertFalse(m.renderer_run(native_tx, side))
                    f.assert_images(f.after if side == 'after' else f.before)
                    manifest = json.loads((m.ROOT / 'manifest.json').read_bytes())
                    self.assertEqual('helperOverride' in manifest, side == 'before')
                    self.assert_current_reader(manifest)
                    self.assertEqual(f.facts(fixed), fixed)
        self.assertTrue(old_helper.is_dir())
        # A further helper-only delta must bind the newly installed native head,
        # not silently reconnect to the native generation preceding 17 helpers.
        native = f.facts(path for path in (m.ROOT / 'runtime').rglob('*') if path.is_file())
        history = self.preserved()
        self.prepare_helper(17)
        self.assertEqual(self.f.policy['rendererBinding']['transactionCommit'], str(schema) * 40)
        self.assertTrue(m.renderer_run(self.f.tx, 'after'))
        with patch.object(m, 'ADMISSION_SHA', m.sha(m.HOME / 'AIDev/bin/game-launch-admission')):
            manifest = json.loads((m.ROOT / 'manifest.json').read_bytes())
            self.assert_current_reader(manifest)
        self.assertEqual(f.facts(native), native)
        history = {path: facts for path, facts in history.items() if path not in m.renderer_launch_targets().values()}
        self.assertEqual(f.facts(history), history)

    def test_schema7_after_seventeen_helpers_roundtrip_then_helper_again(self):
        self.roundtrip(7)

    def test_schema9_after_seventeen_helpers_roundtrip_then_helper_again(self):
        self.roundtrip(9)

    def test_helper_predecessor_descriptor_mismatch_refused(self):
        self.apply_helpers(1)
        self.prepare_native(7)
        for field, value in [('transactionCommit', 'f' * 40), ('policySha256', 'f' * 64),
                             ('lifecycleSha256', 'f' * 64), ('admissionSha256', 'f' * 64)]:
            policy = copy.deepcopy(self.f.policy)
            policy['helperPredecessor']['descriptor'][field] = value
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                m.renderer_after(self.f.before, self.f.modes, self.f.files, policy,
                                 self.f.commit, self.f.rows)

    def test_foreign_current_launcher_blocks_native_update_without_writes(self):
        self.apply_helpers(1)
        self.prepare_native(9)
        before = self.f.capture(m.renderer_targets(self.f.policy))
        for name, path in m.renderer_launch_targets().items():
            if name not in m.RENDERER_LAUNCH_FILES:
                continue
            raw = path.read_bytes()
            path.write_bytes(b'foreign launcher must survive')
            with self.subTest(name=name), self.assertRaises(RuntimeError):
                m.renderer_run(self.f.tx, 'after')
            self.assertEqual(self.f.capture(m.renderer_targets(self.f.policy)), before)
            self.assertEqual(path.read_bytes(), b'foreign launcher must survive')
            path.write_bytes(raw)


if __name__ == '__main__':
    unittest.main()
