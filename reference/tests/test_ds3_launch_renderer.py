"""Real-file launch-only renderer generations; isolated HOME, no Wine or launch."""
import copy
import inspect
import json
from pathlib import Path
import shutil
import subprocess
import types
import unittest
from unittest.mock import patch

import test_ds3_admission_renderer as admitted
import test_ds3_renderer as legacy


m = admitted.m
SOURCE = admitted.SOURCE
CB1 = 'cb1bf619dbcba969703a17ed63f17ea7ea9246fd'


class LaunchRenderer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        admitted.AdmissionRenderer.setUpClass()
        cls.cb1_source = subprocess.check_output(
            ['git', 'show', CB1 + ':bin/ds3-runtime'], cwd=SOURCE)
        cls.pre_d3d_source = subprocess.check_output(
            ['git', 'show', '12e314c:bin/ds3-runtime'], cwd=SOURCE)

    def setUp(self):
        original = legacy.Renderer.setUp

        def with_dxgi(f):
            original(f)
            raw = b'original immutable dxgi'
            manifest = json.loads(f.before['manifest'])
            manifest['sourceCriticalHashes'][m.DXGI_REL] = m.digest_bytes(raw)
            f.before['manifest'] = m.json_bytes(manifest)
            (f.root / 'manifest.json').write_bytes(f.before['manifest'])
            for path in (f.root / 'runtime' / m.DXGI_REL, m.PREFIX / m.DXGI_PREFIX):
                admitted.AdmissionRenderer.put(path, raw, 0o644)

        self.f = admitted.AdmissionRenderer('run')
        with patch.object(legacy.Renderer, 'setUp', with_dxgi):
            self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        f = self.f

        # Preserve the real native/admission proofs. A complete historical
        # graphics generation gives the unchanged cb1 reader a rollback target.
        shutil.rmtree(f.tx)
        f.files['ds3-runtime'] = self.cb1_source
        provenance = json.loads(f.files['provenance.json'])
        provenance['lifecycleSha256'] = m.digest_bytes(self.cb1_source)
        f.files['provenance.json'] = m.json_bytes(provenance)
        f.policy['candidateFiles'] = self.hashes(f.files)
        f.after = m.renderer_after(f.before, f.modes, f.files, f.policy, f.commit, f.rows)
        f.make_transaction()
        m.renderer_run(f.tx, 'after')
        self.predecessor_tx = f.tx

        self.before = self.capture(m.renderer_targets({'schema': 8}))
        self.modes = {name: path.stat().st_mode & 0o777
                      for name, path in m.renderer_targets({'schema': 8}).items()}
        self.files = dict(f.files)
        self.files.update({'ds3-runtime': (f.control / 'bin/ds3-runtime').read_bytes(),
                           'd3d11.dll': self.before['runtime'],
                           'dxgi.dll': self.before['dxgiRuntime']})
        self.files.update({name: self.before[key] for key, (_, name) in m.RENDERER_NATIVE.items()})
        for key, name in m.RENDERER_LAUNCH_FILES.items():
            self.files[name] = (SOURCE / 'bin' / name).read_bytes()
            f.put(f.control / 'bin' / name, self.files[name], 0o755)
        self.pin_patch = patch.object(m, 'ADMISSION_SHA', m.digest_bytes(self.files['game-launch-admission']))
        self.pin_patch.start()
        self.addCleanup(self.pin_patch.stop)
        self.refresh_provenance()
        current = json.loads(self.before['manifest'])
        self.policy = dict(f.policy, schema=8,
                           previousRendererSha256=m.renderer_hash(current),
                           previousDxgiSha256=m.renderer_dxgi_hash(current),
                           previousNativeRuntimeHashes=m.renderer_native_hashes(current),
                           previousManifestSha256=m.digest_bytes(self.before['manifest']),
                           previousEffectiveLifecycleSha256=m.digest_bytes(self.before['lifecycle']),
                           candidateFiles=self.hashes(self.files),
                           launchAdmission={key: m.digest_bytes(self.before[key])
                                            for key in m.RENDERER_LAUNCH_FILES})
        self.commit = '6' * 40
        self.rows = m.renderer_rows()
        self.after = m.renderer_after(self.before, self.modes, self.files,
                                      self.policy, self.commit, self.rows)
        self.tx = m.renderer_transaction(self.commit, launch=True)
        self.make_transaction()
        launch_paths = set(m.renderer_launch_targets().values())
        protected = {path for path in f.protected if path not in launch_paths}
        protected.update(path for directory in (self.predecessor_tx, f.native_transaction)
                         for path in directory.rglob('*') if path.is_file())
        protected.update(path for path in (f.root / 'runtime').rglob('*') if path.is_file())
        protected.update((m.PREFIX / m.RENDERER_PREFIX, m.PREFIX / m.DXGI_PREFIX,
                          m.PREFIX / 'save.dat'))
        self.preserved = self.facts(protected)

    @staticmethod
    def hashes(files):
        return {name: m.digest_bytes(raw) for name, raw in files.items()}

    @staticmethod
    def capture(targets):
        return {name: path.read_bytes() for name, path in targets.items()}

    @staticmethod
    def facts(paths):
        result = {}
        for path in paths:
            st = path.stat()
            result[path] = (path.read_bytes(), st.st_mode & 0o777, st.st_ino,
                            st.st_mtime_ns, st.st_ctime_ns)
        return result

    def refresh_provenance(self):
        provenance = json.loads(self.files['provenance.json'])
        provenance.update(d3d11Sha256=m.digest_bytes(self.files['d3d11.dll']),
                          dxgiSha256=m.digest_bytes(self.files['dxgi.dll']),
                          lifecycleSha256=m.digest_bytes(self.files['ds3-runtime']),
                          nativeRuntimeHashes={rel: m.digest_bytes(self.files[name])
                                               for rel, name in m.RENDERER_NATIVE.values()})
        if 'game-launch-admission' in self.files:
            provenance['launchAdmissionFiles'] = {
                name: m.digest_bytes(self.files[name]) for name in m.RENDERER_LAUNCH_FILES.values()}
        else:
            provenance.pop('launchAdmissionFiles', None)
        self.files['provenance.json'] = m.json_bytes(provenance)

    def make_transaction(self):
        admitted.AdmissionRenderer.make_transaction(self)

    put = staticmethod(admitted.AdmissionRenderer.put)

    def assert_images(self, images):
        for name, path in m.renderer_targets(self.policy).items():
            self.assertEqual(path.read_bytes(), images[name], name)
            self.assertEqual(path.stat().st_mode & 0o777, self.modes[name], name)

    def assert_preserved(self):
        self.assertEqual(self.facts(self.preserved), self.preserved)
        self.assertFalse((self.f.home / 'AIDev/state/game-launch-pending.json').exists())
        self.assertFalse(list((self.f.home / 'AIDev/state').glob('.game-launch-pending-*')))

    def test_apply_noop_rollback_return_has_eighteen_targets_and_no_runtime_writes(self):
        self.assertEqual(len(m.renderer_targets(self.policy)), 18)
        self.assertEqual(set(m.renderer_launch_targets()), set(m.RENDERER_LAUNCH_MODES))
        self.assertEqual(self.tx.name, '.launch-renderer-' + self.commit)
        self.assertEqual(self.policy['nativeAdmissionBase'], self.f.policy['nativeAdmissionBase'])
        for side in ('after', 'before', 'after'):
            self.assertTrue(m.renderer_run(self.tx, side))
            images = self.after if side == 'after' else self.before
            self.assert_images(images)
            self.assertFalse(m.renderer_run(self.tx, side))
            if side == 'after':
                current = json.loads(images['manifest'])
                m.renderer_verify_binding(current)
                self.assertEqual(m.native_admission_lifecycle(current),
                                 m.digest_bytes(self.files['ds3-runtime']))
                self.assertEqual(current['launchAdmissionOverride'],
                                 self.policy['nativeAdmissionBase']['descriptor'])
            self.assert_preserved()
        for name in ('launchHubReceipt', 'launchCs2Receipt'):
            self.assertEqual(json.loads(self.after[name])['keep'], ['opaque owner state'])

    def test_each_changed_publication_recovers_in_both_directions(self):
        names = [name for name in self.before if self.before[name] != self.after[name]]
        self.assertTrue(set(m.RENDERER_LAUNCH_MODES) <= set(names))
        for direction in ('after', 'before'):
            for name in names:
                for boundary in ('intent:', 'published:'):
                    with self.subTest(direction=direction, name=name, boundary=boundary):
                        m.renderer_run(self.tx, 'before' if direction == 'after' else 'after')
                        fired = []

                        def fault(label):
                            if label == boundary + name and not fired:
                                fired.append(True)
                                raise SystemExit(77)

                        with patch.object(m, 'renderer_checkpoint', side_effect=fault):
                            with self.assertRaises(SystemExit):
                                m.renderer_run(self.tx, direction)
                        self.assertTrue(fired)
                        self.assertIsNone(m._RENDERER_LAUNCH_POLICY)
                        m.renderer_run(self.tx, direction, recover=True)
                        self.assert_images(self.after if direction == 'after' else self.before)
                        self.assert_preserved()

    def old_reader(self, raw, name):
        old = types.ModuleType(name)
        old.__file__ = str(self.f.root / 'ds3-runtime')
        exec(compile(raw, old.__file__, 'exec'), old.__dict__)
        old.ROOT, old.PREFIX, old.HOME = self.f.root, m.PREFIX, self.f.home
        old.CONTROL, old.ADMISSION_BRIDGE_PATH = self.f.control, self.f.bridge_path
        return old

    def test_unchanged_cb1_and_f921_readers_accept_their_rollback_endpoints(self):
        m.renderer_run(self.tx, 'after')
        m.renderer_run(self.tx, 'before')
        old = self.old_reader(self.cb1_source, 'unchanged_cb1_launch_rollback')
        old.renderer_pending_guard()
        old.native_admission_pending_guard()
        current = json.loads(self.before['manifest'])
        self.assertEqual(old.native_admission_lifecycle(current), m.digest_bytes(self.cb1_source))
        old.renderer_verify_binding(current)
        self.assertEqual(old.renderer_overlay_lifecycle(current),
                         m.digest_bytes(self.f.native.before['lifecycle']))
        # f921 predates schema4. Restore the retained graphics predecessor too
        # and verify its own native/admission endpoint with its unchanged code.
        self.assert_preserved()
        with patch.object(m, 'ADMISSION_SHA', m.digest_bytes(self.f.admission_helper)):
            m.renderer_run(self.predecessor_tx, 'before')
        oldest = self.old_reader(self.f.old_source, 'unchanged_f921_launch_rollback')
        oldest.renderer_pending_guard()
        oldest.native_admission_pending_guard()
        current = json.loads(self.f.before['manifest'])
        self.assertEqual(oldest.native_admission_lifecycle(current), m.digest_bytes(self.f.old_source))
        oldest.renderer_verify_binding(current)

    def test_each_fixed_launch_target_third_state_is_retained_before_any_write(self):
        targets = m.renderer_targets(self.policy)
        for name, path in m.renderer_launch_targets().items():
            with self.subTest(name=name):
                raw = path.read_bytes()
                path.write_bytes(b'foreign launch owner bytes')
                snapshot = self.capture(targets)
                record = (self.tx / 'record.json').read_bytes()
                with self.assertRaises(RuntimeError):
                    m.renderer_run(self.tx, 'after')
                self.assertEqual(self.capture(targets), snapshot)
                self.assertEqual((self.tx / 'record.json').read_bytes(), record)
                self.assertIsNone(m._RENDERER_LAUNCH_POLICY)
                path.write_bytes(raw)

    def test_installed_launch_helper_third_state_refuses_normal_verification(self):
        m.renderer_run(self.tx, 'after')
        current = json.loads(self.after['manifest'])
        m.renderer_verify_binding(current)
        self.assertEqual(m.native_admission_lifecycle(current),
                         m.digest_bytes(self.files['ds3-runtime']))
        helper = m.renderer_launch_targets()['launchHelper']
        helper.write_bytes(b'foreign helper after complete launch publication')
        snapshot = self.facts(m.renderer_targets(self.policy).values())
        for verifier in (m.renderer_verify_binding, m.native_admission_lifecycle):
            with self.subTest(verifier=verifier.__name__), self.assertRaises(RuntimeError):
                verifier(current)
            self.assertEqual(self.facts(snapshot), snapshot)
            self.assertIsNone(m._RENDERER_LAUNCH_POLICY)
        helper.write_bytes(self.after['launchHelper'])
        m.renderer_verify_binding(current)
        self.assertEqual(m.native_admission_lifecycle(current),
                         m.digest_bytes(self.files['ds3-runtime']))
        self.assert_preserved()

    def test_overlay_depth_exact_boundary_and_default_preserve_real_history(self):
        m.renderer_run(self.tx, 'after')
        current = json.loads(self.after['manifest'])
        expected = m.digest_bytes(self.f.native.before['lifecycle'])
        self.assertEqual(m.RENDERER_MAX_GENERATIONS, 16)
        self.assertEqual(inspect.signature(m.renderer_overlay_lifecycle)
                         .parameters['max_generations'].default, 16)
        histories = self.facts(path for directory in
                              (self.tx, self.predecessor_tx, self.f.native_transaction)
                              for path in directory.rglob('*') if path.is_file())
        # This fixture has three real generations, including the native/admission
        # join. The exact bound succeeds; one fewer refuses instead of truncating.
        with self.assertRaisesRegex(RuntimeError, 'renderer_lifecycle_depth'):
            m.renderer_overlay_lifecycle(current, max_generations=2)
        self.assertEqual(m.renderer_overlay_lifecycle(current, max_generations=3), expected)
        self.assertEqual(m.renderer_overlay_lifecycle(current, max_generations=15), expected)
        self.assertEqual(m.renderer_overlay_lifecycle(current), expected)
        self.assertEqual(self.facts(histories), histories)
        self.assert_preserved()

    def test_overlay_parser_observed_cycle_refuses_without_rewriting_real_proofs(self):
        m.renderer_run(self.tx, 'after')
        current = json.loads(self.after['manifest'])
        original = m.renderer_fields
        observed = []

        def cyclic_fields(manifest):
            value = original(manifest)
            caller = inspect.currentframe().f_back
            if caller.f_code is m.renderer_overlay_lifecycle.__code__ and value is not None:
                observed.append(value['transactionCommit'])
                if value['transactionCommit'] != self.commit:
                    # Inject a repeated identity at the parser observation seam;
                    # immutable records, backups and derivation stay genuine.
                    value = dict(value, transactionCommit=self.commit)
            return value

        histories = self.facts(path for directory in
                              (self.tx, self.predecessor_tx, self.f.native_transaction)
                              for path in directory.rglob('*') if path.is_file())
        with patch.object(m, 'renderer_fields', cyclic_fields):
            with self.assertRaisesRegex(RuntimeError, 'renderer_lifecycle_cycle'):
                m.renderer_overlay_lifecycle(current)
        self.assertIn(self.commit, observed)
        self.assertIn(self.f.commit, observed)
        self.assertEqual(self.facts(histories), histories)
        self.assert_preserved()
        self.assertEqual(m.renderer_overlay_lifecycle(current),
                         m.digest_bytes(self.f.native.before['lifecycle']))

    def prepare_admitted_depth_generation(self, depth):
        self.before = self.capture(m.renderer_targets({'schema': 7}))
        self.modes = {name: path.stat().st_mode & 0o777
                      for name, path in m.renderer_targets({'schema': 7}).items()}
        for name in m.RENDERER_LAUNCH_FILES.values():
            self.files.pop(name, None)
        self.files['winemac.so'] = ('real admitted driver generation %d' % depth).encode()
        self.refresh_provenance()
        current = json.loads(self.before['manifest'])
        self.policy = dict(self.policy, schema=7,
                           previousRendererSha256=m.renderer_hash(current),
                           previousDxgiSha256=m.renderer_dxgi_hash(current),
                           previousNativeRuntimeHashes=m.renderer_native_hashes(current),
                           previousManifestSha256=m.digest_bytes(self.before['manifest']),
                           previousEffectiveLifecycleSha256=m.digest_bytes(self.before['lifecycle']),
                           candidateFiles=self.hashes(self.files))
        self.policy.pop('launchAdmission', None)
        self.commit = '%040x' % (100 + depth)
        self.rows = m.renderer_rows()
        self.after = m.renderer_after(self.before, self.modes, self.files,
                                      self.policy, self.commit, self.rows)
        self.tx = m.renderer_transaction(self.commit, admission=True)
        self.make_transaction()

    def test_admitted_history_nine_sixteen_and_seventeen_keep_full_history_bound(self):
        self.assertEqual(inspect.signature(m.renderer_admission_ancestry)
                         .parameters['max_generations'].default, m.RENDERER_MAX_GENERATIONS)
        self.assertEqual(m.RENDERER_MAX_GENERATIONS, 16)
        m.renderer_run(self.tx, 'after')
        retained = [self.f.native_transaction, self.predecessor_tx, self.tx]
        # The fixture starts with one native renderer and two admitted graphics
        # generations. Build genuine schema7 records, derived images and files.
        for depth in range(3, 17):
            prior_facts = self.facts(path for directory in retained
                                     for path in directory.rglob('*') if path.is_file())
            self.prepare_admitted_depth_generation(depth)
            self.assertTrue(m.renderer_run(self.tx, 'after'))
            self.assertEqual(self.facts(prior_facts), prior_facts)
            self.assert_images(self.after)
            retained.append(self.tx)
            if depth == 9:
                record, images = m.renderer_read(self.tx)
                m.renderer_admission_ancestry(record, images)
                with self.assertRaisesRegex(RuntimeError, 'renderer_admission_depth'):
                    m.renderer_admission_ancestry(record, images, max_generations=8)
                current = json.loads(self.after['manifest'])
                m.renderer_verify_binding(current)
                self.assertEqual(m.native_admission_lifecycle(current),
                                 m.digest_bytes(self.files['ds3-runtime']))
                previous = m.renderer_binding_transaction(json.loads(images['before']['manifest']))
                previous_record, _ = m.renderer_read(previous)
                # Repeated input identity must fail even when the joined
                # predecessor is read and derived from genuine immutable files.
                cyclic = dict(record, commit=previous_record['commit'])
                with self.assertRaisesRegex(RuntimeError, 'renderer_admission_ancestry'):
                    m.renderer_admission_ancestry(cyclic, images)
                raw = (previous / 'record.json').read_bytes()
                invalid = dict(previous_record, phase='prepared')
                invalid.pop('_recordSha')
                (previous / 'record.json').write_bytes(m.json_bytes(invalid))
                targets = self.facts(m.renderer_targets(self.policy).values())
                with self.assertRaisesRegex(RuntimeError, 'renderer_admission_ancestry'):
                    m.renderer_admission_ancestry(record, images)
                self.assertEqual(self.facts(targets), targets)
                (previous / 'record.json').write_bytes(raw)
                m.renderer_admission_ancestry(record, images)
            if depth == 15:
                current = json.loads(self.after['manifest'])
                self.assertEqual(m.renderer_overlay_lifecycle(current),
                                 m.digest_bytes(self.f.native.before['lifecycle']))
                with self.assertRaisesRegex(RuntimeError, 'renderer_lifecycle_depth'):
                    m.renderer_overlay_lifecycle(current, max_generations=15)
            if depth == 16:
                record, images = m.renderer_read(self.tx)
                m.renderer_admission_ancestry(record, images)
                # The lower-level ancestry bound does not bypass the enclosing
                # full-overlay limit: one native plus sixteen admitted is 17.
                with self.assertRaisesRegex(RuntimeError, 'renderer_lifecycle_depth'):
                    m.renderer_overlay_lifecycle(json.loads(self.after['manifest']))
        self.prepare_admitted_depth_generation(17)
        record, images = m.renderer_read(self.tx)
        snapshot = self.facts([*m.renderer_targets(self.policy).values(),
                               *(path for directory in (*retained, self.tx)
                                 for path in directory.rglob('*') if path.is_file())])
        with self.assertRaisesRegex(RuntimeError, 'renderer_admission_depth'):
            m.renderer_admission_ancestry(record, images)
        with self.assertRaisesRegex(RuntimeError, 'renderer_admission_depth'):
            m.renderer_run(self.tx, 'after')
        self.assertEqual(self.facts(snapshot), snapshot)
        self.assertIsNone(m._RENDERER_LAUNCH_POLICY)

    def test_launch_policy_rejects_runtime_changes_and_wrong_predecessors(self):
        for name in ('d3d11.dll', 'dxgi.dll', 'winemac.so', 'winemetal.so', 'ntdll.so'):
            policy = copy.deepcopy(self.policy)
            policy['candidateFiles'][name] = 'f' * 64
            with self.subTest(name=name), self.assertRaisesRegex(RuntimeError, 'renderer_launch_only_scope'):
                m.renderer_policy_validate(policy)
        for key in ('launchHelper', 'launchHub', 'launchCs2'):
            policy = copy.deepcopy(self.policy)
            policy['launchAdmission'][key] = 'f' * 64
            with self.subTest(key=key), self.assertRaisesRegex(RuntimeError, 'renderer_launch_preimage'):
                m.renderer_after(self.before, self.modes, self.files, policy, self.commit, self.rows)
        policy = copy.deepcopy(self.policy)
        policy['launchAdmission']['foreign'] = 'f' * 64
        with self.assertRaisesRegex(RuntimeError, 'renderer_launch_only_scope'):
            m.renderer_policy_validate(policy)
        policy = copy.deepcopy(self.policy)
        policy['previousManifestSha256'] = 'f' * 64
        with self.assertRaises(RuntimeError):
            m.renderer_after(self.before, self.modes, self.files, policy, self.commit, self.rows)

    def test_wrong_launch_modes_receipts_and_prefix_refuse(self):
        for name in m.RENDERER_LAUNCH_MODES:
            modes = dict(self.modes, **{name: 0o700})
            with self.subTest(mode=name), self.assertRaisesRegex(RuntimeError, 'renderer_launch_.*preimage'):
                m.renderer_after(self.before, modes, self.files, self.policy, self.commit, self.rows)
        for name, field in (('launchHubReceipt', 'owner'), ('launchHubReceipt', 'launcherSha256'),
                            ('launchHubReceipt', 'launchAdmissionSha256'), ('launchCs2Receipt', 'owner'),
                            ('launchCs2Receipt', 'launcherSha256')):
            receipt = json.loads(self.before[name])
            receipt[field] = 'foreign'
            before = dict(self.before, **{name: m.json_bytes(receipt)})
            with self.subTest(receipt=name, field=field), self.assertRaisesRegex(RuntimeError, 'renderer_launch_receipt_preimage'):
                m.renderer_after(before, self.modes, self.files, self.policy, self.commit, self.rows)
        for name in ('prefix', 'dxgiPrefix'):
            path = m.renderer_targets(self.policy)[name]
            raw = path.read_bytes()
            path.write_bytes(b'foreign prefix bytes')
            snapshot = self.capture(m.renderer_targets(self.policy))
            with self.subTest(prefix=name), self.assertRaises(RuntimeError):
                m.renderer_run(self.tx, 'after')
            self.assertEqual(self.capture(m.renderer_targets(self.policy)), snapshot)
            path.write_bytes(raw)

    def test_candidate_source_and_launch_provenance_are_checked(self):
        source = self.tx / 'source'
        for name in m.RENDERER_LAUNCH_FILES.values():
            path = source / name
            raw = path.read_bytes()
            path.write_bytes(b'foreign candidate')
            with self.subTest(name=name), self.assertRaisesRegex(RuntimeError, 'renderer_candidate_pin'):
                m.renderer_candidate(source, self.policy)
            path.write_bytes(raw)
        provenance = json.loads(self.files['provenance.json'])
        provenance['launchAdmissionFiles']['games-play'] = 'f' * 64
        raw = m.json_bytes(provenance)
        (source / 'provenance.json').write_bytes(raw)
        policy = copy.deepcopy(self.policy)
        policy['candidateFiles']['provenance.json'] = m.digest_bytes(raw)
        with self.assertRaisesRegex(RuntimeError, 'renderer_launch_provenance'):
            m.renderer_candidate(source, policy)

    def test_scoped_helper_pins_restore_after_error_and_reject_third_helper(self):
        self.assertEqual(m.renderer_launch_helper_pins(), (m.ADMISSION_SHA,))
        old_pin = self.policy['launchAdmission']['launchHelper']
        self.assertNotEqual(old_pin, m.ADMISSION_SHA)
        with self.assertRaisesRegex(RuntimeError, 'injected'):
            with m.renderer_launch_scope(self.policy):
                self.assertEqual(m.renderer_launch_helper_pins(), (old_pin, m.ADMISSION_SHA))
                m.renderer_admission_base_check(self.policy['nativeAdmissionBase'])
                raise RuntimeError('injected')
        self.assertIsNone(m._RENDERER_LAUNCH_POLICY)
        self.assertEqual(m.renderer_launch_helper_pins(), (m.ADMISSION_SHA,))
        with self.assertRaisesRegex(RuntimeError, 'native_admission_helper_drift'):
            m.renderer_admission_base_check(self.policy['nativeAdmissionBase'])
        helper = m.renderer_launch_targets()['launchHelper']
        helper.write_bytes(b'foreign third helper')
        with m.renderer_launch_scope(self.policy):
            with self.assertRaisesRegex(RuntimeError, 'native_admission_helper_drift'):
                m.renderer_admission_base_check(self.policy['nativeAdmissionBase'])

    def test_operation_error_restores_scope_and_foreign_nested_policy_is_refused(self):
        def source_failure(*args, **kwargs):
            self.assertEqual(m._RENDERER_LAUNCH_POLICY, self.policy)
            raise RuntimeError('source generation changed')

        with patch.object(m, 'renderer_policy', return_value=self.policy), \
                patch.object(m, 'source_gate', side_effect=source_failure):
            with self.assertRaisesRegex(RuntimeError, 'source generation changed'):
                m.renderer_operation(self.commit, 'upgrade', self.tx / 'source')
        self.assertIsNone(m._RENDERER_LAUNCH_POLICY)
        other = copy.deepcopy(self.policy)
        other['launchAdmission']['launchHub'] = 'f' * 64
        with m.renderer_launch_scope(self.policy):
            with self.assertRaisesRegex(RuntimeError, 'renderer_launch_scope_conflict'):
                with m.renderer_launch_scope(other):
                    self.fail('conflicting source policy was admitted')
            self.assertEqual(m._RENDERER_LAUNCH_POLICY, self.policy)
        self.assertIsNone(m._RENDERER_LAUNCH_POLICY)

    def test_real_lock_order_is_cs2_then_shared_games_and_scope_is_released(self):
        cs2 = self.f.home / 'Library/Application Support/CS2 Standalone/.launcher.lock'
        self.put(cs2, b'')
        locks = []
        actual_flock = m.fcntl.flock

        def flock(fd, operation):
            if operation & m.fcntl.LOCK_EX:
                facts = m.os.fstat(fd if isinstance(fd, int) else fd.fileno())
                names = (cs2, self.f.home / 'AIDev/state/games-hub.lock')
                locks.append(next(path.name for path in names if path.exists()
                                  and path.stat().st_ino == facts.st_ino))
            return actual_flock(fd, operation)

        for command in ('upgrade-renderer', 'recover-renderer', 'rollback-renderer', 'return-renderer'):
            locks.clear()
            args = ['ds3-runtime', command, self.commit]
            if command == 'upgrade-renderer':
                args.append(str(self.tx / 'source'))
            with self.subTest(command=command), patch.object(m.sys, 'argv', args), \
                    patch.object(m, 'renderer_policy', return_value=self.policy), \
                    patch.object(m.fcntl, 'flock', side_effect=flock), \
                    patch.object(m, 'renderer_operation', side_effect=RuntimeError('boundary reached')):
                with self.assertRaisesRegex(RuntimeError, 'boundary reached'):
                    m.main()
            self.assertEqual(locks, ['.launcher.lock', 'games-hub.lock'])
            self.assertIsNone(m._RENDERER_CS2_GUARD)
        shared = self.f.home / 'AIDev/state/games-hub.lock'

        def change_shared(*args, **kwargs):
            m._RENDERER_CS2_GUARD()
            replacement = shared.with_name('replacement')
            self.put(replacement, b'')
            replacement.replace(shared)
            m._RENDERER_CS2_GUARD()

        with patch.object(m.sys, 'argv', ['ds3-runtime', 'recover-renderer', self.commit]), \
                patch.object(m, 'renderer_policy', return_value=self.policy), \
                patch.object(m, 'renderer_operation', side_effect=change_shared):
            with self.assertRaisesRegex(RuntimeError, 'renderer_shared_lock_changed'):
                m.main()
        self.assertIsNone(m._RENDERER_CS2_GUARD)
        with self.assertRaisesRegex(RuntimeError, 'renderer_launch_lock_changed'):
            with m.renderer_cs2_locked():
                replacement = cs2.with_name('replacement')
                self.put(replacement, b'')
                replacement.replace(cs2)
                m._RENDERER_CS2_GUARD()
        self.assertIsNone(m._RENDERER_CS2_GUARD)

    def prepare_schema6_after_launch(self):
        m.renderer_run(self.tx, 'after')
        self.before = self.capture(m.renderer_targets({'schema': 6}))
        self.modes = {name: path.stat().st_mode & 0o777
                      for name, path in m.renderer_targets({'schema': 6}).items()}
        for name in m.RENDERER_LAUNCH_FILES.values():
            self.files.pop(name)
        self.files['dxgi.dll'] = b'paired DXGI successor after launch admission'
        self.refresh_provenance()
        current = json.loads(self.before['manifest'])
        self.policy = dict(self.policy, schema=6,
                           previousRendererSha256=m.renderer_hash(current),
                           previousDxgiSha256=m.renderer_dxgi_hash(current),
                           previousNativeRuntimeHashes=m.renderer_native_hashes(current),
                           previousManifestSha256=m.digest_bytes(self.before['manifest']),
                           previousEffectiveLifecycleSha256=m.digest_bytes(self.before['lifecycle']),
                           candidateFiles=self.hashes(self.files))
        del self.policy['launchAdmission']
        self.commit = '9' * 40
        self.rows = m.renderer_rows()
        self.after = m.renderer_after(self.before, self.modes, self.files,
                                      self.policy, self.commit, self.rows)
        self.tx = m.renderer_transaction(self.commit, admission=True)
        self.make_transaction()

    def ordinary_endpoint(self, images, fixed):
        self.assert_images(images)
        current = json.loads(images['manifest'])
        m.renderer_verify_binding(current)
        self.assertEqual(m.native_admission_lifecycle(current),
                         m.digest_bytes(images['lifecycle']))
        self.assertEqual(m.renderer_overlay_lifecycle(current),
                         m.digest_bytes(self.f.native.before['lifecycle']))
        self.assertEqual(json.loads(images['receipt'])['runtimeTreeSha256'],
                         m.code_tree(self.f.root / 'runtime'))
        self.assertEqual(self.facts(fixed), fixed)
        self.assertIsNone(m._RENDERER_LAUNCH_POLICY)

    def test_schema6_after_launch_roundtrip_preserves_latest_fixed_five_and_histories(self):
        launch_tx = self.tx
        self.prepare_schema6_after_launch()
        self.assertEqual(len(m.renderer_targets(self.policy)), 13)
        self.assertEqual(self.policy['schema'], 6)
        fixed_paths = list(m.renderer_launch_targets().values())
        fixed_paths.extend(path for path in launch_tx.rglob('*') if path.is_file())
        fixed_paths.extend(m.renderer_targets(self.policy)[name] for name in
                           ('nativeWinemac', 'nativeMetal', 'nativeNtdll', 'nativeApproval',
                            'lifecycle', 'runtime', 'prefix'))
        fixed = self.facts(fixed_paths)
        self.assertNotEqual(self.before['dxgiRuntime'], self.after['dxgiRuntime'])
        for side in ('after', 'before', 'after'):
            self.assertTrue(m.renderer_run(self.tx, side))
            self.ordinary_endpoint(self.after if side == 'after' else self.before, fixed)
            self.assertFalse(m.renderer_run(self.tx, side))
        self.assertEqual(self.after['dxgiRuntime'], self.after['dxgiPrefix'])

    def test_schema6_after_launch_recovers_both_dxgi_publications_in_both_directions(self):
        launch_tx = self.tx
        self.prepare_schema6_after_launch()
        fixed = self.facts([*m.renderer_launch_targets().values(),
                            *(path for path in launch_tx.rglob('*') if path.is_file())])
        for direction in ('after', 'before'):
            for name in ('dxgiRuntime', 'dxgiPrefix'):
                for boundary in ('intent:', 'published:'):
                    with self.subTest(direction=direction, name=name, boundary=boundary):
                        m.renderer_run(self.tx, 'before' if direction == 'after' else 'after')
                        fired = []

                        def fault(label):
                            if label == boundary + name and not fired:
                                fired.append(True)
                                raise SystemExit(77)

                        with patch.object(m, 'renderer_checkpoint', side_effect=fault):
                            with self.assertRaises(SystemExit):
                                m.renderer_run(self.tx, direction)
                        self.assertTrue(fired)
                        self.assertIsNone(m._RENDERER_LAUNCH_POLICY)
                        m.renderer_run(self.tx, direction, recover=True)
                        self.ordinary_endpoint(self.after if direction == 'after' else self.before, fixed)

    def test_schema6_after_launch_normal_verifiers_refuse_each_foreign_fixed_five(self):
        self.prepare_schema6_after_launch()
        m.renderer_run(self.tx, 'after')
        current = json.loads(self.after['manifest'])
        targets = dict(m.renderer_targets(self.policy), **m.renderer_launch_targets())
        for name, path in m.renderer_launch_targets().items():
            raw = path.read_bytes()
            path.write_bytes(b'foreign retained launch endpoint after DXGI successor')
            snapshot = self.facts(targets.values())
            for verifier in (m.renderer_verify_binding, m.native_admission_lifecycle):
                with self.subTest(name=name, verifier=verifier.__name__), self.assertRaises(RuntimeError):
                    verifier(current)
                self.assertEqual(self.facts(snapshot), snapshot)
                self.assertIsNone(m._RENDERER_LAUNCH_POLICY)
            path.write_bytes(raw)
            m.renderer_verify_binding(current)
            self.assertEqual(m.native_admission_lifecycle(current),
                             m.digest_bytes(self.files['ds3-runtime']))

    def test_schema7_after_dxgi_after_launch_roundtrip_retains_paired_dxgi_and_launch_closure(self):
        launch_tx = self.tx
        self.prepare_schema6_after_launch()
        m.renderer_run(self.tx, 'after')
        dxgi_tx = self.tx
        fixed_paths = list(m.renderer_launch_targets().values())
        fixed_paths.extend(path for directory in (launch_tx, dxgi_tx)
                           for path in directory.rglob('*') if path.is_file())
        fixed_paths.extend(m.renderer_targets(self.policy)[name]
                           for name in ('dxgiRuntime', 'dxgiPrefix', 'nativeMetal', 'nativeNtdll'))
        fixed = self.facts(fixed_paths)
        self.prepare_schema7()
        self.assertEqual(len(m.renderer_targets(self.policy)), 13)
        self.assertEqual(self.policy['schema'], 7)
        self.assertEqual(self.policy['previousDxgiSha256'], m.digest_bytes(self.files['dxgi.dll']))
        for side in ('after', 'before', 'after'):
            self.assertTrue(m.renderer_run(self.tx, side))
            self.ordinary_endpoint(self.after if side == 'after' else self.before, fixed)
            self.assertFalse(m.renderer_run(self.tx, side))
        snapshot = self.facts(dict(m.renderer_targets(self.policy), **m.renderer_launch_targets()).values())
        with self.assertRaises(RuntimeError):
            m.renderer_run(dxgi_tx, 'before')
        self.assertEqual(self.facts(snapshot), snapshot)

    def prepare_schema9_after_launch_dxgi_and_cursor(self):
        # Deliver the actual historical reader first, so rollback restores the
        # same code whose unchanged verifier is exercised below.
        shutil.rmtree(self.tx)
        self.files['ds3-runtime'] = self.pre_d3d_source
        self.put(self.f.control / 'bin/ds3-runtime', self.pre_d3d_source, 0o755)
        self.refresh_provenance()
        self.policy['candidateFiles'] = self.hashes(self.files)
        self.after = m.renderer_after(self.before, self.modes, self.files,
                                      self.policy, self.commit, self.rows)
        self.make_transaction()
        retained = [self.tx]
        self.prepare_schema6_after_launch()
        m.renderer_run(self.tx, 'after')
        retained.append(self.tx)
        self.prepare_schema7()
        m.renderer_run(self.tx, 'after')
        retained.append(self.tx)
        self.before = self.capture(m.renderer_targets({'schema': 9}))
        self.modes = {name: path.stat().st_mode & 0o777
                      for name, path in m.renderer_targets({'schema': 9}).items()}
        self.files['d3d11.dll'] = b'D3D allocation successor after cursor and launch admission'
        self.files['ds3-runtime'] = (SOURCE / 'bin/ds3-runtime').read_bytes()
        self.put(self.f.control / 'bin/ds3-runtime', self.files['ds3-runtime'], 0o755)
        self.refresh_provenance()
        current = json.loads(self.before['manifest'])
        self.policy = dict(self.policy, schema=9,
                           previousRendererSha256=m.renderer_hash(current),
                           previousDxgiSha256=m.renderer_dxgi_hash(current),
                           previousNativeRuntimeHashes=m.renderer_native_hashes(current),
                           previousManifestSha256=m.digest_bytes(self.before['manifest']),
                           previousEffectiveLifecycleSha256=m.digest_bytes(self.before['lifecycle']),
                           candidateFiles=self.hashes(self.files))
        self.commit = 'a' * 40
        self.rows = m.renderer_rows()
        self.after = m.renderer_after(self.before, self.modes, self.files,
                                      self.policy, self.commit, self.rows)
        self.tx = m.renderer_transaction(self.commit, d3d=True)
        self.make_transaction()
        paths = list(m.renderer_launch_targets().values())
        paths.extend(m.renderer_targets(self.policy)[name] for name in
                     ('nativeWinemac', 'nativeMetal', 'nativeNtdll', 'nativeApproval',
                      'dxgiRuntime', 'dxgiPrefix'))
        paths.extend(path for directory in retained for path in directory.rglob('*') if path.is_file())
        return self.facts(paths)

    def test_schema9_d3d_scope_rejects_dxgi_native_predecessor_and_provenance_changes(self):
        self.prepare_schema9_after_launch_dxgi_and_cursor()
        m.renderer_policy_validate(self.policy)
        for name in ('dxgi.dll', 'winemac.so', 'winemetal.so', 'ntdll.so'):
            policy = copy.deepcopy(self.policy)
            policy['candidateFiles'][name] = 'f' * 64
            with self.subTest(name=name), self.assertRaisesRegex(RuntimeError, 'renderer_d3d_only_scope'):
                m.renderer_policy_validate(policy)
        for key in ('previousRendererSha256', 'previousManifestSha256', 'previousEffectiveLifecycleSha256'):
            policy = dict(self.policy, **{key: 'f' * 64})
            with self.subTest(predecessor=key), self.assertRaises(RuntimeError):
                m.renderer_after(self.before, self.modes, self.files, policy, self.commit, self.rows)
        provenance = json.loads(self.files['provenance.json'])
        provenance['d3d11Sha256'] = 'f' * 64
        raw = m.json_bytes(provenance)
        (self.tx / 'source/provenance.json').write_bytes(raw)
        policy = copy.deepcopy(self.policy)
        policy['candidateFiles']['provenance.json'] = m.digest_bytes(raw)
        with self.assertRaisesRegex(RuntimeError, 'renderer_provenance'):
            m.renderer_candidate(self.tx / 'source', policy)

    def test_schema9_after_launch_dxgi_cursor_roundtrip_and_old_reader_rollback(self):
        fixed = self.prepare_schema9_after_launch_dxgi_and_cursor()
        self.assertEqual(len(m.renderer_targets(self.policy)), 13)
        self.assertEqual(self.tx.name, '.d3d-renderer-' + self.commit)
        self.assertNotEqual(self.before['runtime'], self.after['runtime'])
        self.assertEqual(self.after['runtime'], self.after['prefix'])
        self.assertNotEqual(self.before['lifecycle'], self.after['lifecycle'])
        for side in ('after', 'before', 'after'):
            self.assertTrue(m.renderer_run(self.tx, side))
            self.ordinary_endpoint(self.after if side == 'after' else self.before, fixed)
            self.assertFalse(m.renderer_run(self.tx, side))
            old = self.old_reader(self.pre_d3d_source, 'unchanged_12e_d3d_rollback')
            if side == 'before':
                self.assertEqual((self.f.root / 'ds3-runtime').read_bytes(), self.pre_d3d_source)
                old.renderer_pending_guard()
                old.native_admission_pending_guard()
                current = json.loads(self.before['manifest'])
                old.renderer_verify_binding(current)
                self.assertEqual(old.native_admission_lifecycle(current),
                                 m.digest_bytes(self.before['lifecycle']))
                self.assertEqual(old.renderer_overlay_lifecycle(current),
                                 m.digest_bytes(self.f.native.before['lifecycle']))
            else:
                with self.assertRaises((RuntimeError, OSError)):
                    old.renderer_verify_binding(json.loads(self.after['manifest']))

    def test_schema9_changed_publications_recover_in_both_directions(self):
        fixed = self.prepare_schema9_after_launch_dxgi_and_cursor()
        names = [name for name in self.before if self.before[name] != self.after[name]]
        self.assertTrue({'runtime', 'prefix', 'manifest', 'receipt'} <= set(names))
        for direction in ('after', 'before'):
            for name in names:
                for boundary in ('intent:', 'published:'):
                    with self.subTest(direction=direction, name=name, boundary=boundary):
                        m.renderer_run(self.tx, 'before' if direction == 'after' else 'after')
                        fired = []

                        def fault(label):
                            if label == boundary + name and not fired:
                                fired.append(True)
                                raise SystemExit(77)

                        with patch.object(m, 'renderer_checkpoint', side_effect=fault):
                            with self.assertRaises(SystemExit):
                                m.renderer_run(self.tx, direction)
                        self.assertTrue(fired)
                        m.renderer_run(self.tx, direction, recover=True)
                        self.ordinary_endpoint(self.after if direction == 'after' else self.before, fixed)

    def test_schema9_normal_verifiers_refuse_each_foreign_retained_launch_endpoint(self):
        self.prepare_schema9_after_launch_dxgi_and_cursor()
        m.renderer_run(self.tx, 'after')
        current = json.loads(self.after['manifest'])
        targets = dict(m.renderer_targets(self.policy), **m.renderer_launch_targets())
        for name, path in m.renderer_launch_targets().items():
            raw = path.read_bytes()
            path.write_bytes(b'foreign retained launch endpoint after D3D successor')
            snapshot = self.facts(targets.values())
            for verifier in (m.renderer_verify_binding, m.native_admission_lifecycle):
                with self.subTest(name=name, verifier=verifier.__name__), self.assertRaises(RuntimeError):
                    verifier(current)
                self.assertEqual(self.facts(snapshot), snapshot)
                self.assertIsNone(m._RENDERER_LAUNCH_POLICY)
            path.write_bytes(raw)
            m.renderer_verify_binding(current)
            self.assertEqual(m.native_admission_lifecycle(current),
                             m.digest_bytes(self.files['ds3-runtime']))

    def test_schema9_pending_journal_and_duplicate_namespaces_refuse_without_target_writes(self):
        self.prepare_schema9_after_launch_dxgi_and_cursor()
        targets = self.facts(m.renderer_targets(self.policy).values())
        with self.assertRaisesRegex(RuntimeError, 'renderer_recovery_required'):
            m.renderer_pending_guard()
        self.assertEqual(self.facts(targets), targets)
        m.renderer_run(self.tx, 'after')
        current = json.loads(self.after['manifest'])
        raw = (self.tx / 'record.json').read_bytes()
        record = json.loads(raw)
        record.update(phase='running', intent='runtime')
        (self.tx / 'record.json').write_bytes(m.json_bytes(record))
        targets = self.facts(m.renderer_targets(self.policy).values())
        for verifier in (m.renderer_pending_guard,
                         lambda: m.renderer_verify_binding(current),
                         lambda: m.native_admission_lifecycle(current)):
            with self.assertRaisesRegex(RuntimeError, 'renderer_recovery_required'):
                verifier()
            self.assertEqual(self.facts(targets), targets)
        (self.tx / 'record.json').write_bytes(raw)
        for duplicate in (m.renderer_transaction(self.commit, admission=True),
                          m.renderer_transaction(self.commit, launch=True)):
            with self.subTest(namespace=duplicate.name):
                duplicate.mkdir(mode=0o700)
                for resolver in (m.renderer_binding_transaction, m.renderer_admission_record,
                                 m.renderer_verify_binding, m.native_admission_lifecycle):
                    with self.assertRaisesRegex(RuntimeError, 'renderer_proof_generation'):
                        resolver(current)
                    self.assertEqual(self.facts(targets), targets)
                duplicate.rmdir()
        m.renderer_verify_binding(current)

    def test_ordinary_schema7_after_schema9_retains_updated_d3d_and_helper_ancestry(self):
        self.prepare_schema9_after_launch_dxgi_and_cursor()
        m.renderer_run(self.tx, 'after')
        d3d_tx = self.tx
        paths = list(m.renderer_launch_targets().values())
        paths.extend(m.renderer_targets(self.policy)[name] for name in
                     ('runtime', 'prefix', 'nativeMetal', 'nativeNtdll', 'nativeApproval',
                      'dxgiRuntime', 'dxgiPrefix', 'lifecycle'))
        paths.extend(path for path in d3d_tx.rglob('*') if path.is_file())
        fixed = self.facts(paths)
        self.prepare_schema7(revision='b', driver=b'ordinary cursor successor after D3D allocation')
        self.assertEqual(self.files['d3d11.dll'], self.before['runtime'])
        for side in ('after', 'before', 'after'):
            self.assertTrue(m.renderer_run(self.tx, side))
            self.ordinary_endpoint(self.after if side == 'after' else self.before, fixed)
            self.assertFalse(m.renderer_run(self.tx, side))

    def prepare_schema7(self, revision='7', driver=b'next ordinary graphics driver'):
        m.renderer_run(self.tx, 'after')
        self.before = self.capture(m.renderer_targets({'schema': 7}))
        self.modes = {name: path.stat().st_mode & 0o777
                      for name, path in m.renderer_targets({'schema': 7}).items()}
        for name in m.RENDERER_LAUNCH_FILES.values():
            self.files.pop(name, None)
        self.files['winemac.so'] = driver
        self.refresh_provenance()
        current = json.loads(self.before['manifest'])
        self.policy = dict(self.policy, schema=7,
                           previousRendererSha256=m.renderer_hash(current),
                           previousDxgiSha256=m.renderer_dxgi_hash(current),
                           previousNativeRuntimeHashes=m.renderer_native_hashes(current),
                           previousManifestSha256=m.digest_bytes(self.before['manifest']),
                           previousEffectiveLifecycleSha256=m.digest_bytes(self.before['lifecycle']),
                           candidateFiles=self.hashes(self.files))
        self.policy.pop('launchAdmission', None)
        self.commit = revision * 40
        self.rows = m.renderer_rows()
        self.after = m.renderer_after(self.before, self.modes, self.files,
                                      self.policy, self.commit, self.rows)
        self.tx = m.renderer_transaction(self.commit, admission=True)
        self.make_transaction()

    def test_schema7_winemac_successor_roundtrip_preserves_new_helper(self):
        launch_tx = self.tx
        launch_after = dict(self.after)
        self.prepare_schema7()
        fixed = self.facts(m.renderer_launch_targets().values())
        for side in ('after', 'before', 'after'):
            self.assertTrue(m.renderer_run(self.tx, side))
            images = self.after if side == 'after' else self.before
            self.assert_images(images)
            self.assertFalse(m.renderer_run(self.tx, side))
            current = json.loads(images['manifest'])
            m.renderer_verify_binding(current)
            self.assertEqual(m.native_admission_lifecycle(current), m.digest_bytes(self.files['ds3-runtime']))
            self.assertEqual(self.facts(fixed), fixed)
        self.assertEqual(self.capture(m.renderer_launch_targets()),
                         {key: launch_after[key] for key in m.RENDERER_LAUNCH_MODES})
        self.assertTrue(launch_tx.exists())

    def test_installed_schema7_refuses_each_foreign_retained_launch_endpoint(self):
        self.prepare_schema7()
        m.renderer_run(self.tx, 'after')
        current = json.loads(self.after['manifest'])
        m.renderer_verify_binding(current)
        targets = dict(m.renderer_targets(self.policy), **m.renderer_launch_targets())
        for name, path in m.renderer_launch_targets().items():
            raw = path.read_bytes()
            path.write_bytes(b'foreign retained launch endpoint after schema7')
            snapshot = self.facts(targets.values())
            for verifier in (m.renderer_verify_binding, m.native_admission_lifecycle):
                with self.subTest(name=name, verifier=verifier.__name__), self.assertRaises(RuntimeError):
                    verifier(current)
                self.assertEqual(self.facts(snapshot), snapshot)
                self.assertIsNone(m._RENDERER_LAUNCH_POLICY)
            path.write_bytes(raw)
            m.renderer_verify_binding(current)
            self.assertEqual(m.native_admission_lifecycle(current),
                             m.digest_bytes(self.files['ds3-runtime']))

    def test_second_launch_generation_after_schema7_roundtrips_without_history_rewrite(self):
        self.prepare_schema7()
        m.renderer_run(self.tx, 'after')
        retained = self.facts(path for directory in (self.tx, m.renderer_transaction('6' * 40, launch=True))
                              for path in directory.rglob('*') if path.is_file())
        self.before = self.capture(m.renderer_targets({'schema': 8}))
        self.modes = {name: path.stat().st_mode & 0o777
                      for name, path in m.renderer_targets({'schema': 8}).items()}
        for key, name in m.RENDERER_LAUNCH_FILES.items():
            self.files[name] = self.before[key] + b'\n# second launch generation\n'
        self.files['ds3-runtime'] += b'\n# second launch lifecycle generation\n'
        self.refresh_provenance()
        current = json.loads(self.before['manifest'])
        self.policy = dict(self.policy, schema=8,
                           previousNativeRuntimeHashes=m.renderer_native_hashes(current),
                           previousManifestSha256=m.digest_bytes(self.before['manifest']),
                           previousEffectiveLifecycleSha256=m.digest_bytes(self.before['lifecycle']),
                           candidateFiles=self.hashes(self.files),
                           launchAdmission={key: m.digest_bytes(self.before[key])
                                            for key in m.RENDERER_LAUNCH_FILES})
        self.commit = '8' * 40
        self.rows = m.renderer_rows()
        self.after = m.renderer_after(self.before, self.modes, self.files,
                                      self.policy, self.commit, self.rows)
        self.tx = m.renderer_transaction(self.commit, launch=True)
        self.make_transaction()
        runtime = self.facts(path for path in (self.f.root / 'runtime').rglob('*') if path.is_file())
        with patch.object(m, 'ADMISSION_SHA', m.digest_bytes(self.files['game-launch-admission'])):
            for side in ('after', 'before', 'after'):
                self.assertTrue(m.renderer_run(self.tx, side))
                self.assert_images(self.after if side == 'after' else self.before)
                self.assertFalse(m.renderer_run(self.tx, side))
                if side == 'after':
                    current = json.loads(self.after['manifest'])
                    m.renderer_verify_binding(current)
                    self.assertEqual(m.native_admission_lifecycle(current),
                                     m.digest_bytes(self.files['ds3-runtime']))
                self.assertEqual(self.facts(retained), retained)
                self.assertEqual(self.facts(runtime), runtime)


if __name__ == '__main__':
    unittest.main()
