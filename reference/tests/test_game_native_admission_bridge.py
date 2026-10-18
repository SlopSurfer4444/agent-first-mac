"""Synthetic metadata evidence only; no publisher, observer or Wine execution."""
import copy
import os
from pathlib import Path
import tempfile
import unittest

from lib import game_native_admission_bridge as b


class BridgeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='native-admission-')
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name).resolve()
        self.root = self.home / 'Library/Application Support/Adapted Games DS3'
        self.root.mkdir(parents=True, mode=0o700)
        self.commit = '1' * 40
        self.helper = b'admitted launch admission helper'
        self.new_lifecycle = b'new lifecycle'
        native = {'d3d11Sha256': '2' * 64, 'provenanceSha256': '3' * 64,
                  'policySha256': '4' * 64, 'transactionCommit': '5' * 40,
                  'diagnosticCapable': True, 'nativeBorderlessCapable': True,
                  'traceProtocolVersion': 2, 'nativeRuntimeHashes': {rel: '6' * 64 for rel in b.NATIVE_PATHS},
                  'lifecycleSha256': b.sha(b'old lifecycle')}
        manifest = {'schema': 4, 'id': 'ds3-marshal-fix', 'owner': 'control-ds3-marshal-fix',
                    'rendererOverride': native, 'sourceCriticalHashes': {'opaque': '7' * 64},
                    'keep': {'nested': ['metadata', 1]}}
        manifest_raw = b.json_bytes(manifest)
        receipt = {'schema': 1, 'owner': 'control-ds3-marshal-fix',
                   'manifestSha256': b.sha(manifest_raw), 'lifecycleSha256': b.sha(b'old lifecycle'),
                   'runtimeTreeSha256': '8' * 64, 'sourceRuntimeTreeSha256': '9' * 64,
                   'appCommit': 'a' * 40, 'keep': ['owner state', {'futureKey': True}]}
        borderless = {'schema': 1, 'owner': 'control-ds3-marshal-fix', 'commit': 'b' * 40,
                      'manifestSha256': 'c' * 64, 'baseRuntimeTreeSha256': receipt['runtimeTreeSha256'],
                      'baseManifestSha256': b.sha(manifest_raw)}
        self.before = {'lifecycle': b'old lifecycle', 'manifest': manifest_raw,
                       'receipt': b.json_bytes(receipt), 'borderlessReceipt': b.json_bytes(borderless)}
        self.policy = {'schema': 1, 'id': 'ds3-native-admission-bridge', 'owner': b.OWNER,
                       'previousLifecycleSha256': b.sha(self.before['lifecycle']),
                       'lifecycleSha256': b.sha(self.new_lifecycle), 'admissionSha256': b.sha(self.helper),
                       'sourceManifestSha256': b.sha(manifest_raw)}
        self.after = b.derive(self.before, self.policy, self.commit, self.new_lifecycle)
        self.directory = self.root / ('.native-admission-' + self.commit)
        self.directory.mkdir(mode=0o700)
        self.record = {'schema': 1, 'owner': b.OWNER, 'commit': self.commit,
                       'policy': self.policy, 'phase': 'complete', 'direction': 'after',
                       'images': {key: {'before': b.sha(self.before[key]), 'after': b.sha(self.after[key]),
                                        'mode': b.MODES[key]} for key in b.TARGETS}}
        for side, images in (('before', self.before), ('after', self.after)):
            for key, raw in images.items():
                self.put(self.directory / (key + '.' + side), raw)
        self.save_record()
        for key, relative in b.TARGETS.items():
            self.put(self.root / relative, self.after[key], b.MODES[key])
        self.put(self.home / 'AIDev/bin/game-launch-admission', self.helper)

    def put(self, path, raw, mode=0o600):
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_bytes(raw)
        path.chmod(mode)

    def save_record(self):
        self.put(self.directory / 'record.json', b.json_bytes(self.record))

    def verify(self):
        return b.verify(self.root, b.decode(self.after['manifest']))

    def test_derive_preserves_original_native_and_owner_metadata(self):
        before = copy.deepcopy(self.before)
        old_manifest = b.decode(self.before['manifest'])
        new_manifest = b.decode(self.after['manifest'])
        descriptor = new_manifest.pop('launchAdmissionOverride')
        self.assertEqual(new_manifest, old_manifest)
        self.assertEqual(descriptor, {'acceptedCommit': self.commit,
                                     'policySha256': b.sha(b.json_bytes(self.policy)),
                                     'lifecycleSha256': b.sha(self.new_lifecycle),
                                     'admissionSha256': b.sha(self.helper)})
        receipt = b.decode(self.before['receipt'])
        receipt.update(manifestSha256=b.sha(self.after['manifest']), lifecycleSha256=b.sha(self.new_lifecycle))
        self.assertEqual(b.decode(self.after['receipt']), receipt)
        borderless = b.decode(self.before['borderlessReceipt'])
        borderless['baseManifestSha256'] = b.sha(self.after['manifest'])
        self.assertEqual(b.decode(self.after['borderlessReceipt']), borderless)
        self.assertEqual(before, self.before)

    def test_verify_accepts_exact_proof_and_does_not_write(self):
        files = {path: (path.read_bytes(), path.stat().st_mtime_ns)
                 for path in self.home.rglob('*') if path.is_file()}
        self.assertEqual(self.verify(), b.sha(self.new_lifecycle))
        b.pending_guard(self.root)
        self.assertEqual(files, {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in files})

    def test_each_mixed_endpoint_and_admission_helper_refused(self):
        for key, relative in b.TARGETS.items():
            with self.subTest(key=key):
                self.put(self.root / relative, self.before[key], b.MODES[key])
                with self.assertRaisesRegex(b.Blocked, 'endpoint_drift'):
                    self.verify()
                self.put(self.root / relative, self.after[key], b.MODES[key])
        self.put(self.home / 'AIDev/bin/game-launch-admission', b'foreign helper')
        with self.assertRaisesRegex(b.Blocked, 'helper_drift'):
            self.verify()

    def test_missing_or_forged_backup_refused(self):
        path = self.directory / 'receipt.before'
        path.unlink()
        with self.assertRaisesRegex(b.Blocked, 'namespace_inventory'):
            self.verify()
        self.put(path, b'forged')
        with self.assertRaisesRegex(b.Blocked, 'backup_drift'):
            self.verify()

    def test_jointly_forged_afterimage_and_hash_refused_by_derivation(self):
        receipt = b.decode(self.after['receipt'])
        receipt['runtimeTreeSha256'] = 'f' * 64
        raw = b.json_bytes(receipt)
        self.put(self.directory / 'receipt.after', raw)
        self.put(self.root / 'receipt.json', raw)
        self.record['images']['receipt']['after'] = b.sha(raw)
        self.save_record()
        with self.assertRaisesRegex(b.Blocked, 'derived_images'):
            self.verify()

    def test_rolled_back_history_settled_but_not_active_proof(self):
        self.record['direction'] = 'before'
        self.save_record()
        b.pending_guard(self.root)
        with self.assertRaisesRegex(b.Blocked, 'not_applied'):
            self.verify()

    def test_pending_and_malformed_history_headers_refused(self):
        for phase in ('prepared', 'running'):
            self.record['phase'] = phase
            self.save_record()
            with self.assertRaisesRegex(b.Blocked, 'recovery_required'):
                b.pending_guard(self.root)
        self.record['phase'] = 'complete'
        self.record['direction'] = 'unknown'
        self.save_record()
        with self.assertRaisesRegex(b.Blocked, 'record_schema'):
            b.pending_guard(self.root)

    def test_policy_descriptor_and_snapshot_scope_refused(self):
        manifest = b.decode(self.after['manifest'])
        manifest['launchAdmissionOverride']['policySha256'] = 'f' * 64
        with self.assertRaisesRegex(b.Blocked, 'policy_binding'):
            b.verify(self.root, manifest)
        self.record['images']['receipt']['mode'] = 0o644
        self.save_record()
        with self.assertRaisesRegex(b.Blocked, 'record_images'):
            self.verify()

    def test_duplicate_keys_in_record_and_before_metadata_refused(self):
        raw = b.json_bytes(self.record).replace(b'"schema": 1,', b'"schema": 1, "schema": 1,', 1)
        self.put(self.directory / 'record.json', raw)
        with self.assertRaisesRegex(b.Blocked, 'duplicate_json_key'):
            self.verify()
        before = dict(self.before)
        before['receipt'] = before['receipt'].replace(b'"schema": 1,', b'"schema": 1, "schema": 1,', 1)
        with self.assertRaisesRegex(b.Blocked, 'duplicate_json_key'):
            b.derive(before, self.policy, self.commit, self.new_lifecycle)

    def test_predecessor_pins_and_existing_successor_refused(self):
        for field in ('previousLifecycleSha256', 'lifecycleSha256', 'sourceManifestSha256'):
            with self.subTest(field=field):
                policy = dict(self.policy, **{field: 'f' * 64})
                with self.assertRaises(b.Blocked):
                    b.derive(self.before, policy, self.commit, self.new_lifecycle)
        before = dict(self.before, manifest=self.after['manifest'])
        policy = dict(self.policy, sourceManifestSha256=b.sha(before['manifest']))
        with self.assertRaisesRegex(b.Blocked, 'successor_already_present'):
            b.derive(before, policy, self.commit, self.new_lifecycle)
        for key, field in (('receipt', 'manifestSha256'), ('borderlessReceipt', 'baseManifestSha256')):
            value = b.decode(self.before[key])
            value[field] = 'f' * 64
            before = dict(self.before, **{key: b.json_bytes(value)})
            with self.assertRaisesRegex(b.Blocked, 'preimage'):
                b.derive(before, self.policy, self.commit, self.new_lifecycle)

    def test_unsafe_files_namespaces_and_parent_symlinks_refused(self):
        snapshot = self.directory / 'lifecycle.before'
        raw = snapshot.read_bytes()
        snapshot.chmod(0o644)
        with self.assertRaisesRegex(b.Blocked, 'unsafe_file'):
            self.verify()
        snapshot.chmod(0o600)
        self.directory.chmod(0o755)
        with self.assertRaisesRegex(b.Blocked, 'namespace_mode'):
            self.verify()
        self.directory.chmod(0o700)
        snapshot.unlink()
        target = self.home / 'same-bytes'
        self.put(target, raw)
        snapshot.symlink_to(target)
        with self.assertRaises(OSError):
            self.verify()
        snapshot.unlink()
        os.link(target, snapshot)
        with self.assertRaisesRegex(b.Blocked, 'unsafe_file'):
            self.verify()
        snapshot.unlink()
        self.put(snapshot, raw)
        linked = self.home / 'linked-library'
        linked.symlink_to(self.home / 'Library', target_is_directory=True)
        with self.assertRaises(OSError):
            b.verify(linked / 'Application Support/Adapted Games DS3', b.decode(self.after['manifest']))

    def test_namespace_foreign_files_and_malformed_names_refused(self):
        self.put(self.directory / 'unreviewed', b'foreign')
        with self.assertRaisesRegex(b.Blocked, 'namespace_inventory'):
            self.verify()
        (self.directory / 'unreviewed').unlink()
        (self.root / '.native-admission-invalid').mkdir(mode=0o700)
        with self.assertRaisesRegex(b.Blocked, 'history_name'):
            b.pending_guard(self.root)

    def test_exact_second_generation_preserves_first_proof_and_renderer(self):
        previous = copy.deepcopy(self.after)
        descriptor = b.decode(previous['manifest'])['launchAdmissionOverride']
        policy = dict(self.policy, schema=2, previousAdmission=descriptor,
                      previousLifecycleSha256=b.sha(previous['lifecycle']),
                      lifecycleSha256=b.sha(b'second lifecycle'), admissionSha256=b.sha(b'second helper'),
                      sourceManifestSha256=b.sha(previous['manifest']))
        commit = 'd' * 40
        after = b.derive(previous, policy, commit, b'second lifecycle')
        self.assertEqual(b.decode(after['manifest'])['rendererOverride'],
                         b.decode(previous['manifest'])['rendererOverride'])
        directory = b.proof_directory(self.root, commit, 2)
        directory.mkdir(mode=0o700)
        record = dict(self.record, commit=commit, policy=policy,
                      images={key: {'before': b.sha(previous[key]), 'after': b.sha(after[key]),
                                    'mode': b.MODES[key]} for key in b.TARGETS})
        for side, images in (('before', previous), ('after', after)):
            for key, raw in images.items(): self.put(directory / (key + '.' + side), raw)
        self.put(directory / 'record.json', b.json_bytes(record))
        first_proof = {p: p.read_bytes() for p in self.directory.iterdir()}
        for key, relative in b.TARGETS.items(): self.put(self.root / relative, after[key], b.MODES[key])
        self.put(self.home / 'AIDev/bin/game-launch-admission', b'second helper')
        self.assertEqual(b.verify(self.root, b.decode(after['manifest'])), b.sha(b'second lifecycle'))
        self.assertEqual(first_proof, {p: p.read_bytes() for p in self.directory.iterdir()})
        self.assertEqual(b.decode(after['receipt'])['runtimeTreeSha256'],
                         b.decode(previous['receipt'])['runtimeTreeSha256'])

    def test_second_generation_rejects_unknown_or_missing_predecessor(self):
        previous = copy.deepcopy(self.after)
        descriptor = b.decode(previous['manifest'])['launchAdmissionOverride']
        policy = dict(self.policy, schema=2, previousAdmission=descriptor,
                      previousLifecycleSha256=b.sha(previous['lifecycle']),
                      sourceManifestSha256=b.sha(previous['manifest']))
        for field in b.DESCRIPTOR_FIELDS:
            changed = dict(descriptor, **{field: 'f' * (40 if field == 'acceptedCommit' else 64)})
            with self.subTest(field=field), self.assertRaisesRegex(b.Blocked, 'previous_descriptor'):
                b.derive(previous, dict(policy, previousAdmission=changed), 'd' * 40, self.new_lifecycle)
        with self.assertRaisesRegex(b.Blocked, 'previous_descriptor'):
            b.derive(self.before, dict(policy, sourceManifestSha256=b.sha(self.before['manifest']),
                                      previousLifecycleSha256=b.sha(self.before['lifecycle'])), 'd' * 40, self.new_lifecycle)
        with self.assertRaisesRegex(b.Blocked, 'successor_commit'):
            b.derive(previous, policy, self.commit, self.new_lifecycle)


if __name__ == '__main__':
    unittest.main()
