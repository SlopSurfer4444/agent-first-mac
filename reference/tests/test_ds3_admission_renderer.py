"""Real-file renderer/admission ancestry with isolated HOME; no Wine or launch."""
import copy
import json
from pathlib import Path
import plistlib
import shutil
import struct
import subprocess
import types
import unittest
from unittest.mock import patch

import test_ds3_native_renderer as native
from lib import game_native_admission_bridge as bridge
from lib import game_native_admission_capability as capability
from lib import game_native_admission_transaction as admission_transaction


SOURCE = Path(__file__).resolve().parents[1]
OLD_COMMIT = 'f921b26585e1e57eb30732b6302cac69d7d6cac5'
m = native.m


class AdmissionRenderer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.old_source = subprocess.check_output(
            ['git', 'show', OLD_COMMIT + ':bin/ds3-runtime'], cwd=SOURCE)
        cls.admission_helper = subprocess.check_output(
            ['git', 'show', OLD_COMMIT + ':bin/game-launch-admission'], cwd=SOURCE)
        cls.bridge_source = subprocess.check_output(
            ['git', 'show', OLD_COMMIT + ':lib/game_native_admission_bridge.py'], cwd=SOURCE)

    def setUp(self):
        self.native = native.NativeRenderer('run')
        self.native.setUp()
        self.addCleanup(self.native.doCleanups)
        initial_root = self.native.root
        self.home = initial_root / 'fixture-home'
        self.root = self.home / 'Library/Application Support/Adapted Games DS3'
        self.root.mkdir(parents=True, mode=0o700)
        for path in list(initial_root.iterdir()):
            if path != self.home:
                shutil.move(str(path), self.root / path.name)
        self.native.root = self.root
        self.native.tx = self.root / self.native.tx.name
        self.patch('ROOT', self.root)
        self.patch('PREFIX', self.root / 'profiles/ds3')
        self.patch('HOME', self.home)
        self.patch('SOURCE', self.home / 'Library/Application Support/Adapted Games')
        # This fixture preserves OLD_COMMIT's Admission closure while testing
        # a graphics-only successor; its helper pin is historical too.
        self.patch('ADMISSION_SHA', m.digest_bytes(self.admission_helper))
        self.patch('inactive', lambda *args, **kwargs: None)
        self.patch('renderer_checkpoint', lambda _: None)
        self.control = self.home / 'control'
        self.put(self.control / 'bin/ds3-runtime', (SOURCE / 'bin/ds3-runtime').read_bytes(), 0o755)
        self.patch('CONTROL', self.control)
        self.bridge_path = self.home / 'AIDev/lib/game-launch-admission-v2/bridge.py'
        self.put(self.bridge_path, self.bridge_source)
        self.patch('ADMISSION_BRIDGE_PATH', self.bridge_path)
        self.put(self.home / 'AIDev/bin/game-launch-admission', self.admission_helper)
        self.other_admission_paths = [self.home / 'AIDev/bin/game-launch-admission']
        self.admission_other_before = {'admission.helper': (self.admission_helper, 0o600)}
        for component, launcher, receipt_path, owner in (
                ('Adapted Games', 'games-play', 'receipt.json', 'control-games-hub'),
                ('CS2 Standalone', 'cs2-play', 'runtime/.owner.json', 'control-cs2-standalone')):
            directory = self.home / 'Library/Application Support' / component
            raw = subprocess.check_output(['git', 'show', OLD_COMMIT + ':bin/' + launcher], cwd=SOURCE)
            self.put(directory / launcher, raw, 0o755)
            self.put(directory / receipt_path, self.canonical({'schema': 1, 'owner': owner,
                                                              'launcherSha256': m.digest_bytes(raw),
                                                              'keep': ['opaque owner state']}))
            self.other_admission_paths.extend((directory / launcher, directory / receipt_path))
            key = 'hub' if component == 'Adapted Games' else 'cs2'
            self.admission_other_before[key + '.launcher'] = (raw, 0o755)
            self.admission_other_before[key + '.receipt'] = ((directory / receipt_path).read_bytes(), 0o600)
        self.server = self.root / 'runtime/engine/bin/wineserver'
        self.put(self.server, b'frozen synthetic wineserver', 0o755)

        # Enrich the reusable native fixture with the production bridge's real
        # owner/schema preconditions, retaining opaque owner fields unchanged.
        before = dict(self.native.before)
        manifest = json.loads(before['manifest'])
        manifest.update(id='ds3-marshal-fix', owner='control-ds3-marshal-fix')
        before['manifest'] = m.json_bytes(manifest)
        receipt = json.loads(before['receipt'])
        receipt.update(schema=1, owner=manifest['owner'], lifecycleSha256=m.digest_bytes(before['lifecycle']),
                       manifestSha256=m.digest_bytes(before['manifest']), runtimeTreeSha256=m.code_tree(self.root / 'runtime'))
        before['receipt'] = m.json_bytes(receipt)
        borderless = json.loads(before['borderlessReceipt'])
        borderless.update(schema=1, owner=manifest['owner'], baseManifestSha256=m.digest_bytes(before['manifest']),
                          baseRuntimeTreeSha256=receipt['runtimeTreeSha256'])
        before['borderlessReceipt'] = m.json_bytes(borderless)
        self.native.before = before
        for name, path in m.renderer_targets(self.native.policy).items():
            self.put(path, before[name], self.native.modes[name])
        self.native.rows = m.renderer_rows()
        self.native.after = m.renderer_after(before, self.native.modes, self.native.files,
                                            self.native.policy, self.native.commit, self.native.rows)
        shutil.rmtree(self.native.tx)
        self.native.make_transaction()
        m.renderer_run(self.native.tx, 'after')
        self.native_transaction = self.native.tx
        native_state = {key: (self.root / rel).read_bytes() for key, rel in bridge.TARGETS.items()}

        self.first_admission, first_record = self.admit(native_state, b'first admitted lifecycle', '2' * 40)
        self.admitted, self.admission_record = self.admit(self.first_admission, self.old_source, '3' * 40, schema=2)
        self.admission_directory = bridge.proof_directory(self.root, '3' * 40, 2)
        self.admission_other_after = dict(self.admission_other_before)
        for key, index in (('hub', 2), ('cs2', 4)):
            receipt = json.loads(self.admission_other_before[key + '.receipt'][0])
            if key == 'hub':
                receipt.update(launchAdmissionSha256=m.digest_bytes(self.admission_helper), launchReliabilityCommit='3' * 40)
            else:
                receipt['launcherCommit'] = '3' * 40
            raw = self.canonical(receipt)
            self.admission_other_after[key + '.receipt'] = (raw, 0o600)
            self.put(self.other_admission_paths[index], raw)
        self.before = {name: path.read_bytes() for name, path in m.renderer_targets(self.native.policy).items()}
        self.modes = dict(self.native.modes)
        self.assertEqual(m.native_admission_lifecycle(json.loads(self.before['manifest'])), m.digest_bytes(self.old_source))

        self.intent = copy.deepcopy(json.loads((SOURCE / 'manifests/game-native-launch-admission.json').read_bytes()))
        self.intent.update(previousAdmissionOverride=json.loads(self.first_admission['manifest'])['launchAdmissionOverride'],
                           previousLifecycleSha256=m.digest_bytes(self.first_admission['lifecycle']),
                           previousManifestSha256=m.digest_bytes(self.first_admission['manifest']),
                           preserveRendererPolicySha256=json.loads(self.before['manifest'])['rendererOverride']['policySha256'],
                           preserveRuntimeHashes={rel: m.sha(self.root / 'runtime' / rel)
                                                  for rel in [m.RENDERER_REL, *(value[0] for value in m.RENDERER_NATIVE.values())]},
                           preserveServerSha256=m.sha(self.server))
        self.intent['sourceFiles']['bin/ds3-runtime'] = m.digest_bytes(self.old_source)
        self.intent['sourceFiles']['bin/game-launch-admission'] = m.digest_bytes(self.admission_helper)
        self.intent['sourceFiles']['lib/game_native_admission_bridge.py'] = m.digest_bytes(self.bridge_source)
        self.target = m.PREFIX / 'drive_c/Program Files (x86)/Steam/steamapps/common/DARK SOULS III/Game/DarkSoulsIII.exe'
        pe = bytearray(512)
        pe[:2] = b'MZ'
        struct.pack_into('<I', pe, 0x3c, 0x80)
        pe[0x80:0x84] = b'PE\0\0'
        struct.pack_into('<H', pe, 0x84, 0x8664)
        self.put(self.target, bytes(pe))
        app = self.root / 'native/Dark Souls III Native.app'
        app_files = {'Contents/MacOS/wine': b'frozen native app loader',
                     'Contents/Info.plist': plistlib.dumps({'CFBundleIdentifier': 'local.synthetic.ds3',
                                                          'CFBundleExecutable': 'wine', 'CFBundlePackageType': 'APPL'}),
                     'Contents/_CodeSignature/CodeResources': b'frozen signature resources'}
        self.intent['nativeRoute'].update(bundleIdentifier='local.synthetic.ds3', targetSha256=m.sha(self.target),
                                         bundleFiles={rel: {'sha256': m.digest_bytes(raw),
                                                           'mode': 0o755 if rel.endswith('/wine') else 0o644}
                                                      for rel, raw in app_files.items()})
        for rel, raw in app_files.items():
            self.put(app / rel, raw, self.intent['nativeRoute']['bundleFiles'][rel]['mode'])
        self.native_receipt = self.root / 'native/receipt.json'
        self.put(self.native_receipt, self.canonical({'schema': 1, 'owner': bridge.OWNER, 'namespace': 'native',
                                                     'acceptedCommit': '2' * 40, 'policySha256': 'a' * 64}))
        self.intent['assetPredecessor']['acceptedCommit'] = '2' * 40
        self.intent['assetPredecessor']['nativeReceiptSha256'] = m.sha(self.native_receipt)
        self.companion_files = []
        for relative, row in self.intent['companions'].items():
            path = self.home / 'AIDev/lib/game-launch-admission-v2' / relative
            if relative == 'bridge.py':
                raw = self.bridge_source
            else:
                raw = ('synthetic fixed companion ' + relative).encode()
            mode = 0o700 if relative in ('native-identity/probe', 'native-identity/prefix_probe') else 0o600
            self.put(path, raw, mode)
            row.update(sha256=m.digest_bytes(raw), mode=mode)
            self.companion_files.append(path)
        self.intent_hash = m.digest_bytes(self.canonical(self.intent))
        self.companion_receipt = self.home / 'AIDev/lib/game-launch-admission-v2/receipt.json'
        self.put(self.companion_receipt, self.canonical({'schema': 1, 'owner': bridge.OWNER, 'namespace': 'companions',
                                                        'acceptedCommit': '3' * 40, 'policySha256': self.intent_hash}))
        self.capability = capability.derive(self.intent, _test_home=self.home)
        self.capability_paths = capability.layout(self.home)[2]
        for key, path in self.capability_paths.items():
            self.put(path, self.capability[key])

        self.files = dict(self.native.files)
        self.files.update({'d3d11.dll': b'admitted renderer successor',
                           'winemac.so': b'admitted winemac successor',
                           'winemetal.so': b'admitted winemetal successor',
                           'ntdll.so': self.before['nativeNtdll'],
                           'ds3-runtime': (self.control / 'bin/ds3-runtime').read_bytes(),
                           'source.tar.gz': b'corresponding admitted renderer sources'})
        provenance = json.loads(self.files['provenance.json'])
        provenance.update(d3d11Sha256=m.digest_bytes(self.files['d3d11.dll']),
                          sourceArchiveSha256=m.digest_bytes(self.files['source.tar.gz']),
                          nativeRuntimeHashes={rel: m.digest_bytes(self.files[name]) for rel, name in m.RENDERER_NATIVE.values()},
                          lifecycleSha256=m.digest_bytes(self.files['ds3-runtime']))
        self.files['provenance.json'] = m.json_bytes(provenance)
        current = json.loads(self.before['manifest'])
        self.policy = dict(self.native.policy, schema=4, previousRendererSha256=m.renderer_hash(current),
                           previousNativeRuntimeHashes=m.renderer_native_hashes(current),
                           previousManifestSha256=m.digest_bytes(self.before['manifest']),
                           previousEffectiveLifecycleSha256=m.digest_bytes(self.before['lifecycle']),
                           candidateFiles={name: m.digest_bytes(raw) for name, raw in self.files.items()},
                           nativeAdmissionBase={'descriptor': current['launchAdmissionOverride'],
                                                'intent': self.intent, 'intentSha256': self.intent_hash,
                                                'images': {key: m.digest_bytes(raw) for key, raw in self.admitted.items()},
                                                'assetReceipts': {'companions': m.sha(self.companion_receipt),
                                                                  'native': m.sha(self.native_receipt)}})
        self.commit = '4' * 40
        self.rows = m.renderer_rows()
        self.after = m.renderer_after(self.before, self.modes, self.files, self.policy, self.commit, self.rows)
        self.assertEqual(self.after['nativeNtdll'], self.before['nativeNtdll'])
        self.tx = m.renderer_transaction(self.commit, native=True, admission=True)
        self.make_transaction()
        approval = json.loads(self.capability['approval'])
        self.five_native_targets = {Path(path): (Path(path).read_bytes(), Path(path).stat().st_mode & 0o777)
                                    for path in approval['files']}
        self.assertEqual(len(self.five_native_targets), 5)
        protected = [*self.other_admission_paths, *self.companion_files, self.native_receipt,
                     self.companion_receipt, *self.capability_paths.values(),
                     *self.admission_directory.iterdir(),
                     *bridge.proof_directory(self.root, '2' * 40).iterdir()]
        self.protected = {path: (path.read_bytes(), path.stat().st_mode & 0o777) for path in protected}

    @staticmethod
    def canonical(value):
        return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()

    @staticmethod
    def put(path, raw, mode=0o600):
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_bytes(raw)
        path.chmod(mode)

    def patch(self, key, value):
        patcher = patch.object(m, key, value)
        patcher.start()
        self.addCleanup(patcher.stop)

    def admit(self, before, lifecycle, commit, schema=1):
        policy = {'schema': schema, 'id': 'ds3-native-admission-bridge', 'owner': bridge.OWNER,
                  'previousLifecycleSha256': bridge.sha(before['lifecycle']), 'lifecycleSha256': bridge.sha(lifecycle),
                  'admissionSha256': bridge.sha(self.admission_helper), 'sourceManifestSha256': bridge.sha(before['manifest'])}
        if schema == 2:
            policy['previousAdmission'] = json.loads(before['manifest'])['launchAdmissionOverride']
        after = bridge.derive(before, policy, commit, lifecycle)
        directory = bridge.proof_directory(self.root, commit, schema)
        directory.mkdir(mode=0o700)
        record = {'schema': 1, 'owner': bridge.OWNER, 'commit': commit, 'policy': policy,
                  'phase': 'complete', 'direction': 'after',
                  'images': {key: {'before': bridge.sha(before[key]), 'after': bridge.sha(after[key]),
                                    'mode': bridge.MODES[key]} for key in bridge.TARGETS}}
        for side, images in (('before', before), ('after', after)):
            for key, raw in images.items():
                self.put(directory / (key + '.' + side), raw)
        self.put(directory / 'record.json', bridge.json_bytes(record))
        for key, rel in bridge.TARGETS.items():
            self.put(self.root / rel, after[key], bridge.MODES[key])
        return after, record

    def make_transaction(self):
        self.tx.mkdir(mode=0o700)
        (self.tx / 'source').mkdir(mode=0o700)
        for name, raw in self.files.items():
            self.put(self.tx / 'source' / name, raw)
        for side, images in (('before', self.before), ('after', self.after)):
            for name, raw in images.items():
                self.put(self.tx / (name + '.' + side), raw)
        record = {'schema': 1, 'commit': self.commit, 'policy': self.policy,
                  'images': {name: {'before': m.digest_bytes(self.before[name]), 'after': m.digest_bytes(self.after[name]),
                                    'mode': self.modes[name]} for name in self.before},
                  'treeRows': self.rows, 'phase': 'prepared', 'direction': 'after', 'intent': None}
        self.put(self.tx / 'record.json', m.json_bytes(record))

    def assert_images(self, images):
        for name, path in m.renderer_targets(self.policy).items():
            self.assertEqual(path.read_bytes(), images[name], name)
            self.assertEqual(path.stat().st_mode & 0o777, self.modes[name], name)

    def assert_native_unchanged(self):
        self.assertEqual(self.five_native_targets,
                         {path: (path.read_bytes(), path.stat().st_mode & 0o777) for path in self.five_native_targets})
        self.assertEqual(self.protected,
                         {path: (path.read_bytes(), path.stat().st_mode & 0o777) for path in self.protected})
        self.assertFalse((self.home / 'AIDev/state/game-launch-pending.json').exists())
        self.assertFalse(list((self.home / 'AIDev/state').glob('.game-launch-pending-*')))

    def test_apply_noop_rollback_return_preserves_admission_and_native_targets(self):
        self.assertTrue(self.tx.name.startswith('.admitted-renderer-'))
        self.assertEqual(m.renderer_targets(self.policy), {
            'nativeWinemac': self.root / 'runtime/engine/lib/wine/x86_64-unix/winemac.so',
            'nativeMetal': self.root / 'runtime/engine/lib/wine/x86_64-unix/winemetal.so',
            'nativeNtdll': self.root / 'runtime/engine/lib/wine/x86_64-unix/ntdll.so',
            'lifecycle': self.root / 'ds3-runtime',
            'runtime': self.root / 'runtime/engine/lib/wine/x86_64-windows/d3d11.dll',
            'prefix': self.root / 'profiles/ds3/drive_c/windows/system32/d3d11.dll',
            'manifest': self.root / 'manifest.json', 'borderless': self.root / 'borderless/manifest.json',
            'borderlessReceipt': self.root / 'borderless/receipt.json', 'receipt': self.root / 'receipt.json'})
        self.assertTrue(m.renderer_run(self.tx, 'after'))
        self.assert_images(self.after)
        self.assertFalse(m.renderer_run(self.tx, 'after'))
        current = json.loads(self.after['manifest'])
        self.assertEqual(current['launchAdmissionOverride'], self.policy['nativeAdmissionBase']['descriptor'])
        m.renderer_verify_binding(current)
        self.assertEqual(m.native_admission_lifecycle(current), m.digest_bytes(self.files['ds3-runtime']))
        self.assertEqual(m.renderer_overlay_lifecycle(current), m.digest_bytes(self.native.before['lifecycle']))
        self.assert_native_unchanged()
        self.assertTrue(m.renderer_run(self.tx, 'before'))
        self.assert_images(self.before)
        self.assertFalse(m.renderer_run(self.tx, 'before'))
        self.assertTrue(m.renderer_run(self.tx, 'after'))
        self.assert_native_unchanged()

    def test_each_changed_publication_recovers_in_both_directions(self):
        names = [name for name in m.renderer_targets(self.policy) if self.before[name] != self.after[name]]
        for direction in ('after', 'before'):
            for name in names:
                with self.subTest(direction=direction, name=name):
                    m.renderer_checkpoint = lambda _: None
                    m.renderer_run(self.tx, 'before' if direction == 'after' else 'after')
                    fired = []
                    def fault(label):
                        if label == 'published:' + name and not fired:
                            fired.append(True)
                            raise SystemExit(77)
                    m.renderer_checkpoint = fault
                    with self.assertRaises(SystemExit):
                        m.renderer_run(self.tx, direction)
                    self.assertTrue(fired)
                    m.renderer_checkpoint = lambda _: None
                    m.renderer_run(self.tx, direction, recover=True)
                    self.assert_images(self.after if direction == 'after' else self.before)
                    self.assert_native_unchanged()

    def test_original_f921_verifiers_accept_complete_rollback(self):
        m.renderer_run(self.tx, 'after')
        m.renderer_run(self.tx, 'before')
        old = types.ModuleType('original_f921_admitted_renderer')
        old.__file__ = str(self.root / 'ds3-runtime')
        exec(compile(self.old_source, old.__file__, 'exec'), old.__dict__)
        old.ROOT = self.root
        old.PREFIX = m.PREFIX
        old.HOME = self.home
        old.CONTROL = self.control
        old.ADMISSION_BRIDGE_PATH = self.bridge_path
        old.renderer_pending_guard()
        old.native_admission_pending_guard()
        current = json.loads(self.before['manifest'])
        self.assertEqual(old.native_admission_lifecycle(current), m.digest_bytes(self.old_source))
        old.renderer_verify_binding(current)
        self.assertEqual(old.renderer_overlay_lifecycle(current), m.digest_bytes(self.native.before['lifecycle']))
        self.assert_native_unchanged()

    def test_admission_proof_and_asset_receipt_tamper_refuse_before_target_writes(self):
        targets = {path: path.read_bytes() for path in m.renderer_targets(self.policy).values()}
        first = bridge.proof_directory(self.root, '2' * 40)
        ancestry = [directory / (key + '.' + side) for directory in (first, self.admission_directory)
                    for key in bridge.TARGETS for side in ('before', 'after')]
        ancestry.extend((first / 'record.json', self.admission_directory / 'record.json',
                         self.companion_receipt, self.native_receipt, *self.companion_files))
        for path in ancestry:
            with self.subTest(path=path):
                raw = path.read_bytes()
                path.write_bytes(b'foreign ancestry')
                with self.assertRaises((RuntimeError, ValueError)):
                    m.renderer_run(self.tx, 'after')
                self.assertEqual(targets, {path: path.read_bytes() for path in targets})
                path.write_bytes(raw)

    def test_native_transaction_rollback_refuses_after_admitted_graphics(self):
        m.renderer_run(self.tx, 'after')
        targets = {path: path.read_bytes() for path in m.renderer_targets(self.policy).values()}
        with self.assertRaises(RuntimeError):
            m.renderer_run(self.native_transaction, 'before')
        self.assertEqual(targets, {path: path.read_bytes() for path in targets})
        self.assert_native_unchanged()

    def test_valid_prepared_neighbor_blocks_recover_rollback_and_return(self):
        m.renderer_run(self.tx, 'after')
        current_transaction, current_commit, current_after = self.tx, self.commit, self.after
        try:
            self.commit = '5' * 40
            self.tx = m.renderer_transaction(self.commit, native=True, admission=True)
            self.after = m.renderer_after(self.before, self.modes, self.files, self.policy, self.commit, self.rows)
            self.make_transaction()
            neighbor = self.tx
        finally:
            self.tx, self.commit, self.after = current_transaction, current_commit, current_after
        record, _ = m.renderer_read(neighbor)
        self.assertEqual(record['phase'], 'prepared')
        self.assertEqual(record['commit'], '5' * 40)
        targets = {path: path.read_bytes() for path in m.renderer_targets(self.policy).values()}
        journal = (self.tx / 'record.json').read_bytes()
        neighbor_files = {path: path.read_bytes() for path in neighbor.rglob('*') if path.is_file()}
        for direction, recover in (('after', True), ('before', False), ('after', False)):
            with self.subTest(direction=direction, recover=recover):
                with self.assertRaisesRegex(RuntimeError, 'renderer_recovery_required'):
                    m.renderer_run(self.tx, direction, recover=recover)
                self.assertEqual(targets, {path: path.read_bytes() for path in targets})
                self.assertEqual((self.tx / 'record.json').read_bytes(), journal)
                self.assertEqual(neighbor_files, {path: path.read_bytes() for path in neighbor_files})
        self.assert_native_unchanged()

    def test_actual_admission_transaction_rollback_refuses_after_graphics(self):
        before = dict(self.admission_other_before)
        after = dict(self.admission_other_after)
        before.update({'ds3.' + key: (raw, bridge.MODES[key]) for key, raw in self.first_admission.items()})
        after.update({'ds3.' + key: (raw, bridge.MODES[key]) for key, raw in self.admitted.items()})
        targets, state, proof = admission_transaction._layout('3' * 40, self.home, 2)
        for key, path in targets.items():
            self.put(path, *before[key])
        shutil.rmtree(proof)
        policy = self.admission_record['policy']
        reviewed = {'schema': 1, 'provisionalCommit': '3' * 40, 'policySha256': self.intent_hash,
                    'ds3BridgePolicySha256': bridge.sha(bridge.json_bytes(policy)),
                    'capabilityBeforeSha256': {key: bridge.sha(raw) for key, raw in self.capability.items()},
                    'approvalCandidateSha256': bridge.sha(self.capability['approval']),
                    'routeCandidateSha256': bridge.sha(self.capability['routes']),
                    'targets': {key: {'beforeSha256': bridge.sha(before[key][0]),
                                      'afterSha256': bridge.sha(after[key][0]),
                                      'mode': admission_transaction.MODES[key]} for key in admission_transaction.KEYS}}
        raw = bridge.json_bytes(reviewed)
        transaction = admission_transaction.prepare('3' * 40, before, after, policy,
                                                     reviewed_plan=raw, expected_plan_sha256=bridge.sha(raw),
                                                     guard=lambda: True, _test_home=self.home)
        self.assertTrue(transaction.run('after')['changed'])
        self.assertEqual({key: path.read_bytes() for key, path in targets.items()},
                         {key: row[0] for key, row in after.items()})
        m.renderer_run(self.tx, 'after')
        observed = {path: path.read_bytes() for path in targets.values()}
        journal = (state / 'journal.json').read_bytes()
        proof_record = (proof / 'record.json').read_bytes()
        with self.assertRaisesRegex(RuntimeError, 'third_state|preimage'):
            transaction.run('before')
        self.assertEqual(observed, {path: path.read_bytes() for path in observed})
        self.assertEqual((state / 'journal.json').read_bytes(), journal)
        self.assertEqual((proof / 'record.json').read_bytes(), proof_record)
        self.assert_native_unchanged()

    def test_policy_requires_exact_admission_schema_and_before_pins(self):
        m.renderer_policy_validate(self.policy)
        for key in ('previousManifestSha256', 'previousEffectiveLifecycleSha256', 'nativeAdmissionBase'):
            policy = copy.deepcopy(self.policy)
            del policy[key]
            with self.subTest(missing=key), self.assertRaises(RuntimeError):
                m.renderer_policy_validate(policy)
        for key in ('previousManifestSha256', 'previousEffectiveLifecycleSha256'):
            policy = dict(self.policy, **{key: 'f' * 64})
            with self.subTest(pin=key), self.assertRaises(RuntimeError):
                m.renderer_after(self.before, self.modes, self.files, policy, self.commit, self.rows)
        for key in ('descriptor', 'intent', 'intentSha256', 'images', 'assetReceipts'):
            policy = copy.deepcopy(self.policy)
            del policy['nativeAdmissionBase'][key]
            with self.subTest(base=key), self.assertRaises(RuntimeError):
                m.renderer_policy_validate(policy)

    def test_admitted_before_tree_must_match_immutable_receipt(self):
        rows = copy.deepcopy(self.rows)
        row = next(row for row in rows if row[0] == 'native-preserved')
        row[2] = m.digest_bytes(b'unrelated replacement bytes')
        with self.assertRaisesRegex(RuntimeError, 'renderer_admission_before_tree'):
            m.renderer_after(self.before, self.modes, self.files, self.policy, self.commit, rows)
        before = dict(self.before)
        borderless = json.loads(before['borderless'])
        borderless['nativeBinding']['d3d11Sha256'] = 'f' * 64
        before['borderless'] = m.json_bytes(borderless)
        with self.assertRaisesRegex(RuntimeError, 'renderer_admission_before_metadata'):
            m.renderer_after(before, self.modes, self.files, self.policy, self.commit, self.rows)
        self.assert_images(self.before)
        self.assert_native_unchanged()

    def test_ntdll_delta_is_rejected_and_pending_record_blocks_before_writes(self):
        policy = copy.deepcopy(self.policy)
        policy['candidateFiles']['ntdll.so'] = m.digest_bytes(b'changed ntdll')
        with self.assertRaises(RuntimeError):
            m.renderer_policy_validate(policy)
        pending = self.home / 'AIDev/state/game-launch-pending.json'
        self.put(pending, m.json_bytes({'schema': 1, 'route': 'ds3', 'phase': 'prepared', 'children': [],
                                       'request': 'a' * 32, 'goal': 'game'}))
        targets = {path: path.read_bytes() for path in m.renderer_targets(self.policy).values()}
        self.assertIsNotNone(m.admission(self.home, 'ds3').record())
        with self.assertRaises(RuntimeError):
            m.renderer_run(self.tx, 'after')
        self.assertEqual(targets, {path: path.read_bytes() for path in targets})

    def test_new_pending_request_at_publication_boundary_refuses_target_write(self):
        pending = self.home / 'AIDev/state/game-launch-pending.json'
        targets = {path: path.read_bytes() for path in m.renderer_targets(self.policy).values()}
        fired = []
        def fault(label):
            if label == 'intent:nativeWinemac' and not fired:
                fired.append(True)
                self.put(pending, m.json_bytes({'schema': 1, 'route': 'ds3', 'phase': 'prepared',
                                               'children': [], 'request': 'a' * 32, 'goal': 'game'}))
        m.renderer_checkpoint = fault
        with self.assertRaisesRegex(RuntimeError, 'pending_launch_requires_recovery'):
            m.renderer_run(self.tx, 'after')
        self.assertTrue(fired)
        self.assertEqual(targets, {path: path.read_bytes() for path in targets})
        self.assertIsNotNone(m.admission(self.home, 'ds3').record())

    def test_other_admission_receipt_drift_at_publication_boundary_is_retained(self):
        receipt = self.other_admission_paths[2]
        targets = {path: path.read_bytes() for path in m.renderer_targets(self.policy).values()}
        fired = []
        def fault(label):
            if label == 'intent:nativeWinemac' and not fired:
                fired.append(True)
                receipt.write_bytes(b'owner receipt changed after preparation')
        m.renderer_checkpoint = fault
        with self.assertRaisesRegex(RuntimeError, 'renderer_admission_static_drift'):
            m.renderer_run(self.tx, 'after')
        self.assertTrue(fired)
        self.assertEqual(targets, {path: path.read_bytes() for path in targets})
        self.assertEqual(receipt.read_bytes(), b'owner receipt changed after preparation')

    def test_final_replace_guard_target_mutation_is_retained(self):
        target = m.renderer_targets(self.policy)['runtime']
        before = target.read_bytes()
        called = []
        def guard():
            called.append(True)
            target.write_bytes(b'foreign bytes from final guard')
        with self.assertRaisesRegex(RuntimeError, 'renderer_target_changed'):
            m.renderer_replace(target, self.files['d3d11.dll'], self.modes['runtime'],
                               m.digest_bytes(before), guard=guard)
        self.assertEqual(called, [True])
        self.assertEqual(target.read_bytes(), b'foreign bytes from final guard')
        self.assertEqual(m.renderer_targets(self.policy)['prefix'].read_bytes(), self.before['prefix'])

    def test_prefix_activity_at_publication_boundary_refuses_target_write(self):
        targets = {path: path.read_bytes() for path in m.renderer_targets(self.policy).values()}
        active = []
        def checkpoint(label):
            if label == 'intent:nativeWinemac':
                active.append(True)
        def inactive(*args, **kwargs):
            if active:
                raise RuntimeError('profile_active')
        m.renderer_checkpoint = checkpoint
        with patch.object(m, 'inactive', side_effect=inactive):
            with self.assertRaisesRegex(RuntimeError, 'profile_active'):
                m.renderer_run(self.tx, 'after')
        self.assertTrue(active)
        self.assertEqual(targets, {path: path.read_bytes() for path in targets})

    def test_actual_operation_prepares_applies_noop_rollback_and_return(self):
        candidate = self.home / 'candidate'
        shutil.copytree(self.tx / 'source', candidate)
        shutil.rmtree(self.tx)
        def installed(*, operational=False):
            self.assertIs(operational, False)
            return tuple(json.loads((self.root / name).read_bytes()) for name in ('manifest.json', 'receipt.json'))
        with patch.object(m, 'source_gate'), patch.object(m, 'window_repair_pending_guard'), \
             patch.object(m, 'inactive'), patch.object(m, 'renderer_policy', return_value=self.policy), \
             patch.object(m, 'verify_installed', side_effect=installed), patch.object(m, 'verify_borderless'):
            result = m.renderer_operation(self.commit, 'upgrade', candidate)
            self.assertTrue(result['changed'])
            self.assertFalse(result['gameStarted'])
            self.assertFalse(result['gameplayVerified'])
            self.assert_images(self.after)
            self.assertFalse(m.renderer_operation(self.commit, 'upgrade', candidate)['changed'])
            self.assertFalse(m.renderer_operation(self.commit, 'recover')['changed'])
            self.assertTrue(m.renderer_operation(self.commit, 'rollback')['changed'])
            self.assert_images(self.before)
            self.assertTrue(m.renderer_operation(self.commit, 'return')['changed'])
        self.assert_native_unchanged()


if __name__ == '__main__':
    unittest.main()
