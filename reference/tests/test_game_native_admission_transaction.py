"""Real filesystem transaction on synthetic private homes only; no game launch."""
import copy
import json
import os
from pathlib import Path
import shutil
import unittest
from unittest.mock import patch

from lib import game_native_admission_bridge as b
from lib import game_native_admission_transaction as t
import test_game_native_admission_bridge as fixture


class Transactions(unittest.TestCase):
    def setUp(self):
        self.fixture = fixture.BridgeTests('run')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        f = self.fixture
        self.home, self.root, self.commit = f.home, f.root, f.commit
        self.targets, self.state, self.proof = t._layout(self.commit, self.home)
        shutil.rmtree(self.proof)
        self.policy = f.policy
        self.before = {'admission.helper': (b'old admission helper', 0o600),
                       'hub.launcher': (b'old hub launcher', 0o755),
                       'cs2.launcher': (b'old cs2 launcher', 0o755)}
        self.after = {'admission.helper': (f.helper, 0o600), 'hub.launcher': (b'new hub launcher', 0o755),
                      'cs2.launcher': (b'new cs2 launcher', 0o755)}
        self.before.update({'ds3.' + key: (raw, b.MODES[key]) for key, raw in f.before.items()})
        self.after.update({'ds3.' + key: (raw, b.MODES[key]) for key, raw in f.after.items()})
        hub = {'owner': 'control-games-hub', 'schema': 1, 'launcherSha256': b.sha(self.before['hub.launcher'][0]),
               'keep': ['opaque owner metadata'], 'manifestSha256': 'd' * 64}
        cs2 = {'owner': 'control-cs2-standalone', 'schemaVersion': 1,
               'launcherSha256': b.sha(self.before['cs2.launcher'][0]), 'keep': {'runtime': 'preserved'}}
        enc = lambda value: (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
        self.before['hub.receipt'], self.before['cs2.receipt'] = (enc(hub), 0o600), (enc(cs2), 0o600)
        hub.update(launcherSha256=b.sha(self.after['hub.launcher'][0]), launchAdmissionSha256=self.policy['admissionSha256'],
                   launchReliabilityCommit=self.commit)
        cs2.update(launcherSha256=b.sha(self.after['cs2.launcher'][0]), launcherCommit=self.commit)
        self.after['hub.receipt'], self.after['cs2.receipt'] = (enc(hub), 0o600), (enc(cs2), 0o600)
        for key, path in self.targets.items():
            f.put(path, *self.before[key])
        self.state.parent.mkdir(parents=True, mode=0o700)
        self.sentinel = self.root / 'profiles/ds3/save.dat'
        f.put(self.sentinel, b'preserved save')
        self.guard_calls = 0
        self.reviewed = {'schema': 1, 'provisionalCommit': self.commit, 'policySha256': 'a' * 64,
                         'ds3BridgePolicySha256': b.sha(b.json_bytes(self.policy)),
                         'capabilityBeforeSha256': {'approval': None, 'routes': 'b' * 64},
                         'approvalCandidateSha256': 'c' * 64, 'routeCandidateSha256': 'd' * 64,
                         'targets': {key: {'beforeSha256': b.sha(self.before[key][0]),
                                           'afterSha256': b.sha(self.after[key][0]), 'mode': t.MODES[key]} for key in t.KEYS}}
        self.reviewed_raw = b.json_bytes(self.reviewed)
        self.pin = b.sha(self.reviewed_raw)

    def guard(self):
        self.guard_calls += 1
        return True

    def prepare(self, checkpoint=lambda _: None):
        return t.prepare(self.commit, self.before, self.after, self.policy, reviewed_plan=self.reviewed_raw, expected_plan_sha256=self.pin,
                         guard=self.guard, checkpoint=checkpoint, _test_home=self.home)

    def load(self, checkpoint=lambda _: None):
        return t.load(self.commit, self.pin, guard=self.guard, checkpoint=checkpoint, _test_home=self.home)

    def images(self):
        return {key: (path.read_bytes(), path.stat().st_mode & 0o777) for key, path in self.targets.items()}

    def fault(self, label):
        def checkpoint(actual):
            if actual == label:
                raise SystemExit(label)
        return checkpoint

    def test_prepare_apply_noop_rollback_return_preserves_exact_images(self):
        tx = self.prepare()
        self.assertEqual(self.images(), self.before)
        with self.assertRaisesRegex(b.Blocked, 'recovery_required'):
            b.pending_guard(self.root)
        self.assertTrue(tx.run('after')['changed'])
        self.assertEqual(self.images(), self.after)
        self.assertEqual(b.verify(self.root, b.decode(self.after['ds3.manifest'][0])), self.policy['lifecycleSha256'])
        self.assertFalse(self.load().run('after')['changed'])
        self.assertTrue(self.load().run('before')['changed'])
        self.assertEqual(self.images(), self.before)
        b.pending_guard(self.root)
        self.assertTrue(self.load().run('after')['changed'])
        self.assertEqual(self.images(), self.after)
        self.assertEqual(self.sentinel.read_bytes(), b'preserved save')
        self.assertGreater(self.guard_calls, 9)

    def test_namespace_partial_preparation_resumes_without_target_writes(self):
        stage = self.state.parent / ('.game-admission-stage-' + self.state.name.lstrip('.'))
        original = os.write
        fired = []
        def interrupted(fd, raw):
            if not fired:
                fired.append(True)
                original(fd, raw[:7])
                raise InterruptedError('fixture interruption')
            return original(fd, raw)
        with patch.object(t.os, 'write', interrupted):
            with self.assertRaises(InterruptedError):
                self.prepare()
        self.assertTrue(stage.exists())
        self.assertFalse(self.state.exists())
        self.assertEqual(self.images(), self.before)
        self.prepare()
        self.assertFalse(stage.exists())
        self.prepare()  # Complete preparation is idempotent as well.
        self.assertEqual(self.images(), self.before)

    def test_namespace_foreign_partial_is_preserved(self):
        stage = self.state.parent / ('.game-admission-stage-' + self.state.name.lstrip('.'))
        stage.mkdir(mode=0o700)
        self.fixture.put(stage / 'plan.json', b'foreign')
        with self.assertRaisesRegex(RuntimeError, 'stage_drift'):
            self.prepare()
        self.assertEqual((stage / 'plan.json').read_bytes(), b'foreign')
        self.assertEqual(set(stage.iterdir()), {stage / 'plan.json'})
        self.assertEqual(self.images(), self.before)

    def test_namespace_changed_prefix_before_open_is_not_appended(self):
        stage = self.state.parent / 'fixture-stage'
        stage.mkdir(mode=0o700)
        self.fixture.put(stage / 'image', b'abc')
        original = os.open
        def race(name, flags, *args, **kwargs):
            if name == 'image' and flags & os.O_APPEND:
                (stage / 'image').write_bytes(b'xyz')
            return original(name, flags, *args, **kwargs)
        with patch.object(t.os, 'open', race):
            with self.assertRaisesRegex(RuntimeError, 'stage_drift'):
                t._complete_namespace(stage, {'image': b'abcdef'})
        self.assertEqual((stage / 'image').read_bytes(), b'xyz')

    def test_each_intent_and_publication_recovers_both_directions(self):
        self.prepare()
        for direction in ('after', 'before'):
            labels = [kind + ':' + key + ':' + direction for key in t.KEYS for kind in ('intent', 'published')]
            for label in labels:
                with self.subTest(direction=direction, label=label):
                    start = 'before' if direction == 'after' else 'after'
                    self.load().run(start)
                    with self.assertRaises(SystemExit):
                        self.load(self.fault(label)).run(direction)
                    with self.assertRaisesRegex(b.Blocked, 'recovery_required'):
                        b.pending_guard(self.root)
                    # Recovery chooses the durable direction, ignoring the requested argument.
                    self.load().run(start, recover=True)
                    self.assertEqual(self.images(), self.after if direction == 'after' else self.before)
                    b.pending_guard(self.root)

    def test_each_global_and_proof_boundary_recovers_both_directions(self):
        self.prepare()
        for direction in ('after', 'before'):
            labels = ['journal:running:' + direction + ':proof-running', 'proof:running:' + direction,
                      'journal:running:' + direction + ':proof-complete', 'proof:complete:' + direction,
                      'journal:complete:' + direction + ':none']
            for label in labels:
                with self.subTest(label=label):
                    start = 'before' if direction == 'after' else 'after'
                    self.load().run(start)
                    with self.assertRaises(SystemExit):
                        self.load(self.fault(label)).run(direction)
                    self.load().run(start, recover=True)
                    self.assertEqual(self.images(), self.after if direction == 'after' else self.before)

    def test_global_before_direction_overrules_old_after_proof(self):
        self.prepare().run('after')
        with self.assertRaises(SystemExit):
            self.load(self.fault('journal:running:before:proof-running')).run('before')
        self.assertEqual(b.decode((self.proof / 'record.json').read_bytes())['direction'], 'after')
        self.assertEqual(b.decode((self.state / 'journal.json').read_bytes())['direction'], 'before')
        self.load().run('after', recover=True)
        self.assertEqual(self.images(), self.before)

    def test_missing_proof_after_global_prepare_resumes_without_target_mutation(self):
        with self.assertRaises(SystemExit):
            self.prepare(self.fault('prepared:global'))
        self.assertFalse(self.proof.exists())
        self.assertEqual(self.images(), self.before)
        self.prepare().run('after')
        self.assertEqual(self.images(), self.after)

    def test_preparation_partial_stage_blocks_without_target_mutation(self):
        stage = self.state.parent / ('.game-admission-stage-' + self.state.name.lstrip('.'))
        stage.mkdir(mode=0o700)
        self.fixture.put(stage / 'partial', b'owned incomplete stage')
        with self.assertRaisesRegex(b.Blocked, 'stage_inventory'):
            self.prepare()
        self.assertEqual(self.images(), self.before)
        self.assertEqual((stage / 'partial').read_bytes(), b'owned incomplete stage')

    def test_third_state_in_last_target_blocks_every_publication(self):
        self.prepare()
        path = self.targets[t.KEYS[-1]]
        self.fixture.put(path, b'owner changed ninth target')
        original = self.images()
        with self.assertRaisesRegex(b.Blocked, 'third_state'):
            self.load().run('after')
        self.assertEqual(self.images(), original)
        self.assertEqual(b.decode((self.state / 'journal.json').read_bytes())['phase'], 'prepared')

    def test_wrong_mode_symlink_and_hardlink_refused(self):
        self.prepare()
        path = self.targets['hub.launcher']
        raw = path.read_bytes()
        path.chmod(0o700)
        with self.assertRaisesRegex(b.Blocked, 'unsafe_file'):
            self.load()
        path.chmod(0o755)
        path.unlink()
        target = self.home / 'same-launcher'
        self.fixture.put(target, raw, 0o755)
        path.symlink_to(target)
        with self.assertRaises(OSError):
            self.load()
        path.unlink()
        os.link(target, path)
        with self.assertRaisesRegex(b.Blocked, 'unsafe_file'):
            self.load()

    def test_backup_proof_and_record_forgery_refused_without_writes(self):
        self.prepare()
        original = self.images()
        snapshot = self.state / 'cs2.receipt.before'
        raw = snapshot.read_bytes()
        self.fixture.put(snapshot, b'foreign')
        with self.assertRaisesRegex(b.Blocked, 'backup_drift'):
            self.load()
        self.fixture.put(snapshot, raw)
        proof = self.proof / 'manifest.after'
        raw = proof.read_bytes()
        self.fixture.put(proof, b'foreign')
        with self.assertRaisesRegex(b.Blocked, 'proof_backup_drift'):
            self.load()
        self.fixture.put(proof, raw)
        record = b.decode((self.proof / 'record.json').read_bytes())
        record['unreviewed'] = True
        self.fixture.put(self.proof / 'record.json', b.json_bytes(record))
        with self.assertRaisesRegex(b.Blocked, 'proof_binding'):
            self.load()
        self.assertEqual(self.images(), original)

    def test_stale_transaction_object_cannot_continue_after_direction_change(self):
        self.prepare().run('after')
        stale = self.load()
        self.load().run('before')
        with self.assertRaisesRegex(b.Blocked, 'stale_journal'):
            stale.run('after')
        self.assertEqual(self.images(), self.before)

    def test_guard_failure_prevents_preparation_and_publication(self):
        with self.assertRaisesRegex(b.Blocked, 'prerequisite_guard'):
            t.prepare(self.commit, self.before, self.after, self.policy, reviewed_plan=self.reviewed_raw, expected_plan_sha256=self.pin,
                      guard=lambda: False, _test_home=self.home)
        self.assertFalse(self.state.exists())
        tx = self.prepare()
        tx.guard = lambda: False
        with self.assertRaisesRegex(b.Blocked, 'prerequisite_guard'):
            tx.run('after')
        self.assertEqual(self.images(), self.before)

    def test_known_partial_target_stage_recovers_unknown_stage_refuses(self):
        self.prepare()
        key = t.KEYS[0]
        with self.assertRaises(SystemExit):
            self.load(self.fault('intent:' + key + ':after')).run('after')
        tx = self.load()
        stage = tx._target_stage(key)
        self.fixture.put(stage, self.after[key][0][:4], t.MODES[key])
        self.load().run('before', recover=True)
        self.assertEqual(self.images(), self.after)
        self.load().run('before')
        with self.assertRaises(SystemExit):
            self.load(self.fault('intent:' + key + ':after')).run('after')
        self.fixture.put(stage, b'foreign', t.MODES[key])
        original = self.images()
        with self.assertRaisesRegex(b.Blocked, 'stage_drift'):
            self.load()
        self.assertEqual(self.images(), original)

    def test_known_partial_metadata_stages_resume(self):
        self.prepare()
        # A cut during the initial global intent precedes every target write.
        begin = t.encode(t._journal(self.commit, self.pin, 'running', 'after', 'proof-running'))
        self.fixture.put(self.state / '.journal.next', begin[:40])
        self.load().run('after')
        self.load().run('before')
        with self.assertRaises(SystemExit):
            self.load(self.fault('journal:running:after:proof-running')).run('after')
        running = t.encode(t._proof(self.commit, self.policy, self.before, self.after, 'running', 'after'))
        self.fixture.put(self.proof / '.record.next', running[:100])
        self.load().run('before', recover=True)
        self.assertEqual(self.images(), self.after)
        self.load().run('before')
        with self.assertRaises(SystemExit):
            self.load(self.fault('proof:complete:after')).run('after')
        terminal = t.encode(t._journal(self.commit, self.pin, 'complete', 'after'))
        self.fixture.put(self.state / '.journal.next', terminal[:60])
        self.load().run('before', recover=True)
        self.assertEqual(self.images(), self.after)

    def test_foreign_metadata_stage_and_reviewed_report_drift_refused(self):
        self.prepare()
        original = self.images()
        stage = self.state / '.journal.next'
        self.fixture.put(stage, b'foreign intent')
        with self.assertRaisesRegex(b.Blocked, 'stage_drift'):
            self.load()
        self.assertEqual(self.images(), original)
        stage.unlink()
        reviewed = dict(self.reviewed, capabilityBeforeSha256={'approval': 'f' * 64, 'routes': None})
        self.fixture.put(self.state / 'reviewed-plan.json', b.json_bytes(reviewed))
        with self.assertRaisesRegex(b.Blocked, 'reviewed_plan_pin'):
            self.load()
        self.assertEqual(self.images(), original)

    def test_recovery_discards_unpublished_direction_stage_and_keeps_durable_side(self):
        self.prepare().run('after')
        next_direction = t.encode(t._journal(self.commit, self.pin, 'running', 'before', 'proof-running'))
        self.fixture.put(self.state / '.journal.next', next_direction[:100])
        result = self.load().run('before', recover=True)
        self.assertEqual(result['direction'], 'after')
        self.assertTrue(result['changed'])
        self.assertEqual(self.images(), self.after)
        self.assertFalse((self.state / '.journal.next').exists())

    def test_prepared_recovery_discards_unpublished_opposite_direction_stage(self):
        self.prepare()
        uncommitted = t.encode(t._journal(self.commit, self.pin, 'running', 'before', 'proof-running'))
        self.fixture.put(self.state / '.journal.next', uncommitted[:-2])
        result = self.load().run('before', recover=True)
        self.assertEqual(result['direction'], 'after')
        self.assertEqual(self.images(), self.after)
        self.assertFalse((self.state / '.journal.next').exists())

    def test_already_correct_target_reconciles_owned_stage_before_advancing_intent(self):
        self.prepare()
        key = t.KEYS[0]
        with self.assertRaises(SystemExit):
            self.load(self.fault('intent:' + key + ':after')).run('after')
        tx = self.load()
        stage = tx._target_stage(key)
        self.fixture.put(stage, self.after[key][0][:5], t.MODES[key])
        self.fixture.put(self.targets[key], *self.after[key])
        self.load().run('before', recover=True)
        self.assertEqual(self.images(), self.after)
        self.assertFalse(stage.exists())

    def test_plan_derivation_and_external_pin_are_required(self):
        after = copy.deepcopy(self.after)
        receipt = b.decode(after['ds3.receipt'][0])
        receipt['runtimeTreeSha256'] = 'f' * 64
        after['ds3.receipt'] = (b.json_bytes(receipt), 0o600)
        with self.assertRaisesRegex(b.Blocked, 'ds3_derivation'):
            t.plan(self.commit, self.before, after, self.policy)
        with self.assertRaisesRegex(b.Blocked, 'plan_pin'):
            t.prepare(self.commit, self.before, self.after, self.policy, reviewed_plan=self.reviewed_raw, expected_plan_sha256='f' * 64,
                      guard=self.guard, _test_home=self.home)
        self.assertFalse(self.state.exists())


if __name__ == '__main__':
    unittest.main()
