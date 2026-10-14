"""Real disposable DAGs for pinned successor admission; no machine probes."""
import copy
import hashlib
import json
import unittest
from unittest.mock import patch

from lib import current_source_admission as A
from lib import current_source_checkpoint as K
from lib import config_transition_source as S
from lib import config_transitions as F
import test_current_source_admission as fixture


class CheckpointTests(unittest.TestCase):
    # Reuse fixture setup/helpers, not the legacy suite's policy expectations.
    put = fixture.CurrentSourceTests.put
    commit = fixture.CurrentSourceTests.commit
    observe = fixture.CurrentSourceTests.observe
    admit = fixture.CurrentSourceTests.admit

    def setUp(self):
        fixture.CurrentSourceTests.setUp(self)
        self.pin = self.checkpoint
        self.binding = dict(commit=self.pin, tree=self.git._text('rev-parse', self.pin+'^{tree}'),
            receipt=A.MIGRATION_PATH, blob=F.blob_oid(json.dumps(self.record).encode()),
            reviewed=self.reviewed, reviewed_tree=self.record['reviewed_tree'],
            previous=self.base, previous_receipt=A.PREVIOUS_RECEIPT)
        self.updates = {A.MIGRATION_PATH: {'previous_commit': self.base,
            'paths': self.rules['bootstrap_paths'], 'after': self.rules},
            A.OWNER_FIRST_WAVE_PATH: {'previous_commit': self.pin,
            'paths': {'lib/engine.py'}, 'after': self.rules}}
        for p in (patch.object(A, 'CHECKPOINT_BINDING', self.binding),
                  patch.object(S, 'policy_updates', return_value=self.updates)):
            p.start(); self.addCleanup(p.stop)
        self.previous, self.previous_path = self.pin, A.MIGRATION_PATH
        self.accept('owner-first-harness-wave', {'lib/engine.py': b'wave engine'}, kind='policy')
        self.wave = self.previous

    def accept(self, ident, mutations=None, *, kind='configuration', overrides=None, extra=None,
               evidence_subject=None):
        base = self.git._tree(self.previous)
        for path, raw in (mutations or {}).items(): self.put(path, raw)
        evidence = {}
        if ident == 'owner-first-harness-wave':
            for role in ('validation', 'review', 'rollback'):
                path = F.PREFIX+ident+'/'+role+'.json'
                self.put(path, b'{}'); evidence[role] = [path]
        else:
            plan = F.PREFIX+ident+'/recovery-plan.txt'
            self.put(plan, b'Fixture source rollback plan; no machine changes.')
            subject = self.commit() if self.git._text('status', '--porcelain') else self.git._text('rev-parse', 'HEAD')
            subject = evidence_subject or subject
            subject_tree = self.git._text('rev-parse', subject+'^{tree}')
            checks = [{'id': 'fixture-check', 'command': ['fixture-only-observation'],
                       'observation': {'completed': True, 'exit_code': 0,
                                       'output_sha256': hashlib.sha256(b'fixture').hexdigest()}}]
            bundle = dict(schema=1, subject_commit=subject, subject_tree=subject_tree,
                validation=checks, review=dict(subject_commit=subject, subject_tree=subject_tree,
                    reviewer={'name': 'Independent Fixture Reviewer', 'email': 'review@example.invalid'},
                    decision='ACCEPT', unresolved_findings=[], checks=checks),
                recovery=dict(plan=plan, checks=checks))
            path = F.PREFIX+ident+'/observations.json'
            self.put(path, json.dumps(bundle).encode())
            evidence = {'bundle': path}
        reviewed = self.commit()
        record = dict(schema=1 if ident == 'owner-first-harness-wave' else 2, id=ident, kind=kind, status='ACCEPTED_CONFIGURATION',
            anchor_commit=self.base, previous_commit=self.previous, previous_acceptance=self.previous_path,
            reviewed_commit=reviewed, reviewed_tree=self.git._text('rev-parse', reviewed+'^{tree}'),
            changes=F.delta(base, self.git._tree(reviewed)), evidence=evidence,
            coordinator=self.rules['coordinator'])
        record.update(overrides or {})
        path = F.PREFIX+ident+'/acceptance.json'
        self.put(path, json.dumps(record).encode())
        for p, raw in (extra or {}).items(): self.put(p, raw)
        self.previous, self.previous_path = self.commit(), path
        return reviewed

    def proof(self):
        observation, head, current = self.observe()
        return A.checkpoint_admission(observation, head, current)

    def test_wave_and_two_aggregate_advances_without_policy_rebaseline(self):
        self.assertEqual(self.proof()['checkpoint'], self.wave)
        for ident in ('root-one', 'root-two'):
            self.put('darwin/payload.nix', ident.encode()); routine = self.commit()
            self.assertTrue(self.admit()['accepted'])
            self.assertTrue(A.admitted_revision(self.git, routine))
            with self.assertRaisesRegex(F.TransitionError, 'requires_independent_review'):
                A.reviewed_target(self.git, routine, self.git._tree(routine))
            reviewed = self.accept(ident)
            self.assertEqual(self.proof()['checkpoint'], self.previous)
            self.assertTrue(A.reviewed_target(self.git, self.previous, self.git._tree(self.previous)))
            self.assertTrue(A.admitted_revision(self.git, reviewed, accepted=False))
            with self.assertRaisesRegex(F.TransitionError, 'revision_not_accepted'):
                A.admitted_revision(self.git, reviewed)
        self.assertEqual(len(self.updates), 2)

    def test_routine_uses_pin_not_migration_replay(self):
        calls = []
        original = self.git._text
        def recording(*args):
            calls.append(args); return original(*args)
        with patch.object(self.git, '_text', side_effect=recording), \
             patch.object(F, 'verify', side_effect=AssertionError('historical replay')):
            self.assertTrue(self.admit()['accepted'])
        ranges = [arg for call in calls for arg in call if '..' in arg]
        self.assertTrue(ranges)
        self.assertTrue(all(item.startswith(self.pin+'..') for item in ranges))

    def restart_wave(self):
        # Only the disposable fixture checkout is reset; never canonical Git.
        self.git._read('reset', '--hard', self.pin)
        self.previous, self.previous_path = self.pin, A.MIGRATION_PATH
        self.updates[A.OWNER_FIRST_WAVE_PATH]['paths'] |= {'darwin/wine.nix', 'darwin/later.nix'}

    def assert_candidate_only(self, commit):
        self.assertTrue(A.admitted_revision(self.git, commit, accepted=False))
        with self.assertRaisesRegex(F.TransitionError, 'revision_not_accepted'):
            A.admitted_revision(self.git, commit, accepted=True)

    def test_later_policy_receipt_preserves_original_routine_prefix(self):
        self.restart_wave()
        self.put('darwin/wine.nix', b'independently admitted Wine payload'); wine = self.commit()
        self.assertTrue(A.admitted_revision(self.git, wine, accepted=True))
        self.put('darwin/later.nix', b'second routine payload'); routine = self.commit()
        reviewed = self.accept('owner-first-harness-wave', {'lib/engine.py': b'wave engine'}, kind='policy')
        self.assertEqual(self.proof()['checkpoint'], self.previous)
        for revision in (wine, routine):
            self.assertTrue(A.admitted_revision(self.git, revision, accepted=True))
        self.assert_candidate_only(reviewed)

    def test_policy_stage_restore_and_routine_descendant_never_regain_admission(self):
        self.restart_wave()
        self.put('darwin/wine.nix', b'routine'); wine = self.commit()
        self.put('lib/engine.py', b'protected staging'); staged = self.commit()
        self.put('lib/engine.py', b'reviewed migration engine'); restored = self.commit()
        self.put('darwin/later.nix', b'ordinary descendant'); descendant = self.commit()
        self.accept('owner-first-harness-wave', {'lib/engine.py': b'wave engine'}, kind='policy')
        self.assertTrue(self.admit()['accepted'])
        self.assertTrue(A.admitted_revision(self.git, wine, accepted=True))
        for revision in (staged, restored, descendant): self.assert_candidate_only(revision)
        self.put('darwin/later.nix', b'after genuine acceptance'); routine = self.commit()
        self.assertTrue(A.admitted_revision(self.git, routine, accepted=True))

    def test_evidence_stage_and_its_routine_tail_remain_candidates(self):
        self.restart_wave()
        self.put('darwin/wine.nix', b'routine'); wine = self.commit()
        self.put('evidence/policy-preparation.json', b'{}'); evidence = self.commit()
        self.put('darwin/later.nix', b'ordinary descendant'); descendant = self.commit()
        self.accept('owner-first-harness-wave', {'lib/engine.py': b'wave engine'}, kind='policy')
        self.assertTrue(self.admit()['accepted'])
        self.assertTrue(A.admitted_revision(self.git, wine, accepted=True))
        for revision in (evidence, descendant): self.assert_candidate_only(revision)

    def test_registered_exact_policy_edit_without_receipt_still_rejects(self):
        self.restart_wave()
        self.put('lib/engine.py', b'authorized scope but no acceptance'); self.commit()
        with self.assertRaisesRegex(F.TransitionError, 'protected_policy_changed'): self.admit()

    def test_routine_prefix_merge_during_registered_policy_still_rejects(self):
        self.restart_wave()
        branch = self.git._text('branch', '--show-current')
        self.git._read('checkout', '--quiet', '-b', 'wine-side')
        self.put('darwin/wine.nix', b'independent payload'); self.commit()
        self.git._read('checkout', '--quiet', branch)
        self.put('darwin/later.nix', b'other payload'); self.commit()
        self.git._read('merge', '--no-ff', '--no-edit', 'wine-side')
        self.accept('owner-first-harness-wave', {'lib/engine.py': b'wave engine'}, kind='policy')
        with self.assertRaisesRegex(F.TransitionError, 'nonlinear_policy_candidate'): self.admit()

    def test_matching_checkpoint_payload_merge_passes(self):
        original = self.git._text('branch', '--show-current')
        self.git._read('checkout', '--quiet', '-b', 'side')
        self.put('darwin/side.nix', b'side'); side = self.commit()
        self.git._read('checkout', '--quiet', original)
        self.put('darwin/main.nix', b'main'); self.commit()
        self.git._read('merge', '--no-ff', '--no-edit', 'side')
        self.assertTrue(self.admit()['accepted'])
        self.assertTrue(A.admitted_revision(self.git, side))
        self.accept('merged-root')
        self.assertEqual(self.proof()['checkpoint'], self.previous)

    def test_side_branch_protected_edit_restored_before_merge_rejects(self):
        original = self.git._text('branch', '--show-current')
        self.git._read('checkout', '--quiet', '-b', 'side')
        self.put('lib/engine.py', b'bad'); self.commit()
        self.put('lib/engine.py', b'wave engine'); self.commit()
        self.git._read('checkout', '--quiet', original)
        self.put('darwin/main.nix', b'main'); self.commit()
        self.git._read('merge', '--no-ff', '--no-edit', 'side')
        with self.assertRaisesRegex(F.TransitionError, 'protected_policy_changed'): self.admit()

    def test_pending_evidence_and_history_rewrite_reject(self):
        self.put('evidence/pending.json', b'{}'); pending = self.commit()
        with self.assertRaisesRegex(F.TransitionError, 'unreviewed_checkpoint_evidence'): self.admit()
        self.accept('consumes-pending')
        self.assertTrue(self.admit()['accepted'])
        with self.assertRaises(F.TransitionError): A.admitted_revision(self.git, pending)
        self.put('evidence/pending.json', b'changed'); self.commit()
        self.put('evidence/pending.json', b'{}'); self.commit()
        with self.assertRaisesRegex(F.TransitionError, 'historical_evidence_changed'): self.admit()

    def test_aggregate_bad_predecessor_policy_scope_and_extra_child_reject(self):
        for changes, overrides, extra in (
            ({}, {'previous_commit': self.pin}, None),
            ({}, {'previous_acceptance': A.MIGRATION_PATH}, None),
            ({}, {'reviewed_tree': 'b'*40}, None),
            ({'lib/engine.py': b'unreviewed policy'}, {}, None),
            ({}, {'kind': 'policy'}, None),
            ({}, {}, {'darwin/hidden.nix': b'hidden'}),
        ):
            with self.subTest(overrides=overrides, changes=changes, extra=extra):
                self.git._read('reset', '--hard', self.wave)
                self.previous, self.previous_path = self.wave, A.OWNER_FIRST_WAVE_PATH
                self.accept('invalid-root', changes, overrides=overrides, extra=extra)
                with self.assertRaises(F.TransitionError): self.admit()

    def test_fresh_wave_from_new_routine_prefix_does_not_replay_sibling_receipt(self):
        sibling, sibling_tree = self.wave, self.git._tree(self.wave)
        self.restart_wave()
        client = 'manifests/windows-host-ssh-client.json'
        self.updates[A.OWNER_FIRST_WAVE_PATH]['paths'] |= {client, 'bin/new-delivery'}
        self.put(client, b'new independently delivered transport')
        canonical_prefix = self.commit()
        self.assertNotIn(A.OWNER_FIRST_WAVE_PATH, self.git._tree(canonical_prefix))
        after = dict(self.rules, protected_paths=self.rules['protected_paths'] | {'bin/new-delivery'})
        self.updates[A.OWNER_FIRST_WAVE_PATH]['after'] = after
        reviewed = self.accept('owner-first-harness-wave',
            {'lib/engine.py': b'combined wave', 'bin/new-delivery': b'fixed authority'}, kind='policy')
        self.assertTrue(self.admit()['accepted'])
        self.assertTrue(A.admitted_revision(self.git, canonical_prefix))
        self.assertEqual(self.git._tree(sibling), sibling_tree)
        self.assertNotIn(sibling, self.proof()['candidateRevisions'])
        self.assertNotEqual(self.git._tree(self.previous)[A.OWNER_FIRST_WAVE_PATH],
                            sibling_tree[A.OWNER_FIRST_WAVE_PATH])
        with self.assertRaisesRegex(F.TransitionError, 'revision_not_accepted'):
            A.admitted_revision(self.git, reviewed)
        self.put('bin/new-delivery', b'changed'); self.commit()
        self.put('bin/new-delivery', b'fixed authority'); self.commit()
        with self.assertRaisesRegex(F.TransitionError, 'protected_policy_changed'):
            self.admit()

    def test_pin_bindings_and_missing_wave_registration_reject(self):
        for field in ('commit', 'tree', 'blob', 'reviewed', 'reviewed_tree', 'previous'):
            with self.subTest(field=field), patch.object(A, 'CHECKPOINT_BINDING', dict(self.binding, **{field: 'f'*40})):
                with self.assertRaises((F.TransitionError, AssertionError)): self.admit()
        with patch.object(S, 'policy_updates', return_value={A.MIGRATION_PATH: self.updates[A.MIGRATION_PATH]}):
            with self.assertRaisesRegex(F.TransitionError, 'successor_not_registered'): self.admit()

    def test_consecutive_narrow_policy_repairs_preserve_real_checkpoint_chain(self):
        earlier = self.wave
        for path, ident, content in (
            (S.VENDOR_FIXTURE_CUSTODY_REPAIR_PATH, 'vendor-fixture-custody-repair', b'custody repair'),
            (S.SCHEDULER_DESCRIPTOR_REPAIR_PATH, 'scheduler-descriptor-repair', b'scheduler repair'),
            (S.PRODUCT_SURFACE_PATH, 'product-surface', b'product documentation and navigation')):
            prior, prior_tree = self.previous, self.git._tree(self.previous)
            self.updates[path] = {'previous_commit': prior, 'paths': {'lib/engine.py'}, 'after': self.rules}
            reviewed = self.accept(ident, {'lib/engine.py': content}, kind='policy')
            self.assertTrue(self.admit()['accepted'])
            self.assertTrue(A.admitted_revision(self.git, prior))
            self.assertTrue(A.admitted_revision(self.git, earlier))
            self.assertEqual(self.git._tree(prior), prior_tree)
            self.assertEqual(self.proof()['rules'], self.rules)
            with self.assertRaisesRegex(F.TransitionError, 'revision_not_accepted'):
                A.admitted_revision(self.git, reviewed)

    def test_narrow_schema2_custody_policy_preserves_checkpoint_and_rejects_intermediates(self):
        path = S.VENDOR_FIXTURE_CUSTODY_REPAIR_PATH
        self.updates[path] = {'previous_commit': self.wave,
                             'paths': {'lib/engine.py'}, 'after': self.rules}
        old_wave = self.git._tree(self.wave)
        self.put('lib/engine.py', b'bounded custody fix'); staged = self.commit()
        with self.assertRaisesRegex(F.TransitionError, 'protected_policy_changed'):
            self.admit()
        reviewed = self.accept('vendor-fixture-custody-repair', kind='policy')
        self.assertTrue(self.admit()['accepted'])
        self.assertEqual(self.proof()['checkpoint'], self.previous)
        self.assertEqual(self.proof()['rules'], self.rules)
        self.assertEqual(self.git._tree(self.wave), old_wave)
        self.assertTrue(A.admitted_revision(self.git, self.wave))
        for intermediate in (staged, reviewed):
            with self.assertRaisesRegex(F.TransitionError, 'revision_not_accepted'):
                A.admitted_revision(self.git, intermediate)
        observation, head, current = self.observe()
        bad = copy.deepcopy(observation)
        bundle = bad['rows'][-1]['receipt']['bundle']
        data = json.loads(bundle['raw']); data['review']['decision'] = 'PENDING'
        bundle['raw'] = json.dumps(data).encode()
        with self.assertRaisesRegex(F.TransitionError, 'unresolved_independent_review'):
            A.admit(bad, head, current)

    def test_foreign_parent_mixed_checkpoints_and_history_limit_reject(self):
        tree_id = self.git._text('rev-parse', self.wave+'^{tree}')
        foreign = self.git._text('commit-tree', tree_id, '-p', self.wave, '-p', self.base, '-m', 'foreign')
        self.git._read('reset', '--hard', foreign)
        with self.assertRaisesRegex(F.TransitionError, 'unknown_checkpoint_predecessor'): self.admit()
        self.git._read('reset', '--hard', self.wave)
        self.put('darwin/side.nix', b'side'); side = self.commit()
        self.git._read('reset', '--hard', self.wave)
        self.accept('root-one')
        tree_id = self.git._text('rev-parse', self.previous+'^{tree}')
        mixed = self.git._text('commit-tree', tree_id, '-p', self.previous, '-p', side, '-m', 'mixed')
        self.git._read('reset', '--hard', mixed)
        with self.assertRaisesRegex(F.TransitionError, 'merge_checkpoint_mismatch'): self.admit()
        self.git._read('reset', '--hard', self.wave)
        with patch.object(K, 'MAX_COMMITS', 1):
            with self.assertRaisesRegex(F.TransitionError, 'checkpoint_history_limit'): self.admit()

    def test_incomplete_observation_wrong_current_and_extra_schema_reject(self):
        observation, head, current = self.observe()
        for change in ('missing-row', 'wrong-head', 'extra-key'):
            altered = copy.deepcopy(observation)
            if change == 'missing-row': altered['rows'] = altered['rows'][1:]
            if change == 'wrong-head': altered['head'] = self.pin
            if change == 'extra-key': altered['reviewed'] = True
            with self.subTest(change=change), self.assertRaises(F.TransitionError):
                A.admit(altered, head, current)

    def test_aggregate_bundle_requires_observed_checks_not_pass_labels(self):
        self.accept('bundle-root')
        observation, head, current = self.observe()
        raw = observation['rows'][-1]['receipt']['bundle']['raw']
        good = json.loads(raw)
        variants = []
        bad = copy.deepcopy(good); bad['validation'] = []; variants.append(bad)
        bad = copy.deepcopy(good); bad['review']['unresolved_findings'] = ['open']; variants.append(bad)
        bad = copy.deepcopy(good); bad['review']['subject_commit'] = self.pin; variants.append(bad)
        for outcome in (1, True, None):
            bad = copy.deepcopy(good); bad['validation'][0]['observation']['exit_code'] = outcome; variants.append(bad)
        bad = copy.deepcopy(good); bad['validation'][0]['observation']['completed'] = False; variants.append(bad)
        bad = copy.deepcopy(good); del bad['validation'][0]['observation']; variants.append(bad)
        bad = copy.deepcopy(good); bad['validation'][0]['observation'] = {'verdict': 'PASS'}; variants.append(bad)
        bad = copy.deepcopy(good); bad['recovery']['checks'] = []; variants.append(bad)
        for index, bad in enumerate(variants):
            with self.subTest(index=index), self.assertRaises(F.TransitionError):
                K.parse_bundle(json.dumps(bad).encode())
        self.assertEqual(K.parse_bundle(raw), good)

    def test_misbound_bundle_and_source_change_after_checks_reject(self):
        self.accept('bundle-root')
        observation, head, current = self.observe()
        for field in ('subject_commit', 'subject_tree'):
            altered = copy.deepcopy(observation)
            bundle = altered['rows'][-1]['receipt']['bundle']
            record = json.loads(bundle['raw']); record[field] = 'f'*40
            record['review'][field] = 'f'*40
            bundle['raw'] = json.dumps(record).encode()
            with self.subTest(field=field), self.assertRaises(F.TransitionError):
                A.admit(altered, head, current)
        # Real committed blob with checks bound before a later source edit.
        self.git._read('reset', '--hard', self.wave)
        self.previous, self.previous_path = self.wave, A.OWNER_FIRST_WAVE_PATH
        reviewed = self.accept('source-drift')
        record = json.loads((self.root/(F.PREFIX+'source-drift/acceptance.json')).read_bytes())
        self.git._read('reset', '--hard', reviewed)
        self.put('darwin/changed-after-checks.nix', b'late change'); reviewed = self.commit()
        record.update(reviewed_commit=reviewed, reviewed_tree=self.git._text('rev-parse', reviewed+'^{tree}'),
                      changes=F.delta(self.git._tree(self.wave), self.git._tree(reviewed)))
        self.put(F.PREFIX+'source-drift/acceptance.json', json.dumps(record).encode()); self.commit()
        with self.assertRaisesRegex(F.TransitionError, 'source_changed_after_evidence_subject'): self.admit()

    def test_recovery_plan_must_exist_at_observed_subject(self):
        self.accept('plan-root', evidence_subject=self.wave)
        # A real committed/observed subject omits the recovery plan even though
        # the later final reviewed tree contains a regular path with that name.
        with self.assertRaisesRegex(F.TransitionError, 'recovery_plan_not_source_bound'):
            self.admit()

    def test_previous_checkpoint_subject_cannot_be_reused_for_new_review(self):
        self.accept('first-root')
        self.accept('stale-subject', evidence_subject=self.wave)
        with self.assertRaisesRegex(F.TransitionError, 'evidence_subject_before_checkpoint'):
            self.admit()


if __name__ == '__main__': unittest.main()
