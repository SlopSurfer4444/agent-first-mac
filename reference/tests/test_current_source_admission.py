"""Disposable Git migration/current-state tests; no native sentinel or machine writes."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from lib import current_source_admission as A
from lib import config_transition_source as S
from lib import config_transitions as F
from test_config_transition_repository import LocalGit


class CurrentSourceTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='current-source-fixture-')
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.git = LocalGit(self.root)
        self.git._read('init', '--quiet')
        self.put('lib/engine.py', b'old engine')
        self.put('bin/current-doctor', b'old doctor')
        self.put(A.PREVIOUS_RECEIPT, b'previous accepted evidence')
        self.base = self.commit()
        self.base_tree = self.git._tree(self.base)
        self.rules = dict(protected_paths={'lib/engine.py', 'bin/current-doctor'},
            protected_prefixes=S.PROTECTED_PREFIXES, allowed_paths=('flake.nix', 'flake.lock'),
            allowed_prefixes=S.ALLOWED_PREFIXES, bootstrap_paths={'lib/engine.py', 'bin/current-doctor'},
            coordinator={'name': 'Fixture Coordinator', 'email': 'fixture@example.invalid'})
        for p in (patch.object(A, 'MIGRATION_PREVIOUS', self.base),
                  patch.object(S, 'ANCHOR', self.base),
                  patch.object(S, 'COORDINATOR', self.rules['coordinator']),
                  patch.object(S, 'policy_v2', return_value=self.rules),
                  patch.object(S, 'policy_updates', return_value={A.MIGRATION_PATH: {
                      'previous_commit': self.base, 'paths': self.rules['bootstrap_paths'], 'after': self.rules}})):
            p.start(); self.addCleanup(p.stop)
        self.put('lib/engine.py', b'reviewed migration engine')
        evidence = {}
        for role in ('validation', 'review', 'rollback'):
            path = 'evidence/migration/' + role + '.json'
            self.put(path, b'{}'); evidence[role] = [path]
        self.reviewed = self.commit()
        reviewed = self.git._tree(self.reviewed)
        self.record = dict(schema=1, id='global-harness-simplification', kind='policy',
            status='ACCEPTED_CONFIGURATION', anchor_commit=self.base,
            previous_commit=self.base, previous_acceptance=A.PREVIOUS_RECEIPT,
            reviewed_commit=self.reviewed, reviewed_tree=self.git._text('rev-parse', self.reviewed+'^{tree}'),
            changes=F.delta(self.base_tree, reviewed), evidence=evidence, coordinator=self.rules['coordinator'])
        self.put(A.MIGRATION_PATH, json.dumps(self.record).encode())
        self.checkpoint = self.commit()

    def put(self, path, raw):
        p = self.root/path; p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(raw)

    def commit(self):
        self.git._read('add', '--all'); self.git._read('commit', '--quiet', '-m', 'fixture')
        return self.git._text('rev-parse', 'HEAD')

    def observe(self):
        head = self.git._text('rev-parse', 'HEAD'); tree = self.git._tree(head)
        return A.observe(self.git, head, tree), head, tree

    def admit(self):
        return A.admit(*self.observe())

    def test_checkpoint_and_two_payload_successors_need_no_receipt(self):
        self.assertTrue(self.admit()['accepted'])
        for text in (b'first', b'second'):
            self.put('darwin/payload.nix', text); self.commit()
            self.assertTrue(self.admit()['accepted'])
        observation, head, _ = self.observe()
        self.assertEqual(observation['checkpoint'], self.checkpoint)
        self.assertEqual(len(observation['candidates']), 1)
        self.assertTrue(A.admitted_revision(self.git, head))
        self.assertTrue(A.admitted_revision(self.git, self.reviewed, accepted=False))
        with self.assertRaises((F.TransitionError, AssertionError)):
            A.admitted_revision(self.git, self.reviewed)

    def test_no_full_historical_collector_in_routine(self):
        from lib import config_transition_git
        with patch.object(config_transition_git, 'observe', side_effect=AssertionError('old replay')):
            self.assertTrue(self.admit()['accepted'])

    def test_divergent_routine_merge_preserves_linear_history_requirement(self):
        original = self.git._text('branch', '--show-current')
        self.git._read('checkout', '--quiet', '-b', 'side-payload')
        self.put('darwin/side.nix', b'side'); self.commit()
        self.git._read('checkout', '--quiet', original)
        self.put('darwin/main.nix', b'main'); self.commit()
        self.git._read('merge', '--no-ff', '--no-edit', 'side-payload')
        with self.assertRaisesRegex(F.TransitionError, 'nonlinear_current_history'):
            self.admit()

    def test_protected_evidence_import_and_unknown_namespace_rejected(self):
        observation, head, current = self.observe()
        for path in ('lib/engine.py', 'lib/new.py', 'bin/current-doctor', A.PREVIOUS_RECEIPT,
                     'evidence/new.json', 'bin/json.py', 'json.py', 'vendor/__init__.py'):
            with self.subTest(path=path):
                changed = dict(current); changed[path] = ('100644', 'f'*40)
                with self.assertRaises(F.TransitionError):
                    A.admit(observation, head, changed)

    def test_replacement_then_restoration_of_migration_receipt_is_rejected(self):
        original = (self.root/A.MIGRATION_PATH).read_bytes()
        self.put(A.MIGRATION_PATH, original+b' '); self.commit()
        self.put(A.MIGRATION_PATH, original); self.commit()
        with self.assertRaisesRegex(F.TransitionError, 'history_changed'):
            self.admit()

    def test_forged_migration_predecessor_and_scope_rejected(self):
        observation, head, current = self.observe()
        for field, value in (('previous_commit', 'e'*40), ('previous_acceptance', 'evidence/config-transitions/other/acceptance.json'),
                             ('reviewed_commit', 'd'*40)):
            with self.subTest(field=field):
                altered = copy.deepcopy(observation)
                record = dict(self.record); record[field] = value
                altered['raw'] = json.dumps(record).encode()
                with self.assertRaises(F.TransitionError):
                    A.admit(altered, head, current)

    def test_missing_registration_and_extra_receipt_child_payload_rejected(self):
        observation, head, current = self.observe()
        with patch.object(S, 'policy_updates', return_value={}):
            with self.assertRaisesRegex(F.TransitionError, 'not_registered'):
                A.admit(observation, head, current)
        observation['checkpointTree'] = dict(current, **{'darwin/hidden.nix': ('100644', 'b'*40)})
        with self.assertRaisesRegex(F.TransitionError, 'sole_receipt_child'):
            A.admit(observation, head, current)

    def test_merge_receipt_and_wrong_coordinator_are_rejected(self):
        tree_id = self.git._text('rev-parse', self.checkpoint+'^{tree}')
        merged = self.git._text('commit-tree', tree_id, '-p', self.reviewed, '-p', self.base, '-m', 'invalid merge child')
        self.git._read('reset', '--hard', merged)
        with self.assertRaises(F.TransitionError): self.admit()
        self.git._read('reset', '--hard', self.reviewed)
        self.git.env['GIT_AUTHOR_NAME'] = 'Unreviewed Alternate'
        self.put(A.MIGRATION_PATH, json.dumps(self.record).encode())
        self.commit()
        with self.assertRaisesRegex(F.TransitionError, 'metadata_mismatch'): self.admit()

    def test_alternate_branch_receipt_without_reviewed_parent_rejected(self):
        self.git._read('checkout', '--quiet', '-b', 'alternate', self.base)
        self.put(A.MIGRATION_PATH, json.dumps(self.record).encode())
        self.commit()
        with self.assertRaises(F.TransitionError): self.admit()

    def test_deleted_payload_parent_is_held_absent(self):
        checkpoint = self.git._tree(self.checkpoint)
        checkpoint['darwin/old/config.nix'] = ('100644', 'a'*40)
        self.assertIn('darwin', A.admit_tree(checkpoint, self.git._tree(self.checkpoint))['absent'])


if __name__ == '__main__':
    unittest.main()
