"""Fixture-only source/build/receipt preparation: no unrelated vendor launch."""
import importlib.machinery
from pathlib import Path
import unittest
from unittest.mock import patch
from test_current_doctor import C

ROOT = Path(__file__).resolve().parents[1]
P = importlib.machinery.SourceFileLoader('prepare_productivity_fixture', str(ROOT/'bin/prepare-productivity-apply')).load_module()


class PreparationTests(unittest.TestCase):
    def test_plain_startup_does_not_dirty_source_with_bytecode(self):
        import os
        import shutil
        import subprocess
        import sys
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'bin').mkdir()
            (root/'lib').mkdir()
            for relative in ('bin/prepare-productivity-apply',
                             'lib/prepared_receipt.py', 'lib/productivity_ownership.py'):
                shutil.copyfile(ROOT/relative, root/relative)
            environment = dict(os.environ)
            environment.pop('PYTHONDONTWRITEBYTECODE', None)
            result = subprocess.run([sys.executable, str(root/'bin/prepare-productivity-apply')],
                                    capture_output=True, env=environment, cwd=root)
            self.assertEqual(result.returncode, 1)
            self.assertIn(b'usage', result.stdout)
            self.assertFalse(list(root.rglob('__pycache__')))

    def value(self):
        return C.report(historical=True, source=True, accepted=True, integrated=True,
            git_only=True, exposure=True, exposure_accepted=True,
            configuration=True, configuration_accepted=True, admission_mode='current-state')

    def test_requires_fresh_source_and_same_clean_commit_without_vendor(self):
        import json
        calls = []
        def checked(argv, **kwargs):
            calls.append(argv)
            if str(argv[0]).endswith('current-doctor'): return json.dumps(self.value())
            if 'rev-parse' in argv: return 'a'*40
            if 'branch' in argv: return 'main'
            return ''
        with patch.object(P, 'checked', side_effect=checked):
            P.fresh_source(ROOT, 'a'*40, ['git'], env={})
        self.assertEqual(calls[0], [ROOT/'bin/current-doctor', '--git-only', '--json'])
        self.assertIn('--untracked-files=all', calls[-1])

    def test_unadmitted_or_dirty_source_cannot_prepare_receipt(self):
        import json
        for value in (C.report(git_only=True), C.report(), self.value()):
            with self.subTest(value=value['verdict']):
                with patch.object(P, 'checked', side_effect=[json.dumps(value), 'a'*40, 'main', ' M source']):
                    with self.assertRaises((RuntimeError, C.D.DoctorError, ValueError)):
                        P.fresh_source(ROOT, 'a'*40, ['git'], env={})

    def test_broker_review_field_needs_actual_historical_target_review(self):
        import json
        reviewed = C.report(historical=True, source=True, accepted=True, integrated=True,
            git_only=True, exposure=True, exposure_accepted=True, configuration=True,
            configuration_accepted=True)
        with patch.object(P, 'checked', return_value=json.dumps(reviewed)) as checked:
            P.reviewed_target(ROOT, env={})
        self.assertEqual(checked.call_args.args[0],
            [ROOT/'bin/current-doctor', '--git-only', '--reviewed-target', '--json'])
        reviewed['verdict'] = 'NEEDS_REVIEW'
        with patch.object(P, 'checked', return_value=json.dumps(reviewed)):
            with self.assertRaisesRegex(RuntimeError, 'independently_reviewed_target_required'):
                P.reviewed_target(ROOT, env={})

    def test_changed_revision_nar_and_policy_reject_actual_receipt_binding(self):
        import hashlib
        policy = b'fixture-policy'
        commit, nar = 'a'*40, 'sha256:' + '0'*52
        with patch.object(P, 'EXPECTED_POLICY_SHA256', hashlib.sha256(policy).hexdigest()):
            self.assertEqual(P.validate_build_binding(commit,
                {'configurationRevision': commit}, nar, policy), hashlib.sha256(policy).hexdigest())
            for revision, digest, data, reason in (
                    ({'configurationRevision': 'b'*40}, nar, policy, 'configuration_revision'),
                    ({'configurationRevision': commit}, 'sha256:unknown', policy, 'target_nar_hash'),
                    ({'configurationRevision': commit}, nar, b'changed', 'installed_policy_hash')):
                with self.subTest(reason=reason), self.assertRaisesRegex(RuntimeError, reason):
                    P.validate_build_binding(commit, revision, digest, data)

if __name__ == '__main__': unittest.main()
