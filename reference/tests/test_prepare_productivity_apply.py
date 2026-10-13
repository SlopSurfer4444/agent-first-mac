"""Fixture-only validation of fresh sentinel admission before receipt preparation."""
import importlib.machinery
from pathlib import Path
import unittest
from unittest.mock import patch
from test_current_doctor import C

ROOT = Path(__file__).resolve().parents[1]
P = importlib.machinery.SourceFileLoader('prepare_productivity_fixture', str(ROOT/'bin/prepare-productivity-apply')).load_module()


class PreparationTests(unittest.TestCase):
    def value(self):
        return C.report(historical=True, source=True, accepted=True, integrated=True,
            sentinel=True, sentinel_checked=True, exposure=True, exposure_accepted=True,
            configuration=True, configuration_accepted=True, admission_mode='current-state')

    def test_requires_full_fresh_pass_and_same_clean_commit(self):
        import json
        calls = []
        def checked(argv, **kwargs):
            calls.append(argv)
            if str(argv[0]).endswith('current-doctor'): return json.dumps(self.value())
            if 'rev-parse' in argv: return 'a'*40
            if 'branch' in argv: return 'main'
            return ''
        with patch.object(P, 'checked', side_effect=checked):
            P.fresh_doctor(ROOT, 'a'*40, ['git'], env={})
        self.assertEqual(calls[0], [ROOT/'bin/current-doctor', '--json'])
        self.assertIn('--untracked-files=all', calls[-1])

    def test_git_only_needs_review_and_dirty_source_cannot_prepare_receipt(self):
        import json
        for value in (C.report(git_only=True), C.report(), self.value()):
            with self.subTest(value=value['verdict']):
                with patch.object(P, 'checked', side_effect=[json.dumps(value), 'a'*40, 'main', ' M source']):
                    with self.assertRaises((RuntimeError, C.D.DoctorError, ValueError)):
                        P.fresh_doctor(ROOT, 'a'*40, ['git'], env={})

    def test_broker_review_field_needs_actual_historical_target_review(self):
        import json
        reviewed = C.report(historical=True, source=True, accepted=True, integrated=True,
            git_only=True, exposure=True, exposure_accepted=True, configuration=True,
            configuration_accepted=True)
        with patch.object(P, 'checked', return_value=json.dumps(reviewed)) as checked:
            P.reviewed_target(ROOT, env={})
        self.assertEqual(checked.call_args.args[0],
            [ROOT/'bin/current-doctor', '--git-only', '--audit-history', '--json'])
        reviewed['admissionMode'] = 'current-state'
        with patch.object(P, 'checked', return_value=json.dumps(reviewed)):
            with self.assertRaisesRegex(RuntimeError, 'independently_reviewed_target_required'):
                P.reviewed_target(ROOT, env={})

if __name__ == '__main__': unittest.main()
