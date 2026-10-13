"""Connected doctor fixtures: alignment never substitutes for component health."""
import contextlib
import importlib.machinery
import importlib.util
import io
import json
from pathlib import Path, PurePosixPath
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]


def load(name):
    loader = importlib.machinery.SourceFileLoader(name.replace('-', '_'), str(ROOT / 'bin' / name))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


P = load('productivity-doctor')
T = load('tailscale-windows-host-doctor')
PM = json.loads((ROOT / 'manifests/productivity-baseline.json').read_text())
TM = json.loads((ROOT / 'manifests/tailscale-windows-host-m1.json').read_text())


def report(exact=False, admission="historical-review"):
    current_state = admission == "current-state"
    return {'schema': 1, 'state': 'CURRENT_REVISION' if exact else (
                'CURRENT_CONTROL_ONLY_SUCCESSOR' if current_state else 'ACCEPTED_CONTROL_ONLY_SUCCESSOR'),
            'compatible': True, 'revisionExact': exact, 'sourceAccepted': True,
            'installedCommitAccepted': True, 'systemInputsEqual': True,
            'sourceRevision': 'a' * 40, 'installedRevision': ('a' if exact else 'b') * 40,
            'sourceAdmissionMode': admission,
            'reason': (('exact_admitted_revision' if current_state else 'exact_accepted_revision') if exact
                       else ('current_system_inputs_unchanged' if current_state else 'reviewed_system_inputs_unchanged')), 'readOnly': True, 'systemMutationsPerformed': False,
            'childSettled': True, 'sourceHandlesClosed': True}


class FixturePath(PurePosixPath):
    @classmethod
    def home(cls):
        return cls('/fixture-owner')

    def is_dir(self):
        return True

    def is_file(self):
        return True

    def exists(self):
        return True

    def stat(self):
        return SimpleNamespace(st_mode=0o700, st_uid=501)

    def read_text(self):
        return TM['source']['version'] + '|' + TM['source']['sha256']


class RevisionReportTests(unittest.TestCase):
    def observe(self, module, value, code=0):
        output = value if isinstance(value, str) else json.dumps(value)
        with patch.object(module, 'command', return_value=SimpleNamespace(returncode=code, stdout=output)) as call:
            result = module.revision_observation()
            self.assertEqual(call.call_count, 1)
            self.assertEqual(call.call_args.kwargs, {'timeout': 200})
            self.assertEqual(call.call_args.args[0][-1], '--json')
            self.assertTrue(call.call_args.args[0][-2].endswith('/bin/system-revision-status'))
            return result

    def test_exact_and_accepted_successor_are_distinct_positive_states(self):
        for module in (P, T):
            for exact in (False, True):
                result = self.observe(module, report(exact))
                self.assertTrue(result['compatible'])
                self.assertIs(result['revisionExact'], exact)

    def test_current_admission_preserves_mode_and_rejects_historical_labels(self):
        for module in (P, T):
            for exact in (False, True):
                value = report(exact, admission="current-state")
                result = self.observe(module, value)
                self.assertTrue(result['compatible'])
                self.assertEqual(result['sourceAdmissionMode'], 'current-state')
                self.assertEqual(result['state'], value['state'])
                for change in ({'sourceAdmissionMode': 'historical-review'},
                               {'reason': 'exact_accepted_revision' if exact else 'reviewed_system_inputs_unchanged'}):
                    self.assertFalse(self.observe(module, dict(value, **change))['compatible'])
                value.pop('sourceAdmissionMode')
                self.assertFalse(self.observe(module, value)['compatible'])

    def test_inconsistent_false_or_malformed_proofs_fail_closed(self):
        changes = [{'schema': True}, {'compatible': 1}, {'sourceAccepted': False},
                   {'installedCommitAccepted': False}, {'systemInputsEqual': False},
                   {'childSettled': False}, {'sourceHandlesClosed': False},
                   {'readOnly': False}, {'systemMutationsPerformed': True},
                   {'state': 'CURRENT_REVISION'}, {'revisionExact': True},
                   {'sourceRevision': 'private-value'}, {'installedRevision': '0' * 40},
                   {'sourceAdmissionMode': None}, {'sourceAdmissionMode': True},
                   {'sourceAdmissionMode': 'current-state'}, {'reason': 'fixture'}]
        for module in (P, T):
            for change in changes:
                with self.subTest(module=module.__name__, change=change):
                    result = self.observe(module, dict(report(), **change))
                    self.assertFalse(result['compatible'])
                    self.assertNotIn('private-value', json.dumps(result))
            for invalid in ('not JSON', '[]', '{"schema":1,"schema":1}', 'x' * 16385):
                self.assertFalse(self.observe(module, invalid)['compatible'])
            self.assertFalse(self.observe(module, report(), code=1)['compatible'])


class ConnectedDoctorTests(unittest.TestCase):
    def test_unavailable_initial_revision_stops_without_retry_or_component_io(self):
        for module in (P, T):
            output = io.StringIO()
            with patch.object(module, 'command', return_value=SimpleNamespace(returncode=124, stdout='')) as command, \
                    patch.object(module, 'MANIFEST') as manifest, \
                    patch.object(module.sys, 'argv', ['fixture-doctor']), \
                    contextlib.redirect_stdout(output):
                with self.assertRaises(SystemExit) as stopped:
                    module.main()
                self.assertEqual(stopped.exception.code, 1)
                self.assertEqual(command.call_count, 1)
                manifest.read_text.assert_not_called()
            value = json.loads(output.getvalue())
            self.assertFalse(value['componentChecksRun'])
            self.assertEqual(value['configurationRevisionStatus']['state'], 'UNKNOWN')

    def run_doctor(self, module, fault=None, drift=False, manifest_race=False, admission="historical-review"):
        observations = [report(admission=admission), dict(report(admission=admission), sourceRevision=('c' if drift else 'a') * 40)]
        events, coordinate = [], {'source': 'a' * 40}
        def read_manifest():
            events.append('manifest')
            if manifest_race:
                coordinate['source'] = 'c' * 40
            return json.dumps(PM if module is P else TM)
        target = PM['desiredState']
        defaults = {
            'AppleIconAppearanceTheme': target['iconAppearance'],
            'AppleInterfaceStyleSwitchesAutomatically': '1', 'AppleShowAllExtensions': '1',
            'InitialKeyRepeat': str(target['initialKeyRepeat']), 'KeyRepeat': str(target['keyRepeat']),
            'com.apple.trackpad.scaling': str(target['trackpadScaling']).rstrip('0').rstrip('.'),
            'autohide': '1' if target['dockAutohide'] else '0', 'minimize-to-application': '1',
            'mru-spaces': '0', 'show-recents': '0', 'wvous-br-corner': str(target['bottomRightHotCornerRaw']),
            'ShowPathbar': '1', 'ShowStatusBar': '1', 'Clicking': '1', 'TrackpadRightClick': '1',
            'TrackpadThreeFingerDrag': '1', 'GloballyEnabled': '0',
            'EnableStandardClickToShowDesktop': '1' if target['clickWallpaperToShowDesktop'] else '0',
            'EnableTilingByEdgeDrag': '1', 'EnableTopTilingByEdgeDrag': '1',
            'EnableTilingOptionAccelerator': '1', 'EnableTiledWindowMargins': '0',
            'widgetAppearance': str(target['widgetAppearanceRaw']),
            'location': '/fixture-owner/Pictures/Screenshots'}
        def default(domain, key):
            return 'wrong' if fault == 'default' and key == 'KeyRepeat' else defaults[key]

        def command(argv, timeout=None):
            text, code = '', 0
            if len(argv) > 1 and argv[1].endswith('/bin/system-revision-status'):
                events.append('revision')
                self.assertEqual(timeout, 200)
                observation = observations.pop(0)
                if manifest_race:
                    observation['sourceRevision'] = coordinate['source']
                text = json.dumps(observation)
            elif argv[0].endswith('socketfilterfw'):
                text = 'Firewall is enabled\nblock all state set to disabled\nbuilt-in signed software ENABLED\ndownloaded signed software ENABLED\n'
                if target['firewallStealthMode']:
                    text += 'stealth mode is on'
            elif argv[0] == '/usr/bin/pmset':
                battery = not target['batteryLowPowerMode'] if fault == 'power' else target['batteryLowPowerMode']
                text = 'Battery Power:\n lowpowermode ' + ('1' if battery else '0') + '\nAC Power:\n lowpowermode 0\n'
            elif argv[0] == '/usr/bin/codesign':
                code = 1 if fault == 'signature' else 0
            elif argv[0] == '/usr/sbin/spctl':
                code = 1 if fault == 'gatekeeper' else 0
            elif argv[0] == '/opt/homebrew/bin/brew':
                text = ''
            elif argv[0] == '/usr/bin/fdesetup':
                text = 'FileVault is On'
            elif argv[-1] == 'version':
                text = TM['application']['minimumVersion']
            elif argv[0] == '/usr/bin/file':
                text = 'Mach-O universal x86_64 arm64'
            elif argv[0] == '/usr/sbin/pkgutil':
                text = 'version: ' + TM['source']['version']
            elif argv[0] in ('/bin/launchctl', '/usr/sbin/lsof'):
                code = 1
            else:
                raise AssertionError('Unexpected fixture command: ' + repr(argv))
            return SimpleNamespace(returncode=code, stdout=text)

        def plist(bundle, key):
            if module is P:
                app = next(row for row in PM['applications'] if str(bundle).endswith(row['bundleName']))
                value = {'CFBundleIdentifier': app['bundleIdentifier'], 'CFBundleShortVersionString': app['version']}[key]
            else:
                app = TM['application']
                extension = str(bundle).endswith(app['systemExtension'])
                value = {'CFBundleIdentifier': app['systemExtensionBundleIdentifier'] if extension else app['bundleIdentifier'],
                         'CFBundleShortVersionString': app['minimumVersion']}[key]
            return '0' if fault == 'version' and key == 'CFBundleShortVersionString' else value

        def team(bundle):
            if module is T:
                return TM['application']['teamIdentifier']
            return next(row['teamIdentifier'] for row in PM['applications'] if str(bundle).endswith(row['bundleName']))

        capture = io.StringIO()
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(module, 'command', side_effect=command))
            stack.enter_context(patch.object(module, 'MANIFEST', SimpleNamespace(read_text=read_manifest)))
            stack.enter_context(patch.object(module, 'Path', FixturePath))
            stack.enter_context(patch.object(module, 'plist_value', side_effect=plist))
            stack.enter_context(patch.object(module.sys, 'argv', ['fixture-doctor']))
            if module is P:
                stack.enter_context(patch.object(module, 'default', side_effect=default))
                stack.enter_context(patch.object(module, 'codesign_team', side_effect=team))
                stack.enter_context(patch.object(module.os, 'getuid', return_value=501))
            else:
                stack.enter_context(patch.object(module, 'team_id', side_effect=team))
                stack.enter_context(patch.object(module, 'sha256', side_effect=lambda path:
                    TM['vendorCompanions']['cliWrapperSha256'] if str(path) == TM['vendorCompanions']['cliWrapper']
                    else TM['vendorCompanions']['manPageSha256']))
            stack.enter_context(contextlib.redirect_stdout(capture))
            with self.assertRaises(SystemExit) as stopped:
                module.main()
        self.assertEqual(observations, [])
        self.assertLess(events.index('revision'), events.index('manifest'))
        return stopped.exception.code, json.loads(capture.getvalue())

    def test_healthy_components_accept_control_only_successor(self):
        for module in (P, T):
            code, value = self.run_doctor(module)
            self.assertEqual((code, value['problems']), (0, []))
            self.assertFalse(value['configurationRevisionStatus']['revisionExact'])

    def test_current_state_alignment_preserves_component_health_checks(self):
        for module in (P, T):
            for fault in (None, 'signature'):
                code, value = self.run_doctor(module, fault=fault, admission="current-state")
                self.assertEqual(code, 0 if fault is None else 1)
                self.assertTrue(value['checks']['configuration_revision'])
                self.assertEqual(value['configurationRevisionStatus']['sourceAdmissionMode'], 'current-state')
                self.assertEqual(value['configurationRevisionStatus']['state'], 'CURRENT_CONTROL_ONLY_SUCCESSOR')

    def test_component_failures_remain_failures_with_compatible_revision(self):
        for module, faults in ((P, ('default', 'power', 'signature', 'gatekeeper', 'version')),
                               (T, ('signature', 'gatekeeper', 'version'))):
            for fault in faults:
                with self.subTest(module=module.__name__, fault=fault):
                    code, value = self.run_doctor(module, fault=fault)
                    self.assertEqual(code, 1)
                    self.assertEqual(value['result'], 'fail')
                    self.assertTrue(value['checks']['configuration_revision'])
                    self.assertTrue(any(not key.startswith('configuration_revision') for key in value['problems']))

    def test_changed_source_during_component_observation_rejects(self):
        for module in (P, T):
            code, value = self.run_doctor(module, drift=True)
            self.assertEqual(code, 1)
            self.assertIn('configuration_revision_stable', value['problems'])

    def test_source_switch_at_manifest_read_cannot_bind_stale_values_to_new_revision(self):
        for module in (P, T):
            code, value = self.run_doctor(module, manifest_race=True)
            self.assertEqual(code, 1)
            self.assertIn('configuration_revision_stable', value['problems'])


if __name__ == '__main__':
    unittest.main()
