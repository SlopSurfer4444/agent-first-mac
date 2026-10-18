"""Private helper tests; synthetic files only, subprocesses denied by default."""
import importlib.machinery
import importlib.util
import contextlib
import io
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
TEST_ROOT = Path(__file__).resolve().parents[1]
SOURCE = Path(os.environ.get('DS3_ROUTE_TEST_SOURCE', TEST_ROOT / 'bin/ds3-runtime'))
if not SOURCE.is_file():
    SOURCE = TEST_ROOT / 'source/bin/ds3-runtime'


class LiveRequest:
    def record(self):
        return self.pending


def xml(mode='WINDOW', full=('1920', '1080'), window=('1710', '1068'), quality='HIGH'):
    return (f'<?xml version="1.0" encoding="UTF-16"?>\r\n<config>\r\n'
            f'<ScreenMode>{mode}</ScreenMode>\r\n'
            f'<Resolution-FullScreenWidth>{full[0]}</Resolution-FullScreenWidth>\r\n'
            f'<Resolution-FullScreenHeight>{full[1]}</Resolution-FullScreenHeight>\r\n'
            f'<Resolution-WindowScreenWidth>{window[0]}</Resolution-WindowScreenWidth>\r\n'
            f'<Resolution-WindowScreenHeight>{window[1]}</Resolution-WindowScreenHeight>\r\n'
            f'<TextureQuality>{quality}</TextureQuality>\r\n<!-- preserve -->\r\n</config>\r\n').encode('utf-16-le')


def registry(global_emulate='Y', app_emulate='Y', capture='N'):
    return (b'WINE REGISTRY Version 2\n\n' +
            br'[Software\\Wine\\Mac Driver]' + b'\n"RetinaMode"="Y"\n\n' +
            br'[Software\\Wine\\X11 Driver]' + f'\n"EmulateModeset"="{global_emulate}"\n\n'.encode() +
            br'[Software\\Wine\\AppDefaults\\darksoulsiii.exe\\X11 Driver]' + f'\n"EmulateModeset"="{app_emulate}"\n\n'.encode() +
            br'[Software\\Wine\\AppDefaults\\darksoulsiii.exe\\Mac Driver]' + f'\n"CaptureDisplaysForFullscreen"="{capture}"\n"Unrelated"="keep"\n'.encode())


class PersistentFullscreen(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        loader = importlib.machinery.SourceFileLoader('private_persistent_ds3_helper', str(SOURCE))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        cls.h = importlib.util.module_from_spec(spec)
        # Import must remain inert, including accidental subprocess side effects.
        with mock.patch('subprocess.run', side_effect=AssertionError('import subprocess forbidden')), \
                mock.patch('subprocess.Popen', side_effect=AssertionError('import subprocess forbidden')):
            loader.exec_module(cls.h)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ds3-persistent-offline-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve() / 'ds3'
        self.prefix = self.root / 'profiles/ds3'
        self.graphics = self.prefix / self.h.CONFIG_REL
        self.graphics.parent.mkdir(parents=True)
        (self.root / 'logs').mkdir()
        self.graphics.write_bytes(xml())
        self.graphics.chmod(0o600)
        self.reg = self.prefix / 'user.reg'
        self.reg.write_bytes(registry())
        self.reg.chmod(0o600)
        self.steam = self.prefix / 'drive_c/Program Files (x86)/Steam/steam.exe'
        self.steam.parent.mkdir(parents=True)
        self.steam.write_bytes(b'offline synthetic client never executed')
        for name, value in [('ROOT', self.root), ('PREFIX', self.prefix), ('HOME', self.root), ('SOURCE', self.root / 'absent-source')]:
            patch = mock.patch.object(self.h, name, value)
            patch.start()
            self.addCleanup(patch.stop)
        for name in ('run', 'Popen', 'check_output'):
            patch = mock.patch.object(self.h.subprocess, name, side_effect=AssertionError('unmocked process forbidden'))
            patch.start()
            self.addCleanup(patch.stop)

    def test_window_config_retains_existing_dimensions_and_no_registry_requirement(self):
        self.reg.write_bytes(registry('N', 'N', 'Y'))
        result = self.h.verify_window_config()
        self.assertEqual(result['windowMode'], 'WINDOW')
        self.assertEqual((result['windowWidth'], result['windowHeight']), (1710, 1068))

    def test_fullscreen_config_requires_all_three_policy_fields(self):
        self.graphics.write_bytes(xml('FULLSCREEN'))
        self.assertEqual(self.h.verify_window_config()['windowMode'], 'FULLSCREEN')
        for values in [('N', 'Y', 'N'), ('Y', 'N', 'N'), ('Y', 'Y', 'Y')]:
            self.reg.write_bytes(registry(*values))
            with self.subTest(values=values), self.assertRaises(RuntimeError):
                self.h.verify_window_config()

    def test_resolution_plan_changes_selected_mode_fields_only(self):
        for mode in ('WINDOW', 'FULLSCREEN'):
            before = xml(mode)
            after = self.h.resolution_plan(before, '1440')
            expected = xml(mode, full=('2560', '1440')) if mode == 'FULLSCREEN' else xml(mode, window=('2560', '1440'))
            self.assertEqual(after, expected)

    def route(self, mode):
        self.graphics.write_bytes(xml(mode))
        request = mock.Mock()
        request.allow_client.return_value = {'targetActive': False, 'clientActive': False}
        popen = mock.Mock(return_value=mock.Mock())
        override = {'nativeBorderlessCapable': True, 'diagnosticCapable': True}
        base = {'aspectFit': True, 'rendererOverride': override}
        with mock.patch.object(self.h, 'verify_installed', return_value=(base, None)), \
                mock.patch.object(self.h, 'verify_borderless', return_value=({'argv': ['--synthetic']}, None)), \
                mock.patch.object(self.h, 'admission', return_value=request), \
                mock.patch.object(self.h, 'inactive'), mock.patch.object(self.h, 'wine_env', side_effect=lambda *args: {}), \
                mock.patch.object(self.h, 'renderer_fields', return_value=override), \
                mock.patch.object(self.h, 'renderer_hash', return_value='a'*64), \
                mock.patch.object(self.h.subprocess, 'Popen', popen):
            result = self.h.play()
        return result, request, popen

    def test_normal_window_play_retains_native_borderless_route(self):
        self.reg.write_bytes(registry('N', 'N', 'Y'))
        before = self.graphics.read_bytes()
        result, request, popen = self.route('WINDOW')
        self.assertEqual(popen.call_count, 1)
        self.assertEqual(popen.call_args.kwargs['env']['DXMT_DS3_BORDERLESS'], '1')
        self.assertEqual(result['borderlessRoute'], 'native-owner-thread')
        request.dispatched.assert_called_once_with([popen.return_value])
        self.assertEqual(self.graphics.read_bytes(), before)

    def test_window_preference_with_virtual_policy_allows_later_fullscreen_toggle(self):
        before = self.graphics.read_bytes()
        registry_before = self.reg.read_bytes()
        result, request, popen = self.route('WINDOW')
        self.assertEqual(popen.call_count, 1)
        self.assertNotIn('DXMT_DS3_BORDERLESS', popen.call_args.kwargs['env'])
        self.assertEqual(popen.call_args.kwargs['env']['DXMT_DS3_ASPECT_FIT'], '1')
        self.assertEqual(result['windowMode'], 'WINDOW')
        self.assertEqual(result['borderlessRoute'], 'virtual-fullscreen-capable')
        self.assertFalse(result['borderlessRequested'])
        self.assertEqual(self.graphics.read_bytes(), before)
        self.assertEqual(self.reg.read_bytes(), registry_before)
        request.dispatched.assert_called_once_with([popen.return_value])

    def test_window_partial_virtual_policy_preserves_fallback(self):
        for fields in [('N','Y','N'),('Y','N','N'),('Y','Y','Y')]:
            self.reg.write_bytes(registry(*fields))
            result, request, popen = self.route('WINDOW')
            self.assertEqual(result['borderlessRoute'], 'native-owner-thread')
            self.assertEqual(popen.call_args.kwargs['env']['DXMT_DS3_BORDERLESS'], '1')

    @contextlib.contextmanager
    def transaction_gates(self):
        request = mock.Mock()
        request.record.return_value = None
        with mock.patch.object(self.h, 'source_gate') as source, \
                mock.patch.object(self.h, 'window_repair_pending_guard'), \
                mock.patch.object(self.h, 'verify_installed', return_value=({'aspectFit': True}, None)), \
                mock.patch.object(self.h, 'verify_borderless'), \
                mock.patch.object(self.h, 'admission', return_value=request), \
                mock.patch.object(self.h, 'inactive') as inactive:
            yield request, source, inactive

    def test_fullscreen_guard_failure_precedes_admission_and_log_creation(self):
        self.graphics.write_bytes(xml('FULLSCREEN'))
        self.reg.write_bytes(registry('N', 'Y', 'N'))
        with mock.patch.object(self.h, 'verify_installed', return_value=({'aspectFit': True}, None)), \
                mock.patch.object(self.h, 'admission') as admission:
            with self.assertRaisesRegex(RuntimeError, 'virtual_fullscreen_registry_required'):
                self.h.play()
        admission.assert_not_called()
        self.assertFalse((self.root / 'logs/launch-ds3.log').exists())

    def test_plan_without_preset_preserves_existing_fullscreen_dimensions(self):
        before = xml(full=('1710', '1068'))
        graphics, reg, fields = self.h.virtual_fullscreen_plan(before, registry('N', 'N', 'Y'))
        self.assertEqual(graphics, xml('FULLSCREEN', full=('1710', '1068')))
        self.assertEqual(fields['graphics']['before']['Resolution-FullScreenWidth'], '1710')
        for section, name, value in self.h.VIRTUAL_REG_FIELDS:
            self.assertEqual(self.h.virtual_reg_field(reg, section, name)[0].strip(), f'"{name}"="{value}"')

    def test_real_two_file_apply_and_field_merge_rollback(self):
        self.reg.write_bytes(registry('N', 'N', 'Y'))
        before_xml, before_reg = self.graphics.read_bytes(), self.reg.read_bytes()
        apply = 'a'*40
        with self.transaction_gates() as (request, source, inactive):
            result = self.h.virtual_fullscreen(apply, '1440')
            self.assertFalse(result['gameStarted'])
            self.assertTrue(result['changed'])
            self.assertEqual(self.h.virtual_fullscreen_record(apply)['state'], 'complete')
            source.assert_called_with(apply, 'virtual-fullscreen', apply_commit=None)
            self.assertGreaterEqual(inactive.call_count, 2)
            self.graphics.write_bytes(self.graphics.read_bytes().replace('HIGH'.encode('utf-16-le'), 'LOW'.encode('utf-16-le')))
            self.reg.write_bytes(self.reg.read_bytes() + b'\n[Owner]\n"Value"="preserve"\n')
            self.reg.chmod(0o644)
            rolled = self.h.rollback_virtual_fullscreen('b'*40, apply)
        self.assertFalse(rolled['gameStarted'])
        self.assertEqual(self.graphics.read_bytes(), before_xml.replace('HIGH'.encode('utf-16-le'), 'LOW'.encode('utf-16-le')))
        for section, name, _ in self.h.VIRTUAL_REG_FIELDS:
            self.assertEqual(self.h.virtual_reg_field(self.reg.read_bytes(), section, name), self.h.virtual_reg_field(before_reg, section, name))
        self.assertIn(b'"Value"="preserve"', self.reg.read_bytes())
        self.assertEqual(self.reg.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.h.virtual_fullscreen_record(apply)['state'], 'rolled-back')

    def test_complete_same_command_does_not_reset_later_in_game_resolution(self):
        with self.transaction_gates():
            self.h.virtual_fullscreen('a'*40, '1080')
            self.graphics.write_bytes(xml('FULLSCREEN', full=('2560', '1440')))
            current = self.graphics.read_bytes()
            again = self.h.virtual_fullscreen('a'*40, '1080')
        self.assertFalse(again['changed'])
        self.assertEqual(self.graphics.read_bytes(), current)

    def test_rollback_prevalidates_both_owned_field_sets_before_write(self):
        self.reg.write_bytes(registry('N', 'N', 'Y'))
        with self.transaction_gates():
            self.h.virtual_fullscreen('a'*40, '1440')
            self.graphics.write_bytes(xml('FULLSCREEN', full=('3840', '2160')))
            before_xml, before_reg = self.graphics.read_bytes(), self.reg.read_bytes()
            with mock.patch.object(self.h, 'virtual_atomic_replace') as replace:
                with self.assertRaisesRegex(RuntimeError, 'xml_restore_conflict'):
                    self.h.rollback_virtual_fullscreen('b'*40, 'a'*40)
            self.assertFalse(any(call.args[0] in (self.graphics, self.reg) for call in replace.call_args_list),
                             'durable rollback intent may publish, but neither profile file may change')
        self.assertEqual(self.graphics.read_bytes(), before_xml)
        self.assertEqual(self.reg.read_bytes(), before_reg)

    def test_caught_second_file_failure_rolls_back_known_first_file(self):
        self.reg.write_bytes(registry('N', 'N', 'Y'))
        before_xml, before_reg = self.graphics.read_bytes(), self.reg.read_bytes()
        real = self.h.virtual_atomic_replace
        failed = False
        def replace(path, before, after, *args, **kwargs):
            nonlocal failed
            if path == self.graphics and not failed:
                failed = True
                raise OSError('synthetic second file failure')
            return real(path, before, after, *args, **kwargs)
        with self.transaction_gates(), mock.patch.object(self.h, 'virtual_atomic_replace', side_effect=replace):
            with self.assertRaisesRegex(OSError, 'synthetic second file failure'):
                self.h.virtual_fullscreen('a'*40, '1440')
        self.assertEqual(self.graphics.read_bytes(), before_xml)
        self.assertEqual(self.reg.read_bytes(), before_reg)
        self.assertEqual(self.h.virtual_fullscreen_record('a'*40)['state'], 'rolled-back')

    def test_hard_interruption_leaves_prepared_guard_and_exact_same_command_resumes(self):
        self.reg.write_bytes(registry('N', 'N', 'Y'))
        real = self.h.virtual_atomic_replace
        def crash(path, before, after, *args, **kwargs):
            if path == self.graphics:
                raise KeyboardInterrupt('synthetic crash after registry publish')
            return real(path, before, after, *args, **kwargs)
        with self.transaction_gates():
            with mock.patch.object(self.h, 'virtual_atomic_replace', side_effect=crash), self.assertRaises(KeyboardInterrupt):
                self.h.virtual_fullscreen('a'*40, '1440')
            self.assertEqual(self.h.virtual_fullscreen_record('a'*40)['state'], 'prepared')
            with self.assertRaisesRegex(RuntimeError, 'virtual_fullscreen_recovery_required'):
                self.h.virtual_fullscreen_pending_guard()
            self.h.virtual_fullscreen('a'*40, '1440')
        self.assertEqual(self.h.virtual_fullscreen_record('a'*40)['state'], 'complete')
        self.assertEqual(self.graphics.read_bytes(), xml('FULLSCREEN', full=('2560', '1440')))

    def test_changed_backup_or_pending_admission_refuses_before_settings_write(self):
        with self.transaction_gates() as (request, _, _):
            request.record.return_value = {'pending': 'foreign'}
            with mock.patch.object(self.h, 'virtual_atomic_replace') as replace:
                with self.assertRaisesRegex(RuntimeError, 'pending_launch_requires_recovery'):
                    self.h.virtual_fullscreen('a'*40)
                replace.assert_not_called()
            request.record.return_value = None
            self.h.virtual_fullscreen('a'*40)
            transaction = self.h.virtual_fullscreen_transaction('a'*40)
            (transaction/'graphics.before').write_bytes(xml(quality='CORRUPTED'))
            with mock.patch.object(self.h, 'virtual_atomic_replace') as replace:
                with self.assertRaisesRegex(RuntimeError, 'virtual_fullscreen_backup_changed'):
                    self.h.rollback_virtual_fullscreen('b'*40, 'a'*40)
                replace.assert_not_called()

    def test_rollback_interruption_is_guarded_and_cannot_be_reversed_by_forward_retry(self):
        self.reg.write_bytes(registry('N', 'N', 'Y'))
        before_xml = self.graphics.read_bytes()
        real = self.h.virtual_atomic_replace
        def crash(path, before, after, *args, **kwargs):
            if path == self.graphics:
                raise KeyboardInterrupt('synthetic crash during rollback')
            return real(path, before, after, *args, **kwargs)
        with self.transaction_gates():
            self.h.virtual_fullscreen('a'*40, '1440')
            with mock.patch.object(self.h, 'virtual_atomic_replace', side_effect=crash), self.assertRaises(KeyboardInterrupt):
                self.h.rollback_virtual_fullscreen('b'*40, 'a'*40)
            self.assertNotIn(self.h.virtual_fullscreen_record('a'*40)['state'], ('complete', 'rolled-back'))
            with self.assertRaisesRegex(RuntimeError, 'virtual_fullscreen_recovery_required'):
                self.h.virtual_fullscreen_pending_guard()
            with self.assertRaises(RuntimeError):
                self.h.virtual_fullscreen('a'*40, '1440')
            self.h.rollback_virtual_fullscreen('b'*40, 'a'*40)
        self.assertEqual(self.graphics.read_bytes(), before_xml)
        self.assertEqual(self.h.virtual_fullscreen_record('a'*40)['state'], 'rolled-back')

    def test_source_or_active_prefix_gate_refuses_before_journal_or_file_writes(self):
        for gate in ('source_gate', 'inactive'):
            with self.subTest(gate=gate), self.transaction_gates(), \
                    mock.patch.object(self.h, gate, side_effect=RuntimeError('synthetic '+gate)), \
                    mock.patch.object(self.h, 'virtual_atomic_replace') as replace:
                with self.assertRaisesRegex(RuntimeError, 'synthetic '+gate):
                    self.h.virtual_fullscreen('a'*40)
                replace.assert_not_called()
                self.assertFalse(self.h.virtual_fullscreen_transaction('a'*40).exists())
    def test_normal_fullscreen_play_has_no_borderless_optin_or_helper_and_no_xml_reset(self):
        result, request, popen = self.route('FULLSCREEN')
        self.assertEqual(popen.call_count, 1)
        self.assertNotIn('DXMT_DS3_BORDERLESS', popen.call_args.kwargs['env'])
        self.assertEqual(result['borderlessRoute'], 'virtual-fullscreen')
        self.assertFalse(result['borderlessRequested'])
        self.assertEqual(result['windowMode'], 'FULLSCREEN')
        self.assertEqual(self.graphics.read_bytes(), xml('FULLSCREEN'))
        request.begin.assert_called_once()
        request.dispatched.assert_called_once_with([popen.return_value])

    def test_actual_command_dispatch_holds_shared_game_lock_for_both_settings_operations(self):
        state = self.root / 'AIDev/state'
        state.mkdir(parents=True, mode=0o700)
        lock = state / 'games-hub.lock'
        def assert_locked(*args):
            fd = os.open(lock, os.O_RDWR)
            try:
                with self.assertRaises(BlockingIOError):
                    self.h.fcntl.flock(fd, self.h.fcntl.LOCK_EX | self.h.fcntl.LOCK_NB)
            finally:
                os.close(fd)
            return {'state': 'OFFLINE_LOCK_CHECK'}
        for command, function, args in [('virtual-fullscreen', 'virtual_fullscreen', ['a'*40, '1440']),
                                         ('rollback-virtual-fullscreen', 'rollback_virtual_fullscreen', ['b'*40, 'a'*40])]:
            with self.subTest(command=command), mock.patch.object(self.h.sys, 'argv', ['ds3-runtime', command, *args]), \
                    mock.patch.object(self.h, function, side_effect=assert_locked) as call, \
                    contextlib.redirect_stdout(io.StringIO()):
                self.h.main()
            call.assert_called_once_with(*args)

    @contextlib.contextmanager
    def live_route(self, failure=None):
        self.graphics.write_bytes(xml('FULLSCREEN'))
        if failure:
            for name in ('launch-ds3.log', 'borderless-latest.log'):
                (self.root/'logs'/name).unlink(missing_ok=True)
        program = self.root/'runtime/engine/lib/wine/x86_64-windows/reg.exe'
        program.parent.mkdir(parents=True, exist_ok=True)
        program.write_bytes(b'synthetic reg.exe never executed')
        request = LiveRequest()
        request.pending = None
        request.paths = mock.Mock(return_value=(self.steam, None))
        rows = [(700, str(self.steam))]
        request.processes = mock.Mock(return_value=rows)
        request.summary = mock.Mock(return_value={'clientActive': True, 'targetActive': False, 'foreignSteam': False})
        request.allow_client = mock.Mock(return_value={'clientActive': True, 'targetActive': False})
        request.reconcile, request.dispatched = mock.Mock(), mock.Mock()
        identity = {'pid': 700, 'birth': '100:1', 'group': 700}
        identities = mock.Mock(return_value=identity)
        events = []
        request.begin = mock.Mock(side_effect=lambda: events.append('begin'))
        if failure == 'changed-client':
            identities.side_effect = [identity, {**identity, 'birth': '999:1'}]
        if failure == 'late-client-change':
            identities.side_effect = [identity, identity, {**identity, 'birth': '999:1'}]
        if failure == 'changed-comm':
            request.processes.side_effect = [rows, [(701, str(self.steam))]]
        if failure == 'foreign-steam':
            request.summary.return_value['foreignSteam'] = True
        def query(args, **kwargs):
            self.assertEqual(args[:3], [str(self.root/'runtime/engine/bin/wine'), str(program), 'query'])
            self.assertEqual(args[-2], '/v')
            self.assertEqual(kwargs['env']['WINEPREFIX'], str(self.prefix))
            self.assertNotIn('DS3_TEST_POISON', kwargs['env'])
            self.assertNotIn('DXMT_DS3_BORDERLESS', kwargs['env'])
            self.assertLessEqual(kwargs['timeout'], 3)
            events.append('query')
            if failure == 'timeout':
                raise self.h.subprocess.TimeoutExpired(args, kwargs['timeout'])
            name = args[-1]
            expected = 'N' if name == 'CaptureDisplaysForFullscreen' else 'Y'
            if failure == 'disk-live-mismatch': expected = 'N' if expected == 'Y' else 'Y'
            kind = 'REG_DWORD' if failure == 'wrong-type' else 'REG_SZ'
            raw = (args[3].replace('HKCU', 'HKEY_CURRENT_USER', 1)+'\n    '+name+'    '+kind+'    '+expected+'\n').encode()
            if failure == 'duplicate':raw += raw.splitlines()[1]+b'\n'
            if failure == 'late-pending':request.pending = {'foreign': 'reservation'}
            return mock.Mock(returncode=1 if failure == 'query-error' else 0, stderr=b'', stdout=raw)
        override = {'nativeBorderlessCapable': True, 'diagnosticCapable': True}
        popen = mock.Mock(return_value=mock.Mock())
        with mock.patch.dict(LiveRequest.record.__globals__, {'process_identity': identities, 'valid_identity': lambda v: v == identity}), \
                mock.patch.dict(os.environ, {'DS3_TEST_POISON': 'must-not-inherit'}), \
                mock.patch.object(self.h, 'verify_installed', return_value=({'aspectFit': True, 'rendererOverride': override}, None)), \
                mock.patch.object(self.h, 'verify_borderless', return_value=({'argv': []}, None)), \
                mock.patch.object(self.h, 'renderer_fields', return_value=override), \
                mock.patch.object(self.h, 'renderer_hash', return_value='a'*64), \
                mock.patch.object(self.h, 'admission', return_value=request), \
                mock.patch.object(self.h, 'inactive') as inactive, \
                mock.patch.object(self.h.subprocess, 'run', side_effect=query) as run, \
                mock.patch.object(self.h.subprocess, 'Popen', popen):
            yield request, run, popen, inactive, events

    def test_retained_steam_window_preference_keeps_virtual_policy_queries(self):
        with self.live_route() as (request, run, popen, inactive, events):
            self.graphics.write_bytes(xml('WINDOW'))
            before = self.graphics.read_bytes()
            result = self.h.play()
            self.assertEqual(run.call_count, 3)
            self.assertEqual(events, ['query','query','query','begin'])
            self.assertNotIn('DXMT_DS3_BORDERLESS', popen.call_args.kwargs['env'])
            self.assertEqual(result['borderlessRoute'], 'virtual-fullscreen-capable')
            self.assertEqual(self.graphics.read_bytes(), before)
            inactive.assert_not_called()

    def test_retained_steam_actual_play_queries_live_registry_before_begin(self):
        with self.live_route() as (request, run, popen, inactive, events):
            result = self.h.play()
        self.assertEqual(run.call_count, 3)
        self.assertEqual(events, ['query', 'query', 'query', 'begin'])
        self.assertEqual(request.processes.call_count, 2)
        self.assertEqual(result['virtualFullscreenPolicy']['state'], 'LIVE_REGISTRY_VERIFIED')
        self.assertEqual(result['virtualFullscreenPolicy']['fields'], 3)
        request.dispatched.assert_called_once_with([popen.return_value])
        self.assertEqual(popen.call_count, 1)
        inactive.assert_not_called()

    def test_retained_steam_live_policy_failures_never_begin_or_create_launch_log(self):
        failures = ('disk-live-mismatch', 'wrong-type', 'duplicate', 'query-error', 'timeout',
                    'changed-client', 'late-client-change', 'changed-comm', 'foreign-steam', 'late-pending')
        for failure in failures:
            with self.subTest(failure=failure), self.live_route(failure) as (request, run, popen, inactive, events):
                with self.assertRaises((RuntimeError, self.h.subprocess.TimeoutExpired)):
                    self.h.play()
                request.begin.assert_not_called()
                popen.assert_not_called()
                self.assertFalse((self.root/'logs/launch-ds3.log').exists())

    def test_live_query_total_deadline_includes_first_process_list(self):
        with self.live_route() as (request, run, popen, inactive, events), \
                mock.patch.object(self.h.time, 'monotonic', side_effect=[0, 9]):
            with self.assertRaisesRegex(RuntimeError, 'virtual_fullscreen_live_query_deadline'):
                self.h.play()
        request.begin.assert_not_called()
        run.assert_not_called()
        popen.assert_not_called()

    def test_live_query_parser_rejects_wrong_key_extra_output_nonascii_and_value(self):
        section, name, expected = self.h.VIRTUAL_REG_FIELDS[0]
        key = section.replace('\\\\', '\\')
        valid = ('HKEY_CURRENT_USER\\'+key+'\n'+name+' REG_SZ '+expected+'\n').encode()
        self.h.virtual_live_query_value(valid, section, name, expected)
        for raw in (valid.replace(b'HKEY_CURRENT_USER', b'HKEY_LOCAL_MACHINE'), valid+b'extra\n',
                    valid+b'\xff', valid.replace(b'REG_SZ Y', b'REG_SZ N'), valid.replace(b'REG_SZ', b'REG_EXPAND_SZ')):
            with self.subTest(raw=raw[:40]), self.assertRaises(RuntimeError):
                self.h.virtual_live_query_value(raw, section, name, expected)

    def test_staging_failure_is_inert_and_does_not_poison_normal_pending_guard(self):
        before_xml, before_reg = self.graphics.read_bytes(), self.reg.read_bytes()
        real = self.h.virtual_write_private
        def fail(path, raw):
            if path.name == 'graphics.after':raise OSError('synthetic staging failure')
            return real(path, raw)
        with self.transaction_gates(), mock.patch.object(self.h, 'virtual_write_private', side_effect=fail):
            with self.assertRaisesRegex(OSError, 'synthetic staging failure'):
                self.h.virtual_fullscreen('a'*40)
        self.assertFalse(self.h.virtual_fullscreen_transaction('a'*40).exists())
        self.assertTrue(list(self.root.glob('.vfs-settings-*')))
        self.assertEqual(self.graphics.read_bytes(), before_xml)
        self.assertEqual(self.reg.read_bytes(), before_reg)
        self.h.virtual_fullscreen_pending_guard()

    def test_oversize_record_is_rejected_before_stage_or_profile_publication(self):
        self.reg.write_bytes(registry().replace(b'"EmulateModeset"="Y"', b'"EmulateModeset"="'+b'X'*70000+b'"', 1))
        before_xml, before_reg = self.graphics.read_bytes(), self.reg.read_bytes()
        with self.transaction_gates(), mock.patch.object(self.h, 'virtual_atomic_replace') as replace:
            with self.assertRaisesRegex(RuntimeError, 'virtual_fullscreen_record_size'):
                self.h.virtual_fullscreen('a'*40)
            replace.assert_not_called()
        self.assertFalse(list(self.root.glob('.vfs-settings-*')))
        self.assertFalse(self.h.virtual_fullscreen_transaction('a'*40).exists())
        self.assertEqual(self.graphics.read_bytes(), before_xml)
        self.assertEqual(self.reg.read_bytes(), before_reg)


if __name__ == '__main__':
    unittest.main(verbosity=2)
