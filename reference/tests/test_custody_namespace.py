"""Private disposable fixtures only; simulated boots never reboot the host."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace as NS
from unittest.mock import patch

from lib import vendor_fixture_custody as C


class NamespaceTests(unittest.TestCase):
    def open(self, root, boot='a' * 64, **kwargs):
        return C.Custody(root, root, os.getuid(), envelope=lambda *args: None,
                         boot_identity=lambda: boot, **kwargs)

    def marker(self, root):
        return Path(root) / C.NAMESPACE / 'namespace.json'

    def seed(self, root, *, slot=False):
        with self.open(root) as c:
            if slot:
                c.reserve()
        path = self.marker(root)
        value = json.loads(path.read_text())
        self.assertEqual(value['schema'], 2)
        return value

    def write(self, root, value):
        self.marker(root).write_text(json.dumps(value))

    def stale_device(self, value):
        value['identity'][0] += 100
        value['lock'][0] += 100

    def test_cross_boot_empty_namespace_device_refresh_and_next_allocation(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as d:
            old = self.seed(d)
            self.stale_device(old)
            self.write(d, old)
            with self.open(d, 'b' * 64) as c:
                new = json.loads(self.marker(d).read_text())
                self.assertEqual(new['boot'], 'b' * 64)
                self.assertNotEqual(old['identity'][0], new['identity'][0])
                self.assertEqual(old['persistent'], new['persistent'])
                self.assertEqual(c.reserve(), 0)

    def test_same_boot_device_change_refuses_without_rewrite(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as d:
            old = self.seed(d)
            self.stale_device(old)
            self.write(d, old)
            before = self.marker(d).read_bytes()
            with self.assertRaises(C.CustodyError):
                self.open(d)
            self.assertEqual(self.marker(d).read_bytes(), before)

    def test_namespace_refresh_preserves_legacy_slot_without_rebinding_it(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as d:
            old = self.seed(d, slot=True)
            self.stale_device(old)
            self.write(d, old)
            before = self.marker(d).read_bytes()
            slot = self.marker(d).with_name('0.json')
            legacy = json.loads(slot.read_bytes())
            legacy['schema'] = 1
            legacy.pop('output')
            legacy.pop('provenance')
            slot.write_text(json.dumps(legacy))
            slot_before = slot.read_bytes()
            with self.open(d, 'b' * 64) as custody:
                self.assertEqual(custody.records()[0], legacy)
            self.assertNotEqual(self.marker(d).read_bytes(), before)
            self.assertEqual(slot.read_bytes(), slot_before)

    def test_other_persistent_identity_changes_are_never_rebound(self):
        for component in ('identity', 'lock', 'directory-volume', 'lock-volume',
                          'directory-birth', 'lock-birth'):
            with self.subTest(component=component), tempfile.TemporaryDirectory(dir='/private/tmp') as d:
                old = self.seed(d)
                self.stale_device(old)
                if component in ('identity', 'lock'):
                    old[component][1] += 1
                else:
                    part, field = component.split('-')
                    if field == 'volume':
                        old['persistent'][part][field] = 'f' * 32
                    else:
                        old['persistent'][part][field][0] += 1
                self.write(d, old)
                before = self.marker(d).read_bytes()
                with self.assertRaises(C.CustodyError):
                    self.open(d, 'b' * 64)
                self.assertEqual(self.marker(d).read_bytes(), before)

    def test_provider_failure_is_not_a_device_ignore_fallback(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as d:
            old = self.seed(d)
            self.stale_device(old)
            self.write(d, old)
            before = self.marker(d).read_bytes()
            for value in (None, {'volume': '0' * 32, 'birth': [1, 0]}):
                with self.assertRaises(C.CustodyError):
                    self.open(d, 'b' * 64, persistent_identity=lambda fd: value)
            with self.assertRaises(OSError):
                self.open(d, 'b' * 64, persistent_identity=lambda fd: (_ for _ in ()).throw(OSError('unavailable')))
            self.assertEqual(self.marker(d).read_bytes(), before)

    def test_legacy_exact_empty_marker_upgrades_but_device_mismatch_does_not(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as d:
            old = self.seed(d)
            old = {k: v for k, v in old.items() if k in ('schema', 'identity', 'lock')}
            old['schema'] = 1
            self.write(d, old)
            with self.open(d):
                self.assertEqual(json.loads(self.marker(d).read_text())['schema'], 2)
            self.stale_device(old)
            self.write(d, old)
            before = self.marker(d).read_bytes()
            with self.assertRaises(C.CustodyError):
                self.open(d, 'b' * 64)
            self.assertEqual(self.marker(d).read_bytes(), before)

    def test_legacy_nonempty_exact_marker_keeps_existing_semantics(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as d:
            old = self.seed(d, slot=True)
            old = {k: v for k, v in old.items() if k in ('schema', 'identity', 'lock')}
            old['schema'] = 1
            self.write(d, old)
            with self.open(d) as c:
                self.assertEqual(json.loads(self.marker(d).read_text()), old)
                self.assertEqual(len(c.records()), 1)

    def test_named_lock_replacement_at_refresh_refuses(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as d:
            old = self.seed(d)
            self.stale_device(old)
            self.write(d, old)
            before = self.marker(d).read_bytes()
            def race(point):
                if point == 'namespace-refresh-ready':
                    lock = self.marker(d).with_name('lock')
                    lock.rename(lock.with_name('old-lock'))
                    lock.touch(mode=0o600)
            with self.assertRaises(C.CustodyError):
                self.open(d, 'b' * 64, checkpoint=race)
            self.assertEqual(self.marker(d).read_bytes(), before)

    def test_slot_appearing_at_refresh_refuses(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as d:
            old = self.seed(d)
            self.stale_device(old)
            self.write(d, old)
            before = self.marker(d).read_bytes()
            def race(point):
                if point == 'namespace-refresh-ready':
                    self.marker(d).with_name('0.json').write_text('preserve')
            with self.assertRaises(C.CustodyError):
                self.open(d, 'b' * 64, checkpoint=race)
            self.assertEqual(self.marker(d).read_bytes(), before)

    def test_marker_is_reread_after_lock_not_only_before(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as d:
            old = self.seed(d)
            self.stale_device(old)
            self.write(d, old)
            original = C.fcntl.flock
            def race(fd, mode):
                result = original(fd, mode)
                if mode == C.fcntl.LOCK_EX | C.fcntl.LOCK_NB:
                    changed = dict(old, boot='b' * 64)
                    self.write(d, changed)
                return result
            with patch.object(C.fcntl, 'flock', side_effect=race), self.assertRaises(C.CustodyError):
                self.open(d, 'b' * 64)

    def test_slot_appearing_after_temporary_marker_write_prevents_publication(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as d:
            old = self.seed(d)
            self.stale_device(old)
            self.write(d, old)
            before = self.marker(d).read_bytes()
            def race(point):
                if point == 'record-written':
                    self.marker(d).with_name('0.json').write_text('preserve')
            with self.assertRaises(C.CustodyError):
                self.open(d, 'b' * 64, checkpoint=race)
            self.assertEqual(self.marker(d).read_bytes(), before)
            self.assertEqual(self.marker(d).with_name('0.json').read_text(), 'preserve')

    def test_interrupted_refresh_has_durable_transaction_and_recovers(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as d:
            old = self.seed(d)
            self.stale_device(old)
            self.write(d, old)
            before = self.marker(d).read_bytes()
            def stop(point):
                if point == 'record-written':
                    raise RuntimeError('injected interruption')
            with self.assertRaises(RuntimeError):
                self.open(d, 'b' * 64, checkpoint=stop)
            self.assertEqual(self.marker(d).read_bytes(), before)
            pending, = self.marker(d).parent.glob('.prepare-*.payload')
            self.assertTrue(self.marker(d).with_name(C.TRANSACTION).exists())
            with self.open(d, 'b' * 64):
                pass
            self.assertFalse(pending.exists())
            self.assertFalse(self.marker(d).with_name(C.TRANSACTION).exists())

    def test_native_stable_volume_provider_reads_held_directory_and_lock(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as d:
            value = self.seed(d)
            self.assertEqual(value['persistent']['directory']['volume'], value['persistent']['lock']['volume'])
            self.assertEqual(len(value['persistent']['directory']['volume']), 32)

    def test_connected_readonly_status_never_migrates_or_refreshes_marker(self):
        from lib import current_doctor_native as N
        doctor = NS(require=C.need, D=NS(R=NS(integrations=NS(_path=lambda value: True))))
        with tempfile.TemporaryDirectory(dir='/private/tmp') as home:
            scratch = Path(home) / 'AIDev' / 'scratch'
            scratch.mkdir(parents=True, mode=0o700)
            scratch.parent.chmod(0o700)
            root = str(scratch)
            old = self.seed(root)
            legacy = {k: v for k, v in old.items() if k in ('schema', 'identity', 'lock')}
            legacy['schema'] = 1
            self.write(root, legacy)
            before = self.marker(root).read_bytes()
            with patch.object(N.pwd, 'getpwuid', return_value=NS(pw_dir=home)), \
                    patch.object(N.probe, 'require_fixture_envelope', lambda *args: None), \
                    patch.object(C, 'namespace_boot', return_value='a' * 64):
                self.assertEqual(N.custody_cli(doctor)['outstanding'], 0)
            self.assertEqual(self.marker(root).read_bytes(), before)
            self.stale_device(old)
            self.write(root, old)
            before = self.marker(root).read_bytes()
            with patch.object(N.pwd, 'getpwuid', return_value=NS(pw_dir=home)), \
                    patch.object(N.probe, 'require_fixture_envelope', lambda *args: None), \
                    patch.object(C, 'namespace_boot', return_value='b' * 64):
                report = N.custody_cli(doctor)
                self.assertEqual(report['outstanding'], 0)
                self.assertEqual(report['capacityReason'], 'fixture_namespace_refresh_required')
            self.assertEqual(self.marker(root).read_bytes(), before)
            self.assertEqual(set(p.name for p in self.marker(root).parent.iterdir()), {'lock', 'namespace.json'})

    def test_readonly_retained_crossboot_status_preserves_records_and_blocks_mutation(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as d:
            old = self.seed(d, slot=True)
            self.stale_device(old)
            self.write(d, old)
            before = {p.name: p.read_bytes() for p in self.marker(d).parent.iterdir()}
            with self.open(d, 'b' * 64, create=False) as custody:
                report = custody.status()
                self.assertEqual(report['outstanding'], 1)
                self.assertTrue(report['namespaceRefreshRequired'])
                for action in (lambda: custody.reserve(),
                               lambda: custody.update(0, state='retiring'),
                               lambda: custody.release_absent(0)):
                    with self.assertRaisesRegex(C.CustodyError, 'fixture_namespace_refresh_required'):
                        action()
            self.assertEqual(before, {p.name: p.read_bytes() for p in self.marker(d).parent.iterdir()})
            with self.open(d, 'b' * 64, create=False) as custody:
                self.assertTrue(custody.retire(0)['retired'])

    def test_same_device_crossboot_retained_record_can_refresh_or_retire_exact_absence(self):
        for create in (False, True):
            with self.subTest(create=create), tempfile.TemporaryDirectory(dir='/private/tmp') as d:
                self.seed(d, slot=True)
                before = self.marker(d).read_bytes()
                slot_before = self.marker(d).with_name('0.json').read_bytes()
                with self.open(d, 'b' * 64, create=create) as custody:
                    self.assertEqual(self.marker(d).with_name('0.json').read_bytes(), slot_before)
                    if not create:
                        self.assertEqual(self.marker(d).read_bytes(), before)
                        with self.assertRaisesRegex(C.CustodyError, 'fixture_namespace_refresh_required'):
                            custody.reserve()
                    self.assertTrue(custody.retire(0)['retired'])
                with self.open(d, 'b' * 64) as custody:
                    self.assertEqual(custody.reserve(), 0)

    def test_retained_record_changed_during_namespace_refresh_is_not_rebound(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as d:
            self.seed(d, slot=True)
            before = self.marker(d).read_bytes()
            def race(point):
                if point == 'record-written':
                    slot = self.marker(d).with_name('0.json')
                    value = json.loads(slot.read_bytes())
                    value['settled'] = False
                    slot.write_text(json.dumps(value))
            with self.assertRaises(C.CustodyError):
                self.open(d, 'b' * 64, checkpoint=race)
            self.assertEqual(self.marker(d).read_bytes(), before)
            self.assertFalse(json.loads(self.marker(d).with_name('0.json').read_bytes())['settled'])

    def test_known_settled_tree_retires_crossboot_but_unsettled_tree_never_does(self):
        for settled in (True, False):
            with self.subTest(settled=settled), tempfile.TemporaryDirectory(dir='/private/tmp') as d:
                with self.open(d) as custody:
                    slot = custody.reserve()
                    root = Path(d) / custody.leaf(custody.records()[slot])
                    root.mkdir(mode=0o700)
                    child = root / 'home'
                    child.mkdir(mode=0o700)
                    custody.update(slot, root=C.identity(root.stat()),
                                   children={'home': C.identity(child.stat())},
                                   state='retained', settled=settled)
                with self.open(d, 'b' * 64, create=False) as custody:
                    self.assertEqual(custody.status()['slots'][0]['settled'], settled)
                    if settled:
                        self.assertTrue(custody.retire(slot)['retired'])
                        self.assertFalse(root.exists())
                    else:
                        with self.assertRaisesRegex(C.CustodyError, 'fixture_settlement_required'):
                            custody.retire(slot)
                        self.assertTrue(child.is_dir())

    def test_pending_metadata_is_observable_but_never_interpreted_as_authority(self):
        for leaf in ('namespace.json.pending', '0.json.pending'):
            with self.subTest(leaf=leaf), tempfile.TemporaryDirectory(dir='/private/tmp') as d:
                self.seed(d, slot=True)
                pending = self.marker(d).with_name(leaf)
                pending.write_bytes(b'unknown incomplete write')
                before = {p.name: p.read_bytes() for p in pending.parent.iterdir()}
                with self.open(d, create=False) as custody:
                    report = custody.status()
                    self.assertEqual(report['pendingMetadataCount'], 1)
                    self.assertEqual(report['capacityReason'], 'fixture_metadata_pending')
                    with self.assertRaisesRegex(C.CustodyError, 'fixture_metadata_pending'):
                        custody.retire(0)
                with self.assertRaises(C.CustodyError):
                    self.open(d)
                self.assertEqual(before, {p.name: p.read_bytes() for p in pending.parent.iterdir()})

    def test_each_reservation_publication_interruption_keeps_status_available(self):
        for point in ('record-written', 'record-published', 'record-durable', 'reservation-durable'):
            with self.subTest(point=point), tempfile.TemporaryDirectory(dir='/private/tmp') as d:
                with self.open(d) as custody:
                    def stop(current):
                        if current == point:
                            raise RuntimeError('publication interrupted')
                    custody.checkpoint = stop
                    with self.assertRaisesRegex(RuntimeError, 'publication interrupted'):
                        custody.reserve()
                before = {p.name: p.read_bytes() for p in self.marker(d).parent.iterdir()}
                with self.open(d, create=False) as custody:
                    report = custody.status()
                    self.assertEqual(report['outstanding'], int(point != 'record-written'))
                    self.assertEqual(report['pendingMetadataCount'],
                                     2 if point == 'record-written' else int(point in ('record-published', 'record-durable')))
                self.assertEqual(before, {p.name: p.read_bytes() for p in self.marker(d).parent.iterdir()})


if __name__ == '__main__':
    unittest.main()
