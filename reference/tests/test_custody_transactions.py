"""Restart-safe metadata publication in disposable owner fixtures only."""
import contextlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from lib import vendor_fixture_custody as C


class TransactionTests(unittest.TestCase):
    def open(self, root, boot='a' * 64, **kwargs):
        return C.Custody(root, root, os.getuid(), envelope=lambda *args: None,
                         boot_identity=lambda: boot, **kwargs)

    def crash(self, wanted):
        def checkpoint(point):
            if point == wanted:
                raise RuntimeError('crash')
        return checkpoint

    def snapshot(self, root):
        return {str(p.relative_to(root)): (p.stat().st_ino, p.read_bytes())
                for p in Path(root).rglob('*') if p.is_file()}

    def test_initial_namespace_is_never_published_incomplete(self):
        for point in ('namespace-prepared', 'namespace-ready', 'namespace-published'):
            with self.subTest(point=point), tempfile.TemporaryDirectory(dir='/private/tmp') as root:
                with self.assertRaisesRegex(RuntimeError, 'crash'):
                    self.open(root, checkpoint=self.crash(point))
                target = Path(root) / C.NAMESPACE
                if target.exists():
                    self.assertEqual({p.name for p in target.iterdir()}, {'namespace.json', 'lock'})
                preserved = self.snapshot(root)
                with self.open(root) as custody:
                    self.assertEqual(custody.status()['outstanding'], 0)
                self.assertEqual({name: self.snapshot(root)[name] for name in preserved}, preserved)

    def test_transaction_crash_points_observable_and_retryable(self):
        for point in ('record-written', 'transaction-prepared', 'transaction-ready',
                      'record-published', 'record-durable', 'transaction-cleared'):
            with self.subTest(point=point), tempfile.TemporaryDirectory(dir='/private/tmp') as root:
                with self.open(root) as custody:
                    pass
                with self.assertRaisesRegex(RuntimeError, 'crash'):
                    with self.open(root, checkpoint=self.crash(point)) as custody:
                        custody.reserve()
                before = self.snapshot(root)
                with self.open(root, create=False) as custody:
                    self.assertIn(custody.status()['outstanding'], (0, 1))
                self.assertEqual(self.snapshot(root), before, 'status mutated interrupted state')
                with self.open(root) as custody:
                    expected = 0 if point == 'transaction-prepared' else 1
                    self.assertEqual(custody.status()['outstanding'], expected)
                    self.assertNotIn(C.TRANSACTION, os.listdir(custody.directory.descriptor))
                    # Complete transactions never leave payload aliases/hard links.
                    if expected:
                        self.assertEqual((Path(root) / C.NAMESPACE / '0.json').stat().st_nlink, 1)
                        self.assertTrue(custody.retire(0)['retired'])
                    custody.reserve()

    def test_foreign_namespace_preparation_is_never_published(self):
        for change in ('member', 'marker', 'lock'):
            with self.subTest(change=change), tempfile.TemporaryDirectory(dir='/private/tmp') as root:
                retained = []
                def interfere(point):
                    if point != 'namespace-ready':
                        return
                    staged, = Path(root).glob('.' + C.NAMESPACE + '-*')
                    retained.append(staged)
                    if change == 'member':
                        (staged / 'owner-file').write_bytes(b'preserve owner data')
                    elif change == 'marker':
                        marker = staged / 'namespace.json'
                        value = json.loads(marker.read_bytes())
                        value['identity'][1] += 1
                        marker.write_text(json.dumps(value))
                    else:
                        (staged / 'lock').rename(staged / 'preserved-lock')
                        (staged / 'lock').touch(mode=0o600)
                with self.assertRaises(C.CustodyError):
                    self.open(root, checkpoint=interfere)
                self.assertFalse((Path(root) / C.NAMESPACE).exists())
                before = self.snapshot(retained[0])
                with self.open(root) as custody:
                    self.assertEqual(custody.status()['outstanding'], 0)
                self.assertEqual(self.snapshot(retained[0]), before)

    def test_every_successful_write_mkdir_fsync_and_rename_interruption_recovers(self):
        operations = [(C.os, key) for key in ('mkdir', 'write', 'fsync', 'replace', 'unlink')]
        operations.append((C, 'rename_exclusive'))
        def run(root, fail_at=None):
            events = []
            with contextlib.ExitStack() as stack:
                for module, name in operations:
                    real = getattr(module, name)
                    def wrapped(*args, _real=real, _name=name, **kwargs):
                        result = _real(*args, **kwargs)
                        events.append(_name)
                        if len(events) == fail_at:
                            raise RuntimeError('crash')
                        return result
                    stack.enter_context(patch.object(module, name, wrapped))
                with self.open(root) as custody:
                    slot = custody.reserve()
                    custody.update(slot, state='retained')
            return events
        with tempfile.TemporaryDirectory(dir='/private/tmp') as root:
            events = run(root)
        for index, name in enumerate(events, 1):
            with self.subTest(index=index, operation=name), tempfile.TemporaryDirectory(dir='/private/tmp') as root:
                with self.assertRaisesRegex(RuntimeError, 'crash'):
                    run(root, index)
                with self.open(root) as custody:
                    self.assertNotIn(C.TRANSACTION, os.listdir(custody.directory.descriptor))
                    self.assertIn(custody.status()['outstanding'], (0, 1))

    def test_foreign_preimage_or_payload_is_preserved_and_refused(self):
        for target in ('preimage', 'payload'):
            with self.subTest(target=target), tempfile.TemporaryDirectory(dir='/private/tmp') as root:
                with self.open(root) as custody:
                    custody.reserve()
                with self.assertRaisesRegex(RuntimeError, 'crash'):
                    with self.open(root, checkpoint=self.crash('transaction-ready')) as custody:
                        custody.update(0, state='retained')
                directory = Path(root) / C.NAMESPACE
                journal = json.loads((directory / C.TRANSACTION).read_text())
                path = directory / ('0.json' if target == 'preimage' else journal['candidate'])
                value = json.loads(path.read_text())
                value['reason'] = 'foreign-change'
                path.write_text(json.dumps(value))
                before = self.snapshot(root)
                with self.assertRaises(C.CustodyError):
                    self.open(root)
                self.assertEqual(self.snapshot(root), before)

    def test_partial_preparation_write_and_budget_preserve_unknown_bytes(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as root:
            with self.open(root):
                pass
            real = C.os.write
            def short_crash(fd, raw):
                real(fd, raw[:max(1, len(raw) // 2)])
                raise RuntimeError('crash')
            with self.open(root) as custody, patch.object(C.os, 'write', short_crash):
                with self.assertRaisesRegex(RuntimeError, 'crash'):
                    custody.reserve()
            directory = Path(root) / C.NAMESPACE
            pending = next(directory.glob('.prepare-*.payload'))
            before = pending.read_bytes()
            with self.open(root) as custody:
                custody.reserve()
            self.assertEqual(pending.read_bytes(), before)
        with tempfile.TemporaryDirectory(dir='/private/tmp') as root:
            with self.open(root):
                pass
            directory = Path(root) / C.NAMESPACE
            for index in range(C.MAX_PREPARATIONS * 2):
                (directory / ('.prepare-%032x.payload' % index)).write_bytes(b'unknown')
            before = self.snapshot(root)
            with self.open(root) as custody:
                with self.assertRaisesRegex(C.CustodyError, 'fixture_preparation_capacity'):
                    custody.reserve()
            self.assertEqual(self.snapshot(root), before)

    def test_explicit_reconcile_does_not_create_missing_namespace(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as root:
            with self.assertRaisesRegex(C.CustodyError, 'fixture_custody_absent'):
                self.open(root, create=False, reconcile=True)
            self.assertEqual(list(Path(root).iterdir()), [])

    def test_repeated_known_prelaunch_interruptions_retry_without_capacity_debt(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as root:
            with self.open(root):
                pass
            for _ in range(C.MAX_PREPARATIONS * 2):
                with self.assertRaisesRegex(RuntimeError, 'crash'):
                    with self.open(root, checkpoint=self.crash('record-written')) as custody:
                        custody.reserve()
            with self.open(root) as custody:
                slot = custody.reserve()
                self.assertEqual(slot, 0)
                report = custody.status()
                self.assertEqual(report['outstanding'], 1)
                self.assertIsNone(report['capacityReason'])
                self.assertEqual(report['preparationCount'], 0)
                self.assertEqual(report['pendingMetadataCount'], 0)

    def test_unknown_preparation_capacity_debt_is_visible_and_preserved(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as root:
            with self.open(root):
                pass
            directory = Path(root) / C.NAMESPACE
            for index in range(C.MAX_PREPARATIONS * 2):
                (directory / ('.prepare-%032x.payload' % index)).write_bytes(b'unknown')
            before = self.snapshot(root)
            with self.open(root, create=False) as custody:
                report = custody.status()
                self.assertEqual(report['capacityReason'], 'fixture_preparation_capacity')
                self.assertEqual(report['preparationReason'], 'fixture_preparation_recovery_required')
                self.assertEqual(report['preparationCount'], C.MAX_PREPARATIONS * 2)
                self.assertEqual(report['pendingMetadataCount'], C.MAX_PREPARATIONS * 2)
                self.assertEqual(report['retainedBytesObserved'], 7 * C.MAX_PREPARATIONS * 2)
                self.assertEqual(report['entriesObserved'], C.MAX_PREPARATIONS * 2)
                self.assertEqual(report['nextAction'], 'preserve-preparations-for-bounded-recovery')
            with self.open(root) as custody, self.assertRaisesRegex(C.CustodyError, 'fixture_preparation_capacity'):
                custody.reserve()
            self.assertEqual(self.snapshot(root), before)

    def test_status_remains_available_above_preparation_allocation_limit(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as root:
            with self.open(root):
                pass
            directory = Path(root) / C.NAMESPACE
            for index in range(C.MAX_PREPARATIONS * 2 + 1):
                (directory / ('.prepare-%032x.payload' % index)).write_bytes(b'foreign bytes')
            before = self.snapshot(root)
            with self.open(root, create=False) as custody:
                report = custody.status()
                self.assertEqual(report['preparationCount'], 65)
                self.assertEqual(report['retainedBytesObserved'], 65 * len(b'foreign bytes'))
                self.assertEqual(report['capacityReason'], 'fixture_preparation_capacity')
                self.assertEqual(report['nextAction'], 'preserve-preparations-for-bounded-recovery')
            with self.assertRaisesRegex(C.CustodyError, 'fixture_preparation_capacity'):
                self.open(root)
            self.assertEqual(self.snapshot(root), before)

    def test_publication_requires_room_for_both_preparation_names(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as root:
            with self.open(root):
                pass
            directory = Path(root) / C.NAMESPACE
            for index in range(C.MAX_PREPARATIONS * 2 - 1):
                (directory / ('.prepare-%032x.payload' % index)).write_bytes(b'unknown')
            before = self.snapshot(root)
            with self.open(root) as custody, self.assertRaisesRegex(C.CustodyError, 'fixture_preparation_capacity'):
                custody.reserve()
            with self.open(root, create=False) as custody:
                self.assertEqual(custody.status()['preparationCount'], 63)
                self.assertEqual(custody.status()['capacityReason'], 'fixture_preparation_capacity')
            self.assertEqual(self.snapshot(root), before)

    def test_same_process_reservations_are_not_auto_retired(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as root:
            with self.open(root) as custody:
                self.assertEqual(custody.reserve(), 0)
                self.assertEqual(custody.reserve(), 1)
                self.assertEqual(custody.status()['outstanding'], 2)

    def test_unknown_root_or_unsettled_empty_reservation_is_never_auto_retired(self):
        for case in ('unknown-root', 'unsettled'):
            with self.subTest(case=case), tempfile.TemporaryDirectory(dir='/private/tmp') as root:
                with self.open(root) as custody:
                    slot = custody.reserve()
                    if case == 'unknown-root':
                        foreign = Path(root) / custody.leaf(custody.records()[slot])
                        foreign.mkdir(mode=0o700)
                        (foreign / 'owner-file').write_bytes(b'preserve')
                    else:
                        custody.update(slot, settled=False)
                before = self.snapshot(root)
                with self.open(root) as custody, self.assertRaises(C.CustodyError):
                    custody.reserve()
                self.assertEqual(self.snapshot(root), before)

    def test_unknown_transaction_fields_preserved_without_mutation(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as root:
            with self.open(root):
                pass
            transaction = Path(root) / C.NAMESPACE / C.TRANSACTION
            transaction.write_text('{"schema":1,"unknown":"owner data"}')
            transaction.chmod(0o600)
            before = self.snapshot(root)
            with self.assertRaises(C.CustodyError):
                self.open(root)
            with self.open(root, create=False) as custody:
                self.assertEqual(custody.status()['capacityReason'], 'fixture_metadata_pending')
            self.assertEqual(self.snapshot(root), before)

    def test_transaction_device_renumber_only_across_boot_with_persistent_proof(self):
        for point in ('transaction-ready', 'record-published'):
            for changed_boot in (False, True):
                with self.subTest(point=point, changed_boot=changed_boot), tempfile.TemporaryDirectory(dir='/private/tmp') as root:
                    with self.open(root) as custody:
                        custody.reserve()
                    with self.assertRaisesRegex(RuntimeError, 'crash'):
                        with self.open(root, checkpoint=self.crash(point)) as custody:
                            custody.update(0, state='retained')
                    path = Path(root) / C.NAMESPACE / C.TRANSACTION
                    value = json.loads(path.read_text())
                    value['before'][1][0] += 100
                    value['afterIdentity'][0] += 100
                    path.write_text(json.dumps(value))
                    if changed_boot:
                        with self.open(root, boot='b' * 64) as custody:
                            self.assertEqual(custody.records()[0]['state'], 'retained')
                            self.assertFalse(path.exists())
                    else:
                        before = self.snapshot(root)
                        with self.assertRaises(C.CustodyError):
                            self.open(root)
                        self.assertEqual(self.snapshot(root), before)

    def test_namespace_transaction_rechecks_retained_record_closure_on_restart(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as root:
            with self.open(root) as custody:
                custody.reserve()
            with self.assertRaisesRegex(RuntimeError, 'crash'):
                self.open(root, boot='b' * 64, checkpoint=self.crash('transaction-ready'))
            path = Path(root) / C.NAMESPACE / '0.json'
            value = json.loads(path.read_text())
            value['reason'] = 'foreign-change'
            path.write_text(json.dumps(value))
            before = self.snapshot(root)
            with self.assertRaises(C.CustodyError):
                self.open(root, boot='b' * 64)
            self.assertEqual(self.snapshot(root), before)

    def test_transaction_persistent_candidate_proof_mismatch_never_publishes(self):
        for field in ('volume', 'birth'):
            with self.subTest(field=field), tempfile.TemporaryDirectory(dir='/private/tmp') as root:
                with self.open(root):
                    pass
                with self.assertRaisesRegex(RuntimeError, 'crash'):
                    with self.open(root, checkpoint=self.crash('transaction-ready')) as custody:
                        custody.reserve()
                path = Path(root) / C.NAMESPACE / C.TRANSACTION
                value = json.loads(path.read_text())
                if field == 'volume':
                    value['afterPersistent']['volume'] = 'f' * 32
                else:
                    value['afterPersistent']['birth'][0] += 1
                path.write_text(json.dumps(value))
                before = self.snapshot(root)
                with self.assertRaises(C.CustodyError):
                    self.open(root, boot='b' * 64)
                self.assertEqual(self.snapshot(root), before)
                self.assertFalse((path.parent / '0.json').exists())

    def test_namespace_transaction_slot_closure_reconciles_device_only_across_boot(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as root:
            with self.open(root) as custody:
                custody.reserve()
            with self.assertRaisesRegex(RuntimeError, 'crash'):
                self.open(root, boot='b' * 64, checkpoint=self.crash('transaction-ready'))
            path = Path(root) / C.NAMESPACE / C.TRANSACTION
            value = json.loads(path.read_text())
            value['before'][1][0] += 100
            value['afterIdentity'][0] += 100
            value['records']['0.json']['stamp'][0] += 100
            path.write_text(json.dumps(value))
            with self.open(root, boot='c' * 64) as custody:
                self.assertEqual(custody.status()['outstanding'], 1)
                self.assertFalse(path.exists())

    def test_legacy_pending_and_unmarked_namespace_not_adopted(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as root:
            with self.open(root):
                pass
            pending = Path(root) / C.NAMESPACE / '0.json.pending'
            pending.write_bytes(b'legacy unknown')
            before = self.snapshot(root)
            with self.assertRaises(C.CustodyError):
                self.open(root)
            with self.open(root, create=False) as custody:
                self.assertEqual(custody.status()['capacityReason'], 'fixture_metadata_pending')
            self.assertEqual(self.snapshot(root), before)
        with tempfile.TemporaryDirectory(dir='/private/tmp') as root:
            (Path(root) / C.NAMESPACE).mkdir(mode=0o700)
            with self.assertRaises(FileNotFoundError):
                self.open(root)
            self.assertEqual(list((Path(root) / C.NAMESPACE).iterdir()), [])


if __name__ == '__main__':
    unittest.main()
