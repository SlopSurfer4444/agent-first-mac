"""Native temporary files, injected boot/device renumber; no live custody."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace as NS
from unittest.mock import patch

from lib import vendor_fixture_custody as C
import test_vendor_fixture_custody as fixture_tests


class DurableRecordTests(unittest.TestCase):
    def open(self, path, boot='a' * 64, **kwargs):
        return C.Custody(path, path, os.getuid(), envelope=lambda *args: None,
                         boot_identity=lambda: boot, **kwargs)

    def renumber(self, path):
        namespace = Path(path) / C.NAMESPACE
        marker = namespace / 'namespace.json'
        value = json.loads(marker.read_bytes())
        value['identity'][0] += 100
        value['lock'][0] += 100
        marker.write_text(json.dumps(value))
        record = namespace / '0.json'
        value = json.loads(record.read_bytes())
        if value['root'] is not None: value['root'][0] += 100
        for row in value['children'].values(): row[0] += 100
        for row in value['schemas'].values(): row[0] += 100
        for row in (value.get('output') or {}).values(): row[0] += 100
        record.write_text(json.dumps(value))
        return record

    def seed(self, path, *, sealed=False):
        with self.open(path) as custody:
            if sealed:
                slot, root, consumed = fixture_tests.CustodyTests().generated(custody, count=3)
                custody.seal_output(slot, consumed)
            else:
                slot = custody.reserve()
                root = Path(path) / custody.leaf(custody.records()[slot])
                root.mkdir(mode=0o700)
                custody.update(slot, root=C.identity(root.stat()), state='retained')
        return root

    def test_new_settled_records_rebase_and_retire_across_device_renumber(self):
        for sealed in (False, True):
            with self.subTest(sealed=sealed), tempfile.TemporaryDirectory(dir='/private/tmp') as path, \
                    patch.object(C.paths, 'DarwinEnvelope', return_value=NS(acl_count=lambda fd: 0, xattr_names=lambda fd: ())):
                root = self.seed(path, sealed=sealed)
                record = self.renumber(path)
                old = json.loads(record.read_bytes())
                with self.open(path, 'b' * 64) as custody:
                    current = custody.records()[0]
                    self.assertEqual(current['provenance']['objects'], old['provenance']['objects'])
                    self.assertEqual(current['provenance']['boot'], 'b' * 64)
                    self.assertEqual(current['root'][0], root.stat().st_dev)
                    self.assertEqual(current['settled'], old['settled'])
                    self.assertTrue(custody.retire(0)['retired'])
                self.assertFalse(root.exists())

    def test_unknown_settlement_replacement_or_proof_mismatch_never_rebases(self):
        for failure in ('unsettled', 'replacement', 'birth', 'volume', 'same-boot'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory(dir='/private/tmp') as path:
                root = self.seed(path)
                record = self.renumber(path)
                value = json.loads(record.read_bytes())
                if failure == 'unsettled': value['settled'] = False
                elif failure == 'birth': value['provenance']['objects']['']['birth'][0] += 1
                elif failure == 'volume': value['provenance']['objects']['']['volume'] = 'f' * 32
                elif failure == 'replacement':
                    root.rename(root.with_name('retained-owner-root'))
                    root.mkdir(mode=0o700)
                record.write_text(json.dumps(value))
                before = record.read_bytes()
                with self.assertRaises(C.CustodyError):
                    self.open(path, ('a' if failure == 'same-boot' else 'b') * 64)
                self.assertEqual(record.read_bytes(), before)
                self.assertTrue(root.is_dir())

    def test_legacy_record_is_readable_but_never_assigned_new_provenance(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as path:
            root = self.seed(path)
            record = self.renumber(path)
            value = json.loads(record.read_bytes())
            value['schema'] = 1
            value.pop('output')
            value.pop('provenance')
            record.write_text(json.dumps(value))
            before = record.read_bytes()
            with self.open(path, 'b' * 64, create=False) as custody:
                self.assertEqual(custody.status()['outstanding'], 1)
            with self.assertRaisesRegex(C.CustodyError, 'fixture_legacy_identity_required'):
                self.open(path, 'b' * 64)
            self.assertEqual(record.read_bytes(), before)
            self.assertTrue(root.is_dir())

    def test_same_boot_retirement_checks_birth_proof_not_only_raw_inode(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as path:
            root = self.seed(path)
            record = Path(path) / C.NAMESPACE / '0.json'
            value = json.loads(record.read_bytes())
            value['provenance']['objects']['']['birth'][0] += 1
            record.write_text(json.dumps(value))
            before = record.read_bytes()
            with self.open(path) as custody, self.assertRaises(C.CustodyError):
                custody.retire(0)
            self.assertEqual(record.read_bytes(), before)
            self.assertTrue(root.is_dir())


if __name__ == '__main__':
    unittest.main()
