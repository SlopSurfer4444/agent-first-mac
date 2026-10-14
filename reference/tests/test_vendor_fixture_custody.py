"""Actual private directories/inert Python restart children, never vendor probes."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace as NS
from unittest.mock import patch

from lib import vendor_fixture_custody as C
from lib import vendor_compatibility_probe as V

ROOT = Path(__file__).resolve().parents[1]
EMPTY = lambda *args: None


class CustodyTests(unittest.TestCase):
    def generated(self, custody, count=317):
        slot, root = self.owned(custody)
        children = {}
        for name in C.CHILDREN:
            (root/name).mkdir(mode=0o700)
            children[name] = C.identity((root/name).stat())
        for name in ('schema/v1', 'schema/v2', 'codex/tmp', 'codex/tmp/arg0'):
            (root/name).mkdir(mode=0o755)
        for index, name in enumerate(C.SCHEMAS + tuple('v2/Type%d.json' % i for i in range(count - 2))):
            target = root/'schema'/name
            target.write_bytes(b'{}')
            target.chmod(0o644)
        custody.update(slot, children=children, state='allocated')
        consumed = {name: C.stamp((root/'schema'/name).stat()) for name in C.SCHEMAS}
        return slot, root, consumed

    def test_generated_317_file_tree_is_sealed_retired_and_next_allocation_succeeds(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as d, patch.object(C.paths, 'DarwinEnvelope',
                return_value=NS(acl_count=lambda fd: 0, xattr_names=lambda fd: ())):
            with C.Custody(d, d, os.getuid(), envelope=EMPTY) as custody:
                slot, root, consumed = self.generated(custody)
                self.assertEqual(custody.census(), (634, 326))
                custody.seal_output(slot, consumed)
                self.assertEqual(custody.records()[slot]['schema'], 2)
                self.assertEqual(len(custody.records()[slot]['output']), 326)
                custody.retire(slot)
                self.assertFalse(root.exists())
                second, artifact = self.owned(custody)
                self.assertEqual(second, slot)
                self.assertTrue(artifact.is_dir())

    def test_generated_seal_refuses_unknown_unsafe_changed_and_bounded_output_without_deletion(self):
        cases = ('foreign', 'nested', 'symlink', 'hardlink', 'writable', 'consumed',
                 'missing-consumed', 'entries', 'bytes', 'acl', 'xattr', 'retained', 'inflight', 'unsettled')
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory(dir='/private/tmp') as d, \
                    patch.object(C.paths, 'DarwinEnvelope', return_value=NS(
                        acl_count=lambda fd: int(case == 'acl'),
                        xattr_names=lambda fd: ('foreign.metadata',) if case == 'xattr' else ())):
                with C.Custody(d, d, os.getuid(), envelope=EMPTY) as custody:
                    slot, root, consumed = self.generated(custody, count=3)
                    target = root/'schema/v2/Type0.json'
                    if case == 'foreign': (root/'home/foreign').write_bytes(b'keep')
                    elif case == 'nested': (root/'schema/v2/extra').mkdir()
                    elif case == 'symlink': (root/'schema/link.json').symlink_to(target)
                    elif case == 'hardlink': os.link(target, root/'schema/link.json')
                    elif case == 'writable': target.chmod(0o666)
                    elif case == 'consumed': (root/'schema'/C.SCHEMAS[0]).write_bytes(b'changed')
                    elif case == 'missing-consumed': consumed.pop(C.SCHEMAS[0])
                    elif case in ('retained', 'inflight'): custody.update(slot, state=case)
                    elif case == 'unsettled': custody.update(slot, settled=False)
                    with patch.object(C, 'MAX_OUTPUT_ENTRIES', 10 if case == 'entries' else 1024), \
                            patch.object(C, 'MAX_OUTPUT_BYTES', 1 if case == 'bytes' else 16 * 1024 * 1024):
                        with self.assertRaises(C.CustodyError): custody.seal_output(slot, consumed)
                    self.assertEqual(custody.records()[slot]['schema'], 1)
                    self.assertTrue(target.exists())

    def test_generated_retained_schema1_is_never_adopted_after_restart(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as d, patch.object(C.paths, 'DarwinEnvelope',
                return_value=NS(acl_count=lambda fd: 0, xattr_names=lambda fd: ())):
            with C.Custody(d, d, os.getuid(), envelope=EMPTY) as custody:
                slot, root, consumed = self.generated(custody)
            with C.Custody(d, d, os.getuid(), envelope=EMPTY) as custody:
                with self.assertRaises(C.CustodyError): custody.seal_output(slot, consumed)
                with self.assertRaises(C.CustodyError): custody.retire(slot)
                self.assertEqual(len(tuple((root/'schema/v2').iterdir())), 315)

    def test_generated_schema2_restart_refuses_missing_or_replaced_or_extra_before_intent(self):
        for case in ('missing', 'replaced-file', 'replaced-dir', 'extra'):
            with self.subTest(case=case), tempfile.TemporaryDirectory(dir='/private/tmp') as d, \
                    patch.object(C.paths, 'DarwinEnvelope', return_value=NS(acl_count=lambda fd: 0, xattr_names=lambda fd: ())):
                with C.Custody(d, d, os.getuid(), envelope=EMPTY) as custody:
                    slot, root, consumed = self.generated(custody, count=3)
                    custody.seal_output(slot, consumed)
                target = root/'schema/v2/Type0.json'
                if case == 'missing': target.unlink()
                elif case == 'replaced-file':
                    target.rename(Path(d)/'saved-file'); target.write_bytes(b'{}')
                elif case == 'replaced-dir':
                    target.parent.rename(Path(d)/'saved-dir'); target.parent.mkdir(mode=0o755)
                else: (root/'schema/foreign.json').write_bytes(b'keep')
                with C.Custody(d, d, os.getuid(), envelope=EMPTY) as custody:
                    with self.assertRaises(C.CustodyError): custody.retire(slot)
                    self.assertEqual(custody.records()[slot]['state'], 'allocated')
                    self.assertTrue((root/'schema'/C.SCHEMAS[0]).exists())

    def test_generated_schema2_retirement_crashes_resume_exact_known_missing_only(self):
        for point in ('retirement-intent', 'schema-retired', 'child-retired', 'root-retired'):
            with self.subTest(point=point), tempfile.TemporaryDirectory(dir='/private/tmp') as d, \
                    patch.object(C.paths, 'DarwinEnvelope', return_value=NS(acl_count=lambda fd: 0, xattr_names=lambda fd: ())):
                with C.Custody(d, d, os.getuid(), envelope=EMPTY) as custody:
                    slot, root, consumed = self.generated(custody, count=3)
                    custody.seal_output(slot, consumed)
                result = self.child(d, "c._output_envelope=lambda fd:None;"
                    "c.checkpoint=lambda p:os._exit(73) if p=='" + point + "' else None;c.retire(0)")
                self.assertEqual(result.returncode, 73, result.stderr)
                with C.Custody(d, d, os.getuid(), envelope=EMPTY) as custody:
                    self.assertEqual(custody.records()[slot]['state'], 'retiring')
                    self.assertTrue(custody.retire(slot)['retired'])
                    self.assertFalse(root.exists())

    def test_generated_schema2_resume_preserves_foreign_replacement_and_entries(self):
        for case in ('replacement', 'extra'):
            with self.subTest(case=case), tempfile.TemporaryDirectory(dir='/private/tmp') as d, \
                    patch.object(C.paths, 'DarwinEnvelope', return_value=NS(acl_count=lambda fd: 0, xattr_names=lambda fd: ())):
                with C.Custody(d, d, os.getuid(), envelope=EMPTY) as custody:
                    slot, root, consumed = self.generated(custody, count=3)
                    custody.seal_output(slot, consumed)
                    def stop(point):
                        if point == 'schema-retired': raise RuntimeError('stop')
                    custody.checkpoint = stop
                    with self.assertRaises(RuntimeError): custody.retire(slot)
                if case == 'replacement':
                    target = root/'schema/v2/Type0.json'
                else: target = root/'schema/new.json'
                target.write_bytes(b'preserve')
                with C.Custody(d, d, os.getuid(), envelope=EMPTY) as custody:
                    with self.assertRaises(C.CustodyError): custody.retire(slot)
                    self.assertEqual(target.read_bytes(), b'preserve')

    def test_generated_provenance_only_metadata_is_accepted(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as d, patch.object(C.paths, 'DarwinEnvelope',
                return_value=NS(acl_count=lambda fd: 0, xattr_names=lambda fd: ('com.apple.provenance',))):
            with C.Custody(d, d, os.getuid(), envelope=EMPTY) as custody:
                slot, root, consumed = self.generated(custody, count=3)
                custody.seal_output(slot, consumed)
                self.assertTrue(custody.retire(slot)['retired'])

    def test_generated_schema2_malformed_manifest_cannot_authorize_deletion(self):
        for case in ('path', 'boolean', 'mode', 'parent', 'missing-consumed'):
            with self.subTest(case=case), tempfile.TemporaryDirectory(dir='/private/tmp') as d, \
                    patch.object(C.paths, 'DarwinEnvelope', return_value=NS(acl_count=lambda fd: 0, xattr_names=lambda fd: ())):
                with C.Custody(d, d, os.getuid(), envelope=EMPTY) as custody:
                    slot, root, consumed = self.generated(custody, count=3)
                    custody.seal_output(slot, consumed)
                    value = custody.records()[slot]['output']
                    if case == 'path': value['schema/../foreign.json'] = value.pop('schema/v2/Type0.json')
                    elif case == 'boolean': value['schema/v2/Type0.json'][0] = True
                    elif case == 'mode': value['schema/v2/Type0.json'][2] |= 0o4000
                    elif case == 'parent': value['schema/v2'] = []
                    else: value.pop('schema/' + C.SCHEMAS[0])
                    custody.update(slot, output=value)
                    with self.assertRaises(C.CustodyError): custody.retire(slot)
                    self.assertTrue((root/'schema/v2/Type0.json').exists())

    def test_generated_replacement_after_intent_is_preserved(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as d, patch.object(C.paths, 'DarwinEnvelope',
                return_value=NS(acl_count=lambda fd: 0, xattr_names=lambda fd: ())):
            with C.Custody(d, d, os.getuid(), envelope=EMPTY) as custody:
                slot, root, consumed = self.generated(custody, count=3)
                custody.seal_output(slot, consumed)
                target = root/'schema/v2/Type0.json'
                def replace(point):
                    if point == 'retirement-intent':
                        target.rename(Path(d)/'saved')
                        target.write_bytes(b'preserve')
                custody.checkpoint = replace
                with self.assertRaises(C.CustodyError): custody.retire(slot)
                self.assertEqual(target.read_bytes(), b'preserve')
                self.assertEqual((Path(d)/'saved').read_bytes(), b'{}')

    def owned(self, custody, *, settled=True):
        slot = custody.reserve()
        leaf = custody.leaf(custody.records()[slot])
        os.mkdir(leaf, 0o700, dir_fd=custody.parent.descriptor)
        custody.update(slot, root=C.identity(os.stat(leaf, dir_fd=custody.parent.descriptor,
                         follow_symlinks=False)), state="retained", settled=settled)
        return slot, Path(custody.scratch) / leaf

    def child(self, directory, body):
        code = ("import os,json,sys; from lib.vendor_fixture_custody import Custody,identity; "
                "d=sys.argv[1]; c=Custody(d,d,os.getuid(),envelope=lambda *a:None); " + body)
        return subprocess.run([sys.executable, "-B", "-c", code, directory], cwd=ROOT,
            env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(ROOT), "TMPDIR": "/private/tmp"},
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)

    def test_real_process_restart_retains_exact_artifact_then_explicitly_retires(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as d:
            result = self.child(d, "s=c.reserve();r=c.records()[s];l=c.leaf(r);os.mkdir(d+'/'+l,0o700);"
                "c.update(s,root=identity(os.stat(d+'/'+l)),state='retained');c.close()")
            self.assertEqual(result.returncode, 0, result.stderr)
            status = self.child(d, "print(json.dumps(c.status()));c.close()")
            self.assertEqual(json.loads(status.stdout)["outstanding"], 1)
            retired = self.child(d, "print(json.dumps(c.retire(0)));c.close()")
            self.assertEqual(retired.returncode, 0, retired.stderr)
            self.assertTrue(json.loads(retired.stdout)["retired"])
            with C.Custody(d, d, os.getuid(), envelope=EMPTY) as custody:
                self.assertEqual(custody.status()["outstanding"], 0)

    def test_existing_cli_after_process_exit_has_real_private_status_and_retirement_consumer(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as d:
            scratch = Path(d)/'AIDev'/'scratch'
            scratch.mkdir(parents=True, mode=0o700)
            scratch.parent.chmod(0o700)
            with C.Custody(str(scratch), d, os.getuid(), envelope=EMPTY) as custody:
                slot, artifact = self.owned(custody)
            code = '''import os,sys,importlib.machinery
from types import SimpleNamespace as NS
from lib import current_doctor_native as N
N.pwd.getpwuid=lambda uid:NS(pw_dir=sys.argv[1])
N.probe.require_fixture_envelope=lambda *args:None
def admitted(doctor, git_only, **kwargs):
    assert git_only is True
    assert kwargs['operation_check']('a'*40,source_guard=lambda:True) is True
    return {'verdict':'GIT_ONLY_VALID'}
N.native=admitted
C=importlib.machinery.SourceFileLoader('custody_cli_test','bin/current-doctor').load_module()
raise SystemExit(C.main(sys.argv[2:]))
'''
            for flags in (['--fixture-custody-status','--json'], ['--retire-fixture-slot',str(slot),'--json']):
                result = subprocess.run([sys.executable,'-B','-c',code,d,*flags],cwd=ROOT,
                    env={'PYTHONPATH':str(ROOT),'TMPDIR':'/private/tmp','PATH':'/usr/bin:/bin'},
                    stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
                self.assertEqual(result.returncode,0,result.stderr)
                public = json.loads(result.stdout)
                self.assertNotIn(d,result.stdout.decode())
                self.assertEqual(public['scope'],'disposable-vendor-fixture-custody')
            self.assertFalse(artifact.exists())

    def test_eight_outstanding_artifact_reservations_persist_and_exhaust_capacity(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as d:
            with C.Custody(d, d, os.getuid(), envelope=EMPTY) as custody:
                artifacts = [self.owned(custody)[1] for _ in range(C.SLOTS)]
            with C.Custody(d, d, os.getuid(), envelope=EMPTY) as custody:
                with self.assertRaisesRegex(C.CustodyError, "fixture_capacity_required"):
                    custody.reserve()
                self.assertTrue(all(path.is_dir() for path in artifacts))
                self.assertEqual(custody.status()["outstanding"], 8)

    def test_unknown_inflight_remains_unsettled_across_real_process_exit(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as d:
            with C.Custody(d, d, os.getuid(), envelope=EMPTY) as custody:
                slot, path = self.owned(custody, settled=False)
                custody.update(slot, state="inflight")
            result = self.child(d, "c.retire(0)")
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue(path.is_dir())
            with C.Custody(d, d, os.getuid(), envelope=EMPTY) as custody:
                self.assertFalse(custody.records()[slot]["settled"])
                with self.assertRaisesRegex(C.CustodyError, "fixture_settlement_required"):
                    custody.reserve()

    def test_parent_exit_after_inert_child_launch_never_infers_settlement(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as d:
            result = self.child(d, "import subprocess;s=c.reserve();l=c.leaf(c.records()[s]);"
                "os.mkdir(d+'/'+l,0o700);c.update(s,root=identity(os.stat(d+'/'+l)),state='inflight',settled=False);"
                "subprocess.Popen([sys.executable,'-c','pass'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);os._exit(73)")
            self.assertEqual(result.returncode, 73)
            with C.Custody(d, d, os.getuid(), envelope=EMPTY) as custody:
                self.assertFalse(custody.records()[0]['settled'])
                with self.assertRaisesRegex(C.CustodyError, 'fixture_settlement_required'):
                    custody.retire(0)

    def test_record_write_all_and_zero_write_uncertainty(self):
        for short in (True, False):
            with self.subTest(short=short), tempfile.TemporaryDirectory(dir="/private/tmp") as d:
                with C.Custody(d, d, os.getuid(), envelope=EMPTY) as custody:
                    actual = os.write
                    def write(fd, data):
                        return actual(fd, data[:7]) if short else 0
                    with patch.object(C.os, 'write', side_effect=write):
                        if short:
                            slot = custody.reserve()
                            self.assertEqual(custody.records()[slot]['state'], 'reserved')
                        else:
                            with self.assertRaises(C.CustodyError):
                                custody.reserve()
                            self.assertTrue((Path(d)/C.NAMESPACE/'0.json.pending').exists())

    def test_uncertain_record_descriptor_close_retains_owner_without_retry(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as d:
            custody = C.Custody(d, d, os.getuid(), envelope=EMPTY)
            target = custody.lock
            actual = os.close
            calls = []
            def close(fd):
                calls.append(fd)
                if fd == target:
                    raise OSError('uncertain close')
                return actual(fd)
            try:
                with patch.object(C.os, 'close', side_effect=close):
                    with self.assertRaises(OSError) as caught:
                        custody.close()
                    self.assertIs(caught.exception.private_custody, custody)
                    self.assertFalse(caught.exception.source_handles_closed)
                    with self.assertRaises(OSError):
                        custody.close()
                    self.assertEqual(calls.count(target), 1)
                    self.assertIn(target, custody.fds)
            finally:
                actual(target)  # explicit fixture-owner reconciliation only

    def test_bytes_entries_and_unknown_symlink_budget_block_only_new_allocation(self):
        for case in ("bytes", "entries", "symlink"):
            with self.subTest(case=case), tempfile.TemporaryDirectory(dir="/private/tmp") as d:
                with C.Custody(d, d, os.getuid(), envelope=EMPTY) as custody:
                    slot, path = self.owned(custody)
                    if case == "bytes":
                        (path / "foreign").write_bytes(b"12345")
                    elif case == "entries":
                        for index in range(3):
                            (path / str(index)).write_bytes(b"x")
                    else:
                        (path / "foreign").symlink_to("/nonexistent-foreign")
                    with patch.object(C, "MAX_BYTES", 4), patch.object(C, "MAX_ENTRIES", 2):
                        with self.assertRaisesRegex(C.CustodyError, "fixture_capacity_required"):
                            custody.reserve()
                    with self.assertRaises(C.CustodyError):
                        custody.retire(slot)
                    self.assertTrue(path.is_dir())
                    self.assertTrue(list(path.iterdir()))

    def test_foreign_root_replacement_is_not_retired_or_adopted(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as d:
            with C.Custody(d, d, os.getuid(), envelope=EMPTY) as custody:
                slot, path = self.owned(custody)
                path.rename(Path(d) / "saved")
                path.mkdir(mode=0o700)
                (path / "foreign").write_bytes(b"preserve")
                with self.assertRaises(C.CustodyError):
                    custody.retire(slot)
                self.assertEqual((path / "foreign").read_bytes(), b"preserve")

    def test_root_swap_between_stat_and_open_keeps_foreign_empty_directory(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as d:
            with C.Custody(d, d, os.getuid(), envelope=EMPTY) as custody:
                slot, path = self.owned(custody)
                actual = C.paths.OwnedParent.open
                def opening(target, *args, **kwargs):
                    if target == str(path):
                        path.rename(Path(d)/'saved')
                        path.mkdir(mode=0o700)
                    return actual(target, *args, **kwargs)
                with patch.object(C.paths.OwnedParent, 'open', side_effect=opening):
                    with self.assertRaises(C.CustodyError):
                        custody.retire(slot)
                self.assertTrue(path.is_dir())
                self.assertTrue((Path(d)/'saved').is_dir())

    def test_named_lock_replacement_denies_split_lock_or_publication(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as d:
            with C.Custody(d, d, os.getuid(), envelope=EMPTY) as custody:
                lock = Path(d)/C.NAMESPACE/'lock'
                lock.rename(lock.with_name('saved-lock'))
                lock.touch(mode=0o600)
                with self.assertRaises(C.CustodyError):
                    custody.reserve()
                with self.assertRaises(C.CustodyError):
                    C.Custody(d, d, os.getuid(), envelope=EMPTY)
                self.assertTrue(lock.is_file())

    def test_malformed_or_bool_schema_record_never_authorizes_retirement(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as d:
            with C.Custody(d, d, os.getuid(), envelope=EMPTY) as custody:
                slot, path = self.owned(custody)
            record = Path(d)/C.NAMESPACE/(str(slot)+'.json')
            value = json.loads(record.read_bytes())
            value['schema'] = True
            record.write_text(json.dumps(value))
            with self.assertRaises(C.CustodyError):
                C.Custody(d, d, os.getuid(), envelope=EMPTY)
            self.assertTrue(path.is_dir())

    def test_durable_reservation_and_publication_crashpoints_never_allocate_unowned_fixture(self):
        for point in ("record-written", "record-published", "record-durable", "reservation-durable"):
            with self.subTest(point=point), tempfile.TemporaryDirectory(dir="/private/tmp") as d:
                with C.Custody(d, d, os.getuid(), envelope=EMPTY):
                    pass
                result = self.child(d, "c.checkpoint=lambda p:os._exit(73) if p=='" + point +
                                      "' else None;c.reserve()")
                self.assertEqual(result.returncode, 73)
                self.assertFalse(any(p.name.startswith("vendor-sentinel-") and p.name != C.NAMESPACE
                                     for p in Path(d).iterdir()))
                if point == "record-written":
                    with self.assertRaises(C.CustodyError):
                        C.Custody(d, d, os.getuid(), envelope=EMPTY)
                else:
                    with C.Custody(d, d, os.getuid(), envelope=EMPTY) as custody:
                        self.assertEqual(custody.status()["outstanding"], 1)
                        custody.retire(0)  # positive absent, pre-launch reservation

    def test_retirement_intent_survives_abrupt_process_exit_and_resumes(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as d:
            with C.Custody(d, d, os.getuid(), envelope=EMPTY) as custody:
                slot, path = self.owned(custody)
            result = self.child(d, "c.checkpoint=lambda p:os._exit(73) if p=='root-retired' else None;c.retire(0)")
            self.assertEqual(result.returncode, 73)
            self.assertFalse(path.exists())
            with C.Custody(d, d, os.getuid(), envelope=EMPTY) as custody:
                self.assertEqual(custody.records()[slot]["state"], "retiring")
                self.assertTrue(custody.retire(slot)["retired"])

    def test_actual_probe_fixture_success_releases_persistent_slot(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as d, patch.object(V.paths, "DarwinEnvelope",
                return_value=NS(acl_count=lambda fd: 0, xattr_names=lambda fd: ())):
            fixture = V.Fixture(d, d, os.getuid(), V.paths)
            for leaf in C.SCHEMAS:
                target = Path(fixture.path) / "schema" / leaf
                target.write_bytes(b"{}")
                target.chmod(0o600)
                fixture.schema(leaf)
            self.assertTrue(fixture.retire())
            fixture.close()
            with C.Custody(d, d, os.getuid(), envelope=EMPTY) as custody:
                self.assertEqual(custody.status()["outstanding"], 0)

    def test_partial_probe_retirement_close_preserves_durable_intent_for_restart(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as d, patch.object(V.paths, "DarwinEnvelope",
                return_value=NS(acl_count=lambda fd: 0, xattr_names=lambda fd: ())):
            fixture = V.Fixture(d, d, os.getuid(), V.paths)
            slot = fixture.slot
            for leaf in C.SCHEMAS:
                target = Path(fixture.path)/'schema'/leaf
                target.write_bytes(b'{}'); target.chmod(0o600)
                fixture.schema(leaf)
            actual = os.rmdir
            count = [0]
            def remove(*args, **kwargs):
                count[0] += 1
                if count[0] == 2:
                    raise OSError('synthetic second-rmdir failure')
                return actual(*args, **kwargs)
            with patch.object(V.os, 'rmdir', side_effect=remove):
                with self.assertRaises(OSError):
                    fixture.retire()
            fixture.close()
            with C.Custody(d, d, os.getuid(), envelope=EMPTY) as custody:
                self.assertEqual(custody.records()[slot]['state'], 'retiring')
                self.assertTrue(custody.retire(slot)['retired'])

    def test_automatic_retirement_fsync_failure_cannot_release_durable_reservation(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as d, patch.object(V.paths, "DarwinEnvelope",
                return_value=NS(acl_count=lambda fd: 0, xattr_names=lambda fd: ())):
            fixture = V.Fixture(d, d, os.getuid(), V.paths)
            slot = fixture.slot
            for leaf in C.SCHEMAS:
                target = Path(fixture.path)/'schema'/leaf
                target.write_bytes(b'{}'); target.chmod(0o600)
                fixture.schema(leaf)
            target_fd = fixture.custody.parent.descriptor
            actual = os.fsync
            def sync(fd):
                if fd == target_fd:
                    raise OSError('synthetic scratch fsync failure')
                return actual(fd)
            with patch.object(V.os, 'fsync', side_effect=sync):
                with self.assertRaises(OSError):
                    fixture.retire()
            fixture.close()
            with C.Custody(d, d, os.getuid(), envelope=EMPTY) as custody:
                self.assertEqual(custody.records()[slot]['state'],'retiring')
                self.assertTrue(custody.retire(slot)['retired'])

    def test_listing_stops_at_first_extra_entry_without_materializing_unknown_names(self):
        consumed = []
        class Entries:
            def __enter__(self):
                return self
            def __exit__(self,*args):
                pass
            def __iter__(self):
                for index in range(10000):
                    consumed.append(index)
                    yield NS(name=str(index))
        with patch.object(C.os, 'scandir', return_value=Entries()):
            with self.assertRaisesRegex(C.CustodyError,'fixture_capacity_required'):
                C.names(42,2)
        self.assertEqual(consumed,[0,1,2])

    def test_actual_probe_constructor_failure_has_durable_exact_root_binding(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as d, patch.object(V.paths, "DarwinEnvelope",
                return_value=NS(acl_count=lambda fd: 0, xattr_names=lambda fd: ())):
            owner = V.Fixture.__new__(V.Fixture)
            original = V.require_fixture_envelope
            def envelope(handle, module):
                if Path(handle._parts[-1]).name.startswith("vendor-sentinel-") and handle._parts[-1] != C.NAMESPACE:
                    raise V.ProbeError("fixture_invalid")
                return original(handle, module)
            with patch.object(V, "require_fixture_envelope", side_effect=envelope):
                with self.assertRaises(V.ProbeError):
                    V.Fixture.__init__(owner, d, d, os.getuid(), V.paths)
            with C.Custody(d, d, os.getuid(), envelope=EMPTY) as custody:
                record = custody.records()[owner.slot]
                self.assertEqual(record["root"], C.identity(os.stat(owner.path)))
                self.assertEqual(record["state"], "retained")
                self.assertTrue(custody.retire(owner.slot)["retired"])

    def test_whole_observe_wires_durable_before_launch_and_settled_failure_or_success(self):
        from tests.test_vendor_compatibility_probe import Harness
        actual_fixture = V.Fixture
        for succeeds in (True, False):
            with self.subTest(succeeds=succeeds), tempfile.TemporaryDirectory(dir="/private/tmp") as d, \
                    patch.object(V.paths, "DarwinEnvelope", return_value=NS(acl_count=lambda fd: 0, xattr_names=lambda fd: ())):
                h = Harness()
                class LocalFixture(actual_fixture):
                    def __init__(self, *args):
                        h.fixture = self
                        super().__init__(d, d, os.getuid(), V.paths)
                h.fixture_class = LocalFixture
                original = h.process.command
                admissions = []
                def command(launch, *args, **kwargs):
                    if hasattr(h, 'fixture'):
                        record = h.fixture.custody.records()[h.fixture.slot]
                        self.assertFalse(record['settled'])
                        self.assertEqual(record['state'], 'inflight')
                        admissions.append(record['slot'])
                    if 'generate-json-schema' in launch.argv:
                        for leaf in C.SCHEMAS:
                            target = Path(h.fixture.path)/'schema'/leaf
                            target.write_bytes(b'{"definitions":{}}')
                            target.chmod(0o600)
                    return original(launch, *args, **kwargs)
                h.process.command = command
                if not succeeds:
                    h.fail_command = '--version'
                if succeeds:
                    self.assertTrue(h.observe()['fixtureRetired'])
                    self.assertEqual(len(admissions), 7)  # six CLI + final signing
                else:
                    with self.assertRaises(V.ProbeError):
                        h.observe()
                with C.Custody(d, d, os.getuid(), envelope=EMPTY) as custody:
                    if succeeds:
                        self.assertEqual(custody.status()['outstanding'], 0)
                    else:
                        record = custody.records()[h.fixture.slot]
                        self.assertTrue(record['settled'])
                        self.assertEqual(record['state'], 'retained')
                        self.assertTrue(custody.retire(h.fixture.slot)['retired'])

    def test_positive_process_error_settlement_is_durable_not_inferred(self):
        from tests.test_vendor_compatibility_probe import Harness
        from lib.phase5_probe_process import ProbeProcessError
        actual_fixture = V.Fixture
        with tempfile.TemporaryDirectory(dir="/private/tmp") as d, patch.object(V.paths, "DarwinEnvelope",
                return_value=NS(acl_count=lambda fd: 0, xattr_names=lambda fd: ())):
            h = Harness()
            class LocalFixture(actual_fixture):
                def __init__(self, *args):
                    h.fixture = self
                    super().__init__(d, d, os.getuid(), V.paths)
            h.fixture_class = LocalFixture
            command = h.process.command
            def failed(launch, *args, **kwargs):
                if launch.argv[0] == '/usr/bin/sandbox-exec':
                    kwargs['admit_launch'](launch)
                    raise ProbeProcessError('command_failed', child_settled=True)
                return command(launch, *args, **kwargs)
            h.process.command = failed
            with self.assertRaises(V.ProbeError):
                h.observe()
            with C.Custody(d, d, os.getuid(), envelope=EMPTY) as custody:
                self.assertTrue(custody.records()[h.fixture.slot]['settled'])
                self.assertTrue(custody.retire(h.fixture.slot)['retired'])


if __name__ == "__main__":
    unittest.main()
