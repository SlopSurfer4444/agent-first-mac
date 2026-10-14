"""Actual launch planner/transaction proof on its existing private fixtures."""
import contextlib
import fcntl
import os
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from lib import game_delivery_bridge as bridge
from test_game_launch_reliability_update import Tests as LaunchFixture, u, COMMIT


class BridgeTests(LaunchFixture):
    @contextlib.contextmanager
    def bridge_context(self, phase):
        root = u.make_root(u.engine())
        fd = os.open(self.path('state/games-hub.lock'), os.O_RDONLY)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        identity = os.fstat(fd).st_ino
        def held():
            self.assertEqual(os.stat(self.path('state/games-hub.lock')).st_ino, identity)
        overlay = SimpleNamespace(anchors=dict(root.anchors, control=root.anchors['source']),
                                  bound=root.bound, _operation_lock_check=held)
        try:
            # Path/loading seam only; policy, guards, planning, transaction,
            # descriptors and file images remain their real implementations.
            with patch.object(bridge, '_load', return_value=u):
                with bridge.launch_bridge(self.source, overlay, COMMIT, phase=phase) as proof:
                    yield proof
        finally:
            os.close(fd)
            root.close()

    def test_bridge_predecessor_exact_and_no_writes(self):
        before = self.images()
        with self.bridge_context('predecessor') as proof:
            self.assertEqual(proof.before_lifecycle, self.path('ds3/ds3-runtime').read_bytes())
            self.assertIsNone(proof.admission)
            self.assertEqual(proof.desired_admission, self.path('candidate/game-launch-admission').read_bytes())
            self.assertIsNone(proof.revalidate())
        self.assertEqual(before, self.images())
        with self.assertRaisesRegex(bridge.Blocked, 'bridge_closed'):
            proof.revalidate()

    def test_bridge_settled_actual_apply(self):
        old = self.path('ds3/ds3-runtime').read_bytes()
        u.operate('apply', COMMIT, self.pin)
        before = self.images()
        with self.bridge_context('settled') as proof:
            self.assertEqual(proof.before_lifecycle, old)
            self.assertEqual(proof.installed_lifecycle, self.path('ds3/ds3-runtime').read_bytes())
            self.assertNotEqual(proof.before_lifecycle, proof.installed_lifecycle)
            self.assertEqual(proof.admission, self.path('aid-bin/game-launch-admission').read_bytes())
            self.assertEqual(proof.desired_admission, proof.admission)
        self.assertEqual(before, self.images())

    def test_bridge_unknown_stage_refused(self):
        u.operate('apply', COMMIT, self.pin)
        self.put('state/' + u.NAMESPACE + '/transaction/unknown-stage', b'x')
        with self.assertRaisesRegex(bridge.Blocked, 'bridge_transaction_inventory'):
            with self.bridge_context('settled'):
                pass

    def test_bridge_nonterminal_refused(self):
        u.operate('apply', COMMIT, self.pin)
        rel = 'state/' + u.NAMESPACE + '/transaction/journal.json'
        journal = u.decode(self.path(rel).read_bytes())
        journal['phase'] = 'applying'
        self.put(rel, u.encode(journal))
        with self.assertRaisesRegex(bridge.Blocked, 'bridge_launch_not_settled'):
            with self.bridge_context('settled'):
                pass

    def test_bridge_changed_afterimage_refused(self):
        u.operate('apply', COMMIT, self.pin)
        self.put('ds3/ds3-runtime', b'foreign', 0o700)
        with self.assertRaisesRegex(bridge.Blocked, 'bridge_launch_after_drift'):
            with self.bridge_context('settled'):
                pass

    def test_bridge_cs2_busy_refused_without_wait(self):
        fd = os.open(self.path('cs2/.launcher.lock'), os.O_RDONLY)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(bridge.Blocked, 'bridge_cs2_busy'):
                with self.bridge_context('predecessor'):
                    pass
        finally:
            os.close(fd)

    def test_bridge_receipt_drift_refused(self):
        u.operate('apply', COMMIT, self.pin)
        receipt = u.decode(self.path('ds3/receipt.json').read_bytes())
        receipt['opaqueOwnerField'] = 'changed after launch'
        self.put('ds3/receipt.json', u.encode(receipt))
        with self.assertRaisesRegex(bridge.Blocked, 'bridge_launch_after_drift'):
            with self.bridge_context('settled'):
                pass

    def test_bridge_backup_tamper_refused(self):
        u.operate('apply', COMMIT, self.pin)
        self.put('state/' + u.NAMESPACE + '/transaction/ds3.lifecycle.before', b'foreign', 0o700)
        with self.assertRaisesRegex(u.Blocked, 'backup_drift'):
            with self.bridge_context('settled'):
                pass

    def test_bridge_guard_drift_refused(self):
        self.put('ds3/manifest.json', b'foreign')
        with self.assertRaisesRegex(u.Blocked, 'guard_drift'):
            with self.bridge_context('predecessor'):
                pass

    def test_bridge_source_commit_drift_refused(self):
        self.head = 'f' * 40
        with self.assertRaises(u.Blocked):
            with self.bridge_context('predecessor'):
                pass

    def test_bridge_revalidation_catches_mid_context_target_drift(self):
        with self.bridge_context('predecessor') as proof:
            self.put('ds3/ds3-runtime', b'foreign', 0o700)
            with self.assertRaisesRegex(u.Blocked, 'predecessor_drift'):
                proof.revalidate()

    def test_bridge_predecessor_refuses_existing_settled_transaction(self):
        u.operate('apply', COMMIT, self.pin)
        u.operate('rollback', COMMIT, self.pin)
        with self.assertRaisesRegex(bridge.Blocked, 'bridge_launch_transaction_present'):
            with self.bridge_context('predecessor'):
                pass


def load_tests(loader, tests, pattern):
    return unittest.TestSuite(BridgeTests(name) for name in
                             loader.getTestCaseNames(BridgeTests) if name.startswith('test_bridge_'))
