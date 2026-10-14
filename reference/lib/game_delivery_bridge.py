"""Read-only cross-proof between two fixed game delivery transactions.

This grants no execution authority. The caller retains its accepted-source and
readiness gates and shared games lock throughout the context. We additionally
take the existing CS2 lock nonblocking: never wait in reversed lock order.
"""
import contextlib
import fcntl
import importlib.machinery
import importlib.util
import os
import stat
from pathlib import Path


class Blocked(RuntimeError):
    pass


def need(ok, reason):
    if not ok:
        raise Blocked(reason)


def _load(control):
    path = control / 'bin/game-launch-reliability-update'
    loader = importlib.machinery.SourceFileLoader('reviewed_game_delivery_bridge_launch', str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    need(module.CONTROL == control, 'bridge_control_path')
    return module


def _identity(fd):
    info = os.fstat(fd)
    return info.st_dev, info.st_ino


class _Proof:
    def __init__(self, module, root, overlay, commit, phase, lock_check):
        self.module, self.root, self.overlay = module, root, overlay
        self.commit, self.phase, self.lock_check = commit, phase, lock_check
        self.active = True
        self._baseline = None
        self.revalidate()

    def revalidate(self):
        need(self.active, 'bridge_closed')
        m, root = self.module, self.root
        self.overlay.bound()
        self.overlay._operation_lock_check()
        root.bound()
        self.lock_check()
        for launch_name, overlay_name in (('hub', 'hub'), ('ds3', 'ds3'),
                                          ('state', 'state'), ('source', 'control')):
            need(_identity(root.anchors[launch_name].fd) ==
                 _identity(self.overlay.anchors[overlay_name].fd), 'bridge_anchor_mismatch')
        m.source_check(self.commit)
        value, native, policy_sha = m.policy(root)
        m.guards(root, value)
        if self.phase == 'predecessor':
            plan, before, after = m.plan(root, self.commit, value, native, policy_sha)
            # An old namespace may be retained, but a live transaction cannot
            # silently become a different delivery's predecessor proof.
            need(not root.exists('state/transaction'), 'bridge_launch_transaction_present')
            result = (before['ds3.lifecycle'], before['ds3.lifecycle'], before['helper'],
                      m.digest(m.encode(plan)), after['helper'])
        else:
            state = root.anchors['state']
            need(state.read(m.NAMESPACE + '/owner.json') == (m.OWNER, 0o600), 'bridge_namespace_owner')
            with state.parent(m.NAMESPACE + '/.unused') as (fd, _, check):
                need(set(os.listdir(fd)) == {'owner.json', 'transaction'}, 'bridge_namespace_inventory')
                check()
            raw, mode = root.read('state/transaction/plan.json')
            need(mode == 0o600, 'bridge_plan_mode')
            tx = m.Transaction(root, m.digest(raw), self.commit, value, native, policy_sha)
            journal = tx.journal()
            need(journal['phase'] == 'applied' and journal['intent'] is None,
                 'bridge_launch_not_settled')
            need(root.read('state/transaction/journal.json')[1] == 0o600,
                 'bridge_journal_mode')
            expected = {'plan.json', 'journal.json'} | {
                key + '.' + side for key in m.ORDER for side in ('before', 'after')
                if tx.images[key][side] is not None}
            with root.parent('state/transaction/.unused') as (fd, _, check):
                info = os.fstat(fd)
                need(stat.S_IMODE(info.st_mode) == 0o700 and
                     set(os.listdir(fd)) == expected, 'bridge_transaction_inventory')
                check()
            need(tx.side('after'), 'bridge_launch_after_drift')
            result = (tx.images['ds3.lifecycle']['before'], tx.images['ds3.lifecycle']['after'],
                      tx.images['helper']['after'], tx.sha, tx.images['helper']['after'])
        need(self._baseline is None or result == self._baseline, 'bridge_proof_drift')
        self._baseline = result
        self.before_lifecycle = result[0][0]
        self.installed_lifecycle = result[1][0]
        self.admission = None if result[2] is None else result[2][0]
        self.plan_sha256 = result[3]
        self.desired_admission = result[4][0]
        self.lock_check()
        self.overlay._operation_lock_check()
        root.bound()
        return None


@contextlib.contextmanager
def launch_bridge(control, overlay_root, commit, *, phase):
    """Hold exact predecessor or settled launch proof until caller publication.

    Historical policy must separately bind ``before_lifecycle``; no policy
    semantics are inferred here. Calling revalidate after context exit fails.
    """
    need(phase in ('predecessor', 'settled'), 'bridge_phase')
    control = Path(control)
    module = _load(control)
    root = module.make_root(module.engine())
    lock = None
    proof = None
    try:
        overlay_root._operation_lock_check()
        with root.parent('cs2/.launcher.lock') as (parent, name, check):
            lock = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            info = os.fstat(lock)
            need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and
                 info.st_nlink == 1 and not info.st_mode & 0o077, 'bridge_cs2_lock_unsafe')
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Blocked('bridge_cs2_busy') from None
            def lock_check():
                with root.parent('cs2/.launcher.lock') as (fd, leaf, bound):
                    current = os.stat(leaf, dir_fd=fd, follow_symlinks=False)
                    need((current.st_dev, current.st_ino) == (info.st_dev, info.st_ino),
                         'bridge_cs2_lock_changed')
                    bound()
            check()
            proof = _Proof(module, root, overlay_root, commit, phase, lock_check)
            yield proof
            # The consuming transaction may now own changed target bytes.
            # Caller explicitly revalidates before binding its plan; leaving
            # this context checks custody, not a stale launch after-side.
            root.bound()
            overlay_root.bound()
            overlay_root._operation_lock_check()
            lock_check()
    finally:
        if proof is not None:
            proof.active = False
        if lock is not None:
            os.close(lock)
        root.close()
