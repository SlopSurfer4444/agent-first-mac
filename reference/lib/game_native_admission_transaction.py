"""Fixed nine-file admission transaction; caller owns authority and prerequisites.

The production layout is derived from the account database, never from records
or caller-supplied target paths. The wrapper must hold the existing CS2 then
games locks and supply a fresh guard for admitted source, inactive prefixes and
required companions. This core supplies no permission, launch or approval.
"""
import os
from pathlib import Path
import pwd
import stat

from lib import game_native_admission_bridge as bridge

HOME = Path(pwd.getpwuid(os.getuid()).pw_dir)
OWNER = bridge.OWNER
MAX_IMAGE = bridge.MAX_IMAGE
KEYS = ('admission.helper', 'hub.launcher', 'cs2.launcher', 'ds3.lifecycle',
        'hub.receipt', 'cs2.receipt', 'ds3.manifest', 'ds3.receipt', 'ds3.borderlessReceipt')
MODES = {key: 0o755 if key in ('hub.launcher', 'cs2.launcher') else
         0o700 if key == 'ds3.lifecycle' else 0o600 for key in KEYS}
DS_KEYS = {key: 'ds3.' + key for key in bridge.TARGETS}
need, sha, encode, decode = bridge.need, bridge.sha, bridge.json_bytes, bridge.decode
Blocked = bridge.Blocked


def _layout(commit, test_home=None, proof_schema=1):
    need(bridge.pinned(commit, 40) and commit != '0' * 40, 'transaction_commit')
    home = HOME if test_home is None else Path(test_home)
    need(home.is_absolute() and '..' not in home.parts, 'transaction_home')
    ds3 = home / 'Library/Application Support/Adapted Games DS3'
    hub = home / 'Library/Application Support/Adapted Games'
    cs2 = home / 'Library/Application Support/CS2 Standalone'
    targets = {'admission.helper': home / 'AIDev/bin/game-launch-admission',
               'hub.launcher': hub / 'games-play', 'cs2.launcher': cs2 / 'cs2-play',
               'ds3.lifecycle': ds3 / 'ds3-runtime', 'hub.receipt': hub / 'receipt.json',
               'cs2.receipt': cs2 / 'runtime/.owner.json', 'ds3.manifest': ds3 / 'manifest.json',
               'ds3.receipt': ds3 / 'receipt.json', 'ds3.borderlessReceipt': ds3 / 'borderless/receipt.json'}
    return targets, home / 'AIDev/state' / ('.game-native-admission-' + commit), bridge.proof_directory(ds3, commit, proof_schema)


def target_paths():
    """The fixed production destinations; never read target paths from a plan."""
    return _layout('1' * 40)[0]


def _exists(path):
    try:
        path.lstat()
        return True
    except FileNotFoundError:
        return False


def _identity(path, private=False):
    fd = bridge._directory(path, private=private)
    try:
        s = os.fstat(fd)
        return s.st_dev, s.st_ino, s.st_mode, s.st_uid
    finally:
        os.close(fd)


def _inventory(path, expected):
    fd = bridge._directory(path, private=True)
    try:
        need(set(os.listdir(fd)) == expected, 'transaction_inventory')
    finally:
        os.close(fd)


def _images(images):
    need(type(images) is dict and set(images) == set(KEYS), 'transaction_image_scope')
    for key, value in images.items():
        need(type(value) is tuple and len(value) == 2 and type(value[0]) is bytes
             and len(value[0]) <= MAX_IMAGE and type(value[1]) is int and value[1] == MODES[key],
             'transaction_image_schema')


def _derived(before, after, policy, commit):
    _images(before)
    _images(after)
    ds_before = {key: before[target][0] for key, target in DS_KEYS.items()}
    ds_after = bridge.derive(ds_before, policy, commit, after['ds3.lifecycle'][0])
    need(all(after[target] == (ds_after[key], MODES[target]) for key, target in DS_KEYS.items()),
         'transaction_ds3_derivation')
    need(sha(after['admission.helper'][0]) == policy['admissionSha256'], 'transaction_admission_pin')
    # Preserve the owners' opaque metadata while binding their new callers.
    hub = decode(before['hub.receipt'][0])
    cs2 = decode(before['cs2.receipt'][0])
    need(hub.get('owner') == 'control-games-hub' and hub.get('launcherSha256') == sha(before['hub.launcher'][0]),
         'transaction_hub_preimage')
    need(cs2.get('owner') == 'control-cs2-standalone' and cs2.get('launcherSha256') == sha(before['cs2.launcher'][0]),
         'transaction_cs2_preimage')
    hub.update(launcherSha256=sha(after['hub.launcher'][0]), launchAdmissionSha256=policy['admissionSha256'],
               launchReliabilityCommit=commit)
    cs2.update(launcherSha256=sha(after['cs2.launcher'][0]), launcherCommit=commit)
    # Existing planner encoding sorts keys; compare exact bytes against that format.
    import json
    canonical = lambda value: (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    need(after['hub.receipt'][0] == canonical(hub) and after['cs2.receipt'][0] == canonical(cs2),
         'transaction_receipt_derivation')


def plan(commit, before, after, bridge_policy):
    """Pure exact plan; no paths, readiness assertions or mutable authority fields."""
    _layout(commit)
    _derived(before, after, bridge_policy, commit)
    return {'schema': 1, 'owner': OWNER, 'commit': commit, 'bridgePolicy': bridge_policy,
            'targets': {key: {'before': sha(before[key][0]), 'after': sha(after[key][0]), 'mode': MODES[key]}
                        for key in KEYS}}


def _reviewed(raw, pin, commit, before, after, bridge_policy):
    need(type(raw) is bytes and bridge.pinned(pin) and sha(raw) == pin, 'transaction_reviewed_plan_pin')
    value = decode(raw)
    need(value.get('provisionalCommit') == commit and type(value.get('targets')) is dict
         and set(value['targets']) == set(KEYS)
         and value.get('ds3BridgePolicySha256') == sha(encode(bridge_policy)), 'transaction_reviewed_plan_schema')
    need(value['targets'] == {key: {'beforeSha256': sha(before[key][0]), 'afterSha256': sha(after[key][0]),
                                  'mode': MODES[key]} for key in KEYS}, 'transaction_reviewed_targets')
    need(bridge.pinned(value.get('policySha256'))
         and type(value.get('capabilityBeforeSha256')) is dict
         and set(value['capabilityBeforeSha256']) == {'approval', 'routes'}
         and all(item is None or bridge.pinned(item) for item in value['capabilityBeforeSha256'].values())
         and bridge.pinned(value.get('approvalCandidateSha256'))
         and bridge.pinned(value.get('routeCandidateSha256', value.get('routesCandidateSha256'))),
         'transaction_reviewed_capability_binding')
    return value


def _check_guard(guard):
    need(callable(guard) and guard() is True, 'transaction_prerequisite_guard')


def _complete_namespace(destination, files):
    """Resume only exact expected byte prefixes; never retire unknown evidence."""
    directory = bridge._directory(destination, private=True)
    try:
        need(set(os.listdir(directory)) <= set(files), 'transaction_stage_inventory')
        # Validate the entire retained inventory before completing any file.
        for name in os.listdir(directory):
            need(files[name].startswith(bridge._read(destination / name, 0o600, MAX_IMAGE)),
                 'transaction_stage_drift')
        for name, raw in files.items():
            path = destination / name
            prior = bridge._read(path, 0o600, MAX_IMAGE) if _exists(path) else None
            flags = os.O_RDWR | os.O_NOFOLLOW | (os.O_APPEND if prior is not None else os.O_CREAT | os.O_EXCL)
            fd = os.open(name, flags, 0o600, dir_fd=directory)
            try:
                s = os.fstat(fd)
                offset = len(prior) if prior is not None else 0
                need(stat.S_ISREG(s.st_mode) and s.st_uid == os.getuid() and s.st_nlink == 1
                     and stat.S_IMODE(s.st_mode) == 0o600 and s.st_size == offset,
                     'transaction_stage_drift')
                need(os.read(fd, offset + 1) == (prior or b''), 'transaction_stage_drift')
                named = os.stat(name, dir_fd=directory, follow_symlinks=False)
                held = os.fstat(directory)
                parent_named = destination.lstat()
                need((named.st_dev, named.st_ino) == (s.st_dev, s.st_ino)
                     and (parent_named.st_dev, parent_named.st_ino) == (held.st_dev, held.st_ino),
                     'transaction_stage_drift')
                need(raw.startswith(prior or b''), 'transaction_stage_drift')
                while offset < len(raw):
                    count = os.write(fd, raw[offset:])
                    need(count > 0, 'transaction_stage_write')
                    offset += count
                os.fsync(fd)
            finally:
                os.close(fd)
        _inventory(destination, set(files))
        need(all(bridge._read(destination / name, 0o600, MAX_IMAGE) == raw
                 for name, raw in files.items()), 'transaction_stage_drift')
        os.fsync(directory)
    finally:
        os.close(directory)


def _new_namespace(destination, files):
    """Publish an entirely fsynced private namespace without replacing a name.

    A partial exact staging namespace resumes; unknown bytes remain untouched.
    No installed target changes at this preparation boundary.
    """
    parent = bridge._directory(destination.parent)
    stage = '.game-admission-stage-' + destination.name.lstrip('.')
    directory = None
    try:
        need(not _exists(destination), 'transaction_stage_collision')
        if not _exists(destination.parent / stage):
            os.mkdir(stage, 0o700, dir_fd=parent)
        directory = os.open(stage, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        _complete_namespace(destination.parent / stage, files)
        # macOS' no-replace rename is used in production. Linux supports the
        # same primitive via renameat2, keeping fixture tests portable.
        import ctypes
        library = ctypes.CDLL(None, use_errno=True)
        if hasattr(library, 'renameatx_np'):
            function = library.renameatx_np
            args = (parent, os.fsencode(stage), parent, os.fsencode(destination.name), 4)
        else:
            function = library.renameat2
            args = (parent, os.fsencode(stage), parent, os.fsencode(destination.name), 1)
        function.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
        function.restype = ctypes.c_int
        held = os.fstat(directory)
        named = os.stat(stage, dir_fd=parent, follow_symlinks=False)
        need((held.st_dev, held.st_ino) == (named.st_dev, named.st_ino)
             and set(os.listdir(directory)) == set(files), 'transaction_stage_drift')
        for name, raw in files.items():
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
            try:
                facts = os.fstat(fd)
                need(stat.S_ISREG(facts.st_mode) and facts.st_uid == os.getuid()
                     and facts.st_nlink == 1 and stat.S_IMODE(facts.st_mode) == 0o600
                     and facts.st_size == len(raw) and os.read(fd, len(raw) + 1) == raw,
                     'transaction_stage_drift')
            finally:
                os.close(fd)
        if function(*args) != 0:
            raise OSError(ctypes.get_errno(), 'transaction_namespace_publish')
        os.fsync(parent)
    finally:
        if directory is not None:
            os.close(directory)
        os.close(parent)


def _journal(commit, pin, phase='prepared', direction='after', intent=None):
    return {'schema': 1, 'owner': OWNER, 'commit': commit, 'planSha256': pin,
            'phase': phase, 'direction': direction, 'intent': intent}


def _proof(commit, policy, before, after, phase='prepared', direction='after'):
    return {'schema': 1, 'owner': OWNER, 'commit': commit, 'policy': policy,
            'phase': phase, 'direction': direction,
            'images': {key: {'before': sha(before[target][0]), 'after': sha(after[target][0]), 'mode': MODES[target]}
                       for key, target in DS_KEYS.items()}}


def prepare(commit, before, after, bridge_policy, *, reviewed_plan, expected_plan_sha256, guard,
            checkpoint=lambda _: None, _test_home=None):
    """Stage exact evidence only; run() is a separate guarded operation.

    `_test_home` is an explicit synthetic-fixture seam, not production routing.
    Parent adapters must never expose it as a CLI option or read it from data.
    """
    targets, state, proof = _layout(commit, _test_home, bridge_policy['schema'])
    value = plan(commit, before, after, bridge_policy)
    _reviewed(reviewed_plan, expected_plan_sha256, commit, before, after, bridge_policy)
    value['reviewedPlanSha256'] = expected_plan_sha256
    raw = encode(value)
    _check_guard(guard)
    need(all(bridge._read(path, MODES[key], MAX_IMAGE) == before[key][0] for key, path in targets.items()),
         'transaction_prepare_preimage')
    files = {'plan.json': raw, 'reviewed-plan.json': reviewed_plan,
             'journal.json': encode(_journal(commit, expected_plan_sha256))}
    files.update({key + '.' + side: images[key][0] for side, images in (('before', before), ('after', after)) for key in KEYS})
    if _exists(state):
        _inventory(state, set(files))
        need(all(bridge._read(state / name, 0o600, MAX_IMAGE) == data for name, data in files.items()),
             'transaction_existing_preparation')
    else:
        _new_namespace(state, files)
    checkpoint('prepared:global')
    _check_guard(guard)
    need(all(bridge._read(path, MODES[key], MAX_IMAGE) == before[key][0] for key, path in targets.items()),
         'transaction_prepare_preimage')
    proof_files = {'record.json': encode(_proof(commit, bridge_policy, before, after))}
    proof_files.update({key + '.' + side: images[target][0]
                        for side, images in (('before', before), ('after', after)) for key, target in DS_KEYS.items()})
    if _exists(proof):
        _inventory(proof, set(proof_files))
        need(all(bridge._read(proof / name, 0o600, MAX_IMAGE) == data for name, data in proof_files.items()),
             'transaction_proof_collision')
    else:
        _new_namespace(proof, proof_files)
    checkpoint('prepared:proof')
    return load(commit, expected_plan_sha256, guard=guard, checkpoint=checkpoint, _test_home=_test_home)


def load(commit, expected_plan_sha256, *, guard, checkpoint=lambda _: None, _test_home=None):
    return Transaction(commit, expected_plan_sha256, guard, checkpoint, _test_home)


class Transaction:
    def __init__(self, commit, pin, guard, checkpoint, test_home):
        need(bridge.pinned(pin), 'transaction_plan_pin')
        self.commit, self.plan_sha256, self.guard, self.checkpoint = commit, pin, guard, checkpoint
        self.targets, self.state, self.proof = _layout(commit, test_home)
        raw = bridge._read(self.state / 'plan.json', 0o600)
        self.snapshot_plan = decode(raw)
        self.snapshot_plan_sha256 = sha(raw)
        need(set(self.snapshot_plan) == {'schema', 'owner', 'commit', 'bridgePolicy', 'targets', 'reviewedPlanSha256'}
             and type(self.snapshot_plan['schema']) is int and self.snapshot_plan['schema'] == 1
             and self.snapshot_plan['owner'] == OWNER and self.snapshot_plan['commit'] == commit
             and self.snapshot_plan['reviewedPlanSha256'] == pin
             and type(self.snapshot_plan['targets']) is dict and set(self.snapshot_plan['targets']) == set(KEYS), 'transaction_plan_schema')
        self.before, self.after = {}, {}
        for key, row in self.snapshot_plan['targets'].items():
            need(type(row) is dict and set(row) == {'before', 'after', 'mode'}
                 and type(row['mode']) is int and row['mode'] == MODES[key]
                 and bridge.pinned(row['before']) and bridge.pinned(row['after']), 'transaction_plan_images')
            for side, images in (('before', self.before), ('after', self.after)):
                data = bridge._read(self.state / (key + '.' + side), 0o600, MAX_IMAGE)
                need(sha(data) == row[side], 'transaction_backup_drift')
                images[key] = (data, MODES[key])
        _derived(self.before, self.after, self.snapshot_plan['bridgePolicy'], commit)
        self.proof = bridge.proof_directory(self.proof.parent, commit, self.snapshot_plan['bridgePolicy']['schema'])
        self.plan = _reviewed(bridge._read(self.state / 'reviewed-plan.json', 0o600), pin, commit,
                              self.before, self.after, self.snapshot_plan['bridgePolicy'])
        self.images = {key: {'before': self.before[key], 'after': self.after[key]} for key in KEYS}
        self.journal_raw = bridge._read(self.state / 'journal.json', 0o600)
        directories = {self.state, self.proof} | {path.parent for path in self.targets.values()}
        self.identities = {path: _identity(path, private=path in (self.state, self.proof)) for path in directories}
        self.verify()

    def _current(self):
        need(bridge._read(self.state / 'journal.json', 0o600) == self.journal_raw, 'transaction_stale_journal')
        value = decode(self.journal_raw)
        need(set(value) == set(_journal(self.commit, self.plan_sha256))
             and type(value['schema']) is int and value['schema'] == 1
             and value['owner'] == OWNER and value['commit'] == self.commit and value['planSha256'] == self.plan_sha256
             and value['phase'] in ('prepared', 'running', 'complete') and value['direction'] in ('before', 'after')
             and value['intent'] in (None, 'proof-running', 'proof-complete', *KEYS)
             and (value['phase'] == 'running' or value['intent'] is None)
             and (value['phase'] != 'prepared' or value['direction'] == 'after'), 'transaction_journal_schema')
        return value

    def _next_journals(self, current):
        if current['phase'] in ('prepared', 'complete'):
            return [_journal(self.commit, self.plan_sha256, 'running', direction, 'proof-running')
                    for direction in ('before', 'after')]
        return [_journal(self.commit, self.plan_sha256, 'running', current['direction'], intent)
                for intent in ('proof-running', 'proof-complete', *KEYS)] + [
                    _journal(self.commit, self.plan_sha256, 'complete', current['direction'])]

    def _prefix_stage(self, path, choices, mode=0o600):
        if _exists(path):
            raw = bridge._read(path, mode, MAX_IMAGE)
            need(any(choice.startswith(raw) for choice in choices), 'transaction_stage_drift')

    def _proof_value(self):
        value = decode(bridge._read(self.proof / 'record.json', 0o600))
        need(value.get('phase') in ('prepared', 'running', 'complete') and value.get('direction') in ('before', 'after'),
             'transaction_proof_schema')
        need(value == _proof(self.commit, self.snapshot_plan['bridgePolicy'], self.before, self.after,
                            value['phase'], value['direction']), 'transaction_proof_binding')
        return value

    def verify(self):
        current = self._current()
        for path, identity in self.identities.items():
            need(_identity(path, private=path in (self.state, self.proof)) == identity, 'transaction_directory_drift')
        global_files = {'plan.json', 'reviewed-plan.json', 'journal.json'} | {key + '.' + side for key in KEYS for side in ('before', 'after')}
        proof_files = {'record.json'} | {key + '.' + side for key in bridge.TARGETS for side in ('before', 'after')}
        for directory, files, stage in ((self.state, global_files, '.journal.next'), (self.proof, proof_files, '.record.next')):
            if _exists(directory / stage):
                files.add(stage)
            _inventory(directory, files)
        need(sha(bridge._read(self.state / 'plan.json', 0o600)) == self.snapshot_plan_sha256, 'transaction_plan_drift')
        need(sha(bridge._read(self.state / 'reviewed-plan.json', 0o600)) == self.plan_sha256, 'transaction_reviewed_plan_pin')
        for key in KEYS:
            for side, images in (('before', self.before), ('after', self.after)):
                need(bridge._read(self.state / (key + '.' + side), 0o600, MAX_IMAGE) == images[key][0], 'transaction_backup_drift')
            actual = bridge._read(self.targets[key], MODES[key], MAX_IMAGE)
            need(actual in (self.before[key][0], self.after[key][0]), 'transaction_target_third_state')
            stage = self._target_stage(key)
            if _exists(stage):
                need(current['phase'] == 'running' and current['intent'] == key, 'transaction_unowned_stage')
                self._prefix_stage(stage, [self._side(current['direction'])[key][0]], MODES[key])
        for key, target in DS_KEYS.items():
            for side, images in (('before', self.before), ('after', self.after)):
                need(bridge._read(self.proof / (key + '.' + side), 0o600, MAX_IMAGE) == images[target][0],
                     'transaction_proof_backup_drift')
        proof = self._proof_value()
        if current['phase'] == 'prepared':
            need(proof['phase'] == 'prepared' and proof['direction'] == 'after', 'transaction_proof_phase')
        if current['phase'] == 'complete':
            need(proof['phase'] == 'complete' and proof['direction'] == current['direction']
                 and self.side(current['direction']), 'transaction_terminal_drift')
        self._prefix_stage(self.state / '.journal.next', [encode(value) for value in self._next_journals(current)])
        choices = [_proof(self.commit, self.snapshot_plan['bridgePolicy'], self.before, self.after, phase, current['direction'])
                   for phase in ('running', 'complete')]
        self._prefix_stage(self.proof / '.record.next', [encode(value) for value in choices])
        return current

    def _guard(self):
        _check_guard(self.guard)
        self.verify()

    def _side(self, direction):
        return self.after if direction == 'after' else self.before

    def side(self, direction):
        return all(bridge._read(path, MODES[key], MAX_IMAGE) == self._side(direction)[key][0]
                   for key, path in self.targets.items())

    def _target_stage(self, key):
        return self.targets[key].parent / ('.game-native-admission-' + self.commit + '-' + key + '.next')

    def _replace(self, path, wanted, mode, expected, stage):
        need(bridge._read(path, mode, MAX_IMAGE) == expected, 'transaction_replace_preimage')
        parent = bridge._directory(path.parent)
        fd = None
        try:
            need(stage.parent == path.parent, 'transaction_stage_parent')
            if not _exists(stage):
                fd = os.open(stage.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=parent)
                os.fchmod(fd, mode)
                offset = 0
            else:
                raw = bridge._read(stage, mode, MAX_IMAGE)
                need(wanted.startswith(raw), 'transaction_stage_drift')
                offset = len(raw)
                fd = os.open(stage.name, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW, dir_fd=parent)
                opened = os.fstat(fd)
                need(stat.S_ISREG(opened.st_mode) and opened.st_uid == os.getuid() and opened.st_nlink == 1
                     and stat.S_IMODE(opened.st_mode) == mode and opened.st_size == offset, 'transaction_stage_drift')
            with os.fdopen(os.dup(fd), 'wb') as stream:
                stream.write(wanted[offset:])
                stream.flush()
            os.fsync(fd)
            os.close(fd)
            fd = None
            self._guard()
            need(bridge._read(path, mode, MAX_IMAGE) == expected and bridge._read(stage, mode, MAX_IMAGE) == wanted,
                 'transaction_replace_preimage')
            os.replace(stage.name, path.name, src_dir_fd=parent, dst_dir_fd=parent)
            os.fsync(parent)
        finally:
            if fd is not None:
                os.close(fd)
            os.close(parent)

    def _save_journal(self, phase, direction, intent=None):
        wanted = encode(_journal(self.commit, self.plan_sha256, phase, direction, intent))
        self._replace(self.state / 'journal.json', wanted, 0o600, self.journal_raw, self.state / '.journal.next')
        self.journal_raw = wanted
        self.checkpoint('journal:' + phase + ':' + direction + ':' + (intent or 'none'))

    def _save_proof(self, phase, direction):
        path = self.proof / 'record.json'
        expected = bridge._read(path, 0o600)
        wanted = encode(_proof(self.commit, self.snapshot_plan['bridgePolicy'], self.before, self.after, phase, direction))
        self._replace(path, wanted, 0o600, expected, self.proof / '.record.next')
        self.checkpoint('proof:' + phase + ':' + direction)

    def _discard_stage(self, path, mode=0o600):
        """Retire only a known stage already validated against the current journal."""
        self._guard()
        raw = bridge._read(path, mode, MAX_IMAGE)
        parent = bridge._directory(path.parent)
        try:
            self._guard()
            need(bridge._read(path, mode, MAX_IMAGE) == raw, 'transaction_stage_drift')
            os.unlink(path.name, dir_fd=parent)
            os.fsync(parent)
        finally:
            os.close(parent)

    def run(self, direction, recover=False):
        need(direction in ('before', 'after') and type(recover) is bool, 'transaction_direction')
        self._guard()
        current = self._current()
        if recover:
            direction = current['direction']
            if current['phase'] == 'prepared':
                # No operation direction has yet replaced the prepared journal.
                # An unfinished request for BEFORE must not redirect recovery.
                for stage in (self.state / '.journal.next', self.proof / '.record.next'):
                    if _exists(stage):
                        self._discard_stage(stage)
        else:
            need(current['phase'] != 'running', 'transaction_explicit_recovery_required')
        if current['phase'] == 'complete' and current['direction'] == direction:
            stages = [path for path in (self.state / '.journal.next', self.proof / '.record.next') if _exists(path)]
            need(recover or not stages, 'transaction_unsettled_metadata_stage')
            # An unrenamed next-direction intent cannot have published targets.
            # Retain the canonical terminal direction; discard its known stage.
            for stage in stages:
                self._discard_stage(stage)
            return {'changed': bool(stages), 'direction': direction, 'phase': 'complete', 'planSha256': self.plan_sha256}
        if current['phase'] != 'running':
            need(self.side(current['direction'] if current['phase'] == 'complete' else 'before'), 'transaction_operation_preimage')
            self._save_journal('running', direction, 'proof-running')
        proof = self._proof_value()
        # A crash after the final proof publication needs only global settlement.
        if not (proof['phase'] == 'complete' and proof['direction'] == direction and self.side(direction)):
            if proof['phase'] != 'running' or proof['direction'] != direction:
                self._save_proof('running', direction)
            order = KEYS if direction == 'after' else tuple(reversed(KEYS))
            for key in order:
                self._guard()
                wanted = self._side(direction)[key][0]
                observed = bridge._read(self.targets[key], MODES[key], MAX_IMAGE)
                if observed == wanted:
                    if _exists(self._target_stage(key)):
                        self._discard_stage(self._target_stage(key), MODES[key])
                    continue
                self._save_journal('running', direction, key)
                self.checkpoint('intent:' + key + ':' + direction)
                self._replace(self.targets[key], wanted, MODES[key], observed, self._target_stage(key))
                self.checkpoint('published:' + key + ':' + direction)
            self._guard()
            need(self.side(direction), 'transaction_postimage')
            self._save_journal('running', direction, 'proof-complete')
            self._save_proof('complete', direction)
        self._guard()
        need(self.side(direction), 'transaction_postimage')
        self._save_journal('complete', direction)
        self.verify()
        return {'changed': True, 'direction': direction, 'phase': 'complete', 'planSha256': self.plan_sha256}
