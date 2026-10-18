"""Closed paired root-runtime release; owner-level custody, never root execution.

The manifest is reviewed intent, not its own acceptance. Native mutation requires
the existing admitted-source/scoped-root boundary. Synthetic tests inject homes
and guards only through the Python API; the CLI has no destination override.
"""
import argparse
import ctypes
import hashlib
import fcntl
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import stat
from lib.scoped_source_admission import SourceError

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = 'manifests/root-runtime-release.json'
RELEASE_ID = 'usability-root-9123d91-v1'
# Reviewed build-source anchor, not acceptance of this release or installed state.
BASE = '9123d91269c673d4c58878a54bd5ba9fa728150d'
SUFFIX = 'AIDev/state/root-runtime/releases/' + RELEASE_ID
LIMIT = 2 * 1024 * 1024
MAX_RETAINED_ATTEMPTS = 32
MAX_INVENTORY = 256
FILES = {
    'bootstrap': ('install', 'aid-admin-bootstrap', 'aid-admin-bootstrap', '0555'),
    'broker': ('install', 'aid-admin', 'aid-admin', '0555'),
    'policy': ('install', 'aid-admin-policy.json', 'aid-admin-policy.json', '0444'),
    'sudoersTemplate': ('install', 'agent-first-mac-aid-admin.sudoers-template', 'agent-first-mac-aid-admin.sudoers-template', '0444'),
    'installInputs': ('install', 'install-inputs.json', 'install-inputs.json', '0444'),
    'launcher': ('install', 'launch-owner-authenticated-install.zsh', 'launch-owner-authenticated-install.zsh', '0555'),
    'emergency': ('emergency', 'aid-admin-emergency-action', 'aid-admin-emergency-action', '0555'),
    'installReview': ('install', 'review-manifest.json', 'install-review-manifest.json', '0444'),
    'emergencyReview': ('emergency', 'review-manifest.json', 'emergency-review-manifest.json', '0444'),
}


class Fault(ValueError):
    pass


def need(value, reason):
    if value is not True:
        raise Fault(reason)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def parse(raw):
    def pairs(rows):
        value = {}
        for key, item in rows:
            need(key not in value, 'duplicate_key')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(Fault('invalid_json')))


def pin(value):
    need(type(value) is dict and set(value) == {'sha256', 'size'} and
        type(value['sha256']) is str and re.fullmatch('[0-9a-f]{64}', value['sha256']) is not None and
        type(value['size']) is int and 0 < value['size'] <= LIMIT, 'invalid_pin')


def validate_release(value):
    need(type(value) is dict and set(value) == {'schema', 'releaseID', 'sourceAcceptedCommit',
        'sourceAcceptanceRole', 'independentReleaseReviewRequired', 'destinationSuffix',
        'artifacts', 'sourceArtifactSHA256', 'installedContracts'}, 'release_schema')
    need(type(value['schema']) is int and value['schema'] == 1 and value['releaseID'] == RELEASE_ID and
        value['sourceAcceptedCommit'] == BASE and value['destinationSuffix'] == SUFFIX and
        value['sourceAcceptanceRole'] == 'reference-only-not-release-self-acceptance' and
        value['independentReleaseReviewRequired'] is True, 'release_identity')
    need(type(value['artifacts']) is dict and set(value['artifacts']) == set(FILES), 'artifact_set')
    for role, row in value['artifacts'].items():
        need(type(row) is dict and set(row) == {'bundle', 'file', 'destination', 'mode', 'sha256', 'size'} and
            tuple(row[k] for k in ('bundle', 'file', 'destination', 'mode')) == FILES[role], 'artifact_shape')
        pin({k: row[k] for k in ('sha256', 'size')})
    sources = value['sourceArtifactSHA256']
    need(type(sources) is dict and 1 <= len(sources) <= 64, 'source_closure')
    for name, sha in sources.items():
        need(type(name) is str and len(name) < 256 and re.fullmatch('[A-Za-z0-9_./-]+', name) is not None and
            not name.startswith('/') and all(p not in ('', '.', '..') for p in name.split('/')) and
            type(sha) is str and re.fullmatch('[0-9a-f]{64}', sha) is not None, 'source_closure')
    contracts = value['installedContracts']
    need(type(contracts) is dict and set(contracts) == {'successor', 'predecessor'}, 'contract_schema')
    for contract in contracts.values():
        need(type(contract) is dict and set(contract) == {'broker', 'policy', 'sudoers', 'attestation'}, 'contract_schema')
        for role in ('broker', 'policy', 'sudoers'):
            pin(contract[role])
        need(contract['attestation'] == {'size': 341} and type(contract['attestation']['size']) is int, 'attestation_shape')
    for role in ('broker', 'policy'):
        need(contracts['successor'][role] == {k: value['artifacts'][role][k] for k in ('sha256', 'size')}, 'paired_pin')
    return value


def artifact_records(release):
    return validate_release(release)['artifacts']


def health_contract(release):
    return validate_release(release)['installedContracts']


def identity(facts):
    return facts.st_dev, facts.st_ino


class Directory:
    """Hold and recheck every no-follow component, including the named leaf."""
    def __init__(self, path, uid, *, create_from=None):
        self.fds, self.links, self.uid = [], [], uid
        self.path = Path(path)
        need(self.path.is_absolute() and '..' not in self.path.parts, 'absolute_path_required')
        try:
            fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            self.fds.append(fd)
            current = Path('/')
            for part in self.path.parts[1:]:
                current /= part
                if create_from is not None and current.is_relative_to(create_from):
                    self.verify()
                    try:
                        os.mkdir(part, 0o700, dir_fd=fd)
                        os.fsync(fd)
                    except FileExistsError:
                        pass
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                self.fds.append(child)
                facts = os.fstat(child)
                sticky_root = facts.st_uid == 0 and bool(facts.st_mode & stat.S_ISVTX)
                need(stat.S_ISDIR(facts.st_mode) and facts.st_uid in (0, uid) and
                    (not facts.st_mode & 0o022 or sticky_root), 'unsafe_directory')
                if create_from is not None and current.is_relative_to(create_from):
                    need(facts.st_uid == uid and not facts.st_mode & 0o022, 'unsafe_owner_directory')
                self.links.append((fd, part, child, identity(facts)))
                fd = child
            self.fd = fd
            need(os.fstat(fd).st_uid == uid, 'directory_owner')
            self.verify()
        except BaseException:
            self.close()
            raise

    def verify(self):
        for parent, name, fd, expected in self.links:
            facts = os.stat(name, dir_fd=parent, follow_symlinks=False)
            held = os.fstat(fd)
            need(stat.S_ISDIR(facts.st_mode) and identity(facts) == expected == identity(held) and
                facts.st_uid in (0, self.uid) and (not facts.st_mode & 0o022 or
                (facts.st_uid == 0 and bool(facts.st_mode & stat.S_ISVTX))), 'directory_drift')
        return True

    def close(self):
        for fd in reversed(self.fds):
            os.close(fd)
        self.fds = []

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def read_file(directory, name, uid, *, record=None, mode=None):
    need('/' not in name and name not in ('', '.', '..'), 'fixed_leaf')
    directory.verify()
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory.fd)
    try:
        facts = os.fstat(fd)
        need(stat.S_ISREG(facts.st_mode) and facts.st_uid == uid and facts.st_nlink == 1 and
            not facts.st_mode & 0o022 and 0 < facts.st_size <= LIMIT and
            (mode is None or stat.S_IMODE(facts.st_mode) == mode), 'unsafe_file')
        raw = bytearray()
        while len(raw) <= facts.st_size:
            block = os.read(fd, min(65536, facts.st_size + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
        final = os.fstat(fd)
        need(len(raw) == facts.st_size and
            (identity(facts), facts.st_size, facts.st_mtime_ns, facts.st_ctime_ns) ==
            (identity(final), final.st_size, final.st_mtime_ns, final.st_ctime_ns) and
            identity(os.stat(name, dir_fd=directory.fd, follow_symlinks=False)) == identity(facts), 'file_drift')
        if record is not None:
            need(len(raw) == record['size'] and digest(raw) == record['sha256'], 'artifact_drift')
        directory.verify()
        return bytes(raw)
    finally:
        os.close(fd)


def load_manifest(root=ROOT):
    uid = os.getuid()
    with Directory(Path(root) / 'manifests', uid) as directory:
        return validate_release(parse(read_file(directory, 'root-runtime-release.json', uid)))


def load_release(root=ROOT):
    uid = os.getuid()
    release = load_manifest(root)
    # Build-time heads differ; the complete recorded source closure, not a fake
    # manifest acceptance flag, binds these reused binaries to accepted source.
    for name, expected in release['sourceArtifactSHA256'].items():
        with Directory(Path(root) / Path(name).parent, uid) as directory:
            need(digest(read_file(directory, Path(name).name, uid)) == expected, 'source_artifact_drift')
    return release


def verify_bundles(release, install_bundle, emergency_bundle, uid):
    records = artifact_records(release)
    result = {}
    for bundle, path in (('install', install_bundle), ('emergency', emergency_bundle)):
        with Directory(path, uid) as directory:
            for role, row in records.items():
                if row['bundle'] == bundle:
                    result[role] = read_file(directory, row['file'], uid, record=row, mode=int(row['mode'], 8))
    return result


def durable_paths(release, home):
    validate_release(release)
    directory = Path(home) / SUFFIX
    return {'releaseID': RELEASE_ID, 'directory': str(directory),
        'launcher': str(directory / FILES['launcher'][2]),
        'emergency': str(directory / FILES['emergency'][2]), 'verified': True}


def verify_durable(release, home, uid):
    paths = durable_paths(release, home)
    with Directory(paths['directory'], uid) as directory:
        need(stat.S_IMODE(os.fstat(directory.fd).st_mode) == 0o700, 'release_directory_mode')
        expected = {row['destination'] for row in artifact_records(release).values()} | {'root-runtime-release.json'}
        need(set(os.listdir(directory.fd)) == expected, 'release_membership')
        for row in release['artifacts'].values():
            read_file(directory, row['destination'], uid, record=row, mode=int(row['mode'], 8))
        need(read_file(directory, 'root-runtime-release.json', uid, mode=0o444) == encoded(release), 'release_record_drift')
    return paths


def rename_exclusive(fd, source, target):
    libc = ctypes.CDLL(None, use_errno=True)
    function = libc.renameatx_np
    function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    function.restype = ctypes.c_int
    if function(fd, os.fsencode(source), fd, os.fsencode(target), 4) != 0:
        raise OSError(ctypes.get_errno(), 'exclusive_publication_refused')


def attempt_name(token):
    need(type(token) is str and re.fullmatch('[0-9a-f]{32}', token) is not None, 'attempt_id')
    return '.' + RELEASE_ID + '.pending-' + token


def attempt_record(release, token):
    return encoded({'schema': 1, 'owner': 'root-delivery-preparation',
        'releaseSHA256': digest(encoded(release)), 'attempt': token})


def preparation_names(parent):
    # Bound iteration itself, not just the resulting pending count.
    names = []
    with os.scandir(parent.fd) as entries:
        for entry in entries:
            need(len(names) < MAX_INVENTORY, 'preparation_inventory_limit')
            names.append(entry.name)
    return names


def preparation_lease(parent, *, exclusive):
    try:
        fcntl.flock(parent.fd, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB)
    except BlockingIOError:
        raise Fault('preparation_busy') from None


def inventory_attempts(release, home, uid):
    """Report metadata debt too; never adopt an unknown legacy attempt."""
    parent_path = (Path(home) / SUFFIX).parent
    current = Path(home)
    with Directory(current, uid):
        pass
    for part in parent_path.relative_to(home).parts:
        current /= part
        if not os.path.lexists(current):
            return {'status': 'PREPARATION_INVENTORY', 'attempts': [], 'retainedAttempts': 0,
                'pendingMetadata': 0, 'capacityReason': None, 'installed': False}
        with Directory(current, uid):
            pass
    with Directory(parent_path, uid) as parent:
        preparation_lease(parent, exclusive=False)
        names = preparation_names(parent)
        prefix = '.' + RELEASE_ID + '.pending'
        bases = sorted({name.removesuffix('.json') for name in names
            if name == prefix or name.startswith(prefix + '-')})
        rows = []
        for name in bases:
            token = name[len(prefix) + 1:]
            known = False
            if re.fullmatch('[0-9a-f]{32}', token) and name + '.json' in names:
                try:
                    known = read_file(parent, name + '.json', uid, mode=0o600) == attempt_record(release, token)
                except (Fault, OSError):
                    pass
            rows.append({'attempt': token if re.fullmatch('[0-9a-f]{32}', token) else None,
                'recordVerified': known, 'directoryPresent': name in names,
                'metadataPresent': name + '.json' in names,
                'nextAction': 'retire-exact-attempt-with-sealed-bundles' if known else 'preserve-unknown-attempt'})
        parent.verify()
        return {'status': 'PREPARATION_INVENTORY', 'attempts': rows,
            'retainedAttempts': len(rows),
            'pendingMetadata': sum(row['metadataPresent'] for row in rows),
            'capacityReason': 'retained_attempt_limit_preserve_and_review' if len(rows) >= MAX_RETAINED_ATTEMPTS else None,
            'installed': False}


def retire_attempt(release, token, install_bundle, emergency_bundle, home, uid, *, source_guard):
    """Retire one recorded preparation only, never a release/recovery journal.

    The complete inventory must be absent or exact expected byte prefixes from
    the supplied sealed bundles. The record is removed last, so interruption
    leaves a re-verifiable subset. Unknown names/bytes/metadata are untouched.
    The shared directory lease serializes this with cooperating preparation.
    """
    name = attempt_name(token)
    need(source_guard() is True, 'source_drift')
    payloads = verify_bundles(release, install_bundle, emergency_bundle, uid)
    expected = {row['destination']: (payloads[role], int(row['mode'], 8))
        for role, row in release['artifacts'].items()}
    expected['root-runtime-release.json'] = (encoded(release), 0o444)
    with Directory((Path(home) / SUFFIX).parent, uid) as parent:
        preparation_lease(parent, exclusive=True)
        record = name + '.json'
        names = preparation_names(parent)
        if name not in names and record not in names:
            need(source_guard() is True and parent.verify() is True, 'source_drift')
            return {'status': 'PREPARATION_ABSENT', 'attempt': token, 'installed': False,
                'publishedReleaseChanged': False, 'recoveryMaterialRemoved': False}
        need(read_file(parent, record, uid, mode=0o600) == attempt_record(release, token), 'attempt_record_unknown')
        record_fd = os.open(record, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent.fd)
        parent.fds.append(record_fd)
        record_identity = identity(os.fstat(record_fd))
        def record_guard():
            need(read_file(parent, record, uid, mode=0o600) == attempt_record(release, token)
                and identity(os.stat(record, dir_fd=parent.fd, follow_symlinks=False)) ==
                identity(os.fstat(record_fd)) == record_identity, 'attempt_record_unknown')
        record_guard()
        if name in names:
            with Directory(parent.path / name, uid) as staged:
                need(stat.S_IMODE(os.fstat(staged.fd).st_mode) == 0o700, 'attempt_directory_metadata')
                members = set(preparation_names(staged))
                need(members <= set(expected), 'attempt_inventory_unknown')
                held = []
                try:
                    for leaf in sorted(members):
                        raw, mode = expected[leaf]
                        fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=staged.fd)
                        held.append((leaf, fd, None, None))
                        facts = os.fstat(fd)
                        need(stat.S_ISREG(facts.st_mode) and facts.st_uid == uid and facts.st_nlink == 1
                            and stat.S_IMODE(facts.st_mode) in (0o600, mode)
                            and 0 <= facts.st_size <= len(raw)
                            and (stat.S_IMODE(facts.st_mode) == 0o600 or facts.st_size == len(raw)), 'attempt_file_unknown')
                        actual = os.pread(fd, len(raw) + 1, 0)
                        need(len(actual) == facts.st_size and raw.startswith(actual), 'attempt_bytes_unknown')
                        stamp = lambda s: (s.st_dev, s.st_ino, s.st_uid, s.st_gid,
                            s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
                        held[-1] = leaf, fd, stamp(facts), actual
                    # Validate every file before deleting any. Repeat binding at
                    # each unlink; no path traversal or recursive removal.
                    for leaf, fd, before, actual in held:
                        need(source_guard() is True and parent.verify() and staged.verify(), 'source_drift')
                        record_guard()
                        need(set(os.listdir(staged.fd)) == members, 'attempt_inventory_unknown')
                        facts = os.fstat(fd)
                        named = os.stat(leaf, dir_fd=staged.fd, follow_symlinks=False)
                        raw, mode = expected[leaf]
                        need(stamp(named) == stamp(facts) == before
                            and os.pread(fd, len(raw) + 1, 0) == actual, 'attempt_drift')
                        os.unlink(leaf, dir_fd=staged.fd)
                        members.remove(leaf)
                    need(not os.listdir(staged.fd) and staged.verify() and parent.verify(), 'attempt_drift')
                    record_guard()
                    os.rmdir(name, dir_fd=parent.fd)
                    os.fsync(parent.fd)
                finally:
                    for _, fd, _, _ in held:
                        os.close(fd)
        need(source_guard() is True and parent.verify() is True, 'source_drift')
        record_guard()
        os.unlink(record, dir_fd=parent.fd)
        os.fsync(parent.fd)
    return {'status': 'PREPARATION_RETIRED', 'attempt': token, 'installed': False,
        'publishedReleaseChanged': False, 'recoveryMaterialRemoved': False}


def stage_release(release, install_bundle, emergency_bundle, home, uid, *, source_guard):
    need(uid > 0 and callable(source_guard) and source_guard() is True, 'source_guard_required')
    payloads = verify_bundles(release, install_bundle, emergency_bundle, uid)
    target = Path(home) / SUFFIX
    # The owner home must already exist; only this fixed user-state subtree can
    # be created. Existing parents are never chmod/chowned or replaced.
    with Directory(home, uid):
        pass
    need(source_guard() is True, 'source_drift')
    with Directory(target.parent, uid, create_from=Path(home) / 'AIDev') as parent:
        preparation_lease(parent, exclusive=True)
        names = preparation_names(parent)
        if RELEASE_ID in names:
            value = verify_durable(release, home, uid)
            need(source_guard() is True, 'source_drift')
            return {**value, 'status': 'UNCHANGED', 'installed': False}
        # A crashed preparation owns no published target. Never resume or remove
        # its unknown bytes; use a fresh exclusive sibling instead. Count even
        # foreign/symlink entries without following them to bound retained work.
        prefix = '.' + RELEASE_ID + '.pending'
        need(len({name.removesuffix('.json') for name in names
            if name == prefix or name.startswith(prefix + '-')}) < MAX_RETAINED_ATTEMPTS,
            'retained_attempt_limit_preserve_and_review')
        token = secrets.token_hex(16)
        pending = attempt_name(token)
        need(source_guard() is True and parent.verify() is True, 'source_drift')
        # Reserve ownership before mkdir. A completed record with no directory
        # is truthful metadata debt and is safely retireable by exact token.
        record = pending + '.json'
        fd = os.open(record, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent.fd)
        try:
            raw = attempt_record(release, token)
            offset = 0
            while offset < len(raw):
                count = os.write(fd, raw[offset:])
                need(count > 0, 'short_write')
                offset += count
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(parent.fd)
        os.mkdir(pending, 0o700, dir_fd=parent.fd)
        os.fsync(parent.fd)
        # Failures retain this isolated attempt. A later invocation starts fresh;
        # only an exact verified published release can be reported UNCHANGED.
        with Directory(target.parent / pending, uid) as staged:
            rows = [(row['destination'], payloads[role], int(row['mode'], 8))
                for role, row in release['artifacts'].items()]
            rows.append(('root-runtime-release.json', encoded(release), 0o444))
            for name, raw, mode in rows:
                need(source_guard() is True and parent.verify() is True and staged.verify() is True, 'source_drift')
                fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=staged.fd)
                try:
                    offset = 0
                    while offset < len(raw):
                        count = os.write(fd, raw[offset:])
                        need(count > 0, 'short_write')
                        offset += count
                    os.fchmod(fd, mode)
                    os.fsync(fd)
                finally:
                    os.close(fd)
                need(read_file(staged, name, uid, mode=mode) == raw, 'staged_drift')
            os.fsync(staged.fd)
            need(verify_bundles(release, install_bundle, emergency_bundle, uid) == payloads and
                source_guard() is True and parent.verify() is True and staged.verify() is True, 'prepublication_drift')
            rename_exclusive(parent.fd, pending, RELEASE_ID)
            os.fsync(parent.fd)
        value = verify_durable(release, home, uid)
        need(source_guard() is True and parent.verify() is True, 'postpublication_drift')
        need(read_file(parent, record, uid, mode=0o600) == attempt_record(release, token), 'attempt_record_unknown')
        os.unlink(record, dir_fd=parent.fd)
        os.fsync(parent.fd)
        return {**value, 'status': 'STAGED', 'installed': False}


def admitted_source(*, full=False, operation_check=None, entrypoint='bin/root-delivery'):
    from lib.scoped_source_admission import admitted_source as held_source, require_execution
    need(full is False, 'source_scope')
    need(ROOT == Path(pwd.getpwuid(os.getuid()).pw_dir) / 'AIDev/control', 'canonical_source_required')
    require_execution(ROOT)
    # This is unprivileged custody/observation, not review of a root apply
    # target. The sealed artifacts and installed-owner/native boundary remain
    # separate. Hold every computed release input without replaying history.
    # Build scripts/tests in the release closure are hash-only provenance,
    # not programs this adapter executes. Actual runtime imports still promote
    # normal executable discovery even if also present in this opaque set.
    with held_source(ROOT, entrypoints=(entrypoint,), data_paths=(),
            opaque_paths=(MANIFEST,)) as (head, guard):
        # Select dynamic provenance inputs only from the already held manifest.
        # The nested context extends the original snapshot, not a newer HEAD.
        release = load_manifest()
        need(guard() is True, 'source_drift')
        with held_source(ROOT, data_paths=(), opaque_paths=tuple(release['sourceArtifactSHA256'])) as (same_head, extended):
            need(same_head == head and extended() is True and load_release() == release, 'source_drift')
            if operation_check is not None:
                need(operation_check(head, source_guard=extended) is True, 'source_operation_failed')
            need(extended() is True and load_release() == release, 'source_drift')


def native(operation, install_bundle=None, emergency_bundle=None, attempt=None):
    uid = os.getuid()
    home = pwd.getpwuid(uid).pw_dir
    need(uid > 0, 'owner_only')
    need(operation in ('inspect', 'verify', 'stage', 'handoff', 'inventory', 'retire'), 'fixed_operation')
    if operation == 'inspect':
        release = load_release()
        verify_bundles(release, install_bundle, emergency_bundle, uid)
        return {'status': 'BUNDLES_VERIFIED', 'releaseID': RELEASE_ID, 'installed': False,
            'sourceAdmissionClaimed': False}
    # Staging/handoff consume sealed bundle and root-contract observations,
    # not vendor CLI schema capability. Held source admission below spans the
    # work; native_health and the owner-authenticated typed installer remain
    # independent requirements and are never replaced by source admission.
    results = []
    def operation_check(head, *, source_guard):
        need(source_guard() is True, 'source_drift')
        release = load_release()
        if operation == 'stage':
            result = stage_release(release, install_bundle, emergency_bundle, home, uid, source_guard=source_guard)
        elif operation == 'inventory':
            result = inventory_attempts(release, home, uid)
        elif operation == 'retire':
            result = retire_attempt(release, attempt, install_bundle, emergency_bundle, home, uid, source_guard=source_guard)
        else:
            result = verify_durable(release, home, uid)
            result['status'] = 'DURABLE_RELEASE_VERIFIED'
            if operation == 'handoff':
                from lib.root_runtime_health import native_health
                health = native_health(release, home, uid, source_guard, allow_predecessor=True)
                need(health.get('verdict') in ('ROOT_RUNTIME_READY', 'PREDECESSOR_READY'), 'installed_preflight_failed')
                result.update(status='OWNER_NATIVE_HANDOFF' if health['verdict'] == 'PREDECESSOR_READY' else 'ROOT_ALREADY_INSTALLED', installedPreflight=health['verdict'],
                    installedPreflightEvidence=health,
                    timestampClearCommand='/usr/bin/sudo -k',
                    postcheckCommand=str(ROOT / 'bin/root-runtime-doctor') + ' --json',
                    installerExecuted=False)
        if result['status'] != 'OWNER_NATIVE_HANDOFF':
            result.pop('launcher', None)
        need(source_guard() is True and load_release() == release, 'source_drift')
        results.append(result)
        return True
    admitted_source(full=False, operation_check=operation_check)
    need(len(results) == 1, 'source_unadmitted')
    return results[0]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('inspect', 'verify', 'stage', 'handoff', 'inventory', 'retire'))
    parser.add_argument('--install-bundle')
    parser.add_argument('--emergency-bundle')
    parser.add_argument('--attempt')
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args(argv)
    try:
        need((args.operation in ('inspect', 'stage', 'retire')) == (args.install_bundle is not None and args.emergency_bundle is not None)
            and (args.operation in ('inspect', 'stage', 'retire') or (args.install_bundle is None and args.emergency_bundle is None)), 'paired_bundle_arguments')
        need((args.operation == 'retire') == (args.attempt is not None), 'attempt_argument')
        value = native(args.operation, args.install_bundle, args.emergency_bundle, args.attempt)
    except Exception as error:
        value = {'status': 'BLOCKED', 'reason': str(error) if isinstance(error, Fault) else 'delivery_unavailable',
            'installerExecuted': False, 'rootOperationsPerformed': False}
        if isinstance(error, SourceError):
            from lib.scoped_source_admission import public_failure
            value.update(public_failure(error))
        elif isinstance(error, Fault) and str(error) in {
                'retained_attempt_limit_preserve_and_review', 'preparation_inventory_limit',
                'preparation_busy', 'attempt_record_unknown', 'attempt_inventory_unknown',
                'attempt_file_unknown', 'attempt_bytes_unknown', 'attempt_drift'}:
            value['nextAction'] = ('retry-after-preparation-settles' if str(error) == 'preparation_busy'
                else 'inspect-preparations-and-preserve-unknown')
    print(json.dumps(value, sort_keys=True))
    return 1 if value['status'] == 'BLOCKED' else 0
