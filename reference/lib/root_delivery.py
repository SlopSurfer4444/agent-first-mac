"""Closed paired root-runtime release; owner-level custody, never root execution.

The manifest is reviewed intent, not its own acceptance. Native mutation requires
the existing accepted-source/full-doctor boundary. Synthetic tests inject homes
and guards only through the Python API; the CLI has no destination override.
"""
import argparse
import ctypes
import hashlib
import importlib.machinery
import json
import os
from pathlib import Path
import pwd
import re
import stat

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = 'manifests/root-runtime-release.json'
RELEASE_ID = 'owner-first-root-849a241-v1'
BASE = '849a241f9592e1faf3b9a2a9dc2107d6b93ac46a'
SUFFIX = 'AIDev/state/root-runtime/releases/' + RELEASE_ID
LIMIT = 2 * 1024 * 1024
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


def load_release(root=ROOT):
    uid = os.getuid()
    with Directory(Path(root) / 'manifests', uid) as directory:
        release = validate_release(parse(read_file(directory, 'root-runtime-release.json', uid)))
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
        pending = '.' + RELEASE_ID + '.pending'
        need(pending not in os.listdir(parent.fd), 'partial_release_retained')
        if RELEASE_ID in os.listdir(parent.fd):
            value = verify_durable(release, home, uid)
            need(source_guard() is True, 'source_drift')
            return {**value, 'status': 'UNCHANGED', 'installed': False}
        need(source_guard() is True and parent.verify() is True, 'source_drift')
        os.mkdir(pending, 0o700, dir_fd=parent.fd)
        os.fsync(parent.fd)
        # Failures retain this exact pending directory for diagnosis. No cleanup
        # can delete foreign contents or turn a failed attempt into success.
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
        return {**value, 'status': 'STAGED', 'installed': False}


def admitted_source(*, full, operation_check=None):
    from lib import current_doctor_native
    need(ROOT == Path(pwd.getpwuid(os.getuid()).pw_dir) / 'AIDev/control', 'canonical_source_required')
    doctor = importlib.machinery.SourceFileLoader('root_delivery_doctor', str(ROOT / 'bin/current-doctor')).load_module()
    if operation_check is None:
        def operation_check(head, *, source_guard):
            return source_guard()
    value = current_doctor_native.native(doctor, not full, operation_check=operation_check)
    report = doctor.public_report(value, git_only=not full)
    need(report.get('integratedMain') is True and report.get('verdict') ==
        ('PASS' if full else 'GIT_ONLY_VALID'), 'source_unadmitted')


def native(operation, install_bundle=None, emergency_bundle=None):
    uid = os.getuid()
    home = pwd.getpwuid(uid).pw_dir
    need(uid > 0, 'owner_only')
    release = load_release()
    need(operation in ('inspect', 'verify', 'stage', 'handoff'), 'fixed_operation')
    if operation == 'inspect':
        verify_bundles(release, install_bundle, emergency_bundle, uid)
        return {'status': 'BUNDLES_VERIFIED', 'releaseID': RELEASE_ID, 'installed': False,
            'sourceAdmissionClaimed': False}
    if operation in ('stage', 'handoff'):
        # current-doctor executes operation_check before its vendor sentinel.
        # Complete full readiness first, then hold a fresh Git-only source guard
        # around staging, as the existing maintenance delivery adapter does.
        admitted_source(full=True)
    results = []
    def operation_check(head, *, source_guard):
        need(source_guard() is True, 'source_drift')
        need(load_release() == release, 'release_source_drift')
        if operation == 'stage':
            result = stage_release(release, install_bundle, emergency_bundle, home, uid, source_guard=source_guard)
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
    parser.add_argument('operation', choices=('inspect', 'verify', 'stage', 'handoff'))
    parser.add_argument('--install-bundle')
    parser.add_argument('--emergency-bundle')
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args(argv)
    try:
        need((args.operation in ('inspect', 'stage')) == (args.install_bundle is not None and args.emergency_bundle is not None)
            and (args.operation in ('inspect', 'stage') or (args.install_bundle is None and args.emergency_bundle is None)), 'paired_bundle_arguments')
        value = native(args.operation, args.install_bundle, args.emergency_bundle)
    except Exception as error:
        value = {'status': 'BLOCKED', 'reason': str(error) if isinstance(error, Fault) else 'delivery_unavailable',
            'installerExecuted': False, 'rootOperationsPerformed': False}
    print(json.dumps(value, sort_keys=True))
    return 1 if value['status'] == 'BLOCKED' else 0
