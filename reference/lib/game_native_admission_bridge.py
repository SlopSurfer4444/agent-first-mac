"""Read-only, predecessor-bound admission successors of installed native DS3.

The caller owns source admission, locks and publication. This module derives
metadata and verifies retained evidence; no applier is supplied here. It grants
no launch/write authority and establishes no native observer MATCH result.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat

OWNER = 'control-ds3-native-launch'
POLICY_FIELDS = {'schema', 'id', 'owner', 'previousLifecycleSha256',
                 'lifecycleSha256', 'admissionSha256', 'sourceManifestSha256'}
DESCRIPTOR_FIELDS = {'acceptedCommit', 'policySha256', 'lifecycleSha256', 'admissionSha256'}
TARGETS = {'lifecycle': 'ds3-runtime', 'manifest': 'manifest.json',
           'receipt': 'receipt.json', 'borderlessReceipt': 'borderless/receipt.json'}
MODES = {key: 0o700 if key == 'lifecycle' else 0o600 for key in TARGETS}
NATIVE_PATHS = {'engine/lib/wine/x86_64-unix/' + name
                for name in ('winemac.so', 'winemetal.so', 'ntdll.so')}
MAX_IMAGE = 64 * 1024 * 1024
MAX_METADATA = 1024 * 1024
MAX_HISTORY = 8
PROOF_PREFIXES = {1: '.native-admission-', 2: '.native-launch-admission-'}


class Blocked(RuntimeError):
    pass


def need(ok, reason):
    if not ok:
        raise Blocked(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def pinned(value, size=64):
    return type(value) is str and re.fullmatch('[0-9a-f]{' + str(size) + '}', value) is not None


def json_bytes(value):
    return (json.dumps(value, indent=2) + '\n').encode()


def decode(raw):
    need(type(raw) is bytes and len(raw) <= MAX_METADATA, 'admission_metadata_limit')
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'admission_duplicate_json_key')
            result[key] = value
        return result
    def constant(_):
        raise Blocked('admission_invalid_json')
    try:
        value = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, UnicodeError, RecursionError):
        raise Blocked('admission_invalid_json') from None
    need(type(value) is dict, 'admission_metadata_object')
    return value


def _policy(policy):
    need(type(policy) is dict and type(policy.get('schema')) is int
         and policy['schema'] in (1, 2), 'admission_policy_schema')
    fields = POLICY_FIELDS | ({'previousAdmission'} if policy['schema'] == 2 else set())
    need(set(policy) == fields
         and policy['id'] == 'ds3-native-admission-bridge' and policy['owner'] == OWNER
         and all(pinned(policy[key]) for key in POLICY_FIELDS - {'schema', 'id', 'owner'}),
         'admission_policy_schema')
    if policy['schema'] == 2:
        previous = policy['previousAdmission']
        need(type(previous) is dict and set(previous) == DESCRIPTOR_FIELDS
             and pinned(previous['acceptedCommit'], 40)
             and all(pinned(previous[key]) for key in DESCRIPTOR_FIELDS - {'acceptedCommit'})
             and previous['lifecycleSha256'] == policy['previousLifecycleSha256'],
             'admission_previous_descriptor')


def _native(manifest):
    need(type(manifest) is dict and type(manifest.get('schema')) is int and manifest['schema'] == 4
         and manifest.get('id') == 'ds3-marshal-fix'
         and manifest.get('owner') == 'control-ds3-marshal-fix', 'admission_manifest_schema')
    native = manifest.get('rendererOverride')
    fields = {'d3d11Sha256', 'provenanceSha256', 'policySha256', 'transactionCommit',
              'diagnosticCapable', 'nativeBorderlessCapable', 'traceProtocolVersion',
              'nativeRuntimeHashes', 'lifecycleSha256'}
    need(type(native) is dict and set(native) == fields
         and all(pinned(native[key]) for key in ('d3d11Sha256', 'provenanceSha256', 'policySha256', 'lifecycleSha256'))
         and pinned(native['transactionCommit'], 40)
         and type(native['diagnosticCapable']) is bool and type(native['nativeBorderlessCapable']) is bool
         and type(native['traceProtocolVersion']) is int and native['traceProtocolVersion'] == 2
         and type(native['nativeRuntimeHashes']) is dict and set(native['nativeRuntimeHashes']) == NATIVE_PATHS
         and all(pinned(value) for value in native['nativeRuntimeHashes'].values()), 'admission_native_schema')
    return native


def derive(before, policy, commit, after_lifecycle):
    """Derive exactly four images, preserving opaque owner metadata verbatim in value."""
    _policy(policy)
    need(pinned(commit, 40), 'admission_commit')
    need(type(before) is dict and set(before) == set(TARGETS)
         and all(type(raw) is bytes and len(raw) <= MAX_IMAGE for raw in before.values())
         and type(after_lifecycle) is bytes and len(after_lifecycle) <= MAX_IMAGE, 'admission_image_schema')
    need(sha(before['lifecycle']) == policy['previousLifecycleSha256']
         and sha(after_lifecycle) == policy['lifecycleSha256'], 'admission_lifecycle_pin')
    need(sha(before['manifest']) == policy['sourceManifestSha256'], 'admission_source_manifest_pin')
    manifest = decode(before['manifest'])
    native = _native(manifest)
    if policy['schema'] == 1:
        need('launchAdmissionOverride' not in manifest, 'admission_successor_already_present')
        need(native['lifecycleSha256'] == policy['previousLifecycleSha256'], 'admission_native_lifecycle_pin')
    else:
        need(manifest.get('launchAdmissionOverride') == policy['previousAdmission'],
             'admission_previous_descriptor')
        need(commit != policy['previousAdmission']['acceptedCommit'], 'admission_successor_commit')
    receipt = decode(before['receipt'])
    borderless = decode(before['borderlessReceipt'])
    need(type(receipt.get('schema')) is int and receipt['schema'] == 1
         and receipt.get('owner') == 'control-ds3-marshal-fix'
         and receipt.get('manifestSha256') == policy['sourceManifestSha256']
         and receipt.get('lifecycleSha256') == policy['previousLifecycleSha256']
         and pinned(receipt.get('runtimeTreeSha256')), 'admission_receipt_preimage')
    need(type(borderless.get('schema')) is int and borderless['schema'] == 1
         and borderless.get('owner') == 'control-ds3-marshal-fix'
         and borderless.get('baseManifestSha256') == policy['sourceManifestSha256']
         and borderless.get('baseRuntimeTreeSha256') == receipt['runtimeTreeSha256'],
         'admission_borderless_preimage')
    descriptor = {'acceptedCommit': commit, 'policySha256': sha(json_bytes(policy)),
                  'lifecycleSha256': policy['lifecycleSha256'], 'admissionSha256': policy['admissionSha256']}
    manifest_after = json_bytes(dict(manifest, launchAdmissionOverride=descriptor))
    return {'lifecycle': after_lifecycle, 'manifest': manifest_after,
            'receipt': json_bytes(dict(receipt, manifestSha256=sha(manifest_after), lifecycleSha256=policy['lifecycleSha256'])),
            'borderlessReceipt': json_bytes(dict(borderless, baseManifestSha256=sha(manifest_after)))}


def _directory(path, private=False):
    """Open each directory without following links; caller closes the returned fd."""
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts, 'admission_unsafe_path')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            current = os.fstat(fd)
            need(current.st_uid in (0, os.getuid()) and not current.st_mode & 0o022,
                 'admission_unsafe_directory')
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        current = os.fstat(fd)
        need(current.st_uid in (0, os.getuid()) and not current.st_mode & 0o022,
             'admission_unsafe_directory')
        if private:
            need(current.st_uid == os.getuid() and stat.S_IMODE(current.st_mode) == 0o700,
                 'admission_namespace_mode')
        return fd
    except BaseException:
        os.close(fd)
        raise


def _read(path, mode=None, limit=MAX_METADATA):
    path = Path(path)
    parent = _directory(path.parent)
    fd = None
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and before.st_nlink == 1
             and not before.st_mode & 0o022 and before.st_size <= limit
             and (mode is None or stat.S_IMODE(before.st_mode) == mode), 'admission_unsafe_file')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            raw = stream.read(limit + 1)
        after = os.fstat(fd)
        identity = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_uid,
                                  value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        current = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        need(len(raw) <= limit and identity(before) == identity(after) == identity(current), 'admission_file_drift')
        return raw
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def _record(directory):
    fd = _directory(directory, private=True)
    try:
        expected = {'record.json'} | {key + '.' + side for key in TARGETS for side in ('before', 'after')}
        need(set(os.listdir(fd)) == expected, 'admission_namespace_inventory')
    finally:
        os.close(fd)
    record = decode(_read(directory / 'record.json', 0o600))
    need(set(record) == {'schema', 'owner', 'commit', 'policy', 'phase', 'direction', 'images'}
         and type(record['schema']) is int and record['schema'] == 1 and record['owner'] == OWNER
         and pinned(record['commit'], 40)
         and record['phase'] in ('prepared', 'running', 'complete')
         and record['direction'] in ('before', 'after'), 'admission_record_schema')
    _policy(record['policy'])
    need(directory == proof_directory(directory.parent, record['commit'], record['policy']['schema']),
         'admission_history_generation')
    need(type(record['images']) is dict and set(record['images']) == set(TARGETS), 'admission_record_images')
    for key, row in record['images'].items():
        need(type(row) is dict and set(row) == {'before', 'after', 'mode'}
             and type(row['mode']) is int and row['mode'] == MODES[key]
             and pinned(row['before']) and pinned(row['after']), 'admission_record_images')
    return record


def proof_directory(root, commit, schema=1):
    need(type(schema) is int and schema in PROOF_PREFIXES and pinned(commit, 40),
         'admission_proof_generation')
    return Path(root) / (PROOF_PREFIXES[schema] + commit)


def pending_guard(root):
    """Reject malformed or unsettled admission histories without recursive verification."""
    root = Path(root)
    fd = _directory(root)
    try:
        names = [name for name in os.listdir(fd) if any(name.startswith(prefix) for prefix in PROOF_PREFIXES.values())]
    finally:
        os.close(fd)
    need(len(names) <= MAX_HISTORY, 'admission_history_limit')
    for name in names:
        schema = next((schema for schema, prefix in PROOF_PREFIXES.items()
                       if re.fullmatch(re.escape(prefix) + r'[0-9a-f]{40}', name)), None)
        need(schema is not None, 'admission_history_name')
        record = _record(root / name)
        need(record['policy']['schema'] == schema and record['commit'] == name[-40:],
             'admission_history_generation')
        need(record['phase'] == 'complete', 'admission_recovery_required')


def verify(root, manifest):
    """Prove the active exact successor and return its effective lifecycle hash."""
    root = Path(root)
    _native(manifest)
    descriptor = manifest.get('launchAdmissionOverride')
    need(type(descriptor) is dict and set(descriptor) == DESCRIPTOR_FIELDS
         and pinned(descriptor['acceptedCommit'], 40)
         and all(pinned(descriptor[key]) for key in DESCRIPTOR_FIELDS - {'acceptedCommit'}), 'admission_override_schema')
    pending_guard(root)
    directories = [proof_directory(root, descriptor['acceptedCommit'], schema) for schema in PROOF_PREFIXES]
    present = [path for path in directories if path.exists() or path.is_symlink()]
    need(len(present) == 1, 'admission_proof_generation')
    directory = present[0]
    record = _record(directory)
    need(record['phase'] == 'complete' and record['direction'] == 'after', 'admission_not_applied')
    policy = record['policy']
    need(descriptor == {'acceptedCommit': record['commit'], 'policySha256': sha(json_bytes(policy)),
                        'lifecycleSha256': policy['lifecycleSha256'], 'admissionSha256': policy['admissionSha256']},
         'admission_policy_binding')
    images = {side: {} for side in ('before', 'after')}
    for key in TARGETS:
        for side in images:
            raw = _read(directory / (key + '.' + side), 0o600, MAX_IMAGE)
            need(sha(raw) == record['images'][key][side], 'admission_backup_drift')
            images[side][key] = raw
    need(derive(images['before'], policy, record['commit'], images['after']['lifecycle']) == images['after'],
         'admission_derived_images')
    need(decode(images['after']['manifest']) == manifest, 'admission_manifest_binding')
    for key, relative in TARGETS.items():
        need(_read(root / relative, MODES[key], MAX_IMAGE) == images['after'][key], 'admission_endpoint_drift')
    need(len(root.parents) >= 3, 'admission_root_scope')
    helper = root.parents[2] / 'AIDev/bin/game-launch-admission'
    need(sha(_read(helper, limit=65536)) == policy['admissionSha256'], 'admission_helper_drift')
    return policy['lifecycleSha256']
