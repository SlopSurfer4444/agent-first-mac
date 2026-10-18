"""Immutable assets for the separately owned native admission publisher.

No launch, approval, route or existing code endpoint is changed here. Assets
are retained through admission rollback because retained histories need them.
The caller owns source admission, locks and the guard supplied to publish().
"""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess

from lib import game_native_admission_transaction as transaction

HOME = Path(pwd.getpwuid(os.getuid()).pw_dir)
OWNER = 'control-ds3-native-launch'
APP = 'Dark Souls III Native.app'
COMPANIONS = {
    'binding/native_launch_binding.py': 0o600,
    'bridge.py': 0o600,
    'native-identity/native_identity.py': 0o600,
    'native-identity/probe': 0o700,
    'native-identity/prefix_identity.py': 0o600,
    'native-identity/prefix_probe': 0o700,
}
BUNDLE = {'Contents/Info.plist': 0o644, 'Contents/MacOS/wine': 0o755,
          'Contents/_CodeSignature/CodeResources': 0o644}
MAX_FILE = 64 * 1024 * 1024


class Blocked(RuntimeError):
    pass


def need(ok, reason):
    if not ok:
        raise Blocked(reason)


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def pinned(value, length=64):
    return type(value) is str and re.fullmatch('[0-9a-f]{' + str(length) + '}', value) is not None


def decode(raw):
    def pairs(rows):
        out = {}
        for key, value in rows:
            need(key not in out, 'asset_duplicate_json_key')
            out[key] = value
        return out
    try:
        value = json.loads(raw, object_pairs_hook=pairs)
    except (ValueError, UnicodeError, RecursionError):
        raise Blocked('asset_invalid_json') from None
    need(type(value) is dict, 'asset_receipt_schema')
    return value


def _generation(intent):
    need(type(intent) is dict, 'asset_intent_identity')
    if 'companionGeneration' not in intent:
        need('assetPredecessor' not in intent, 'asset_predecessor_requires_generation_two')
        return 1
    need(type(intent['companionGeneration']) is int and intent['companionGeneration'] == 2,
         'asset_companion_generation')
    predecessor = intent.get('assetPredecessor')
    need(type(predecessor) is dict and set(predecessor) == {
        'acceptedCommit', 'intentSha256', 'companionReceiptSha256', 'nativeReceiptSha256'}
        and pinned(predecessor['acceptedCommit'], 40)
        and all(pinned(predecessor[key]) for key in predecessor if key != 'acceptedCommit'),
        'asset_predecessor_policy')
    return 2


def layout(intent):
    need(type(intent) is dict and type(intent.get('schema')) is int and intent['schema'] == 1
         and intent.get('id') == 'game-native-launch-admission' and intent.get('owner') == OWNER,
         'asset_intent_identity')
    companions = intent.get('companions')
    route = intent.get('nativeRoute')
    need(type(companions) is dict and set(companions) == set(COMPANIONS), 'asset_companion_scope')
    need(type(route) is dict and route.get('durableRelativePath') == 'native/' + APP
         and type(route.get('bundleFiles')) is dict and set(route['bundleFiles']) == set(BUNDLE),
         'asset_bundle_scope')
    for rows, modes in ((companions, COMPANIONS), (route['bundleFiles'], BUNDLE)):
        for name, row in rows.items():
            need(type(row) is dict and set(row) == {'sha256', 'mode'}
                 and pinned(row['sha256']) and type(row['mode']) is int and row['mode'] == modes[name],
                 'asset_file_policy')
    files = {'companions/' + name: dict(row) for name, row in companions.items()}
    files.update({'native/' + APP + '/' + name: dict(row) for name, row in route['bundleFiles'].items()})
    companion_files = {name: dict(row) for name, row in companions.items()}
    native_files = {APP + '/' + name: dict(row) for name, row in route['bundleFiles'].items()}
    if _generation(intent) == 2:
        return files, (
            ('companions', HOME / 'AIDev/lib', 'game-launch-admission-v2',
             '.game-launch-admission-v2-assets-stage', companion_files),
        )
    return files, (
        ('companions', HOME / 'AIDev/lib', 'game-launch-admission', '.game-launch-admission-assets-stage', companion_files),
        ('native', HOME / 'Library/Application Support/Adapted Games DS3', 'native', '.native-admission-assets-stage', native_files),
    )


def _facts(info):
    return tuple(getattr(info, key) for key in ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_nlink',
                                              'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def _directory(path):
    """Hold every ancestor by descriptor; never follow a named link."""
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts, 'asset_absolute_path')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            current = os.fstat(fd)
            need(current.st_uid in (0, os.getuid()) and not current.st_mode & 0o022,
                 'asset_unsafe_directory')
            following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = following
        current = os.fstat(fd)
        need(current.st_uid in (0, os.getuid()) and not current.st_mode & 0o022,
             'asset_unsafe_directory')
        return fd
    except BaseException:
        os.close(fd)
        raise


def _read_at(directory, name, mode=None):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
             and before.st_nlink == 1 and not before.st_mode & 0o022 and before.st_size <= MAX_FILE
             and (mode is None or stat.S_IMODE(before.st_mode) == mode), 'asset_unsafe_file')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            raw = stream.read(MAX_FILE + 1)
        need(len(raw) <= MAX_FILE and _facts(before) == _facts(os.fstat(fd))
             == _facts(os.stat(name, dir_fd=directory, follow_symlinks=False)), 'asset_input_changed')
        return raw
    finally:
        os.close(fd)


def _read_path(path):
    directory = _directory(path.parent)
    try:
        return _read_at(directory, path.name)
    finally:
        os.close(directory)


def _dirs(files):
    return {str(parent) for name in files for parent in Path(name).parents if str(parent) != '.'}


def _inventory(fd, files, partial=False, private=True):
    """Exact directories and regular files; partial staging may omit entries."""
    allowed_dirs = _dirs(files)
    observed = set()
    def visit(current, prefix=''):
        for leaf in os.listdir(current):
            name = prefix + leaf
            info = os.stat(leaf, dir_fd=current, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                need(name in allowed_dirs and info.st_uid == os.getuid()
                     and (not private or stat.S_IMODE(info.st_mode) == 0o700)
                     and not info.st_mode & 0o022, 'asset_directory_inventory')
                nested = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
                try:
                    visit(nested, name + '/')
                finally:
                    os.close(nested)
            else:
                need(name in files, 'asset_unknown_inventory')
                raw = _read_at(current, leaf, files[name]['mode'] if private else None)
                need(sha(raw) == files[name]['sha256'], 'asset_file_drift')
                observed.add(name)
    visit(fd)
    need(partial or observed == set(files), 'asset_missing_inventory')
    return observed


def _receipt(intent, files, namespace, commit):
    return {'schema': 1, 'owner': OWNER, 'policySha256': sha(encode(intent)),
            'acceptedCommit': commit, 'namespace': namespace, 'payloadFiles': files}


def _expected_receipt(intent, files, namespace, raw, commit=None):
    receipt = decode(raw)
    need(pinned(receipt.get('acceptedCommit'), 40), 'asset_receipt_commit')
    expected = _receipt(intent, files, namespace, receipt['acceptedCommit'])
    need(receipt == expected and (commit is None or receipt['acceptedCommit'] == commit),
         'asset_receipt_binding')
    need(raw == encode(expected), 'asset_receipt_bytes')
    return receipt


def _open_namespace(parent, name):
    info = os.stat(name, dir_fd=parent, follow_symlinks=False)
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
         and stat.S_IMODE(info.st_mode) == 0o700, 'asset_namespace_mode')
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    try:
        need((os.fstat(fd).st_dev, os.fstat(fd).st_ino) == (info.st_dev, info.st_ino), 'asset_namespace_changed')
        return fd
    except BaseException:
        os.close(fd)
        raise


def _exists(parent, name):
    try:
        os.stat(name, dir_fd=parent, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False


def _owned(parent, name, intent, all_files, namespace, files, partial=False, commit=None):
    fd = _open_namespace(parent, name)
    try:
        raw = _read_at(fd, 'receipt.json', 0o600)
        receipt = _expected_receipt(intent, all_files, namespace, raw, commit)
        expected = dict(files, **{'receipt.json': {'sha256': sha(raw), 'mode': 0o600}})
        _inventory(fd, expected, partial=partial)
        return receipt
    finally:
        os.close(fd)


def _initial_stage(stage):
    return '.game-admission-stage-' + stage.lstrip('.')


def _initial_receipt(parent, stage, intent, files, namespace, commit=None):
    """Read-only preflight of the transaction primitive's receipt-only scratch.

    The fixed asset stage still requires a complete receipt. Only the separate
    construction scratch admits missing/exact-prefix receipt bytes; unknown
    entries or bytes are never repaired or removed.
    """
    fd = _open_namespace(parent, _initial_stage(stage))
    try:
        need(set(os.listdir(fd)) <= {'receipt.json'}, 'asset_initial_stage_inventory')
        if not _exists(fd, 'receipt.json'):
            return None
        raw = _read_at(fd, 'receipt.json', 0o600)
        try:
            receipt = _expected_receipt(intent, files, namespace, raw)
        except Blocked:
            if commit is not None:
                need(encode(_receipt(intent, files, namespace, commit)).startswith(raw),
                     'asset_initial_receipt_drift')
            return None
        return receipt
    finally:
        os.close(fd)


def _predecessor_assets(intent):
    """Verify exactly the retained first generation from its trusted receipts.

    The old intent itself is not reconstructed or adopted. Its policy digest and
    complete nine-file map are authenticated by both explicit receipt digests.
    The fixed original namespaces remain read-only through this successor.
    """
    need(_generation(intent) == 2, 'asset_generation_two_required')
    predecessor = intent['assetPredecessor']
    new_files, _ = layout(intent)
    modes = {'companions/' + rel: mode for rel, mode in COMPANIONS.items()}
    modes.update({'native/' + APP + '/' + rel: mode for rel, mode in BUNDLE.items()})
    namespaces = (
        ('companions', HOME / 'AIDev/lib', 'game-launch-admission',
         '.game-launch-admission-assets-stage', 'companionReceiptSha256'),
        ('native', HOME / 'Library/Application Support/Adapted Games DS3', 'native',
         '.native-admission-assets-stage', 'nativeReceiptSha256'),
    )
    receipts = {}
    old_files = None
    for namespace, parent, name, stage, receipt_pin in namespaces:
        parent_fd = _directory(parent)
        try:
            need(not _exists(parent_fd, stage) and not _exists(parent_fd, _initial_stage(stage)),
                 'asset_predecessor_stage_pending')
            fd = _open_namespace(parent_fd, name)
            try:
                raw = _read_at(fd, 'receipt.json', 0o600)
                need(sha(raw) == predecessor[receipt_pin], 'asset_predecessor_receipt_drift')
                receipt = decode(raw)
                files = receipt.get('payloadFiles')
                need(type(files) is dict and set(files) == set(modes), 'asset_predecessor_payload_scope')
                for rel, row in files.items():
                    need(type(row) is dict and set(row) == {'sha256', 'mode'}
                         and pinned(row['sha256']) and type(row['mode']) is int and row['mode'] == modes[rel],
                         'asset_predecessor_payload_policy')
                expected = {'schema': 1, 'owner': OWNER, 'policySha256': predecessor['intentSha256'],
                            'acceptedCommit': predecessor['acceptedCommit'], 'namespace': namespace,
                            'payloadFiles': files}
                need(raw == encode(expected), 'asset_predecessor_receipt_binding')
                need(old_files is None or files == old_files, 'asset_predecessor_closure_mismatch')
                old_files = files
                local_files = {rel[len(namespace) + 1:]: row for rel, row in files.items()
                               if rel.startswith(namespace + '/')}
                local_files['receipt.json'] = {'mode': 0o600, 'sha256': sha(raw)}
                _inventory(fd, local_files)
                receipts[namespace] = receipt
            finally:
                os.close(fd)
        finally:
            os.close(parent_fd)
    need(all(old_files[rel] == row for rel, row in new_files.items() if rel.startswith('native/')),
         'asset_predecessor_native_changed')
    return receipts


def verify_assets(intent):
    """Verify the fixed installed asset closure without changing any file."""
    files, namespaces = layout(intent)
    predecessor = _predecessor_assets(intent) if _generation(intent) == 2 else None
    receipts = {}
    for namespace, parent, name, stage, expected in namespaces:
        fd = _directory(parent)
        try:
            need(not _exists(fd, stage) and not _exists(fd, _initial_stage(stage)), 'asset_stage_pending')
            receipts[namespace] = _owned(fd, name, intent, files, namespace, expected)
        finally:
            os.close(fd)
    need(len({receipt['acceptedCommit'] for receipt in receipts.values()}) == 1,
         'asset_closure_commit_mismatch')
    if predecessor is not None:
        need(receipts['companions']['acceptedCommit'] != intent['assetPredecessor']['acceptedCommit'],
             'asset_successor_commit_required')
        receipts['native'] = predecessor['native']
    return {'owner': OWNER, 'policySha256': sha(encode(intent)), 'receipts': receipts}


def verify_signature(bundle):
    """Read-only signature check; wrapper may replace this with an equivalent callback."""
    result = subprocess.run(['/usr/bin/codesign', '--verify', '--strict', str(bundle)],
                            capture_output=True, timeout=15)
    need(result.returncode == 0, 'asset_bundle_signature')


def _write(fd, name, raw, mode, guard, event, label):
    guard()
    out = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=fd)
    try:
        with os.fdopen(os.dup(out), 'wb') as stream:
            stream.write(raw)
            stream.flush()
        os.fchmod(out, mode)
        os.fsync(out)
    finally:
        os.close(out)
    os.fsync(fd)
    event(label)


def _make_parents(fd, relative, guard, event, label):
    current = os.dup(fd)
    try:
        for part in Path(relative).parts[:-1]:
            if not _exists(current, part):
                guard()
                os.mkdir(part, mode=0o700, dir_fd=current)
                os.fsync(current)
                event(label + ':directory:' + part)
            info = os.stat(part, dir_fd=current, follow_symlinks=False)
            need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
                 and stat.S_IMODE(info.st_mode) == 0o700, 'asset_stage_directory')
            following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
            os.close(current)
            current = following
        return current
    except BaseException:
        os.close(current)
        raise


def _rename_exclusive(parent, source, destination):
    # renameatx_np binds both names to the already-open fixed parent.
    need(os.uname().sysname == 'Darwin', 'asset_exclusive_rename_unavailable')
    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.renameatx_np(parent, os.fsencode(source), parent, os.fsencode(destination), 4)
    if result:
        raise OSError(ctypes.get_errno(), 'asset exclusive rename failed')


def publish(intent, payload, commit, guard, event):
    """Publish only immutable assets, with caller guard before every mutation.

    payload contains exactly companions/<six fixed files> and native/<app>/<three
    fixed files>. The stage is atomically published with its complete receipt.
    Receipt construction uses the existing exact-prefix transaction scratch.
    A foreign receipt-less asset stage is retained and refused.
    Known partial stages resume only absent files; no existing file is repaired.
    """
    need(pinned(commit, 40) and callable(guard) and callable(event), 'asset_publish_arguments')
    generation = _generation(intent)
    if generation == 2:
        need(commit != intent['assetPredecessor']['acceptedCommit'], 'asset_successor_commit_required')
        caller_guard = guard
        def guard():
            caller_guard()
            _predecessor_assets(intent)
    guard()
    files, namespaces = layout(intent)
    payload = Path(payload)
    source_fd = _directory(payload)
    try:
        _inventory(source_fd, files, private=False)
    finally:
        os.close(source_fd)
    contents = {name: _read_path(payload / name) for name in files}
    need(all(sha(raw) == files[name]['sha256'] for name, raw in contents.items()), 'asset_payload_drift')
    if generation == 2:
        # The native namespace is immutable generation one. The full payload
        # still supplies and signature-checks the identical three app files.
        verify_signature(payload / 'native' / APP)
        source_fd = _directory(payload)
        try:
            _inventory(source_fd, files, private=False)
        finally:
            os.close(source_fd)
        need(all(_read_path(payload / name) == raw for name, raw in contents.items()), 'asset_payload_drift')
        guard()
    # Check both final/staging namespaces before creating any managed asset.
    # One first accepted commit owns the complete retained closure, including a
    # retry from a later source commit that has the identical intent policy.
    first_commits = set()
    for namespace, parent, name, stage, expected in namespaces:
        if namespace == 'companions' and not parent.exists():
            ancestor = _directory(parent.parent)
            os.close(ancestor)
            continue
        fd = _directory(parent)
        try:
            need(not (_exists(fd, name) and _exists(fd, stage)), 'asset_final_and_stage_conflict')
            if _exists(fd, _initial_stage(stage)):
                need(not _exists(fd, name) and not _exists(fd, stage), 'asset_initial_stage_conflict')
                receipt = _initial_receipt(fd, stage, intent, files, namespace)
                if receipt is not None:
                    first_commits.add(receipt['acceptedCommit'])
            if _exists(fd, name):
                receipt = _owned(fd, name, intent, files, namespace, expected)
                first_commits.add(receipt['acceptedCommit'])
            elif _exists(fd, stage):
                receipt = _owned(fd, stage, intent, files, namespace, expected, partial=True)
                first_commits.add(receipt['acceptedCommit'])
        finally:
            os.close(fd)
    need(len(first_commits) <= 1, 'asset_closure_commit_mismatch')
    first_commit = next(iter(first_commits)) if first_commits else commit
    # A completed receipt elsewhere owns the first commit even when a retry
    # comes from a later source. Validate all construction prefixes against that
    # binding before creating any asset, not against the retry's source commit.
    for namespace, parent, name, stage, expected in namespaces:
        if not parent.exists():
            continue
        fd = _directory(parent)
        try:
            if _exists(fd, _initial_stage(stage)):
                _initial_receipt(fd, stage, intent, files, namespace, first_commit)
        finally:
            os.close(fd)
    if generation == 2:
        need(first_commit != intent['assetPredecessor']['acceptedCommit'], 'asset_successor_commit_required')
    changed = False
    staged = []
    # Complete and signature-check every staged namespace before promoting any.
    for namespace, parent, name, stage, expected in namespaces:
        if namespace == 'companions' and not parent.exists():
            ancestor = _directory(parent.parent)
            try:
                guard()
                os.mkdir(parent.name, mode=0o700, dir_fd=ancestor)
                os.fsync(ancestor)
                event('assets:lib-created')
            finally:
                os.close(ancestor)
        fd = _directory(parent)
        try:
            if _exists(fd, name):
                need(not _exists(fd, stage), 'asset_final_and_stage_conflict')
                _owned(fd, name, intent, files, namespace, expected, commit=first_commit)
                continue
            if not _exists(fd, stage):
                guard()
                raw = encode(_receipt(intent, files, namespace, first_commit))
                transaction._new_namespace(parent / stage, {'receipt.json': raw})
                event('assets:' + namespace + ':stage-created')
                event('assets:' + namespace + ':owner-written')
            _owned(fd, stage, intent, files, namespace, expected, partial=True, commit=first_commit)
            stage_fd = _open_namespace(fd, stage)
            try:
                for rel, row in sorted(expected.items()):
                    directory = _make_parents(stage_fd, rel, guard, event, 'assets:' + namespace)
                    try:
                        leaf = Path(rel).name
                        if _exists(directory, leaf):
                            need(sha(_read_at(directory, leaf, row['mode'])) == row['sha256'], 'asset_file_drift')
                            continue
                        key = namespace + '/' + rel
                        _write(directory, leaf, contents[key], row['mode'], guard, event,
                               'assets:' + namespace + ':file:' + rel)
                    finally:
                        os.close(directory)
                os.fsync(stage_fd)
            finally:
                os.close(stage_fd)
            _owned(fd, stage, intent, files, namespace, expected, commit=first_commit)
            if namespace == 'native':
                verify_signature(parent / stage / APP)
                _owned(fd, stage, intent, files, namespace, expected, commit=first_commit)
            identity = os.stat(stage, dir_fd=fd, follow_symlinks=False)
            staged.append((namespace, parent, name, stage, expected, identity.st_dev, identity.st_ino))
        finally:
            os.close(fd)
    for namespace, parent, name, stage, expected, device, inode in staged:
        fd = _directory(parent)
        try:
            stage_fd = _open_namespace(fd, stage)
            try:
                need((os.fstat(stage_fd).st_dev, os.fstat(stage_fd).st_ino) == (device, inode),
                     'asset_stage_changed')
                guard()
                # The guard is external code: repeat the complete closure check
                # after it, while retaining the checked source directory inode.
                _owned(fd, stage, intent, files, namespace, expected, commit=first_commit)
                identity = os.stat(stage, dir_fd=fd, follow_symlinks=False)
                need((identity.st_dev, identity.st_ino) == (device, inode), 'asset_stage_changed')
                named_parent = _directory(parent)
                try:
                    need((os.fstat(fd).st_dev, os.fstat(fd).st_ino)
                         == (os.fstat(named_parent).st_dev, os.fstat(named_parent).st_ino), 'asset_parent_changed')
                finally:
                    os.close(named_parent)
                _rename_exclusive(fd, stage, name)
                os.fsync(fd)
                changed = True
                event('assets:' + namespace + ':published')
            finally:
                os.close(stage_fd)
        finally:
            os.close(fd)
    verified = verify_assets(intent)
    return dict(verified, changed=changed)
