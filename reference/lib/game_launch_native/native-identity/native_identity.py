"""Mapping-first observation. Unix ancestry is diagnostic, never ownership."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

PROBE = Path(__file__).with_name('probe')
PROBE_SHA256 = '93e3486f4528c96c35a147a8bd77a9c6d73bd578e90b50dcd60991c39aa40dda'

class Unknown(RuntimeError):
    pass

def require(ok, reason):
    if not ok: raise Unknown(reason)

def valid_pid(value): return type(value) is int and 1 < value < 2**31
def valid_birth(value):
    return type(value) is str and re.fullmatch(r'[1-9][0-9]{0,19}:[0-9]{1,6}', value) is not None and int(value.split(':')[1]) < 1000000

def file_identity(facts):
    return tuple(getattr(facts,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))

def inspect_process(pid, birth, expected_executable=None, timeout=1.25):
    """Bounded public metadata only; never target/prefix acceptance evidence."""
    require(valid_pid(pid) and valid_birth(birth), 'invalid_identity')
    require(type(timeout) in (int,float) and 0 < timeout <= 1.25, 'invalid_budget')
    expected='-' if expected_executable is None else str(expected_executable)
    require(expected=='-' or (expected.startswith('/') and '\x00' not in expected), 'invalid_expected_executable')
    facts=PROBE.lstat()
    require(stat.S_ISREG(facts.st_mode) and facts.st_uid==os.getuid() and not facts.st_mode&0o022
            and facts.st_nlink==1 and facts.st_size<1024*1024 and facts.st_mode&0o100,'unsafe_probe')
    require(hashlib.sha256(PROBE.read_bytes()).hexdigest()==PROBE_SHA256,'probe_changed')
    try:
        result=subprocess.run([str(PROBE),'--metadata',str(pid),birth,expected],stdin=subprocess.DEVNULL,
            capture_output=True,timeout=timeout,env={'PATH':'/usr/bin:/bin','LANG':'C'},cwd='/')
    except (OSError,subprocess.SubprocessError):raise Unknown('metadata_probe_unavailable') from None
    require(len(result.stdout)<=32768 and not result.stderr,'metadata_probe_output')
    try:value=json.loads(result.stdout)
    except (ValueError,UnicodeError):raise Unknown('metadata_probe_output') from None
    require(type(value) is dict and result.returncode==0 and value.get('state')=='PROCESS_OBSERVED','metadata_probe_unknown')
    require(set(value)=={'state','pid','birth','ppid','group','snapshotStable','expectedExecutable','nativeExecutable'}
            and type(value['pid']) is int and value['pid']==pid and value['birth']==birth
            and type(value['ppid']) is int and 0<=value['ppid']<2**31
            and type(value['group']) is int and 0<=value['group']<2**31
            and type(value['snapshotStable']) is bool and type(value['expectedExecutable']) is bool
            and type(value['nativeExecutable']) is str and value['nativeExecutable'].startswith('/')
            and len(value['nativeExecutable'])<4096 and '\x00' not in value['nativeExecutable']
            and value['expectedExecutable']==(value['nativeExecutable']==expected),'metadata_probe_identity')
    require(file_identity(PROBE.lstat())==file_identity(facts) and hashlib.sha256(PROBE.read_bytes()).hexdigest()==PROBE_SHA256,'probe_changed')
    return value

def inspect_mapped(pid, birth, loader, target, timeout=2.5):
    """Observe one exact native process mapping this executable PE file.

    Caller binds route bytes, exact loader/target content and installed runtime.
    MATCH_IMAGE is not a prefix/server binding or launch reservation milestone.
    Generic bundle path alone never matches. Unknown is not process absence.
    """
    require(valid_pid(pid) and valid_birth(birth), 'invalid_identity')
    require(type(timeout) in (int,float) and 0 < timeout <= 2.5, 'invalid_budget')
    loader, target = Path(loader), Path(target)
    require(all(p.is_absolute() and '..' not in p.parts and p.resolve() == p for p in (loader,target)), 'noncanonical_path')
    facts = PROBE.lstat()
    require(stat.S_ISREG(facts.st_mode) and facts.st_uid == os.getuid()
            and not facts.st_mode & 0o022 and facts.st_nlink == 1
            and facts.st_size < 1024*1024 and facts.st_mode & 0o100, 'unsafe_probe')
    require(hashlib.sha256(PROBE.read_bytes()).hexdigest() == PROBE_SHA256, 'probe_changed')
    try:
        result = subprocess.run([str(PROBE), str(pid), birth, str(loader), str(target)],
                                stdin=subprocess.DEVNULL, capture_output=True,
                                timeout=timeout, env={'PATH':'/usr/bin:/bin','LANG':'C'}, cwd='/')
    except (OSError, subprocess.SubprocessError): raise Unknown('probe_unavailable') from None
    require(len(result.stdout) <= 8192 and not result.stderr, 'probe_output')
    try: value = json.loads(result.stdout)
    except (ValueError, UnicodeError): raise Unknown('probe_output') from None
    require(type(value) is dict and result.returncode == 0 and value.get('state') == 'MATCH_IMAGE',
            'probe_unknown:' + (str(value.get('reason','exit'))[:64] if type(value) is dict else 'shape'))
    require(set(value) == {'state','pid','birth','mappedExecutable','targetDev','targetIno','regionsExamined','ancestryStable','ancestry'}
            and value['pid'] == pid and value['birth'] == birth and value['mappedExecutable'] is True
            and type(value['regionsExamined']) is int and 1 <= value['regionsExamined'] <= 4096
            and type(value['ancestryStable']) is bool,
            'probe_identity')
    chain = value['ancestry']
    require(type(chain) is list and len(chain) <= 16, 'probe_diagnostic_ancestry')
    for row in chain:
        require(type(row) is dict and set(row) == {'pid','birth','ppid','group'}
                and valid_pid(row['pid']) and valid_birth(row['birth'])
                and type(row['ppid']) is int and 0 <= row['ppid'] < 2**31
                and type(row['group']) is int and 0 <= row['group'] < 2**31, 'probe_diagnostic_ancestry')
    require(len({r['pid'] for r in chain}) == len(chain)
            and (not chain or (chain[0]['pid'] == pid and chain[0]['birth'] == birth))
            and all(a['ppid'] == b['pid'] for a,b in zip(chain,chain[1:]))
            and (chain or not value['ancestryStable']), 'probe_diagnostic_ancestry')
    file = target.lstat()
    require(stat.S_ISREG(file.st_mode) and type(value['targetDev']) is int and type(value['targetIno']) is int
            and value['targetDev'] == (file.st_dev & 0xffffffff) and value['targetIno'] == file.st_ino,
            'probe_target')
    require(file_identity(PROBE.lstat()) == file_identity(facts) and hashlib.sha256(PROBE.read_bytes()).hexdigest() == PROBE_SHA256,
            'probe_changed')
    return value
