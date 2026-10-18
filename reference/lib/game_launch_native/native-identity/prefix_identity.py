"""Optional diagnostic socket graph; not admitted durable launch ownership."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

PROBE=Path(__file__).with_name('prefix_probe')
PROBE_SHA256='c6251ecb0aba5ad5bc4b8afbc4ecae8fac4302517372afba37186433b59898f0'
class Unknown(RuntimeError):pass
def require(ok,reason):
    if not ok:raise Unknown(reason)
def identity(value):
    return type(value) is dict and set(value)=={'pid','birth','group'} and type(value['pid']) is int and 1<value['pid']<2**31 and type(value['group']) is int and 0<=value['group']<2**31 and type(value['birth']) is str and re.fullmatch('[1-9][0-9]{0,19}:[0-9]{1,6}',value['birth']) is not None and int(value['birth'].split(':')[1])<1000000
def fingerprint(s):return tuple(getattr(s,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))

def inspect_prefix_connection(game,owner,server,prefix,loader,server_executable,timeout=3.5):
    """Observe reciprocal Unix socket edges to an inode-bound prefix wineserver.

    All three inputs are captured {pid,birth,group}; their groups are diagnostic.
    Caller binds exact Steam comm, loader/server content, prefix identity and game
    executable mapping separately. Unknown is never target absence. This candidate
    needs real public socket-field validation before durable admission use.
    """
    require(all(identity(v) for v in (game,owner,server)) and len({v['pid'] for v in (game,owner,server)})==3,'invalid_identities')
    require(type(timeout) in (int,float) and 0<timeout<=3.5,'invalid_budget')
    paths=[Path(p) for p in (prefix,loader,server_executable)]
    require(all(p.is_absolute() and '..' not in p.parts and p.resolve()==p for p in paths),'noncanonical_paths')
    facts=PROBE.lstat()
    require(stat.S_ISREG(facts.st_mode) and facts.st_uid==os.getuid() and not facts.st_mode&0o022 and facts.st_nlink==1
        and facts.st_mode&0o100 and facts.st_size<1024*1024,'unsafe_prefix_probe')
    require(hashlib.sha256(PROBE.read_bytes()).hexdigest()==PROBE_SHA256,'prefix_probe_changed')
    args=[str(PROBE)]
    for v in (game,owner,server):args.extend((str(v['pid']),v['birth']))
    args.extend((str(paths[1]),str(paths[2]),str(paths[0])))
    try:result=subprocess.run(args,stdin=subprocess.DEVNULL,capture_output=True,timeout=timeout,env={'PATH':'/usr/bin:/bin','LANG':'C'},cwd='/')
    except (OSError,subprocess.SubprocessError):raise Unknown('prefix_probe_unavailable') from None
    require(len(result.stdout)<=16384 and not result.stderr,'prefix_probe_output')
    try:value=json.loads(result.stdout)
    except (ValueError,UnicodeError):raise Unknown('prefix_probe_output') from None
    require(type(value) is dict and result.returncode==0 and value.get('state') in ('PREFIX_CONNECTION_OBSERVED','PREFIX_CONNECTION_UNKNOWN'),'prefix_probe_unknown')
    require(set(value)=={'state','stable','complete','serverScopeBefore','serverScopeAfter','gameEdgesBefore','gameEdgesAfter','steamEdgesBefore','steamEdgesAfter','roles'},'prefix_probe_shape')
    flags=('stable','complete','serverScopeBefore','serverScopeAfter')
    counts=('gameEdgesBefore','gameEdgesAfter','steamEdgesBefore','steamEdgesAfter')
    require(all(type(value[k]) is bool for k in flags) and all(type(value[k]) is int and 0<=value[k]<=1024 for k in counts),'prefix_probe_shape')
    require(type(value['roles']) is list and len(value['roles'])==3,'prefix_probe_roles')
    for expected,name,row in zip((game,owner,server),('game','steam','server'),value['roles']):
        require(type(row) is dict and set(row)=={'role','pid','birth','ppid','group','unixSocketsBefore','unixSocketsAfter','zeroHandlesBefore','zeroHandlesAfter'}
            and row['role']==name and type(row['pid']) is int and row['pid']==expected['pid'] and row['birth']==expected['birth']
            and all(type(row[k]) is int and 0<=row[k]<2**31 for k in ('ppid','group'))
            and all(type(row[k]) is int and 0<=row[k]<=8192 for k in ('unixSocketsBefore','unixSocketsAfter','zeroHandlesBefore','zeroHandlesAfter')),'prefix_probe_roles')
    if value['state']=='PREFIX_CONNECTION_OBSERVED':require(all(value[k] for k in flags) and all(value[k]==1 for k in counts)
        and all(row['zeroHandlesBefore']==row['zeroHandlesAfter']==0 for row in value['roles']),'prefix_probe_positive_inconsistent')
    require(fingerprint(PROBE.lstat())==fingerprint(facts) and hashlib.sha256(PROBE.read_bytes()).hexdigest()==PROBE_SHA256,'prefix_probe_changed')
    return value
