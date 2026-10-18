"""Pinned companion of the private admission candidate. Host supplies file guards."""
import hashlib
import os
from pathlib import Path
import plistlib
import re
import stat
import time

IDENTITY_DIR = Path(__file__).resolve().parent.parent/'native-identity'
IDENTITY_SHA = 'f44c2b267eeeb3ffd415c33567687ad75524ed199f252ed14ccf8af83c92e3b3'
PROBE_SHA = '93e3486f4528c96c35a147a8bd77a9c6d73bd578e90b50dcd60991c39aa40dda'
PREFIX_SHA = 'c1e5cab75132d5bdac12c55fe8d4493bec4a791d8474ceedff35963a1a8687bf'
PREFIX_PROBE_SHA = 'c6251ecb0aba5ad5bc4b8afbc4ecae8fac4302517372afba37186433b59898f0'
IMAGE = r'C:\Program Files (x86)\Steam\steamapps\common\DARK SOULS III\Game\DarkSoulsIII.exe'
KEYS = ('st_dev','st_ino','st_mode','st_uid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')

def facts(path):
    directory(path.parent)
    value=path.lstat()
    require(stat.S_ISREG(value.st_mode) and value.st_uid==os.getuid() and value.st_nlink==1
            and not value.st_mode&0o022,'native_binding_file')
    return {k:getattr(value,k) for k in KEYS}

def content(path,limit=256*1024*1024):
    before=facts(path);raw=regular(path,limit)
    require(facts(path)==before,'native_binding_changed')
    return raw,before

def shape(binding):
    require(type(binding) is dict and set(binding)=={'schema','approval','approvalSha256','prefixIdentity','files'}
            and type(binding['schema']) is int and binding['schema']==2,'invalid_native_binding')
    approval=binding['approval']
    require(type(approval) is dict and set(approval)=={'schema','owner','route','prefix','image','machine','target','loader','bundleIdentifier','files'}
            and approval['schema']==2 and type(approval['schema']) is int and approval['owner']=='control-ds3-native-launch'
            and approval['route']=='ds3' and approval['image']==IMAGE and approval['machine']==0x8664
            and type(approval['machine']) is int,'invalid_native_binding')
    for field in ('prefix','target','loader'):
        p=approval[field]
        require(type(p) is str and p.startswith('/') and '\x00' not in p and '..' not in Path(p).parts,'invalid_native_binding')
    require(type(approval['bundleIdentifier']) is str and re.fullmatch('[A-Za-z0-9][A-Za-z0-9.-]{1,200}',approval['bundleIdentifier']), 'invalid_native_binding')
    require(type(binding['prefixIdentity']) is dict and set(binding['prefixIdentity'])=={'st_dev','st_ino'}
            and all(type(v) is int and v>=0 for v in binding['prefixIdentity'].values()),'invalid_native_binding')
    require(type(binding['approvalSha256']) is str and re.fullmatch('[0-9a-f]{64}',binding['approvalSha256']),'invalid_native_binding')
    require(type(approval['files']) is dict and len(approval['files'])==5
            and all(type(k) is str and k.startswith('/') and type(v) is str and re.fullmatch('[0-9a-f]{64}',v) for k,v in approval['files'].items()),'invalid_native_binding')
    require(type(binding['files']) is dict and len(binding['files'])==7
            and all(type(k) is str and type(v) is dict and set(v)==set(KEYS)
                and all(type(n) is int for n in v.values()) for k,v in binding['files'].items()),'invalid_native_binding')
    return approval

def scope(home,approval):
    prefix=Path(home)/'Library/Application Support/Adapted Games DS3/profiles/ds3'
    target=prefix/'drive_c/Program Files (x86)/Steam/steamapps/common/DARK SOULS III/Game/DarkSoulsIII.exe'
    loader=Path(approval['loader']);bundle=loader.parent.parent.parent
    ntdll=prefix.parent.parent/'runtime/engine/lib/wine/x86_64-unix/ntdll.so'
    server=prefix.parent.parent/'runtime/engine/bin/wineserver'
    require(approval['prefix']==str(prefix) and approval['target']==str(target)
            and loader==bundle/'Contents/MacOS/wine' and bundle.suffix=='.app'
            and loader.resolve()==loader and target.resolve()==target and prefix.resolve()==prefix,'native_binding_scope')
    plist=bundle/'Contents/Info.plist'
    require(set(approval['files'])=={str(target),str(loader),str(plist),str(ntdll),str(server)},'native_binding_scope')
    return prefix,target,loader,plist,ntdll,server

def bind(home,route,goal):
    if route!='ds3' or goal!='game':return None
    prefix=Path(home)/'Library/Application Support/Adapted Games DS3/profiles/ds3'
    routes=prefix/'native-applications.routes'
    approval_path=Path(home)/'AIDev/state/ds3-native-launch-approval.json'
    if not routes.exists() and not routes.is_symlink():return None
    require(approval_path.exists() and not approval_path.is_symlink(),'native_route_unapproved')
    approval_raw,approval_facts=content(approval_path,16384);approval=decode(approval_raw)
    # Reuse persisted-shape validation before using caller-controlled paths.
    dummy={k:0 for k in KEYS}
    binding={'schema':2,'approval':approval,'approvalSha256':hashlib.sha256(approval_raw).hexdigest(),
             'prefixIdentity':{'st_dev':0,'st_ino':0},'files':{str(i):dict(dummy) for i in range(7)}}
    shape(binding);prefix,target,loader,plist,ntdll,server=scope(home,approval)
    directory(prefix);p=prefix.lstat();binding['prefixIdentity']={'st_dev':p.st_dev,'st_ino':p.st_ino}
    route_raw,route_facts=content(routes,65536)
    expected=('WINE-NATIVE-APPLICATIONS\t1\n8664\t'+IMAGE+'\t'+str(loader)+'\n').encode()
    require(route_raw==expected,'native_route_not_exact')
    binding['files']={str(approval_path):approval_facts,str(routes):route_facts}
    for path,digest in approval['files'].items():
        raw,file_facts=content(Path(path))
        require(hashlib.sha256(raw).hexdigest()==digest,'native_content_changed')
        binding['files'][path]=file_facts
    try:info=plistlib.loads(regular(plist,65536))
    except (ValueError,TypeError,OverflowError):raise Blocked('native_bundle_plist') from None
    require(type(info) is dict and info.get('CFBundleIdentifier')==approval['bundleIdentifier']
            and info.get('CFBundleExecutable')=='wine' and info.get('CFBundlePackageType')=='APPL','native_bundle_identity')
    # The approved target must itself be an amd64 PE executable.
    with target.open('rb') as f:
        head=f.read(64);require(len(head)==64 and head[:2]==b'MZ','native_target_pe')
        offset=int.from_bytes(head[60:64],'little');require(64<=offset<=16*1024*1024,'native_target_pe')
        f.seek(offset);pe=f.read(24)
    require(len(pe)==24 and pe[:6]==b'PE\0\0\x64\x86' and int.from_bytes(pe[22:24],'little')&2,'native_target_pe')
    unchanged(home,binding)
    return binding

def unchanged(home,binding):
    approval=shape(binding);prefix,target,loader,plist,ntdll,server=scope(home,approval)
    directory(prefix);p=prefix.lstat()
    require(binding['prefixIdentity']=={'st_dev':p.st_dev,'st_ino':p.st_ino},'native_prefix_changed')
    approval_path=Path(home)/'AIDev/state/ds3-native-launch-approval.json'
    routes=prefix/'native-applications.routes'
    require(set(binding['files'])==set(approval['files'])|{str(approval_path),str(routes)},'native_binding_scope')
    raw=regular(approval_path,16384)
    require(hashlib.sha256(raw).hexdigest()==binding['approvalSha256'] and decode(raw)==approval,'native_approval_changed')
    expected=('WINE-NATIVE-APPLICATIONS\t1\n8664\t'+IMAGE+'\t'+str(loader)+'\n').encode()
    require(regular(routes,65536)==expected,'native_route_changed')
    for path,before in binding['files'].items():require(facts(Path(path))==before,'native_binding_changed')

def identity_module(prefix=False):
    path=IDENTITY_DIR/('prefix_identity.py' if prefix else 'native_identity.py');raw=regular(path,65536)
    require(hashlib.sha256(raw).hexdigest()==(PREFIX_SHA if prefix else IDENTITY_SHA) and
            hashlib.sha256(regular(IDENTITY_DIR/('prefix_probe' if prefix else 'probe'),1024*1024)).hexdigest()==(PREFIX_PROBE_SHA if prefix else PROBE_SHA),'native_inspector_changed')
    ns={'__name__':'admission_native_identity','__file__':str(path)}
    exec(compile(raw,str(path),'exec'),ns)
    return ns

def server_directory(binding):
    base=Path('/tmp').resolve();parent=base/('.wine-'+str(os.getuid()))
    expected=parent/('server-%x-%x'%(binding['prefixIdentity']['st_dev'],binding['prefixIdentity']['st_ino']))
    for path in (parent,expected):
        s=path.lstat();require(stat.S_ISDIR(s.st_mode) and s.st_uid==os.getuid() and not s.st_mode&0o077
            and path.resolve()==path,'native_server_directory')
    s=expected.lstat()
    return {'path':str(expected),'dev':s.st_dev,'ino':s.st_ino,'mode':s.st_mode,'uid':s.st_uid}

def birth_order(value):return tuple(int(n) for n in value.split(':'))

def server_candidates(rows,binding):
    # Wine may retain lib/wine/../../bin/wineserver as its comm. Lexical
    # normalization selects candidates only; the bound file and native prefix
    # probe still prove the canonical executable and its process incarnation.
    expected=Path(binding['approval']['prefix']).parent.parent/'runtime/engine/bin/wineserver'
    candidates=[]
    for pid,command in rows:
        if type(command) is not str or not command.startswith('/') or '\0' in command or os.path.normpath(command)!=str(expected):continue
        path=Path(command)
        require(expected.resolve(strict=True)==expected and path.resolve(strict=True)==expected,'native_server_executable_alias')
        raw,observed=content(path)
        require(observed==binding['files'][str(expected)]
            and hashlib.sha256(raw).hexdigest()==binding['approval']['files'][str(expected)],'native_server_executable_changed')
        candidates.append(pid)
    return candidates

def observation_shape(value,binding,owner,dispatch):
    require(type(value) is dict and set(value)=={'proof','identity','owner','dispatch','server','serverExecutable','serverDirectory','targetDev','targetIno','approvalSha256','mappedExecutable','prefixConnectionVerified','connection'}
        and value['proof']=='mapped-pe-reciprocal-prefix-server-v1'
        and value['owner']==owner and value['approvalSha256']==binding['approvalSha256']
        and value['mappedExecutable'] is True and value['prefixConnectionVerified'] is True,'invalid_native_observation')
    for field in ('identity','owner','dispatch','server'):require(valid_identity(value[field]),'invalid_native_observation')
    require(len(dispatch)==1 and value['dispatch']==dispatch[0]
        and birth_order(value['identity']['birth'])>birth_order(value['dispatch']['birth']),'invalid_native_observation')
    require(len({value[k]['pid'] for k in ('identity','owner','server')})==3,'invalid_native_observation')
    target=binding['files'][binding['approval']['target']]
    require(type(value['targetDev']) is int and value['targetDev']==target['st_dev']&0xffffffff
        and type(value['targetIno']) is int and value['targetIno']==target['st_ino'],'invalid_native_observation')
    expected_server=str(Path(binding['approval']['prefix']).parent.parent/'runtime/engine/bin/wineserver')
    require(value['serverExecutable']==expected_server,'invalid_native_observation')
    d=value['serverDirectory']
    expected=Path('/tmp').resolve()/('.wine-'+str(os.getuid()))/('server-%x-%x'%(binding['prefixIdentity']['st_dev'],binding['prefixIdentity']['st_ino']))
    require(type(d) is dict and set(d)=={'path','dev','ino','mode','uid'} and d['path']==str(expected)
        and all(type(d[k]) is int and d[k]>=0 for k in ('dev','ino','mode','uid'))
        and stat.S_ISDIR(d['mode']) and not d['mode']&0o077 and d['uid']==os.getuid(),'invalid_native_observation')
    c=value['connection']
    require(type(c) is dict and set(c)=={'stable','complete','serverScope','gameEdges','steamEdges','opaqueHandles'}
        and all(c[k] is True for k in ('stable','complete','serverScope'))
        and all(type(c[k]) is int and c[k]==1 for k in ('gameEdges','steamEdges'))
        and type(c['opaqueHandles']) is int and c['opaqueHandles']==0,'invalid_native_observation')

def observe(home,binding,owner,dispatch,rows,timeout,processes):
    deadline=time.monotonic()+min(timeout,8.5)
    def budget(cap):
        remaining=deadline-time.monotonic();require(remaining>0,'native_observation_deadline')
        return min(cap,remaining)
    unchanged(home,binding)
    require(len(dispatch)==1 and valid_identity(dispatch[0]),'native_dispatch_identity_ambiguous')
    candidates=[pid for pid,command in rows if command in (binding['approval']['loader'],binding['approval']['image'],binding['approval']['target'])]
    require(len(candidates)<=1,'native_target_ambiguous')
    if not candidates:return None
    current=process_identity(owner['pid'])
    require(current==owner,'native_launch_owner_changed')
    client=Path(binding['approval']['prefix'])/'drive_c/Program Files (x86)/Steam/steam.exe'
    require((owner['pid'],str(client)) in rows,'native_launch_owner_executable_changed')
    pid=candidates[0];before=process_identity(pid)
    require(valid_identity(before),'native_target_unknown')
    require(birth_order(before['birth'])>birth_order(dispatch[0]['birth']),'native_target_precedes_dispatch')
    server_path=Path(binding['approval']['prefix']).parent.parent/'runtime/engine/bin/wineserver'
    servers=server_candidates(rows,binding)
    if not servers:return None
    require(len(servers)==1,'native_prefix_server_ambiguous')
    server=process_identity(servers[0]);require(server is not None,'native_prefix_server_unknown')
    require(len({pid,owner['pid'],server['pid']})==3,'native_prefix_identity_ambiguous')
    directory_before=server_directory(binding)
    mapping=identity_module();connection=identity_module(prefix=True)
    try:
        first=mapping['inspect_mapped'](pid,before['birth'],binding['approval']['loader'],binding['approval']['target'],timeout=budget(2.5))
        graph=connection['inspect_prefix_connection'](before,owner,server,binding['approval']['prefix'],binding['approval']['loader'],str(server_path),timeout=budget(3.5))
        if graph['state']!='PREFIX_CONNECTION_OBSERVED':return None
        require(all(graph.get(k) is True for k in ('stable','complete','serverScopeBefore','serverScopeAfter'))
            and all(type(graph.get(k)) is int and graph[k]==1 for k in ('gameEdgesBefore','gameEdgesAfter','steamEdgesBefore','steamEdgesAfter')),'native_prefix_proof_incomplete')
        roles=graph.get('roles');require(type(roles) is list and len(roles)==3,'native_prefix_proof_incomplete')
        for identity,name,role in zip((before,owner,server),('game','steam','server'),roles):
            require(type(role) is dict and role.get('role')==name and role.get('pid')==identity['pid'] and role.get('birth')==identity['birth']
                and type(role.get('zeroHandlesBefore')) is int and role['zeroHandlesBefore']==0
                and type(role.get('zeroHandlesAfter')) is int and role['zeroHandlesAfter']==0,'native_prefix_proof_incomplete')
        second=mapping['inspect_mapped'](pid,before['birth'],binding['approval']['loader'],binding['approval']['target'],timeout=budget(2.5))
    except (mapping['Unknown'],connection['Unknown']):return None
    budget(8.5)
    unchanged(home,binding)
    require(server_directory(binding)==directory_before,'native_server_directory_changed')
    after=process_identity(pid)
    require(after==before and process_identity(owner['pid'])==owner
        and process_identity(server['pid'])==server,'native_process_changed')
    fresh=processes(timeout=budget(5))
    aliases=(binding['approval']['loader'],binding['approval']['image'],binding['approval']['target'])
    require([p for p,command in fresh if command in aliases]==[pid]
        and (owner['pid'],str(client)) in fresh
        and server_candidates(fresh,binding)==[server['pid']],'native_process_command_changed')
    require(process_identity(pid)==before and process_identity(owner['pid'])==owner
        and process_identity(server['pid'])==server,'native_process_changed_after_commands')
    budget(8.5);unchanged(home,binding)
    target=binding['files'][binding['approval']['target']]
    for observed in (first,second):
        require(observed['state']=='MATCH_IMAGE' and observed['pid']==pid and observed['birth']==before['birth']
            and observed['mappedExecutable'] is True and observed['targetDev']==target['st_dev']&0xffffffff
            and observed['targetIno']==target['st_ino'],'native_mapped_file_changed')
    # Both public modules validate their exact schemas and consistency. No Unix
    # ancestry or opaque socket handles are persisted or used as authority.
    value={'proof':'mapped-pe-reciprocal-prefix-server-v1','identity':after,'owner':owner,'dispatch':dispatch[0],'server':server,
        'serverExecutable':str(server_path),'serverDirectory':directory_before,'targetDev':first['targetDev'],'targetIno':first['targetIno'],
        'approvalSha256':binding['approvalSha256'],'mappedExecutable':True,'prefixConnectionVerified':True,
        'connection':{'stable':True,'complete':True,'serverScope':True,'gameEdges':1,'steamEdges':1,'opaqueHandles':0}}
    observation_shape(value,binding,owner,dispatch)
    return value
