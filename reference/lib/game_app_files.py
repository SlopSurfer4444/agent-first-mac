"""Fixed Finder launcher image/policy primitives; no runtime or migration imports."""
import hashlib,importlib.machinery,importlib.util,json,os,pwd,re,shutil,stat,tempfile
from pathlib import Path
HOME = Path(pwd.getpwuid(os.getuid()).pw_dir)
HERE = Path(__file__).resolve().parent.parent
CONTROL = HOME/'AIDev/control'
HUB = HOME/'Library/Application Support/Adapted Games'
DS3 = HOME/'Library/Application Support/Adapted Games DS3'
MANIFEST = 'manifests/game-app-launchers.json'
# Route labels are policy data, not modules dispatched by these primitives.
# The bound entrypoint holds this exact input before importing this module.
APP_ROUTES: "source-data-only" = 'lib/game_app_routes.json'
NAMES = {name:tuple(route) for name,route in json.loads((HERE/APP_ROUTES).read_bytes()).items()}
FILES = {'Contents/Info.plist':0o600,'Contents/MacOS/launcher':0o700,'Contents/Resources/Game.icns':0o600}
ERROR_POLICY = 'manifests/game-app-launcher-errors.json'

def need(ok,reason):
    if not ok: raise RuntimeError(reason)

def digest(data): return hashlib.sha256(data).hexdigest()

def pinned(s): return type(s) is str and re.fullmatch('[0-9a-f]{64}',s) is not None

def safe_dir(p):
    for x in [*reversed(p.parents),p]:
        s=x.lstat(); need(stat.S_ISDIR(s.st_mode) and s.st_uid in (0,os.getuid()) and not s.st_mode & 0o002,'unsafe_directory')

def regular(p):
    safe_dir(p.parent); s=p.lstat()
    need(stat.S_ISREG(s.st_mode) and s.st_uid in (0,os.getuid()) and s.st_nlink == 1 and not s.st_mode & 0o022 and s.st_size <= 32*1024*1024,'unsafe_file')
    return s

def sha(p): regular(p); return digest(p.read_bytes())

def load(p):
    regular(p); need(p.stat().st_size <= 128*1024,'metadata_limit')
    def unique(rows):
        d={}
        for k,v in rows: need(k not in d,'duplicate_key'); d[k]=v
        return d
    return json.loads(p.read_bytes(),object_pairs_hook=unique)

def jb(value): return (json.dumps(value,indent=2,ensure_ascii=False)+'\n').encode()

def policy(path=None,*,root=None):
    root=HERE if root is None else root
    if path is None: path = ERROR_POLICY if (root/ERROR_POLICY).exists() else MANIFEST
    m=load(root/path)
    need(m.get('schema') == 1 and type(m.get('schema')) is int and m.get('owner') == 'control-game-app-launchers','policy_identity')
    need(set(m['apps']) == set(NAMES),'app_inventory')
    for i,(name,route) in enumerate(NAMES.items(),1):
        row=m['apps'][name]
        need(row['route'] == list(route) and row['routeNumber'] == i and type(row['routeNumber']) is int,'route_drift')
        need(type(row['iconSource']) is str and row['iconSource'].startswith(('~/','/Applications/')) and '..' not in Path(row['iconSource']).parts and pinned(row['iconSha256']),'icon_policy')
    return m

def policy_digest(m): return digest(jb(m))

def policy_for_digest(value,*,root=None):
    root=HERE if root is None else root
    for path in (ERROR_POLICY,MANIFEST):
        if (root/path).exists() and sha(root/path) == value: return policy(path,root=root)
    raise RuntimeError('unknown_app_policy')

def image(p):
    if not p.exists() and not p.is_symlink(): return None
    if p.is_dir() and not p.is_symlink():
        safe_dir(p); rows={}
        for q in sorted(p.rglob('*')):
            if q.is_dir() and not q.is_symlink(): safe_dir(q); continue
            s=regular(q); rows[str(q.relative_to(p))]={'sha256':sha(q),'mode':s.st_mode & 0o777}
        need(set(rows) == set(FILES),'bundle_inventory')
        need(all(rows[k]['mode'] == v for k,v in FILES.items()),'bundle_mode')
        need({str(q.relative_to(p)) for q in p.rglob('*') if q.is_dir()} == {'Contents','Contents/MacOS','Contents/Resources'},'bundle_directories')
        return {'kind':'app','files':rows}
    s=regular(p); return {'kind':'file','sha256':sha(p),'mode':s.st_mode & 0o777}

def bundle_inventory(candidate):
    return {name:image(candidate/name)['files'] for name in NAMES}

def candidate_check(candidate,m,*,root=None):
    root=HERE if root is None else root
    safe_dir(candidate)
    need(set(p.name for p in candidate.iterdir()) == set(NAMES)|{'build.json'},'candidate_inventory')
    report=load(candidate/'build.json')
    need(report == {'schema':1,'sourceSha256':sha(root/'bin/game-app-launcher.m'),'apps':m['builtApps']},'candidate_binding')
    need(bundle_inventory(candidate) == m['builtApps'],'candidate_drift')

def copy_image(src,dst):
    need(not dst.exists() and not dst.is_symlink(),'copy_collision')
    if src.is_dir(): shutil.copytree(src,dst)
    else: shutil.copyfile(src,dst); dst.chmod(src.stat().st_mode & 0o777)

def write_image(p,data,mode=0o600): p.write_bytes(data); p.chmod(mode)

def replace_image(src,target,expected):
    safe_dir(target.parent); need(image(target) == expected,'transaction_target_changed')
    replacement=image(src)
    if replacement == expected: return
    if replacement is None:
        if expected['kind'] == 'app':
            # Atomic removal preserves recovery after a crash; keep retired
            # bundles with this private transaction rather than partially delete.
            safe_dir(src.parent)
            retired=Path(tempfile.mkdtemp(prefix='retired-app-',dir=src.parent))
            need(image(target) == expected,'transaction_target_changed')
            os.rename(target,retired/'app')
        else: target.unlink()
    else:
        need(replacement['kind'] != 'app' or expected is None,'app_replacement_conflict')
        scratch=Path(tempfile.mkdtemp(prefix='.game-app-stage-',dir=target.parent))
        try:
            staged=scratch/'payload'; copy_image(src,staged)
            need(image(staged) == replacement and image(target) == expected,'staging_drift')
            os.replace(staged,target)
        finally: shutil.rmtree(scratch)

def module_bridge(control=None):
    control=CONTROL if control is None else control
    loader=importlib.machinery.SourceFileLoader('game_scoped_ready',str(control/'lib/game_operation_readiness.py'))
    spec=importlib.util.spec_from_loader(loader.name,loader);out=importlib.util.module_from_spec(spec);loader.exec_module(out);return out
