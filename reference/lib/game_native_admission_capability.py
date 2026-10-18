"""Fixed DS3 approval/route pair. No launch, privilege, or observer acceptance."""
import os,pwd,stat
from pathlib import Path
from lib import game_native_admission_bridge as b

HOME=Path(pwd.getpwuid(os.getuid()).pw_dir)
NAMES=('approval','routes')

def layout(home=None):
 home=HOME if home is None else Path(home)
 root=home/'Library/Application Support/Adapted Games DS3'
 return home,root,{'approval':home/'AIDev/state/ds3-native-launch-approval.json','routes':root/'profiles/ds3/native-applications.routes'}

def optional(path):
 try:path.lstat()
 except FileNotFoundError:return None
 return b._read(path,0o600)

def derive(intent,*,_test_home=None):
 home,root,_=layout(_test_home);route=intent['nativeRoute'];app=root/'native/Dark Souls III Native.app'
 target=root/'profiles/ds3/drive_c/Program Files (x86)/Steam/steamapps/common/DARK SOULS III/Game/DarkSoulsIII.exe'
 loader=app/'Contents/MacOS/wine';prefix=root/'profiles/ds3'
 b.need(route['machine']==0x8664 and route['image']==r'C:\Program Files (x86)\Steam\steamapps\common\DARK SOULS III\Game\DarkSoulsIII.exe','capability_route_scope')
 approval={'schema':2,'owner':b.OWNER,'route':'ds3','prefix':str(prefix),'image':route['image'],'machine':0x8664,'target':str(target),'loader':str(loader),'bundleIdentifier':route['bundleIdentifier'],'files':{str(target):route['targetSha256'],str(loader):route['bundleFiles']['Contents/MacOS/wine']['sha256'],str(app/'Contents/Info.plist'):route['bundleFiles']['Contents/Info.plist']['sha256'],str(root/'runtime/engine/lib/wine/x86_64-unix/ntdll.so'):intent['preserveRuntimeHashes']['engine/lib/wine/x86_64-unix/ntdll.so'],str(root/'runtime/engine/bin/wineserver'):intent['preserveServerSha256']}}
 b.need(all(b.pinned(value) for value in approval['files'].values()),'capability_file_pins')
 routes=('WINE-NATIVE-APPLICATIONS\t1\n8664\t'+route['image']+'\t'+str(loader)+'\n').encode()
 return {'approval':b.json_bytes(approval),'routes':routes}

def replace(path,raw,expected,stage,before_publish=lambda:None):
 parent=b._directory(path.parent);name=stage.name
 b.need(stage.parent==path.parent,'capability_stage_parent')
 try:
  b.need(optional(path)==expected,'capability_target_drift')
  if raw is None:
   if expected is not None:before_publish();b.need(optional(path)==expected,'capability_target_drift');os.unlink(path.name,dir_fd=parent);os.fsync(parent)
   return
  if stage.exists() or stage.is_symlink():
   partial=b._read(stage,0o600);b.need(raw.startswith(partial),'capability_stage_drift');offset=len(partial)
   fd=os.open(name,os.O_WRONLY|os.O_APPEND|os.O_NOFOLLOW,dir_fd=parent)
  else:
   fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent);offset=0
  try:
   while offset<len(raw):
    size=os.write(fd,raw[offset:]);b.need(size>0,'capability_write_failed');offset+=size
   os.fsync(fd)
  finally:os.close(fd)
  b.need(optional(path)==expected,'capability_target_drift')
  before_publish();b.need(optional(path)==expected,'capability_target_drift')
  os.replace(name,path.name,src_dir_fd=parent,dst_dir_fd=parent);os.fsync(parent)
  b.need(optional(path)==raw,'capability_readback')
 finally:os.close(parent)

class Transaction:
 def __init__(self,commit,intent,guard,*,_test_home=None,event=lambda _:None):
  b.need(b.pinned(commit,40) and callable(guard),'capability_binding')
  self.home,self.root,self.targets=layout(_test_home);self.directory=self.home/'AIDev/state'/('.game-native-capability-'+commit)
  self.commit=commit;self.intent=intent;self.guard=guard;self.event=event;self.after=derive(intent,_test_home=_test_home)
 def gate(self):b.need(self.guard() is True,'capability_prerequisite_unknown')
 def prepare(self,expected_before):
  self.gate();b.need(type(expected_before) is dict and set(expected_before)==set(NAMES),'capability_before_schema')
  before={key:optional(path) for key,path in self.targets.items()}
  b.need({key:None if raw is None else b.sha(raw) for key,raw in before.items()}==expected_before,'capability_prestate_changed')
  b.need(not self.directory.exists() and not self.directory.is_symlink(),'capability_transaction_exists')
  parent=b._directory(self.directory.parent);os.mkdir(self.directory.name,0o700,dir_fd=parent);os.fsync(parent);os.close(parent)
  images={key:{'before':None if before[key] is None else b.sha(before[key]),'after':b.sha(self.after[key])} for key in NAMES}
  record={'schema':1,'owner':b.OWNER,'commit':self.commit,'policySha256':b.sha(b.json_bytes(self.intent)),'phase':'prepared','direction':'after','intent':None,'images':images}
  # No managed target changes until this complete immutable image inventory exists.
  for side,files in (('before',before),('after',self.after)):
   for key,raw in files.items():
    if raw is not None:self.new(self.directory/(key+'.'+side),raw)
  self.new(self.directory/'record.json',b.json_bytes(record));self.read();return record
 def new(self,path,raw):
  parent=b._directory(path.parent,private=True);fd=None
  try:
   fd=os.open(path.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent);offset=0
   while offset<len(raw):
    n=os.write(fd,raw[offset:]);b.need(n>0,'capability_write_failed');offset+=n
   os.fsync(fd);os.fsync(parent)
  finally:
   if fd is not None:os.close(fd)
   os.close(parent)
 def read(self):
  record=b.decode(b._read(self.directory/'record.json',0o600));fields={'schema','owner','commit','policySha256','phase','direction','intent','images'}
  b.need(set(record)==fields and type(record['schema']) is int and record['schema']==1 and record['owner']==b.OWNER and record['commit']==self.commit and record['policySha256']==b.sha(b.json_bytes(self.intent)) and record['phase'] in ('prepared','running','complete') and record['direction'] in ('before','after') and record['intent'] in (None,*NAMES) and (record['phase']=='running' or record['intent'] is None) and (record['phase']!='prepared' or record['direction']=='after'),'capability_record_schema')
  b.need(type(record['images']) is dict and set(record['images'])==set(NAMES),'capability_images')
  files={'before':{},'after':{}};inventory={'record.json'}
  for key,row in record['images'].items():
   b.need(type(row) is dict and set(row)=={'before','after'} and (row['before'] is None or b.pinned(row['before'])) and b.pinned(row['after']),'capability_images')
   for side in files:
    if row[side] is None:files[side][key]=None;continue
    name=key+'.'+side;raw=b._read(self.directory/name,0o600);b.need(b.sha(raw)==row[side],'capability_snapshot_drift');files[side][key]=raw;inventory.add(name)
  fd=b._directory(self.directory,private=True)
  try:b.need(set(os.listdir(fd)) in (inventory,inventory|{'.record.next'}),'capability_inventory')
  finally:os.close(fd)
  b.need(files['after']==self.after,'capability_after_binding')
  stage=self.directory/'.record.next'
  if stage.exists() or stage.is_symlink():
   partial=b._read(stage,0o600)
   choices=[dict(record,phase='running',direction=direction,intent=key) for direction in ('before','after') for key in (None,*NAMES)]+[dict(record,phase='complete',intent=None)]
   b.need(any(b.json_bytes(choice).startswith(partial) for choice in choices),'capability_record_stage_drift')
  for key,path in self.targets.items():
   stage=self.target_stage(key)
   if stage.exists() or stage.is_symlink():
    b.need(record['phase']=='running' and record['intent']==key and files[record['direction']][key] is not None,'capability_unowned_stage')
    b.need(files[record['direction']][key].startswith(b._read(stage,0o600)),'capability_stage_drift')
  return record,files
 def save(self,record):
  path=self.directory/'record.json';replace(path,b.json_bytes(record),b._read(path,0o600),self.directory/'.record.next')
 def target_stage(self,key):return self.targets[key].parent/('.game-native-capability-'+self.commit+'-'+key+'.next')
 def arm_after(self):
  self.gate();record,files=self.read()
  b.need(record['phase'] in ('prepared','complete') and record['intent'] is None,'capability_recovery_required')
  side=record['direction'] if record['phase']=='complete' else 'before'
  b.need(all(optional(path)==files[side][key] for key,path in self.targets.items()),'capability_arm_preimage')
  record.update(phase='running',direction='after',intent=None);self.save(record);self.event('armed:after')
 def run(self,direction,recover=False):
  b.need(direction in ('before','after'),'capability_direction');self.gate();record,files=self.read()
  if recover:b.need(direction==record['direction'],'capability_recovery_direction')
  else:b.need(record['phase'] in ('prepared','complete') and record['intent'] is None,'capability_recovery_required')
  if recover:
   stage=self.directory/'.record.next'
   if stage.exists() or stage.is_symlink():
    raw=b._read(stage,0o600);self.gate();self.read();parent=b._directory(stage.parent)
    try:b.need(b._read(stage,0o600)==raw,'capability_record_stage_drift');os.unlink(stage.name,dir_fd=parent);os.fsync(parent)
    finally:os.close(parent)
  current={key:optional(path) for key,path in self.targets.items()};b.need(all(current[key] in (files['before'][key],files['after'][key]) for key in NAMES),'capability_third_state')
  if record['phase']=='complete' and record['direction']==direction:
   b.need(current==files[direction],'capability_noop_drift')
   stage=self.directory/'.record.next'
   if stage.exists() or stage.is_symlink():
    b.need(recover,'capability_unsettled_record_stage');raw=b._read(stage,0o600);self.gate();self.read()
    parent=b._directory(stage.parent)
    try:b.need(b._read(stage,0o600)==raw,'capability_record_stage_drift');os.unlink(stage.name,dir_fd=parent);os.fsync(parent)
    finally:os.close(parent)
   return False
  if not recover and record['phase']=='complete':b.need(current==files[record['direction']],'capability_rollback_preimage')
  record.update(phase='running',direction=direction,intent=record['intent'] if recover else None);self.save(record);self.event('running')
  for key in (NAMES if direction=='after' else tuple(reversed(NAMES))):
   self.gate();self.read();current={name:optional(path) for name,path in self.targets.items()};b.need(all(current[name] in (files['before'][name],files['after'][name]) for name in NAMES),'capability_third_state')
   if current[key]==files[direction][key] and not self.target_stage(key).exists():continue
   record['intent']=key;self.save(record);self.event('intent:'+key);self.gate()
   replace(self.targets[key],files[direction][key],current[key],self.target_stage(key),before_publish=self.gate);self.event('published:'+key)
   record['intent']=None;self.save(record)
  b.need(all(optional(path)==files[direction][key] for key,path in self.targets.items()),'capability_postimage')
  record.update(phase='complete',intent=None);self.save(record);self.event('complete');return True
