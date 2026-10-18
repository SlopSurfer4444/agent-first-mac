import ast, os, stat, subprocess, tempfile, unittest
from pathlib import Path
from unittest.mock import Mock
source=Path(__file__).resolve().parents[1]/'bin/ds3-runtime'
function=next(n for n in ast.parse(source.read_text()).body if isinstance(n,ast.FunctionDef) and n.name=='play')
class LaunchTests(unittest.TestCase):
 def setup(self,cap=True):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);root=Path(self.tmp.name)/'ds3';prefix=root/'profiles/ds3';(root/'logs').mkdir(parents=True)
  steam=prefix/'drive_c/Program Files (x86)/Steam/steam.exe';steam.parent.mkdir(parents=True);steam.write_text('fixture')
  req=Mock();req.allow_client.return_value={'targetActive':False,'clientActive':False};pop=Mock();pop.return_value=Mock()
  base={'aspectFit':True};override={'nativeBorderlessCapable':True} if cap else None
  def need(ok,reason):
   if not ok:raise RuntimeError(reason)
  ns=dict(ROOT=root,PREFIX=prefix,SOURCE=root/'absent',HOME=root,HERE=root,os=os,stat=stat,subprocess=Mock(Popen=pop),need=need,
   verify_installed=lambda:(base,None),verify_window_config=lambda:dict(windowMode='WINDOW',windowWidth=1920,windowHeight=1080),
   virtual_fullscreen_registry_enabled=lambda:False,verify_borderless=lambda:({'argv':['--follow','--wait','900']},None),admission=lambda *a:req,
   safe_directory=lambda *a:None,safe_file=lambda *a:None,inactive=lambda *a:None,wine_env=lambda *a:{},
   renderer_fields=lambda *a:override,renderer_hash=lambda *a:'a'*64)
  exec(compile(ast.Module(body=[function],type_ignores=[]),str(source),'exec'),ns);return ns,pop,req
 def test_native_exactly_one_client_no_helper(self):
  ns,pop,req=self.setup();result=ns['play']();self.assertEqual(pop.call_count,1)
  args,kwargs=pop.call_args;self.assertIn('-applaunch',args[0]);self.assertEqual(kwargs['env']['DXMT_DS3_BORDERLESS'],'1');self.assertEqual(kwargs['env']['DXMT_DS3_ASPECT_FIT'],'1')
  req.dispatched.assert_called_once_with([pop.return_value]);self.assertFalse(result['borderlessVerified']);self.assertEqual(result['borderlessRoute'],'native-owner-thread');self.assertEqual(result['windowWidth'],1920)
 def test_old_renderer_retains_helper_route(self):
  ns,pop,req=self.setup(False);result=ns['play']();self.assertEqual(pop.call_count,2);self.assertNotIn('DXMT_DS3_BORDERLESS',pop.call_args.kwargs['env']);self.assertEqual(result['borderlessRoute'],'external-helper')
 def test_native_client_launch_error_no_helper_cancel(self):
  ns,pop,req=self.setup();pop.side_effect=OSError('fixture failed')
  with self.assertRaisesRegex(RuntimeError,'steam_launch_failed'):ns['play']()
  self.assertEqual(pop.call_count,1);req.dispatched.assert_not_called()
 def test_fallback_client_error_cancels_exact_helper(self):
  ns,pop,req=self.setup(False);helper=Mock();pop.side_effect=[helper,OSError('fixture failed')]
  with self.assertRaisesRegex(RuntimeError,'steam_launch_failed'):ns['play']()
  helper.terminate.assert_called_once();req.dispatched.assert_not_called()
 def test_native_requires_aspect_before_launch_state_or_logs(self):
  ns,pop,req=self.setup();ns['verify_installed']=lambda:({},None)
  with self.assertRaisesRegex(RuntimeError,'native_borderless_requires_aspect'):ns['play']()
  pop.assert_not_called();req.begin.assert_not_called();req.reconcile.assert_not_called()
  self.assertFalse((ns['ROOT']/'logs/launch-ds3.log').exists())
if __name__=='__main__':unittest.main()
