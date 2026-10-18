"""Synthetic launch plumbing only; no Wine, Steam, profile or GUI execution."""
import contextlib,io,os,sys,unittest
from pathlib import Path
from unittest import mock
import test_ds3_virtual_fullscreen as virtual_fixture

class QuitTrace(unittest.TestCase):
    setUpClass=classmethod(virtual_fixture.PersistentFullscreen.setUpClass.__func__)
    setUp=virtual_fixture.PersistentFullscreen.setUp

    def route(self,**kwargs):
        request=mock.Mock();request.allow_client.return_value={'targetActive':False,'clientActive':False}
        request.allow_client.return_value.update(kwargs.pop('session',{}))
        override={'nativeBorderlessCapable':True,'diagnosticCapable':True}
        self.request=request
        with contextlib.ExitStack() as stack:
            for name,value in [('verify_installed',({'aspectFit':True,'rendererOverride':override},None)),
                               ('verify_borderless',({'argv':['synthetic']},None)),('admission',request),
                               ('renderer_fields',override),('renderer_hash','a'*64),
                               ('wine_env',{'WINEDEBUG':'-all'}),('inactive',None),
                               ('renderer_trace_session',self.root/'logs/dxmt-trace')]:
                stack.enter_context(mock.patch.object(self.h,name,return_value=value))
            popen=stack.enter_context(mock.patch.object(self.h.subprocess,'Popen',return_value=mock.Mock()))
            result=self.h.play(**kwargs)
        return result,popen

    def test_explicit_quit_trace_is_steam_scoped_fresh_private_log_without_settings_changes(self):
        old=self.root/'logs/launch-ds3.log';old.write_bytes(b'prior launch evidence')
        graphics,registry=self.graphics.read_bytes(),self.reg.read_bytes()
        result,popen=self.route(quit_trace=True)
        env=popen.call_args.kwargs['env']
        self.assertEqual(env['WINEDEBUG'],'-all,steam.exe:trace+macdrv,steam.exe:warn+macdrv,steam.exe:err+macdrv')
        self.assertNotIn('DXMT_CS2_TRACE_DIR',env);self.assertNotIn('MTL_HUD_ENABLED',env)
        log=Path(result['quitTraceLog']);self.assertEqual(log.parent,self.root/'logs')
        self.assertEqual(log.stat().st_mode&0o777,0o600);self.assertEqual(old.read_bytes(),b'prior launch evidence')
        self.assertEqual((self.graphics.read_bytes(),self.reg.read_bytes()),(graphics,registry))
        self.request.begin.assert_called_once();self.request.dispatched.assert_called_once_with([popen.return_value])
    def test_normal_and_performance_trace_remain_quiet(self):
        for kwargs in ({},{'trace':True},{'measure':True}):
            with self.subTest(kwargs=kwargs):
                result,popen=self.route(**kwargs)
                self.assertEqual(popen.call_args.kwargs['env']['WINEDEBUG'],'-all')
                self.assertNotIn('quitTraceLog',result)
    def test_warm_steam_or_active_game_refuses_before_log_and_dispatch(self):
        for session in ({'clientActive':True},{'targetActive':True}):
            with self.subTest(session=session),self.assertRaisesRegex(RuntimeError,'quit_trace_requires_stopped_client_target'):
                self.route(quit_trace=True,session=session)
            self.request.begin.assert_not_called()
            self.assertEqual(list((self.root/'logs').glob('steam-quit-trace-*')),[])
    def test_diagnostic_cannot_mix_with_measure_trace_or_preset(self):
        for kwargs in ({'trace':True},{'measure':True},{'preset':'1080'}):
            with self.subTest(kwargs=kwargs),self.assertRaisesRegex(RuntimeError,'quit_trace_exclusive'):
                self.h.play(quit_trace=True,**kwargs)
    def test_exact_cli_routes_quit_and_performance_trace_separately(self):
        (self.root/'AIDev/state').mkdir(parents=True)
        for action,expected in [('quit-trace',{'quit_trace':True}),('measure-trace',{'trace':True})]:
            with mock.patch.object(sys,'argv',['ds3-runtime',action]),mock.patch.object(self.h,'play',return_value={}) as play,contextlib.redirect_stdout(io.StringIO()):
                self.h.main()
            play.assert_called_once_with(**expected)

if __name__=='__main__':unittest.main(verbosity=2)
