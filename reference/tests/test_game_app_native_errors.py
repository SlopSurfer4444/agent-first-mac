"""Native read-only diagnostics; never dispatches installed launchers or games."""
import json,subprocess,sys,tempfile,unittest
from pathlib import Path
P=Path(__file__).resolve().parents[1]
@unittest.skipUnless(sys.platform=='darwin','native AppKit diagnostics require macOS')
class NativeErrorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory();cls.binaries=[]
        for route in range(1,5):
            exe=Path(cls.tmp.name)/str(route)
            subprocess.run(['/usr/bin/clang','-x','objective-c','-fobjc-arc','-Os','-framework','AppKit','-DGAME_ROUTE='+str(route),str(P/'bin/game-app-launcher.m'),'-o',str(exe)],capture_output=True,check=True)
            cls.binaries.append(exe)
    @classmethod
    def tearDownClass(cls):cls.tmp.cleanup()
    def test_fixed_routes(self):
        for exe,expected in zip(self.binaries,('games-play cs2','games-play prince','games-play steam','ds3-play play')):
            p=subprocess.run([str(exe),'--check-route'],capture_output=True,text=True,check=True);self.assertEqual(p.stdout.strip(),expected)
    def test_known_errors_and_private_malformed_fallbacks(self):
        cases=[json.dumps({'state':'BLOCKED','reason':r}).encode() for r in ('profile_active','foreign_steam_active','PRIVATE_MARKER')]
        cases += [b'{"state":"BLOCKED","reason":null}',b'{"state":"BLOCKED","reason":[]}',b'[]',b'null',b'PRIVATE_MARKER',b'x'*4097]
        for route,exe in enumerate(self.binaries,1):
            for i,raw in enumerate(cases):
                with self.subTest(route=route,fixture=i):
                    p=subprocess.run([str(exe),'--check-error'],input=raw,capture_output=True,check=True)
                    result=p.stdout.decode();self.assertNotIn('PRIVATE_MARKER',result);self.assertEqual(p.stderr,b'')
                    if route==4:
                        self.assertNotIn('VPN',result)
                        self.assertIn('Игровая сессия или её служебные процессы ещё работают' if i==0 else 'другой игровой среде' if i==1 else 'Проверьте состояние игровой среды',result)
                    elif route==2:self.assertIn('Ubisoft Connect',result)
                    elif route==1:self.assertIn('Counter-Strike 2',result)
                    else:self.assertIn('Steam',result)
    def test_common_structured_failures_lowercase_state_and_no_raw_text(self):
        for route,exe in enumerate(self.binaries,1):
            for reason in ('launcher_busy','launch_in_progress','pending_launch_unconfirmed','runtime_changed','session_active','foreign_steam_active','vpn_proxy_unavailable'):
                with self.subTest(route=route,reason=reason):
                    raw=json.dumps({'state':'blocked','reason':reason,'details':'PRIVATE_MARKER /private/account'}).encode()
                    result=subprocess.run([str(exe),'--check-error'],input=raw,capture_output=True,check=True)
                    text=result.stdout.decode();self.assertNotIn('PRIVATE_MARKER',text);self.assertNotIn('/private/account',text)
                    self.assertEqual(result.stderr,b'')
                    if reason=='launch_in_progress':self.assertIn('Повторный запрос не отправлен',text)
                    if reason=='runtime_changed':self.assertIn('Требуется восстановить проверенный запуск',text)
                    if route!=2:self.assertNotIn('VPN',text)
if __name__=='__main__':unittest.main()
