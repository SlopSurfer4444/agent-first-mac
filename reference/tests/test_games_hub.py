import importlib.machinery,importlib.util,json,os,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
P=Path(__file__).resolve().parents[1]
loader=importlib.machinery.SourceFileLoader('games_hub',str(P/'bin/games-hub'))
spec=importlib.util.spec_from_loader(loader.name,loader); h=importlib.util.module_from_spec(spec);loader.exec_module(h)
class GamesHubTests(unittest.TestCase):
    def test_profile_links_reject_escape(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);(p/'bad').symlink_to('/tmp')
            with self.assertRaisesRegex(RuntimeError,'unexpected_profile_link'): h.snapshot(p)
    def test_profile_standard_drives_opaque_files(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);(p/'dosdevices').mkdir();(p/'dosdevices/z:').symlink_to('/');(p/'dosdevices/c:').symlink_to('../drive_c');(p/'secret').write_bytes(b'not parsed')
            rows=h.snapshot(p);self.assertEqual(len(rows),3);self.assertNotIn('not parsed',repr(rows))
    def test_font_rebase_only_donor_font_path(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);old=('Z:'+str(h.DONOR/h.ENGINE/'share/wine/fonts').replace('/','\\')).replace('\\','\\\\')
            for n in ('system.reg','user.reg','userdef.reg'): (p/n).write_text('keep account content\n'+old+'\\\\symbol.ttf')
            self.assertEqual(h.rebase_fonts(p),3)
            self.assertIn('keep account content',(p/'user.reg').read_text());self.assertNotIn(old,(p/'user.reg').read_text())
    def test_code_digest_detects_content_and_links(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);(p/'code').write_bytes(b'a');first=h.code_tree(p);(p/'code').write_bytes(b'b');self.assertNotEqual(first,h.code_tree(p))
    def test_copy_rejects_dangling_collision(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'target';p.symlink_to('/nonexistent')
            with self.assertRaisesRegex(RuntimeError,'destination_collision'):h.copy(Path(d),p)
    def test_inactive_timeout_blocks(self):
        with patch.object(h,'run',side_effect=h.subprocess.TimeoutExpired('wine',3)):
            with self.assertRaisesRegex(RuntimeError,'source_profile_active'):h.inactive()
    def test_launch_policy(self):
        text=(P/'bin/games-play').read_text()
        self.assertIn('--in-process-gpu',text);self.assertNotIn('-applaunch',text);self.assertNotIn('Game Library',text);self.assertNotIn('runpy',text)
        manifest=json.loads((P/'manifests/games-hub.json').read_text());self.assertEqual(set(manifest['controllerOverlay']),{'winebus.so','libgtm-controller-SDL2.dylib'})
    def test_cs2_delegation_shortcut(self):
        self.assertIn(b'games-play" cs2',h.shortcut_bytes('cs2'))
if __name__=='__main__': unittest.main()
