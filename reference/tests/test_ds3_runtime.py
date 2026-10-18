import importlib.machinery,importlib.util,json,os,runpy,shutil,subprocess,sys,tempfile,unittest
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import Mock,patch
from lib import game_operation_readiness as game_ready
from lib import scoped_source_admission as source_admission
P=Path(__file__).resolve().parents[1]
loader=importlib.machinery.SourceFileLoader('ds3_runtime',str(P/'bin/ds3-runtime'))
spec=importlib.util.spec_from_loader(loader.name,loader); h=importlib.util.module_from_spec(spec);loader.exec_module(h)

class DS3Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.base=Path(self.tmp.name).resolve()
        self.home=self.base/'home'; self.home.mkdir(); self.source=self.home/'Library/Application Support/Adapted Games';self.root=self.source.with_name('Adapted Games DS3')
        self.control=self.home/'AIDev/control';self.control.mkdir(parents=True);(self.control/'bin').mkdir();(self.control/'manifests').mkdir()
        (self.home/'AIDev/bin').mkdir();(self.home/'Games').mkdir();(self.home/'AIDev/state').mkdir()
        self.candidate=self.base/'candidate';self.candidate.mkdir()
        self.prefix=self.root/'profiles/ds3'
        self.patches=[patch.object(h,k,v) for k,v in {'HOME':self.home,'ROOT':self.root,'SOURCE':self.source,'PREFIX':self.prefix,'CONTROL':self.control,'HERE':self.control}.items()]
        self.request=Mock();self.request.allow_client.return_value={'clientActive':False,'steamActive':False,'targetActive':False}
        self.patches.append(patch.object(h,'admission',return_value=self.request))
        for p in self.patches:p.start()
        self.critical={}
        for rel,data in {'engine/bin/wine':b'wine','engine/bin/wineserver':b'server',h.METAL:b'old metal',h.NATIVE_LOADER:b'native loader','engine/lib/wine/x86_64-windows/d3d11.dll':b'full d3d11','engine/share/wine/fonts/font':b'font'}.items():
            p=self.source/'runtime'/rel;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data);self.critical[rel]=h.sha(p)
        # Production pins this native loader via the complete runtime tree receipt,
        # while engine/bin/wine is the separate critical wrapper.
        self.critical.pop(h.NATIVE_LOADER)
        hub={'id':'games-hub','owner':'control-games-hub','criticalHashes':self.critical};hp=self.control/'manifests/games-hub.json';hp.write_text(json.dumps(hub));self.source.joinpath('manifest.json').write_bytes(hp.read_bytes()); (self.control/h.SOURCE_HUB_MANIFEST).write_bytes(hp.read_bytes())
        r={'owner':'control-games-hub','manifestSha256':h.sha(hp),'runtimeTreeSha256':h.code_tree(self.source/'runtime')};(self.source/'receipt.json').write_text(json.dumps(r))
        sp=self.source/'profiles/prince';sp.mkdir(parents=True)
        old=('Z:'+str(self.source/'runtime/engine/share/wine/fonts').replace('/','\\')).replace('\\','\\\\')
        for n in ('user.reg','userdef.reg','system.reg'):(sp/n).write_text('WINE REGISTRY Version 2\n;; opaque auth preserved\n'+old+'\n'+old)
        self.graphics=('<?xml version="1.0" encoding="UTF-16"?>\r\n<config><ScreenMode>FULLSCREEN</ScreenMode><Resolution-FullScreenWidth>1710</Resolution-FullScreenWidth><Resolution-FullScreenHeight>1068</Resolution-FullScreenHeight><Resolution-WindowScreenWidth>1680</Resolution-WindowScreenWidth><Resolution-WindowScreenHeight>945</Resolution-WindowScreenHeight><TextureQuality>HIGH</TextureQuality><AutoDetect>OFF</AutoDetect></config>').encode('utf-16-le')
        gp=sp/h.CONFIG_REL;gp.parent.mkdir(parents=True);gp.write_bytes(self.graphics)
        steam=sp/'drive_c/Program Files (x86)/Steam/steam.exe';steam.parent.mkdir(parents=True);steam.write_bytes(b'fake client')
        (self.candidate/'winemetal.so').write_bytes(b'candidate');(self.candidate/'winemetal-airconv-original.so').write_bytes(b'old metal')
        prov={'candidate':h.sha(self.candidate/'winemetal.so'),'donor':self.critical[h.METAL],'d3d11':self.critical['engine/lib/wine/x86_64-windows/d3d11.dll'],'installed':False};(self.candidate/'provenance.json').write_text(json.dumps(prov))
        self.m={'schema':1,'id':'ds3-marshal-fix','owner':'control-ds3-marshal-fix','candidateSha256':prov['candidate'],'provenanceSha256':h.sha(self.candidate/'provenance.json'),'donorSha256':prov['donor'],'sourceHubManifestSha256':h.sha(hp),'sourceCriticalHashes':self.critical,'windowMode':'WINDOW','fontPathCount':6}
        src=self.candidate/'source/src/winemetal/test.c';src.parent.mkdir(parents=True);src.write_bytes(b'corresponding source')
        prov['sourceFiles']={'src/winemetal/test.c':h.sha(src)}
        (self.candidate/'provenance.json').write_text(json.dumps(prov));self.m['provenanceSha256']=h.sha(self.candidate/'provenance.json')
        (self.candidate/'build.py').write_bytes(b'build');(self.candidate.parent/'dxmt_command.patched.metal').write_bytes(b'patch')
        self.m['candidateBuildFiles']={'build.py':h.sha(self.candidate/'build.py')};self.m['marshalSources']={'dxmt_command.patched.metal':h.sha(self.candidate.parent/'dxmt_command.patched.metal')}
        self.mp=self.control/h.MANIFEST;self.mp.write_text(json.dumps(self.m))
        for name in ('ds3-runtime','ds3-play'):shutil.copyfile(P/'bin'/name,self.control/'bin'/name)
        self.bcandidate=self.base/'borderless-candidate';self.bcandidate.mkdir()
        pe=bytearray(256);pe[:2]=b'MZ';pe[60:64]=(128).to_bytes(4,'little');pe[128:132]=b'PE\0\0';pe[132:134]=(0x8664).to_bytes(2,'little')
        (self.bcandidate/'helper.exe').write_bytes(pe);(self.bcandidate/'helper.c').write_bytes(b'reviewed fixture source');(self.control/h.BORDERLESS_SOURCE).write_bytes(b'reviewed fixture source')
        report={'sourceSha256':h.sha(self.bcandidate/'helper.c'),'productionSha256':h.sha(self.bcandidate/'helper.exe'),'fixturePrefixStopped':True,'realGameStarted':False,'targetProfileChanged':False,'cases':[{'pass':True,'exit':n,'expectedExit':n} for n in (0,2,3,2)]}
        (self.bcandidate/'final-fixture-results.json').write_text(json.dumps(report))
        provenance={'schema':1,'sourceSha256':report['sourceSha256'],'helperSha256':report['productionSha256'],'compilerVersion':'0.15.2','compilerTarSha256':'e'*64,'target':'x86_64-windows-gnu','flags':['-O2','-Wall','-Wextra','-Werror','-luser32','-ladvapi32'],'fixtureReportSha256':h.sha(self.bcandidate/'final-fixture-results.json')}
        (self.bcandidate/'build-provenance.json').write_text(json.dumps(provenance))
        self.bm={'schema':1,'id':'ds3-borderless','owner':'control-ds3-marshal-fix','helperSha256':provenance['helperSha256'],'sourceSha256':provenance['sourceSha256'],'provenanceSha256':h.sha(self.bcandidate/'build-provenance.json'),'fixtureReportSha256':provenance['fixtureReportSha256'],'compilerVersion':'0.15.2','compilerTarSha256':'e'*64,'target':'x86_64-windows-gnu','nativeBinding':{'winemetalSha256':self.m['candidateSha256'],'donorSha256':self.m['donorSha256'],'d3d11Sha256':self.m['sourceCriticalHashes']['engine/lib/wine/x86_64-windows/d3d11.dll']},'argv':['--apply','--wait','180'],'timeoutSeconds':190}
        self.bmp=self.control/h.BORDERLESS_MANIFEST;self.bmp.write_text(json.dumps(self.bm))
    def tearDown(self):
        for p in reversed(self.patches):p.stop()
        self.tmp.cleanup()
    def installed(self):
        with patch.object(h,'source_gate'),patch.object(h,'inactive'):
            result=h.install('a'*40,self.candidate)
            h.install_borderless('a'*40,self.bcandidate)
            return result
    def test_accepted_source_loader_hardlinks_copy_to_independent_files(self):
        runtime=self.source/'runtime';os.link(runtime/'engine/bin/wine',runtime/'engine/bin/wine-alias')
        receipt=json.loads((self.source/'receipt.json').read_text());receipt['runtimeTreeSha256']=h.code_tree(runtime,allow_source_hardlinks=True);(self.source/'receipt.json').write_text(json.dumps(receipt))
        result=self.installed();self.assertTrue(result['changed'])
        src=runtime/'engine/bin/wine';dst=self.root/'runtime/engine/bin/wine';alias=self.root/'runtime/engine/bin/wine-alias'
        self.assertEqual(src.stat().st_nlink,2);self.assertEqual(dst.stat().st_nlink,1);self.assertEqual(alias.stat().st_nlink,1)
        self.assertNotEqual(src.stat().st_ino,dst.stat().st_ino);self.assertNotEqual(dst.stat().st_ino,alias.stat().st_ino)
        with self.assertRaisesRegex(RuntimeError,'unsafe_file'):h.sha(src)
    def test_inactive_blocks_before_copy(self):
        with patch.object(h,'source_gate'),patch.object(h,'inactive',side_effect=RuntimeError('profile_active')):
            with self.assertRaisesRegex(RuntimeError,'profile_active'):h.install('a'*40,self.candidate)
        self.assertFalse(self.root.exists())
    def test_wrong_candidate_hash_zero_mutations(self):
        (self.candidate/'winemetal.so').write_bytes(b'changed')
        with patch.object(h,'source_gate'),patch.object(h,'inactive'):
            with self.assertRaisesRegex(RuntimeError,'candidate_hash_mismatch'):h.install('a'*40,self.candidate)
        self.assertFalse(self.root.exists())
    def test_full_d3d11_drift_blocks(self):
        p=self.source/'runtime/engine/lib/wine/x86_64-windows/d3d11.dll';p.write_bytes(b'changed')
        with patch.object(h,'inactive'):
            with self.assertRaisesRegex(RuntimeError,'source_runtime_drift'):h.prepare(self.candidate)
        self.assertFalse(self.root.exists())
    def test_apfs_install_idempotent_no_start_source_preserved(self):
        before=h.snapshot(self.source/'profiles/prince');source_tree=h.code_tree(self.source/'runtime')
        original=h.subprocess.Popen
        def only_copy(*args,**kwargs):
            self.assertEqual(args[0][0],'/bin/cp');return original(*args,**kwargs)
        with patch.object(h.subprocess,'Popen',side_effect=only_copy):
            first=self.installed();second=self.installed()
        self.assertTrue(first['changed']);self.assertFalse(second['changed']);self.assertFalse(first['gameStarted'])
        self.assertEqual(before,h.snapshot(self.source/'profiles/prince'));self.assertEqual(source_tree,h.code_tree(self.source/'runtime'))
        original=self.source/'profiles/prince'/h.CONFIG_REL;clone=self.prefix/h.CONFIG_REL
        self.assertEqual(original.read_bytes(),self.graphics);self.assertEqual(clone.with_name(clone.name+'.ds3-pre-window').read_bytes(),self.graphics)
        text=clone.read_bytes().decode('utf-16-le');self.assertIn('<ScreenMode>WINDOW</ScreenMode>',text);self.assertIn('<TextureQuality>HIGH</TextureQuality><AutoDetect>OFF</AutoDetect>',text)
        self.assertNotEqual(original.stat().st_ino,clone.stat().st_ino);self.assertEqual(clone.stat().st_nlink,1)
    def test_pending_pins_fail_closed(self):
        self.m['candidateSha256']=None;self.mp.write_text(json.dumps(self.m))
        with self.assertRaisesRegex(RuntimeError,'candidate_pins_pending'):h.prepare(self.candidate)
    def test_profile_escape_and_hardlink_reject(self):
        p=self.source/'profiles/prince';(p/'escape').symlink_to('/tmp')
        with self.assertRaisesRegex(RuntimeError,'unexpected_profile_link'):h.snapshot(p)
        (p/'escape').unlink();os.link(p/'user.reg',p/'linked')
        with self.assertRaisesRegex(RuntimeError,'profile_hardlink'):h.snapshot(p)
    def test_prefix_missing_does_not_call_wine(self):
        with patch.object(h,'run',side_effect=AssertionError('Wine executed')):
            with self.assertRaisesRegex(RuntimeError,'profile_missing'):h.inactive(self.source/'runtime',self.base/'absent')
    def test_inactive_timeout_blocks(self):
        with patch.object(h,'run',side_effect=subprocess.TimeoutExpired('server',3)):
            with self.assertRaisesRegex(RuntimeError,'profile_active'):h.inactive(self.source/'runtime',self.source/'profiles/prince')
    def test_foreign_steam_blocks_no_launch(self):
        self.installed()
        with patch.object(self.request,'allow_client',side_effect=RuntimeError('foreign_steam_active')),patch.object(h.subprocess,'Popen',side_effect=AssertionError('launch')):
            with self.assertRaisesRegex(RuntimeError,'foreign_steam_active'):h.play()
    def test_launch_exact_ds3_environment_without_ambient(self):
        self.installed()
        with patch.object(h,'inactive'),patch.object(h,'run',return_value=b'') as run,patch.object(h.subprocess,'Popen') as launch,patch.dict(os.environ,{'DYLD_INSERT_LIBRARIES':'evil','DXMT_DS3_MARSHAL_FIX':'0'}):
            h.play()
        args,kwargs=launch.call_args;self.assertEqual(args[0][-3:],['-cef-disable-gpu','-applaunch','374320'])
        self.assertEqual(kwargs['env']['DXMT_DS3_MARSHAL_FIX'],'1');self.assertEqual(kwargs['env']['WINEPREFIX'],str(self.prefix));self.assertNotIn('DYLD_INSERT_LIBRARIES',kwargs['env'])
    def test_tampered_installed_metal_blocks_launch(self):
        self.installed();(self.root/'runtime'/h.METAL).write_bytes(b'bad')
        with patch.object(h.subprocess,'Popen',side_effect=AssertionError('launch')):
            with self.assertRaisesRegex(RuntimeError,'installed_critical_drift'):h.play()
    def test_unknown_graphics_preimage_rejects_no_rewrite(self):
        self.prefix.mkdir(parents=True);p=self.prefix/h.CONFIG_REL;p.parent.mkdir(parents=True);raw=self.graphics.replace('FULLSCREEN'.encode('utf-16-le'),'BORDERLESS'.encode('utf-16-le'));p.write_bytes(raw)
        with self.assertRaisesRegex(RuntimeError,'graphics_preimage_drift'):h.window_config()
        self.assertEqual(p.read_bytes(),raw)
    def test_canonical_gate_rejects_worktree_before_commands(self):
        with patch.object(h,'HERE',P),patch.object(h,'run',side_effect=AssertionError('execution')):
            with self.assertRaisesRegex(RuntimeError,'canonical_source_required'):h.source_gate('a'*40)
    def test_unadmitted_or_nonboolean_scoped_readiness_cannot_borrow_pass_label(self):
        for ready in (False,1,None):
            report={'verdict':'PASS','gitOnly':True,'scopedCandidateReady':ready}
            bridge=SimpleNamespace(metadata=game_ready.metadata,bound=game_ready.bound,ready=Mock(return_value=report))
            with patch.object(h.Path,'absolute',return_value=self.control/'bin/ds3-runtime'),patch.object(source_admission,'check'),patch.object(h,'readiness_bridge',return_value=bridge):
                with self.assertRaisesRegex(RuntimeError,'scoped_operation_readiness_required'):h.source_gate('a'*40)
    def test_source_drift_after_scoped_readiness_rejects(self):
        bridge=SimpleNamespace(metadata=game_ready.metadata,bound=game_ready.bound,ready=Mock(return_value={'scopedCandidateReady':True}))
        with patch.object(h.Path,'absolute',return_value=self.control/'bin/ds3-runtime'),patch.object(source_admission,'check',side_effect=[None,source_admission.SourceError('source_dirty')]),patch.object(h,'readiness_bridge',return_value=bridge):
            with self.assertRaisesRegex(RuntimeError,'source_dirty'):h.source_gate('a'*40)
    def test_runtime_external_symlink_and_critical_symlink_block(self):
        runtime=self.source/'runtime';(runtime/'outside').symlink_to(self.candidate)
        with self.assertRaisesRegex(RuntimeError,'external_runtime_link'):h.code_tree(runtime)
        (runtime/'outside').unlink();metal=runtime/h.METAL;metal.unlink();metal.symlink_to(self.candidate/'winemetal.so')
        with self.assertRaisesRegex(RuntimeError,'unsafe_file'):h.sha(metal)
    def test_stop_only_exact_ds3_prefix(self):
        self.installed()
        with patch.object(h.subprocess,'run',return_value=subprocess.CompletedProcess([],0,stdout=b'',stderr=b'')) as run:h.stop()
        for call in run.call_args_list:self.assertEqual(call.kwargs['env']['WINEPREFIX'],str(self.prefix))
        self.assertEqual(run.call_args_list[0].args[0][-1],'-k')
    def test_emergency_stop_skips_full_runtime_profile_and_shortcuts(self):
        self.installed();(self.home/'Games/Dark Souls III.command').unlink();(self.root/'runtime'/h.METAL).write_bytes(b'changed');(self.prefix/'new-save').write_bytes(b'updated')
        with patch.object(h,'snapshot',side_effect=AssertionError('profile scan')),patch.object(h,'code_tree',side_effect=AssertionError('runtime scan')),patch.object(h.subprocess,'run',return_value=subprocess.CompletedProcess([],1,stdout=b'',stderr=b'')),patch.object(h,'inactive'):
            self.assertEqual(h.stop()['state'],'DS3_PREFIX_STOPPED')
    def test_launch_without_retained_source_uses_owned_prefix(self):
        self.installed();shutil.rmtree(self.source)
        with patch.object(h,'inactive'),patch.object(h,'run',return_value=b''),patch.object(h.subprocess,'Popen') as launch:h.play()
        self.assertEqual(launch.call_args.kwargs['env']['WINEPREFIX'],str(self.prefix))
    def schema4_installed(self):
        self.installed()
        overrides={}
        for rel in h.RUNTIME_EXTENDED_PATHS:
            path=self.root/'runtime'/rel
            if not path.exists():
                path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'fixture runtime')
            overrides[rel]=h.sha(path)
        policy={'schema':2,'id':'wine-runtime-overlay','owner':'control-games-hub',
                'previousHubManifestSha256':'a'*64,'previousDS3ManifestSha256':'b'*64,
                'previousHubCriticalHashes':self.critical,'sourceHubManifestSha256':self.m['sourceHubManifestSha256'],
                'sourceCriticalHashes':self.critical,'desiredRuntimeHashes':overrides,
                'lifecycleSha256':h.sha(self.root/'ds3-runtime')}
        directory=self.root/'policy-source';directory.mkdir(mode=0o700)
        original=directory/'source-hub-v1.json';original.write_bytes((self.control/h.SOURCE_HUB_MANIFEST).read_bytes());original.chmod(0o600)
        target=directory/'overlay-policy.json';target.write_text(json.dumps(policy));target.chmod(0o600)
        manifest=dict(self.m,schema=4,runtimeOverrides=overrides,runtimeOverlayPolicySha256=h.sha(target))
        (self.root/'manifest.json').write_text(json.dumps(manifest))
        receipt=json.loads((self.root/'receipt.json').read_text());receipt.update(manifestSha256=h.sha(self.root/'manifest.json'),runtimeTreeSha256=h.code_tree(self.root/'runtime'))
        (self.root/'receipt.json').write_text(json.dumps(receipt))
        borderless=self.root/'borderless/receipt.json'
        row=json.loads(borderless.read_text());row.update(baseManifestSha256=receipt['manifestSha256'],baseRuntimeTreeSha256=receipt['runtimeTreeSha256'])
        borderless.write_text(json.dumps(row))
    def test_schema4_launch_and_stop_without_donor_or_control_policy(self):
        self.schema4_installed();shutil.rmtree(self.source);shutil.rmtree(self.control/'manifests')
        with patch.object(h,'inactive'),patch.object(h,'run',return_value=b''),patch.object(h.subprocess,'Popen') as launch:
            h.play()
        self.assertEqual(launch.call_args.kwargs['env']['WINEPREFIX'],str(self.prefix))
        with patch.object(h.subprocess,'run',return_value=subprocess.CompletedProcess([],0,stdout=b'',stderr=b'')) as run:
            h.stop()
        self.assertTrue(all(call.kwargs['env']['WINEPREFIX']==str(self.prefix) for call in run.call_args_list))
    def test_drifted_donor_server_never_executed_on_launch(self):
        self.schema4_installed();(self.source/'runtime/engine/bin/wineserver').write_bytes(b'donor independently updated')
        (self.source/'manifest.json').write_bytes(b'unrelated donor generation')
        with patch.object(h,'inactive') as inactive,patch.object(h,'run',return_value=b''),patch.object(h.subprocess,'Popen'):
            h.play()
        self.assertTrue(all(call.args[0]==self.root/'runtime' for call in inactive.call_args_list))
    def test_schema4_unrelated_overlay_policy_drift_does_not_block_stop(self):
        self.schema4_installed();(self.root/'policy-source/overlay-policy.json').write_text('{}')
        with patch.object(h.subprocess,'run',return_value=subprocess.CompletedProcess([],0,stdout=b'',stderr=b'')) as run:
            self.assertEqual(h.stop()['state'],'DS3_PREFIX_STOPPED')
        self.assertEqual(run.call_args_list[0].args[0],[str(self.root/'runtime/engine/bin/wineserver'),'-k'])
        self.assertEqual(run.call_args_list[1].args[0],[str(self.root/'runtime/engine/bin/wineserver'),'-w'])
    def test_stop_own_server_drift_still_blocks_before_execution(self):
        self.schema4_installed();(self.root/'runtime/engine/bin/wineserver').write_bytes(b'foreign server')
        with patch.object(h.subprocess,'run',side_effect=AssertionError('executed')):
            with self.assertRaisesRegex(RuntimeError,'installed_server_drift'):h.stop()
    def test_already_running_skips_history_but_keeps_process_admission(self):
        self.request.allow_client.return_value={'targetActive':True,'clientActive':True}
        with patch.object(h,'verify_installed',side_effect=AssertionError('history replay')),patch.object(h,'verify_borderless',side_effect=AssertionError('history replay')),patch.object(h.subprocess,'Popen',side_effect=AssertionError('launch')):
            self.assertEqual(h.play()['state'],'DS3_ALREADY_RUNNING')
        self.request.reconcile.assert_called_once();self.request.allow_client.assert_called_once()
    def test_corresponding_source_drift_blocks_before_install(self):
        (self.candidate/'source/src/winemetal/test.c').write_bytes(b'changed')
        with patch.object(h,'source_gate'),patch.object(h,'inactive'):
            with self.assertRaisesRegex(RuntimeError,'candidate_source_drift'):h.install('a'*40,self.candidate)
        self.assertFalse(self.root.exists())
    def test_game_saved_window_dimensions_accepted_and_reported(self):
        self.installed();p=self.prefix/h.CONFIG_REL;text=p.read_bytes().decode('utf-16-le')
        text=text.replace('<Resolution-WindowScreenWidth>1710</Resolution-WindowScreenWidth>','<Resolution-WindowScreenWidth>1680</Resolution-WindowScreenWidth>').replace('<Resolution-WindowScreenHeight>1068</Resolution-WindowScreenHeight>','<Resolution-WindowScreenHeight>945</Resolution-WindowScreenHeight>');raw=text.encode('utf-16-le');p.write_bytes(raw)
        result=h.status();self.assertEqual((result['windowWidth'],result['windowHeight']),(1680,945));self.assertEqual(p.read_bytes(),raw)
        with patch.object(h,'inactive'),patch.object(h,'run',return_value=b''),patch.object(h.subprocess,'Popen') as launch:h.play()
        self.assertEqual(launch.call_args.kwargs['env']['MTL_HUD_ENABLED'],'0');self.assertEqual(p.read_bytes(),raw)
    def test_invalid_duplicate_malformed_window_configuration_rejected(self):
        self.installed();p=self.prefix/h.CONFIG_REL;good=p.read_bytes().decode('utf-16-le')
        bad=[good.replace('WINDOW','UNSUPPORTED'),good.replace('<config>','<junk>').replace('</config>','</junk>'),good.replace('<config>','<config><nested>').replace('</config>','</nested></config>'),good.replace('</config>','<ScreenMode>WINDOW</ScreenMode></config>'),good.replace('</config>','<Resolution-WindowScreenWidth>1680</Resolution-WindowScreenWidth></config>'),good.replace('</Resolution-WindowScreenWidth>',''),good.replace('<Resolution-WindowScreenHeight>1068</Resolution-WindowScreenHeight>',''),good.replace('<config>','<!DOCTYPE config [<!ENTITY test "x">]><config>')]
        for value in ('0','-1','1680.0','NaN','7681','123456','000640','639'):
            bad.append(good.replace('<Resolution-WindowScreenWidth>1710</Resolution-WindowScreenWidth>','<Resolution-WindowScreenWidth>'+value+'</Resolution-WindowScreenWidth>'))
        for value in ('0','359','4321'):
            bad.append(good.replace('<Resolution-WindowScreenHeight>1068</Resolution-WindowScreenHeight>','<Resolution-WindowScreenHeight>'+value+'</Resolution-WindowScreenHeight>'))
        for i,text in enumerate(bad):
            with self.subTest(case=i):
                raw=text.encode('utf-16-le');p.write_bytes(raw)
                with self.assertRaisesRegex(RuntimeError,'ds3_window_config_drift'):h.verify_window_config()
                self.assertEqual(p.read_bytes(),raw)
    def test_measure_only_changes_sanitized_hud_flag(self):
        self.installed();calls=[]
        with patch.object(h,'inactive'),patch.object(h,'run',return_value=b''),patch.object(h.subprocess,'Popen',side_effect=lambda *a,**kw:calls.append((a,kw))),patch.dict(os.environ,{'MTL_HUD_ENABLED':'evil','DYLD_INSERT_LIBRARIES':'evil'}):
            normal=h.play();measure=h.play(measure=True)
        self.assertEqual(calls[1][0],calls[3][0]);a=calls[1][1]['env'];b=calls[3][1]['env']
        self.assertEqual({k for k in a if a[k]!=b[k]},{'MTL_HUD_ENABLED'});self.assertEqual(a['MTL_HUD_ENABLED'],'0');self.assertEqual(b['MTL_HUD_ENABLED'],'1');self.assertNotIn('DYLD_INSERT_LIBRARIES',b)
        self.assertFalse(normal['diagnosticHud']);self.assertTrue(measure['diagnosticHud'])
    def test_measure_cannot_bypass_runtime_drift(self):
        self.installed();(self.root/'runtime'/h.METAL).write_bytes(b'bad')
        with patch.object(h.subprocess,'Popen',side_effect=AssertionError('launch')):
            with self.assertRaisesRegex(RuntimeError,'installed_critical_drift'):h.play(measure=True)
    def test_wrapper_measure_routes_to_owned_lifecycle_with_clean_env(self):
        self.installed()
        with patch.object(h.pwd,'getpwuid',return_value=SimpleNamespace(pw_dir=str(self.home))),patch.object(sys,'argv',[str(P/'bin/ds3-play'),'measure']),patch.object(os,'execve') as execute,patch.dict(os.environ,{'DYLD_INSERT_LIBRARIES':'evil','MTL_HUD_ENABLED':'evil'}):
            runpy.run_path(str(P/'bin/ds3-play'))
        args=execute.call_args.args;self.assertEqual(args[0],str(self.root/'ds3-runtime'));self.assertEqual(args[1],[str(self.root/'ds3-runtime'),'measure']);self.assertNotIn('DYLD_INSERT_LIBRARIES',args[2]);self.assertNotIn('MTL_HUD_ENABLED',args[2])
    def new_helpers(self):
        for name in ('ds3-runtime','ds3-play'):
            p=self.control/'bin'/name;p.write_bytes(p.read_bytes()+b'\n# reviewed fixture helper successor\n')
    def test_refresh_updates_helpers_only_and_is_idempotent(self):
        self.installed();profile=h.snapshot(self.prefix);runtime=h.code_tree(self.root/'runtime');old=json.loads((self.root/'receipt.json').read_text());self.new_helpers()
        with patch.object(h,'source_gate'),patch.object(h,'inactive'),patch.object(h.subprocess,'Popen',side_effect=AssertionError('launch')):
            first=h.refresh('c'*40);second=h.refresh('c'*40)
        self.assertTrue(first['changed']);self.assertFalse(second['changed']);self.assertFalse(first['gameStarted']);self.assertEqual(profile,h.snapshot(self.prefix));self.assertEqual(runtime,h.code_tree(self.root/'runtime'))
        new=json.loads((self.root/'receipt.json').read_text());self.assertEqual({k for k in new if old[k]!=new[k]},{'commit','launcherSha256','lifecycleSha256'})
        for name in ('ds3-runtime','ds3-play'):self.assertEqual((self.root/name).read_bytes(),(self.control/'bin'/name).read_bytes())
    def test_refresh_drift_or_active_prefix_rejects_before_backups(self):
        self.installed();self.new_helpers();p=self.root/'ds3-play';old=p.read_bytes()
        with patch.object(h,'source_gate'),patch.object(h,'inactive',side_effect=RuntimeError('profile_active')):
            with self.assertRaisesRegex(RuntimeError,'profile_active'):h.refresh('c'*40)
        self.assertEqual(list(self.root.glob('.helper-refresh-*')),[]);self.assertEqual(p.read_bytes(),old)
        p.write_bytes(b'unknown')
        with patch.object(h,'source_gate'):
            with self.assertRaisesRegex(RuntimeError,'installed_helper_drift'):h.refresh('c'*40)
        self.assertEqual(list(self.root.glob('.helper-refresh-*')),[])
    def test_refresh_failure_restores_exact_helpers_receipt_and_preserves_data(self):
        self.installed();self.new_helpers();names=('ds3-runtime','ds3-play','receipt.json');old={name:(self.root/name).read_bytes() for name in names};profile=h.snapshot(self.prefix);runtime=h.code_tree(self.root/'runtime')
        with patch.object(h,'source_gate'),patch.object(h,'inactive'),patch.object(h,'status',side_effect=RuntimeError('postcheck_failed')):
            with self.assertRaisesRegex(RuntimeError,'postcheck_failed'):h.refresh('c'*40)
        for name in names:self.assertEqual((self.root/name).read_bytes(),old[name]);self.assertEqual((self.root/('.helper-refresh-'+('c'*12))/(name+'.before')).read_bytes(),old[name])
        self.assertEqual(profile,h.snapshot(self.prefix));self.assertEqual(runtime,h.code_tree(self.root/'runtime'));h.verify_installed()
    def test_refresh_midwrite_failure_rolls_back_partial_replacement(self):
        self.installed();self.new_helpers();old={name:(self.root/name).read_bytes() for name in ('ds3-runtime','ds3-play','receipt.json')};original=os.replace;attempts=[]
        def fail_second(src,dst):
            if str(src).endswith('.after'):
                attempts.append(src)
                if len(attempts)==2:raise OSError('fixture replacement failure')
            return original(src,dst)
        with patch.object(h,'source_gate'),patch.object(h,'inactive'),patch.object(os,'replace',side_effect=fail_second):
            with self.assertRaises(OSError):h.refresh('c'*40)
        for name in old:self.assertEqual((self.root/name).read_bytes(),old[name])
        h.verify_installed()
    def test_installed_native_loader_temporary_link_preserves_status_and_refresh(self):
        self.installed();loader=self.root/'runtime'/h.NATIVE_LOADER;link=self.base/'temporary-process-loader';os.link(loader,link)
        self.assertEqual(loader.stat().st_nlink,2);self.assertTrue(h.status()['runtimeVerified'])
        self.new_helpers()
        with patch.object(h,'source_gate'),patch.object(h,'inactive'):
            self.assertTrue(h.refresh('c'*40)['changed']);self.assertFalse(h.refresh('c'*40)['changed'])
        self.assertEqual(loader.read_bytes(),b'native loader');self.assertEqual(loader.stat().st_nlink,2)
        with self.assertRaisesRegex(RuntimeError,'unsafe_file'):h.code_tree(self.root/'runtime')
    def test_installed_native_loader_link_does_not_allow_byte_drift(self):
        self.installed();loader=self.root/'runtime'/h.NATIVE_LOADER;link=self.base/'temporary-process-loader';os.link(loader,link);link.write_bytes(b'modified native loader')
        with self.assertRaisesRegex(RuntimeError,'installed_runtime_drift'):h.status()
        with patch.object(h,'source_gate'):
            with self.assertRaisesRegex(RuntimeError,'installed_runtime_drift'):h.refresh('c'*40)
    def test_unrelated_installed_code_hardlink_still_rejected(self):
        self.installed();code=self.root/'runtime/engine/share/wine/fonts/font';os.link(code,self.base/'unrelated-link')
        with self.assertRaisesRegex(RuntimeError,'unsafe_file'):h.status()
        with patch.object(h,'source_gate'):
            with self.assertRaisesRegex(RuntimeError,'unsafe_file'):h.refresh('c'*40)
    def test_installed_loader_exception_cannot_change_initial_copy_scope(self):
        with self.assertRaisesRegex(RuntimeError,'invalid_installed_runtime_scope'):
            h.code_tree(self.source/'runtime',allow_installed_loader_hardlinks=True)
    def current_display(self):
        self.installed();xml=self.prefix/h.CONFIG_REL;xml.write_bytes(self.graphics)
        reg=self.prefix/'user.reg';reg.write_bytes(reg.read_bytes()+b'\n[Software\\\\Wine\\\\Mac Driver] 123\n"RetinaMode"="Y"\n"Keep"="opaque"\n\n[Software\\\\Wine\\\\AppDefaults\\\\Other.exe\\\\Mac Driver] 456\n"RetinaMode"="Y"\n')
        return xml,reg
    def test_large_window_changes_only_mode_and_isolated_global_retina(self):
        xml,reg=self.current_display();oldxml=xml.read_bytes();oldreg=reg.read_bytes();runtime=h.code_tree(self.root/'runtime');receipt=(self.root/'receipt.json').read_bytes()
        with patch.object(h,'source_gate'),patch.object(h,'inactive'),patch.object(h,'status',side_effect=AssertionError('prestate window check')),patch.object(h.subprocess,'Popen',side_effect=AssertionError('game launch')):
            first=h.large_window('d'*40);second=h.large_window('d'*40)
        self.assertTrue(first['changed']);self.assertFalse(second['changed']);self.assertFalse(first['gameStarted'])
        self.assertEqual(xml.read_bytes(),oldxml.replace('FULLSCREEN'.encode('utf-16-le'),'WINDOW'.encode('utf-16-le'),1));self.assertEqual(reg.read_bytes(),oldreg.replace(b'"RetinaMode"="Y"',b'"RetinaMode"="N"',1))
        self.assertEqual(runtime,h.code_tree(self.root/'runtime'));self.assertEqual(receipt,(self.root/'receipt.json').read_bytes())
        backup=self.root/('.large-window-'+('d'*12));self.assertEqual((backup/'user.reg.before').read_bytes(),oldreg);self.assertEqual((backup/'GraphicsConfig.xml.before').read_bytes(),oldxml)
    def test_large_window_active_or_invalid_prestate_has_zero_writes(self):
        xml,reg=self.current_display();oldxml=xml.read_bytes();oldreg=reg.read_bytes()
        with patch.object(h,'source_gate'),patch.object(h,'inactive',side_effect=RuntimeError('profile_active')):
            with self.assertRaisesRegex(RuntimeError,'profile_active'):h.large_window('d'*40)
        self.assertEqual(xml.read_bytes(),oldxml);self.assertEqual(reg.read_bytes(),oldreg);self.assertEqual(list(self.root.glob('.large-window-*')),[])
        for broken in (oldreg.replace(b'"RetinaMode"="Y"',b'"RetinaMode"="?"',1),oldreg+b'\n[Software\\\\Wine\\\\Mac Driver] 789\n"RetinaMode"="Y"\n',oldreg.replace(b'"Keep"="opaque"',b'"RetinaMode"="Y"',1)):
            with self.assertRaisesRegex(RuntimeError,'retina_'):h.large_window_plan(oldxml,broken)
        with self.assertRaisesRegex(RuntimeError,'display_graphics_drift'):h.large_window_plan(oldxml.replace('1680'.encode('utf-16-le'),'1920'.encode('utf-16-le')),oldreg)
    def test_large_window_postcheck_failure_restores_two_exact_preimages(self):
        xml,reg=self.current_display();oldxml=xml.read_bytes();oldreg=reg.read_bytes()
        with patch.object(h,'source_gate'),patch.object(h,'inactive'),patch.object(h,'verify_window_config',side_effect=RuntimeError('postcheck_failed')):
            with self.assertRaisesRegex(RuntimeError,'postcheck_failed'):h.large_window('d'*40)
        self.assertEqual(xml.read_bytes(),oldxml);self.assertEqual(reg.read_bytes(),oldreg)
    def test_large_window_midwrite_failure_restores_registry(self):
        xml,reg=self.current_display();oldxml=xml.read_bytes();oldreg=reg.read_bytes();original=os.replace
        def failure(src,dst):
            if str(src).endswith('GraphicsConfig.xml.after'):raise OSError('fixture write failure')
            return original(src,dst)
        with patch.object(h,'source_gate'),patch.object(h,'inactive'),patch.object(os,'replace',side_effect=failure):
            with self.assertRaises(OSError):h.large_window('d'*40)
        self.assertEqual(xml.read_bytes(),oldxml);self.assertEqual(reg.read_bytes(),oldreg)
    def base_only(self):
        with patch.object(h,'source_gate'),patch.object(h,'inactive'):h.install('a'*40,self.candidate)
    def test_borderless_install_preserves_core_and_profile_and_is_idempotent(self):
        self.base_only();runtime=h.code_tree(self.root/'runtime');profile=h.snapshot(self.prefix);receipt=(self.root/'receipt.json').read_bytes()
        with patch.object(h,'source_gate'),patch.object(h,'inactive'),patch.object(h.subprocess,'Popen',side_effect=AssertionError('launch')):
            first=h.install_borderless('b'*40,self.bcandidate);second=h.install_borderless('b'*40,self.bcandidate)
        self.assertTrue(first['changed']);self.assertFalse(second['changed']);self.assertFalse(first['gameStarted']);self.assertEqual(runtime,h.code_tree(self.root/'runtime'));self.assertEqual(profile,h.snapshot(self.prefix));self.assertEqual(receipt,(self.root/'receipt.json').read_bytes());h.verify_borderless()
    def test_borderless_wrong_hash_or_native_binding_rejects_zero_publication(self):
        self.base_only();(self.bcandidate/'helper.exe').write_bytes(b'wrong')
        with patch.object(h,'source_gate'),patch.object(h,'inactive'):
            with self.assertRaisesRegex(RuntimeError,'borderless_candidate_drift'):h.install_borderless('b'*40,self.bcandidate)
        self.assertFalse((self.root/'borderless').exists())
        self.bm['nativeBinding']['winemetalSha256']='f'*64;self.bmp.write_text(json.dumps(self.bm))
        with patch.object(h,'source_gate'),patch.object(h,'inactive'):
            with self.assertRaisesRegex(RuntimeError,'borderless_native_drift'):h.install_borderless('b'*40,self.bcandidate)
    def test_borderless_provenance_mismatch_rejects_even_rehashed_file(self):
        self.base_only();p=self.bcandidate/'build-provenance.json';data=json.loads(p.read_text());data['helperSha256']='f'*64;p.write_text(json.dumps(data));self.bm['provenanceSha256']=h.sha(p);self.bmp.write_text(json.dumps(self.bm))
        with patch.object(h,'source_gate'),patch.object(h,'inactive'):
            with self.assertRaisesRegex(RuntimeError,'borderless_provenance_binding'):h.install_borderless('b'*40,self.bcandidate)
        self.assertFalse((self.root/'borderless').exists())
    def test_borderless_postverify_failure_retains_stage_and_preserves_core(self):
        self.base_only();receipt=(self.root/'receipt.json').read_bytes();runtime=h.code_tree(self.root/'runtime')
        with patch.object(h,'source_gate'),patch.object(h,'inactive'),patch.object(h,'verify_borderless',side_effect=RuntimeError('postcheck_failed')):
            with self.assertRaisesRegex(RuntimeError,'postcheck_failed'):h.install_borderless('b'*40,self.bcandidate)
        self.assertFalse((self.root/'borderless').exists());self.assertTrue((self.root/('.borderless-stage-'+('b'*12))/'helper.exe').is_file());self.assertEqual(receipt,(self.root/'receipt.json').read_bytes());self.assertEqual(runtime,h.code_tree(self.root/'runtime'))
    def test_borderless_install_active_prefix_rejects_before_copy(self):
        self.base_only()
        with patch.object(h,'source_gate'),patch.object(h,'inactive',side_effect=RuntimeError('profile_active')):
            with self.assertRaisesRegex(RuntimeError,'profile_active'):h.install_borderless('b'*40,self.bcandidate)
        self.assertFalse((self.root/'borderless').exists());self.assertEqual(list(self.root.glob('.borderless-stage-*')),[])
    def test_play_starts_bound_helper_before_steam_with_separate_env(self):
        self.installed()
        with patch.object(h,'inactive'),patch.object(h,'run',return_value=b''),patch.object(h.subprocess,'Popen') as launch:result=h.play(measure=True)
        helper,steam=launch.call_args_list
        self.assertEqual(helper.args[0][-3:],['--apply','--wait','180']);self.assertEqual(steam.args[0][-3:],['-cef-disable-gpu','-applaunch','374320'])
        self.assertEqual(helper.kwargs['env']['DXMT_DS3_MARSHAL_FIX'],'0');self.assertEqual(helper.kwargs['env']['MTL_HUD_ENABLED'],'0');self.assertEqual(steam.kwargs['env']['DXMT_DS3_MARSHAL_FIX'],'1');self.assertEqual(steam.kwargs['env']['MTL_HUD_ENABLED'],'1');self.assertTrue(result['borderlessRequested']);self.assertFalse(result['borderlessVerified'])
    def test_helper_launch_failure_never_starts_steam(self):
        self.installed()
        with patch.object(h,'inactive'),patch.object(h,'run',return_value=b''),patch.object(h.subprocess,'Popen',side_effect=OSError('helper failed')) as launch:
            with self.assertRaises(OSError):h.play()
        self.assertEqual(launch.call_count,1)
    def test_steam_launch_failure_requests_only_helper_cancellation(self):
        from unittest.mock import Mock
        self.installed();helper=Mock()
        with patch.object(h,'inactive'),patch.object(h,'run',return_value=b''),patch.object(h.subprocess,'Popen',side_effect=[helper,OSError('steam failed')]):
            with self.assertRaisesRegex(RuntimeError,'steam_launch_failed_borderless_cancel_requested'):h.play()
        helper.terminate.assert_called_once_with()
    def test_missing_borderless_helper_blocks_play_and_refresh(self):
        self.base_only()
        with patch.object(h.subprocess,'Popen',side_effect=AssertionError('launch')):
            with self.assertRaises(FileNotFoundError):h.play()
        with patch.object(h,'source_gate'),patch.object(h,'inactive'):
            with self.assertRaises(FileNotFoundError):h.refresh('b'*40)
    def test_borderless_tamper_blocks_before_any_process(self):
        self.installed();(self.root/'borderless/helper.exe').write_bytes(b'changed')
        with patch.object(h.subprocess,'Popen',side_effect=AssertionError('launch')):
            with self.assertRaisesRegex(RuntimeError,'borderless_candidate_drift'):h.play()
    def overlay_bytes(self, value=None):
        leaf=b'' if value is None else b'"OverlayAppEnable" "'+value+b'"'
        return b'// opaque header\r\n"UserLocalConfigStore" { "Software" { "Valve" { "Steam" { "apps" { "42" {"OverlayAppEnable" "1"} "374320" {"LastPlayed" "opaque" '+leaf+b'} } "EnableOverlay" "1" } } } }\r\n'
    def overlay_fixture(self, value=None):
        self.installed();p=self.prefix/'drive_c/Program Files (x86)/Steam/userdata/123/config/localconfig.vdf';p.parent.mkdir(parents=True);p.write_bytes(self.overlay_bytes(value));return p
    def test_overlay_plan_inserts_exact_scope_preserves_all_prior_bytes(self):
        before=self.overlay_bytes();after=h.overlay_off_plan(before)
        self.assertEqual(after.replace(b'\r\n\t"OverlayAppEnable"\t\t"0"\r\n',b'',1),before)
        self.assertIn(b'"42" {"OverlayAppEnable" "1"}',after);self.assertIn(b'"EnableOverlay" "1"',after);self.assertEqual(h.overlay_off_plan(after),after)
    def test_overlay_plan_existing_value_changes_one_byte_and_noop(self):
        before=self.overlay_bytes(b'1');after=h.overlay_off_plan(before)
        self.assertEqual(sum(a!=b for a,b in zip(before,after)),1);self.assertEqual(len(before),len(after));self.assertEqual(h.overlay_off_plan(after),after)
    def test_overlay_namespace_duplicate_wrong_value_and_malformed_reject(self):
        before=self.overlay_bytes(b'1')
        invalid=(before.replace(b'"374320"',b'"374321"'),before.replace(b'"apps"',b'"notapps"'),before.replace(b'"OverlayAppEnable" "1"}',b'"OverlayAppEnable" "1" "overlayappenable" "0"}'),self.overlay_bytes(b'yes'),before[:-5],before.replace(b'"374320" {',b'"374320" {} "374320" {'))
        for data in invalid:
            with self.assertRaises(RuntimeError):h.overlay_off_plan(data)
    def test_overlay_parser_comments_escaped_values_and_limits(self):
        before=self.overlay_bytes().replace(b'"opaque"',b'"keep\\\"quoted\\\\path" // comment\r\n')
        after=h.overlay_off_plan(before);self.assertIn(b'"keep\\\"quoted\\\\path" // comment\r\n',after)
        for data in (b'"x" {'*66+b'}'*66,b'"x" "\0"',b'x "value"'):
            with self.assertRaises(RuntimeError):h.overlay_vdf(data)
    def test_overlay_off_private_backup_noop_preserves_runtime_graphics_receipt(self):
        target=self.overlay_fixture();before=target.read_bytes();graphics=(self.prefix/h.CONFIG_REL).read_bytes();runtime=h.code_tree(self.root/'runtime');receipt=(self.root/'receipt.json').read_bytes()
        with patch.object(h,'source_gate'),patch.object(h,'inactive'),patch.object(h.subprocess,'Popen',side_effect=AssertionError('launch')):
            result=h.overlay_off('c'*40);repeat=h.overlay_off('c'*40)
        self.assertTrue(result['changed']);self.assertFalse(repeat['changed']);self.assertFalse(result['gameStarted']);self.assertEqual((self.root/('.overlay-off-'+('c'*12))/'localconfig.vdf.before').read_bytes(),before);self.assertEqual((self.root/('.overlay-off-'+('c'*12))/'localconfig.vdf.before').stat().st_mode&0o777,0o600)
        self.assertEqual((self.prefix/h.CONFIG_REL).read_bytes(),graphics);self.assertEqual(h.code_tree(self.root/'runtime'),runtime);self.assertEqual((self.root/'receipt.json').read_bytes(),receipt)
    def test_overlay_off_source_gate_and_active_prefix_block_before_backup(self):
        target=self.overlay_fixture();before=target.read_bytes()
        with patch.object(h,'source_gate',side_effect=RuntimeError('gate_failed')),patch.object(h,'inactive') as inactive:
            with self.assertRaisesRegex(RuntimeError,'gate_failed'):h.overlay_off('c'*40)
        inactive.assert_not_called()
        with patch.object(h,'source_gate'),patch.object(h,'inactive',side_effect=RuntimeError('profile_active')):
            with self.assertRaisesRegex(RuntimeError,'profile_active'):h.overlay_off('c'*40)
        self.assertEqual(target.read_bytes(),before);self.assertEqual(list(self.root.glob('.overlay-off-*')),[])
    def test_overlay_discovery_multiple_and_symlink_reject(self):
        target=self.overlay_fixture();other=target.parents[2]/'456/config/localconfig.vdf';other.parent.mkdir(parents=True);other.write_bytes(target.read_bytes())
        with self.assertRaisesRegex(RuntimeError,'overlay_config_count'):h.overlay_config()
        other.unlink();other.symlink_to(target)
        with self.assertRaisesRegex(RuntimeError,'unsafe_file'):h.overlay_config()
    def test_overlay_postcheck_failure_restores_exact_preimage(self):
        target=self.overlay_fixture();before=target.read_bytes();original=h.overlay_off_plan
        def fail_after(data):
            if data!=before:raise RuntimeError('postcheck_failed')
            return original(data)
        with patch.object(h,'source_gate'),patch.object(h,'inactive'),patch.object(h,'overlay_off_plan',side_effect=fail_after):
            with self.assertRaisesRegex(RuntimeError,'postcheck_failed'):h.overlay_off('c'*40)
        self.assertEqual(target.read_bytes(),before)
    def test_overlay_runtime_drift_blocks_without_mutation(self):
        target=self.overlay_fixture();before=target.read_bytes();(self.root/'runtime'/h.METAL).write_bytes(b'changed')
        with patch.object(h,'source_gate'),patch.object(h,'inactive'):
            with self.assertRaisesRegex(RuntimeError,'installed_critical_drift'):h.overlay_off('c'*40)
        self.assertEqual(target.read_bytes(),before)
    def test_overlay_wrong_leaf_does_not_replace_global_or_wrong_named_key(self):
        before=self.overlay_bytes().replace(b'"LastPlayed" "opaque"',b'"EnableOverlayApp" "1" "LastPlayed" "opaque"');after=h.overlay_off_plan(before)
        self.assertIn(b'"EnableOverlayApp" "1"',after);self.assertEqual(h.overlay_off_plan(after),after)
        with self.assertRaisesRegex(RuntimeError,'overlay_vdf_key_escape'):h.overlay_off_plan(before.replace(b'"374320"',b'"\\374320"'))
    def test_overlay_backup_collision_retained_without_write(self):
        target=self.overlay_fixture();before=target.read_bytes();txn=self.root/('.overlay-off-'+('c'*12));txn.mkdir();(txn/'opaque').write_bytes(b'keep')
        with patch.object(h,'source_gate'),patch.object(h,'inactive'):
            with self.assertRaisesRegex(RuntimeError,'overlay_backup_collision'):h.overlay_off('c'*40)
        self.assertEqual(target.read_bytes(),before);self.assertEqual((txn/'opaque').read_bytes(),b'keep')
    def test_overlay_unknown_postimage_is_not_overwritten_during_rollback(self):
        target=self.overlay_fixture();original=h.overlay_off_plan;before=target.read_bytes()
        def changed_target(data):
            if data!=before:target.write_bytes(b'unknown third state');raise RuntimeError('postcheck_failed')
            return original(data)
        with patch.object(h,'source_gate'),patch.object(h,'inactive'),patch.object(h,'overlay_off_plan',side_effect=changed_target):
            with self.assertRaisesRegex(RuntimeError,'overlay_rollback_drift'):h.overlay_off('c'*40)
        self.assertEqual(target.read_bytes(),b'unknown third state');self.assertEqual((self.root/('.overlay-off-'+('c'*12))/'localconfig.vdf.before').read_bytes(),before)
    def resolution_fixture(self):
        self.installed();p=self.prefix/h.CONFIG_REL;p.write_bytes(self.graphics.replace('FULLSCREEN'.encode('utf-16-le'),'WINDOW'.encode('utf-16-le')));return p
    def test_resolution_plan_changes_only_two_values_and_preserves_quality(self):
        before=self.graphics.replace('FULLSCREEN'.encode('utf-16-le'),'WINDOW'.encode('utf-16-le')).replace('HIGH'.encode('utf-16-le'),'MAX'.encode('utf-16-le'))
        expected=before.replace('<Resolution-WindowScreenWidth>1680</Resolution-WindowScreenWidth>'.encode('utf-16-le'),'<Resolution-WindowScreenWidth>1920</Resolution-WindowScreenWidth>'.encode('utf-16-le')).replace('<Resolution-WindowScreenHeight>945</Resolution-WindowScreenHeight>'.encode('utf-16-le'),'<Resolution-WindowScreenHeight>1080</Resolution-WindowScreenHeight>'.encode('utf-16-le'))
        after=h.resolution_1080_plan(before);self.assertEqual(after,expected);self.assertEqual(h.resolution_1080_plan(after),after)
    def test_resolution_plan_rejects_wrong_mode_dimensions_duplicates_and_encoding(self):
        before=self.graphics.decode('utf-16-le').replace('FULLSCREEN','WINDOW')
        bad=(before.replace('WINDOW','FULLSCREEN'),before.replace('<Resolution-WindowScreenWidth>1680','<Resolution-WindowScreenWidth>1920'),before.replace('<Resolution-WindowScreenHeight>945','<Resolution-WindowScreenHeight>1080'),before.replace('</config>','<Resolution-WindowScreenWidth>1680</Resolution-WindowScreenWidth></config>'),before.replace('<config>','<config><nested>').replace('</config>','</nested></config>'),before.replace('<Resolution-WindowScreenHeight>','<Resolution-WindowScreenHeight value="x">'),before.replace('<config>','<!DOCTYPE config><config>'),before.replace('<config>','<wrong>').replace('</config>','</wrong>'))
        for text in bad:
            with self.assertRaises(RuntimeError):h.resolution_1080_plan(text.encode('utf-16-le'))
        for raw in (b'\xff\xfe'+before.encode('utf-16-le'),b'bad',b'x'*131073):
            with self.assertRaises(RuntimeError):h.resolution_1080_plan(raw)
    def test_resolution_command_backup_noop_and_preserves_unrelated_state(self):
        target=self.resolution_fixture();before=target.read_bytes();runtime=h.code_tree(self.root/'runtime');receipt=(self.root/'receipt.json').read_bytes();registry=(self.prefix/'user.reg').read_bytes();borderless=h.sha(self.root/'borderless/helper.exe');environment=h.wine_env(self.root/'runtime',self.prefix,True)
        with patch.object(h,'source_gate'),patch.object(h,'inactive'),patch.object(h.subprocess,'Popen',side_effect=AssertionError('launch')):
            first=h.resolution_1080('e'*40);second=h.resolution_1080('e'*40)
        self.assertTrue(first['changed']);self.assertFalse(second['changed']);self.assertFalse(first['gameStarted']);self.assertEqual((first['windowWidth'],first['windowHeight']),(1920,1080))
        backup=self.root/('.resolution-1080-'+('e'*12))/'GraphicsConfig.xml.before';self.assertEqual(backup.read_bytes(),before);self.assertEqual(backup.stat().st_mode&0o777,0o600)
        self.assertEqual(runtime,h.code_tree(self.root/'runtime'));self.assertEqual(receipt,(self.root/'receipt.json').read_bytes());self.assertEqual(registry,(self.prefix/'user.reg').read_bytes());self.assertEqual(borderless,h.sha(self.root/'borderless/helper.exe'));self.assertEqual(environment,h.wine_env(self.root/'runtime',self.prefix,True))
    def test_resolution_command_source_and_active_gate_reject_before_backup(self):
        target=self.resolution_fixture();before=target.read_bytes()
        with patch.object(h,'source_gate',side_effect=RuntimeError('gate_failed')),patch.object(h,'inactive') as inactive:
            with self.assertRaisesRegex(RuntimeError,'gate_failed'):h.resolution_1080('e'*40)
        inactive.assert_not_called()
        with patch.object(h,'source_gate'),patch.object(h,'inactive',side_effect=RuntimeError('profile_active')):
            with self.assertRaisesRegex(RuntimeError,'profile_active'):h.resolution_1080('e'*40)
        self.assertEqual(target.read_bytes(),before);self.assertEqual(list(self.root.glob('.resolution-1080-*')),[])
    def test_resolution_postcheck_failure_restores_exact_preimage_and_mode(self):
        target=self.resolution_fixture();before=target.read_bytes();mode=target.stat().st_mode&0o777
        with patch.object(h,'source_gate'),patch.object(h,'inactive'),patch.object(h,'verify_window_config',side_effect=RuntimeError('postcheck_failed')):
            with self.assertRaisesRegex(RuntimeError,'postcheck_failed'):h.resolution_1080('e'*40)
        self.assertEqual(target.read_bytes(),before);self.assertEqual(target.stat().st_mode&0o777,mode)
    def test_resolution_unknown_postimage_is_retained_during_rollback(self):
        target=self.resolution_fixture();before=target.read_bytes()
        def drift():target.write_bytes(b'unknown third state');raise RuntimeError('postcheck_failed')
        with patch.object(h,'source_gate'),patch.object(h,'inactive'),patch.object(h,'verify_window_config',side_effect=drift):
            with self.assertRaisesRegex(RuntimeError,'resolution_rollback_drift'):h.resolution_1080('e'*40)
        self.assertEqual(target.read_bytes(),b'unknown third state');self.assertEqual((self.root/('.resolution-1080-'+('e'*12))/'GraphicsConfig.xml.before').read_bytes(),before)
    def test_resolution_backup_collision_retained_and_runtime_drift_blocks(self):
        target=self.resolution_fixture();before=target.read_bytes();txn=self.root/('.resolution-1080-'+('e'*12));txn.mkdir();(txn/'keep').write_bytes(b'keep')
        with patch.object(h,'source_gate'),patch.object(h,'inactive'):
            with self.assertRaisesRegex(RuntimeError,'resolution_backup_collision'):h.resolution_1080('e'*40)
        self.assertEqual(target.read_bytes(),before);self.assertEqual((txn/'keep').read_bytes(),b'keep')
        (self.root/'runtime'/h.METAL).write_bytes(b'changed')
        with patch.object(h,'source_gate'),patch.object(h,'inactive'):
            with self.assertRaisesRegex(RuntimeError,'installed_critical_drift'):h.resolution_1080('e'*40)
        self.assertEqual(target.read_bytes(),before)
    def test_retirement_keeps_data(self):
        self.installed()
        with patch.object(h,'source_gate'),patch.object(h,'inactive'):result=h.retire('b'*40)
        self.assertFalse(result['profileDeleted']);self.assertFalse(self.root.exists());self.assertTrue(self.root.with_name(self.root.name+' retired '+('b'*12)).joinpath('profiles/ds3',h.CONFIG_REL).is_file())
        self.assertTrue(self.source.is_dir());self.assertFalse((self.home/'Games/Dark Souls III.command').exists())
    def aspect_fixture(self):
        self.installed()
        (self.prefix/'user.reg').write_bytes(b'WINE REGISTRY Version 2\n[Software\\\\Wine\\\\Mac Driver] 123\n"RetinaMode"="N"\n"Other"="keep"\n')
        oldmanifest=h.sha(self.root/'manifest.json');oldborderless=h.sha(self.root/'borderless/manifest.json')
        (self.candidate/'winemetal.so').write_bytes(b'aspect candidate')
        prov=json.loads((self.candidate/'provenance.json').read_text());prov['candidate']=h.sha(self.candidate/'winemetal.so');(self.candidate/'provenance.json').write_text(json.dumps(prov))
        policy={'schema':1,'id':'ds3-aspect-fit','owner':self.m['owner'],'previousManifestSha256':oldmanifest,'previousBorderlessManifestSha256':oldborderless,'candidateSha256':prov['candidate'],'provenanceSha256':h.sha(self.candidate/'provenance.json'),'candidateBuildFiles':self.m['candidateBuildFiles'],'marshalSources':self.m['marshalSources']}
        (self.control/h.ASPECT_MANIFEST).write_text(json.dumps(policy))
        return {n:None if not t.exists() else t.read_bytes() for n,t in h.aspect_targets().items()}
    def aspect_upgrade(self):
        with patch.object(h,'source_gate'),patch.object(h,'inactive'):return h.upgrade_aspect('f'*40,self.candidate)
    def test_aspect_upgrade_noop_rollback_preserves_quality_and_old_runtime(self):
        before=self.aspect_fixture();source=h.code_tree(self.source/'runtime')
        result=self.aspect_upgrade();self.assertTrue(result['changed']);self.assertFalse(result['gameplayVerified'])
        self.assertFalse(self.aspect_upgrade()['changed']);m,r=h.verify_installed();h.verify_borderless();self.assertTrue(m['aspectFit'])
        text=(self.prefix/h.CONFIG_REL).read_bytes().decode('utf-16-le')
        self.assertIn('<Resolution-WindowScreenWidth>2560</Resolution-WindowScreenWidth>',text)
        self.assertIn('<TextureQuality>HIGH</TextureQuality><AutoDetect>OFF</AutoDetect>',text)
        self.assertIn(b'"RetinaMode"="Y"',(self.prefix/'user.reg').read_bytes())
        self.assertEqual(h.code_tree(self.source/'runtime'),source)
        with patch.object(h,'source_gate'),patch.object(h,'inactive'):h.rollback_aspect('e'*40,'f'*40)
        self.assertEqual(before,{n:None if not t.exists() else t.read_bytes() for n,t in h.aspect_targets().items()})
    def test_aspect_reject_candidate_before_mutation(self):
        before=self.aspect_fixture();(self.candidate/'winemetal.so').write_bytes(b'wrong')
        with self.assertRaisesRegex(RuntimeError,'candidate_hash_mismatch'):self.aspect_upgrade()
        self.assertEqual(before,{n:None if not t.exists() else t.read_bytes() for n,t in h.aspect_targets().items()})
    def test_aspect_reject_active_before_transaction(self):
        self.aspect_fixture()
        with patch.object(h,'source_gate'),patch.object(h,'inactive',side_effect=RuntimeError('profile_active')):
            with self.assertRaisesRegex(RuntimeError,'profile_active'):h.upgrade_aspect('f'*40,self.candidate)
        self.assertFalse((self.root/('.aspect-upgrade-'+'f'*40)).exists())
    def test_aspect_failure_restores_complete_prestate(self):
        before=self.aspect_fixture();original=h.os.replace;count=0
        def fail_once(a,b):
            nonlocal count
            count+=1
            if count==5:raise OSError('fixture replacement failure')
            return original(a,b)
        with patch.object(h.os,'replace',side_effect=fail_once):
            with self.assertRaises(OSError):self.aspect_upgrade()
        self.assertEqual(before,{n:None if not t.exists() else t.read_bytes() for n,t in h.aspect_targets().items()})
        h.verify_installed();h.verify_borderless()
    def test_aspect_rollback_drift_zero_changes(self):
        self.aspect_fixture();self.aspect_upgrade();(self.prefix/h.CONFIG_REL).write_bytes(b'owner changed')
        before={n:None if not t.exists() else t.read_bytes() for n,t in h.aspect_targets().items()}
        with patch.object(h,'source_gate'),patch.object(h,'inactive'):
            with self.assertRaisesRegex(RuntimeError,'aspect_rollback_drift'):h.rollback_aspect('e'*40,'f'*40)
        self.assertEqual(before,{n:None if not t.exists() else t.read_bytes() for n,t in h.aspect_targets().items()})
    def test_aspect_fallback_collision_zero_changes(self):
        self.aspect_fixture();(self.home/'Games/Dark Souls III - 1080p.command').write_bytes(b'owner file')
        with self.assertRaisesRegex(RuntimeError,'aspect_shortcut_collision'):self.aspect_upgrade()
        self.assertEqual((self.home/'Games/Dark Souls III - 1080p.command').read_bytes(),b'owner file')
    def test_aspect_launch_presets_reapply_only_dimensions(self):
        self.aspect_fixture();self.aspect_upgrade();target=self.prefix/h.CONFIG_REL;initial=target.read_bytes()
        h.select_resolution('1080');fallback=target.read_bytes();self.assertNotEqual(initial,fallback)
        self.assertEqual(h.verify_window_config()['windowWidth'],1920)
        h.select_resolution('1440');self.assertEqual(initial,target.read_bytes())
        with self.assertRaisesRegex(RuntimeError,'unsupported_resolution'):h.select_resolution('2160')
        self.assertEqual(initial,target.read_bytes())
    def test_aspect_launch_flag_and_fallback(self):
        self.aspect_fixture();self.aspect_upgrade();calls=[]
        with patch.object(h,'inactive'),patch.object(h,'no_foreign_steam'),patch.object(h.subprocess,'Popen',side_effect=lambda *a,**kw:calls.append((a,kw))):
            result=h.play(preset='1080')
        self.assertEqual(result['windowWidth'],1920);self.assertEqual(calls[1][1]['env']['DXMT_DS3_ASPECT_FIT'],'1')
        self.assertNotIn('DXMT_DS3_ASPECT_FIT',calls[0][1]['env'])
    def test_aspect_preset_malformed_rejected(self):
        raw=self.graphics.replace('FULLSCREEN'.encode('utf-16-le'),'WINDOW'.encode('utf-16-le'))
        text=raw.decode('utf-16-le')
        for invalid in (text.replace('<config>','<!DOCTYPE config><config>'),text.replace('</config>','<ScreenMode>WINDOW</ScreenMode></config>'),text.replace('1680','99999'),text.replace('WINDOW','UNSUPPORTED')):
            with self.assertRaises(RuntimeError):h.resolution_plan(invalid.encode('utf-16-le'),'1440')
    def test_aspect_registry_other_bytes_preserved(self):
        raw=b'[Software\\\\Wine\\\\Mac Driver] 1\n"RetinaMode"="N"\n"Other"="N"\n[Other]\n"RetinaMode"="N"\n'
        after=h.retina_plan(raw);self.assertEqual(after,raw.replace(b'"RetinaMode"="N"',b'"RetinaMode"="Y"',1));self.assertEqual(h.retina_plan(after),after)
        with self.assertRaises(RuntimeError):h.retina_plan(raw+raw)

    def test_aspect_interrupted_transaction_recovery(self):
        before=self.aspect_fixture();original=h.os.replace;count=0
        def interrupt_once(a,b):
            nonlocal count
            count+=1
            if count==4:raise KeyboardInterrupt()
            return original(a,b)
        with patch.object(h.os,'replace',side_effect=interrupt_once):
            with self.assertRaises(KeyboardInterrupt):self.aspect_upgrade()
        with patch.object(h,'source_gate'),patch.object(h,'inactive'):h.rollback_aspect('e'*40,'f'*40)
        self.assertEqual(before,{n:None if not t.exists() else t.read_bytes() for n,t in h.aspect_targets().items()})

if __name__=='__main__':unittest.main()
