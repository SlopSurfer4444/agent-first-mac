"""Schema4 downstream archive proofs; writes only disposable delivery fixtures."""
from types import SimpleNamespace
import unittest
from test_game_delivery_order import DeliveryOrder, u, w, a, COMMIT

class Schema4Archive(DeliveryOrder):
    successor_commit='e'*40
    def setUp(self):
        super().setUp()
        a.operate('archive-applied',COMMIT,self.old_overlay_pin,self.old_commit)
        a.operate('bootstrap-policy-source',COMMIT)
        u.operate('apply',COMMIT,self.pin)
        self.launch_history={key:self.path('source/'+key).read_bytes() for key in (u.POLICY,u.NATIVE_POLICY,'manifests/wine-runtime-overlay.json','manifests/ds3-source-hub-v1.json','bin/ds3-runtime')}
        self.new_overlay_pin=a.operate('plan',COMMIT)['planSha256']
        a.operate('apply',COMMIT,self.new_overlay_pin)
        self.head=self.successor_commit
        self.definition['previousFiles']={key:self.image(rel) for key,rel in u.TARGETS.items()}
        self.definition['guards']={rel:self.image(rel) for rel in u.GUARDS}
        self.put('source/'+u.POLICY,u.encode(self.definition))
    def command(self,argv,**kwargs):
        if argv[0]=='/usr/bin/git':
            if argv[-2]=='show' and hasattr(self,'second_history') and argv[-1].startswith('e'*40+':'):
                return SimpleNamespace(returncode=0,stdout=self.second_history[argv[-1].split(':',1)[1]])
            if 'cat-file' in argv and argv[-1] in (self.successor_commit,COMMIT,getattr(self,'old_commit','b'*40)):
                return SimpleNamespace(returncode=0,stdout=b'commit\n')
            if argv[-2]=='show' and argv[-1].startswith(COMMIT+':') and hasattr(self,'launch_history'):
                return SimpleNamespace(returncode=0,stdout=self.launch_history[argv[-1].split(':',1)[1]])
            if 'merge-base' in argv:
                rank={'b'*40:0,COMMIT:1,'e'*40:2,'f'*40:3}
                if '--is-ancestor' not in argv:
                    left,right=argv[-2:]
                    valid=left in rank and right in rank
                    return SimpleNamespace(returncode=0 if valid else 1,stdout=(min((left,right),key=rank.get)+'\n').encode() if valid else b'')
                valid=argv[-2] in rank and argv[-1] in rank and rank[argv[-2]]<=rank[argv[-1]]
                return SimpleNamespace(returncode=0 if valid else 1,stdout=b'')
        return super().command(argv,**kwargs)
    def archive(self):return u.operate('archive-settled',self.successor_commit,self.pin,old_commit=getattr(self,'archive_old_commit',COMMIT))
    def refused(self):
        before=self.images()
        with self.assertRaises((RuntimeError,OSError,ValueError)):self.archive()
        self.assertEqual(self.images(),before)
        self.assertTrue((self.mapping['state']/u.NAMESPACE/'transaction').is_dir())
    def overlay_path(self,name):return self.mapping['state']/a.NAMESPACE/'transaction'/name
    def rebind(self,plan):
        raw=w.encode(plan);self.overlay_path('plan.json').write_bytes(raw)
        p=self.overlay_path('journal.json');j=w.decode(p.read_bytes());j['planSha256']=w.digest(raw);p.write_bytes(w.encode(j))
    def second_generation(self):
        self.archive()
        a.operate('archive-applied',self.successor_commit,self.new_overlay_pin,COMMIT)
        old_helper=self.path('ds3/ds3-runtime').read_bytes()
        new_helper=self.path('source/bin/ds3-runtime').read_bytes()+b' next helper generation'
        self.put('source/bin/ds3-runtime',new_helper,0o755)
        self.put('candidate/'+u.CANDIDATE_FILES['ds3.lifecycle'],new_helper,self.definition['desiredFiles']['ds3.lifecycle']['mode'])
        self.definition['sourceFiles']['bin/ds3-runtime']=u.digest(new_helper)
        self.definition['desiredFiles']['ds3.lifecycle']=self.image('candidate/'+u.CANDIDATE_FILES['ds3.lifecycle'])
        self.definition['previousNativePolicySha256']=u.digest(self.native_raw)
        self.put('source/'+u.POLICY,u.encode(self.definition))
        hm=w.decode(self.path('hub/manifest.json').read_bytes());dm=w.decode(self.path('ds3/manifest.json').read_bytes())
        policy=w.decode(self.path('source/manifests/wine-runtime-overlay.json').read_bytes())
        policy.update(previousHubManifestSha256=w.digest(self.path('hub/manifest.json').read_bytes()),previousDS3ManifestSha256=w.digest(self.path('ds3/manifest.json').read_bytes()),previousHubCriticalHashes=hm['criticalHashes'],lifecycleSha256=w.digest(new_helper))
        raw=w.encode(policy);self.put('source/manifests/wine-runtime-overlay.json',raw)
        self.put('source/manifests/games-hub.json',w.encode(dict(hm,runtimeOverlayPolicySha256=w.digest(raw))))
        self.delivery['overlayPolicySha256']=w.digest(raw);self.put('source/manifests/wine-runtime-update.json',w.encode(self.delivery))
        self.pin=u.operate('plan',self.successor_commit)['planSha256']
        u.operate('apply',self.successor_commit,self.pin)
        self.second_history={key:self.path('source/'+key).read_bytes() for key in self.launch_history}
        self.new_overlay_pin=a.operate('plan',self.successor_commit)['planSha256']
        a.operate('apply',self.successor_commit,self.new_overlay_pin)
        self.assertEqual(w.decode(self.overlay_path('ds3.manifest.before').read_bytes())['schema'],4)
        self.assertEqual(w.decode(self.overlay_path('ds3.policy-source.before').read_bytes())['lifecycleSha256'],w.digest(old_helper))
        self.assertNotEqual(old_helper,new_helper)
        self.archive_old_commit=self.successor_commit;self.successor_commit='f'*40;self.head=self.successor_commit
        self.definition['previousFiles']={key:self.image(rel) for key,rel in u.TARGETS.items()}
        self.definition['guards']={rel:self.image(rel) for rel in u.GUARDS}
        self.put('source/'+u.POLICY,u.encode(self.definition))
    def test_schema4_subsequent_changed_helper_generation(self):
        self.second_generation();self.assertTrue(self.archive()['changed'])
    def test_schema4_subsequent_rebound_old_policy_refused(self):
        self.second_generation();self.test_schema4_policy_before_rebound_tamper()
    def test_schema4_same_commit_proven(self):
        self.assertEqual(w.decode(self.path('ds3/manifest.json').read_bytes())['schema'],4)
        self.assertTrue(self.archive()['changed'])
    def test_schema4_policy_after_tamper(self):
        self.overlay_path('ds3.policy-source.after').write_bytes(b'forged');self.refused()
    def test_schema4_source_before_tamper(self):
        self.overlay_path('ds3.source-hub.before').write_bytes(b'forged');self.refused()
    def test_schema4_policy_before_rebound_tamper(self):
        p=self.overlay_path('ds3.policy-source.before');policy=w.decode(p.read_bytes());policy['lifecycleSha256']='0'*64
        p.write_bytes(w.encode(policy));plan=w.decode(self.overlay_path('plan.json').read_bytes())
        plan['targets']['ds3.policy-source']['before']['sha256']=w.digest(p.read_bytes());self.rebind(plan);self.refused()
    def test_schema4_policy_mode_tamper(self):
        self.overlay_path('ds3.policy-source.before').chmod(0o700);self.refused()
    def test_schema4_extra_policy_inventory(self):
        self.put('ds3/policy-source/extra.json',b'{}');self.refused()
    def test_schema4_same_commit_link_tamper(self):
        p=self.overlay_path('ds3.lifecycle.before');p.write_bytes(b'forged launch boundary')
        plan=w.decode(self.overlay_path('plan.json').read_bytes());plan['targets']['ds3.lifecycle']['before']['sha256']=w.digest(p.read_bytes());self.rebind(plan);self.refused()
    def test_schema4_prepared_refused(self):
        p=self.overlay_path('journal.json');j=w.decode(p.read_bytes());j['phase']='prepared';p.write_bytes(w.encode(j));self.refused()
    def test_schema4_old_kind_same_commit_refused(self):
        plan=w.decode(self.overlay_path('plan.json').read_bytes());plan['kind']='wine-winemac-oleacc-runtime-overlay'
        for key in ('ds3.policy-source','ds3.source-hub'):del plan['targets'][key]
        self.rebind(plan);self.refused()

def load_tests(loader,tests,pattern):
    return unittest.TestSuite(Schema4Archive(name) for name in loader.getTestCaseNames(Schema4Archive) if name.startswith('test_schema4_'))
