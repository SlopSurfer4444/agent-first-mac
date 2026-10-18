"""Current helper delivery is a launch-only successor, not rewritten history."""
import hashlib
import importlib.machinery
import json
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
PREDECESSOR = '831dbaa0c4f316b697adfd672428b887783b985f'


class HarnessSuccessor(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = importlib.machinery.SourceFileLoader(
            'harness_successor_renderer', str(ROOT / 'bin/ds3-runtime')).load_module()
        cls.policy = json.loads((ROOT / 'manifests/ds3-renderer-update.json').read_bytes())
        cls.old = json.loads(subprocess.check_output(
            ['git', 'show', PREDECESSOR + ':manifests/ds3-renderer-update.json'], cwd=ROOT))

    def test_existing_schema_eight_consumes_current_helpers(self):
        p = self.policy
        self.engine.renderer_policy_validate(p)
        self.assertEqual(p['schema'], 8)
        for name in ('ds3-runtime', *self.engine.RENDERER_LAUNCH_FILES.values()):
            self.assertEqual(p['candidateFiles'][name],
                             hashlib.sha256((ROOT / 'bin' / name).read_bytes()).hexdigest())

    def test_no_native_payload_change_or_historical_rebinding(self):
        p, old = self.policy, self.old
        self.assertEqual(p['nativeAdmissionBase'], old['nativeAdmissionBase'])
        self.assertEqual(p['nativeIdentityHashes'], old['nativeIdentityHashes'])
        for name in ('d3d11.dll', 'dxgi.dll', 'ntdll.so', 'winemac.so',
                     'winemetal.so', 'source.tar.gz'):
            self.assertEqual(p['candidateFiles'][name], old['candidateFiles'][name])
        self.assertEqual(p['previousEffectiveLifecycleSha256'], old['candidateFiles']['ds3-runtime'])
        self.assertNotEqual(p['previousManifestSha256'], old['previousManifestSha256'])

    def test_older_delivery_intents_remain_byte_exact(self):
        for name in ('game-launch-reliability', 'game-native-launch-admission',
                     'wine-runtime-overlay', 'wine-runtime-update'):
            path = 'manifests/' + name + '.json'
            old = subprocess.check_output(['git', 'show', PREDECESSOR + ':' + path], cwd=ROOT)
            self.assertEqual((ROOT / path).read_bytes(), old, path)


if __name__ == '__main__':
    unittest.main()
