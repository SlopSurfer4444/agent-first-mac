"""Current helper delta preserves the accepted native generation and history."""
import hashlib
import importlib.machinery
import json
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
PREDECESSOR = 'ec05bc98cc61ab0e6e2cde960a08fc55607ce6ca'


class HarnessSuccessor(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = importlib.machinery.SourceFileLoader(
            'harness_successor_renderer', str(ROOT / 'bin/ds3-runtime')).load_module()
        cls.policy = json.loads((ROOT / 'manifests/ds3-renderer-update.json').read_bytes())
        cls.old = json.loads(subprocess.check_output(
            ['git', 'show', PREDECESSOR + ':manifests/ds3-renderer-update.json'], cwd=ROOT))

    def test_delta_schema_consumes_only_current_helpers(self):
        p = self.policy
        self.engine.renderer_policy_validate(p)
        self.assertEqual(p['schema'], 10)
        self.assertEqual(set(p['candidateFiles']),
                         {'ds3-runtime', *self.engine.RENDERER_LAUNCH_FILES.values()})
        for name in ('ds3-runtime', *self.engine.RENDERER_LAUNCH_FILES.values()):
            self.assertEqual(p['candidateFiles'][name],
                             hashlib.sha256((ROOT / 'bin' / name).read_bytes()).hexdigest())

    def test_no_native_payload_change_or_historical_rebinding(self):
        p, old = self.policy, self.old
        self.assertEqual(p['nativeAdmissionBase'], old['nativeAdmissionBase'])
        binding = p['rendererBinding']
        self.assertEqual(binding['d3d11Sha256'], old['candidateFiles']['d3d11.dll'])
        self.assertEqual(binding['dxgiSha256'], old['candidateFiles']['dxgi.dll'])
        for _, (relative, name) in self.engine.RENDERER_NATIVE.items():
            self.assertEqual(binding['nativeRuntimeHashes'][relative], old['candidateFiles'][name])
        for key, name in self.engine.RENDERER_LAUNCH_FILES.items():
            self.assertEqual(p['launchAdmission'][key], old['candidateFiles'][name])
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
