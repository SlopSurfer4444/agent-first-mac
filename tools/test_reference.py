"""Selected isolated logic tests, not an installed-workstation acceptance gate."""
from pathlib import Path
import os
import sys
import unittest

sys.dont_write_bytecode = True
root = Path(__file__).resolve().parents[1] / 'reference'
sys.path.insert(0, str(root))
sys.path.insert(0, str(root / 'tests'))
os.chdir(root)
names = [
    'test_config_transitions',
    'test_config_transition_source',
    'test_config_transition_repository',
    'test_current_source_admission',
    'test_project_context_boundary',
    'test_vendor_compatibility_policy',
]
suite = unittest.defaultTestLoader.loadTestsFromNames(names)
result = unittest.TextTestRunner(verbosity=1).run(suite)
raise SystemExit(0 if result.wasSuccessful() else 1)
