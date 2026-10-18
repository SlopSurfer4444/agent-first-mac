"""Selected isolated logic tests, not an installed-workstation acceptance gate."""
from pathlib import Path
import os
import sys
import unittest
import importlib

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
    'test_rustdesk_ssh_tunnel',
    'test_custody_namespace',
]
# This single test reads deliberately omitted live hook configuration. Keep it
# visible as SKIPPED; never synthesize an authority-bearing configuration to pass.
context = importlib.import_module('test_project_context_boundary')
method = 'test_successor_definition_has_one_dynamic_context_and_no_policing'
original = getattr(context.ProjectContextTests, method)
setattr(context.ProjectContextTests, method, unittest.skip(
    'Public release intentionally omits operational codex/hooks.json')(original))
# This source-lineage test requires real private predecessor objects, not logic
# fixtures. Public history is intentionally separate; do not fabricate ancestry.
transitions = importlib.import_module('test_config_transition_source')
method = 'test_actual_post_checkpoint_edges_match_the_exact_registration'
original = getattr(transitions.NativeLaunchAdmissionScope, method)
setattr(transitions.NativeLaunchAdmissionScope, method, unittest.skip(
    'Public release intentionally omits private source Git ancestry')(original))
suite = unittest.defaultTestLoader.loadTestsFromNames(names)
result = unittest.TextTestRunner(verbosity=1).run(suite)
raise SystemExit(0 if result.wasSuccessful() else 1)
