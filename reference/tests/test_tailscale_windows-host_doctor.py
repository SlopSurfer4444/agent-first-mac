#!/usr/bin/python3
"""Pure fixtures for the M1 boolean-only Tailscale doctor."""

import importlib.util
from importlib.machinery import SourceFileLoader
from pathlib import Path
import unittest


DOCTOR = Path(__file__).resolve().parents[1] / "bin/tailscale-windows-host-doctor"
LOADER = SourceFileLoader("tailscale_doctor", str(DOCTOR))
SPEC = importlib.util.spec_from_loader(LOADER.name, LOADER)
MODULE = importlib.util.module_from_spec(SPEC)
LOADER.exec_module(MODULE)


class AdvertiseRoutesFixtures(unittest.TestCase):
    def test_null_and_empty_list_pass(self):
        self.assertTrue(MODULE.no_advertised_routes({"AdvertiseRoutes": None}))
        self.assertTrue(MODULE.no_advertised_routes({"AdvertiseRoutes": []}))

    def test_nonempty_list_fails(self):
        self.assertFalse(MODULE.no_advertised_routes({"AdvertiseRoutes": ["route"]}))

    def test_missing_or_other_type_fails(self):
        for prefs in ({}, {"AdvertiseRoutes": ""}, {"AdvertiseRoutes": False},
                      {"AdvertiseRoutes": {}}, {"AdvertiseRoutes": 0}, None):
            self.assertFalse(MODULE.no_advertised_routes(prefs))


if __name__ == "__main__":
    unittest.main()
