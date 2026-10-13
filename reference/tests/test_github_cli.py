"""Package-intent regression; no network, Nix, authentication or installation."""
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class GitHubCliIntentTests(unittest.TestCase):
    def test_single_locked_home_manager_owner(self):
        manifest = json.loads((ROOT / "manifests/github-cli.json").read_text())
        self.assertEqual(manifest["primaryOwner"], "home-manager-via-nix-darwin")
        self.assertEqual(manifest["packageAttribute"], "pkgs.gh")
        flake = (ROOT / "flake.nix").read_text()
        self.assertEqual(flake.count("./darwin/github-cli.nix"), 1)
        module = (ROOT / "darwin/github-cli.nix").read_text()
        self.assertIn("home.packages = [ pkgs.gh ];", module)
        self.assertEqual(module.count("pkgs.gh"), 1)
        self.assertNotIn("activation", module)
        self.assertIn("packages = [ ];", (ROOT / "darwin/home-manager.nix").read_text())

    def test_auth_is_owner_consent_not_declarative_payload(self):
        boundary = json.loads((ROOT / "manifests/github-cli.json").read_text())["dataBoundary"]
        self.assertTrue(boundary["ownerConsentRequired"])
        self.assertFalse(any(value for key, value in boundary.items() if key != "ownerConsentRequired"))
        module = (ROOT / "darwin/github-cli.nix").read_text()
        self.assertNotIn("builtins.readFile", module)
        self.assertNotIn("programs.git", module)
        self.assertNotIn("programs.gh", module)


if __name__ == "__main__":
    unittest.main()
