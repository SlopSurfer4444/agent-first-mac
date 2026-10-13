import contextlib
import hashlib
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
loader = importlib.machinery.SourceFileLoader("cs2_play", str(ROOT / "bin/cs2-play"))
spec = importlib.util.spec_from_loader(loader.name, loader)
cs2 = importlib.util.module_from_spec(spec)
loader.exec_module(cs2)


class LauncherTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        # macOS /var is a system symlink, which is not part of an admitted home.
        self.home = Path(self.temp.name).resolve()
        self.launcher = cs2.Launcher(self.home)
        self.launcher.runtime.mkdir(parents=True, mode=0o700)
        for name in ("engine/bin", "engine/lib/wine", "Frameworks"):
            (self.launcher.runtime / name).mkdir(parents=True, mode=0o700)
        hashes = {}
        for name in sorted(cs2.MIN_CRITICAL):
            path = self.launcher.runtime / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"fixture-" + name.encode())
            path.chmod(0o700)
            hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        self.manifest = json.dumps({"criticalHashes": hashes,
                                    "expectedRuntimeTreeSha256": "b" * 64}).encode()
        (self.launcher.runtime / ".manifest.json").write_bytes(self.manifest)
        self.receipt = {"schemaVersion": 1, "owner": cs2.OWNER,
                        "runtimeTreeSha256": "b" * 64,
                        "manifestSha256": hashlib.sha256(self.manifest).hexdigest(),
                        "criticalHashes": hashes, "commit": "a" * 40}
        self.write_receipt()
        self.request = Mock()
        self.request.allow_client.return_value={'clientActive':False,'targetActive':False,'steamActive':False}
        self.request.locked.return_value = contextlib.nullcontext(self.request)
        self.patches = [patch.object(cs2, 'admission', return_value=self.request),
                        patch.object(cs2.Launcher, 'no_foreign_steam'),
                        patch.object(cs2.subprocess, 'run', return_value=Mock(returncode=0, stdout=b''))]
        for fixture_patch in self.patches: fixture_patch.start()

    def tearDown(self):
        for fixture_patch in reversed(self.patches): fixture_patch.stop()
        self.temp.cleanup()

    def write_receipt(self):
        (self.launcher.runtime / ".owner.json").write_text(json.dumps(self.receipt))

    def prefix(self, steam=True):
        self.launcher.prefix.mkdir(mode=0o700)
        (self.launcher.prefix / ".cs2-prefix-owner.json").write_text(json.dumps(cs2.PREFIX_OWNER))
        if steam:
            self.launcher.steam.parent.mkdir(parents=True)
            self.launcher.steam.write_bytes(b"fixture-pe")

    def test_runtime_receipt_binds_manifest_and_critical_files(self):
        self.launcher.validate_runtime()
        self.launcher.wine.write_bytes(b"changed")
        with self.assertRaisesRegex(cs2.Blocked, "runtime_changed"):
            self.launcher.validate_runtime()
        self.assertEqual(self.launcher.base.exists(), True)

    def test_manifest_drift_blocks_before_process_dispatch(self):
        (self.launcher.runtime / ".manifest.json").write_bytes(b"different")
        with patch.object(cs2.subprocess, "Popen") as popen:
            with self.assertRaisesRegex(cs2.Blocked, "manifest_changed"):
                self.launcher.execute("play")
        popen.assert_not_called()
        self.assertFalse(self.launcher.logs.exists())

    def test_schema_bool_missing_hashes_and_parent_escape_rejected(self):
        for value in (True, 2, "1"):
            self.receipt["schemaVersion"] = value
            self.write_receipt()
            with self.assertRaises(cs2.Blocked):
                self.launcher.validate_runtime()
        self.receipt["schemaVersion"] = 1
        self.receipt["criticalHashes"]["../outside"] = "0" * 64
        self.write_receipt()
        with self.assertRaisesRegex(cs2.Blocked, "runtime_hash_receipt_changed"):
            self.launcher.validate_runtime()
        del self.receipt["criticalHashes"]["../outside"]
        del self.receipt["criticalHashes"]["engine/bin/wineserver"]
        self.write_receipt()
        with self.assertRaisesRegex(cs2.Blocked, "invalid_runtime_hashes"):
            self.launcher.validate_runtime()

    def test_receipt_cannot_rebind_changed_runtime_without_manifest_update(self):
        self.launcher.wine.write_bytes(b"changed")
        self.receipt["criticalHashes"]["engine/bin/wine"] = hashlib.sha256(b"changed").hexdigest()
        self.write_receipt()
        with self.assertRaisesRegex(cs2.Blocked, "runtime_hash_receipt_changed"):
            self.launcher.validate_runtime()

    def test_runtime_and_prefix_symlinks_rejected(self):
        self.launcher.prefix.symlink_to(self.launcher.runtime, target_is_directory=True)
        with patch.object(cs2.subprocess, "run") as run:
            with self.assertRaisesRegex(cs2.Blocked, "unsafe_directory"):
                self.launcher.execute("stop")
        run.assert_not_called()

    def test_read_only_status_does_not_create_state(self):
        result = self.launcher.execute("status")
        self.assertEqual(result["state"], "setup_required")
        self.assertFalse(self.launcher.prefix.exists())
        self.assertFalse(self.launcher.graphics.exists())
        self.assertFalse(self.launcher.logs.exists())
        self.assertFalse((self.launcher.base / ".launcher.lock").exists())

    def test_environment_is_dedicated_and_does_not_inherit_foreign_loaders(self):
        with patch.dict(os.environ, {"WINEPREFIX": "/other", "DYLD_LIBRARY_PATH": "/other",
                                     "GAMETOMAC_TOKEN": "private", "DXMT_CS2_PIPELINE_CACHE": "/other"}):
            env = self.launcher.environment(True)
        self.assertEqual(env["WINEPREFIX"], str(self.launcher.prefix))
        self.assertEqual(env["MTL_HUD_ENABLED"], "1")
        self.assertEqual(env["WINEDLLOVERRIDES"], cs2.DLL_OVERRIDES)
        self.assertEqual(env["DXMT_CS2_EARLY_COMPILE"], "1")
        self.assertEqual(env["DXMT_CS2_PIPELINE_CACHE"], str(self.launcher.graphics / "game-archives"))
        self.assertNotIn("DYLD_LIBRARY_PATH", env)
        self.assertNotIn("GAMETOMAC_TOKEN", env)

    def test_play_uses_owned_steam_and_no_helper_without_recipes(self):
        self.prefix()
        with patch.object(cs2.subprocess, "Popen") as popen, patch.object(cs2.subprocess, "run", return_value=Mock(returncode=0)) as run:
            result = self.launcher.execute("play")
        self.assertEqual(result["prewarm"], "no_recipes")
        run.assert_not_called()
        args = popen.call_args.args[0]
        self.assertEqual(args, [str(self.launcher.wine), str(self.launcher.steam),
                                "-cef-disable-gpu", "-applaunch", "730"])
        self.assertTrue(popen.call_args.kwargs["start_new_session"])
        self.assertEqual((self.launcher.logs / "launch.log").stat().st_mode & 0o777, 0o600)

    def test_steam_mode_does_not_launch_game_or_prewarm(self):
        self.prefix()
        with patch.object(cs2.subprocess, "Popen") as popen:
            result = self.launcher.execute("steam")
        self.assertEqual(result["mode"], "steam")
        self.assertNotIn("-applaunch", popen.call_args.args[0])
        self.assertEqual(result["prewarm"], "not_requested")

    def test_unknown_active_session_blocks_before_recipe_or_steam_dispatch(self):
        self.prefix()
        self.request.allow_client.side_effect=cs2.Blocked('profile_active')
        with patch.object(cs2.subprocess, "Popen") as popen:
            with self.assertRaisesRegex(cs2.Blocked, "profile_active"):
                self.launcher.execute("play")
        popen.assert_not_called();self.request.begin.assert_not_called()

    def test_exact_owned_steam_can_receive_applaunch_when_game_absent(self):
        self.prefix();self.request.allow_client.return_value={'clientActive':True,'steamActive':True,'targetActive':False}
        with patch.object(cs2.subprocess,'Popen') as popen:
            result=self.launcher.execute('play')
        self.assertEqual(result['state'],'launch_dispatched');self.assertEqual(popen.call_args.args[0][-2:],['-applaunch','730'])

    def test_exact_target_running_skips_recipe_and_client_dispatch(self):
        self.prefix();self.request.allow_client.return_value={'clientActive':True,'steamActive':True,'targetActive':True}
        with patch.object(cs2.subprocess,'Popen') as popen:
            result=self.launcher.execute('play')
        self.assertEqual(result['state'],'already_running');popen.assert_not_called();self.request.begin.assert_not_called()

    def test_prewarm_invocation_and_nonfatal_failure(self):
        self.prefix()
        self.launcher.writable_state()
        (self.launcher.graphics / "recipes/test.recipe").write_bytes(b"recipe")
        child = Mock(pid=234)
        child.wait.return_value = 1
        with patch.object(cs2.subprocess, "run", return_value=Mock(returncode=0)):
            with patch.object(cs2.subprocess, "Popen", return_value=child) as popen:
                result = self.launcher.execute("play")
        self.assertEqual(result["prewarm"], "failed")
        self.assertEqual(popen.call_count, 2)
        self.assertEqual(popen.call_args_list[0].args[0],
                         [str(self.launcher.wine), str(self.launcher.helper),
                          str(self.launcher.graphics / "recipes"),
                          str(self.launcher.graphics / "shader-cache")])
        child.wait.assert_called_once_with(timeout=45)

    def test_prewarm_timeout_signals_only_its_process_group_then_dispatches(self):
        self.prefix()
        self.launcher.writable_state()
        (self.launcher.graphics / "recipes/test.recipe").write_bytes(b"recipe")
        child = Mock(pid=234)
        child.wait.side_effect = [subprocess.TimeoutExpired("helper", 45), 0]
        with patch.object(cs2.subprocess, "run", return_value=Mock(returncode=0)):
            with patch.object(cs2.subprocess, "Popen", return_value=child) as popen:
                with patch.object(cs2.os, "killpg") as kill:
                    result = self.launcher.execute("play")
        self.assertEqual(result["prewarm"], "timed_out")
        kill.assert_called_once_with(234, cs2.signal.SIGTERM)
        self.assertEqual(popen.call_count, 2)

    def test_setup_fresh_prefix_uses_only_owned_installer(self):
        with patch.object(cs2.subprocess, "Popen", return_value=Mock(wait=Mock(return_value=0))) as popen:
            result = self.launcher.execute("setup")
        self.assertEqual(result["login"], "owner_action_required")
        self.assertEqual(json.loads((self.launcher.prefix / ".cs2-prefix-owner.json").read_text()),
                         cs2.PREFIX_OWNER)
        self.assertEqual([c.args[0] for c in popen.call_args_list],
                         [[str(self.launcher.wine), "wineboot", "--init"],
                          [str(self.launcher.wine), str(self.launcher.runtime / "SteamSetup.exe"), "/S"]])

    def test_setup_existing_steam_is_idempotent(self):
        self.prefix()
        with patch.object(cs2.subprocess, "run", return_value=Mock(returncode=0)) as run:
            with patch.object(cs2.subprocess, "Popen") as popen:
                result = self.launcher.execute("setup")
        self.assertEqual(result["state"], "already_setup")
        popen.assert_not_called()
        self.assertEqual(run.call_args.args[0], [str(self.launcher.server), "-w"])

    def test_setup_timeout_cleans_only_owned_group(self):
        child = Mock(pid=789)
        child.wait.side_effect = [subprocess.TimeoutExpired("setup", 180), 0]
        with patch.object(cs2.subprocess, "Popen", return_value=child) as popen:
            with patch.object(cs2.os, "killpg") as kill:
                with self.assertRaisesRegex(cs2.Blocked, "setup_timed_out"):
                    self.launcher.execute("setup")
        kill.assert_called_once_with(789, cs2.signal.SIGTERM)
        self.assertEqual(popen.call_count, 1)
        self.assertTrue(popen.call_args.kwargs["start_new_session"])

    def test_unknown_existing_prefix_is_never_adopted_by_setup(self):
        self.launcher.prefix.mkdir()
        (self.launcher.prefix / "unrelated").write_bytes(b"preserve")
        with patch.object(cs2.subprocess, "run") as run:
            with self.assertRaises(OSError):
                self.launcher.execute("setup")
        run.assert_not_called()
        self.assertEqual((self.launcher.prefix / "unrelated").read_bytes(), b"preserve")

    def test_stop_is_wineserver_scoped_to_owned_prefix(self):
        self.prefix()
        with patch.object(cs2.subprocess, "run", return_value=Mock(returncode=0)) as run:
            self.launcher.execute("stop")
        self.assertEqual([c.args[0] for c in run.call_args_list],
                         [[str(self.launcher.server), "-k"], [str(self.launcher.server), "-w"]])
        self.assertTrue(all(c.kwargs["env"]["WINEPREFIX"] == str(self.launcher.prefix)
                            for c in run.call_args_list))

    def test_steam_group_writable_directories_below_private_prefix_are_allowed(self):
        self.prefix()
        for path in (self.launcher.prefix / "drive_c", self.launcher.steam.parent.parent,
                     self.launcher.steam.parent):
            path.chmod(0o775)
        with patch.object(cs2.subprocess, "Popen") as popen:
            self.launcher.execute("steam")
        popen.assert_called_once()
        with patch.object(cs2.subprocess, "run", return_value=Mock(returncode=0)):
            with patch.object(cs2.subprocess, "Popen") as popen:
                self.assertEqual(self.launcher.execute("setup")["state"], "already_setup")
        popen.assert_not_called()

    def test_steam_data_directory_world_write_is_rejected(self):
        self.prefix()
        self.launcher.steam.parent.chmod(0o777)
        with patch.object(cs2.subprocess, "Popen") as popen:
            with self.assertRaisesRegex(cs2.Blocked, "unsafe_steam_directory"):
                self.launcher.execute("steam")
        popen.assert_not_called()

    def test_steam_external_symlink_is_rejected(self):
        self.prefix()
        self.launcher.steam.unlink()
        self.launcher.steam.parent.rmdir()
        external = self.home / "external"
        external.mkdir()
        (external / "steam.exe").write_bytes(b"external")
        self.launcher.steam.parent.symlink_to(external, target_is_directory=True)
        with patch.object(cs2.subprocess, "Popen") as popen:
            with self.assertRaises(OSError):
                self.launcher.execute("steam")
        popen.assert_not_called()

    def test_group_writable_data_requires_private_prefix(self):
        self.prefix()
        self.launcher.prefix.chmod(0o755)
        self.launcher.steam.parent.chmod(0o775)
        with self.assertRaisesRegex(cs2.Blocked, "prefix_not_private"):
            self.launcher.validate_steam_directory()

    def test_runtime_group_write_remains_rejected(self):
        (self.launcher.runtime / "engine/bin").chmod(0o775)
        with self.assertRaisesRegex(cs2.Blocked, "unsafe_directory"):
            self.launcher.validate_runtime()

    def test_read_regular_allows_only_access_time_change(self):
        path = self.home / "read-fixture"
        path.write_bytes(b"content")
        before = path.stat()
        fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size",
                  "st_mtime_ns", "st_ctime_ns", "st_atime_ns")
        facts = {key: getattr(before, key) for key in fields}
        changed_access = dict(facts, st_atime_ns=facts["st_atime_ns"] + 1000000000)
        with patch.object(cs2.os, "fstat", side_effect=[types.SimpleNamespace(**facts),
                                                      types.SimpleNamespace(**changed_access)]):
            self.assertEqual(cs2.read_regular(path, os.getuid()), b"content")
        for changed in (dict(changed_access, st_size=facts["st_size"] + 1),
                        dict(changed_access, st_mtime_ns=facts["st_mtime_ns"] + 1),
                        dict(changed_access, st_ctime_ns=facts["st_ctime_ns"] + 1),
                        dict(changed_access, st_ino=facts["st_ino"] + 1)):
            with patch.object(cs2.os, "fstat", side_effect=[types.SimpleNamespace(**facts),
                                                          types.SimpleNamespace(**changed)]):
                with self.assertRaisesRegex(cs2.Blocked, "file_changed"):
                    cs2.read_regular(path, os.getuid())

    def test_hardlinked_private_log_not_truncated(self):
        self.launcher.writable_state()
        source = self.home / "preserve"
        source.write_bytes(b"untouched")
        source.chmod(0o600)
        os.link(source, self.launcher.logs / "prewarm.log")
        with self.assertRaisesRegex(cs2.Blocked, "unsafe_private_file"):
            self.launcher.private_file(self.launcher.logs / "prewarm.log", truncate=True)
        self.assertEqual(source.read_bytes(), b"untouched")


if __name__ == "__main__":
    unittest.main()
