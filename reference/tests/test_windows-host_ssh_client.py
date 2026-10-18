import base64
import hashlib
import importlib.machinery
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
loader = importlib.machinery.SourceFileLoader(
    "windows-host_ssh_client", str(ROOT / "bin/windows-host-ssh-client")
)
module = loader.load_module()


def effective_fixture(paths, *, proxy=False, user="fixture"):
    rows = ["stricthostkeychecking true", "passwordauthentication no",
            "kbdinteractiveauthentication no", "identitiesonly yes", "forwardagent no",
            "preferredauthentications publickey", "pubkeyauthentication yes",
            "permitlocalcommand no", "forwardx11 no", "hostname 100.64.0.1", "user " + user,
            "identityfile " + str(paths["private"]), "userknownhostsfile " + str(paths["known"])]
    if proxy:
        rows += ["proxycommand " + module.PROXY, "hostkeyalgorithms ssh-ed25519",
                 "globalknownhostsfile /dev/null", "batchmode yes"]
    return "\n".join(rows)


class WindowsHostSSHClientTests(unittest.TestCase):
    def test_atomic_publication_preserves_racing_owner_file_and_symlink(self):
        for symlink in (False, True):
            with self.subTest(symlink=symlink), tempfile.TemporaryDirectory() as directory:
                target = Path(directory) / "config"
                owner = Path(directory) / "owner"
                owner.write_bytes(b"owner bytes")
                real_link = os.link

                def race(source, destination, **kwargs):
                    if symlink:
                        target.symlink_to(owner)
                    else:
                        target.write_bytes(b"owner bytes")
                    return real_link(source, destination, **kwargs)

                with patch.object(module.os, "link", side_effect=race):
                    with self.assertRaisesRegex(module.ProfileError, "managed_target_collision"):
                        module.atomic_write(target, b"managed bytes", 0o600)
                self.assertEqual(target.read_bytes(), b"owner bytes")
                self.assertEqual(target.is_symlink(), symlink)
                self.assertEqual(list(Path(directory).glob(".windows-host.*")), [])

    def test_failed_enrollment_preserves_owner_replacement_and_shared_include(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            paths = module.layout(home)
            paths["ssh"].mkdir(mode=0o700)
            original_write = module.atomic_write
            owner_config = paths["config_dir"] / "owner.conf"

            def fail_later(path, data, mode):
                if path == paths["known"]:
                    paths["alias"].unlink()
                    paths["alias"].write_bytes(b"owner replacement")
                    owner_config.write_bytes(b"Host owner\n")
                    raise module.ProfileError("injected_failure")
                return original_write(path, data, mode)

            body = base64.b64encode(b"fixture").decode()
            with patch.object(module, "canonical_home", return_value=home), \
                 patch.object(module, "prepare", return_value=("100.64.0.1", "ssh-ed25519", body, "fixture")), \
                 patch.object(module, "atomic_write", side_effect=fail_later):
                with self.assertRaisesRegex(module.ProfileError, "injected_failure"):
                    module.apply_profile("fixture", "fixture")
            self.assertEqual(paths["alias"].read_bytes(), b"owner replacement")
            self.assertEqual(owner_config.read_bytes(), b"Host owner\n")
            self.assertEqual(paths["main"].read_bytes(), module.enrollment_main(None))

    def test_rollback_keeps_shared_include_and_other_profiles(self):
        for edited in (False, True):
            with self.subTest(edited=edited), tempfile.TemporaryDirectory() as directory:
                home, paths = self.fixture(directory)
                owner = paths["config_dir"] / "owner.conf"
                owner.write_bytes(b"Host owner\n  HostName localhost\n")
                main = module.render_main_config() + (b"# owner setting\n" if edited else b"")
                paths["main"].write_bytes(main)
                with patch.object(module, "canonical_home", return_value=home):
                    module.rollback()
                self.assertEqual(paths["main"].read_bytes(), main)
                self.assertTrue(owner.is_file())
                self.assertFalse(paths["alias"].exists())
                self.assertFalse(paths["known"].exists())
                self.assertEqual(json.loads(paths["receipt"].read_text())["status"], "rolled_back")

    def test_failed_enrollment_never_unlinks_published_files(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            paths = module.layout(home)
            paths["ssh"].mkdir(mode=0o700)
            original_write, original_unlink = module.atomic_write, Path.unlink

            def fail_later(path, data, mode):
                if path == paths["known"]:
                    raise module.ProfileError("injected_failure")
                return original_write(path, data, mode)

            def no_cleanup(path, *args, **kwargs):
                if path in (paths["main"], paths["alias"]):
                    path.write_bytes(b"owner edit at cleanup boundary")
                    raise AssertionError("published file cleanup attempted")
                return original_unlink(path, *args, **kwargs)

            body = base64.b64encode(b"fixture").decode()
            with patch.object(module, "canonical_home", return_value=home), \
                 patch.object(module, "prepare", return_value=("100.64.0.1", "ssh-ed25519", body, "fixture")), \
                 patch.object(module, "atomic_write", side_effect=fail_later), \
                 patch.object(Path, "unlink", no_cleanup):
                with self.assertRaisesRegex(module.ProfileError, "injected_failure"):
                    module.apply_profile("fixture", "fixture")
            self.assertEqual(paths["main"].read_bytes(), module.enrollment_main(None))
            self.assertTrue(paths["alias"].is_file())

    def test_rollback_race_before_capture_restores_actual_owner_entry(self):
        for symlink in (False, True):
            with self.subTest(symlink=symlink), tempfile.TemporaryDirectory() as directory:
                home, paths = self.fixture(directory)
                owner = home / "owner-file"
                owner.write_bytes(b"owner content")
                rename = module.rename_exclusive
                raced = False

                def race(source, destination):
                    nonlocal raced
                    if source == paths["known"] and not raced:
                        raced = True
                        source.unlink()
                        if symlink:
                            source.symlink_to(owner)
                        else:
                            source.write_bytes(b"owner content")
                            source.chmod(0o600)
                    return rename(source, destination)

                with patch.object(module, "canonical_home", return_value=home), \
                     patch.object(module, "rename_exclusive", side_effect=race):
                    with self.assertRaisesRegex(module.ProfileError, "rollback_interrupted_recovery_retained"):
                        module.rollback()
                self.assertEqual(paths["known"].read_bytes(), b"owner content")
                self.assertEqual(paths["known"].is_symlink(), symlink)
                self.assertTrue(paths["alias"].exists())
                self.assertEqual(json.loads(paths["receipt"].read_text())["status"], "applied")

    def test_rollback_race_after_capture_retains_both_versions(self):
        with tempfile.TemporaryDirectory() as directory:
            home, paths = self.fixture(directory)
            old = paths["known"].read_bytes()
            rename = module.rename_exclusive

            def race(source, destination):
                result = rename(source, destination)
                if source == paths["known"]:
                    paths["known"].write_bytes(b"new owner content")
                return result

            with patch.object(module, "canonical_home", return_value=home), \
                 patch.object(module, "rename_exclusive", side_effect=race):
                with self.assertRaisesRegex(module.ProfileError, "rollback_interrupted_recovery_retained"):
                    module.rollback()
            self.assertEqual(paths["known"].read_bytes(), b"new owner content")
            recovered = list(paths["state"].glob("rollback-*/known"))
            self.assertEqual(len(recovered), 1)
            self.assertEqual(recovered[0].read_bytes(), old)
            self.assertTrue(paths["alias"].exists())
            self.assertEqual(json.loads(paths["receipt"].read_text())["status"], "applied")

    def test_rollback_receipt_publication_failure_preserves_owner_and_recovery(self):
        for collision in (False, True):
            with self.subTest(collision=collision), tempfile.TemporaryDirectory() as directory:
                home, paths = self.fixture(directory)
                old = {name: paths[name].read_bytes() for name in ("known", "alias", "receipt")}

                def fail_write(path, data, mode):
                    self.assertEqual(path, paths["receipt"])
                    if collision:
                        path.write_bytes(b"owner receipt replacement")
                    raise module.ProfileError("injected_receipt_failure")

                with patch.object(module, "canonical_home", return_value=home), \
                     patch.object(module, "atomic_write", side_effect=fail_write):
                    with self.assertRaisesRegex(module.ProfileError, "rollback_interrupted_recovery_retained"):
                        module.rollback()
                for name in ("known", "alias"):
                    self.assertEqual(paths[name].read_bytes(), old[name])
                if collision:
                    self.assertEqual(paths["receipt"].read_bytes(), b"owner receipt replacement")
                    recovered = list(paths["state"].glob("rollback-*/receipt"))
                    self.assertEqual(len(recovered), 1)
                    self.assertEqual(recovered[0].read_bytes(), old["receipt"])
                else:
                    self.assertEqual(paths["receipt"].read_bytes(), old["receipt"])

    def test_public_blob_fingerprint(self):
        blob = b"synthetic-ed25519-host-key-fixture"
        body = base64.b64encode(blob).decode("ascii")
        expected = "SHA256:" + base64.b64encode(
            hashlib.sha256(blob).digest()
        ).decode("ascii").rstrip("=")
        self.assertEqual(module.public_blob_fingerprint(body), expected)

    def test_known_host_is_hashed(self):
        body = base64.b64encode(b"fixture").decode("ascii")
        rendered = module.hashed_known_host("100.64.0.1", "ssh-ed25519", body)
        self.assertTrue(rendered.startswith(b"|1|"))
        self.assertNotIn(b"100.64.0.1", rendered)
        self.assertIn(b" ssh-ed25519 ", rendered)

    def test_alias_is_strict(self):
        rendered = module.render_alias_config("100.64.0.1", "fixture-user").decode()
        self.assertIn("StrictHostKeyChecking yes", rendered)
        self.assertIn("PasswordAuthentication no", rendered)
        self.assertIn("KbdInteractiveAuthentication no", rendered)
        self.assertIn("IdentitiesOnly yes", rendered)
        self.assertIn("ForwardAgent no", rendered)
        self.assertNotIn("StrictHostKeyChecking no", rendered)

    def test_apply_has_exact_noop_path(self):
        source = (ROOT / "bin/windows-host-ssh-client").read_text()
        self.assertIn("already_applied_runtime_identity_mismatch", source)
        self.assertIn("apply_noop=", source)

    def test_doctor_uses_the_canonical_posix_remote_shell(self):
        source = (ROOT / "bin/windows-host-ssh-client").read_text()
        self.assertIn('"printf BRIDGE_STRICT_OK"', source)
        self.assertNotIn("cmd.exe /d /c echo BRIDGE_STRICT_OK", source)

    def fixture(self, directory):
        home = Path(directory)
        paths = module.layout(home)
        paths["ssh"].mkdir(mode=0o700)
        paths["config_dir"].mkdir(mode=0o700)
        paths["state"].mkdir(parents=True, mode=0o700)
        for key, mode in (("private", 0o600), ("public", 0o644)):
            paths[key].write_bytes(b"opaque never-read fixture")
            paths[key].chmod(mode)
        body = base64.b64encode(b"synthetic fixture").decode()
        images = {"main": module.render_main_config(),
                  "alias": module.render_alias_config("100.64.0.1", "fixture"),
                  "known": module.hashed_known_host("100.64.0.1", "ssh-ed25519", body)}
        for key, data in images.items():
            paths[key].write_bytes(data)
            paths[key].chmod(0o600)
        receipt = {"schema": 1, "status": "applied", "host": "100.64.0.1", "user": "fixture",
            "hostFingerprint": module.public_blob_fingerprint(body),
            "managed": {alias: module.sha256_bytes(images[name]) for name, alias in
                        (("main", "config"), ("alias", "alias"), ("known", "knownHosts"))}}
        paths["receipt"].write_text(json.dumps(receipt))
        paths["receipt"].chmod(0o600)
        return home, paths

    def test_routine_doctor_authenticates_pin_without_keyscan_or_full_doctor(self):
        with tempfile.TemporaryDirectory(prefix="ssh-client-fixture-") as directory:
            home, paths = self.fixture(directory)
            effective = effective_fixture(paths)
            with patch.object(module, "canonical_home", return_value=home), \
                 patch.object(module, "resolve_windows_peer", return_value="100.64.0.1"), \
                 patch.object(module, "scan_ed25519_host_key", side_effect=AssertionError("routine keyscan")), \
                 patch.object(module.subprocess, "run", side_effect=[SimpleNamespace(stdout=effective),
                    SimpleNamespace(stdout="BRIDGE_STRICT_OK")]) as run:
                module.doctor()
            self.assertEqual(run.call_count, 2)
            smoke = run.call_args.args[0]
            for option in ("BatchMode=yes", "StrictHostKeyChecking=yes", "HostKeyAlgorithms=ssh-ed25519",
                           "GlobalKnownHostsFile=/dev/null", "PreferredAuthentications=publickey",
                           "PasswordAuthentication=no", "KbdInteractiveAuthentication=no", "ForwardAgent=no"):
                self.assertIn(option, smoke)
            self.assertIn(f"UserKnownHostsFile={paths['known']}", smoke)

    def test_changed_host_key_fails_strict_smoke_without_fallback(self):
        with tempfile.TemporaryDirectory(prefix="ssh-client-fixture-") as directory:
            home, paths = self.fixture(directory)
            effective = effective_fixture(paths)
            with patch.object(module, "canonical_home", return_value=home), \
                 patch.object(module, "resolve_windows_peer", return_value="100.64.0.1"), \
                 patch.object(module, "scan_ed25519_host_key", side_effect=AssertionError("routine keyscan")), \
                 patch.object(module.subprocess, "run", side_effect=[SimpleNamespace(stdout=effective),
                    subprocess.CalledProcessError(255, "ssh")]) as run:
                with self.assertRaises(subprocess.CalledProcessError):
                    module.doctor()
                self.assertEqual(run.call_count, 2)

    def test_enrollment_retains_independent_keyscan_fingerprint_check(self):
        with tempfile.TemporaryDirectory(prefix="ssh-enrollment-fixture-") as directory:
            home = Path(directory)
            paths = module.layout(home)
            paths["ssh"].mkdir(mode=0o700)
            for key, mode in (("private", 0o600), ("public", 0o644)):
                paths[key].write_bytes(b"opaque never-read fixture")
                paths[key].chmod(mode)
            body = base64.b64encode(b"fixture").decode()
            with patch.object(module, "canonical_home", return_value=home), \
                 patch.object(module, "resolve_windows_peer", return_value="100.64.0.1"), \
                 patch.object(module, "scan_ed25519_host_key", return_value=("100.64.0.1", "ssh-ed25519", body)) as scan:
                with self.assertRaisesRegex(module.ProfileError, "independent_host_fingerprint_mismatch"):
                    module.prepare("SHA256:" + "A" * 43, "fixture")
                scan.assert_called_once()



class EnrollmentRecoveryTests(unittest.TestCase):
    def local_only(self, paths, command, **kwargs):
        self.assertEqual(command, ["/usr/bin/ssh", "-G", "-o", "CanonicalizeHostname=no", module.ALIAS])
        return SimpleNamespace(stdout=effective_fixture(paths))

    def fixture(self, directory, main=None):
        home = Path(directory)
        paths = module.layout(home)
        paths["ssh"].mkdir(mode=0o700)
        paths["config_dir"].mkdir(mode=0o700)
        (paths["config_dir"] / "owner.conf").write_bytes(b"Host owner\n  HostName localhost\n")
        for name, mode in (("private", 0o600), ("public", 0o644)):
            paths[name].write_bytes(b"must never be read")
            paths[name].chmod(mode)
        if main is not None:
            paths["main"].write_bytes(main)
            paths["main"].chmod(0o600)
        body = base64.b64encode(b"synthetic enrollment pin").decode()
        fingerprint = module.public_blob_fingerprint(body)
        for name, value in (("canonical_home", home), ("resolve_windows_peer", "100.64.0.1"),
                            ("scan_ed25519_host_key", ("100.64.0.1", "ssh-ed25519", body))):
            patcher = patch.object(module, name, return_value=value)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = patch.object(module.subprocess, "run", side_effect=lambda command, **kwargs:
                              self.local_only(paths, command, **kwargs))
        patcher.start(); self.addCleanup(patcher.stop)
        return paths, fingerprint

    def test_prepare_and_apply_coexist_with_config_and_fragments(self):
        for main in (None, b"# owned\nHost owner\n  User owner\n", module.render_main_config(),
                     b"Host owner\n  Include config.d/*.conf\n"):
            with self.subTest(main=main), tempfile.TemporaryDirectory() as directory:
                paths, fingerprint = self.fixture(directory, main)
                owner = (paths["config_dir"] / "owner.conf").read_bytes()
                with patch.object(module, "doctor", side_effect=AssertionError("remote health")), \
                     patch.object(module.subprocess, "run", side_effect=lambda command, **kwargs: self.local_only(paths, command, **kwargs)):
                    module.prepare(fingerprint, "fixture")
                    self.assertTrue(module.apply_profile(fingerprint, "fixture"))
                    expected = module.enrollment_main(main)
                    self.assertEqual(paths["main"].read_bytes(), expected)
                    paths["main"].write_bytes(expected + b"\n# new owner edit\n")
                    self.assertFalse(module.apply_profile(fingerprint, "fixture"))
                    module.rollback()
                self.assertEqual((paths["config_dir"] / "owner.conf").read_bytes(), owner)
                self.assertEqual(paths["main"].read_bytes(), expected + b"\n# new owner edit\n")

    def test_every_publication_interruption_can_retry_or_rollback(self):
        for main in (None, b"Host owner\n  User owner\n"):
            for stage in ("enrollment", "main", "alias", "known", "receipt"):
                for after in (False, True):
                    for recover in ("retry", "rollback"):
                        with self.subTest(main=main, stage=stage, after=after, recover=recover), \
                             tempfile.TemporaryDirectory() as directory:
                            paths, fingerprint = self.fixture(directory, main)
                            atomic = module.atomic_write

                            def interrupt(path, data, mode):
                                if path == paths[stage]:
                                    if after:
                                        atomic(path, data, mode)
                                    raise module.ProfileError("injected_interruption")
                                atomic(path, data, mode)

                            with patch.object(module, "atomic_write", side_effect=interrupt):
                                with self.assertRaisesRegex(module.ProfileError, "injected_interruption"):
                                    module.apply_profile(fingerprint, "fixture")
                            with patch.object(module, "doctor", side_effect=AssertionError("remote health")), \
                                 patch.object(module.subprocess, "run", side_effect=lambda command, **kwargs: self.local_only(paths, command, **kwargs)):
                                if recover == "retry":
                                    module.apply_profile(fingerprint, "fixture")
                                    self.assertFalse(module.apply_profile(fingerprint, "fixture"))
                                    module.validate_local_profile(paths, module.load_receipt(paths))
                                elif paths["enrollment"].exists():
                                    module.rollback()
                                    self.assertFalse(paths["alias"].exists())
                                    self.assertFalse(paths["known"].exists())
                                    self.assertEqual(json.loads(paths["receipt"].read_bytes())["status"], "rolled_back")
                                else:
                                    self.assertFalse(paths["alias"].exists())
                                    self.assertFalse(paths["known"].exists())
                            self.assertEqual((paths["config_dir"] / "owner.conf").read_bytes(),
                                             b"Host owner\n  HostName localhost\n")
                            if main is not None:
                                self.assertIsNotNone(module.read_main(paths))

    def test_partial_foreign_payload_is_preserved_by_retry_and_rollback(self):
        for name in ("alias", "known"):
            for symlink in (False, True):
                with self.subTest(name=name, symlink=symlink), tempfile.TemporaryDirectory() as directory:
                    paths, fingerprint = self.fixture(directory)
                    atomic = module.atomic_write

                    def interrupt(path, data, mode):
                        if path == paths["receipt"]:
                            raise module.ProfileError("injected_interruption")
                        atomic(path, data, mode)

                    with patch.object(module, "atomic_write", side_effect=interrupt):
                        with self.assertRaises(module.ProfileError):
                            module.apply_profile(fingerprint, "fixture")
                    paths[name].unlink()
                    if symlink:
                        owner = Path(directory) / "foreign"
                        owner.write_bytes(b"owner replacement")
                        paths[name].symlink_to(owner)
                    else:
                        paths[name].write_bytes(b"owner replacement")
                        paths[name].chmod(0o600)
                    with self.assertRaisesRegex(module.ProfileError, "preparing_payload_drift"):
                        module.apply_profile(fingerprint, "fixture")
                    with self.assertRaisesRegex(module.ProfileError, "rollback_refuses_managed_drift"):
                        module.rollback()
                    self.assertEqual(paths[name].read_bytes(), b"owner replacement")
                    self.assertEqual(paths[name].is_symlink(), symlink)

    def test_foreign_config_at_capture_is_restored_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            paths, fingerprint = self.fixture(directory, b"# original\n")
            rename = module.rename_exclusive

            def race(source, destination):
                if source == paths["main"]:
                    source.write_bytes(b"# newer owner config\n")
                rename(source, destination)

            with patch.object(module, "rename_exclusive", side_effect=race):
                with self.assertRaisesRegex(module.ProfileError, "preparing_shared_config_drift"):
                    module.apply_profile(fingerprint, "fixture")
            with self.assertRaisesRegex(module.ProfileError, "preparing_shared_config_drift"):
                module.apply_profile(fingerprint, "fixture")
            module.rollback()
            self.assertEqual(paths["main"].read_bytes(), b"# newer owner config\n")

    def test_intermediate_symlink_refused_without_outside_writes(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            paths, fingerprint = self.fixture(directory)
            (Path(directory) / "AIDev").symlink_to(outside)
            with self.assertRaisesRegex(module.ProfileError, "unsafe_managed_parent"):
                module.apply_profile(fingerprint, "fixture")
            self.assertEqual(list(Path(outside).iterdir()), [])

    def test_dedicated_include_precedes_foreign_wildcard_fragments(self):
        with tempfile.TemporaryDirectory() as directory:
            original = b"# owner shared include\nInclude config.d/*.conf\nHost owner\n  User owner\n"
            paths, fingerprint = self.fixture(directory, original)
            foreign = paths["config_dir"] / "a.conf"
            foreign.write_bytes(b"Host *\n  PasswordAuthentication yes\n  ForwardAgent yes\n")
            module.apply_profile(fingerprint, "fixture")
            self.assertEqual(paths["main"].read_bytes(),
                             b"Include config.d/windows-host.conf\nHost *\n" + original)
            self.assertEqual(foreign.read_bytes(),
                             b"Host *\n  PasswordAuthentication yes\n  ForwardAgent yes\n")

    def test_local_noop_checks_effective_additive_identity_and_forwarding_without_remote_health(self):
        with tempfile.TemporaryDirectory() as directory:
            paths, fingerprint = self.fixture(directory)
            module.apply_profile(fingerprint, "fixture")
            for extra in ("identityfile /synthetic/foreign-identity", "localforward 10000 localhost:22",
                          "remoteforward 10001 localhost:22", "dynamicforward 10002",
                          "proxycommand unexpected-proxy"):
                with self.subTest(extra=extra), \
                        patch.object(module, "doctor", side_effect=AssertionError("remote health")), \
                        patch.object(module, "resolve_windows_peer", side_effect=AssertionError("peer lookup")), \
                        patch.object(module, "scan_ed25519_host_key", side_effect=AssertionError("key scan")), \
                        patch.object(module.subprocess, "run", return_value=SimpleNamespace(stdout=effective_fixture(paths) + "\n" + extra)) as run:
                    with self.assertRaisesRegex(module.ProfileError, "effective_ssh_policy_drift"):
                        module.apply_profile(fingerprint, "fixture")
                    self.assertEqual(run.call_count, 1)
                    self.assertIn("-G", run.call_args.args[0])

    def test_new_journal_reads_are_bounded_and_single_link(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "journal"
            path.write_bytes(b"x" * (module.MAX_MANAGED_FILE + 1)); path.chmod(0o600)
            with self.assertRaisesRegex(module.ProfileError, "managed_file_unsafe"):
                module.read_file(path)
            path.write_bytes(b"synthetic")
            os.link(path, path.with_name("second-link"))
            with self.assertRaisesRegex(module.ProfileError, "managed_file_unsafe"):
                module.read_file(path)

    def test_real_local_parser_preserves_first_values_but_rejects_additive_owner_inputs(self):
        # -F disables user/system config loading. All Include/key/pin paths are
        # explicit temporary fixtures; this command never opens a connection.
        actual_run = subprocess.run
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory); paths = module.layout(home)
            paths["ssh"].mkdir(mode=0o700); paths["config_dir"].mkdir()
            alias = module.render_alias_config("100.64.0.1", "fixture")
            alias = alias.replace(b"~/.ssh/", os.fsencode(paths["ssh"]) + b"/")
            paths["alias"].write_bytes(alias)
            original = b"Host *\n  PasswordAuthentication yes\n  ForwardAgent yes\n"
            def local(command, **kwargs):
                self.assertEqual(command, ["/usr/bin/ssh", "-G", "-o", "CanonicalizeHostname=no", module.ALIAS])
                return actual_run(command[:1] + ["-F", str(paths["main"])] + command[1:], **kwargs)
            for extra, refused in ((b"", False),
                                   (b"  IdentityFile /synthetic/foreign-key\n", True),
                                   (b"  LocalForward 10000 localhost:22\n", True)):
                config = module.enrollment_main(original + extra)
                config = config.replace(b"Include config.d/windows-host.conf", b"Include " + os.fsencode(paths["alias"]))
                paths["main"].write_bytes(config)
                with self.subTest(extra=extra), patch.object(module.subprocess, "run", side_effect=local):
                    if refused:
                        with self.assertRaisesRegex(module.ProfileError, "effective_ssh_policy_drift"):
                            module.validate_effective_policy(paths, {"host": "100.64.0.1", "user": "fixture"})
                    else:
                        module.validate_effective_policy(paths, {"host": "100.64.0.1", "user": "fixture"})
    def test_atomic_parent_swap_does_not_follow_new_symlink(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            parent = Path(directory) / "parent"
            parent.mkdir()
            target = parent / "config"
            retained = Path(directory) / "retained"
            link = os.link

            def race(source, destination, **kwargs):
                parent.rename(retained)
                parent.symlink_to(outside)
                return link(source, destination, **kwargs)

            with patch.object(module.os, "link", side_effect=race):
                with self.assertRaisesRegex(module.ProfileError, "unsafe_managed_parent"):
                    module.atomic_write(target, b"managed", 0o600)
            self.assertEqual(list(Path(outside).iterdir()), [])
            self.assertEqual((retained / "config").read_bytes(), b"managed")


class TransportMigrationTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        from unittest.mock import patch
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.paths = module.layout(self.home)
        self.paths['ssh'].mkdir(mode=0o700)
        self.paths['config_dir'].mkdir(mode=0o700)
        self.paths['state'].mkdir(parents=True, mode=0o700)
        for name, mode in (('private', 0o600), ('public', 0o644)):
            self.paths[name].write_bytes(b'fixture')
            self.paths[name].chmod(mode)
        import json
        body = base64.b64encode(b'fixture').decode()
        values = {'main': module.render_main_config(),
                  'alias': module.render_alias_config('100.64.0.1', 'fixture-user'),
                  'known': module.hashed_known_host('100.64.0.1', 'ssh-ed25519', body)}
        receipt = {'schema': 1, 'status': 'applied', 'host': '100.64.0.1',
                   'user': 'fixture-user', 'hostFingerprint': module.public_blob_fingerprint(body),
                   'managed': {target: module.sha256_bytes(values[name]) for name, target in
                               (('main', 'config'), ('alias', 'alias'), ('known', 'knownHosts'))}}
        values['receipt'] = (json.dumps(receipt) + '\n').encode()
        for name, data in values.items():
            self.paths[name].write_bytes(data)
            self.paths[name].chmod(0o600)
        self.before = {name: self.paths[name].read_bytes() for name in values}
        for name, value in (('canonical_home', self.home), ('tailscale_cli', Path('/fixture'))):
            patcher = patch.object(module, name, return_value=value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_migrate_noop_and_restore_exact(self):
        from unittest.mock import patch
        with patch.object(module, 'doctor') as doctor, patch.object(module, 'validate_effective_policy') as local:
            self.assertTrue(module.migrate_transport())
            self.assertFalse(module.migrate_transport())
            self.assertEqual(doctor.call_count, 1)
            self.assertEqual(local.call_count, 1)
        self.assertIn(b'ProxyCommand ', self.paths['alias'].read_bytes())
        module.transport_restore(self.paths)
        for name, value in self.before.items():
            self.assertEqual(self.paths[name].read_bytes(), value)

    def test_already_proxy_migration_noop_uses_only_local_effective_policy(self):
        with patch.object(module, 'doctor'):
            module.migrate_transport()
        with patch.object(module, 'doctor', side_effect=AssertionError('remote health')), \
                patch.object(module, 'resolve_windows_peer', side_effect=AssertionError('peer lookup')), \
                patch.object(module, 'scan_ed25519_host_key', side_effect=AssertionError('key scan')), \
                patch.object(module.subprocess, 'run', return_value=SimpleNamespace(
                    stdout=effective_fixture(self.paths, proxy=True, user='fixture-user'))) as run:
            self.assertFalse(module.migrate_transport())
            self.assertEqual(run.call_count, 1)
            self.assertIn('-G', run.call_args.args[0])

    def test_failed_smoke_restores_exact(self):
        from unittest.mock import patch
        with patch.object(module, 'doctor', side_effect=module.ProfileError('smoke_failed')):
            with self.assertRaisesRegex(module.ProfileError, 'smoke_failed'):
                module.migrate_transport()
        for name, value in self.before.items():
            self.assertEqual(self.paths[name].read_bytes(), value)

    def test_drift_is_preserved(self):
        self.paths['alias'].write_bytes(b'owner change')
        with self.assertRaisesRegex(module.ProfileError, 'managed_bytes_drift'):
            module.migrate_transport()
        self.assertEqual(self.paths['alias'].read_bytes(), b'owner change')

    def test_recovery_refuses_unknown_poststate(self):
        from unittest.mock import patch
        with patch.object(module, 'doctor'):
            module.migrate_transport()
        self.paths['alias'].write_bytes(b'owner change')
        with self.assertRaisesRegex(module.ProfileError, 'transport_recovery_drift'):
            module.transport_restore(self.paths)
        self.assertEqual(self.paths['alias'].read_bytes(), b'owner change')

    def test_interrupted_alias_only_transaction_recovers(self):
        from unittest.mock import patch
        with patch.object(module, 'doctor'):
            module.migrate_transport()
        self.paths['receipt'].write_bytes(self.before['receipt'])
        module.transport_restore(self.paths)
        for name, value in self.before.items():
            self.assertEqual(self.paths[name].read_bytes(), value)

    def test_existing_backup_is_not_overwritten(self):
        journal = self.paths['state'] / 'transport-backup.json'
        journal.write_bytes(b'previous transaction')
        journal.chmod(0o600)
        with self.assertRaisesRegex(module.ProfileError, 'managed_target_collision'):
            module.migrate_transport()
        self.assertEqual(journal.read_bytes(), b'previous transaction')
        self.assertEqual(self.paths['alias'].read_bytes(), self.before['alias'])

    def test_doctor_proxy_checks_pin_and_avoids_direct_scan(self):
        from unittest.mock import patch
        import subprocess
        with patch.object(module, 'doctor'):
            module.migrate_transport()
        effective = effective_fixture(self.paths, proxy=True, user="fixture-user")
        results = [subprocess.CompletedProcess([], 0, effective),
                   subprocess.CompletedProcess([], 0, 'BRIDGE_STRICT_OK')]
        with patch.object(module, 'resolve_windows_peer', return_value='100.64.0.1'), \
             patch.object(module, 'scan_ed25519_host_key', side_effect=AssertionError('direct scan')), \
             patch.object(module.subprocess, 'run', side_effect=results):
            module.doctor()
        import json
        receipt = json.loads(self.paths['receipt'].read_text())
        receipt['hostFingerprint'] = 'SHA256:wrong'
        self.paths['receipt'].write_text(json.dumps(receipt))
        with patch.object(module, 'resolve_windows_peer', return_value='100.64.0.1'):
            with self.assertRaisesRegex(module.ProfileError, 'pinned_host_key_drift'):
                module.doctor()

    def test_proxy_pin_for_other_host_is_rejected_before_ssh(self):
        with patch.object(module, 'doctor'):
            module.migrate_transport()
        body = base64.b64encode(b'fixture').decode()
        wrong = module.hashed_known_host('100.64.0.2', 'ssh-ed25519', body)
        self.paths['known'].write_bytes(wrong)
        receipt = json.loads(self.paths['receipt'].read_text())
        receipt['managed']['knownHosts'] = module.sha256_bytes(wrong)
        self.paths['receipt'].write_text(json.dumps(receipt))
        with patch.object(module, 'resolve_windows_peer', return_value='100.64.0.1'), \
             patch.object(module.subprocess, 'run') as run:
            with self.assertRaisesRegex(module.ProfileError, 'pinned_host_key_drift'):
                module.doctor()
            run.assert_not_called()

    def test_proxy_cannot_silently_fall_back_to_direct_alias(self):
        with patch.object(module, 'doctor'):
            module.migrate_transport()
        direct = self.before['alias']
        self.paths['alias'].write_bytes(direct)
        receipt = json.loads(self.paths['receipt'].read_text())
        receipt['managed']['alias'] = module.sha256_bytes(direct)
        self.paths['receipt'].write_text(json.dumps(receipt))
        with patch.object(module, 'resolve_windows_peer', return_value='100.64.0.1'), \
             patch.object(module.subprocess, 'run') as run:
            with self.assertRaisesRegex(module.ProfileError, 'managed_policy_drift'):
                module.doctor()
            run.assert_not_called()

    def test_unknown_transport_is_not_treated_as_direct(self):
        receipt = json.loads(self.paths['receipt'].read_text())
        receipt['transport'] = 'unexpected'
        self.paths['receipt'].write_text(json.dumps(receipt))
        with patch.object(module, 'resolve_windows_peer', return_value='100.64.0.1'), \
             patch.object(module.subprocess, 'run') as run:
            with self.assertRaisesRegex(module.ProfileError, 'unsupported_transport'):
                module.doctor()
            run.assert_not_called()

if __name__ == "__main__":
    unittest.main()
