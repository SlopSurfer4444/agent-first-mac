"""Fake-only capture integration; imports fixture definitions, never native tests."""

import copy
import hashlib
import importlib.util
from pathlib import Path
import sys
from types import MappingProxyType
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from lib import phase5_runtime_capture as capture_module  # noqa: E402
from lib import phase5_runtime_session as session  # noqa: E402
from lib.phase5_runtime_transition import ABSENT, Image  # noqa: E402

spec = importlib.util.spec_from_file_location("capture_fakes", ROOT / "tests/test_phase5_runtime_session.py")
fakes = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fakes)
TARGET_IDS = session.TARGET_IDS


def metadata(image):
    if image == ABSENT:
        return {"exists": False, "linkCount": 0, "mode": None, "ownerClass": "absent", "sha256": None, "size": 0}
    return {"exists": True, "linkCount": 1, "mode": format(image.mode, "04o"),
            "ownerClass": "current-user", "sha256": hashlib.sha256(image.data).hexdigest(), "size": len(image.data)}


def fixture():
    backends, store, logical_before, logical_after, events = fakes.fixture()
    # Existing receipt install contract: launcher0700, other managed payloads0600.
    for i in (4, 7):
        identifier = TARGET_IDS[i]
        mode = 0o700 if i == 7 else 0o600
        for mapping in (logical_before, logical_after):
            image = mapping[identifier]
            if image != ABSENT:
                mapping[identifier] = Image(image.data, image.identity, mode, image.seal)
        backend = backends[identifier][0]
        image = backend.files[identifier]
        backend.files[identifier] = Image(image.data, image.identity, mode, image.seal)
    physical_before, physical_after, rows = {}, {}, []
    for i, identifier in enumerate(TARGET_IDS):
        old, after = logical_before[identifier], logical_after[identifier]
        physical_before[identifier] = Image(b"absent\n" if old == ABSENT else old.data, (10, i), 0o600, b"physical-before")
        physical_after[identifier] = Image(after.data, (11, i), 0o600, b"physical-after")
        rows.append({"id": identifier, "before": metadata(old), "after": metadata(after),
                     "applied": True, "sourceSHA256": "b" * 64})
    receipt = {"acceptedControlCommit": "a" * 40, "appliedOrder": list(TARGET_IDS), "applyResult": "applied",
               "cli": {"source": "chatgpt-app-bundle", "versionPolicy": "exact-stage-b-re-attestation", "version": "0.1.0"},
               "directories": [], "generatedSourceHashes": {}, "manifestSHA256": "c" * 64,
               "phase": "phase5_codex_contract_apply", "rollbackState": "available", "runId": fakes.SESSION,
               "schema": 1, "sourceCommit": "a" * 40, "state": "applied", "targets": rows}
    return backends, store, receipt, physical_before, physical_after, events


def ready(args, *, admit_current=lambda _: True, recheck_dependencies=lambda: True):
    # These are deliberately fake callbacks, not production admission.
    backends, _, receipt, before, after, _ = args
    return capture_module.readiness(backends, receipt, before, after,
                                    admit_current=admit_current, recheck_dependencies=recheck_dependencies)


def capture(args, *, admit_current=lambda _: True, recheck_dependencies=lambda: True):
    backends, store, receipt, before, after, _ = args
    return capture_module.capture(backends, store, receipt, before, after, session_id=fakes.SESSION,
                                  admit_current=admit_current, recheck_dependencies=recheck_dependencies)


class RuntimeCaptureTests(unittest.TestCase):
    def assert_public(self, value, verdict):
        self.assertEqual(value["verdict"], verdict)
        self.assertEqual(set(value), {"schema", "verdict", "observedTargets", "executionAdmission", "liveAdmission",
                                      "phase5Accepted", "phase6Allowed", "cleanupPerformed"})
        for key in ("executionAdmission", "liveAdmission", "phase5Accepted", "phase6Allowed", "cleanupPerformed"):
            self.assertIs(value[key], False)
        self.assertNotIn("private", str(value))
        self.assertNotIn("p5-", str(value))

    def test_readiness_no_store_or_target_writes(self):
        args = fixture()
        original = fakes.images(args[0])
        calls = []
        self.assert_public(ready(args, recheck_dependencies=lambda: calls.append("dependency") or True), "ready")
        self.assertEqual(calls, ["dependency", "dependency"])
        self.assertEqual(args[1].records, {})
        self.assertEqual(args[-1], [])
        self.assertEqual(fakes.images(args[0]), original)

    def test_real_session_capture_only_no_target_methods_exposed(self):
        args = fixture()
        original = fakes.images(args[0])
        implementation = session.capture
        calls = []

        def inspect_readonly(backends, *pos, **kw):
            calls.append(True)
            for backend, name in backends.values():
                for method in ("create_exclusive", "swap", "move_exclusive", "sync"):
                    self.assertFalse(hasattr(backend, method))
                self.assertTrue(callable(backend.snapshot))
            return implementation(backends, *pos, **kw)

        with patch.object(session, "capture", inspect_readonly):
            self.assert_public(capture(args), "captured")
        self.assertEqual(calls, [True])
        self.assertEqual(args[-1], [("persist", "capture")])
        self.assertEqual(fakes.images(args[0]), original)
        verified = session.verify(args[0], args[1])
        self.assertEqual(verified["verdict"], "verified")
        self.assertIs(verified["executionAdmission"], False)

    def test_admission_gets_exact_eight_readonly_images(self):
        args = fixture()
        expected = fakes.images(args[0])

        def admit(images):
            self.assertIs(type(images), MappingProxyType)
            self.assertEqual(tuple(images), TARGET_IDS)
            self.assertEqual(tuple(images.values()), expected)
            with self.assertRaises(TypeError):
                images["config"] = fakes.THIRD
            return True

        self.assert_public(capture(args, admit_current=admit), "captured")

    def test_callback_false_integer_none_and_exception_cannot_accept(self):
        for operation in (ready, capture):
            for callback_kind in ("admission", "dependencies"):
                for bad in (False, 1, None, "exception"):
                    args = fixture()

                    def callback(*_):
                        if bad == "exception":
                            raise RuntimeError("private callback/path/detail")
                        return bad

                    kwargs = {"admit_current" if callback_kind == "admission" else "recheck_dependencies": callback}
                    self.assert_public(operation(args, **kwargs), "recovery-required")
                    self.assertEqual(args[1].records, {})
                    self.assertEqual(args[-1], [])

    def test_every_target_changed_by_admission_is_rejected_before_store(self):
        for identifier in TARGET_IDS:
            args = fixture()

            def drift(_):
                args[0][identifier][0].files[identifier] = fakes.THIRD
                return True

            self.assert_public(capture(args, admit_current=drift), "recovery-required")
            self.assertEqual(args[1].records, {})
            self.assertEqual(args[-1], [])

    def test_changed_between_admission_and_real_session_capture_is_pinned(self):
        for identifier in ("config", "global-agents"):
            args = fixture()
            implementation = session.capture

            def changed_then_capture(*pos, **kw):
                args[0][identifier][0].files[identifier] = fakes.THIRD
                return implementation(*pos, **kw)

            with patch.object(session, "capture", changed_then_capture):
                self.assert_public(capture(args), "recovery-required")
            self.assertEqual(args[1].records, {})
            self.assertEqual(args[-1], [])

    def test_same_bytes_identity_mode_and_seal_drift_are_not_rebased(self):
        for field in ("identity", "mode", "seal"):
            args = fixture()
            backend = args[0]["global-agents"][0]
            original = backend.files["global-agents"]

            def drift(_):
                backend.files["global-agents"] = Image(original.data,
                    (99, 99) if field == "identity" else original.identity,
                    0o644 if field == "mode" else original.mode,
                    b"changed" if field == "seal" else original.seal)
                return True

            self.assert_public(capture(args, admit_current=drift), "recovery-required")
            self.assertEqual(args[-1], [])

    def test_drift_after_successful_session_capture_retains_nonadmitted_artifact(self):
        args = fixture()
        implementation = session.capture
        published = []

        def capture_then_drift(*pos, **kw):
            result = implementation(*pos, **kw)
            self.assertEqual(result["verdict"], "captured")
            published.append(args[1].records["capture"])
            args[0]["global-agents"][0].files["global-agents"] = fakes.THIRD
            return result

        with patch.object(session, "capture", capture_then_drift):
            self.assert_public(capture(args), "recovery-required")
        self.assertEqual(args[1].records, {"capture": published[0]})
        self.assertEqual(args[-1], [("persist", "capture")])

    def test_post_dependency_failure_retains_capture_but_cannot_pass(self):
        for bad in (False, 1, "exception"):
            args = fixture()
            calls = []

            def dependency():
                calls.append(True)
                if len(calls) == 1:
                    return True
                if bad == "exception":
                    raise RuntimeError("private dependency")
                return bad

            self.assert_public(capture(args, recheck_dependencies=dependency), "recovery-required")
            self.assertIn("capture", args[1].records)
            self.assertEqual(args[-1], [("persist", "capture")])
            self.assertEqual(len(calls), 2)

    def test_post_dependency_callback_target_drift_is_also_rechecked(self):
        for operation in (ready, capture):
            args = fixture()
            calls = []

            def dependency():
                calls.append(True)
                if len(calls) == 2:
                    args[0]["config"][0].files["config"] = fakes.THIRD
                return True

            self.assert_public(operation(args, recheck_dependencies=dependency), "recovery-required")
            self.assertEqual(args[0]["config"][0].files["config"], fakes.THIRD)

    def test_logical_launcher0700_from_physical0600_and_originals_retained(self):
        args = fixture()
        history = capture_module.translate_history(args[2], args[3], args[4])
        self.assertEqual(history.before[-1].mode, 0o700)
        self.assertEqual(history.after[-1].mode, 0o700)
        self.assertEqual(history.physical_before[-1].mode, 0o600)
        self.assertEqual(history.physical_after[-1].mode, 0o600)
        self.assertIs(history.physical_before[-1], args[3][TARGET_IDS[-1]])
        self.assertIs(history.physical_after[-1], args[4][TARGET_IDS[-1]])
        self.assertEqual(history.before[-1].seal, b"")
        self.assertEqual(history.physical_before[-1].seal, b"physical-before")
        self.assertNotIn("private", repr(history))
        self.assert_public(capture(args), "captured")

    def test_absence_marker_is_physical_present_and_logical_absent(self):
        args = fixture()
        history = capture_module.translate_history(args[2], args[3], args[4])
        self.assertEqual(history.before[2], ABSENT)
        self.assertEqual(history.physical_before[2].data, b"absent\n")
        self.assertEqual(history.physical_before[2].mode, 0o600)

    def test_logical_and_physical_mode_are_distinct_negative(self):
        args = fixture()
        old = args[4][TARGET_IDS[-1]]
        args[4][TARGET_IDS[-1]] = Image(old.data, old.identity, 0o700, old.seal)
        with self.assertRaisesRegex(capture_module.CaptureError, "^history_translation_invalid$"):
            capture_module.translate_history(args[2], args[3], args[4])
        self.assert_public(ready(args), "recovery-required")

    def test_receipt_exact_types_hash_size_order_and_absence_negatives(self):
        for defect in ("schema-bool", "row-extra", "row-order", "link-bool", "size-bool", "hash",
                       "size", "mode", "missing", "absent-after", "marker", "partial-image"):
            args = fixture()
            receipt, before, after = args[2:5]
            if defect == "schema-bool":
                receipt["schema"] = True
            elif defect == "row-extra":
                receipt["targets"][0]["unknown"] = True
            elif defect == "row-order":
                receipt["targets"].reverse()
            elif defect in ("link-bool", "size-bool", "hash", "size", "mode"):
                key, value = {"link-bool": ("linkCount", True), "size-bool": ("size", True),
                              "hash": ("sha256", "0" * 64), "size": ("size", 0), "mode": ("mode", "1700")}[defect]
                receipt["targets"][0]["after"][key] = value
            elif defect == "missing":
                del before["config"]
            elif defect == "absent-after":
                receipt["targets"][2]["after"] = metadata(ABSENT)
            elif defect == "marker":
                before[TARGET_IDS[2]] = Image(b"not absent\n", (10, 2), 0o600)
            else:
                after["config"] = object.__new__(Image)
            with self.assertRaisesRegex(capture_module.CaptureError, "^history_translation_invalid$"):
                capture_module.translate_history(receipt, before, after)
            self.assertEqual(args[-1], [])

    def test_history_generation_recheck_is_independent_and_connected(self):
        args = fixture()
        physical = tuple(args[3].values())

        def admit(_):
            args[3]["config"] = Image(args[3]["config"].data, (99, 1), 0o600)
            return True

        def dependencies():
            return tuple(args[3].values()) == physical

        self.assert_public(capture(args, admit_current=admit, recheck_dependencies=dependencies), "recovery-required")
        self.assertIn("capture", args[1].records)

    def test_history_and_receipt_inputs_are_never_modified(self):
        args = fixture()
        receipt = copy.deepcopy(args[2])
        before, after = dict(args[3]), dict(args[4])
        self.assert_public(capture(args), "captured")
        self.assertEqual(args[2], receipt)
        self.assertEqual(args[3], before)
        self.assertEqual(args[4], after)

    def test_readiness_checks_actual_composition_and_managed_six(self):
        for defect in ("config", "managed"):
            args = fixture()
            identifier = "config" if defect == "config" else TARGET_IDS[3]
            old = args[0][identifier][0].files[identifier]
            args[0][identifier][0].files[identifier] = Image(b"malformed or unrelated", old.identity, old.mode, old.seal)
            self.assert_public(ready(args), "recovery-required")
            self.assertEqual(args[-1], [])

    def test_post_dependencies_run_after_interrupted_store_publication(self):
        args = fixture()
        args[1].hooks["volatile:capture"] = fakes.failure
        calls = []
        self.assert_public(capture(args, recheck_dependencies=lambda: calls.append(True) or True), "recovery-required")
        self.assertEqual(calls, [True, True])
        self.assertIn("capture", args[1].records)
        self.assertEqual(args[-1], [("persist", "capture")])


if __name__ == "__main__":
    unittest.main()
