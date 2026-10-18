"""Only disposable unprivileged Python children; no native/root calls."""
import sys
import errno
import unittest
from unittest.mock import Mock, patch

from lib import bounded_command as command
from lib.bounded_command import bounded


class BoundedCommandTests(unittest.TestCase):
    def native_bounded(self, *args, **kwargs):
        original = command.os.killpg
        popen = command.subprocess.Popen
        denied, children = [], []
        def owned_child(*call, **options):
            child = popen(*call, **options)
            children.append(child)
            return child
        def observe(*call):
            try:
                return original(*call)
            except PermissionError as error:
                if error.errno == errno.EPERM and call[1] == 0:
                    denied.append(True)
                raise
        try:
            with patch.object(command.os, 'killpg', observe), \
                 patch.object(command.subprocess, 'Popen', owned_child):
                result = bounded(*args, **kwargs)
        finally:
            # Test hygiene only: reap our own direct fixture child. This does
            # not substitute for the unavailable process-group observation.
            for child in children:
                child.wait(timeout=2)
        if denied:
            self.assertEqual(result, (None, b'', b'', False))
            self.skipTest('native syscall observed EPERM for own child-group observation; UNKNOWN preserved')
        return result

    def test_clean_child_output_and_settlement(self):
        result = bounded([sys.executable, '-c', 'import sys; print("ok"); print("note",file=sys.stderr)'], timeout=5)
        self.assertEqual(result, (0, b'ok\n', b'note\n', True))

    def test_output_limit_discards_output_and_settles(self):
        result = self.native_bounded([sys.executable, '-c', 'print("x"*1024)'], timeout=5, limit=32)
        self.assertEqual(result, (None, b'', b'', True))

    def test_timeout_terminates_and_settles(self):
        result = self.native_bounded([sys.executable, '-c', 'import time; time.sleep(30)'], timeout=0.05)
        self.assertEqual(result, (None, b'', b'', True))

    def test_cleanup_group_already_absent_still_observes_direct_child(self):
        process = Mock()
        process.poll.return_value = None
        process.wait.return_value = 0
        selector = Mock()
        selector.get_map.return_value = {}
        with patch.object(command.subprocess, 'Popen', return_value=process), \
             patch.object(command.selectors, 'DefaultSelector', return_value=selector), \
             patch.object(command.os, 'set_blocking'), \
             patch.object(command.os, 'killpg', side_effect=ProcessLookupError):
            self.assertEqual(bounded(['/synthetic/never-executed'], timeout=0),
                (None, b'', b'', True))
        process.wait.assert_called_once_with(timeout=1)

    def test_absent_group_with_unsettled_direct_child_remains_unknown(self):
        process = Mock()
        process.wait.side_effect = command.subprocess.TimeoutExpired('synthetic', 1)
        self.assertFalse(command.reap_absent_group(process))

    def test_denied_group_observation_is_not_settlement(self):
        process = Mock()
        process.poll.return_value = None
        selector = Mock()
        selector.get_map.return_value = {}
        with patch.object(command.subprocess, 'Popen', return_value=process), \
             patch.object(command.selectors, 'DefaultSelector', return_value=selector), \
             patch.object(command.os, 'set_blocking'), \
             patch.object(command.os, 'killpg', side_effect=PermissionError(errno.EPERM, 'synthetic')):
            self.assertEqual(bounded(['/synthetic/never-executed'], timeout=0),
                (None, b'', b'', False))
        process.wait.assert_not_called()


if __name__ == '__main__':
    unittest.main()
