"""Existing private bounded command custody, independent of lifecycle policy.

Callers retain command/authority/source admission. Initially extracted from
workstation_maintenance_delivery so a root observation need not import an
unrelated schedule installer and its historical source inputs. Cleanup now
boundedly reaps the direct child after independently observed group absence.
"""
import os
import selectors
import signal
import subprocess
import time


class Fault(ValueError):
    pass


def need(value, reason):
    if value is not True:
        raise Fault(reason)


def reap_absent_group(process):
    # Group disappearance can precede waitpid readiness by a short interval.
    # Absence alone is not direct-child settlement; retain a bounded wait.
    try:
        return type(process.wait(timeout=1)) is int
    except (OSError, subprocess.TimeoutExpired):
        return False


def bounded(command, *, timeout, limit=32768):
    """Private native command custody; retained output and group lifetime bounded."""
    process, selector, chunks, count = None, selectors.DefaultSelector(), {"out": [], "err": []}, 0
    try:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, start_new_session=True,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"})
        for pipe, key in ((process.stdout, "out"), (process.stderr, "err")):
            os.set_blocking(pipe.fileno(), False)
            selector.register(pipe, selectors.EVENT_READ, key)
        deadline = time.monotonic() + timeout
        while selector.get_map() or process.poll() is None:
            need(time.monotonic() < deadline, "child_timeout")
            for entry, _ in selector.select(min(0.05, max(0, deadline - time.monotonic()))):
                raw = os.read(entry.fileobj.fileno(), min(4096, limit + 1 - count))
                if not raw:
                    selector.unregister(entry.fileobj)
                else:
                    count += len(raw)
                    need(count <= limit, "child_output_limit")
                    chunks[entry.data].append(raw)
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            return process.returncode, b"".join(chunks["out"]), b"".join(chunks["err"]), True
        raise Fault("descendant_still_running")
    except (OSError, Fault):
        if process is not None:
            for action in (signal.SIGTERM, signal.SIGKILL):
                try: os.killpg(process.pid, action)
                except ProcessLookupError:
                    # The child can exit between the output-limit/timeout
                    # failure and cleanup. Observe/reap it rather than
                    # reporting UNKNOWN merely because its group is absent.
                    return None, b"", b"", reap_absent_group(process)
                except OSError: return None, b"", b"", False
                deadline = time.monotonic() + 1
                while time.monotonic() < deadline:
                    process.poll()
                    try: os.killpg(process.pid, 0)
                    except ProcessLookupError:
                        return None, b"", b"", reap_absent_group(process)
                    except OSError:
                        return None, b"", b"", False
                    time.sleep(0.02)
            try:
                os.killpg(process.pid, 0)
            except ProcessLookupError:
                return None, b"", b"", reap_absent_group(process)
            except OSError:
                return None, b"", b"", False
        return None, b"", b"", False
    finally:
        selector.close()
        if process is not None:
            if process.stdout is not None: process.stdout.close()
            if process.stderr is not None: process.stderr.close()
