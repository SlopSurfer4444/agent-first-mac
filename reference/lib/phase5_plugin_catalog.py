"""Bounded app-server observation of installed and vertical plugin catalogs.

The caller owns validation of the executable, argv, environment, app bundle,
and surrounding private state.  This module fixes the RPC surface to two read
methods and never starts a thread, turn, model, installation, or reconciliation.
Raw responses are private.  ``public_projection`` deliberately emits only
counts, booleans, and closed source/reason classes; it grants no admission.
"""

import json
import os
import selectors
import subprocess
import time


MAX_DEADLINE_SECONDS = 20.0
MAX_CAPTURE_BYTES = 4 * 1024 * 1024
MAX_RPC_LINE_BYTES = MAX_CAPTURE_BYTES
MAX_NOTIFICATIONS = 1024
MAX_MARKETPLACES = 256
MAX_PLUGINS = 4096
MAX_STRING = 4096

REASON_CLASSES = frozenset(
    {
        "ok",
        "invalid_arguments",
        "launch_failed",
        "write_failed",
        "deadline_exceeded",
        "output_limit",
        "unexpected_eof",
        "protocol_malformed",
        "server_error",
        "process_settlement_failed",
        "catalog_shape",
    }
)
SOURCE_CLASSES = ("git", "local", "npm", "remote")
_ENVELOPE_KEYS = frozenset({"id", "method", "params", "result", "error", "jsonrpc"})

_INITIALIZE = {
    "id": 0,
    "method": "initialize",
    "params": {
        "clientInfo": {
            "name": "phase5_plugin_catalog_observer",
            "title": "Phase 5 Plugin Catalog Observer",
            "version": "1.0.0",
        }
    },
}
_INITIALIZED = {"method": "initialized", "params": {}}
_INSTALLED = {
    "id": 1,
    "method": "plugin/installed",
    "params": {"cwds": [], "installSuggestionPluginNames": []},
}
_VERTICAL = {
    "id": 2,
    "method": "plugin/list",
    "params": {
        "cwds": [],
        "forceRefetch": False,
        "marketplaceKinds": ["vertical"],
    },
}


class CatalogClientError(Exception):
    """A closed, non-sensitive failure classification."""

    def __init__(self, reason_class, *, private_owner=None, primary_reason=None):
        if type(reason_class) is not str or reason_class not in REASON_CLASSES or reason_class == "ok":
            reason_class = "protocol_malformed"
        self.reason_class = reason_class
        # Never serialize this handle. An unsettled child remains caller-owned;
        # no PID or process-group identity is asserted by a public result.
        self.private_owner = private_owner
        self.primary_reason = primary_reason
        super().__init__(reason_class)


def _valid_launch(command, environment, timeout_seconds):
    if (
        isinstance(command, (str, bytes))
        or not isinstance(command, (list, tuple))
        or not 2 <= len(command) <= 32
        or any(type(item) is not str or not item or "\0" in item
               or len(item) > MAX_STRING for item in command)
        or command[1] != "app-server"
        or command.count("--listen") != 1
        or sum(
            command[index:index + 2] == ("--listen", "stdio://")
            or command[index:index + 2] == ["--listen", "stdio://"]
            for index in range(len(command) - 1)
        ) != 1
        or not isinstance(environment, dict)
        or len(environment) > 256
        or any(
            type(key) is not str
            or type(value) is not str
            or not key
            or "=" in key or "\0" in key or "\0" in value
            or len(key) > 256
            or len(value) > 16384
            for key, value in environment.items()
        )
        or type(timeout_seconds) not in (int, float)
        or not 2.0 < timeout_seconds <= MAX_DEADLINE_SECONDS
    ):
        raise CatalogClientError("invalid_arguments")


def _encode(message):
    return json.dumps(message, ensure_ascii=True, separators=(",", ":")).encode("ascii") + b"\n"


class _Session:
    """Single-threaded pipe owner; not a descendant supervisor or authority."""

    def __init__(self, deadline):
        self.deadline = deadline
        self.notifications = 0
        self.process = self.selector = None
        self.streams = {}
        self.eof = set()
        self.total = 0
        self.stderr_nonempty = False
        self.pending = bytearray()
        self.expected = None
        self.responded = False
        self.result = None
        self.interruption = None

    def __repr__(self):
        return "<private catalog process owner>"

    def start(self, command, environment, popen_factory):
        # The owner exists before spawn. Every later partial initialization is
        # inside collect's settlement boundary. Popen itself is synchronous;
        # the caller's launch boundary must bound process creation separately.
        self.process = popen_factory(
            list(command), env=dict(environment), stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=False,
            bufsize=0, close_fds=True, start_new_session=True,
        )
        self.streams = {name: getattr(self.process, name)
                        for name in ("stdin", "stdout", "stderr")}
        if any(stream is None for stream in self.streams.values()):
            raise CatalogClientError("launch_failed")
        self.selector = selectors.DefaultSelector()
        for name, stream in self.streams.items():
            os.set_blocking(stream.fileno(), False)
            if name != "stdin":
                self.selector.register(stream, selectors.EVENT_READ, name)

    def _remaining(self, deadline):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise CatalogClientError("deadline_exceeded")
        return remaining

    def _line(self, line):
        value = json.loads(line.decode("utf-8"), object_pairs_hook=_unique_object,
                           parse_constant=_invalid_constant)
        if type(value) is not dict:
            raise CatalogClientError("protocol_malformed")
        # Exported wire schemas permit additional envelope metadata. Ignore
        # only non-reserved fields; they convey no RPC, capability or admission.
        # Reserved fields must still describe exactly one supported message
        # kind. In particular, a server request is never treated as a response.
        core = _ENVELOPE_KEYS.intersection(value)
        if "id" in value:
            if (type(value["id"]) is not int or self.expected is None
                    or value["id"] != self.expected or self.responded):
                raise CatalogClientError("protocol_malformed")
            if core == {"id", "error"}:
                raise CatalogClientError("server_error")
            if core != {"id", "result"}:
                raise CatalogClientError("protocol_malformed")
            self.responded, self.result = True, value["result"]
        else:
            if (core != {"method", "params"}
                    or not _short_string(value.get("method"))
                    or type(value.get("params")) is not dict):
                raise CatalogClientError("protocol_malformed")
            self.notifications += 1
            if self.notifications > MAX_NOTIFICATIONS:
                raise CatalogClientError("output_limit")

    def _read(self, name):
        # Count BOTH channels against one capture budget. Read at most one byte
        # beyond it, so overflow is prompt even for a never-ending stderr writer.
        try:
            chunk = os.read(self.streams[name].fileno(),
                            min(65536, MAX_CAPTURE_BYTES - self.total + 1))
        except (BlockingIOError, InterruptedError):
            return
        if not chunk:
            self.selector.unregister(self.streams[name])
            self.eof.add(name)
            if name == "stdout" and self.pending:
                raise CatalogClientError("protocol_malformed")
            return
        self.total += len(chunk)
        if self.total > MAX_CAPTURE_BYTES:
            raise CatalogClientError("output_limit")
        if name == "stderr":
            self.stderr_nonempty = True
            return
        self.pending.extend(chunk)
        while b"\n" in self.pending:
            self._remaining(self.deadline)
            line, _, tail = self.pending.partition(b"\n")
            self.pending = bytearray(tail)
            if len(line) > MAX_RPC_LINE_BYTES:
                raise CatalogClientError("output_limit")
            self._line(line)
        if len(self.pending) > MAX_RPC_LINE_BYTES:
            raise CatalogClientError("output_limit")

    def request(self, messages, identifier):
        outgoing = b"".join(_encode(message) for message in messages)
        self.expected, self.responded, self.result = identifier, False, None
        self.selector.register(self.streams["stdin"], selectors.EVENT_WRITE, "stdin")
        while outgoing or not self.responded:
            for key, _ in self.selector.select(self._remaining(self.deadline)):
                self._remaining(self.deadline)
                if key.data != "stdin":
                    self._read(key.data)
                else:
                    try:
                        written = os.write(key.fd, outgoing)
                    except (BlockingIOError, InterruptedError):
                        continue
                    except OSError:
                        raise CatalogClientError("write_failed") from None
                    if written <= 0:
                        raise CatalogClientError("write_failed")
                    outgoing = outgoing[written:]
                    if not outgoing:
                        self.selector.unregister(self.streams["stdin"])
            if "stdout" in self.eof and not self.responded:
                raise CatalogClientError("unexpected_eof")
        self._remaining(self.deadline)
        return self.result

    def _remember_interruption(self, exc):
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            if self.interruption is None:
                self.interruption = exc
            return True
        return False

    def _close_streams(self):
        ok = True
        # Obtain from Popen too: interruption may precede self.streams setup.
        for name in ("stdin", "stdout", "stderr"):
            stream = getattr(self.process, name, None)
            if stream is not None:
                try:
                    stream.close()  # unbuffered FileIO: never flushes pipe data
                except BaseException as exc:
                    self._remember_interruption(exc)
                    ok = False
        if self.selector is not None:
            try:
                self.selector.close()
            except BaseException as exc:
                self._remember_interruption(exc)
                ok = False
        return ok

    def _wait_child(self, until):
        while self.process.poll() is None:
            remaining = until - time.monotonic()
            if remaining <= 0:
                return False
            time.sleep(min(0.01, remaining))
        return True

    def close(self, deadline, failed):
        """Reap only this Popen child; never signal an exited child or its group.

        Pipes inherited by unrelated descendants cannot keep a reader alive:
        there are no reader threads and all our descriptors are closed here.
        Failure to observe EOF is not claimed as successful transport closure.
        """
        if self.process is None:
            return True, None
        problem = None
        try:
            if not failed:
                self.streams["stdin"].close()
                self.expected = None
                self.deadline = min(deadline - 1.0, time.monotonic() + 0.5)
                while (self.eof != {"stdout", "stderr"}
                       or self.process.poll() is None):
                    for key, _ in self.selector.select(
                            min(0.05, self._remaining(self.deadline))):
                        self._read(key.data)
                if self.process.returncode != 0:
                    problem = "process_settlement_failed"
        except CatalogClientError as exc:
            problem = ("process_settlement_failed" if exc.reason_class == "deadline_exceeded"
                       else exc.reason_class)
        except BaseException as exc:
            self._remember_interruption(exc)
            problem = "process_settlement_failed"
        handles_closed = self._close_streams()
        # Continue the fixed, bounded cleanup after an interruption, remembering
        # the first one for propagation. Recheck the direct child before each
        # signal; never restart a process or extend the original deadline.
        for action in ("terminate", "kill"):
            try:
                if self.process.poll() is None and time.monotonic() < deadline:
                    getattr(self.process, action)()
                    until = (min(deadline, time.monotonic() + 0.5)
                             if action == "terminate" else deadline)
                    self._wait_child(until)
            except BaseException as exc:
                if not self._remember_interruption(exc):
                    break
        try:
            reaped = self.process.poll() is not None
        except BaseException as exc:
            self._remember_interruption(exc)
            reaped = False
        return reaped and handles_closed, problem


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise CatalogClientError("protocol_malformed")
        value[key] = item
    return value


def _invalid_constant(_):
    raise CatalogClientError("protocol_malformed")


def collect_private_catalog(command, environment, timeout_seconds=MAX_DEADLINE_SECONDS,
                            _popen_factory=subprocess.Popen):
    """Run the fixed read-only RPC sequence and return private response objects.

    ``command`` and ``environment`` are supplied and attested by the caller.
    No command, environment value, server error, or response is logged. Pipe I/O
    and settlement share the deadline; synchronous process creation requires a
    caller-owned launch boundary. On settlement failure the exception retains
    a private owner handle; the caller must resolve it, not blindly retry.
    KeyboardInterrupt/SystemExit propagate after cleanup, including when raised
    during cleanup. They carry ``settlement_failed`` and, if unresolved,
    ``private_owner`` rather than concealing ownership behind another error.
    """
    _valid_launch(command, environment, timeout_seconds)
    # Reserve two seconds inside the caller-selected deadline for settlement.
    deadline = time.monotonic() + timeout_seconds
    session = _Session(deadline - 2.0)
    primary = None
    installed = vertical = None
    try:
        session.start(command, environment, _popen_factory)
        if type(session.request((_INITIALIZE,), 0)) is not dict:
            raise CatalogClientError("protocol_malformed")
        installed = session.request((_INITIALIZED, _INSTALLED), 1)
        vertical = session.request((_VERTICAL,), 2)
        _catalog_rows(installed)
        _catalog_rows(vertical)
    except BaseException as exc:
        primary = exc
    settled, settlement_problem = session.close(deadline, primary is not None)
    reason = (primary.reason_class if isinstance(primary, CatalogClientError)
              else "launch_failed" if session.process is None
              else "protocol_malformed")
    interruption = (primary if isinstance(primary, (KeyboardInterrupt, SystemExit))
                    else session.interruption)
    if interruption is not None:
        interruption.settlement_failed = not settled
        interruption.private_owner = session if not settled else None
        raise interruption from None
    if not settled:
        raise CatalogClientError("process_settlement_failed", private_owner=session,
                                 primary_reason=reason if primary else settlement_problem) from None
    if primary is not None:
        # Fresh exception raised outside the handler: formatted tracebacks do
        # not expose JSONDecodeError documents, OSError filenames or RPC errors.
        raise CatalogClientError(reason) from None
    if settlement_problem:
        raise CatalogClientError(settlement_problem) from None
    return {
        "installed": installed,
        "transport": {
            "childReaped": True,
            "notificationCount": session.notifications,
            "stderrEmpty": not session.stderr_nonempty,
        },
        "vertical": vertical,
    }


def _short_string(value, *, nullable=False):
    return (
        value is None and nullable
        or type(value) is str and 0 < len(value) <= MAX_STRING
    )


def _source_valid(value):
    if not isinstance(value, dict) or value.get("type") not in SOURCE_CLASSES:
        return False
    source_type = value["type"]
    if source_type == "local":
        return _short_string(value.get("path"))
    if source_type == "git":
        return _short_string(value.get("url")) and all(
            _short_string(value.get(key), nullable=True)
            for key in ("path", "refName", "sha")
        )
    if source_type == "npm":
        return _short_string(value.get("package")) and all(
            _short_string(value.get(key), nullable=True)
            for key in ("registry", "version")
        )
    return set(value) == {"type"}


def _plugin_valid(value):
    required = {
        "authPolicy", "enabled", "id", "installPolicy", "installed", "name", "source"
    }
    return (
        isinstance(value, dict)
        and required.issubset(value)
        and all(_short_string(value.get(key)) for key in ("authPolicy", "id", "installPolicy", "name"))
        and type(value.get("enabled")) is bool
        and type(value.get("installed")) is bool
        and _source_valid(value.get("source"))
        and _short_string(value.get("remotePluginId"), nullable=True)
        and _short_string(value.get("version"), nullable=True)
        and _short_string(value.get("localVersion"), nullable=True)
    )


def _catalog_rows(value):
    if not isinstance(value, dict) or not isinstance(value.get("marketplaces"), list):
        raise CatalogClientError("catalog_shape")
    errors = value.get("marketplaceLoadErrors", [])
    if not isinstance(errors, list) or len(errors) > MAX_MARKETPLACES:
        raise CatalogClientError("catalog_shape")
    marketplaces = value["marketplaces"]
    if len(marketplaces) > MAX_MARKETPLACES:
        raise CatalogClientError("catalog_shape")
    rows = []
    for marketplace in marketplaces:
        if (
            not isinstance(marketplace, dict)
            or not _short_string(marketplace.get("name"))
            or not isinstance(marketplace.get("plugins"), list)
            or not _short_string(marketplace.get("path"), nullable=True)
        ):
            raise CatalogClientError("catalog_shape")
        for plugin in marketplace["plugins"]:
            if len(rows) >= MAX_PLUGINS or not _plugin_valid(plugin):
                raise CatalogClientError("catalog_shape")
            rows.append((marketplace["name"], plugin))
    return marketplaces, errors, rows


def _summary(value):
    marketplaces, errors, rows = _catalog_rows(value)
    source_counts = {source_type: 0 for source_type in SOURCE_CLASSES}
    identities = []
    names = {}
    remote_backend_ids = remote_backend_versions = local_versions = 0
    installed_true = enabled_true = 0
    for marketplace_name, plugin in rows:
        source_type = plugin["source"]["type"]
        source_counts[source_type] += 1
        identity = (marketplace_name, plugin["id"])
        identities.append(identity)
        if identity in names and names[identity] != plugin["name"]:
            raise CatalogClientError("catalog_shape")
        names[identity] = plugin["name"]
        installed_true += int(plugin["installed"] is True)
        enabled_true += int(plugin["enabled"] is True)
        local_versions += int(type(plugin.get("localVersion")) is str)
        if source_type == "remote":
            remote_backend_ids += int(type(plugin.get("remotePluginId")) is str)
            remote_backend_versions += int(type(plugin.get("version")) is str)
    return {
        "catalogLoadErrorCount": len(errors),
        "enabledTrueCount": enabled_true,
        "installedTrueCount": installed_true,
        "localVersionPresentCount": local_versions,
        "marketplaceCount": len(marketplaces),
        "pluginCount": len(rows),
        "remoteBackendIdPresentCount": remote_backend_ids,
        "remoteBackendVersionPresentCount": remote_backend_versions,
        "sourceClassCounts": source_counts,
        "uniquePluginIdentities": len(identities) == len(set(identities)),
    }, names


def _base_projection(reason_class, succeeded):
    return {
        "admission": {
            "configurationAdmission": False,
            "executionAdmission": False,
            "phase5PassClaimed": False,
            "phase6Authorized": False,
            "pluginAdmission": False,
        },
        "observationSucceeded": succeeded,
        "reasonClass": reason_class,
        "schema": 1,
        "task": "phase5_plugin_catalog_observation",
    }


def public_failure(reason_class):
    """Return a bounded public failure without exception or private text."""
    if type(reason_class) is not str or reason_class not in REASON_CLASSES or reason_class == "ok":
        reason_class = "protocol_malformed"
    return _base_projection(reason_class, False)


def public_projection(private_capture):
    """Project a private capture to counts, booleans and closed classes only."""
    try:
        if (
            not isinstance(private_capture, dict)
            or set(private_capture) != {"installed", "transport", "vertical"}
            or not isinstance(private_capture["transport"], dict)
            or set(private_capture["transport"])
            != {"childReaped", "notificationCount", "stderrEmpty"}
            or private_capture["transport"]["childReaped"] is not True
            or type(private_capture["transport"]["stderrEmpty"]) is not bool
            or type(private_capture["transport"]["notificationCount"]) is not int
            or not 0 <= private_capture["transport"]["notificationCount"] <= MAX_NOTIFICATIONS
        ):
            raise CatalogClientError("catalog_shape")
        installed, installed_ids = _summary(private_capture["installed"])
        vertical, vertical_ids = _summary(private_capture["vertical"])
        if any(installed_ids[key] != vertical_ids[key]
               for key in installed_ids.keys() & vertical_ids.keys()):
            raise CatalogClientError("catalog_shape")
    except Exception:
        return public_failure("catalog_shape")
    result = _base_projection("ok", True)
    result.update(
        {
            "catalogIdentityIntersectionCount": len(installed_ids.keys() & vertical_ids.keys()),
            "installed": installed,
            "transport": {
                "childReaped": True,
                "notificationCount": private_capture["transport"]["notificationCount"],
                "stderrEmpty": private_capture["transport"]["stderrEmpty"],
            },
            "vertical": vertical,
        }
    )
    return result
