"""One explicitly owned loopback fixture, not an execution/admission entry point.

Construct and retain the owner BEFORE calling start. All native-facing objects
are explicitly injected: an admitted socket module, Thread factory and monotonic
clock. Construction performs no native calls. Root owns the finite outer attempt
and must call stop even after start fails, retaining this owner on uncertainty.

health returns accepted-request count, NOT successful-response count. A request
is counted after its bounded GET headers validate, before send. Root independently
checks curl exit zero and exact body, then count1 / denied count1 / fresh count2.
Worker errors are private and never printed. Successful stop additionally checks
worker errors, so late send/close failure cannot become a passing fixture.

Socket timeouts and a two-second join are cooperative bounds, not hard kernel
deadlines. Never close the listener underneath a possibly live thread, kill a
thread, retry start, or rediscover descriptors. An uncertain close is attempted
once only; retained ownership is not a claim that the descriptor is closed.
"""

import math


BODY = b"phase5-loopback\n"
RESPONSE = b"HTTP/1.1 200 OK\r\nContent-Length: 16\r\nConnection: close\r\n\r\n" + BODY
MAX_REQUEST_BYTES = 1024
MAX_CONNECTIONS = 3
ACCEPT_TIMEOUT = 0.1
REQUEST_SECONDS = 0.75
JOIN_SECONDS = 2.0


class ProbeError(Exception):
    def __init__(self, owner):
        self.private_owner = owner
        self.settlement_failed = not owner.settled
        super().__init__("loopback_probe_required")


def _require(value):
    if value is not True:
        raise ValueError("loopback_probe_required") from None


class _Socket:
    def __init__(self, value):
        self.value, self.close_attempted, self.closed = value, False, False

    def __repr__(self):
        return "<private loopback socket>"


class LoopbackProbe:
    def __init__(self, *, socket_api, thread_factory, clock):
        self._api, self._thread_factory, self._clock = socket_api, thread_factory, clock
        self._listener = self._thread = self._address = self._fd = None
        self._connections, self.private_errors = [], []
        self._first_errors = {}
        self._start_attempted = self._thread_start_attempted = self._thread_start_returned = False
        self._socket_pending = self._accept_pending = False
        self._worker_finished = self._thread_settled = self._stop_requested = False
        self._accepted = 0

    def __repr__(self):
        return "<private loopback probe>"

    @property
    def settled(self):
        return (self._thread_settled and not self._socket_pending and not self._accept_pending
                and (self._listener is None or self._listener.closed)
                and all(owner.closed for owner in self._connections))

    @property
    def private_error(self):
        # Read ordinary first, then interruption last. No producer publishes a
        # cached selection which could overwrite the other producer's priority.
        ordinary = self._first_errors.get("ordinary")
        return self._first_errors.get("interrupt", ordinary)

    def _record(self, error):
        # Exact builtin-dict setdefault on constant string keys is the publication
        # point in the admitted CPython runtime. Each category is write-once;
        # ordinary publication cannot overwrite a published KI/SystemExit.
        category = "interrupt" if isinstance(error, (KeyboardInterrupt, SystemExit)) else "ordinary"
        self._first_errors.setdefault(category, error)
        # There is no retry loop: one worker failure plus bounded cleanup errors.
        if len(self.private_errors) < 8 and not any(error is previous for previous in self.private_errors):
            self.private_errors.append(error)

    def _raise(self):
        error = self.private_error
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            error.private_owner = self
            error.settlement_failed = not self.settled
            raise error from None
        raise ProbeError(self) from None

    def _close(self, owner):
        if owner is None or owner.close_attempted:
            return
        owner.close_attempted = True
        try:
            owner.value.close()
            owner.closed = True
        except BaseException as error:
            self._record(error)

    def _now(self):
        value = self._clock()
        _require(type(value) in (int, float) and math.isfinite(value))
        return value

    def _same_listener(self):
        _require(self._listener is not None and not self._listener.close_attempted)
        _require(self._listener.value.getsockname() == self._address
                 and self._listener.value.fileno() == self._fd)

    def start(self):
        """One start only; return the private ephemeral port, not admission."""
        try:
            _require(not self._start_attempted and not self._stop_requested)
            self._start_attempted = True
            self._socket_pending = True
            self._listener = _Socket(self._api.socket(self._api.AF_INET, self._api.SOCK_STREAM))
            self._socket_pending = False
            listener = self._listener.value
            listener.settimeout(ACCEPT_TIMEOUT)
            listener.bind(("127.0.0.1", 0))
            self._address, self._fd = listener.getsockname(), listener.fileno()
            _require(type(self._address) is tuple and len(self._address) == 2
                     and self._address[0] == "127.0.0.1" and type(self._address[1]) is int
                     and 1 <= self._address[1] <= 65535 and type(self._fd) is int and self._fd >= 0)
            listener.listen(1)
            self._thread = self._thread_factory(target=self._worker, daemon=False)
            self._thread_start_attempted = True
            self._thread.start()
            self._thread_start_returned = True
            _require(self._thread.is_alive() is True)
            self._same_listener()
            if self.private_error is not None:
                self._raise()
            return self._address[1]
        except BaseException as error:
            self._stop_requested = True
            self._record(error)
        self._raise()

    def _timeout(self, connection, deadline):
        remaining = deadline - self._now()
        _require(0 < remaining <= REQUEST_SECONDS)
        connection.settimeout(min(ACCEPT_TIMEOUT, remaining))

    def _serve(self, connection):
        deadline, request = self._now() + REQUEST_SECONDS, b""
        for _ in range(MAX_REQUEST_BYTES):
            if self._stop_requested:
                return
            self._timeout(connection, deadline)
            try:
                chunk = connection.recv(MAX_REQUEST_BYTES - len(request))
            except self._api.timeout:
                continue
            _require(type(chunk) is bytes and 0 < len(chunk) <= MAX_REQUEST_BYTES - len(request))
            request += chunk
            if b"\r\n\r\n" in request:
                break
            _require(len(request) < MAX_REQUEST_BYTES)
        _require(request.endswith(b"\r\n\r\n") and request.count(b"\r\n\r\n") == 1
                 and b"\x00" not in request)
        lines = request[:-4].split(b"\r\n")
        _require(lines[0] in (b"GET /phase5 HTTP/1.0", b"GET /phase5 HTTP/1.1"))
        headers = {}
        for line in lines[1:]:
            key, separator, value = line.partition(b":")
            key = key.lower()
            _require(separator == b":" and bool(key) and key not in headers and key.strip() == key)
            headers[key] = value.strip()
        _require(b"transfer-encoding" not in headers and headers.get(b"content-length", b"0") == b"0")
        self._accepted += 1  # Accepted request only; curl independently proves full response.
        sent = 0
        for _ in range(len(RESPONSE)):
            if self._stop_requested:
                return
            self._timeout(connection, deadline)
            try:
                count = connection.send(RESPONSE[sent:])
            except self._api.timeout:
                continue
            _require(type(count) is int and 0 < count <= len(RESPONSE) - sent)
            sent += count
            if sent == len(RESPONSE):
                return
        raise ValueError("loopback_probe_required")

    def _worker(self):
        try:
            while not self._stop_requested:
                _require(len(self._connections) < MAX_CONNECTIONS)
                self._accept_pending = True
                try:
                    accepted = self._listener.value.accept()
                except self._api.timeout:
                    self._accept_pending = False
                    continue
                if any(accepted[0] is old.value for old in self._connections):
                    self._accept_pending = False  # Already retained, never close it twice.
                    raise ValueError("loopback_probe_required")
                owner = _Socket(accepted[0])
                self._connections.append(owner)  # Own before peer/setup/IO checks.
                self._accept_pending = False
                try:
                    _require(type(accepted[1]) is tuple and len(accepted[1]) == 2
                             and accepted[1][0] == "127.0.0.1")
                    self._serve(owner.value)
                except BaseException as error:
                    self._record(error)  # Preserve the first interruption before close.
                finally:
                    self._close(owner)
                if self.private_error is not None:
                    break
        except BaseException as error:
            self._record(error)
        finally:
            self._worker_finished = True

    def health(self):
        """Return only accepted-request count; errors retain this private owner."""
        try:
            _require(self._thread_start_returned and not self._stop_requested
                     and self._thread.is_alive() is True and not self._worker_finished)
            self._same_listener()
            _require(type(self._accepted) is int and 0 <= self._accepted <= MAX_CONNECTIONS)
            if self.private_error is not None:
                self._raise()
            return self._accepted
        except BaseException as error:
            self._stop_requested = True
            self._record(error)
        self._raise()

    def stop(self):
        """Bounded join; explicit later calls may recheck, never re-close a socket.

        After an interrupted start, is_alive=False alone does not prove no thread
        can start. Require completed worker or a returned start before settlement.
        No join or descriptor is looked up by numeric identity.
        """
        self._stop_requested = True
        try:
            if not self._thread_start_attempted:
                self._thread_settled = True
            elif not self._thread_settled:
                alive = self._thread.is_alive()
                _require(type(alive) is bool)
                _require(self._thread_start_returned or alive or self._worker_finished)
                self._thread.join(JOIN_SECONDS)
                _require(self._thread.is_alive() is False and self._worker_finished)
                self._thread_settled = True
        except BaseException as error:
            self._record(error)
        if self._thread_settled:
            self._close(self._listener)
        if self.private_error is not None or not self.settled:
            self._raise()
        return True
