#!/usr/bin/env python3
"""LoopCtrl Phase 0 relay: authenticated repeated-poll byte transport.

The relay never parses or decrypts LoopCtrl envelopes. A device registers with
a one-time enrollment token, repeatedly polls for work using its short-lived
device token, forwards each opaque request to its local LoopCtrl /rpc endpoint,
and posts the opaque response back. Operator requests are authenticated with a
separate process-level token.

Each poll is an ordinary HTTP request. The server may hold that request open
for up to `poll_timeout`, then answers `204`; the HTTP exchange closes after
every cycle. This is not a persistent TCP/TLS socket.

This is a local integration prototype. Put TLS in front of it for any
non-loopback deployment; the optional --certfile/--keyfile flags can serve TLS
directly for a disposable test.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import queue
import secrets
import ssl
import sys
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable
from urllib.parse import urlsplit

DEFAULT_ENROLLMENT_TTL = 5 * 60
# Phase 0 must outlive a 30-minute background test plus reconnect margin. A
# session is extended on every authenticated use; this is the maximum idle gap,
# not a limit on total session lifetime.
DEFAULT_DEVICE_TTL = 60 * 60
DEFAULT_POLL_TIMEOUT = 25.0
DEFAULT_OPERATOR_TIMEOUT = 60.0
DEFAULT_MAX_BODY_BYTES = 16 * 1024 * 1024
DEFAULT_MAX_PENDING = 4

_TOKEN_CONTEXT = b"loopctrl-relay-token-v1"


def _hash_token(token: str) -> bytes:
    return hashlib.sha256(_TOKEN_CONTEXT + token.encode("utf-8")).digest()


def _bearer(header: str | None) -> str | None:
    if not header:
        return None
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token:
        return None
    return token.strip()


def _safe_equal(left: str, right: str) -> bool:
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


@dataclass
class _PendingRequest:
    request_id: str
    body: bytes
    done: threading.Event = field(default_factory=threading.Event)
    status: int = 0
    response_body: bytes = b""
    content_type: str = "application/json"


@dataclass
class _DeviceSession:
    device_id: str
    token_hash: bytes
    name: str
    expires_at: float
    queue: queue.Queue[_PendingRequest] = field(
        default_factory=lambda: queue.Queue(maxsize=DEFAULT_MAX_PENDING)
    )
    in_flight: dict[str, _PendingRequest] = field(default_factory=dict)


class RelayState:
    def __init__(
        self,
        operator_token: str,
        *,
        enrollment_ttl: float = DEFAULT_ENROLLMENT_TTL,
        device_ttl: float = DEFAULT_DEVICE_TTL,
        poll_timeout: float = DEFAULT_POLL_TIMEOUT,
        operator_timeout: float = DEFAULT_OPERATOR_TIMEOUT,
        max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not operator_token:
            raise ValueError("operator token is required")
        self.operator_token = operator_token
        self.enrollment_ttl = enrollment_ttl
        self.device_ttl = device_ttl
        self.poll_timeout = poll_timeout
        self.operator_timeout = operator_timeout
        self.max_body_bytes = max_body_bytes
        # Wall-clock access goes through one seam so the no-poll-gap test can
        # advance time without sleeping for the full TTL.
        self._clock = clock
        self._lock = threading.Lock()
        self._enrollments: dict[bytes, float] = {}
        self._devices_by_token: dict[bytes, _DeviceSession] = {}
        self._devices_by_id: dict[str, _DeviceSession] = {}

    def is_operator(self, token: str | None) -> bool:
        return token is not None and _safe_equal(token, self.operator_token)

    def create_enrollment(self, ttl: float | None = None) -> tuple[str, int]:
        lifetime = self.enrollment_ttl if ttl is None else max(ttl, 0.0)
        token = secrets.token_urlsafe(32)
        expires_at = self._clock() + lifetime
        with self._lock:
            self._drop_expired_locked(self._clock())
            self._enrollments[_hash_token(token)] = expires_at
        return token, int(lifetime)

    def register_device(self, enrollment_token: str, name: str) -> dict[str, Any] | None:
        now = self._clock()
        token_hash = _hash_token(enrollment_token)
        with self._lock:
            expires_at = self._enrollments.pop(token_hash, None)
            if expires_at is None or expires_at <= now:
                return None
            device_id = self._new_device_id_locked()
            device_token = secrets.token_urlsafe(32)
            session = _DeviceSession(
                device_id=device_id,
                token_hash=_hash_token(device_token),
                name=name[:120],
                expires_at=now + self.device_ttl,
            )
            self._devices_by_token[session.token_hash] = session
            self._devices_by_id[device_id] = session
        return {
            "device_id": device_id,
            "device_token": device_token,
            "expires_in": int(self.device_ttl),
            "poll_timeout": int(self.poll_timeout),
        }

    def lookup_device_token(self, token: str | None) -> _DeviceSession | None:
        if not token:
            return None
        now = self._clock()
        with self._lock:
            session = self._devices_by_token.get(_hash_token(token))
            if session is None:
                return None
            if session.expires_at <= now:
                self._drop_session_locked(session)
                return None
            session.expires_at = now + self.device_ttl
            return session

    def lookup_device_id(self, device_id: str) -> _DeviceSession | None:
        now = self._clock()
        with self._lock:
            session = self._devices_by_id.get(device_id)
            if session is None:
                return None
            if session.expires_at <= now:
                self._drop_session_locked(session)
                return None
            session.expires_at = now + self.device_ttl
            return session

    def list_devices(self) -> list[dict[str, Any]]:
        now = self._clock()
        with self._lock:
            self._drop_expired_locked(now)
            return [
                {
                    "device_id": session.device_id,
                    "name": session.name,
                    "expires_in": max(0, int(session.expires_at - now)),
                    "pending": len(session.in_flight),
                }
                for session in sorted(
                    self._devices_by_id.values(), key=lambda item: item.device_id
                )
            ]

    def enqueue(
        self, session: _DeviceSession, body: bytes
    ) -> tuple[_PendingRequest | None, str | None]:
        pending = _PendingRequest(
            request_id=secrets.token_hex(16),
            body=body,
        )
        with self._lock:
            current = self._devices_by_id.get(session.device_id)
            if current is not session:
                return None, "device_unavailable"
            if len(session.in_flight) >= DEFAULT_MAX_PENDING:
                return None, "device_busy"
            session.in_flight[pending.request_id] = pending
        try:
            session.queue.put_nowait(pending)
        except queue.Full:
            with self._lock:
                session.in_flight.pop(pending.request_id, None)
            return None, "device_busy"
        return pending, None

    def take_request(
        self, session: _DeviceSession, timeout: float
    ) -> _PendingRequest | None:
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            try:
                pending = session.queue.get(timeout=remaining)
            except queue.Empty:
                return None
            with self._lock:
                if session.in_flight.get(pending.request_id) is pending:
                    return pending
            # The operator timed out and removed it while it was queued.

    def complete_request(
        self,
        session: _DeviceSession,
        request_id: str,
        status: int,
        body: bytes,
        content_type: str,
    ) -> bool:
        with self._lock:
            current = self._devices_by_id.get(session.device_id)
            if current is not session:
                return False
            pending = session.in_flight.pop(request_id, None)
            if pending is None:
                return False
            pending.status = status
            pending.response_body = body
            pending.content_type = content_type
            session.expires_at = self._clock() + self.device_ttl
        pending.done.set()
        return True

    def wait_for_response(
        self, pending: _PendingRequest, session: _DeviceSession
    ) -> bool:
        """Wait for a device response, but never past the device's TTL.

        A device that never polls again must release its pending operator
        request at session expiry; otherwise the operator waits for the full
        (possibly much longer) operator timeout while the request is already
        undeliverable. The wait is capped to the session deadline, and the
        session is dropped (signalling every pending request) when that
        deadline is reached.
        """
        started_at = self._clock()
        operator_deadline = started_at + self.operator_timeout
        while True:
            now = self._clock()
            with self._lock:
                current = self._devices_by_id.get(session.device_id)
                if current is not session or pending.request_id not in session.in_flight:
                    # A concurrent expiry/completion already owns the outcome.
                    return pending.done.is_set()
                device_deadline = session.expires_at
                if device_deadline <= now:
                    self._drop_session_locked(session)
                    return True
            if operator_deadline <= now:
                return False
            wait_for = min(operator_deadline - now, device_deadline - now)
            if pending.done.wait(timeout=wait_for):
                return True
            # Re-evaluate the live session after the wait. A device poll may
            # have extended it, or another thread may have dropped it.

    def expire_pending(self, pending: _PendingRequest) -> None:
        with self._lock:
            for session in list(self._devices_by_id.values()):
                if session.in_flight.get(pending.request_id) is pending:
                    session.in_flight.pop(pending.request_id, None)
                    return

    def _new_device_id_locked(self) -> str:
        while True:
            device_id = secrets.token_hex(8)
            if device_id not in self._devices_by_id:
                return device_id

    def _drop_session_locked(self, session: _DeviceSession) -> None:
        self._devices_by_token.pop(session.token_hash, None)
        self._devices_by_id.pop(session.device_id, None)
        for pending in list(session.in_flight.values()):
            pending.status = 410
            pending.response_body = b'{"error":"device_session_expired"}'
            pending.content_type = "application/json"
            pending.done.set()
        session.in_flight.clear()

    def _drop_expired_locked(self, now: float) -> None:
        for key, expires_at in list(self._enrollments.items()):
            if expires_at <= now:
                self._enrollments.pop(key, None)
        for session in list(self._devices_by_id.values()):
            if session.expires_at <= now:
                self._drop_session_locked(session)


class RelayHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], state: RelayState) -> None:
        self.state = state
        super().__init__(address, RelayRequestHandler)


class RelayRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "LoopCtrlRelay/0.1"
    sys_version = ""

    @property
    def relay(self) -> RelayState:
        server = self.server
        if not isinstance(server, RelayHTTPServer):
            raise RuntimeError("unexpected server type")
        return server.state

    def log_message(self, fmt: str, *args: Any) -> None:
        # BaseHTTPRequestHandler logs request bodies nowhere, but keep access
        # logging off by default so headers and future mistakes cannot leak.
        if os.environ.get("LOOPCTRL_RELAY_ACCESS_LOG") == "1":
            sys.stderr.write(
                "%s - %s\n" % (self.address_string(), fmt % args)
            )

    def _event(self, kind: str, **fields: Any) -> None:
        """One line per relay event for gap analysis: device ids, statuses,
        sizes and timings only — never tokens or bodies. Off unless
        LOOPCTRL_RELAY_EVENT_LOG=1."""
        if os.environ.get("LOOPCTRL_RELAY_EVENT_LOG") != "1":
            return
        parts = " ".join(f"{key}={value}" for key, value in fields.items())
        sys.stderr.write(f"{time.time():.3f} {kind} {parts}\n")
        sys.stderr.flush()

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path == "/healthz":
            self._json(200, {"ok": True, "phase": 0})
            return
        if path == "/v1/admin/devices":
            if not self._require_operator():
                return
            self._json(200, {"devices": self.relay.list_devices()})
            return
        self._json(404, {"error": "not_found"})

    def do_POST(self) -> None:
        path = urlsplit(self.path).path
        if path == "/v1/admin/enrollments":
            self._create_enrollment()
        elif path == "/v1/device/register":
            self._register_device()
        elif path == "/v1/device/poll":
            self._poll()
        elif path == "/v1/device/response":
            self._device_response()
        elif path.startswith("/v1/operator/devices/") and path.endswith("/rpc"):
            self._operator_rpc(path)
        else:
            self._json(404, {"error": "not_found"})

    def _create_enrollment(self) -> None:
        if not self._require_operator():
            return
        body = self._read_body(required=False, limit=4096)
        if body is None:
            return
        ttl: float | None = None
        if body:
            try:
                obj = json.loads(body)
            except (json.JSONDecodeError, UnicodeDecodeError):
                self._json(400, {"error": "bad_json"})
                return
            if not isinstance(obj, dict):
                self._json(400, {"error": "bad_json"})
                return
            raw_ttl = obj.get("expires_in")
            if raw_ttl is not None:
                if not isinstance(raw_ttl, (int, float)) or raw_ttl < 0:
                    self._json(400, {"error": "bad_expiry"})
                    return
                ttl = float(raw_ttl)
        token, expires_in = self.relay.create_enrollment(ttl)
        self._json(
            201,
            {
                "enrollment_token": token,
                "expires_in": expires_in,
                "single_use": True,
            },
        )

    def _register_device(self) -> None:
        enrollment_token = _bearer(self.headers.get("Authorization"))
        if enrollment_token is None:
            self._json(401, {"error": "unauthorized"})
            return
        body = self._read_body(required=False, limit=4096)
        if body is None:
            return
        name = "LoopCtrl device"
        if body:
            try:
                obj = json.loads(body)
            except (json.JSONDecodeError, UnicodeDecodeError):
                self._json(400, {"error": "bad_json"})
                return
            if not isinstance(obj, dict):
                self._json(400, {"error": "bad_json"})
                return
            candidate = obj.get("name")
            if candidate is not None:
                if not isinstance(candidate, str):
                    self._json(400, {"error": "bad_name"})
                    return
                name = candidate or name
        registered = self.relay.register_device(enrollment_token, name)
        if registered is None:
            self._event("register", status=401)
            self._json(401, {"error": "unauthorized"})
            return
        self._event("register", status=201, device=registered["device_id"])
        self._json(201, registered)

    def _poll(self) -> None:
        session = self.relay.lookup_device_token(
            _bearer(self.headers.get("Authorization"))
        )
        if session is None:
            self._event("poll", status=401)
            self._json(401, {"error": "unauthorized"})
            return
        started = time.monotonic()
        pending = self.relay.take_request(session, self.relay.poll_timeout)
        held = f"{time.monotonic() - started:.2f}"
        if pending is None:
            self._event("poll", device=session.device_id, status=204, held=held)
            self._empty(204)
            return
        self._event("poll", device=session.device_id, status=200, held=held,
                    request=pending.request_id[:8], bytes=len(pending.body))
        self._json(
            200,
            {
                "request_id": pending.request_id,
                "body_b64": base64.b64encode(pending.body).decode("ascii"),
                "expires_in": int(self.relay.device_ttl),
            },
        )

    def _device_response(self) -> None:
        session = self.relay.lookup_device_token(
            _bearer(self.headers.get("Authorization"))
        )
        if session is None:
            self._json(401, {"error": "unauthorized"})
            return
        body = self._read_body(required=True, limit=self.relay.max_body_bytes)
        if body is None:
            return
        try:
            obj = json.loads(body)
            request_id = obj["request_id"]
            status = obj["status"]
            response_body = base64.b64decode(obj["body_b64"], validate=True)
            content_type = obj.get("content_type", "application/json")
        except (json.JSONDecodeError, UnicodeDecodeError, KeyError, TypeError, ValueError):
            self._json(400, {"error": "bad_response"})
            return
        if (
            not isinstance(request_id, str)
            or not request_id
            or not isinstance(status, int)
            or status < 100
            or status > 599
            or not isinstance(content_type, str)
            or len(response_body) > self.relay.max_body_bytes
        ):
            self._json(400, {"error": "bad_response"})
            return
        if not self.relay.complete_request(
            session, request_id, status, response_body, content_type[:120]
        ):
            self._event("response", device=session.device_id, status=404)
            self._json(404, {"error": "unknown_request"})
            return
        self._event("response", device=session.device_id, request=request_id[:8],
                    rpc_status=status, bytes=len(response_body))
        self._json(200, {"ok": True})

    def _operator_rpc(self, path: str) -> None:
        if not self._require_operator():
            return
        prefix = "/v1/operator/devices/"
        device_id = path[len(prefix):-len("/rpc")]
        if not device_id or "/" in device_id:
            self._json(404, {"error": "not_found"})
            return
        session = self.relay.lookup_device_id(device_id)
        if session is None:
            self._json(404, {"error": "device_unavailable"})
            return
        body = self._read_body(required=True, limit=self.relay.max_body_bytes)
        if body is None:
            return
        if not body:
            self._json(400, {"error": "empty_request"})
            return
        started = time.monotonic()
        pending, failure = self.relay.enqueue(session, body)
        if pending is None:
            self._event("rpc", device=device_id, status=failure)
            self._json(429 if failure == "device_busy" else 410, {"error": failure})
            return
        if not self.relay.wait_for_response(pending, session):
            self.relay.expire_pending(pending)
            self._event("rpc", device=device_id, request=pending.request_id[:8],
                        status=504, ms=int((time.monotonic() - started) * 1000))
            self._json(504, {"error": "device_timeout"})
            return
        self._event("rpc", device=device_id, request=pending.request_id[:8],
                    status=pending.status, bytes_in=len(body),
                    bytes_out=len(pending.response_body),
                    ms=int((time.monotonic() - started) * 1000))
        self._body(
            pending.status,
            pending.content_type,
            pending.response_body,
            extra_headers={"X-LoopCtrl-Relay": "phase0"},
        )

    def _require_operator(self) -> bool:
        if self.relay.is_operator(_bearer(self.headers.get("Authorization"))):
            return True
        self._json(401, {"error": "unauthorized"})
        return False

    def _read_body(self, *, required: bool, limit: int) -> bytes | None:
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            if required:
                self._json(411, {"error": "content_length_required"})
                return None
            return b""
        try:
            length = int(raw_length)
        except ValueError:
            self._json(400, {"error": "bad_content_length"})
            return None
        if length < 0 or length > limit:
            self.close_connection = True
            self._json(413, {"error": "body_too_large"})
            return None
        body = self.rfile.read(length)
        if len(body) != length:
            self._json(400, {"error": "truncated_body"})
            return None
        return body

    def _json(self, status: int, obj: dict[str, Any]) -> None:
        body = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        self._body(status, "application/json", body)

    def _empty(self, status: int) -> None:
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True

    def _body(
        self,
        status: int,
        content_type: str,
        body: bytes,
        *,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type or "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        if extra_headers:
            for key, value in extra_headers.items():
                self.send_header(key, value)
        self.end_headers()
        if body:
            self.wfile.write(body)
        self.close_connection = True


def make_server(
    host: str,
    port: int,
    state: RelayState,
    *,
    certfile: str | None = None,
    keyfile: str | None = None,
) -> RelayHTTPServer:
    server = RelayHTTPServer((host, port), state)
    if certfile:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certfile=certfile, keyfile=keyfile)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    return server


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--certfile", help="optional PEM certificate")
    parser.add_argument("--keyfile", help="optional PEM private key")
    parser.add_argument(
        "--enrollment-ttl",
        type=int,
        default=DEFAULT_ENROLLMENT_TTL,
        help="seconds an enrollment token stays valid (default: 300)",
    )
    parser.add_argument(
        "--device-ttl",
        type=int,
        default=DEFAULT_DEVICE_TTL,
        help="seconds a device token survives without use (default: 3600)",
    )
    args = parser.parse_args()

    operator_token = os.environ.get("LOOPCTRL_RELAY_OPERATOR_TOKEN", "")
    if len(operator_token) < 24:
        print(
            "LOOPCTRL_RELAY_OPERATOR_TOKEN must be set to at least 24 characters",
            file=sys.stderr,
        )
        return 2
    if bool(args.certfile) != bool(args.keyfile):
        print("--certfile and --keyfile must be supplied together", file=sys.stderr)
        return 2

    state = RelayState(
        operator_token,
        enrollment_ttl=args.enrollment_ttl,
        device_ttl=args.device_ttl,
    )
    server = make_server(
        args.bind,
        args.port,
        state,
        certfile=args.certfile,
        keyfile=args.keyfile,
    )
    scheme = "https" if args.certfile else "http"
    print(
        f"LoopCtrl relay listening on {scheme}://{args.bind}:{server.server_port} "
        "(Phase 0; secrets are never logged)",
        flush=True,
    )
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
