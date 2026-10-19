#!/usr/bin/env python3
"""LoopCtrl relay: invite enrollment plus a repeated-poll byte transport.

Implements the relay API in docs/relay-enrollment.md:

- an operator mints a one-time connection code naming the operators (by the
  SHA-256 of their X25519 pairing key) the phone should trust;
- the phone previews the code, then redeems it with an Ed25519 key it made
  itself, proving it holds that key;
- from then on the phone authenticates with that key (challenge, signature,
  short-lived device token) and polls for work;
- operators send opaque /pair and /rpc bodies, which the phone hands to its
  local runner as relayed requests and answers.

The relay never parses or decrypts LoopCtrl envelopes. Each poll is an
ordinary HTTP request held for up to `poll_timeout`, then `204`; no socket is
kept open between cycles.

Standard library only. Put TLS in front of it (nginx) for any non-loopback
deployment. Device records (public key, name, operators) are kept in a JSON
state file so a restart doesn't unbind every phone; codes, tokens and
challenges live in memory only. Tokens are stored as digests and nothing logs
tokens or bodies.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import queue
import re
import secrets
import ssl
import sys
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable
from urllib.parse import quote, urlsplit

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ed25519  # noqa: E402

API_VERSION = 1
DEFAULT_CODE_TTL = 10 * 60
MAX_CODE_TTL = 24 * 60 * 60
# A session is extended on every authenticated use; this is the maximum idle
# gap, not a limit on its lifetime. The phone re-authenticates with its key
# whenever it lapses, so this can be short.
DEFAULT_DEVICE_TTL = 60 * 60
DEFAULT_POLL_TIMEOUT = 25.0
DEFAULT_OPERATOR_TIMEOUT = 90.0
DEFAULT_MAX_BODY_BYTES = 16 * 1024 * 1024
DEFAULT_MAX_PENDING = 4
CHALLENGE_TTL = 60.0
UNBIND_SKEW = 300
# Unauthenticated enrollment calls per source address per minute.
ENROLL_RATE = 20
AUTH_RATE = 60

CODE_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
CODE_LENGTH = 8
KEY_ID = re.compile(r"^[0-9a-f]{64}$")
DEVICE_ID = re.compile(r"^dev_[0-9a-f]{16}$")
KNOWN_CAPABILITIES = ("view_screen", "control", "launch_apps", "read_text")

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


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def unb64url(text: str) -> bytes | None:
    if not isinstance(text, str):
        return None
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (ValueError, TypeError):
        return None


def normalize_code(raw: Any) -> str | None:
    """Same rules as the app: upper-case, drop separators, O→0, I/L→1."""
    if not isinstance(raw, str):
        return None
    out = []
    for ch in raw.upper():
        if ch in "- ‐‑–—":
            continue
        ch = {"O": "0", "I": "1", "L": "1"}.get(ch, ch)
        if ch not in CODE_ALPHABET:
            return None
        out.append(ch)
    return "".join(out) if len(out) == CODE_LENGTH else None


def normalize_server(raw: str) -> str:
    """`host[:port][/path]` as the phone names this relay in signatures:
    no scheme, lower-case host, no trailing slash."""
    s = raw.strip()
    for prefix in ("https://", "http://"):
        if s.lower().startswith(prefix):
            s = s[len(prefix):]
    s = s.rstrip("/")
    host, sep, path = s.partition("/")
    return host.lower() + (sep + path if path else "")


def enroll_message(code: str, server: str) -> bytes:
    return f"loopctrl-enroll-v1\n{code}\n{server}".encode("utf-8")


def channel_message(nonce: str, server: str) -> bytes:
    return f"loopctrl-channel-v1\n{nonce}\n{server}".encode("utf-8")


def unbind_message(device_id: str, ts: int, server: str) -> bytes:
    return f"loopctrl-unbind-v1\n{device_id}\n{ts}\n{server}".encode("utf-8")


@dataclass
class _Code:
    organization: str
    operators: list[dict[str, str]]
    capabilities: list[str]
    expires_at: float
    used: bool = False


@dataclass
class _Device:
    device_id: str
    public_key: bytes
    name: str
    organization: str
    operators: list[dict[str, str]]
    enrolled_at: float

    def record(self) -> dict[str, Any]:
        return {
            "device_id": self.device_id,
            "public_key": b64url(self.public_key),
            "name": self.name,
            "organization": self.organization,
            "operators": self.operators,
            "enrolled_at": int(self.enrolled_at),
        }


@dataclass
class _PendingRequest:
    request_id: str
    path: str
    body: bytes
    done: threading.Event = field(default_factory=threading.Event)
    status: int = 0
    response_body: bytes = b""
    content_type: str = "application/json"


@dataclass
class _Session:
    """A device's live channel: its current token and the work waiting for it.
    Re-authenticating swaps the token and keeps the queue."""
    device_id: str
    token_hash: bytes
    expires_at: float
    queue: queue.Queue[_PendingRequest] = field(
        default_factory=lambda: queue.Queue(maxsize=DEFAULT_MAX_PENDING)
    )
    in_flight: dict[str, _PendingRequest] = field(default_factory=dict)
    last_poll: float = 0.0


class RelayState:
    def __init__(
        self,
        operator_token: str,
        public_server: str,
        *,
        state_file: str | None = None,
        default_organization: str = "LoopCtrl Relay",
        device_ttl: float = DEFAULT_DEVICE_TTL,
        poll_timeout: float = DEFAULT_POLL_TIMEOUT,
        operator_timeout: float = DEFAULT_OPERATOR_TIMEOUT,
        max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not operator_token:
            raise ValueError("operator token is required")
        if not public_server:
            raise ValueError("public server name is required")
        self.operator_token = operator_token
        self.server = normalize_server(public_server)
        self.state_file = state_file
        self.default_organization = default_organization
        self.device_ttl = device_ttl
        self.poll_timeout = poll_timeout
        self.operator_timeout = operator_timeout
        self.max_body_bytes = max_body_bytes
        # Wall-clock access goes through one seam so tests can move time.
        self._clock = clock
        self._lock = threading.Lock()
        self._codes: dict[str, _Code] = {}
        self._devices: dict[str, _Device] = {}
        self._challenges: dict[str, tuple[str, float]] = {}
        self._sessions: dict[str, _Session] = {}
        self._by_token: dict[bytes, _Session] = {}
        self._rate: dict[tuple[str, str], list[float]] = {}
        self._load()

    # ------------------------------------------------------------ persistence

    def _load(self) -> None:
        if not self.state_file or not os.path.exists(self.state_file):
            return
        with open(self.state_file, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        for rec in data.get("devices", []):
            key = unb64url(rec.get("public_key", ""))
            if not key or len(key) != 32 or not DEVICE_ID.match(rec.get("device_id", "")):
                continue
            self._devices[rec["device_id"]] = _Device(
                device_id=rec["device_id"],
                public_key=key,
                name=str(rec.get("name", ""))[:120],
                organization=str(rec.get("organization", "")),
                operators=list(rec.get("operators", [])),
                enrolled_at=float(rec.get("enrolled_at", 0)),
            )

    def _save_locked(self) -> None:
        if not self.state_file:
            return
        data = {"version": 1, "devices": [d.record() for d in self._devices.values()]}
        tmp = self.state_file + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=1)
        os.replace(tmp, self.state_file)

    # ----------------------------------------------------------------- limits

    def allow(self, bucket: str, address: str, per_minute: int) -> bool:
        now = self._clock()
        with self._lock:
            hits = [t for t in self._rate.get((bucket, address), []) if t > now - 60]
            if len(hits) >= per_minute:
                self._rate[(bucket, address)] = hits
                return False
            hits.append(now)
            self._rate[(bucket, address)] = hits
            if len(self._rate) > 10_000:
                self._rate = {k: v for k, v in self._rate.items() if v and v[-1] > now - 60}
            return True

    def is_operator(self, token: str | None) -> bool:
        return token is not None and hmac.compare_digest(
            token.encode("utf-8"), self.operator_token.encode("utf-8")
        )

    # ------------------------------------------------------------- enrollment

    def create_code(
        self,
        operators: list[dict[str, str]],
        organization: str | None = None,
        capabilities: list[str] | None = None,
        ttl: float = DEFAULT_CODE_TTL,
    ) -> tuple[str, float]:
        now = self._clock()
        with self._lock:
            self._drop_expired_locked(now)
            while True:
                code = "".join(secrets.choice(CODE_ALPHABET) for _ in range(CODE_LENGTH))
                if code not in self._codes:
                    break
            self._codes[code] = _Code(
                organization=organization or self.default_organization,
                operators=operators,
                capabilities=list(capabilities if capabilities is not None else KNOWN_CAPABILITIES),
                expires_at=now + ttl,
            )
        return code, now + ttl

    def invite_link(self, code: str, expires_at: float, operators: list[dict[str, str]]) -> str:
        parts = [f"v={API_VERSION}", "server=" + quote(self.server, safe=":/"), "code=" + code]
        if operators:
            parts.append("op=" + ",".join(op["key_id"] for op in operators))
        parts.append(f"exp={int(expires_at)}")
        return "loopctrl://connect?" + "&".join(parts)

    def _code_locked(self, code: str | None, now: float) -> tuple[_Code | None, str | None]:
        entry = self._codes.get(code or "")
        if entry is None:
            return None, "invalid_code"
        if entry.used or entry.expires_at <= now:
            return None, "expired_code"
        return entry, None

    def preview(self, raw_code: Any) -> tuple[dict[str, Any] | None, str | None]:
        code = normalize_code(raw_code)
        with self._lock:
            entry, error = self._code_locked(code, self._clock())
            if entry is None:
                return None, error
            return {
                "organization": entry.organization,
                "operators": entry.operators,
                "capabilities": entry.capabilities,
                "code_expires_at": int(entry.expires_at),
            }, None

    def redeem(
        self, raw_code: Any, public_key: bytes, name: str, proof: bytes
    ) -> tuple[dict[str, Any] | None, str | None]:
        code = normalize_code(raw_code)
        now = self._clock()
        with self._lock:
            entry, error = self._code_locked(code, now)
            if entry is None:
                return None, error
            # Checked before the code is spent, so a bad proof can't burn it.
            if not ed25519.verify(public_key, enroll_message(code, self.server), proof):
                return None, "bad_proof"
            entry.used = True
            while True:
                device_id = "dev_" + secrets.token_hex(8)
                if device_id not in self._devices:
                    break
            device = _Device(
                device_id=device_id,
                public_key=public_key,
                name=name[:120] or "LoopCtrl device",
                organization=entry.organization,
                operators=entry.operators,
                enrolled_at=now,
            )
            self._devices[device_id] = device
            self._save_locked()
        return {
            "device_id": device_id,
            "organization": device.organization,
            "operators": device.operators,
            "poll_timeout": int(self.poll_timeout),
        }, None

    # ------------------------------------------------------------ device auth

    def challenge(self, device_id: Any) -> str | None:
        if not isinstance(device_id, str):
            return None
        now = self._clock()
        with self._lock:
            if device_id not in self._devices:
                return None
            nonce = b64url(secrets.token_bytes(32))
            self._challenges[device_id] = (nonce, now + CHALLENGE_TTL)
            return nonce

    def open_session(
        self, device_id: Any, nonce: Any, signature: bytes
    ) -> tuple[dict[str, Any] | None, str | None]:
        if not isinstance(device_id, str) or not isinstance(nonce, str):
            return None, "bad_request"
        now = self._clock()
        with self._lock:
            device = self._devices.get(device_id)
            if device is None:
                return None, "unknown_device"
            pending = self._challenges.pop(device_id, None)
            if pending is None or pending[1] <= now or not hmac.compare_digest(pending[0], nonce):
                return None, "bad_challenge"
            if not ed25519.verify(device.public_key, channel_message(nonce, self.server), signature):
                return None, "bad_signature"
            token = secrets.token_urlsafe(32)
            token_hash = _hash_token(token)
            session = self._sessions.get(device_id)
            if session is None:
                session = _Session(device_id=device_id, token_hash=token_hash,
                                   expires_at=now + self.device_ttl)
                self._sessions[device_id] = session
            else:
                self._by_token.pop(session.token_hash, None)
                session.token_hash = token_hash
                session.expires_at = now + self.device_ttl
            self._by_token[token_hash] = session
        return {
            "device_token": token,
            "expires_in": int(self.device_ttl),
            "poll_timeout": int(self.poll_timeout),
        }, None

    def unbind(self, device_id: str, ts: int, signature: bytes) -> str | None:
        now = self._clock()
        with self._lock:
            device = self._devices.get(device_id)
            if device is None:
                return "unknown_device"
            if abs(now - ts) > UNBIND_SKEW:
                return "ts_skew"
            if not ed25519.verify(device.public_key, unbind_message(device_id, ts, self.server), signature):
                return "bad_signature"
            self._drop_device_locked(device_id)
            self._save_locked()
        return None

    def session_for_token(self, token: str | None) -> _Session | None:
        if not token:
            return None
        now = self._clock()
        with self._lock:
            session = self._by_token.get(_hash_token(token))
            if session is None:
                return None
            if session.expires_at <= now:
                self._drop_session_locked(session)
                return None
            session.expires_at = now + self.device_ttl
            return session

    def live_session(self, device_id: str) -> tuple[_Session | None, str | None]:
        now = self._clock()
        with self._lock:
            if device_id not in self._devices:
                return None, "unknown_device"
            session = self._sessions.get(device_id)
            if session is None:
                return None, "device_offline"
            if session.expires_at <= now:
                self._drop_session_locked(session)
                return None, "device_offline"
            return session, None

    def list_devices(self) -> list[dict[str, Any]]:
        now = self._clock()
        with self._lock:
            self._drop_expired_locked(now)
            out = []
            for device in sorted(self._devices.values(), key=lambda d: d.enrolled_at):
                session = self._sessions.get(device.device_id)
                out.append({
                    "device_id": device.device_id,
                    "name": device.name,
                    "organization": device.organization,
                    "operators": device.operators,
                    "online": session is not None and now - session.last_poll < self.poll_timeout + 30,
                    "pending": len(session.in_flight) if session else 0,
                })
            return out

    # -------------------------------------------------------------- transport

    def enqueue(
        self, session: _Session, path: str, body: bytes
    ) -> tuple[_PendingRequest | None, str | None]:
        if path not in {"/rpc", "/pair"}:
            return None, "unsupported_path"
        pending = _PendingRequest(request_id=secrets.token_hex(16), path=path, body=body)
        with self._lock:
            if self._sessions.get(session.device_id) is not session:
                return None, "device_offline"
            if len(session.in_flight) >= DEFAULT_MAX_PENDING:
                return None, "device_busy"
            session.in_flight[pending.request_id] = pending
        try:
            session.queue.put_nowait(pending)
        except queue.Full:
            # Requests whose operator already gave up stay queued until a poll
            # discards them; with the phone away they would make every later
            # request "busy". Drop them and try once more.
            self._purge_stale(session)
            try:
                session.queue.put_nowait(pending)
            except queue.Full:
                with self._lock:
                    session.in_flight.pop(pending.request_id, None)
                return None, "device_busy"
        return pending, None

    def _purge_stale(self, session: _Session) -> None:
        kept: list[_PendingRequest] = []
        while True:
            try:
                item = session.queue.get_nowait()
            except queue.Empty:
                break
            with self._lock:
                if session.in_flight.get(item.request_id) is item:
                    kept.append(item)
        for item in kept:
            try:
                session.queue.put_nowait(item)
            except queue.Full:
                break

    def take_request(self, session: _Session, timeout: float) -> _PendingRequest | None:
        session.last_poll = self._clock()
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            try:
                pending = session.queue.get(timeout=remaining)
            except queue.Empty:
                return None
            finally:
                session.last_poll = self._clock()
            with self._lock:
                if session.in_flight.get(pending.request_id) is pending:
                    return pending
            # The operator gave up while it was queued.

    def complete_request(
        self, session: _Session, request_id: str, status: int, body: bytes, content_type: str
    ) -> bool:
        with self._lock:
            if self._sessions.get(session.device_id) is not session:
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

    def wait_for_response(self, pending: _PendingRequest, session: _Session) -> bool:
        """Wait for the phone's answer, but never past its session's expiry."""
        operator_deadline = self._clock() + self.operator_timeout
        while True:
            now = self._clock()
            with self._lock:
                if (self._sessions.get(session.device_id) is not session
                        or pending.request_id not in session.in_flight):
                    return pending.done.is_set()
                device_deadline = session.expires_at
                if device_deadline <= now:
                    self._drop_session_locked(session)
                    return True
            if operator_deadline <= now:
                return False
            if pending.done.wait(timeout=min(operator_deadline - now, device_deadline - now)):
                return True

    def expire_pending(self, pending: _PendingRequest) -> None:
        with self._lock:
            for session in self._sessions.values():
                if session.in_flight.get(pending.request_id) is pending:
                    session.in_flight.pop(pending.request_id, None)
                    return

    # ---------------------------------------------------------------- cleanup

    def _drop_session_locked(self, session: _Session, reason: bytes = b'{"error":"device_offline"}') -> None:
        self._by_token.pop(session.token_hash, None)
        if self._sessions.get(session.device_id) is session:
            self._sessions.pop(session.device_id, None)
        for pending in list(session.in_flight.values()):
            pending.status = 410
            pending.response_body = reason
            pending.content_type = "application/json"
            pending.done.set()
        session.in_flight.clear()

    def _drop_device_locked(self, device_id: str) -> None:
        self._devices.pop(device_id, None)
        self._challenges.pop(device_id, None)
        session = self._sessions.get(device_id)
        if session is not None:
            self._drop_session_locked(session, b'{"error":"device_unbound"}')

    def _drop_expired_locked(self, now: float) -> None:
        for code, entry in list(self._codes.items()):
            # Spent codes linger until expiry so a second redeem says "used".
            if entry.expires_at <= now:
                self._codes.pop(code, None)
        for device_id, (_, expires) in list(self._challenges.items()):
            if expires <= now:
                self._challenges.pop(device_id, None)
        for session in list(self._sessions.values()):
            if session.expires_at <= now:
                self._drop_session_locked(session)


_ERROR_STATUS = {
    "invalid_code": 404,
    "expired_code": 410,
    "bad_proof": 400,
    "bad_request": 400,
    "unknown_device": 404,
    "bad_challenge": 401,
    "bad_signature": 401,
    "ts_skew": 401,
    "device_offline": 503,
    "device_busy": 429,
    "unsupported_path": 400,
}

_ERROR_MESSAGE = {
    "invalid_code": "No such connection code.",
    "expired_code": "This connection code has expired or was already used.",
    "bad_proof": "The enrollment proof does not verify for this server.",
    "unknown_device": "This device is not enrolled here.",
    "bad_challenge": "Unknown or expired challenge.",
    "bad_signature": "Signature does not verify.",
    "ts_skew": "Timestamp too far from server time.",
    "device_offline": "The device has no live channel.",
    "device_busy": "Too many requests in flight for this device.",
    "rate_limited": "Too many requests; slow down.",
}


class RelayHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], state: RelayState) -> None:
        self.state = state
        super().__init__(address, RelayRequestHandler)

    def handle_error(self, request: Any, client_address: Any) -> None:
        # A phone that backgrounds or switches networks legitimately closes a
        # held poll. Treat that disconnect as completion, not a server failure.
        if isinstance(sys.exc_info()[1], (BrokenPipeError, ConnectionResetError)):
            return
        super().handle_error(request, client_address)


class RelayRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "LoopCtrlRelay/1"
    sys_version = ""

    @property
    def relay(self) -> RelayState:
        server = self.server
        if not isinstance(server, RelayHTTPServer):
            raise RuntimeError("unexpected server type")
        return server.state

    def log_message(self, fmt: str, *args: Any) -> None:
        if os.environ.get("LOOPCTRL_RELAY_ACCESS_LOG") == "1":
            sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _event(self, kind: str, **fields: Any) -> None:
        """One line per relay event: ids, statuses, sizes and timings only,
        never tokens or bodies. Off unless LOOPCTRL_RELAY_EVENT_LOG=1."""
        if os.environ.get("LOOPCTRL_RELAY_EVENT_LOG") != "1":
            return
        parts = " ".join(f"{key}={value}" for key, value in fields.items())
        sys.stderr.write(f"{time.time():.3f} {kind} {parts}\n")
        sys.stderr.flush()

    def _source(self) -> str:
        # Behind nginx every peer is loopback; trust its header only then.
        peer = self.client_address[0]
        if peer in ("127.0.0.1", "::1"):
            return self.headers.get("X-Real-IP", peer)
        return peer

    # ----------------------------------------------------------------- routes

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path == "/healthz":
            self._json(200, {"ok": True, "api": API_VERSION, "server": self.relay.server})
        elif path == "/v1/admin/devices":
            if self._require_operator():
                self._json(200, {"devices": self.relay.list_devices()})
        else:
            self._json(404, {"error": "not_found"})

    def do_POST(self) -> None:
        path = urlsplit(self.path).path
        routes = {
            "/v1/admin/enrollments": self._create_enrollment,
            "/v1/enroll/preview": self._preview,
            "/v1/enroll/redeem": self._redeem,
            "/v1/device/challenge": self._challenge,
            "/v1/device/session": self._session,
            "/v1/device/poll": self._poll,
            "/v1/device/response": self._device_response,
        }
        if path in routes:
            routes[path]()
        elif path.startswith("/v1/operator/devices/") and (path.endswith("/rpc") or path.endswith("/pair")):
            self._operator_forward(path)
        else:
            self._json(404, {"error": "not_found"})

    def do_DELETE(self) -> None:
        path = urlsplit(self.path).path
        prefix = "/v1/devices/"
        if path.startswith(prefix) and DEVICE_ID.match(path[len(prefix):]):
            self._unbind(path[len(prefix):])
        else:
            self._json(404, {"error": "not_found"})

    # --------------------------------------------------------------- operator

    def _create_enrollment(self) -> None:
        if not self._require_operator():
            return
        obj = self._json_body(required=False)
        if obj is None:
            return
        operators = []
        for op in obj.get("operators", []):
            if not isinstance(op, dict):
                return self._error("bad_request", "operators must be objects")
            key_id = str(op.get("key_id", "")).lower()
            if not KEY_ID.match(key_id):
                return self._error("bad_request", "operators[].key_id must be 64 hex characters")
            name = op.get("name")
            if not isinstance(name, str) or not name.strip():
                return self._error("bad_request", "operators[].name is required")
            operators.append({"name": name.strip()[:80], "key_id": key_id})
        capabilities = obj.get("capabilities")
        if capabilities is not None and (
            not isinstance(capabilities, list) or not all(isinstance(c, str) for c in capabilities)
        ):
            return self._error("bad_request", "capabilities must be a list of strings")
        ttl = obj.get("expires_in", DEFAULT_CODE_TTL)
        if not isinstance(ttl, (int, float)) or not 0 < ttl <= MAX_CODE_TTL:
            return self._error("bad_request", "expires_in must be 1..86400 seconds")
        organization = obj.get("organization")
        if organization is not None and not isinstance(organization, str):
            return self._error("bad_request", "organization must be a string")
        code, expires_at = self.relay.create_code(
            operators, organization=(organization or "").strip()[:80] or None,
            capabilities=capabilities, ttl=float(ttl),
        )
        self._event("enroll", operators=len(operators))
        self._json(201, {
            "code": code,
            "display_code": f"{code[:4]}-{code[4:]}",
            "expires_at": int(expires_at),
            "server": self.relay.server,
            "invite": self.relay.invite_link(code, expires_at, operators),
        })

    def _operator_forward(self, path: str) -> None:
        if not self._require_operator():
            return
        prefix = "/v1/operator/devices/"
        endpoint = "/rpc" if path.endswith("/rpc") else "/pair"
        device_id = path[len(prefix):-len(endpoint)]
        if not DEVICE_ID.match(device_id):
            return self._json(404, {"error": "not_found"})
        session, failure = self.relay.live_session(device_id)
        if session is None:
            return self._error(failure or "device_offline")
        body = self._read_body(required=True, limit=self.relay.max_body_bytes)
        if body is None:
            return
        if not body:
            return self._error("bad_request", "empty request")
        started = time.monotonic()
        pending, failure = self.relay.enqueue(session, endpoint, body)
        if pending is None:
            self._event("forward", device=device_id, status=failure)
            return self._error(failure or "device_offline")
        if not self.relay.wait_for_response(pending, session):
            self.relay.expire_pending(pending)
            self._event("forward", device=device_id, path=endpoint, status=504)
            return self._json(504, {"error": "device_timeout"})
        self._event("forward", device=device_id, path=endpoint, status=pending.status,
                    ms=int((time.monotonic() - started) * 1000))
        self._body(pending.status, pending.content_type, pending.response_body,
                   extra_headers={"X-LoopCtrl-Relay": str(API_VERSION)})

    # ------------------------------------------------------------- enrollment

    def _preview(self) -> None:
        if not self.relay.allow("enroll", self._source(), ENROLL_RATE):
            return self._error("rate_limited", status=429)
        obj = self._json_body(required=True)
        if obj is None:
            return
        info, error = self.relay.preview(obj.get("code"))
        if info is None:
            return self._error(error or "invalid_code")
        self._json(200, info)

    def _redeem(self) -> None:
        if not self.relay.allow("enroll", self._source(), ENROLL_RATE):
            return self._error("rate_limited", status=429)
        obj = self._json_body(required=True)
        if obj is None:
            return
        key = unb64url(obj.get("device_public_key", ""))
        proof = unb64url(obj.get("proof", ""))
        name = obj.get("device_name", "")
        if not key or len(key) != 32 or not proof or len(proof) != 64 or not isinstance(name, str):
            return self._error("bad_request", "device_public_key (32 bytes), proof (64 bytes) and device_name are required")
        result, error = self.relay.redeem(obj.get("code"), key, name, proof)
        if result is None:
            self._event("redeem", status=error)
            return self._error(error or "invalid_code")
        self._event("redeem", status=200, device=result["device_id"])
        self._json(200, result)

    # ------------------------------------------------------------ device auth

    def _challenge(self) -> None:
        if not self.relay.allow("auth", self._source(), AUTH_RATE):
            return self._error("rate_limited", status=429)
        obj = self._json_body(required=True)
        if obj is None:
            return
        nonce = self.relay.challenge(obj.get("device_id"))
        if nonce is None:
            return self._error("unknown_device")
        self._json(200, {"nonce": nonce, "expires_in": int(CHALLENGE_TTL)})

    def _session(self) -> None:
        if not self.relay.allow("auth", self._source(), AUTH_RATE):
            return self._error("rate_limited", status=429)
        obj = self._json_body(required=True)
        if obj is None:
            return
        sig = unb64url(obj.get("sig", "")) or b""
        result, error = self.relay.open_session(obj.get("device_id"), obj.get("nonce"), sig)
        if result is None:
            self._event("session", status=error)
            return self._error(error or "bad_signature")
        self._event("session", status=200, device=obj.get("device_id"))
        self._json(200, result)

    def _unbind(self, device_id: str) -> None:
        header = self.headers.get("Authorization", "")
        scheme, _, rest = header.partition(" ")
        fields = dict(
            part.strip().split("=", 1) for part in rest.split(",") if "=" in part
        ) if scheme == "LoopCtrl-Device" else {}
        sig = unb64url(fields.get("sig", "")) or b""
        try:
            ts = int(fields.get("ts", ""))
        except ValueError:
            return self._error("bad_signature")
        error = self.relay.unbind(device_id, ts, sig)
        if error:
            return self._error(error)
        self._event("unbind", device=device_id)
        self._json(200, {"ok": True})

    # -------------------------------------------------------------- transport

    def _poll(self) -> None:
        session = self.relay.session_for_token(_bearer(self.headers.get("Authorization")))
        if session is None:
            return self._json(401, {"error": "unauthorized"})
        pending = self.relay.take_request(session, self.relay.poll_timeout)
        if pending is None:
            return self._body(204, "application/json", b"")
        self._json(200, {
            "request_id": pending.request_id,
            "path": pending.path,
            "body_b64": base64.b64encode(pending.body).decode("ascii"),
        })

    def _device_response(self) -> None:
        session = self.relay.session_for_token(_bearer(self.headers.get("Authorization")))
        if session is None:
            return self._json(401, {"error": "unauthorized"})
        body = self._read_body(required=True, limit=self.relay.max_body_bytes * 2)
        if body is None:
            return
        try:
            obj = json.loads(body)
            request_id = obj["request_id"]
            status = obj["status"]
            response_body = base64.b64decode(obj["body_b64"], validate=True)
            content_type = obj.get("content_type", "application/json")
        except (json.JSONDecodeError, UnicodeDecodeError, KeyError, TypeError, ValueError):
            return self._json(400, {"error": "bad_response"})
        if (
            not isinstance(request_id, str) or not request_id
            or not isinstance(status, int) or not 100 <= status <= 599
            or not isinstance(content_type, str)
            or len(response_body) > self.relay.max_body_bytes
        ):
            return self._json(400, {"error": "bad_response"})
        if not self.relay.complete_request(session, request_id, status, response_body, content_type[:120]):
            return self._json(404, {"error": "unknown_request"})
        self._json(200, {"ok": True})

    # ---------------------------------------------------------------- helpers

    def _require_operator(self) -> bool:
        if self.relay.is_operator(_bearer(self.headers.get("Authorization"))):
            return True
        self._json(401, {"error": "unauthorized"})
        return False

    def _json_body(self, *, required: bool) -> dict[str, Any] | None:
        body = self._read_body(required=required, limit=64 * 1024)
        if body is None:
            return None
        if not body:
            if required:
                self._error("bad_request", "JSON body required")
                return None
            return {}
        try:
            obj = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            obj = None
        if not isinstance(obj, dict):
            self._error("bad_request", "body must be a JSON object")
            return None
        return obj

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

    def _error(self, code: str, message: str | None = None, *, status: int | None = None) -> None:
        self._json(status or _ERROR_STATUS.get(code, 400),
                   {"error": code, "message": message or _ERROR_MESSAGE.get(code, code)})

    def _json(self, status: int, obj: dict[str, Any]) -> None:
        self._body(status, "application/json", json.dumps(obj, separators=(",", ":")).encode("utf-8"))

    def _body(self, status: int, content_type: str, body: bytes, *,
              extra_headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type or "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if body:
            self.wfile.write(body)
        self.close_connection = True


def make_server(host: str, port: int, state: RelayState, *,
                certfile: str | None = None, keyfile: str | None = None) -> RelayHTTPServer:
    server = RelayHTTPServer((host, port), state)
    if certfile:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certfile=certfile, keyfile=keyfile)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    return server


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--public-server", default=os.environ.get("LOOPCTRL_RELAY_PUBLIC_SERVER", ""),
                        help="how phones reach this relay, host[:port][/path], e.g. "
                             "relay.example.com or example.com/loopctrl-relay; signatures are bound to it")
    parser.add_argument("--organization", default=os.environ.get("LOOPCTRL_RELAY_ORGANIZATION", "LoopCtrl Relay"))
    parser.add_argument("--state-file", default=os.environ.get("LOOPCTRL_RELAY_STATE_FILE"),
                        help="JSON file for enrolled devices (public keys only)")
    parser.add_argument("--certfile", help="optional PEM certificate")
    parser.add_argument("--keyfile", help="optional PEM private key")
    parser.add_argument("--device-ttl", type=int, default=DEFAULT_DEVICE_TTL)
    args = parser.parse_args()

    operator_token = os.environ.get("LOOPCTRL_RELAY_OPERATOR_TOKEN", "")
    if len(operator_token) < 24:
        print("LOOPCTRL_RELAY_OPERATOR_TOKEN must be set to at least 24 characters", file=sys.stderr)
        return 2
    if not args.public_server:
        print("--public-server (or LOOPCTRL_RELAY_PUBLIC_SERVER) is required", file=sys.stderr)
        return 2
    if bool(args.certfile) != bool(args.keyfile):
        print("--certfile and --keyfile must be supplied together", file=sys.stderr)
        return 2

    state = RelayState(operator_token, args.public_server, state_file=args.state_file,
                       default_organization=args.organization, device_ttl=args.device_ttl)
    server = make_server(args.bind, args.port, state, certfile=args.certfile, keyfile=args.keyfile)
    scheme = "https" if args.certfile else "http"
    print(f"LoopCtrl relay (API v{API_VERSION}) listening on {scheme}://{args.bind}:{server.server_port} "
          f"as {state.server}; secrets are never logged", flush=True)
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
