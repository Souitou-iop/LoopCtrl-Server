#!/usr/bin/env python3
"""Self-test for the LoopCtrl relay (API v1, docs/relay-enrollment.md).

Runs the relay in-process on a loopback port and plays both sides: an operator
with the admin token, and a phone with its own Ed25519 key. No iPhone needed.

    python3 relay/selftest.py
"""
from __future__ import annotations

import base64
import json
import os
import secrets
import sys
import tempfile
import threading
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ed25519  # noqa: E402
from loopctrl_relay_server import (  # noqa: E402
    RelayState, b64url, channel_message, enroll_message, make_server, unbind_message,
)

_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
OPERATOR = "op-" + secrets.token_urlsafe(24)
SERVER = "relay.test/loopctrl-relay"
KEY_A = "ab" * 32
KEY_B = "cd" * 32


class Clock:
    def __init__(self) -> None:
        self.now = 1_800_000_000.0

    def __call__(self) -> float:
        return self.now


def req(base, method, path, body=None, token=None, headers=None, timeout=10):
    h = dict(headers or {})
    if token:
        h["Authorization"] = "Bearer " + token
    data = None
    if body is not None:
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        h["Content-Type"] = "application/json"
    r = urllib.request.Request(base + path, data=data, headers=h, method=method)
    try:
        with _OPENER.open(r, timeout=timeout) as resp:
            raw = resp.read()
            return resp.status, (json.loads(raw) if raw and resp.headers.get_content_type() == "application/json" else raw)
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, raw


class Phone:
    def __init__(self, base):
        self.base = base
        self.secret = secrets.token_bytes(32)
        self.pub = ed25519.public_key(self.secret)
        self.device_id = None
        self.token = None

    def redeem(self, code, server=SERVER, name="Test iPhone"):
        proof = ed25519.sign(self.secret, enroll_message(code, server))
        status, body = req(self.base, "POST", "/v1/enroll/redeem", {
            "code": code, "device_public_key": b64url(self.pub),
            "device_name": name, "proof": b64url(proof)})
        if status == 200:
            self.device_id = body["device_id"]
        return status, body

    def authenticate(self):
        status, body = req(self.base, "POST", "/v1/device/challenge", {"device_id": self.device_id})
        if status != 200:
            return status, body
        sig = ed25519.sign(self.secret, channel_message(body["nonce"], SERVER))
        status, body2 = req(self.base, "POST", "/v1/device/session",
                            {"device_id": self.device_id, "nonce": body["nonce"], "sig": b64url(sig)})
        if status == 200:
            self.token = body2["device_token"]
        return status, body2

    def poll(self, timeout=10):
        return req(self.base, "POST", "/v1/device/poll", token=self.token, timeout=timeout)

    def respond(self, request_id, status, payload: bytes):
        return req(self.base, "POST", "/v1/device/response", {
            "request_id": request_id, "status": status,
            "body_b64": base64.b64encode(payload).decode()}, token=self.token)

    def unbind(self, ts):
        sig = ed25519.sign(self.secret, unbind_message(self.device_id, ts, SERVER))
        return req(self.base, "DELETE", f"/v1/devices/{self.device_id}",
                   headers={"Authorization": f"LoopCtrl-Device sig={b64url(sig)}, ts={ts}"})


def check(label, cond):
    if not cond:
        raise SystemExit(f"FAIL: {label}")
    print(f"ok  {label}")


def start(clock, state_file):
    state = RelayState(OPERATOR, "https://Relay.test/loopctrl-relay/", state_file=state_file,
                       poll_timeout=1.0, operator_timeout=5.0, clock=clock)
    server = make_server("127.0.0.1", 0, state)
    threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
    return server, state, f"http://127.0.0.1:{server.server_port}"


def main() -> int:
    check("ed25519 RFC 8032 vector", ed25519.public_key(bytes.fromhex(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")).hex()
        == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")

    clock = Clock()
    tmp = tempfile.mkdtemp()
    state_file = os.path.join(tmp, "state.json")
    server, state, base = start(clock, state_file)
    check("server name normalized", state.server == SERVER)

    # --- operator mints a code
    check("admin needs token", req(base, "POST", "/v1/admin/enrollments", {})[0] == 401)
    check("bad key id refused", req(base, "POST", "/v1/admin/enrollments",
                                    {"operators": [{"name": "A", "key_id": "abc"}]}, token=OPERATOR)[0] == 400)
    status, minted = req(base, "POST", "/v1/admin/enrollments", {
        "organization": "Example Ops", "operators": [{"name": "Alex", "key_id": KEY_A.upper()}],
        "expires_in": 600}, token=OPERATOR)
    check("enrollment created", status == 201 and len(minted["code"]) == 8)
    code = minted["code"]
    check("invite carries path, op, exp", minted["invite"].startswith(
        "loopctrl://connect?v=1&server=relay.test/loopctrl-relay&code=" + code)
        and f"op={KEY_A}" in minted["invite"] and "exp=1800000600" in minted["invite"])

    # --- preview
    status, info = req(base, "POST", "/v1/enroll/preview", {"code": f"{code[:4]}-{code[4:]}".lower()})
    check("preview with display form", status == 200 and info["organization"] == "Example Ops"
          and info["operators"] == [{"name": "Alex", "key_id": KEY_A}]
          and info["code_expires_at"] == 1800000600 and "control" in info["capabilities"])
    check("unknown code 404", req(base, "POST", "/v1/enroll/preview", {"code": "00000000"})[0] == 404)
    check("malformed code 404", req(base, "POST", "/v1/enroll/preview", {"code": "nope"})[0] == 404)

    # --- redeem
    phone = Phone(base)
    status, body = phone.redeem(code, server="evil.example")
    check("proof bound to server name", status == 400 and body["error"] == "bad_proof")
    check("bad proof did not spend the code", req(base, "POST", "/v1/enroll/preview", {"code": code})[0] == 200)
    status, body = phone.redeem(code)
    check("redeem", status == 200 and body["device_id"].startswith("dev_")
          and body["operators"] == [{"name": "Alex", "key_id": KEY_A}])
    other = Phone(base)
    check("second redeem: used", other.redeem(code)[0] == 410)
    check("preview after use: 410", req(base, "POST", "/v1/enroll/preview", {"code": code})[0] == 410)

    _, minted2 = req(base, "POST", "/v1/admin/enrollments",
                     {"operators": [{"name": "B", "key_id": KEY_B}], "expires_in": 60}, token=OPERATOR)
    clock.now += 61
    check("expired code: 410", req(base, "POST", "/v1/enroll/preview", {"code": minted2["code"]})[0] == 410)

    # --- channel auth
    check("operator to offline device: 503",
          req(base, "POST", f"/v1/operator/devices/{phone.device_id}/pair", b"{}", token=OPERATOR)[0] == 503)
    status, _ = phone.authenticate()
    check("challenge/session", status == 200 and phone.token)
    status, ch = req(base, "POST", "/v1/device/challenge", {"device_id": phone.device_id})
    wrong = ed25519.sign(other.secret, channel_message(ch["nonce"], SERVER))
    check("someone else's key refused", req(base, "POST", "/v1/device/session", {
        "device_id": phone.device_id, "nonce": ch["nonce"], "sig": b64url(wrong)})[0] == 401)
    check("challenge single use", req(base, "POST", "/v1/device/session", {
        "device_id": phone.device_id, "nonce": ch["nonce"],
        "sig": b64url(ed25519.sign(phone.secret, channel_message(ch["nonce"], SERVER)))})[0] == 401)
    check("unknown device challenge 404",
          req(base, "POST", "/v1/device/challenge", {"device_id": "dev_" + "0" * 16})[0] == 404)
    check("bad token poll 401", req(base, "POST", "/v1/device/poll", token="nope")[0] == 401)
    check("idle poll 204", phone.poll()[0] == 204)

    # --- forwarding, opaque both ways
    result = {}

    def operator_call(path, payload):
        result[path] = req(base, "POST", f"/v1/operator/devices/{phone.device_id}{path}", payload, token=OPERATOR)

    for path, payload in (("/pair", b'{"client_name":"x","pub":"AAAA"}'), ("/rpc", b'{"v":1,"opaque":true}')):
        t = threading.Thread(target=operator_call, args=(path, payload))
        t.start()
        status, work = phone.poll()
        check(f"{path} delivered", status == 200 and work["path"] == path
              and base64.b64decode(work["body_b64"]) == payload)
        check(f"{path} answered", phone.respond(work["request_id"], 200, b'{"answer":' + path.encode().replace(b"/", b'"') + b'"}')[0] == 200)
        t.join(5)
        check(f"{path} reached operator", result[path][0] == 200)
    check("duplicate response refused", phone.respond("0" * 32, 200, b"{}")[0] == 404)

    # --- re-auth keeps the queue
    t = threading.Thread(target=operator_call, args=("/rpc", b'{"again":1}'))
    t.start()
    old = phone.token
    phone.authenticate()
    check("old token dead after re-auth", req(base, "POST", "/v1/device/poll", token=old)[0] == 401)
    status, work = phone.poll()
    check("queued work survives re-auth", status == 200)
    phone.respond(work["request_id"], 200, b"{}")
    t.join(5)

    # --- persistence
    server.shutdown()
    server.server_close()
    server, state, base = start(clock, state_file)
    phone.base = base
    check("device survives restart", phone.authenticate()[0] == 200)
    _, listed = req(base, "GET", "/v1/admin/devices", token=OPERATOR)
    check("device listed", [d["device_id"] for d in listed["devices"]] == [phone.device_id])
    with open(state_file) as fh:
        check("state file holds no tokens", "device_token" not in fh.read())

    # --- unbind
    ts = int(clock.now)
    check("unbind with stale ts refused", phone.unbind(ts - 1000)[0] == 401)
    check("unbind", phone.unbind(ts)[0] == 200)
    check("unbound device gone", phone.authenticate()[0] == 404)
    check("unbound token dead", phone.poll()[0] == 401)

    # --- rate limit
    statuses = [req(base, "POST", "/v1/enroll/preview", {"code": "00000000"})[0] for _ in range(25)]
    check("preview rate limited", 429 in statuses)

    server.shutdown()
    print("PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
