#!/usr/bin/env python3
"""Operator client for a LoopCtrl relay (docs/relay-enrollment.md).

A test and reference tool, not a control plane. It keeps one long-lived X25519
pairing key per operator in ~/.loopctrl/relay_operator.json, so the key ID it
puts in an invite is the key it later pairs with:

    relay_operator.py key                                  # name and key ID
    relay_operator.py enroll --name "Alex" [--org …]       # code + invite link
    relay_operator.py devices
    relay_operator.py pair --device-id dev_…               # POST /pair through the relay
    relay_operator.py call --device-id dev_… get_status '{}'

The relay operator token is read from LOOPCTRL_RELAY_OPERATOR_TOKEN, so it
never appears in argv. Without it the requests go out unauthenticated, which
is what `operator_shim.py` (run on the relay host, adds the token) expects.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import secrets
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "cli"))
from loopctrl_rpc import (  # noqa: E402
    LABEL_ENC_REQ, LABEL_ENC_RESP, LABEL_MAC, LABEL_PAIR, LABEL_WRAP,
    _X25519_BASE, _hmac, _keystream_xor, _x25519,
)

STORE = os.path.expanduser("~/.loopctrl/relay_operator.json")
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _load() -> dict:
    try:
        with open(STORE) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def _save(data: dict) -> None:
    os.makedirs(os.path.dirname(STORE), exist_ok=True)
    fd = os.open(STORE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(data, fh, indent=1)


def identity(name: str | None = None) -> dict:
    """The operator's key (created on first use) and display name."""
    data = _load()
    if "priv" not in data:
        data["priv"] = secrets.token_bytes(32).hex()
    if name:
        data["name"] = name
    data.setdefault("name", "Operator")
    pub = _x25519(bytes.fromhex(data["priv"]), _X25519_BASE)
    data["key_id"] = hashlib.sha256(pub).hexdigest()
    _save(data)
    return data


def _request(method: str, url: str, body: dict | bytes | None = None, timeout: float = 120) -> tuple[int, bytes]:
    headers = {}
    token = os.environ.get("LOOPCTRL_RELAY_OPERATOR_TOKEN", "")
    if token:
        headers["Authorization"] = "Bearer " + token
    data = None
    if body is not None:
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with _OPENER.open(req, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def pair(base: str, device_id: str, client_name: str) -> dict:
    me = identity()
    priv = bytes.fromhex(me["priv"])
    pub = _x25519(priv, _X25519_BASE)
    print(f"pairing as {client_name!r}, key {me['key_id'][:8]}… through the relay", file=sys.stderr)
    started = time.time()
    status, raw = _request("POST", f"{base}/v1/operator/devices/{device_id}/pair",
                           {"client_name": client_name, "pub": base64.b64encode(pub).decode()})
    took = time.time() - started
    if status != 200:
        raise SystemExit(f"pair failed ({status}) after {took:.1f}s: {raw.decode('utf-8', 'replace')}")
    resp = json.loads(raw)
    device_pub = base64.b64decode(resp["pub"])
    k_wrap = _hmac(_x25519(priv, device_pub), LABEL_PAIR + pub + device_pub)
    key = bytes(a ^ b for a, b in zip(bytes.fromhex(resp["token_ct"]), _hmac(k_wrap, LABEL_WRAP)))
    data = _load()
    data.setdefault("sessions", {})[device_id] = {"key": key.hex(), "tok": hashlib.sha256(key).digest()[:4].hex()}
    _save(data)
    print(f"paired in {took:.1f}s (no prompt means pre-approval applied)", file=sys.stderr)
    return resp


def call(base: str, device_id: str, method: str, params: dict) -> dict:
    record = _load().get("sessions", {}).get(device_id)
    if not record:
        raise SystemExit("not paired with that device: run `pair` first")
    key, tok = bytes.fromhex(record["key"]), record["tok"]
    body = json.dumps({"jsonrpc": "2.0", "method": method, "params": params, "id": 1}).encode()
    nonce, ts = secrets.token_bytes(16), int(time.time())
    k_mac = _hmac(key, LABEL_MAC + nonce)
    ct = _keystream_xor(_hmac(key, LABEL_ENC_REQ + nonce), nonce, body)
    tag = _hmac(k_mac, b"v1" + bytes.fromhex(tok) + ts.to_bytes(8, "big") + nonce + ct)
    status, raw = _request("POST", f"{base}/v1/operator/devices/{device_id}/rpc", {
        "v": 1, "tok": tok, "ts": ts, "nonce": nonce.hex(),
        "ct": base64.b64encode(ct).decode(), "tag": tag.hex(),
    })
    if status != 200:
        raise SystemExit(f"rpc failed ({status}): {raw.decode('utf-8', 'replace')}")
    resp = json.loads(raw)
    resp_ct = base64.b64decode(resp["ct"])
    if not hmac.compare_digest(_hmac(k_mac, b"resp" + nonce + resp_ct), bytes.fromhex(resp["tag"])):
        raise SystemExit("response MAC mismatch — discarding")
    return json.loads(_keystream_xor(_hmac(key, LABEL_ENC_RESP + nonce), nonce, resp_ct))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--relay", default=os.environ.get("LOOPCTRL_RELAY_URL", "http://127.0.0.1:8787"), help="relay base URL, path prefix allowed")
    sub = parser.add_subparsers(dest="command", required=True)
    key = sub.add_parser("key")
    key.add_argument("--name")
    enroll = sub.add_parser("enroll")
    enroll.add_argument("--name", help="operator name shown on the phone")
    enroll.add_argument("--org", help="organization shown on the phone")
    enroll.add_argument("--expires-in", type=int, default=600)
    sub.add_parser("devices")
    p = sub.add_parser("pair")
    p.add_argument("--device-id", required=True)
    p.add_argument("--client-name")
    c = sub.add_parser("call")
    c.add_argument("--device-id", required=True)
    c.add_argument("method")
    c.add_argument("params", nargs="?", default="{}")
    args = parser.parse_args()
    base = args.relay.rstrip("/")

    if args.command == "key":
        me = identity(args.name)
        print(json.dumps({"name": me["name"], "key_id": me["key_id"]}, indent=1))
    elif args.command == "enroll":
        me = identity(args.name)
        payload = {"operators": [{"name": me["name"], "key_id": me["key_id"]}], "expires_in": args.expires_in}
        if args.org:
            payload["organization"] = args.org
        status, raw = _request("POST", base + "/v1/admin/enrollments", payload)
        if status != 201:
            raise SystemExit(f"enrollment failed ({status}): {raw.decode('utf-8', 'replace')}")
        print(json.dumps(json.loads(raw), indent=1))
    elif args.command == "devices":
        status, raw = _request("GET", base + "/v1/admin/devices")
        if status != 200:
            raise SystemExit(f"list failed ({status}): {raw.decode('utf-8', 'replace')}")
        print(json.dumps(json.loads(raw), indent=1))
    elif args.command == "pair":
        pair(base, args.device_id, args.client_name or identity()["name"])
    elif args.command == "call":
        print(json.dumps(call(base, args.device_id, args.method, json.loads(args.params)), indent=1, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
