#!/usr/bin/env python3
"""End-to-end self-test for the Phase 0 LoopCtrl relay.

Runs the relay in-process on loopback, registers a fake device, waits for a
long-poll, forwards the exact opaque envelope bytes to a fake loopback
LoopCtrl endpoint, and verifies the operator receives the exact response.

The second scenario is the one that matters: a REAL sealed v1 envelope is built
with the shipped reference client's crypto, carried through the relay by a fake
device, and opened on the other side. That proves the relay is a byte pipe that
changes nothing about the existing encrypted protocol.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import importlib.util
import json
import secrets
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

from loopctrl_relay_server import RelayState, make_server


_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _load_reference_client():
    """Import Scripts/loopctrl_rpc.py under its own name.

    Reusing the shipped client's primitives means this test cannot drift from
    the protocol the device actually speaks.
    """
    path = Path(__file__).resolve().parent.parent / "Scripts" / "loopctrl_rpc.py"
    spec = importlib.util.spec_from_file_location("loopctrl_reference_client", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


rpc = _load_reference_client()


def _seal_request(key: bytes, tok: str, method: str, params: dict | None = None) -> dict:
    """Build a v1 request envelope exactly as the reference client does."""
    body = json.dumps(
        {"jsonrpc": "2.0", "method": method, "params": params or {}, "id": 7}
    ).encode()
    nonce = secrets.token_bytes(16)
    ts = int(time.time())
    k_enc = rpc._hmac(key, rpc.LABEL_ENC_REQ + nonce)
    k_mac = rpc._hmac(key, rpc.LABEL_MAC + nonce)
    ct = rpc._keystream_xor(k_enc, nonce, body)
    signed = b"v1" + bytes.fromhex(tok) + ts.to_bytes(8, "big") + nonce + ct
    return {
        "v": 1,
        "tok": tok,
        "ts": ts,
        "nonce": nonce.hex(),
        "ct": base64.b64encode(ct).decode(),
        "tag": rpc._hmac(k_mac, signed).hex(),
    }


def _open_sealed_response(key: bytes, tok: str, nonce_hex: str, sealed: dict) -> dict:
    """Verify and decrypt a v1 response envelope, as the reference client does."""
    nonce = bytes.fromhex(nonce_hex)
    k_mac = rpc._hmac(key, rpc.LABEL_MAC + nonce)
    ct = base64.b64decode(sealed["ct"])
    expected = rpc._hmac(k_mac, b"resp" + nonce + ct)
    if not hmac.compare_digest(expected, bytes.fromhex(sealed["tag"])):
        raise AssertionError("response MAC mismatch")
    k_enc_resp = rpc._hmac(key, rpc.LABEL_ENC_RESP + nonce)
    plaintext = rpc._keystream_xor(k_enc_resp, nonce, ct)
    result = json.loads(plaintext)
    if result.get("result") != {"device_info": "synthetic"}:
        raise AssertionError(f"unexpected RPC result: {result}")
    return result


def _post(url: str, body: bytes | None, token: str | None = None) -> tuple[int, bytes]:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with _OPENER.open(request, timeout=10) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def _get(url: str, token: str | None = None) -> tuple[int, bytes]:
    headers = {}
    if token:
        headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with _OPENER.open(request, timeout=10) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def main() -> int:
    operator = "selftest-operator-token-0123456789"
    state = RelayState(
        operator,
        enrollment_ttl=30,
        device_ttl=30,
        poll_timeout=5,
        operator_timeout=5,
    )
    server = make_server("127.0.0.1", 0, state)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"

    try:
        status, body = _get(base + "/healthz")
        assert status == 200, (status, body)

        status, body = _post(
            base + "/v1/admin/enrollments",
            b"{}",
            operator,
        )
        assert status == 201, (status, body)
        enrollment = json.loads(body)["enrollment_token"]

        # A registration must be bearer-authenticated.
        status, _ = _post(
            base + "/v1/device/register",
            b'{"name":"phone"}',
            None,
        )
        assert status == 401, status

        status, body = _post(
            base + "/v1/device/register",
            b'{"name":"phone"}',
            enrollment,
        )
        assert status == 201, (status, body)
        registration = json.loads(body)
        device_id = registration["device_id"]
        device_token = registration["device_token"]

        # Enrollment is single-use.
        status, _ = _post(
            base + "/v1/device/register",
            b'{"name":"phone-2"}',
            enrollment,
        )
        assert status == 401, status

        poll_result: dict[str, object] = {}

        def poll_once() -> None:
            status, body = _post(
                base + "/v1/device/poll",
                None,
                device_token,
            )
            poll_result["status"] = status
            poll_result["body"] = body

        poll_thread = threading.Thread(target=poll_once)
        poll_thread.start()

        # Let the poll block before the operator request arrives.
        threading.Event().wait(0.2)
        request_body = b'{"v":1,"tok":"00112233","ct":"opaque"}'
        response_body = b'{"jsonrpc":"2.0","result":{"ok":true},"id":1}'

        def fake_device() -> None:
            assert poll_thread.is_alive()
            status, body = _post(
                base + "/v1/operator/devices/" + device_id + "/rpc",
                request_body,
                operator,
            )
            poll_result["operator_status"] = status
            poll_result["operator_body"] = body

        operator_thread = threading.Thread(target=fake_device)
        operator_thread.start()
        poll_thread.join(timeout=10)
        assert not poll_thread.is_alive(), "device poll did not return"
        assert poll_result["status"] == 200, poll_result
        work = json.loads(poll_result["body"])
        assert base64.b64decode(work["body_b64"]) == request_body

        status, body = _post(
            base + "/v1/device/response",
            json.dumps(
                {
                    "request_id": work["request_id"],
                    "status": 200,
                    "body_b64": base64.b64encode(response_body).decode("ascii"),
                    "content_type": "application/json",
                }
            ).encode(),
            device_token,
        )
        assert status == 200, (status, body)
        operator_thread.join(timeout=10)
        assert not operator_thread.is_alive(), "operator request did not return"
        assert poll_result["operator_status"] == 200, poll_result
        assert poll_result["operator_body"] == response_body

        status, _ = _post(
            base + "/v1/operator/devices/" + device_id + "/rpc",
            request_body,
            "wrong-operator-token",
        )
        assert status == 401, status

        status, _ = _post(
            base + "/v1/device/poll",
            None,
            "wrong-device-token",
        )
        assert status == 401, status

        status, body = _get(
            base + "/v1/admin/devices",
            operator,
        )
        assert status == 200, (status, body)
        assert json.loads(body)["devices"][0]["device_id"] == device_id

        _sealed_envelope_scenario(base, operator)

        print("relay self-test: PASS")
        print("  registration, single-use enrollment, long-poll forwarding, response return")
        print("  opaque request/response bytes")
        print("  unknown operator/device token rejection")
        print("  a real v1 sealed envelope opens after the round trip")
        return 0
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _sealed_envelope_scenario(base: str, operator: str) -> None:
    """Carry a real sealed v1 request/response pair through the relay.

    The device half is a fake LoopCtrl: it opens the envelope with the reference
    client's crypto, answers, and seals the reply. If the relay altered a single
    byte, the MAC check in `_open_sealed_response` would fail.
    """
    status, body = _post(base + "/v1/admin/enrollments", b"{}", operator)
    assert status == 201, (status, body)
    enrollment = json.loads(body)["enrollment_token"]

    status, body = _post(
        base + "/v1/device/register",
        b'{"name":"sealed-device"}',
        enrollment,
    )
    assert status == 201, (status, body)
    registration = json.loads(body)
    device_id = registration["device_id"]
    device_token = registration["device_token"]

    # The pairing key a real device would already hold. Synthetic, never stored.
    key = secrets.token_bytes(32)
    tok = hashlib.sha256(key).digest()[:4].hex()
    envelope = _seal_request(key, tok, "device_info")
    nonce_hex = envelope["nonce"]
    request_bytes = json.dumps(envelope).encode()

    outcome: dict[str, object] = {}

    def device_half() -> None:
        # 1. Long-poll and take the operator's work.
        status, body = _post(base + "/v1/device/poll", None, device_token)
        outcome["poll_status"] = status
        work = json.loads(body)
        carried = base64.b64decode(work["body_b64"])
        outcome["bytes_identical"] = carried == request_bytes

        # 2. Open the envelope exactly as a paired client's server would.
        fields = json.loads(carried)
        # Verify-and-decrypt with the same primitives the device uses.
        nonce = bytes.fromhex(fields["nonce"])
        k_mac = rpc._hmac(key, rpc.LABEL_MAC + nonce)
        ct = base64.b64decode(fields["ct"])
        signed = (
            b"v1"
            + bytes.fromhex(fields["tok"])
            + int(fields["ts"]).to_bytes(8, "big")
            + nonce
            + ct
        )
        assert hmac.compare_digest(
            rpc._hmac(k_mac, signed), bytes.fromhex(fields["tag"])
        ), "request MAC failed on the device side"
        k_enc_req = rpc._hmac(key, rpc.LABEL_ENC_REQ + nonce)
        rpc_request = json.loads(rpc._keystream_xor(k_enc_req, nonce, ct))
        outcome["method"] = rpc_request["method"]

        # 3. Seal the response under the same nonce, response direction.
        result = {
            "jsonrpc": "2.0",
            "result": {"device_info": "synthetic"},
            "id": rpc_request["id"],
        }
        resp_ct = rpc._keystream_xor(
            rpc._hmac(key, rpc.LABEL_ENC_RESP + nonce), nonce, json.dumps(result).encode()
        )
        sealed = {
            "v": 1,
            "nonce": fields["nonce"],
            "ct": base64.b64encode(resp_ct).decode(),
            "tag": rpc._hmac(k_mac, b"resp" + nonce + resp_ct).hex(),
        }
        status, body = _post(
            base + "/v1/device/response",
            json.dumps(
                {
                    "request_id": work["request_id"],
                    "status": 200,
                    "body_b64": base64.b64encode(json.dumps(sealed).encode()).decode(),
                    "content_type": "application/json",
                }
            ).encode(),
            device_token,
        )
        outcome["response_status"] = status

    device_thread = threading.Thread(target=device_half)
    device_thread.start()
    threading.Event().wait(0.2)

    status, body = _post(
        base + "/v1/operator/devices/" + device_id + "/rpc",
        request_bytes,
        operator,
    )
    assert status == 200, (status, body)
    device_thread.join(timeout=10)
    assert not device_thread.is_alive(), "fake device did not finish"
    assert outcome.get("bytes_identical") is True, outcome
    assert outcome["method"] == "device_info", outcome
    assert outcome["response_status"] == 200, outcome

    opened = _open_sealed_response(key, tok, nonce_hex, json.loads(body))
    assert opened["id"] == 7, opened


if __name__ == "__main__":
    raise SystemExit(main())
