#!/usr/bin/env python3
"""Small operator client for the LoopCtrl Phase 0 relay.

This is only a test/operator helper, not a production control plane. It reads
the relay operator token from LOOPCTRL_RELAY_OPERATOR_TOKEN so the token never
appears in argv or shell history.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _request(
    method: str,
    url: str,
    token: str,
    body: bytes | None = None,
) -> tuple[int, bytes]:
    headers = {"Authorization": "Bearer " + token}
    if body is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with _OPENER.open(request, timeout=90) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--relay", default="http://127.0.0.1:8787")
    parser.add_argument("--device-id")
    parser.add_argument("--body-file")
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--enroll", action="store_true")
    parser.add_argument("--expires-in", type=int, default=300)
    args = parser.parse_args()

    token = os.environ.get("LOOPCTRL_RELAY_OPERATOR_TOKEN", "")
    if len(token) < 24:
        print("LOOPCTRL_RELAY_OPERATOR_TOKEN is not set", file=sys.stderr)
        return 2
    base = args.relay.rstrip("/")

    if args.enroll:
        payload = json.dumps({"expires_in": args.expires_in}).encode()
        status, body = _request("POST", base + "/v1/admin/enrollments", token, payload)
        if status != 201:
            print(f"enrollment failed ({status}): {body.decode('utf-8', 'replace')}", file=sys.stderr)
            return 1
        print(body.decode())
        return 0

    if args.list:
        status, body = _request("GET", base + "/v1/admin/devices", token)
        if status != 200:
            print(f"list failed ({status}): {body.decode('utf-8', 'replace')}", file=sys.stderr)
            return 1
        print(json.dumps(json.loads(body), indent=2))
        return 0

    if not args.device_id or not args.body_file:
        parser.error("--device-id and --body-file are required unless --list/--enroll is used")
    try:
        with open(args.body_file, "rb") as handle:
            envelope = handle.read()
    except OSError as error:
        print(f"cannot read body: {error}", file=sys.stderr)
        return 1

    status, body = _request(
        "POST",
        base + "/v1/operator/devices/" + args.device_id + "/rpc",
        token,
        envelope,
    )
    if status != 200:
        print(f"relay failed ({status}): {body.decode('utf-8', 'replace')}", file=sys.stderr)
        return 1
    # The response is an opaque LoopCtrl envelope. Print it only to stdout so a
    # caller can pipe it into its own private-key handling.
    sys.stdout.buffer.write(body)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
