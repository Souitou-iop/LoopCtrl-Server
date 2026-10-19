#!/usr/bin/env python3
"""Device-test operator for the Phase 0 relay: sealed /rpc calls and timings.

Seals each call with the existing LoopCtrl v1 envelope (the pairing key from
~/.loopctrl/token.json, via Scripts/loopctrl_rpc.py), sends it through the
relay's operator endpoint, opens the sealed response, and reports timings. The
relay sees only the opaque envelope.

    export LOOPCTRL_RELAY_OPERATOR_TOKEN=...     # never on argv
    relay_bench.py --relay https://relay.example --device-id ID --key device:XXXX call get_screen_size
    relay_bench.py ... bench --count 30 get_screen_size
    relay_bench.py ... shot --count 5
    relay_bench.py ... watch --interval 15 --duration 1800 > watch.log

`--direct HOST:PORT` sends the same sealed envelope straight to LoopCtrl's
/rpc instead (LAN / Tailscale comparison). Output never contains keys or the
operator token.
"""
from __future__ import annotations

import argparse
import base64
import hmac
import importlib.util
import json
import os
import secrets
import statistics
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]


def _load_rpc():
    spec = importlib.util.spec_from_file_location(
        "loopctrl_rpc", _ROOT / "Scripts" / "loopctrl_rpc.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


rpc = _load_rpc()
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def seal(record: dict, method: str, params: dict | None, rpc_id: int) -> tuple[bytes, bytes]:
    key = bytes.fromhex(record["key"])
    tok = record["tok"]
    body = json.dumps({"jsonrpc": "2.0", "method": method,
                       "params": params or {}, "id": rpc_id}).encode()
    nonce = secrets.token_bytes(16)
    ts = int(time.time())
    k_enc = rpc._hmac(key, rpc.LABEL_ENC_REQ + nonce)
    k_mac = rpc._hmac(key, rpc.LABEL_MAC + nonce)
    ct = rpc._keystream_xor(k_enc, nonce, body)
    signed = b"v1" + bytes.fromhex(tok) + ts.to_bytes(8, "big") + nonce + ct
    tag = rpc._hmac(k_mac, signed)
    envelope = json.dumps({
        "v": 1, "tok": tok, "ts": ts, "nonce": nonce.hex(),
        "ct": base64.b64encode(ct).decode(), "tag": tag.hex(),
    }).encode()
    return envelope, nonce


def open_sealed(record: dict, nonce: bytes, raw: bytes) -> dict:
    key = bytes.fromhex(record["key"])
    resp = json.loads(raw)
    resp_ct = base64.b64decode(resp["ct"])
    k_mac = rpc._hmac(key, rpc.LABEL_MAC + nonce)
    expect = rpc._hmac(k_mac, b"resp" + nonce + resp_ct)
    if not hmac.compare_digest(expect, bytes.fromhex(resp["tag"])):
        raise RuntimeError("response MAC mismatch")
    k_enc = rpc._hmac(key, rpc.LABEL_ENC_RESP + nonce)
    return json.loads(rpc._keystream_xor(k_enc, nonce, resp_ct))


class Target:
    def __init__(self, args):
        self.args = args
        record = rpc.load_token(args.key)
        if not record:
            raise SystemExit(f"no key stored under {args.key}")
        self.record = record
        if args.direct:
            self.url = f"http://{args.direct}/rpc"
            self.headers = {"Content-Type": "application/json"}
        else:
            token = os.environ.get("LOOPCTRL_RELAY_OPERATOR_TOKEN", "")
            if len(token) < 24 or not args.device_id:
                raise SystemExit("relay mode needs LOOPCTRL_RELAY_OPERATOR_TOKEN and --device-id")
            self.url = f"{args.relay.rstrip('/')}/v1/operator/devices/{args.device_id}/rpc"
            self.headers = {"Content-Type": "application/json",
                            "Authorization": "Bearer " + token}
        self.rpc_id = 0

    def call(self, method: str, params: dict | None = None, timeout: float = 90) -> dict:
        """One call: {ok, ms, status, req_bytes, resp_bytes, result|error}."""
        self.rpc_id += 1
        envelope, nonce = seal(self.record, method, params, self.rpc_id)
        request = urllib.request.Request(self.url, data=envelope,
                                         headers=self.headers, method="POST")
        started = time.perf_counter()
        try:
            with _OPENER.open(request, timeout=timeout) as response:
                raw = response.read()
                status = response.status
        except urllib.error.HTTPError as error:
            raw, status = error.read(), error.code
        except Exception as error:  # transport failure: report, don't raise
            return {"ok": False, "ms": (time.perf_counter() - started) * 1000,
                    "status": 0, "error": type(error).__name__ + ": " + str(error)[:120]}
        ms = (time.perf_counter() - started) * 1000
        out = {"ok": False, "ms": ms, "status": status,
               "req_bytes": len(envelope), "resp_bytes": len(raw)}
        if status != 200:
            out["error"] = raw[:200].decode("utf-8", "replace")
            return out
        try:
            opened = open_sealed(self.record, nonce, raw)
        except Exception as error:
            out["error"] = "open failed: " + str(error)[:120]
            return out
        if "error" in opened:
            out["error"] = json.dumps(opened["error"])[:200]
        else:
            out["ok"] = True
            out["result"] = opened.get("result")
        return out


def _pct(values: list[float], p: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round(p / 100 * (len(ordered) - 1))))
    return ordered[index]


def summary(label: str, samples: list[dict]) -> dict:
    ok = [s["ms"] for s in samples if s["ok"]]
    line = {"label": label, "n": len(samples), "ok": len(ok)}
    if ok:
        line.update(p50=round(_pct(ok, 50)), p95=round(_pct(ok, 95)),
                    min=round(min(ok)), max=round(max(ok)),
                    mean=round(statistics.mean(ok)))
    return line


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--relay", default="https://relay.ebato.top")
    ap.add_argument("--device-id", help="relay device id (from relay_operator.py --list)")
    ap.add_argument("--key", required=True, help="token.json record, e.g. device:<id>")
    ap.add_argument("--direct", metavar="HOST:PORT", help="bypass the relay")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("call")
    c.add_argument("method")
    c.add_argument("params", nargs="?", default="{}")
    b = sub.add_parser("bench")
    b.add_argument("method")
    b.add_argument("params", nargs="?", default="{}")
    b.add_argument("--count", type=int, default=30)
    b.add_argument("--pause", type=float, default=0.2)
    s = sub.add_parser("shot")
    s.add_argument("--count", type=int, default=5)
    s.add_argument("--format", default="jpeg")
    s.add_argument("--quality", type=float, default=0.6)
    s.add_argument("--scale", type=float, default=1.0)
    s.add_argument("--save", help="write the last screenshot here")
    w = sub.add_parser("watch")
    w.add_argument("--interval", type=float, default=15)
    w.add_argument("--duration", type=float, default=600)
    w.add_argument("--method", default="get_screen_size")
    args = ap.parse_args()
    target = Target(args)

    if args.cmd == "call":
        out = target.call(args.method, json.loads(args.params))
        print(json.dumps(out, ensure_ascii=False)[:4000])
        return 0 if out["ok"] else 1

    if args.cmd == "bench":
        params = json.loads(args.params)
        samples = []
        for _ in range(args.count):
            samples.append(target.call(args.method, params))
            if not samples[-1]["ok"]:
                print(json.dumps({k: v for k, v in samples[-1].items() if k != "result"}),
                      file=sys.stderr)
            time.sleep(args.pause)
        print(json.dumps(summary(args.method, samples)))
        print(json.dumps({"ms": [round(s["ms"]) for s in samples]}))
        return 0

    if args.cmd == "shot":
        params = {"format": args.format, "quality": args.quality, "scale": args.scale}
        samples = []
        last = None
        for _ in range(args.count):
            out = target.call("screenshot", params, timeout=120)
            image = None
            if out["ok"] and isinstance(out.get("result"), dict):
                for field in ("image", "data", "base64"):
                    if isinstance(out["result"].get(field), str):
                        image = base64.b64decode(out["result"][field])
                        break
            out["image_bytes"] = len(image) if image else 0
            if image:
                last = image
            samples.append(out)
            print(json.dumps({k: (round(v) if isinstance(v, float) else v)
                              for k, v in out.items() if k != "result"}))
        stats = summary("screenshot", samples)
        ok = [s for s in samples if s["ok"]]
        if ok:
            stats["resp_kb"] = round(statistics.mean(s["resp_bytes"] for s in ok) / 1024)
            stats["kb_per_s"] = round(sum(s["resp_bytes"] for s in ok) / 1024
                                      / (sum(s["ms"] for s in ok) / 1000))
        print(json.dumps(stats))
        if args.save and last:
            Path(args.save).write_bytes(last)
        return 0

    if args.cmd == "watch":
        end = time.time() + args.duration
        while time.time() < end:
            out = target.call(args.method, {}, timeout=75)
            print(json.dumps({"t": round(time.time(), 1), "ok": out["ok"],
                              "ms": round(out["ms"]), "status": out["status"],
                              "error": out.get("error")}), flush=True)
            time.sleep(args.interval)
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
