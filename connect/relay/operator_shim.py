#!/usr/bin/env python3
"""Ephemeral operator forwarder for device tests against a deployed relay.

Runs ON the relay host, inside an SSH session, so the operator token is read
from the relay's own env file and never leaves that host:

    ssh -L 18790:127.0.0.1:18790 relay-host \\
      'set -a; . /opt/loopctrl-relay/relay.env; exec python3 -u - --upstream http://127.0.0.1:8787' \\
      < relay/operator_shim.py

It listens on 127.0.0.1 only, forwards /v1/operator/* and /v1/admin/* with the
operator bearer added, and logs one line per call with the relay-side time
(the device leg, without the operator's WAN hop). It writes nothing to disk
and exits with the SSH session.
"""
from __future__ import annotations

import argparse
import os
import sys
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOKEN = os.environ.get("LOOPCTRL_RELAY_OPERATOR_TOKEN", "")
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    upstream = ""

    def log_message(self, fmt, *args):
        pass

    def _forward(self, method: str) -> None:
        path = self.path.split("?", 1)[0]
        if not (path.startswith("/v1/operator/") or path.startswith("/v1/admin/")):
            self._send(404, b'{"error":"not_found"}', "application/json")
            return
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else None
        req = urllib.request.Request(self.upstream + path, data=body, method=method,
                                     headers={"Authorization": "Bearer " + TOKEN,
                                              "Content-Type": "application/json"})
        started = time.perf_counter()
        try:
            with _OPENER.open(req, timeout=120) as resp:
                status, raw = resp.status, resp.read()
                ctype = resp.headers.get("Content-Type", "application/json")
        except urllib.error.HTTPError as error:
            status, raw = error.code, error.read()
            ctype = error.headers.get("Content-Type", "application/json")
        except Exception as error:
            status, raw, ctype = 502, b'{"error":"upstream"}', "application/json"
            sys.stderr.write(f"upstream error {type(error).__name__}\n")
        ms = (time.perf_counter() - started) * 1000
        if "/rpc" in path:
            sys.stderr.write(f"{time.time():.3f} rpc status={status} in={length} "
                             f"out={len(raw)} relay_ms={ms:.0f}\n")
        self._send(status, raw, ctype, {"X-Relay-Ms": f"{ms:.1f}"})

    def _send(self, status, raw, ctype, extra=None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        self._forward("GET")

    def do_POST(self):
        self._forward("POST")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--upstream", default="http://127.0.0.1:8787")
    ap.add_argument("--port", type=int, default=18790)
    args = ap.parse_args()
    if len(TOKEN) < 24:
        sys.stderr.write("LOOPCTRL_RELAY_OPERATOR_TOKEN is not set\n")
        return 2
    Handler.upstream = args.upstream.rstrip("/")
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    server.daemon_threads = True
    sys.stderr.write(f"operator shim on 127.0.0.1:{args.port} -> {Handler.upstream}\n")
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
