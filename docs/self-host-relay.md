# Self-hosting the relay

The relay (`connect/relay/loopctrl_relay_server.py`) lets a phone running
LoopCtrl be controlled from anywhere with no VPN on the phone. The customer
scans one invite; LoopCtrl then keeps a long-poll channel open to the relay,
and operators send sealed requests through it.

The relay never sees plaintext: pairing and every call are end to end between
the operator and the phone. It stores only enrolled devices' public keys
(`state.json`). Enrollment codes, tokens and challenges live in memory.

## What you need

- A public HTTPS name the phone trusts, either a name of its own
  (`relay.example.com`) or a path on an existing site
  (`example.com/loopctrl-relay`).
- A reverse proxy for TLS (nginx templates are in `connect/relay/`).
- Docker, or Python 3.10+ for the systemd route. No other dependencies.

## 1. Configure

```sh
cd connect/relay
cp relay.env.example relay.env
chmod 600 relay.env
python3 -c 'import secrets; print(secrets.token_urlsafe(32))'   # paste as LOOPCTRL_RELAY_OPERATOR_TOKEN
$EDITOR relay.env
```

`LOOPCTRL_RELAY_PUBLIC_SERVER` must be the public name exactly as phones see
it, `host[:port][/path]` with no scheme and no trailing slash. Every signature
the phone makes is bound to it; a mismatch makes enrollment fail with
`bad_signature`.

## 2a. Run with Docker

```sh
install -d -m 0700 -o 10001 -g 10001 state     # the image runs as uid 10001
docker compose up -d                           # ghcr.io/souitou-iop/loopctrl-relay:latest
docker compose logs -f
```

Pin a version with `RELAY_VERSION=0.1.0 docker compose up -d`, or build
locally with `docker compose build`. The container listens on
`127.0.0.1:8787` on the host.

## 2b. Run with systemd

```sh
git clone https://github.com/Souitou-iop/LoopCtrl-Server /opt/loopctrl-server/current
install -d -m 0700 /etc/loopctrl-relay /var/lib/loopctrl-relay
install -m 0600 connect/relay/relay.env /etc/loopctrl-relay/relay.env

CODE_DIR=/opt/loopctrl-server/current \
ENV_FILE=/etc/loopctrl-relay/relay.env \
STATE_DIR=/var/lib/loopctrl-relay \
  /opt/loopctrl-server/current/connect/relay/systemd/render-unit.sh \
  > /etc/systemd/system/loopctrl-relay.service
systemctl daemon-reload
systemctl enable --now loopctrl-relay
```

`render-unit.sh` also takes `PYTHON`, `BIND`, `PORT` and `USER_NAME`. The unit
is sandboxed (`ProtectSystem=strict`); only `STATE_DIR` is writable.

## 3. Put it behind HTTPS

- Own name: `connect/relay/nginx-site.conf` (replace `RELAY_DOMAIN`).
- Under a path: include `connect/relay/nginx-location.conf` in your existing
  `server { listen 443 ssl; … }` block.

Keep `proxy_buffering off`, `proxy_request_buffering off` and the long
timeouts: each phone holds a request open for about 25 seconds at a time, and
screenshots travel as request bodies (allow up to 32 MB).

The relay rate-limits enrollment per client address, which it takes from
`X-Real-IP` when the request comes from a trusted proxy (loopback by default,
plus the Docker bridge in the compose file; `--trusted-proxies` /
`LOOPCTRL_RELAY_TRUSTED_PROXIES` to change).

Check it:

```sh
curl -s https://relay.example.com/healthz
# {"ok": true, "api": 1, "server": "relay.example.com"}
```

`server` must equal what you put in `LOOPCTRL_RELAY_PUBLIC_SERVER`.

## 4. Enroll a phone and send commands

```sh
export LOOPCTRL_RELAY_URL=https://relay.example.com
export LOOPCTRL_RELAY_OPERATOR_TOKEN=...      # never on the command line
cli/loopctrl relay key                        # your operator name and key ID
cli/loopctrl relay enroll --name "Alex" --org "Example Ops"
```

`enroll` prints a `loopctrl://connect?…` link. Show it as a QR code (or send
the link); the phone shows the organization and your name, and connects after
the customer confirms. Then:

```sh
cli/loopctrl relay devices
cli/loopctrl relay pair --device-id dev_0123456789abcdef
cli/loopctrl relay call --device-id dev_0123456789abcdef device_info
cli/loopctrl relay call --device-id dev_0123456789abcdef tap '{"x":100,"y":200}'
```

Pairing through the relay is pre-approved for the operator keys the invite
named; any other key still needs a tap on the phone. The operator key lives in
`~/.loopctrl/relay_operator.json`; keep it, because invites name it.

For timings and soak tests, `connect/relay/relay_bench.py` sends the same
sealed calls and reports latency.

## Operating it

- **Backups:** `state.json` only. Losing it unbinds every phone (each must
  scan a new invite); nothing else is lost.
- **Restarts** are safe: phones reconnect on their next poll, within seconds.
- **Logs:** with `LOOPCTRL_RELAY_EVENT_LOG=1`, one line per enrollment,
  channel and RPC event (ids, sizes, timings). Tokens and bodies are never
  logged. `LOOPCTRL_RELAY_ACCESS_LOG=1` adds an access log.
- **Token rotation:** change `LOOPCTRL_RELAY_OPERATOR_TOKEN` and restart.
  Phones are unaffected; operators need the new token.
- **Certificate pinning:** invites may carry `pin=` (the SPKI hash, see
  [protocol.md](protocol.md)). A pin breaks when the certificate key changes,
  so renew with the same key (`certbot --reuse-key`) if you pin.

## Testing

```sh
python3 connect/relay/selftest.py
```

Runs the relay in-process and plays both the operator and a phone (with its
own Ed25519 key) through enrollment, the channel, operator calls, unbind and
the rate limits. No iPhone needed.
