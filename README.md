# LoopCtrl-Server

The connection layer for [LoopCtrl](https://github.com/Souitou-iop/LoopCtrl):
the server-side pieces that let an operator reach a phone's LoopCtrl from
another network. Everything here can be self-hosted.

LoopCtrl runs an XCUITest runner on the iPhone that serves an encrypted
JSON-RPC API (protocol v1, port 8300). On the same Wi-Fi an operator talks to
it directly. From anywhere else it needs a path to the phone, and this repo
provides two interchangeable ones:

| | In-app relay (`connect/relay/`) | Headscale tailnet (`connect/headscale/`) |
|---|---|---|
| Phone setup | Scan an invite QR code in LoopCtrl. Nothing else. | Join a tailnet through Shadowrocket (or another Tailscale client) with a pre-auth key. |
| Server | One small Python process behind HTTPS. | Headscale + embedded DERP relay behind HTTPS, UDP 3478 for STUN. |
| Transport | HTTPS long-poll through the relay. | WireGuard, direct when NAT allows, otherwise via your DERP. |
| Operator reaches | `relay/operator` endpoints with a bearer token. | `100.64.x.y:8300` from any `tag:operator` node. |
| Use it when | Default. Zero configuration on the customer's phone. | Fallback, or when you already run a tailnet. |

Either way the operator pairs with the phone (X25519) and every call is
sealed end to end with the LoopCtrl v1 envelope. **Neither the relay nor
Headscale can read or forge requests.** The relay is untrusted by design: the
invite names the operator keys the phone will accept.

## Layout

```
connect/relay/        the relay server, its self-test, operator tools,
                      Dockerfile, compose file, nginx and systemd templates
connect/headscale/    Headscale + embedded DERP: compose file, config, ACL policy, nginx
cli/                  `loopctrl` operator CLI (direct or through the relay)
docs/                 self-hosting guides and the protocol overview
```

## Quick start

Relay, with Docker, behind your own HTTPS reverse proxy:

```sh
cd connect/relay
cp relay.env.example relay.env && $EDITOR relay.env
install -d -m 0700 -o 10001 -g 10001 state
docker compose up -d
curl -s http://127.0.0.1:8787/healthz
```

Then mint an invite and drive the phone:

```sh
export LOOPCTRL_RELAY_URL=https://relay.example.com
export LOOPCTRL_RELAY_OPERATOR_TOKEN=...      # from relay.env
cli/loopctrl relay enroll --name "Alex"       # prints the loopctrl://connect link; show it as a QR code
cli/loopctrl relay devices
cli/loopctrl relay pair --device-id dev_...   # approved automatically: the invite named your key
cli/loopctrl relay call --device-id dev_... device_info
```

Full guides:

- [docs/self-host-relay.md](docs/self-host-relay.md): the relay (Docker or systemd).
- [docs/self-host-headscale.md](docs/self-host-headscale.md): Headscale + DERP, and joining phones through Shadowrocket.
- [docs/protocol.md](docs/protocol.md): how the pieces fit, and where each contract is defined.

## Images

Tagged releases publish `ghcr.io/souitou-iop/loopctrl-relay:<version>` (and
`:latest`). Headscale uses the upstream `headscale/headscale` image.

## Development

```sh
python3 connect/relay/selftest.py     # the relay, in-process, both sides; no iPhone needed
ruff check .
```

Python 3.10+, standard library only (the operator CLI uses `cryptography`
for X25519 pairing if it is installed, and falls back to pure Python).

## License

Apache-2.0, like LoopCtrl.
