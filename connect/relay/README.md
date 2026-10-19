# Relay

LoopCtrl's in-app relay: invite enrollment plus an HTTPS long-poll transport.
Standard-library Python. The full guide is
[docs/self-host-relay.md](../../docs/self-host-relay.md); the API is defined in
LoopCtrl's [docs/relay-enrollment.md](https://github.com/Souitou-iop/LoopCtrl/blob/main/docs/relay-enrollment.md).

| File | What it is |
|---|---|
| `loopctrl_relay_server.py`, `ed25519.py` | The relay. |
| `selftest.py` | In-process test of the whole API, operator and phone sides. |
| `relay_operator.py` | Operator client (`cli/loopctrl relay …`). |
| `relay_bench.py` | Latency and soak tests through a relay, or direct for comparison. |
| `operator_shim.py` | Ephemeral forwarder run on the relay host over SSH, so device tests can use the operator API without the token leaving the host. |
| `Dockerfile`, `docker-compose.yml`, `relay.env.example` | Container deployment. |
| `systemd/` | Unit template and `render-unit.sh` for running from a checkout. |
| `nginx-site.conf`, `nginx-location.conf` | TLS front: own name, or a path on an existing site. |
