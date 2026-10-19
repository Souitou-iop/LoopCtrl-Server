# Headscale + embedded DERP

Templates for LoopCtrl's tailnet connection method. The full guide is
[docs/self-host-headscale.md](../../docs/self-host-headscale.md).

| File | What it is |
|---|---|
| `docker-compose.yml` | `headscale` (host networking, 127.0.0.1:8085 + UDP 3478) and an `operator` node (userspace Tailscale, SOCKS5 on 127.0.0.1:1055). |
| `config/config.yaml` | Headscale config. Replace `HEADSCALE_DOMAIN` and `SERVER_IPV4`. |
| `config/policy.hujson` | ACL: `tag:operator` → `tag:customer` on TCP 8300 only. |
| `nginx-site.conf` | TLS front for the control server and DERP. Replace `HEADSCALE_DOMAIN`. |
| `.env.example` | `HEADSCALE_DOMAIN`, `OPERATOR_AUTHKEY`. Copy to `.env`. |

`data/`, `run/`, `operator/` and `.env` are created at runtime and ignored by git.
