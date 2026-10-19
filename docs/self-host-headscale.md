# Self-hosting Headscale (tailnet fallback)

The fallback connection method: customer phones join a private tailnet run by
your own [Headscale](https://github.com/juanfont/headscale) control server,
and operators reach LoopCtrl at the phone's tailnet address. Traffic is
WireGuard, direct when NAT allows and otherwise through your own embedded
DERP relay. No public Tailscale infrastructure is used.

Use it when the in-app relay is not an option, or when you already run a
tailnet. It needs more setup on the phone (Shadowrocket or another Tailscale
client) than the relay's one scan.

## What you need

- A Linux host with Docker and a public IPv4 address.
- A DNS name for the control server, e.g. `hs.example.com`.
- nginx (or another proxy) for TLS on 443, and **UDP 3478** open to the
  internet (STUN for the embedded DERP; also open it in your cloud security
  group).

## 1. Configure

```sh
cd connect/headscale
cp .env.example .env && chmod 600 .env
sed -i 's/HEADSCALE_DOMAIN/hs.example.com/; s/SERVER_IPV4/203.0.113.10/' config/config.yaml
$EDITOR .env          # HEADSCALE_DOMAIN=hs.example.com
```

`config/config.yaml` lists only what differs from upstream's
`config-example.yaml` for the pinned version. Highlights:

- the embedded DERP is the **only** relay offered (`derp.urls: []`);
- `node.expiry: 0`, so customer phones do not drop off on a timer;
- `magic_dns` on with `override_local_dns: false`, so Shadowrocket keeps
  doing the phone's DNS.

`config/policy.hujson` is the ACL: `tag:operator` may reach `tag:customer` on
TCP 8300 (LoopCtrl's port) and nothing else is allowed. Phones can't reach
each other or your side.

## 2. TLS

```sh
install -d /var/www/hs-acme
certbot certonly --webroot -w /var/www/hs-acme -d hs.example.com
sed 's/HEADSCALE_DOMAIN/hs.example.com/g' nginx-site.conf > /etc/nginx/conf.d/hs.example.com.conf
nginx -t && systemctl reload nginx
```

The site file expects a `map $http_upgrade $connection_upgrade` at http level
(most setups already have one). The control protocol and DERP both ride HTTP
upgrades, hence the long timeouts and `proxy_buffering off`.

The relay can share this name: add `connect/relay/nginx-location.conf` to the
same server block and set `LOOPCTRL_RELAY_PUBLIC_SERVER=hs.example.com/loopctrl-relay`.

## 3. Start Headscale

```sh
docker compose up -d headscale
docker exec headscale headscale users create loopctrl   # owns the tags in policy.hujson
curl -s https://hs.example.com/health
```

## 4. Join an operator node

The compose file has an `operator` service: a userspace Tailscale node tagged
`tag:operator` with a SOCKS5 proxy on `127.0.0.1:1055`, so it never touches
the host's own networking.

```sh
docker exec headscale headscale preauthkeys create --tags tag:operator --reusable=false --expiration 1h
# put the key in .env as OPERATOR_AUTHKEY, then
docker compose up -d operator
docker exec headscale headscale nodes list
```

Any machine running Tailscale can be an operator instead: `tailscale up
--login-server=https://hs.example.com --authkey=<operator key>`.

## 5. Join a customer phone

Create a single-use key per phone, tagged `tag:customer`:

```sh
docker exec headscale headscale preauthkeys create --tags tag:customer --reusable=false --expiration 24h
```

In Shadowrocket, add a Tailscale node with the control server
`https://hs.example.com` and that auth key, and keep it enabled alongside your
usual rules. (Any Tailscale client that supports a custom login server works.)
In LoopCtrl the connection then shows as **Tailscale** (`tailnet`) in the
pairing prompt.

## 6. Send commands

From an operator node, with the phone's tailnet address from `headscale nodes list`:

```sh
cli/loopctrl direct --host 100.64.0.7:8300 pair --name ops-laptop   # approve once on the phone
cli/loopctrl direct --host 100.64.0.7:8300 call device_info
```

Through the compose `operator` node, use its SOCKS5 proxy (for example with
`proxychains` or a SOCKS-aware client) to reach `100.64.x.y:8300`.

## Operating it

- **Back up** `data/db.sqlite` (use `sqlite3 db.sqlite ".backup …"` while
  running, not `cp`) and `data/*.key`. Losing the keys forces every node to
  re-register.
- **Upgrades:** read Headscale's changelog first, back up `data/`, bump the
  image tag in `docker-compose.yml` and the config together.
- **Revoking a phone:** `headscale nodes delete -i <id>`.
