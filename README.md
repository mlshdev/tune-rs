# tune

An in-progress Rust rewrite of gluetun exclusively for **Mullvad VPN**, running in Docker on Linux amd64 and arm64. It uses kernel WireGuard, nftables via netlink, and Linux policy routing. DNS forwarding/filtering, HTTP, SOCKS5 and Shadowsocks proxies, Mullvad relay updates, a control API, and Prometheus metrics are implemented. Full parity and authenticated end-to-end VPN validation are not yet complete.

## Current commands

- `tune run` (or `tune`): load settings, configure firewall and policy routes, start the health endpoint and VPN connection loop, and clean up on SIGINT/SIGTERM.
- `tune healthcheck`: query the configured health endpoint; exit nonzero until a VPN health check succeeds.
- `tune genkey`: generate a random base58 API key, matching gluetun's command. `tune genkey --type wireguard` generates a WireGuard private key.
- `tune pubkey`: read a private key on standard input and print its public key.
- `tune format-servers`: print the bundled Mullvad relays as Markdown. `--format json|summary` selects JSON or a version/count summary; `--output PATH` writes a file instead of standard output.
- `tune update --directory PATH`: download, validate, and persist the current Mullvad relays without requiring VPN credentials. `--min-ratio` overrides `UPDATER_MIN_RATIO`; the default directory is `STORAGE_SERVERS_DIRECTORY_PATH` or `/gluetun/servers`. This explicit standalone command uses its current network namespace; run it inside the VPN container if the request must use the tunnel.

`run` requires a valid `WIREGUARD_PRIVATE_KEY` registered with Mullvad and the matching `WIREGUARD_ADDRESSES`. Copy both from your Mullvad WireGuard configuration, including its IPv6 address for in-tunnel IPv6. Alternatively, mount the configuration at `/run/secrets/wg0.conf` or set `WIREGUARD_CONF_SECRETFILE`. Mullvad is implicit; an optional `VPN_SERVICE_PROVIDER=mullvad` is accepted for migration, and any other VPN provider is rejected, including in `VPNSP` and `UPDATER_VPN_SERVICE_PROVIDERS`.

- Select relays with `SERVER_COUNTRIES` (alias `COUNTRY`), `SERVER_CITIES` (alias `CITY`), `SERVER_HOSTNAMES`, `ISP`, and `OWNED_ONLY`. **Countries are a priority list:** `COUNTRY=Czech Republic,Argentina` tries eligible Czech endpoints before Argentina. A country with no matching relays is skipped; failed connection health checks or PQ negotiations move through its remaining endpoints before falling back. `SERVER_SELECTION_MODE=random|ordered` controls selection within each country, not country priority. Other filters still apply to every fallback. Provider-specific tier, streaming, multihop, and port-forward filters are rejected.
- `WIREGUARD_QUANTUM_RESISTANT=on` (or gluetun's `MULLVAD_POST_QUANTUM_ENABLE=on`) enables Mullvad's ephemeral-peer key exchange.
- `DNS_UPSTREAM_RESOLVER_TYPE=dot|doh|plain` selects upstream DNS. Encrypted DNS defaults to Mullvad; `DNS_UPSTREAM_RESOLVERS` accepts `mullvad`, `mullvad adblock`, `mullvad base`, `mullvad extended`, `mullvad family`, or `mullvad all`. UDP/TCP clients receive `SERVFAIL` until the VPN is running.
- `UPDATER_PERIOD=24h` is the default: refresh active WireGuard relays when the VPN first runs, then periodically. `0` disables updates. Downloads run through the tunnel; failed requests retry after one minute. Invalid responses, empty lists, and lists below `UPDATER_MIN_RATIO` (default `0.8` of the current non-kept count) retain the last good list. Persistent lists marked `preferred` are left in place, and entries marked `keep` survive updates. New relays apply on the next tunnel connection.
- `HTTPPROXY=on` enables the HTTP/CONNECT proxy on port 8888; `SOCKS5=on` enables SOCKS5 TCP CONNECT on port 1080. Both refuse new connections until the tunnel is running; authentication is optional and configured with the corresponding `_USER`/`_PASSWORD` pairs (see the proxy authentication sections below).
- HTTP absolute-URI forwarding supports HTTP and certificate-validated HTTPS. CONNECT remains available for arbitrary TCP tunnels. `HTTPPROXY_STEALTH=on` suppresses adding `X-Forwarded-For`.
- `SHADOWSOCKS=on` enables encrypted TCP/UDP on port 8388. Set `SHADOWSOCKS_PASSWORD` (or its `_SECRETFILE`) and optionally `SHADOWSOCKS_CIPHER`; the default is `chacha20-ietf-poly1305`. Authenticated AEAD and AEAD-2022 ciphers are supported; AEAD-2022 requires a correctly sized base64 key. Replayed and unauthenticated datagrams are rejected. `SHADOWSOCKS_LOG=on` enables relay destination logging. All proxy connections and UDP associations close on tunnel changes or server shutdown.
- The control API listens at `HTTP_CONTROL_SERVER_ADDRESS` (default port 8000). `HTTP_CONTROL_SERVER_API_KEY` accepts Bearer or `X-API-Key` authentication; leave it unset only on a trusted, isolated network. See role-based authentication below.
- `/v1/vpn/status`, `/v1/dns/status`, and `/v1/updater/status` support GET/PUT with `{"status":"running"}` or `{"status":"stopped"}`. Stopping DNS cancels requests, clears its cache, and retains fail-closed listeners returning `SERVFAIL`. Updater requests can trigger a manual refresh even with `UPDATER_PERIOD=0`; downloads still wait for a running tunnel. Stopping the updater cancels the active download and pauses scheduling until restarted.
- `/v1/vpn/settings` supports GET and partial PUT using nested gluetun-style `provider.server_selection` and `wireguard` objects. Validated changes restart the VPN; invalid changes leave the configuration untouched. Secrets are redacted. For example, PUT `{"provider":{"server_selection":{"countries":["Sweden"],"mullvad_post_quantum":true}}}`. Settings are in-memory only; environment/secret files remain the startup source.
- `/v1/publicip/ip` reports the current IP; `/v1/version` reports the version. Legacy `/version`, `/unbound/actions/restart`, and `/updater/restart` are supported.
- `METRICS_TYPE=prometheus` exposes `/metrics` on port 9090, including gluetun-compatible `gluetun_tun_rx_bytes_total` and `gluetun_tun_tx_bytes_total` interface counters.

Mullvad does not offer VPN port forwarding; enabling `VPN_PORT_FORWARDING` or its legacy alias is a configuration error. Defaults and validation are in `src/config.rs`.

A healthy fallback tunnel stays connected; there is no disruptive periodic switch back. The preferred country is checked again on the next reconnect. If all eligible endpoints fail, retries restart from the first country with the existing VPN retry backoff. Setting `HEALTH_RESTART_VPN=off` disables health-triggered failover. This is priority-based failover, not ping/throughput benchmarking. Country values currently require names such as `Poland`, not ISO codes such as `PL`.

## Control API roles

Mount a TOML file and set `HTTP_CONTROL_SERVER_AUTH_CONFIG_FILEPATH` (default `/gluetun/auth/config.toml`). Roles can use `apikey`, `basic`, or `none` and are scoped to exact HTTP methods and paths:

```toml
[[roles]]
name = "status-reader"
auth = "apikey"
apikey = "replace-with-a-strong-secret"
routes = ["GET /v1/vpn/status", "GET /v1/dns/status"]
```

With a role file configured, unassigned routes are denied. `HTTP_CONTROL_SERVER_AUTH_DEFAULT_ROLE` can supply a JSON default role for unassigned routes, for example `{"auth":"basic","username":"operator","password":"replace-with-a-strong-secret"}`. Explicit route roles take precedence. API keys also support the legacy `api_key` query parameter, but headers avoid leaking credentials into URL histories. Keep authentication files out of version control.

## Container quickstart

1. Copy `.env.example` to `.env`; fill in your Mullvad WireGuard private key and matching addresses. For direct access, set `PROXY_BIND_ADDRESS` to your server's LAN IP. `.env` is ignored by Git.
2. On a Linux 6.12+ host with kernel WireGuard and Docker, run `docker compose up --build -d`.
3. Follow startup with `docker compose logs -f tune`. `docker compose down` stops the tunnel: policy routes are restored and the firewall is **sealed** — the deny-by-default kill switch stays committed until the container's network namespace is destroyed, so containers sharing Tune's network namespace cannot egress in the clear after Tune stops.

The stack bind-mounts `tune/config/resolv.conf` as the container's system resolver and persists Mullvad server data and public-IP status under `tune/config/servers` and `tune/data`. Ensure mounted state directories are writable by UID/GID 1000. The image launches a short capability-preserving bootstrap before executing `tune` as UID/GID 1000. The VPN process retains only `NET_ADMIN`; the bootstrap also needs `SETUID` and `SETGID` to change identity. The Compose file contains the required forwarding, router-advertisement, and ping-socket sysctls. The container does not need `/dev/net/tun` or `NET_RAW`.

## Browser proxy access

No SSH forwarding is required. Both proxies listen inside the VPN container; expose them directly on the server's LAN address or through Traefik TCP routers.

### Direct LAN access

Set `PROXY_BIND_ADDRESS` in `.env` to the server's LAN address (`192.168.1.101` for homevm). The `192.0.2.10` in `.env.example` is a documentation placeholder, not a working server address. Run `docker compose up --build -d`; Compose automatically loads `compose.override.yml` and publishes:

| Proxy | Browser server | Default port |
| --- | --- | --- |
| HTTP proxy, including HTTPS via CONNECT | Server's LAN IP | `8888` |
| SOCKS5 | Server's LAN IP | `1080` |

`HTTPPROXY_PUBLISHED_PORT` and `SOCKS5_PUBLISHED_PORT` change host ports without changing the container listeners.

### Optional SOCKS5 authentication

Leave `SOCKS5_USER` and `SOCKS5_PASSWORD` unset or blank to allow unauthenticated SOCKS5 on your trusted LAN. To require authentication, set both in `.env`:

```dotenv
SOCKS5_USER=browser
SOCKS5_PASSWORD=replace-with-a-strong-password
```

Providing only one is a configuration error. When both are set, the proxy requires username/password authentication and rejects incorrect credentials or clients offering only no-authentication. Each field must fit in 255 UTF-8 bytes. Your browser/client must support SOCKS5 username/password authentication; otherwise use the HTTP proxy or restrict unauthenticated SOCKS5 access using LAN controls. This authentication does not encrypt the browser-to-proxy connection.

### Optional HTTP proxy authentication

Leave `HTTPPROXY_USER` and `HTTPPROXY_PASSWORD` unset or blank for an unauthenticated HTTP proxy on your trusted LAN. To require Basic authentication, set both in `.env`:

```dotenv
HTTPPROXY_USER=browser
HTTPPROXY_PASSWORD=replace-with-a-strong-password
```

Setting either without the other is a configuration error, as is a username containing a colon (`:`) or control characters in either field; both are rejected before listeners bind. Unauthenticated or wrong-credential requests receive `407` without the origin ever being dialed. **Basic authentication is not encryption**: credentials travel base64-encoded in cleartext from browser to proxy, so pair it with a TLS frontend or restrict it to trusted networks. Enabling it does not change how HTTPS traffic is tunneled (CONNECT).

### Existing Traefik TCP load balancer

Run `docker compose -f compose.yml up --build -d` to omit host port publishing. Give your Traefik deployment network access to `tune:8888` and `tune:1080`, and load [traefik/config/tune.yml.example](traefik/config/tune.yml.example) through its file provider after adjusting the client IP allowlist. The example uses two dedicated entrypoints; add these to your existing Traefik static configuration:

```yaml
entryPoints:
  proxy-http:
    address: ":8888"
  proxy-socks5:
    address: ":1080"
```

Point the browser at the Traefik server's address and the corresponding entrypoint port. These are **plain TCP routers**, not HTTP routers or TLS/SNI virtual hosts; HTTPS sites travel through HTTP CONNECT normally. Traefik must be able to resolve and reach the backend names; no existing production network is joined automatically. If using published LAN backends instead, change the example's server addresses accordingly and avoid publishing Tune and Traefik on the same host address/port.

Keep Tune in its isolated bridge network. **Do not use `network_mode: host`**: its WireGuard interface, policy routes, and nftables kill switch would affect the host rather than just the container.

Traffic follows **browser → container proxy (directly or via Traefik) → Mullvad WireGuard → internet**. Enable proxy-side DNS for SOCKS5; HTTP proxy hostnames are resolved inside the container automatically. Forwarding is rejected until the VPN is running, and tunnel loss closes proxy connections. Do not disable `FIREWALL`. Restrict access to trusted clients using your LAN firewall, the Traefik IP allowlist, or proxy `_USER`/`_PASSWORD` pairs; never expose an unrestricted open proxy publicly.

Only traffic sent through the proxy is covered, not the Mac's other applications. SOCKS5 supports TCP CONNECT, not UDP; browser WebRTC/direct UDP and local DNS bypasses require browser-side restrictions if all browser traffic must remain tunneled. To tunnel an entire container instead of a browser, share Tune's network namespace as described below.

## Sharing Tune's network namespace

Route another service's **entire** traffic through the tunnel by joining Tune's network namespace — no proxy variables needed. The Compose **service key** in this stack is `tune`, so the companion uses `network_mode: "service:tune"` (in plain Docker: `--network container:<tune-container>`):

```yaml
services:
  companion:
    image: docker.io/library/your-application:tag # e.g. your existing MongoDB
    network_mode: "service:tune" # the Compose service key, not the image name
    depends_on:
      tune:
        condition: service_healthy
    # no ports:, networks:, or dns: entries — the companion shares Tune's stack
```

- `network_mode: "service:tune"` names the `tune` **service key** from `compose.yml` — not the image, hostname, or container name. Compose does not support `ports:`, `networks:`, or per-service `dns:` on a companion in service mode, so publish the companion's service ports on the `tune` service and list them in `FIREWALL_INPUT_PORTS` where its firewall must admit them explicitly. Docker publishes through Tune's network namespace either way.
- The companion shares Tune's `/etc/resolv.conf` automatically (verified on Docker Engine 29.9.1): Docker mounts Tune's bind-mounted loopback resolver file into the dependent container, so companion DNS already flows through Tune's fail-closed resolver — Docker's host-forwarded embedded DNS is not used. Add an explicit read-only `tune/config/resolv.conf` mount only if your engine does not propagate the file.
- TCP, UDP, and IPv6 routes, the nftables kill switch, and `localhost` are shared. The companion needs no capabilities (no `NET_ADMIN`), no engine socket, and no alternate networking; keep it unprivileged and read-only where possible.
- Both services share every port on `localhost` — avoid collisions between the companion's listeners and Tune's health (9999), control (8000), metrics (9090), HTTP (8888), SOCKS5 (1080), and Shadowsocks (8388) listeners.
- `depends_on` orders startup only. Recreate the companion when Tune is recreated; stopping Tune does not stop the companion, and Docker keeps the shared namespace alive while the companion still runs — which is exactly why Tune seals (rather than removes) its firewall on shutdown: the companion cannot egress in the clear after Tune stops.

## Development

Build and test inside a native Linux container with Rust 1.98+, `pkg-config`, `libnftnl-dev`, and `libmnl-dev`. With a development image containing those packages, rustfmt, and clippy, and source available on the Docker engine host:

```sh
docker run --rm -v "/path/on/engine/to/tune-rs:/src" -w /src dev-tune-rs-toolchain:local cargo test --locked --target x86_64-unknown-linux-gnu
docker run --rm -v "/path/on/engine/to/tune-rs:/src" -w /src dev-tune-rs-toolchain:local cargo clippy --locked --target x86_64-unknown-linux-gnu --all-targets -- -D warnings
```

Run only in an isolated network namespace while developing; `tune` manages nftables and policy routes in that namespace. There has not yet been a verified end-to-end connection to a commercial VPN server.

Use `aarch64-unknown-linux-gnu` on native Linux arm64 instead. Fetch dependencies only with `cargo fetch --locked --target x86_64-unknown-linux-gnu --target aarch64-unknown-linux-gnu`; no other deployment targets are supported.

See [TECHNICAL.md](TECHNICAL.md) for the implementation and validation workflow.
