## Layout

Single-crate Rust (`tune`: lib + one binary) plus a Docker stack that runs it. The crate is Linux-only — netlink, rtnetlink, nftables — so nothing here compiles or tests on macOS (see Testing).

Rust:

```text
Cargo.toml  Cargo.lock            # crate `tune`, edition 2024, MSRV 1.98; no workspace
src/lib.rs                       # library root — declares every module
src/main.rs                      # thin binary: CLI parsing, signals, process lifecycle
src/<module>.rs                  # top-level modules: cli, firewall, routing, vpn, socks5, …
src/<module>.rs + src/<module>/   # dir modules, file+dir style (never <module>/mod.rs): config/, control/, dns/, provider/, wireguard/
servers/mullvad.json             # bundled Mullvad relay dataset (include_str! in src/storage.rs)
```

- Unit tests are inline `#[cfg(test)] mod tests { use super::*; … }` at the bottom of the file under test — 31 files, 125 tests. There is no `tests/`, `benches/`, or `examples/` directory; `cargo test` collects the lib target's inline tests (the binary declares none).
- New module → `src/<module>.rs` plus `src/<module>/` for submodules, and its `pub mod` line in `src/lib.rs`.

Docker stack:

```text
Dockerfile                       # multi-stage: rust:1.98-slim-trixie builder → debian:trixie-slim runtime
.dockerignore
compose.yml                      # base stack: one `tune` service, no published host ports (Traefik mode)
compose.override.yml             # auto-loaded by docker compose — publishes 8888/1080 on PROXY_BIND_ADDRESS
tune/config/                     # bind-mount sources: resolv.conf, servers/ (persisted relay lists)
tune/data/                       # bind-mount source: /tmp/gluetun state (public-IP status)
tune/logs/                       # placeholder only — compose does not mount it
traefik/config/tune.yml.example  # file-provider TCP router example for an existing Traefik deployment
.env.example                     # committed placeholder env vars; real .env is gitignored, never committed
```

- Bind mounts resolve on the engine (`homevm`), not on the Mac — rsync the tree to `~/dev/tune-rs` there before `docker compose up`.

CI and meta:

```text
.github/workflows/ci.yml         # fmt + build + test + clippy on native ubuntu-26.04 / ubuntu-26.04-arm
.github/workflows/image.yml      # validated multi-arch image build → ghcr.io manifest list
.github/dependabot.yml           # cargo, docker, github-actions — twice weekly
README.md                        # user-facing: commands, quickstart, proxy access, namespace sharing
TECHNICAL.md                     # internals: architecture, build and validation workflow
HANDOFF.md                       # session handoff — read before acting, keep current per task
```

Root also carries `.scratch/` (gitignored) for one-off session notes, session exports, and scratch validation scripts — never committed, never shipped; delete or promote its contents before finishing a task.

## Testing

The crate needs Linux (`pkg-config`, `libnftnl-dev`, `libmnl-dev`); the Mac cannot compile or test it. Sync to homevm first, then run cargo inside the dev toolchain image:

```sh
rsync -a --delete --exclude .git --exclude .claude --exclude target \
  --exclude '*/logs/*' --exclude '*/data/*' --exclude '*/cache/*' ./ homevm:dev/tune-rs/
```

- Unit: `docker run --rm --name dev-tune-rs-check --cap-drop ALL --cap-add NET_ADMIN --security-opt no-new-privileges:true --sysctl 'net.ipv4.ping_group_range=0 2147483647' --mount type=bind,src=/home/mlsh/dev/tune-rs,dst=/src --mount type=volume,src=dev-tune-rs-cargo,dst=/usr/local/cargo/registry --mount type=volume,src=dev-tune-rs-target,dst=/src/target dev-tune-rs-toolchain:local cargo test --locked --target x86_64-unknown-linux-gnu` · one file: same wrapper with a TESTNAME filter — `… dev-tune-rs-toolchain:local cargo test --locked --target x86_64-unknown-linux-gnu socks5::` (tests are inline, so filter by module path; `--lib` skips the binary and doc targets)
- Integration: same wrapper plus `-- --include-ignored` (needs: `--cap-add NET_ADMIN` in a disposable network namespace for `firewall::tests::kernel_accepts_full_ruleset`; outbound networking + `net.ipv4.ping_group_range` for `pmtud::tests::discovers_container_path_mtu`; public Mullvad API access — no credentials — for `updater::tests::live_mullvad_relay_schema`)
- E2E: none — no committed E2E harness; runtime smoke scripts so far were scratch files outside the repo
- Before finishing: `cargo fmt --check && cargo clippy --locked --target x86_64-unknown-linux-gnu --all-targets -- -D warnings && cargo test --locked --target x86_64-unknown-linux-gnu` — all three inside the same dev container (clippy doubles as the typecheck)

CI (`ci.yml`, `image.yml`) runs plain `cargo test`, so the three ignored tests are skipped there. arm64 is validated only by the native `ubuntu-26.04-arm` CI runner — never emulate it on homevm.