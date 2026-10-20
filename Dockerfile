FROM docker.io/library/rust:1.98-slim-trixie AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config libnftnl-dev libmnl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY servers/ servers/
COPY src/ src/
RUN set -eu; \
    case "$(uname -m)" in \
      x86_64) target="x86_64-unknown-linux-gnu" ;; \
      aarch64) target="aarch64-unknown-linux-gnu" ;; \
      *) exit 1 ;; \
    esac; \
    cargo build --release --locked --target "$target"; \
    install -D -m 0755 "target/$target/release/tune" /out/tune

FROM docker.io/library/debian:trixie-slim

LABEL org.opencontainers.image.title="tune" \
      org.opencontainers.image.description="Kernel WireGuard VPN gateway with nftables" \
      org.opencontainers.image.source="https://github.com/mlshdev/tune-rs"

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates libnftnl11 libmnl0 util-linux passwd \
    && groupadd --gid 1000 tune \
    && useradd --uid 1000 --gid 1000 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin tune \
    && install -d -o 1000 -g 1000 /gluetun/servers /tmp/gluetun \
    && rm -rf /var/lib/apt/lists/* /var/cache/debconf /etc/passwd- /etc/group- /etc/shadow- /etc/gshadow- /var/lib/dpkg/status-old

COPY --from=builder /out/tune /usr/local/bin/tune

ENV PUID=1000 PGID=1000
VOLUME ["/gluetun/servers", "/tmp/gluetun"]
EXPOSE 53/udp 53/tcp 9999/tcp 8888/tcp 1080/tcp 1080/udp

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 CMD ["/usr/local/bin/tune", "healthcheck"]

# PID 1 starts with only the Compose-granted capabilities and immediately execs the app as UID 1000.
ENTRYPOINT ["/usr/bin/setpriv", "--reuid=1000", "--regid=1000", "--clear-groups", "--inh-caps=+net_admin", "--ambient-caps=+net_admin", "/usr/local/bin/tune"]
CMD ["run"]
