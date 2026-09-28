FROM --platform=$BUILDPLATFORM mcr.microsoft.com/dotnet/sdk:10.0 AS build
ARG TARGETARCH
RUN apt-get update \
    && apt-get install -y --no-install-recommends zip \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN case "$TARGETARCH" in \
        amd64) rid=linux-musl-x64 ;; \
        arm64) rid=linux-musl-arm64 ;; \
        *) echo "Unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac \
    && dotnet publish src/ZenitiumDns/ZenitiumDns.csproj -c Release -r "$rid" --self-contained true -p:PublishReadyToRun=true -p:DebugType=embedded -o /out/opt/zenitiumdns --nologo -v quiet -clp:ErrorsOnly \
    && rm -f /out/opt/zenitiumdns/install.sh /out/opt/zenitiumdns/uninstall.sh /out/opt/zenitiumdns/start.sh /out/opt/zenitiumdns/openrc.service /out/opt/zenitiumdns/systemd.service \
    && mkdir -p /out/usr/share/zenitiumdns/apps \
    && for project in apps/*/*.csproj; do \
        name="$(basename "$project" .csproj)"; \
        dotnet publish "$project" -c Release -p:DebugType=embedded -o "/tmp/apps/$name" --nologo -v quiet -clp:ErrorsOnly || exit 1; \
        (cd "/tmp/apps/$name" && zip -q -r -X "/out/usr/share/zenitiumdns/apps/$name.zip" .) || exit 1; \
    done
COPY setup/container/entrypoint.sh /out/usr/local/bin/zenitiumdns-entrypoint

FROM docker.io/library/alpine:3.22
ARG VERSION=dev
LABEL org.opencontainers.image.title="ZenitiumDNS" \
      org.opencontainers.image.description="Recursive DNS resolver with blocking, DNS-over-TLS/HTTPS/QUIC and a web interface" \
      org.opencontainers.image.source="https://github.com/DNSBunker/ZenitiumDNS" \
      org.opencontainers.image.licenses="GPL-3.0-or-later" \
      org.opencontainers.image.version="$VERSION"
RUN apk add --no-cache icu-libs icu-data-full libgcc libstdc++ libssl3 libmsquic tzdata ca-certificates su-exec libcap-setcap \
    && addgroup -S -g 1053 zenitiumdns \
    && adduser -S -D -H -u 1053 -G zenitiumdns -h /etc/zenitiumdns -s /sbin/nologin zenitiumdns
COPY --from=build /out/ /
RUN setcap cap_net_bind_service=+ep /opt/zenitiumdns/ZenitiumDns \
    && apk del --no-cache libcap-setcap \
    && chmod 0755 /usr/local/bin/zenitiumdns-entrypoint \
    && mkdir -p /etc/zenitiumdns /var/log/zenitiumdns \
    && chown zenitiumdns:zenitiumdns /etc/zenitiumdns /var/log/zenitiumdns \
    && chmod 0750 /etc/zenitiumdns /var/log/zenitiumdns
ENV OPENSSL_ENABLE_SHA1_SIGNATURES=1 \
    DNS_SERVER_ADMIN_PASSWORD_FILE=/etc/zenitiumdns/admin.password
WORKDIR /opt/zenitiumdns
VOLUME ["/etc/zenitiumdns", "/var/log/zenitiumdns"]
EXPOSE 53/udp 53/tcp 5380/tcp 53443/tcp 853/tcp 853/udp 443/tcp 443/udp
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/zenitiumdns-entrypoint"]
