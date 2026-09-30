# Container image

[Deutsche Version](Container.de.md)

ZenitiumDNS is available as an OCI container image for amd64 and arm64. It is built from this repository for every release and runs with Podman and Docker:

```
ghcr.io/dnsbunker/zenitiumdns:latest
ghcr.io/dnsbunker/zenitiumdns:15.5.1-11
```

The image is based on Alpine Linux and contains the self-contained server, the bundled apps and `libmsquic` for DNS-over-QUIC and HTTP/3. The server runs as the unprivileged user `zenitiumdns` (uid and gid 1053).

## Start

```
podman run -d --name zenitiumdns \
  -p 53:53/udp -p 53:53/tcp -p 5380:5380/tcp \
  -v zenitiumdns-config:/etc/zenitiumdns \
  -v zenitiumdns-logs:/var/log/zenitiumdns \
  --restart unless-stopped \
  ghcr.io/dnsbunker/zenitiumdns:latest
```

With Docker, use the same command with `docker` instead of `podman`.

Rootless Podman may not publish ports below 1024. Either start the container as root, allow low ports with `sudo sysctl net.ipv4.ip_unprivileged_port_start=53`, or use the host network (`--network host`). Some rootless network modes replace the client address with the address of the container gateway; for statistics, rate limiting and access rules with the real client addresses, use the host network or a rootful container.

## First sign-in

On the first start, the container creates a random password for the user `admin` and prints it to the container log:

```
podman logs zenitiumdns
```

The password is also stored in `/etc/zenitiumdns/admin.password`. Open `http://<host>:5380/`, sign in, choose the language and change the password under the account menu. The server then deletes the file itself.

## Ports

| Port | Protocol | Service |
| ---- | -------- | ------- |
| 53 | UDP, TCP | DNS |
| 5380 | TCP | Web interface (HTTP) |
| 53443 | TCP | Web interface (HTTPS, when enabled) |
| 853 | TCP | DNS-over-TLS |
| 853 | UDP | DNS-over-QUIC |
| 443 | TCP, UDP | DNS-over-HTTPS with HTTP/2 and HTTP/3 |

Only publish the ports of the services you enable. Certificates for the encrypted protocols belong into the configuration volume, for example `/etc/zenitiumdns/fullchain.pem` and `/etc/zenitiumdns/privkey.pem`, readable for uid 1053; enter them under Settings > Encrypted protocols relative to the configuration folder.

## Volumes

| Path | Content |
| ---- | ------- |
| `/etc/zenitiumdns` | Settings, users, statistics, cache, downloaded block lists and installed apps |
| `/var/log/zenitiumdns` | Log files |

The container starts as root, hands the configuration and log directories to uid 1053, including directories mounted from the host, and then starts the server as that user. If the container runs with a fixed user (`--user` or `user:` in Compose), it cannot change the owner itself; mounted directories must then be writable for that user, otherwise the container stops with a message naming the directory:

```
sudo mkdir -p /srv/zenitiumdns/config /srv/zenitiumdns/logs
sudo chown -R 1053:1053 /srv/zenitiumdns
```

Local block lists (`file://`) must also be stored in the configuration volume, for example `file:///etc/zenitiumdns/lists/my-list.txt`.

## Recursion

New installations only answer recursive queries from private networks. That is enough at home and in company networks. If clients reach the server from public addresses, adjust recursion under Settings > Resolver and check the rate limits.

## Update

```
podman pull ghcr.io/dnsbunker/zenitiumdns:latest
podman rm -f zenitiumdns
```

Then start the container again with the same command. Settings and statistics stay in the volumes.

## Memory

Environment variables are passed with `-e`. To make the garbage collection compact the heap more often when memory is tight (at the cost of longer pauses, see [README.Debian](../setup/debian/README.Debian.md)):

```
-e DOTNET_GCConserveMemory=5
```

## Building the image yourself

```
podman build -t zenitiumdns -f Containerfile .
```

The build stage always runs on the architecture of the build machine and compiles for the target architecture. Building for another architecture, for example with `--platform linux/arm64`, needs `qemu-user-static` for the last stage.
