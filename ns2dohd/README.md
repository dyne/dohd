![dohd logo](https://raw.githubusercontent.com/dyne/dohd/master/docs/dohd.png)

<p align="center">
  <a href="https://dyne.org">
    <img src="https://img.shields.io/badge/%3C%2F%3E%20with%20%E2%9D%A4%20by-Dyne.org-blue.svg" alt="Dyne.org" />
  </a>
</p>

<h4 align="center">
  <a href="#-install">💾 Install</a>
  <span> • </span>
  <a href="#-quick-start">🎮 Quick start</a>
  <span> • </span>
  <a href="#-configuration">🔧 Configuration</a>
  <span> • </span>
  <a href="#-license">💼 License</a>
</h4>

`ns2dohd` is a local DNS-to-DoH gateway daemon.
It listens on `127.0.0.1:53` (by default), accepts classic DNS requests, and forwards them to a trusted DoH endpoint using wolfSSL + nghttp2.

***
# 💾 Install

Build requirements: `gcc` or `clang`, `make`, `wolfSSL`, `nghttp2`.

1. Build binaries:

```bash
make build
```

2. Install binaries and manpages (default prefix `/usr/local`):

```bash
sudo make install
```

You can override installation paths, for example:

```bash
sudo make install PREFIX=/usr
```

***
# 🎮 Quick start

Run as root to bind port `53`, then drop privileges using `-u`:

```bash
ns2dohd -d https://dns.dyne.org/dns-query -u nobody
```

`ns2dohd` daemonizes by default. Use `-F` to stay in foreground.

Common options:

- `-d <https://...>` DoH endpoint URL (mandatory)
- `-O` enable ODoH client mode
- `--odoh-proxy <https://...>` ODoH proxy URL (required with `-O`)
- `--odoh-config <file>` binary target ODoH config file (required with `-O`)
- `-p <port>` local UDP port (default: `53`)
- `-u <user>` drop privileges after bind
- `-r <resolver_ip>` bootstrap resolver used to resolve the DoH endpoint host (default: `1.1.1.1`)
- `-A <cafile>` custom CA bundle
- `-F` foreground mode
- `-v` verbose logs

See full options with:

```bash
ns2dohd -h
man ns2dohd
```

***
# 🔧 Configuration

To use `ns2dohd` as your host DNS resolver, configure your system DNS to point to localhost.

## /etc/resolv.conf

Set:

```conf
nameserver 127.0.0.1
```

## NetworkManager

Set `127.0.0.1` as the primary DNS server in your active network profile, then reconnect.

After either configuration, keep `ns2dohd` running as a background daemon as root (with `-u` recommended).

Notes:

- `ns2dohd` uses a separate bootstrap resolver (default `1.1.1.1`) for resolving the DoH endpoint hostname, avoiding resolver recursion.
- Change bootstrap resolver with `-r`, for example `-r 9.9.9.9`.
- In ODoH mode, the `-d` endpoint is the target resolver and is automatically passed to the proxy as `targethost` and `targetpath`.

## ODoH deployment warning (RFC 9230)

Do not treat a same-host or same-organization proxy+target deployment as private ODoH operation.
The ODoH threat model assumes independent proxy and target operators.

Local co-location is only suitable for protocol evaluation and debugging.

***
# 💼 License

This is free software distributed under the GNU Affero General Public License (AGPLv3).

Author: Dyne.org Foundation `<info@dyne.org>`
