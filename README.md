<div align="center">
  <img src="docs/hs-logo.svg" alt="hypershunt" width="440">
  <p>HTTP server and reverse proxy.<br>
  Simple configuration. Just works. No surprises.<br>
  Written in Rust for memory safety.</p>

  <p>
  <a href="https://github.com/MichaelPaddon/hypershunt/actions/workflows/build.yml"><img src="https://github.com/MichaelPaddon/hypershunt/actions/workflows/build.yml/badge.svg" alt="build"></a>
  <a href="https://github.com/MichaelPaddon/hypershunt/releases"><img src="https://img.shields.io/github/v/release/MichaelPaddon/hypershunt?include_prereleases" alt="release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-BSD--2--Clause-blue" alt="license"></a>
  </p>
</div>

> **Status:** release-candidate — approaching 1.0 (currently
> 1.0.0-rc14).  The config format is stable; no breaking changes are
> expected before 1.0.

hypershunt puts the whole serving stack in one coherent place: a
modern KDL configuration instead of accreted directive syntax,
first-class operations (systemd socket activation, hot config reload,
seamless binary upgrades with zero dropped connections), and
batteries-included authentication — OIDC single sign-on, JWT sessions,
PAM/LDAP/htpasswd — with no separate auth proxy to deploy.

A static site and an API behind automatic TLS is this:

```kdl
server state-dir="/var/lib/hypershunt"   // ACME certificate storage

listener "tcp://[::]:80"             // ACME challenges + redirects
listener "tcp://[::]:443" {
    tls "acme" email="you@example.com" {
        domain "example.com"
        domain "api.example.com"
    }
}

vhost "example.com" {
    location "/" { static root="/var/www/example" }
}

vhost "api.example.com" {
    location "/" { proxy { upstream "http://127.0.0.1:8080" } }
}
```

Or try it in one line, no root required — the container serves its own
documentation out of the box:

```sh
podman run --rm --pull=newer -p 8080:80 -p 8443:443 ghcr.io/michaelpaddon/hypershunt:latest
```

Open <http://localhost:8080> (or <https://localhost:8443> with the
ephemeral self-signed certificate), then walk through the
[Quick start](docs/quickstart.md).

## Features

- **Serving** --- static files (range, ETag, `try-files`), redirects,
  inline responses, custom error pages.
- **Routing** --- virtual hosts (literal + regex), request matchers,
  URL rewrites with regex captures.
- **Reverse proxy** --- HTTP/1, HTTP/2, HTTP/3 upstreams; load
  balancing, health checks, retries; FastCGI, SCGI, CGI.
- **Layer-4 proxy** --- TCP, UDP, and Unix-socket forwarders with
  optional TLS termination.
- **TLS** --- ACME (HTTP-01, DNS-01, TLS-ALPN-01), file-based PEM,
  self-signed; OCSP stapling; mTLS with CRLs.
- **Auth & access control** --- HTTP Basic (PAM, LDAP, htpasswd),
  JWT sessions, OIDC SSO, firewall-style policy blocks.
- **Operations** --- compression, structured access logs, status page,
  health endpoints, hot reload, seamless binary upgrade, `.deb` /
  `.rpm` / OCI image.

…and more --- see the [configuration reference](docs/reference.md).

## Standards

| | |
|---|---|
| HTTP/1.1, HTTP/2, HTTP/3 | RFC 9112, RFC 9113, RFC 9114 |
| WebSocket; extended CONNECT | RFC 6455, RFC 8441 |
| TLS 1.2 / 1.3            | RFC 5246, RFC 8446 |
| ACME (HTTP-01, DNS-01, TLS-ALPN-01) | RFC 8555, RFC 8737 |
| OCSP stapling            | RFC 6066 §8 |
| JWT (ES256) / JWS / JWK / JWK thumbprint | RFC 7519, RFC 7515, RFC 7517, RFC 7638 |
| OAuth 2.0 PKCE, token revocation, resource indicators, `iss` param | RFC 7636, RFC 7009, RFC 8707, RFC 9207 |
| OpenID Connect 1.0 + back-channel logout | OIDC Core, OIDC Back-Channel Logout |
| HAProxy PROXY protocol v1 / v2 | HAProxy spec |
| CGI / FastCGI / SCGI     | RFC 3875, FastCGI 1.0, SCGI 1.0 |
| KDL configuration        | KDL v2 |

## Documentation

- [Quick start](docs/quickstart.md) --- five-minute container walkthrough.
- [Configuration guide](docs/guide.md) --- scenario-driven walkthroughs.
- [Configuration reference](docs/reference.md) --- every directive hypershunt accepts.
- [Grammar](docs/grammar.md) --- formal KDL syntax.
- [Manual](docs/manual.md) --- the hypershunt(1) man page.

## Install

Every [release](https://github.com/MichaelPaddon/hypershunt/releases)
ships `.deb` and `.rpm` packages:

| Package | OS family | Architectures |
|---|---|---|
| `.deb` | Debian / Ubuntu | `amd64`, `arm64` |
| `.rpm` | RHEL / Fedora | `x86_64`, `aarch64` |

```sh
sudo dpkg -i hypershunt_<version>_<arch>.deb    # Debian/Ubuntu
sudo rpm -i  hypershunt-<version>.<arch>.rpm    # RHEL/Fedora
sudo systemctl enable --now hypershunt
```

Building from source (prerequisites, tests, and packaging) is covered in
[BUILD.md](BUILD.md).

Next steps: the [Quick start](docs/quickstart.md), then the
[configuration guide](docs/guide.md).

## fail2ban

The `.deb` / `.rpm` packages install ready-to-use (disabled) fail2ban
jails for the [security signals](docs/guide.md#security-signals-fail2ban).
For the container image they're bundled at
`/usr/share/doc/hypershunt/fail2ban/` to copy onto the host — fail2ban
runs on the host, not in the container.

## Operations notes

A fresh install ships an empty `/var/www/hypershunt/` and redirects `/`
to the bundled docs at `/docs/`; drop your own `index.html` into the
webroot and the redirect stops firing.

## License

BSD 2-Clause --- see [LICENSE](LICENSE).
