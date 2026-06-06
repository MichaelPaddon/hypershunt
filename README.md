<div align="center">
  <img src="docs/hypershunt-logo.png" alt="hypershunt" width="320">
  <p>HTTP server and reverse proxy.<br>
  Simple configuration. Just works. No surprises.</p>
</div>

---

hypershunt is an HTTP server written in Rust for speed and memory safety.

## Features

- **Serving** --- static files (range, ETag, `try-files`, opt-in
  directory listings, `~user/`), redirects, custom error pages,
  per-location header injection.
- **Routing** --- virtual hosts (literal + regex), per-location
  matchers (method, header, query), URL rewrites with regex
  captures, alias names, per-SNI ALPN.
- **Reverse proxy** --- HTTP/1, HTTP/2, HTTP/3 upstreams with
  connection pooling; multi-upstream load balancing (round-robin,
  least-conn, ip-hash, header-hash, random); active and passive
  health checks; retries; per-location rate limits and body caps;
  FastCGI, SCGI, CGI.
- **Layer-4 proxy** --- TCP, UDP, and `unix-stream` / `unix-dgram` /
  `unix-seqpacket` forwarders with optional TLS termination.
- **TLS** --- ACME (HTTP-01, DNS-01 via acme-dns / Cloudflare /
  Route 53 / exec, TLS-ALPN-01), file-based PEM, ephemeral
  self-signed; OCSP stapling on by default; mTLS with CRLs;
  shared `certificate` blocks across listeners.
- **Auth & access control** --- HTTP Basic (PAM, LDAP, htpasswd
  with bcrypt / SHA-512 crypt / Argon2id), subrequest auth, JWT
  session cookies (ES256, JWKS endpoint), OIDC SSO with PKCE and
  back-channel logout, OAuth 2.0 bearer resource-server mode,
  firewall-style policy blocks (IP / user / group / GeoIP country).
- **Operations** --- gzip / brotli / zstd response compression,
  structured access logs (NCSA Common/Combined, JSON), built-in
  status page, health endpoints, hot config reload (`SIGHUP`),
  seamless binary upgrade (`SIGUSR2`), socket activation,
  `hypershunt --check-config`, systemd unit, `.deb` / `.rpm` / OCI image.

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

```sh
# From package
sudo dpkg -i hypershunt_<version>_<arch>.deb        # or rpm -i
sudo systemctl enable --now hypershunt

# Container
podman run --rm -p 80:80 -p 443:443 ghcr.io/michaelpaddon/hypershunt:latest

# From source
cargo build --release
```

Building from source (prerequisites, tests, and packaging) is covered in
[BUILD.md](BUILD.md).

The `.deb`/`.rpm` packages install ready-to-use (disabled) fail2ban jails
for the [security signals](docs/guide.md#security-signals-fail2ban); for
the container image they're bundled at
`/usr/share/doc/hypershunt/fail2ban/` to copy onto the host (fail2ban
runs on the host, not in the container).

A fresh install ships an empty `/var/www/hypershunt/` and redirects `/`
to the bundled docs at `/docs/`; drop your own `index.html` into
the webroot and the redirect stops firing.

## License

BSD 2-Clause --- see [LICENSE](LICENSE).
