# Troubleshooting

Common symptoms, their usual cause, and the fix.  Each entry links to
the chapter that covers the feature in depth.

> [!TIP]
> Most "it won't start" reports are a config parse or validation error.
> Run `--check-config` (below) before anything else.

## Validate the config first

Run with `--check-config` to parse and validate without binding any
sockets:

```sh
hypershunt --check-config -c /etc/hypershunt.kdl
```

Exit code `0` means the config is well-formed and internally
consistent; non-zero prints the **first** error with the offending
node.  Fix that, then re-run — errors are reported one at a time.

## Startup

### `bind: address already in use`

Another process already holds that port.  Find it
(`ss -ltnp 'sport = :443'`) and stop it, or change the listener's
`bind` port.  In containers, change the published host port
(`-p 8080:80`) rather than the in-container port.

### `Permission denied` binding port 80 or 443

Ports below 1024 are privileged.  hypershunt expects to start as root,
bind the sockets, then drop to an unprivileged user via
`server user="..."` — see [Running unprivileged](guide.md#running-unprivileged).
If you are already running unprivileged (e.g. `podman --userns=keep-id`),
the process can no longer bind privileged ports; publish to a high
in-container port instead, or keep the default namespace.  See
[Container twist](guide.md#container-twist).

### Running as root with no `user` set

hypershunt warns if it stays root because no `server user` is
configured.  Set `server user="hypershunt"` so it drops privileges
after binding; the packaged config already does this.

## TLS / certificates

### ACME issuance keeps failing

Three things must hold: the [`state-dir`](glossary.md#state-dir) must be
**writable** (certs are persisted there), the CA must be able to reach
this server on **port 80** for the [HTTP-01](glossary.md#http-01)
challenge (or 443 for TLS-ALPN-01), and the domain's DNS must point
here.  While issuance fails hypershunt serves a self-signed cert and
retries hourly — check the logs for the ACME error text.  See
[HTTPS / TLS termination](guide.md#https--tls-termination).

### Hitting Let's Encrypt rate limits while testing

> [!WARNING]
> Production Let's Encrypt has strict per-domain issuance limits, and a
> retry loop can burn through them fast.

Point the ACME directory at the **staging** CA while iterating; staging
certs aren't publicly trusted but exercise the same flow.

### Browser shows "not secure" / self-signed warning

Either ACME hasn't succeeded yet (see above) or you configured a
`self-signed` certificate.  Self-signed is for local testing only; use
`tls "acme"` or a real `tls "files"` cert for anything public.

## Reverse proxy

### Upstream returns `502 Bad Gateway`

hypershunt reached the upstream but the exchange failed — the backend is
down, refused the connection, timed out, or sent a malformed response.
Confirm the `upstream` URL is reachable from the hypershunt host and the
backend is actually listening.  See [Reverse proxy](guide.md#reverse-proxy).

### An upstream silently stops receiving traffic

It was probably ejected.  [Passive health](guide.md#health-checks)
ejects an upstream after N consecutive failures, and
[active health](guide.md#health-checks) checks flip its `healthy` flag.
Check the logs and the [status page](guide.md#status-health-metrics) for
upstream state.

### Retries don't fire

`retry { max N }` requires an explicit `on-status` list — there is no
implicit "any 5xx".  Also note retry only replays the request body when
`max > 0` (bodies are buffered up-front then); with `max 0` no buffering
happens.  See [Retries](guide.md#retries).

## Authentication

### OIDC login loops or the session drops immediately

The JWT session validity may be shorter than expected, or back-channel
logout / token revocation is tearing down server-side state.  Confirm
the IdP redirect URI matches `callback-path` exactly and that the
`state-dir` is writable (the JWT signing key lives there).  See
[OIDC single sign-on](guide.md#oidc-single-sign-on).

### API clients get a 302 to the login page instead of 401

That's by design for browsers (`Accept: text/html` + no `Authorization`
header triggers the OIDC redirect).  API/CLI clients that send neither
keep the `401` path — make sure your client isn't sending
`Accept: text/html`.

### Bearer tokens are rejected

Bearer mode requires `bearer #true` **and** a `bearer-audience`; tokens
are validated against the IdP's JWKS for signature, issuer, expiry, and
that audience.  A token whose `aud` isn't in the allowlist is refused.
See [Bearer-token resource server](guide.md#bearer-token-resource-server).

## Rate limiting

### Limits seem too strict or too loose

Each rule counts requests per its [key](glossary.md#rate-limit-key)
(`client-ip`, `user`, or a header) into a token bucket of size
[`burst`](glossary.md#burst).  Anonymous users and requests missing the
keyed header **share the empty-string bucket**, which can look like one
client throttling everyone.  Stacked rules are AND-evaluated; the first
to deny wins with `429` + `Retry-After`.  See
[Rate limiting](guide.md#rate-limiting).

## Containers / permissions

### `Permission denied` reading mounted files

The in-container `hypershunt` user is a fixed **UID/GID 1000**.  Make
mounted content readable by it (`chmod -R o+rX webroot`), or align host
ownership with `podman run --userns=keep-id:uid=1000,gid=1000`.  Note
`keep-id` starts the process as UID 1000, so it can't bind ports below
1024 — see the privileged-port note above.

### SELinux denials on RHEL/Fedora

Add the `:Z` relabel flag to volume mounts
(`-v ./webroot:/var/www/hypershunt:ro,Z`).  Omit it on Debian/Ubuntu or
under Docker, where SELinux isn't enforcing.

## Still stuck?

Re-run with verbose logging, capture the first error, and open an issue
at <https://github.com/MichaelPaddon/hypershunt>.
