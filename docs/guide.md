# Configuration guide

Scenario-driven walkthroughs of common hypershunt deployments.  Every
directive named in prose links to its entry in the
[reference](reference.md) on first mention.  For pure syntax see
the [grammar](grammar.md).

If you're brand new, start with the [quick start](quickstart.md)
to get a container running, then come back here.

## Anatomy of a config

An `hypershunt.kdl` file is one [`server`](reference.md#server) block,
one or more [`listener`](reference.md#listener) blocks, an
optional pool of [`certificate`](reference.md#certificate) blocks,
and one or more [`vhost`](reference.md#vhost) blocks.  Anything
else at the top level is a parse error.

A minimal "serve files on port 80" config looks like this:

```kdl
listener "tcp://[::]:80"

vhost "example.com" {
    location "/" { static root="/var/www/example" }
}
```

Read top to bottom:

- [`listener "tcp://[::]:80"`](reference.md#listener) binds an
  IPv6 (and dual-stack) TCP socket on port 80.  The string is a
  [bind URL](reference.md#bind-url) -- the scheme picks the
  socket family.
- `vhost "example.com"` claims the HTTP `Host: example.com`
  header.  Vhosts are matched literally first, then by regex
  (when [`regex=#true`](reference.md#regex) is set), then by the
  listener's [`default-vhost`](reference.md#default-vhost)
  fallback.
- `location "/"` matches every request path inside the vhost.
  Multiple locations are matched by **longest prefix**, so a
  more specific `/api/` would win over the `/` catch-all.
- `static root=...` is the handler -- exactly one handler per
  location.  The other handlers are [`proxy`](reference.md#proxy-handler),
  [`redirect`](reference.md#redirect),
  [`fastcgi`](reference.md#fastcgi), [`scgi`](reference.md#scgi),
  [`cgi`](reference.md#cgi), [`status`](reference.md#status),
  and [`auth-request`](reference.md#auth-request).

KDL comments are `//` (to end of line) or `/* ... */`.  Block
nodes use `{ ... }` and properties are written `key=value` on
the node line.

A more realistic shape -- privilege drop, HTTPS, multiple vhosts:

```kdl
server user="hypershunt" state-dir="/var/lib/hypershunt"

listener "tcp://[::]:80"            // HTTP for ACME challenges
listener "tcp://[::]:443" {
    tls "acme" email="ops@example.com" {
        domain "example.com"
        domain "www.example.com"
    }
}

vhost "example.com" {
    alias "www.example.com"
    location "/" { static root="/var/www/example" }
}
```

The [`server`](reference.md#server) block is optional but useful:
`user=` drives the privilege drop after the low ports bind, and
`state-dir=` is where ACME-issued certificates persist.

**See also**: every top-level node in the
[reference](reference.md#server).

## Serving static files

The [`static`](reference.md#static) handler streams files from a
filesystem directory.  The bare minimum is one property and one
directive:

```kdl
location "/" {
    static root="/var/www/site"
}
```

The handler resolves the request path under
[`root`](reference.md#root-static), checks it's a regular file,
and streams it back with the right `Content-Type` (derived from
the file extension), `Content-Length`, and an ETag for
conditional GETs.  Range requests are honoured -- hypershunt supports
single-range `Range: bytes=N-M` for download resume.

### Directory requests and index files

When the resolved path is a directory, hypershunt tries each
[`index-file`](reference.md#index-file) in order:

```kdl
static root="/var/www/site" {
    index-file "index.html"
    index-file "index.htm"
}
```

The defaults are exactly those two names -- specify the block
only when you want something different.

### Single-page apps and `try-files`

SPA bundles like React, Vue, or Svelte serve a single `index.html`
that the framework re-routes client-side.  Hitting a deep URL
directly must still load the SPA, not return `404`.  Use
[`try-files`](reference.md#try-files):

```kdl
location "/" {
    static root="/var/www/spa" {
        try-files "{path}"
        try-files "{path}.html"
        try-files "/index.html"
    }
}
```

Hypershunt walks the list in order, substituting `{path}` with the
request path (location prefix stripped if
[`strip-prefix=#true`](reference.md#strip-prefix-static)).  The
first existing regular file wins.  When no candidate exists, the
response is `404` -- the [`index-file`](reference.md#index-file)
flow is bypassed.

### Directory listing

For internal mirrors or simple file shares, turn on
[`directory-listing`](reference.md#directory-listing):

```kdl
location "/files/" {
    static root="/srv/files" strip-prefix=#true directory-listing=#true
}
```

When a request path resolves to a directory and no
[`index-file`](reference.md#index-file) matches, hypershunt renders
an HTML listing.  Without `directory-listing=#true` the same case
returns `404`.

### Redirecting an empty webroot

A fresh install ships an empty `/var/www/hypershunt/`.  The bundled
config uses
[`fallback-redirect`](reference.md#fallback-redirect) to point
`/` at the documentation site so the first request to a brand-new
server lands somewhere useful rather than `404`:

```kdl
location "/" {
    static root="/var/www/hypershunt" fallback-redirect="/docs/" {
        index-file "index.html"
    }
}
```

The redirect fires only when the resolved path is a directory
with no matching index file.  As soon as the operator drops an
`index.html` into `/var/www/hypershunt/`, that file is served and the
redirect stops -- no config edit required.  Random-path `404`s
(e.g. `/typo`) are unaffected; the property is intentionally
narrow.

### Per-user directories (~user)

Classic `~user/public_html/` style serving:

```kdl
location "/~" {
    static userdir="public_html" userdir-min-uid=1000 {
        userdir-allowlist "alice"
        userdir-allowlist "bob"
    }
}
```

A request to `/~alice/index.html` resolves to
`<alice's home>/public_html/index.html`.
[`userdir-min-uid`](reference.md#userdir-min-uid) defends against
exposing system accounts;
[`userdir-allowlist`](reference.md#userdir-allowlist) narrows
further to a known set of users.

### Strip-prefix mismatch

[`strip-prefix`](reference.md#strip-prefix-static) is for the
common case where the URL prefix doesn't exist on disk:

```kdl
location "/assets/" {
    static root="/var/www/site/static" strip-prefix=#true
}
```

A request for `/assets/css/main.css` resolves to
`/var/www/site/static/css/main.css`, not
`/var/www/site/static/assets/css/main.css`.

**See also**: [Locations and routing](#locations-and-routing) for
how locations are matched; [Reference -- static
handler](reference.md#static) for every knob.

## Virtual hosts

A [`vhost`](reference.md#vhost) claims one or more `Host:` header
values.  Matching order per request: every exact literal name
(O(1) hash lookup), then every regex pattern in declaration
order, then the listener's
[`default-vhost`](reference.md#default-vhost).

```kdl
vhost "example.com" {
    location "/" { static root="/var/www/example" }
}
vhost "blog.example.com" {
    location "/" { static root="/var/www/blog" }
}
```

### Aliases

When several hostnames serve the same content, list them as
[`alias`](reference.md#alias) children:

```kdl
vhost "example.com" {
    alias "www.example.com"
    alias "example.org"
    alias "www.example.org"
    location "/" { static root="/var/www/example" }
}
```

### Regex vhosts

For wildcard ranges -- staging environments, multi-tenant
subdomains -- set `regex=#true`:

```kdl
vhost "(?:\w+\.)?example\.com" regex=#true {
    location "/" { static root="/var/www/example" }
}
```

The pattern is anchored automatically (`^...$`); you don't need
to add the anchors yourself.  Regex vhosts cost more per request
than literal ones -- list literals first and use regex as a
fallback or for genuinely variable subdomains.

### Default-vhost fallback

A literal that catches everything the others miss:

```kdl
listener "tcp://[::]:80" default-vhost="example.com"

vhost "example.com" {
    location "/" { static root="/var/www/example" }
}
vhost "api.example.com" {
    location "/" { proxy { upstream "http://api.internal:9000" } }
}
```

Without `default-vhost=` the first vhost defined in the file
wins.  Set [`default-vhost=#null`](reference.md#default-vhost) to
return `404` for unrecognised hosts instead.

### Per-vhost ALPN

A vhost can override the listener's negotiated ALPN list, e.g. to
keep a legacy host on HTTP/1.1 while everything else uses HTTP/2:

```kdl
listener "tcp://[::]:443" { tls "self-signed" }

vhost "example.com" { /* default: h2 + http/1.1 */
    location "/" { static root="/var/www/example" }
}
vhost "legacy.example.com" {
    alpn "http/1.1"
    location "/" { static root="/var/www/legacy" }
}
```

Per-vhost ALPN only works on TCP/TLS listeners (hypershunt selects
the right config from the SNI in the ClientHello).  Regex vhosts
and QUIC listeners fall back to the listener default.

**See also**: [Reference -- vhost](reference.md#vhost),
[`default-vhost`](reference.md#default-vhost),
[ALPN on a listener](reference.md#alpn).

## Locations and routing

Routing inside a vhost is **longest-prefix match**.  Given:

```kdl
vhost "example.com" {
    location "/" { static root="/var/www/site" }
    location "/api/" { proxy { upstream "http://api:9000" } }
    location "/api/v1/" { proxy { upstream "http://api-v1:9000" } }
}
```

a request to `/api/v1/users` reaches the `api-v1` upstream; one
to `/api/products` reaches `api`; one to `/about` lands on the
static handler.  Order in the file does not matter for prefix
matching -- the parser sorts locations by prefix length.

### Matching beyond prefix

Add a [`match`](reference.md#match) block to gate the location on
something other than the path:

```kdl
location "/upload/" {
    match {
        method "POST"
        header "Content-Type" "multipart/form-data" \
                              "application/octet-stream"
    }
    proxy { upstream "http://uploader:9000" }
}
location "/upload/" {
    static root="/var/www/upload-form"
}
```

Predicates inside the block are AND-evaluated.  When the predicate
is false, the router skips this location and continues with the
next shorter-prefix candidate -- here, the GET case lands on the
HTML form served from disk.

Predicate types:
[`method`](reference.md#method),
[`header`](reference.md#header-match),
[`header-absent`](reference.md#header-absent),
[`query`](reference.md#query),
[`path`](reference.md#path),
[`not`](reference.md#not-match).
Header and query values prefixed with `~` are compiled as
regexes.

### URL rewrites

[`rewrite`](reference.md#rewrite) edits the URL and routes the
request again from the top of the vhost:

```kdl
location "/legacy/" {
    rewrite from="^/legacy/(.*)$" to="/v2/$1"
    static root="/never"        // placeholder; the rewrite fires first
}
location "/v2/" {
    proxy { upstream "http://v2-api:9000" }
}
```

`from=` is a PCRE-style regex compiled at parse time (malformed
patterns fail config load); `to=` is a template with `$1`,
`$2`, ... capture-group back-references.  Hypershunt caps consecutive
rewrites at ten per request to catch accidental cycles.

### `strip-prefix`

When a handler should see the request path with the location
prefix removed, set [`strip-prefix=#true`](reference.md#strip-prefix-proxy)
on the handler.  Useful for proxying:

```kdl
location "/api/v1/" {
    proxy strip-prefix=#true {
        upstream "http://api-v1:9000"
    }
}
```

The upstream sees `/users` for a request to `/api/v1/users`.
The same flag exists on [`static`](reference.md#strip-prefix-static)
for filesystem mounts that don't include the URL prefix.

**See also**: [Reference -- location](reference.md#location),
[Request matching](#request-matching),
[`rewrite`](reference.md#rewrite).

## HTTPS / TLS termination

hypershunt terminates TLS on byte-stream listeners via the
[`tls "<kind>"`](reference.md#tls-listener) node.  Four kinds:
`"self-signed"` (dev only), `"files"` (PEM cert + key),
`"acme"` (Let's Encrypt et al.), and `"ref"` (point at a named
[`certificate`](reference.md#certificate)).

### Self-signed (development)

```kdl
listener "tcp://[::]:443" { tls "self-signed" }
```

hypershunt generates a fresh keypair in memory on each start.  The
certificate is **not** publicly trusted -- use this only locally
or in CI.

### PEM files

```kdl
listener "tcp://[::]:443" {
    tls "files" cert="/etc/hypershunt/cert.pem" key="/etc/hypershunt/key.pem"
}
```

Both files must be readable by the post-privilege-drop user.
hypershunt re-reads them on SIGHUP, so manual rotation is just
"replace + signal".

### ACME / Let's Encrypt (HTTP-01)

```kdl
server state-dir="/var/lib/hypershunt"

listener "tcp://[::]:80"
listener "tcp://[::]:443" {
    tls "acme" email="ops@example.com" {
        domain "example.com"
        domain "www.example.com"
    }
}
```

A few things to know:

- [`state-dir`](reference.md#state-dir) is required for ACME --
  it's where the account key and issued certificates persist.
- The port-80 listener must be reachable from Let's Encrypt for
  the HTTP-01 challenge to succeed.  Hypershunt intercepts
  `/.well-known/acme-challenge/...` automatically.
- Multiple [`domain`](reference.md#domain) lines stack as SANs on
  one certificate.
- If the first issuance fails (rate-limit hit, DNS not ready),
  hypershunt serves a self-signed certificate and retries every
  [`retry-interval`](reference.md#retry-interval) seconds (1 hour
  by default).

Set [`staging=#true`](reference.md#staging) while testing -- Let's
Encrypt's production rate limits are easy to hit during
trial-and-error.

### ACME with DNS-01

DNS-01 is required for **wildcard** certificates and useful when
ports 80/443 aren't reachable from the public internet.  Pick a
[`dns-provider`](reference.md#dns-provider) plugin and set
[`challenge="dns-01"`](reference.md#challenge):

```kdl
server state-dir="/var/lib/hypershunt"

listener "tcp://[::]:443" {
    tls "acme" email="ops@example.com" challenge="dns-01" {
        domain "*.example.com"
        domain "example.com"
        dns-provider "cloudflare" zone-id="..." api-token="..."
    }
}
```

The bundled providers are
[`acme-dns`](reference.md#acme-dns) (works with any DNS server
behind an [acme-dns](https://github.com/joohoi/acme-dns)
instance), [`cloudflare`](reference.md#cloudflare),
[`route53`](reference.md#route53) (requires the `dns-route53`
Cargo feature), and [`exec`](reference.md#exec) (shells out to a
script).

The `exec` provider is the escape hatch for everything else --
write a short script that adds/removes a TXT record on the
record-set you control:

```kdl
dns-provider "exec" program="/usr/local/bin/acme-dns01.sh" {
    arg "--zone"
    arg "example.com"
}
```

The script receives `add` or `remove` as `$1`, the FQDN as `$2`,
and the TXT value as `$3` (with any extra `arg "..."` children
inserted before `$2`).

### Shared named certificates

When two listeners would otherwise need identical ACME blocks,
factor out a [`certificate`](reference.md#certificate) and
reference it.  Both renewals run from a single manager, so the
HTTP-01 challenge fires once per renewal instead of racing:

```kdl
server state-dir="/var/lib/hypershunt"

certificate "edge" {
    tls "acme" email="ops@example.com" {
        domain "example.com"
        domain "www.example.com"
    }
}

listener "tcp://[::]:443" { tls "ref" name="edge" }
listener "udp://[::]:443" { tls "ref" name="edge" }
```

That second listener also turns on HTTP/3 -- on a `udp://`
listener a `tls` block selects HTTP/3 (see the next chapter).

### OCSP stapling

Hypershunt staples OCSP responses by default; no configuration
required.  The responder URL is read from the certificate; hypershunt
fetches a fresh response, caches it until `nextUpdate`, and
attaches it to every TLS handshake.

To disable OCSP for one listener (typically with a self-signed
cert that has no responder URL):

```kdl
listener "tcp://[::]:443" {
    tls "self-signed" ocsp=#false
}
```

The OCSP knobs ([`ocsp-timeout`](reference.md#ocsp-timeout),
[`ocsp-min-refresh`](reference.md#ocsp-min-refresh),
[`ocsp-failure-backoff`](reference.md#ocsp-failure-backoff)) are
properties on the same `tls` node or on
[`tls-options`](reference.md#tls-options) at server scope.

### Mutual TLS (mTLS)

Require clients to present a certificate signed by one of your
trust anchors:

```kdl
listener "tcp://[::]:443" {
    tls "files" cert="server.pem" key="server.key" {
        mtls mode="required" {
            ca "/etc/hypershunt/clients-ca.pem"
        }
    }
}
```

With [`mode="optional"`](reference.md#mode), unauthenticated
connections still go through but a presented certificate is
validated; hypershunt exposes the authenticated identity to access
policies via the `user` predicate.

Add [`revocation`](reference.md#revocation) for CRLs and
[`refresh=N`](reference.md#refresh) to re-read them periodically:

```kdl
mtls mode="required" refresh=600 {
    ca "/etc/hypershunt/clients-ca.pem"
    revocation "/etc/hypershunt/clients.crl"
}
```

**See also**: [Reference -- listener TLS](reference.md#tls-listener),
[ACME providers](reference.md#dns-provider),
[`tls-options`](reference.md#tls-options) for server-wide
defaults like minimum protocol version.

## HTTP/3

HTTP/3 runs over QUIC on a UDP listener.  The shape mirrors
TCP/TLS exactly -- a [`tls`](reference.md#tls-on-udp-http3) block
on a `udp://` listener *is* the HTTP/3 cert source.  Because
QUIC's encryption *is* TLS 1.3 (RFC 9001), the cert plumbing is
identical to HTTPS; the only difference is the socket scheme:

```kdl
server state-dir="/var/lib/hypershunt"

certificate "edge" {
    tls "acme" email="ops@example.com" { domain "example.com" }
}

listener "tcp://[::]:443" { tls "ref" name="edge" }
listener "udp://[::]:443" { tls "ref" name="edge" }
```

### Alt-Svc auto-advertisement

When a TCP/TLS listener and a UDP listener share the same port,
hypershunt injects `Alt-Svc: h3=":<port>"; ma=86400` into HTTP/1.1
and HTTP/2 responses.  Browsers see it on the first hit and
upgrade subsequent requests to HTTP/3 themselves -- no extra
config required.  Override the auto-injected value with a
[`response-headers`](reference.md#response-headers) `set` rule
in the relevant location or vhost, or remove it with `remove
"Alt-Svc"`.

### Transport tuning

Defaults are quinn's; tune via
[`quic-transport`](reference.md#quic-transport):

```kdl
listener "udp://[::]:443" {
    tls "ref" name="edge"
    quic-transport \
        max-concurrent-bidi-streams=100 \
        max-idle-timeout=30 \
        keep-alive-interval=10
}
```

[`zero-rtt=#true`](reference.md#zero-rtt) enables 0-RTT early
data -- carries replay risk, only safe when every handler in the
listener's vhosts is idempotent.

**See also**: [Reference -- tls on udp:// (HTTP/3)](reference.md#tls-on-udp-http3),
[`quic-transport`](reference.md#quic-transport).

## Reverse proxy

The handler-mode [`proxy`](reference.md#proxy-handler) forwards
HTTP requests to one or more upstreams:

```kdl
location "/api/" {
    proxy strip-prefix=#true {
        upstream "http://backend.internal:9000"
    }
}
```

Hypershunt picks one upstream per request (see [Load
balancing](#load-balancing) below), opens or reuses a pooled
connection, forwards the request, and streams the response back.

### Upstream URL schemes

[`upstream`](reference.md#upstream) accepts `http://`, `https://`,
or `unix-stream:/path`.  HTTP/2 over plaintext (`h2c`) is
available via [`scheme="h2c"`](reference.md#scheme); HTTP/3 over
QUIC via `scheme="h3"` (https only).

```kdl
proxy { upstream "https://api.example.com" }
proxy { upstream "http://backend:9000" }
proxy { upstream "unix-stream:/run/api.sock" }
proxy scheme="h3" { upstream "https://api.example.com" }
```

### Forwarded headers

By default hypershunt adds:

- `X-Forwarded-For: <client_ip>` (appended to any existing list)
- `X-Forwarded-Proto: <http|https>`
- `X-Forwarded-Host: <Host header>`
- `X-Real-IP: <client_ip>`
- `Forwarded: by=...;for=...;host=...;proto=...` (RFC 7239)

The client IP is the post-PROXY-protocol peer address when
[`accept-proxy-protocol`](reference.md#accept-proxy-protocol) is
set on the listener, otherwise the raw socket peer.

Replace, append, or remove arbitrary headers with the
[`request-headers`](reference.md#request-headers) block:

```kdl
location "/api/" {
    proxy { upstream "http://api:9000" }
    request-headers {
        set "X-Real-IP" "{client_ip}"
        set "X-Tenant" "{user}"
        remove "Cookie"
    }
}
```

Hypershunt automatically strips hop-by-hop headers (`Connection`,
`Keep-Alive`, `Transfer-Encoding`, etc.) -- the upstream sees a
clean HTTP/1.1+ message.

### Path handling

[`strip-prefix=#true`](reference.md#strip-prefix-proxy) removes
the location's URL prefix before forwarding.  Without it the
upstream receives the full path:

```kdl
// Upstream sees /api/v1/users
location "/api/v1/" { proxy { upstream "http://api:9000" } }

// Upstream sees /users
location "/api/v1/" {
    proxy strip-prefix=#true { upstream "http://api:9000" }
}
```

**See also**: [Load balancing](#load-balancing), [Health
checks](#health-checks), [Retries](#retries),
[Connection pooling and timeouts](#connection-pooling-and-timeouts).

## Load balancing

List two or more [`upstream`](reference.md#upstream) children and
pick an algorithm with [`lb-policy`](reference.md#lb-policy):

```kdl
location "/api/" {
    proxy {
        upstream "http://api1:9000" weight=2
        upstream "http://api2:9000" weight=1
        lb-policy "least-conn"
    }
}
```

The policies:

- `round-robin` (default) -- evenly spread across healthy
  upstreams, weighted by [`weight=`](reference.md#upstream).
- `least-conn` -- pick the healthy upstream with the fewest
  in-flight requests.  Best when request latency varies.
- `random` -- weighted random pick.  Hash-free, no shared
  state.
- `ip-hash` -- hash the client IP.  Stable affinity, no cookies
  needed.  Pool changes (additions, removals) reshuffle some
  clients.
- `header-hash` -- hash a named request header.  Provide
  `header=<name>`.  Common for session affinity via
  `Cookie` or `X-Session-Id`.

Per-upstream `weight=0` parks an upstream (it stays in the pool
but receives no traffic); useful for a warm standby you keep
ready but don't actively use.

**See also**: [Reference -- lb-policy](reference.md#lb-policy),
[Health checks](#health-checks).

## Health checks

Two health-check types, can be combined.

### Passive

[`passive-health`](reference.md#passive-health) ejects an
upstream after consecutive request failures:

```kdl
proxy {
    upstream "http://api1:9000"
    upstream "http://api2:9000"
    passive-health eject-after=5 eject-for=30
}
```

Five real-request failures in a row eject the upstream for thirty
seconds, after which it re-enters rotation.  Default
[`eject-after`](reference.md#eject-after) is `u32::MAX` -- the
feature is opt-in.

### Active

[`active-health`](reference.md#active-health) spawns a background
prober that hits each upstream on a schedule:

```kdl
proxy {
    upstream "http://api1:9000"
    upstream "http://api2:9000"
    active-health \
        path="/healthz" \
        interval=10 \
        timeout=2 \
        expect-status=200 \
        unhealthy-after=3 \
        healthy-after=2
}
```

Active probes use a separate hyper client so a hung probe can't
wedge real traffic.  Use both passive and active together: the
prober is the canary, the passive ejection is the real-time
guard for upstreams that fail fast.

**See also**: [Reference -- active-health](reference.md#active-health),
[`passive-health`](reference.md#passive-health).

## Retries

When an upstream returns one of the listed `on-status` codes,
hypershunt picks a different upstream and tries again, up to
[`max`](reference.md#max-retry) additional attempts:

```kdl
proxy {
    upstream "http://api1:9000"
    upstream "http://api2:9000"
    retry max=2 {
        on-status 502
        on-status 503
        on-status 504
    }
}
```

A few things to know:

- Listing the codes explicitly is mandatory.  Hypershunt does not
  retry "any 5xx" by default -- that would catch
  application-level failures like `503 Service Busy` or `500
  Validation Error` that don't benefit from retry.
- When `max > 0`, hypershunt buffers the request body in memory so it
  can be replayed on each attempt.  Don't enable retries for
  large-upload endpoints; the buffer cost adds up.
- Connection-level failures (TCP reset, TLS handshake error,
  `connect-timeout` expiry) are *always* retried -- they happen
  before the request is sent, so there's nothing to replay.

**See also**: [Reference -- retry](reference.md#retry).

## Connection pooling and timeouts

hypershunt keeps an idle pool of HTTP/1.1 and HTTP/2 upstream
connections per host.  Tune the pool with the proxy-level
properties:

```kdl
proxy \
    pool-idle-timeout=60 \
    pool-max-idle=32 \
    connect-timeout=2 {
    upstream "http://api.internal:9000"
}
```

- [`pool-idle-timeout`](reference.md#pool-idle-timeout): seconds
  an idle connection lingers in the pool.  Defaults to 90.
  Setting `0` disables reuse entirely (every request opens a
  fresh TCP connection -- only ever do this to work around
  upstream bugs).
- [`pool-max-idle`](reference.md#pool-max-idle): cap on idle
  connections per host.  HTTP/1.1 and HTTP/2 only.  Defaults to
  hyper's heuristic.
- [`connect-timeout`](reference.md#connect-timeout): seconds
  hypershunt waits for the TCP+TLS handshake on a new connection.

For HTTP/3, `pool-idle-timeout` controls how long a QUIC
connection sits unused before the reaper closes it.

### Listener-level timeouts

The [`timeouts`](reference.md#timeouts) child of a listener tunes
the *inbound* request lifecycle:

```kdl
listener "tcp://[::]:80" {
    timeouts request-header=30 handler=60 keepalive=75
}
```

- [`request-header`](reference.md#request-header): Slowloris
  defence.  Drop connections that take longer than N seconds to
  send a complete request header.
- [`handler`](reference.md#handler): cap on time spent in the
  handler before returning `408`.  Useful for slow upstreams.
- [`keepalive`](reference.md#keepalive): idle timeout between
  HTTP/1.1 requests on the same connection.  `0` disables
  keep-alive entirely.

**See also**: [Reference -- timeouts](reference.md#timeouts).

## Compression

hypershunt negotiates response compression automatically.  Supported
encodings are gzip, brotli, and zstd; the algorithm is picked
from `Accept-Encoding` per RFC 9110 §12.5.3 (quality values,
identity preference).  Only text-ish MIME types (HTML, JSON,
CSS, JS, SVG, XML, plain text) and a few well-defined extras
are compressed; binary types like images and video are not.

Compression is on by default for every response that's eligible
under the MIME and size thresholds.  There is no per-location
disable knob today; if you need to suppress compression for a
specific response, send `Cache-Control: no-transform` from the
upstream and hypershunt respects it.

The status page exposes per-encoding hit counts so you can see
which clients negotiate which algorithm.

## Header manipulation

Both [`request-headers`](reference.md#request-headers) and
[`response-headers`](reference.md#response-headers) take the same
three operations:

```kdl
location "/api/" {
    proxy { upstream "http://api:9000" }

    request-headers {
        set "X-Real-IP" "{client_ip}"
        add "X-Forwarded-For" "{client_ip}"
        remove "X-Internal-Debug"
    }

    response-headers {
        set "Strict-Transport-Security" "max-age=63072000; includeSubDomains; preload"
        set "Content-Security-Policy" "default-src 'self'"
        set "X-Content-Type-Options" "nosniff"
        set "Referrer-Policy" "strict-origin-when-cross-origin"
        set "Permissions-Policy" "interest-cohort=()"
    }
}
```

- [`set`](reference.md#set-request-headers) replaces every
  existing instance of the header.
- [`add`](reference.md#add-request-headers) appends without
  touching what's already there.
- [`remove`](reference.md#remove-request-headers) deletes every
  instance.

Template variables in `set` / `add` values:

| Variable        | Substitution                                       |
|-----------------|----------------------------------------------------|
| `{client_ip}`   | Post-PROXY-protocol peer address.                  |
| `{user}`        | Authenticated username, or empty.                  |
| `{request_id}`  | UUIDv4 generated per request.                      |

Header rules apply in declaration order; mixing `add` and `set`
on the same name lets you e.g. `set "X-Forwarded-For"` to the
client IP and then `add` extra hops.

**See also**: [Reference -- request-headers](reference.md#request-headers).

## URL redirects

Use [`redirect`](reference.md#redirect) for permanent moves and
canonicalisation.  Common shapes:

```kdl
// Bare domain -> www
vhost "example.com" {
    location "/" { redirect to="https://www.example.com{path_and_query}" code=301 }
}

// http -> https
vhost "www.example.com" {
    location "/" { redirect to="https://{host}{path_and_query}" code=301 }
}

// Legacy URL retirement
location "/old-section/" {
    redirect to="/new-section/" code=301
}
```

Template variables: `{host}` (the original `Host`),
`{path_and_query}` (path plus original query string), plus the
same set available in [header rules](#header-manipulation)
(`{client_ip}`, `{user}`, `{request_id}`).

`code=301` is permanent and cacheable; use `302` (the default)
for temporary moves and `307`/`308` when the body must be
preserved through a method-preserving redirect.

**See also**: [Reference -- redirect](reference.md#redirect).

## Request matching

[`match`](reference.md#match) gates a location on something other
than path prefix.  When the predicate is false, the router falls
through to the next shortest-prefix candidate.

```kdl
location "/api/" {
    match {
        method "POST" "PUT" "PATCH" "DELETE"
        header "Content-Type" "~application/json.*"
    }
    proxy { upstream "http://api:9000" }
}
location "/api/" {
    // Read-only fallback: GET, HEAD, OPTIONS
    proxy { upstream "http://api-read-replica:9000" }
}
```

Predicate types (all OR within their argument list, AND across
multiple predicates):

- [`method`](reference.md#method) HTTP methods.
- [`header`](reference.md#header-match) name plus accepted
  values; prefix `~` for a regex.
- [`header-absent`](reference.md#header-absent) true when the
  header is missing.
- [`query`](reference.md#query) parameter name plus values.
- [`path`](reference.md#path) regex patterns matched against the
  full URI path (auto-anchored).
- [`not`](reference.md#not-match) negation.

A worked example -- gate a location on cookie presence:

```kdl
location "/dashboard/" {
    match {
        header "Cookie" "~hypershunt_session=.+"
    }
    proxy { upstream "http://dashboard:9000" }
}
location "/dashboard/" {
    redirect to="/login?next={path_and_query}" code=302
}
```

**See also**: [Reference -- match](reference.md#match),
[Locations and routing](#locations-and-routing).

## CGI, FastCGI, SCGI

Three gateway protocols for hand-off to a back-end process pool.

### FastCGI -- e.g. PHP-FPM

```kdl
location "/php/" {
    fastcgi socket="unix-stream:/run/php/php-fpm.sock" \
        root="/var/www/example" \
        index="index.php"
}
```

The handler speaks the binary FastCGI/1.0 protocol.  `socket`
accepts `unix-stream:<path>` or `host:port` for TCP.

### SCGI

```kdl
location "/" {
    scgi socket="unix-stream:/run/myapp.sock" \
        root="/var/www/myapp" \
        index="dispatch.py"
}
```

Same property set as `fastcgi`; only the wire protocol differs.
Common in older Python / Ruby deployments.

### CGI -- one process per request

```kdl
location "/cgi-bin/" {
    cgi root="/var/www/cgi-bin"
}
```

Unix only.  Hypershunt fork-execs a fresh process per request, pipes
the body to stdin, reads the response from stdout.  Slow
compared to FastCGI/SCGI but useful for shell scripts, mailman,
small utilities.  The path component after the location prefix
selects the executable; hypershunt refuses to execute anything
outside [`root=`](reference.md#root-cgi).

### Which to use

- **FastCGI** for stable language runtimes (PHP-FPM, mod_wsgi
  alternatives) -- highest throughput, lowest overhead.
- **SCGI** for legacy back-ends already speaking it.
- **CGI** for one-shot scripts where the per-request fork cost
  is acceptable.

**See also**: [Reference -- fastcgi](reference.md#fastcgi),
[`scgi`](reference.md#scgi), [`cgi`](reference.md#cgi).

## HTTP Basic auth -- htpasswd file

The [`auth "file"`](reference.md#auth-file) backend validates
HTTP Basic credentials against an htpasswd-style file:

```kdl
server { auth "file" path="/etc/hypershunt/htpasswd" cache=60 }

vhost "private.example.com" {
    location "/" {
        basic-auth realm="Private"
        policy { allow authenticated; deny code=401 }
        static root="/var/www/private"
    }
}
```

The file is `username:hash` per line, with optional
`:group1,group2` appended for group membership.  Comments start
with `#`; blank lines are ignored.  Hypershunt re-reads the file when
its mtime changes.

### Hash schemes

hypershunt accepts bcrypt (`$2y$`, `$2b$`, `$2a$`), SHA-512 crypt
(`$6$`), and Argon2id (`$argon2id$`).  Plain, MD5-crypt, DES, and
SHA-1 are rejected at parse time -- the parser exits with an
error rather than silently accepting a weak hash.

Generate hashes with:

- bcrypt: `htpasswd -nbB user pass`
- SHA-512: `mkpasswd -m sha-512 pass` (linux); `openssl passwd
  -6 pass`
- Argon2id: `argon2 saltbytes -id -e <<< pass`

### Group-based access

Append `:group1,group2,...` to the line and gate on the group
predicate:

```
alice:$2y$12$...:editors,admins
bob:$2y$12$...:editors
```

```kdl
location "/admin/" {
    basic-auth realm="Admin"
    policy { allow group "admins"; deny code=403 }
    static root="/var/www/admin"
}
```

### Cache TTL

[`cache=N`](reference.md#cache) seconds caches a successful
hash verification.  bcrypt and Argon2 verifications are
deliberately slow; caching keeps the per-request cost low when
the same client makes a burst of requests.

**See also**: [Reference -- auth "file"](reference.md#auth-file),
[Access policies](#access-policies).

## HTTP Basic auth -- PAM

The [`auth "pam"`](reference.md#auth-pam) backend reuses the
host's PAM stack:

```kdl
server { auth "pam" service="hypershunt" }

vhost "private.example.com" {
    location "/" {
        basic-auth realm="PAM"
        policy { allow authenticated; deny code=401 }
        static root="/var/www/private"
    }
}
```

[`service=`](reference.md#service) names the file under
`/etc/pam.d/`.  Don't reuse `login` -- that stack expects a TTY
and will fail in a no-TTY environment.  Drop a minimal
`/etc/pam.d/hypershunt`:

```
auth    required pam_unix.so
account required pam_unix.so
```

### Running unprivileged

PAM authentication via `pam_unix.so` requires read access to
`/etc/shadow`.  Two clean approaches:

- Add hypershunt's user to the `shadow` group (Debian-family) or use
  `setfacl` to grant `r--` on `/etc/shadow`.
- Run hypershunt with `CAP_DAC_READ_SEARCH` instead of dropping the
  capability.

Test from the command line first with `pamtester hypershunt username
authenticate` -- if that fails, hypershunt will too.

### Group resolution

After PAM authentication succeeds, hypershunt reads the user's POSIX
group memberships and exposes them to the `group` predicate.  No
extra config is needed.

**See also**: [Reference -- auth "pam"](reference.md#auth-pam),
[Running unprivileged](#running-unprivileged).

## HTTP Basic auth -- LDAP

The [`auth "ldap"`](reference.md#auth-ldap) backend performs a
simple bind against an LDAP directory:

```kdl
server {
    auth "ldap" url="ldaps://ldap.example.com:636" \
        bind-dn="uid={user},ou=people,dc=example,dc=com" \
        base-dn="ou=groups,dc=example,dc=com" \
        group-filter="(memberUid={user})" \
        group-attr="cn" \
        timeout=5
}
```

[`bind-dn`](reference.md#bind-dn) is a template -- hypershunt replaces
`{user}` with the LDAP-escaped username from HTTP Basic before
binding.  After a successful bind, hypershunt searches under
[`base-dn`](reference.md#base-dn) with
[`group-filter`](reference.md#group-filter) and reads
[`group-attr`](reference.md#group-attr) from each matching entry
to populate the group list.

### URL schemes

- `ldaps://host:port` -- TLS from the start.
- `ldap://host:port` -- plaintext; add
  [`starttls=#true`](reference.md#starttls) to upgrade.
- `ldapi://%2Fvar%2Frun%2Fslapd%2Fldapi` -- Unix-socket
  (URL-encoded path).  Useful for trusted-localhost setups.

### Active Directory

AD uses a different schema; tweak the templates:

```kdl
auth "ldap" url="ldaps://ad.example.com:636" \
    bind-dn="{user}@example.com" \
    base-dn="DC=example,DC=com" \
    group-filter="(&(objectClass=group)(member=CN={user},CN=Users,DC=example,DC=com))" \
    group-attr="cn"
```

Hypershunt doesn't do AD-specific paging today; for very large
directories the group search may be capped by the server's
default page size.

**See also**: [Reference -- auth "ldap"](reference.md#auth-ldap).

## JWT sessions

[`auth "jwt"`](reference.md#auth-jwt) lets you trade a successful
credential-backend login for a signed cookie that's valid for
the next request without re-authenticating.  The wrapped backend
runs once (Basic auth login); subsequent requests are validated
by ES256 signature check alone -- no PAM/LDAP/file lookup per
request.

```kdl
server state-dir="/var/lib/hypershunt" {
    auth "jwt" backend="ldap" cookie-name="session" validity=3600 \
        ldap-url="ldaps://ldap.example.com" \
        ldap-bind-dn="uid={user},ou=people,dc=example,dc=com" \
        ldap-base-dn="ou=groups,dc=example,dc=com"
}
```

The inner backend's properties live on the same `auth` node with
a kind prefix (`ldap-url=`, `pam-service=`, `file-path=`, etc.).
Repeated children (e.g. `forward-header` for subrequest, `scope`
for OIDC) also carry the prefix
(`subrequest-forward-header`, `oidc-scope`).

### How the flow looks

1. Browser hits a protected URL with no cookie.  Hypershunt returns
   `401` + `WWW-Authenticate: Basic` (when
   [`basic-auth`](reference.md#basic-auth) is present) or 401
   from the policy.
2. Browser sends `Authorization: Basic <user:pass>`.  Hypershunt runs
   the inner backend (e.g. LDAP bind).  On success, hypershunt sets a
   `Set-Cookie: <cookie-name>=<JWT>` header on the response.
3. Future requests carry the cookie.  Hypershunt verifies the ES256
   signature locally (no backend hit) and uses the embedded
   username + groups.
4. When the JWT's `exp` passes, the cookie is rejected; the
   client re-authenticates from step 1.

### Cookie flags

By default the cookie is `HttpOnly`, `SameSite=Strict`, `Path=/`,
with `Max-Age=<validity>`.  `Secure` is added when the listener
is TLS.  Override the name with
[`cookie-name=`](reference.md#cookie-name) and the lifetime
with [`validity=`](reference.md#validity).

### Standalone validator

Omit `backend=` and hypershunt won't issue tokens -- it'll only
validate incoming JWTs (cookie or `Authorization: Bearer`):

```kdl
server state-dir="/var/lib/hypershunt" { auth "jwt" }
```

Useful when a peer service (or an IdP, via OIDC) does the
issuing and hypershunt just verifies.

### JWKS

Hypershunt publishes its current ES256 public key at
`/.well-known/jwks.json` on every vhost regardless of the
config.  Peers that want to verify hypershunt-issued tokens can
fetch the JWKS and cache it.

The signing key lives at `{state-dir}/jwt/ec-key.pem`.  Hypershunt
generates it on first start if absent; the file mode is governed
by [`cert-key-mode`](reference.md#cert-key-mode) (default
`0600`).

### Key rotation

Manual rotation: stop hypershunt, replace
`{state-dir}/jwt/ec-key.pem`, restart.  Outstanding cookies are
invalidated; clients re-authenticate on next request.  There's
no built-in rotation schedule today.

**See also**: [Reference -- auth "jwt"](reference.md#auth-jwt),
[`backend`](reference.md#backend),
[`state-dir`](reference.md#state-dir).

## OIDC single sign-on

[`auth "jwt" backend="oidc"`](reference.md#auth-oidc) wraps an
OpenID Connect IdP for browser SSO.  Hypershunt handles the
authorization-code + PKCE flow, ID-token validation, optional
UserInfo merge, refresh tokens, and back-channel logout.

```kdl
server state-dir="/var/lib/hypershunt" {
    auth "jwt" backend="oidc" \
        oidc-issuer="https://accounts.example.com" \
        oidc-client-id="hypershunt" \
        oidc-client-secret-file="/etc/hypershunt/oidc.secret" \
        oidc-redirect-uri="https://app.example.com/oidc/callback" {
        oidc-scope "openid"
        oidc-scope "profile"
        oidc-scope "email"
        oidc-scope "groups"
    }
}
```

### Endpoints hypershunt exposes

Once OIDC is configured, hypershunt owns four paths on every vhost
(rename via the corresponding `oidc-*-path` properties):

- `/oidc/login` -- starts the flow; redirects to the IdP
  with PKCE.
- `/oidc/callback` -- receives the code, exchanges it for
  tokens, issues the JWT cookie.
- `/oidc/logout` -- clears local cookies and (when
  [`oidc-idp-logout=#true`](reference.md#idp-logout)) bounces
  through the IdP's `end_session_endpoint`.
- `/oidc/backchannel-logout` -- accepts IdP-pushed
  `logout_token` POSTs for server-side state teardown.

Browsers hitting a protected URL with no cookie are automatically
redirected to `/oidc/login?next=<original>`.  Hypershunt
detects browsers via `Accept: text/html` and the absence of an
`Authorization:` header -- API clients still get the
`401` + `WWW-Authenticate: Bearer` challenge.

### UserInfo

Some IdPs (notably Google) omit `email` and `groups` from the ID
token.  Set [`oidc-userinfo=#true`](reference.md#userinfo) to
fetch `/userinfo` on callback and every refresh; UserInfo
claims win over ID-token claims when both are non-empty.

### Refresh tokens

[`oidc-refresh=#true`](reference.md#refresh) enables silent
re-authentication.  Hypershunt stores the refresh token in a
separate HttpOnly cookie
([`oidc-refresh-cookie`](reference.md#refresh-cookie)) and uses
it to renew the session JWT just before it expires.  Implies
`offline_access` is added to [`oidc-scope`](reference.md#scope).

### Login-flow query passthrough

The login endpoint forwards `login_hint`, `prompt`, `max_age`,
`acr_values`, and `ui_locales` query parameters to the IdP after
coarse validation.  Enables silent re-auth (`prompt=none`), MFA
enforcement (`acr_values=loa3`), and similar IdP-side knobs from
your application code.

### Back-channel logout

When the IdP supports it, [`oidc-backchannel-logout=#true`](reference.md#backchannel-logout)
(on by default) accepts pushed `logout_token` POSTs and drops
the server-side refresh state.  The user's in-flight JWT cookie
remains valid until its own [`validity`](reference.md#validity)
expires -- keep `validity` short (a few minutes) if fast
revocation matters.

### IdP key rotation

hypershunt re-runs OIDC discovery every
[`oidc-discovery-refresh`](reference.md#discovery-refresh)
seconds (default 1 hour) and atomically swaps the cached JWKS.
Set to `0` to disable.

**See also**: [Reference -- auth "oidc"](reference.md#auth-oidc),
[Bearer-token resource server](#bearer-token-resource-server) for
exposing the same protected endpoints to non-browser clients.

## Bearer-token resource server

Set [`oidc-bearer=#true`](reference.md#bearer) and supply an
audience list, and hypershunt additionally accepts IdP-issued bearer
JWTs on `Authorization: Bearer <jwt>`:

```kdl
server state-dir="/var/lib/hypershunt" {
    auth "jwt" backend="oidc" \
        oidc-issuer="https://accounts.example.com" \
        oidc-client-id="hypershunt-app" \
        oidc-redirect-uri="https://app.example.com/cb" \
        oidc-bearer=#true {
        oidc-scope "openid"
        oidc-bearer-audience "https://api.example.com"
    }
}
```

hypershunt validates each bearer JWT against the cached JWKS
(signature, `iss`, `exp`, `nbf`) and the
[`oidc-bearer-audience`](reference.md#bearer-audience) allowlist.
The token's `aud` claim must match at least one listed audience.

Validated tokens are LRU-cached by `SHA-256(token)` until their
own `exp`, so the per-request cost is one signature check at
worst.  Cache size is tunable via
[`oidc-bearer-cache-size`](reference.md#bearer-cache-size).

Single configuration thus serves two clients:

- Browser users get cookie sessions via the SSO flow.
- API clients (CLIs, native apps, service-to-service) get the
  bearer-token path.

Both populate the same authenticated identity used by
[`policy`](reference.md#policy-location).

**See also**: [Reference -- auth "oidc"](reference.md#auth-oidc),
[JWT sessions](#jwt-sessions).

## Subrequest auth

[`auth "subrequest"`](reference.md#auth-subrequest) delegates
authentication to an external HTTP service.  The pattern is the
same as nginx `auth_request`:

```kdl
server {
    auth "subrequest" url="http://auth.internal/check" \
        user-header="X-Auth-User" \
        groups-header="X-Auth-Groups" \
        timeout=5 {
        forward-header "Authorization"
        forward-header "Cookie"
    }
}
```

For each request that hits a protected location, hypershunt issues a
GET to [`url`](reference.md#url-subrequest) carrying the listed
[`forward-header`](reference.md#forward-header) values from the
inbound request.  Response status `200` means "allow"; the
authenticated identity is read from
[`user-header`](reference.md#user-header) and
[`groups-header`](reference.md#groups-header) on the
subrequest's *response*.  Anything other than `200` denies.

### When to use it

- An existing auth service (e.g. a session-cookie validator
  shared across services) you don't want to re-implement.
- Custom auth logic in a language you're already running --
  call it from hypershunt rather than embedding it.
- Per-tenant or per-vhost auth differences without spawning
  separate hypershunt processes.

### Pairing with `auth-request` on a peer hypershunt

The natural counterpart on the *server* side is the
[`auth-request`](reference.md#auth-request) handler -- it
serves `200 OK` plus the identity headers that
`auth "subrequest"` reads:

```kdl
// Authentication peer
vhost "auth.internal" {
    location "/check" {
        policy { allow address "10.0.0.0/8"; deny code=403 }
        basic-auth realm="Internal"
        auth-request
    }
}
```

Pair that with `auth "subrequest" url="http://auth.internal/check"`
on the protected service and you've split authentication onto a
dedicated process without inventing a new protocol.

### Latency

Every protected request makes one extra HTTP hop.  Keep the
authentication service close (same host, Unix socket if you can)
and the [`timeout=`](reference.md#timeout-subrequest) tight (1-2
seconds).

**See also**: [Reference -- auth "subrequest"](reference.md#auth-subrequest),
[`auth-request` handler](reference.md#auth-request).

## Access policies

[`policy`](reference.md#policy-location) blocks gate access by
IP, country, identity, or any combination thereof.  Statements
run top-to-bottom; the first match decides.  A block with no
matching rule returns `403`.

### IP allowlists and denylists

```kdl
location "/admin/" {
    policy {
        allow address "10.0.0.0/8" "192.168.0.0/16"
        allow address "203.0.113.0/24"      // office IPs
        deny code=403
    }
    static root="/var/www/admin"
}
```

### Country gating

Requires [`geoip`](reference.md#geoip) at server scope:

```kdl
server { geoip db="/var/lib/GeoIP/GeoLite2-Country.mmdb" }

vhost "api.example.com" {
    location "/" {
        policy {
            deny country "RU" "BY"
            allow
        }
        proxy { upstream "http://api:9000" }
    }
}
```

### Authenticated identities

```kdl
location "/admin/" {
    basic-auth realm="Admin"
    policy {
        allow group "admins"
        allow user "alice" "bob"
        deny code=403
    }
    static root="/var/www/admin"
}
```

Identity predicates (`authenticated`, `user`, `group`)
automatically return `401` for anonymous users -- no explicit
`deny code=401` needed.  Wrap them in `not` to suppress the
auto-challenge when you want a different status.

### Block-form predicates (AND)

When you need *both* an IP allowlist *and* a group membership,
use the block predicate form:

```kdl
allow {
    address "10.0.0.0/8"
    group "admins"
}
```

Each predicate in the block must match; values within one
predicate are OR-combined.

### Named policies

Define a reusable named policy at server scope:

```kdl
server {
    policy "internal-network" {
        allow address "10.0.0.0/8" "192.168.0.0/16"
        deny code=403
    }
}

vhost "x.example.com" {
    location "/admin/" {
        policy { apply "internal-network" }
        static root="/var/www/x-admin"
    }
}
vhost "y.example.com" {
    location "/admin/" {
        policy { apply "internal-network" }
        static root="/var/www/y-admin"
    }
}
```

`apply` splices the named policy's rules at that point;
first-match semantics continue across the inlined rules.  Cycles
are rejected at startup.

**See also**: [Reference -- policy on a location](reference.md#policy-location),
[named policies](reference.md#policy-server).

## Rate limiting

[`rate-limit`](reference.md#rate-limit) implements a token bucket
per (location, key) pair.  Multiple limiters on the same
location stack AND-style: a request must satisfy every limiter.

### Burst-then-steady

```kdl
location "/login/" {
    rate-limit rate=5 per="minute" burst=10 { key "client-ip" }
    static root="/var/www/login"
}
```

The bucket holds [`burst`](reference.md#burst) tokens; each
request consumes one.  Refill is linear at [`rate`](reference.md#rate)
per [`per`](reference.md#per) window.  When a request finds the
bucket empty, hypershunt returns `429` with a `Retry-After: <seconds>`
header pointing at when the bucket would next admit one.

### Stacked limits

```kdl
location "/api/" {
    rate-limit rate=100 per="second" burst=200 { key "client-ip" }
    rate-limit rate=10000 per="hour" burst=10000 { key "user" }
    proxy { upstream "http://api:9000" }
}
```

A noisy IP is throttled by the first rule even when the
authenticated user has plenty of headroom; a single user is
throttled by the second when their daily quota runs out
regardless of which IP they're calling from.

### Key dimensions

[`key`](reference.md#key) accepts three forms:

- `"client-ip"` -- bucket per peer IP.  Use with
  [`accept-proxy-protocol`](reference.md#accept-proxy-protocol)
  for accurate IPs when fronted by an LB.
- `"user"` -- bucket per authenticated username.  Anonymous
  requests share the empty-string bucket.
- `"header" "X-API-Key"` -- bucket per value of a named header.
  Useful for API-key throttling.

### Surfacing on `/status`

The built-in status page lists every active limiter (per
location, per key value) with the current bucket level.  Set
[`name=`](reference.md#name) on the rate-limit block to give it
a friendly label.

**See also**: [Reference -- rate-limit](reference.md#rate-limit),
[Status, health, metrics](#status-health-metrics).

## Custom error pages

```kdl
server {
    error-page 404 path="/etc/hypershunt/error/404.html"
    error-page 403 path="/etc/hypershunt/error/403.html"
    error-page 500 html="<h1>Sorry, something broke.</h1>"
}
```

[`error-page`](reference.md#error-page) replaces hypershunt's built-in
HTML body for one status code.  Exactly one of `path=` (file on
disk, served as `Content-Type: text/html`) or `html=` (inline
literal) is required.  The file is read once at startup.

Error pages are returned for status codes the *hypershunt* runtime
emits -- a `404` because no location matched, a `403` from a
policy, a `502` from an upstream failure.  Errors produced by a
proxy *upstream* are passed through unchanged.

**See also**: [Reference -- error-page](reference.md#error-page).

## WebSocket and HTTP-Upgrade proxying

Any [`proxy`](reference.md#proxy-handler) location transparently
bridges HTTP `Upgrade:` requests between an h1 client and an h1
upstream.  No extra config:

```kdl
vhost "example.com" {
    location "/ws/" { proxy { upstream "http://ws-backend:9100" } }
    location "/api/" { proxy { upstream "http://api:9000" } }
}
```

hypershunt detects `Connection: upgrade` + `Upgrade: <name>` on the
inbound side, opens a fresh non-pooled connection to the
upstream, mirrors the headers, and on the 101 response runs a
bidirectional byte pump until either side closes.

Authentication, [`policy`](reference.md#policy-location), and
[`rate-limit`](reference.md#rate-limit) run *before* the upgrade
completes.  Retries and load-balancer picks happen at
upgrade-request time only -- once the tunnel is open, retries
are off.

### Cross-protocol bridge (h1 ↔ h2c)

When the upstream speaks h2 prior-knowledge, set
[`scheme="h2c"`](reference.md#scheme):

```kdl
proxy scheme="h2c" { upstream "http://h2c-backend:9100" }
```

Hypershunt translates the inbound h1 `Upgrade:` into an h2 extended
CONNECT (RFC 8441), receives the 200 response, and synthesises
the 101 + `Sec-WebSocket-Accept` back to the h1 client.

**Caveat for WebSocket specifically**: h1 WS frames carry a
client-side mask (RFC 6455 §5.3), h2 WS frames do not (RFC 8441
§5.5).  Hypershunt's bridge today does not unmask/remask per frame --
the handshake succeeds, but a real WS round-trip fails the
upstream's framing check.  Generic non-WS byte tunnels work
fine.

### h2/h3 native WebSocket

Coming in a future release once `h3` crate support lands;
tracked in the project README.

**See also**: [Reference -- proxy scheme](reference.md#scheme),
[Reference -- proxy upstream](reference.md#upstream).

## Layer-4 proxy

Adding a [`proxy`](reference.md#proxy-listener) child to a
listener switches the entire listener into L4 forwarding mode --
HTTP routing does not apply; vhosts and the
[`timeouts`](reference.md#timeouts) block are rejected at parse
time.

The five supported families:

| Listener            | Upstream                      | Use case                |
|---------------------|-------------------------------|-------------------------|
| `tcp://`            | `tcp://` or `unix-stream:`    | Database, SMTP, Redis  |
| `udp://`            | `udp://` or `unix-dgram:`     | DNS, syslog, game     |
| `unix-stream:/...`  | `tcp://` or `unix-stream:`    | Local pipe to remote  |
| `unix-dgram:/...`   | `udp://` or `unix-dgram:`     | Local dgram tunnel    |
| `unix-seqpacket:/`  | `unix-seqpacket:`             | Linux SOCK_SEQPACKET  |

Cross-family pairings (e.g. `udp://` listener with a `tcp://`
upstream) are rejected at parse time.

L4 bind URLs are resolved at parse time and require **literal IP
addresses** (`127.0.0.1`, `[::1]`, `10.0.0.5`) rather than
hostnames -- hypershunt doesn't do DNS for L4 because flows are
established outside the HTTP request lifecycle.

### Plain TCP forwarder

```kdl
listener "tcp://0.0.0.0:5432" {
    proxy "tcp://10.0.0.5:5432"
}
```

hypershunt accepts each connection, opens an upstream connection, and
runs `tokio::io::copy_bidirectional` until either side closes.

### TLS termination + re-origination

Terminate TLS on the way in, originate TLS on the way out:

```kdl
listener "tcp://0.0.0.0:5432" {
    tls "files" cert="edge.pem" key="edge.key"
    proxy "tcp://10.0.0.5:5432" { tls skip-verify=#false }
}
```

The `tls skip-verify=#true` knob exists for back-ends with
self-signed certificates; never use it across networks you don't
control.

### UDP forwarding

```kdl
listener "udp://0.0.0.0:53" {
    proxy "udp://192.0.2.53:53"
}
```

hypershunt maintains one upstream socket per `(peer_addr, peer_port)`
pair; flows idle for [`flow-idle-timeout`](reference.md#flow-idle-timeout)
seconds (default 30) are torn down.  Useful for DNS forwarding,
syslog relay, simple game-server proxying.

### PROXY protocol on the upstream side

```kdl
listener "tcp://0.0.0.0:5432" {
    proxy "tcp://10.0.0.5:5432" proxy-protocol="v2"
}
```

[`proxy-protocol`](reference.md#proxy-protocol) prepends a
HAProxy header so the back-end sees the original client IP.

### DTLS (reserved)

A DTLS-terminating datagram proxy is spelled by adding a `tls`
cert block to a `udp://` proxy listener -- the presence of `proxy`
distinguishes it from plain HTTP/3 (`tls` alone):

```kdl
listener "udp://[::]:5684" {
    tls "self-signed"
    proxy "udp://10.0.0.5:5684"
}
```

DTLS is **not yet implemented** (no DTLS-capable crate exists in the
stack today), so this combination is reserved and startup fails with
"not yet implemented".  To DTLS-encrypt the *upstream* leg instead,
see the reserved [`dtls`](reference.md#dtls-upstream) child of
`proxy`.

**See also**: [Reference -- L4 proxy](reference.md#proxy-listener),
[PROXY protocol on receive](#proxy-protocol-on-the-receive-side).

## PROXY protocol on the receive side

When hypershunt sits behind another reverse proxy (HAProxy, AWS NLB,
Cloudflare Spectrum) the peer IP hypershunt sees is the load
balancer, not the client.  Enable PROXY protocol on the listener
so the LB tells hypershunt who the real client is:

```kdl
listener "tcp://0.0.0.0:8080" accept-proxy-protocol="v2" {
    trusted-proxies "10.0.0.0/8"
    trusted-proxies "172.16.0.0/12"
}
```

[`accept-proxy-protocol`](reference.md#accept-proxy-protocol)
requires every inbound connection to start with a v1 or v2
header; connections without one are dropped.
[`trusted-proxies`](reference.md#trusted-proxies) limits which
peer IPs may send PROXY headers in the first place -- without
the allowlist, anyone who can reach the listener can claim any
client IP.

After the header is parsed, the carried source address becomes
the peer IP used by access policies, rate-limit buckets, and
`X-Forwarded-For` propagation.

### Combined with X-Forwarded-For

When the upstream LB also writes `X-Forwarded-For`, hypershunt
appends the carried PROXY-protocol address to the chain so the
back-end sees one consistent view.

**See also**: [Reference -- accept-proxy-protocol](reference.md#accept-proxy-protocol),
[Behind another reverse proxy](#behind-another-reverse-proxy).

## Status, health, metrics

hypershunt exposes two operational endpoints.

### `/status` -- the built-in dashboard

Mount the [`status`](reference.md#status) handler on any
location:

```kdl
vhost "ops.internal" {
    location "/.hypershunt/status" {
        policy { allow address "10.0.0.0/8"; deny code=403 }
        status
    }
}
```

The page shows:

- Process info (version, pid, uptime, listeners).
- Per-vhost request and latency counters; latency histograms.
- Active rate-limit buckets with current levels.
- Certificate status (issuer, SAN list, `notAfter`, OCSP
  freshness).
- Upstream pool stats (active connections, idle, ejected).

HTML by default; `Accept: application/json` switches to JSON for
scraping.

### `/.well-known/health`

[`health`](reference.md#health) on the server block enables a
plain-text health endpoint on every vhost:

```kdl
server { health enabled=#true }
```

A GET returns `200 OK` with body `ok\n` when the process is
running.  Useful for container healthchecks (`HEALTHCHECK CMD
curl -fsS http://localhost/.well-known/health`).

### Restricting access

Both endpoints expose operational detail; gate them behind a
[`policy`](reference.md#policy-location) (IP allowlist or
authenticated identity) in production.

**See also**: [Reference -- status](reference.md#status),
[`health`](reference.md#health),
[Rate limit naming for the status page](#rate-limiting).

## Access logging

[`access-log`](reference.md#access-log) selects the log format
and (for non-tracing formats) the destination file:

```kdl
server { access-log "combined" path="/var/log/hypershunt/access.log" }
```

### Formats

- `"tracing"` (default) -- structured events through the
  `tracing` crate.  Goes wherever the runtime's tracing
  subscriber sends it (stderr in containers, typically); the
  [`path=`](reference.md#path-access-log) property is ignored.
- `"common"` -- NCSA Common Log Format.  One CLF line per
  request.
- `"combined"` -- CLF plus `Referer` and `User-Agent` fields.
- `"json"` -- one JSON object per line (ndjson).  Easy to feed
  into Loki, Elasticsearch, or jq.

### Log rotation

For file-backed formats, hypershunt reopens the log file on SIGHUP --
classic rename-and-signal rotation works:

```sh
mv /var/log/hypershunt/access.log /var/log/hypershunt/access.log.1
gzip /var/log/hypershunt/access.log.1 &
kill -HUP $(cat /var/run/hypershunt.pid)
```

logrotate's stock postrotate of `kill -HUP` handles this.

**See also**: [Reference -- access-log](reference.md#access-log).

## Security signals (fail2ban)

Beyond the access log, hypershunt emits **security events** on a
dedicated, stable log target: `hypershunt::security`.  Each event is one
line with a distinct kebab-case token, designed to be both human-readable
and matched by an intrusion-detection tool such as fail2ban:

```
2026-06-06T12:34:56Z WARN hypershunt::security: auth-failure peer=1.2.3.4:5678 method=GET path="/admin" host="example.com"
```

The target is fixed (it never moves with code refactors), so filters
keyed on it don't silently break.

### The tokens

| token | level | meaning | key fields |
|---|---|---|---|
| `auth-failure` | WARN | credentials were **presented but rejected** (bad password, invalid bearer token, invalid/expired session cookie) | `peer`, `method`, `path`, `host` |
| `auth-challenge` | INFO | a protected resource was hit with **no** credentials → 401 challenge (benign / abandoned) | `peer`, `method`, `path`, `host` |
| `access-denied` | WARN | denied by access policy (IP / geo / group → 403; also raw-TCP stream proxy) | `peer`, `method`, `status`, `path`, `host` |
| `rate-limited` | WARN | a rate-limit rule returned 429 | `peer`, `rule`, `retry_after` |
| `bad-client-cert` | WARN | the mTLS handshake rejected the client certificate | `peer`, `reason` (`no-cert`/`untrusted`/`expired`/`revoked`/…) |

`auth-failure` vs `auth-challenge` is the important distinction: a client
that merely *gets challenged* (no credentials) is **not** an attacker, so
it is logged as `auth-challenge` and is **not** banned by default — only
genuine rejected credentials (`auth-failure`) are.

### Injection safety

`peer` is the real accepted socket address (never a forwarded header) and
always precedes any request-derived field.  Attacker-controlled fields
(`path`, `host`) are escaped by the logger (a newline becomes `\n`), so a
crafted request cannot forge a fake log line or a fake `peer=`.  fail2ban
extracts the IP from the trusted `peer=` token, so bans always target the
real client.

### Enabling the bans

The packages install a parametrized fail2ban filter
(`/etc/fail2ban/filter.d/hypershunt.conf`) and a set of jails
(`/etc/fail2ban/jail.d/hypershunt.conf`), **all disabled by default**.
Each jail reads the systemd journal and maps one token to a ban policy:

```ini
[hypershunt-auth]
enabled = true          # turn on the ones you want
filter  = hypershunt[event=auth-failure]
```

Shipped jails: `hypershunt-auth` (auth-failure), `hypershunt-access`
(access-denied), `hypershunt-ratelimit` (rate-limited), `hypershunt-mtls`
(bad-client-cert).  Adjust `maxretry` / `findtime` / `bantime` to taste,
then `systemctl reload fail2ban`.

### From the container image

fail2ban does **not** belong *inside* the container: a container has no
systemd journal, no firewall capabilities, and runs hypershunt as its
only process.  Run fail2ban on the **host** instead, watching the
container's logs and banning on the host firewall (where bans actually
take effect).

The security signals are plain text on the container's stdout, so route
them into the host journal with the journald log driver:

```sh
podman run -d --name hypershunt --log-driver journald \
    -p 80:80 -p 443:443 ghcr.io/michaelpaddon/hypershunt:latest
```

The filter and jail files aren't installed by the image (there's no
package step), but they're **bundled inside it** for you to copy out:

```sh
podman cp hypershunt:/usr/share/doc/hypershunt/fail2ban/filter.d/hypershunt.conf \
    /etc/fail2ban/filter.d/hypershunt.conf
podman cp hypershunt:/usr/share/doc/hypershunt/fail2ban/jail.d/hypershunt.conf \
    /etc/fail2ban/jail.d/hypershunt.conf
```

(They're also in the source tree under `packaging/fail2ban/`.)  Then, on
the host, point the jails at the container's journal instead of the
systemd unit -- change `journalmatch` in each jail to:

```ini
journalmatch = CONTAINER_NAME=hypershunt
```

set `enabled = true` on the jails you want, and `systemctl reload
fail2ban`.

## Running unprivileged

Binding to ports below 1024 requires root.  Hypershunt drops
privileges immediately after binding:

```kdl
server user="hypershunt" group="hypershunt"
```

The drop is `setgroups([gid])` -> `setgid(gid)` ->
`setuid(uid)`, in that order, with a sanity check
(`setuid(0)` must fail afterwards) before the listener loop
starts.  All handler code, config reloads, and ACME issuance run
as `hypershunt:hypershunt`.

### Container twist

Rootless podman maps container-root to your host user; hypershunt
inside the container is already unprivileged even though it
*looks* like root.  Pair `server user="hypershunt"` with
[`inherit-supplementary-groups=#true`](reference.md#inherit-supplementary-groups)
to preserve podman's `--group-add keep-groups` magic:

```kdl
server user="hypershunt" inherit-supplementary-groups=#true
```

The container's `hypershunt` user and group are a **fixed UID/GID
1000** -- identical, and stable across releases, so it is safe to
hardcode in tooling.  To align host file ownership for bind mounts
(so the container can read/write your mounted directories without a
`chmod`), map your host user onto it:

```sh
podman run ... --userns=keep-id:uid=1000,gid=1000 ...
```

See the [quickstart troubleshooting
note](quickstart.md#troubleshooting) for the read-permission case.

`--group-add keep-groups` is podman's way of carrying your host
supplementary groups into the container; pair it with
[`inherit-supplementary-groups=#true`](reference.md#inherit-supplementary-groups)
so hypershunt's privilege drop doesn't strip them.

**Privileged ports vs. `--userns=keep-id`.**  Binding ports below
1024 needs root, and `keep-id` takes it away.  With the *default*
rootless namespace the process runs as container-root (mapped to
your host user), binds 80/443, then drops to `hypershunt`.  But
`--userns=keep-id:uid=1000,gid=1000` starts the process *as* UID
1000 -- it can no longer bind low ports, and hypershunt fails the
bind with `EACCES`.  Pick one:

- **Keep the default namespace** when you need 80/443 directly;
  align file ownership with `--group-add keep-groups` or by
  `chown`ing your mounted volumes instead of `keep-id`.
- **Listen high, publish low** -- bind `:8080` inside the container
  and map it with `-p 80:8080`; nothing inside touches a
  privileged port.
- **Hand in a pre-bound socket** with
  [`--preserve-fds`](#inherited-sockets-and-socket-activation): a
  privileged socket bound outside the container, adopted by
  hypershunt with no `bind()` of its own.
- **Lift the kernel limit** -- `--sysctl
  net.ipv4.ip_unprivileged_port_start=0` lets UID 1000 bind low
  ports directly.

**On Docker.**  The model differs: there is no `keep-groups` (pass
explicit numeric GIDs with `--group-add <gid>`), and `keep-id` is
podman-only -- Docker remaps users daemon-wide via `userns-remap`
in `/etc/docker/daemon.json`, or you run as your host identity with
`--user $(id -u):$(id -g)` (which, like `keep-id`, forfeits
privileged-port binding -- use a workaround above).  Docker also
has no `--preserve-fds`, so socket hand-in is unavailable.

### Capability shortcuts

If you'd rather avoid the root-then-drop dance entirely, grant
just the capability to bind low ports and run hypershunt as `hypershunt`
from the start:

```sh
setcap cap_net_bind_service=+ep /usr/bin/hypershunt
```

`server user=` becomes a no-op in that case (hypershunt logs a
warning that the current user already matches).

**See also**: [Reference -- user](reference.md#user),
[`group`](reference.md#group),
[`inherit-supplementary-groups`](reference.md#inherit-supplementary-groups).

## Reloading and zero-downtime upgrade

hypershunt supports two distinct restart shapes.

### SIGHUP -- config reload

```sh
kill -HUP $(cat /var/run/hypershunt.pid)
```

hypershunt re-parses the config, validates it (parse errors are
rejected without disrupting traffic), and atomically swaps the
new routing tables in.  Listeners that didn't change keep their
sockets and connections.  Listeners that were added bind new
sockets; listeners that were removed close after their
in-flight requests drain (capped by
[`graceful-drain-timeout`](reference.md#graceful-drain-timeout)).

Reload-safe edits: vhosts, locations, policies, rate-limits,
certificates (including triggering a new ACME issuance), listener
add/remove.

Reload-rejected edits: changing the `server.auth` backend
(authenticator state is process-lifetime), changing the user
running the process.

### SIGUSR2 -- binary hand-off

```sh
kill -USR2 $(cat /var/run/hypershunt.pid)
```

hypershunt forks a fresh process from the same binary, passes the
already-bound listening sockets across the fork via fd
inheritance, waits for the child to signal readiness (capped by
[`upgrade-startup-timeout`](reference.md#upgrade-startup-timeout)),
and then drains its own connections (capped by
[`graceful-drain-timeout`](reference.md#graceful-drain-timeout)).

The child picks up where the parent left off without dropping a
single connection.  Use SIGUSR2 to upgrade the *binary* (not the
config) -- replace `/usr/bin/hypershunt`, then signal.

### Inherited sockets and socket activation

Underneath both restart shapes is one mechanism: at startup
hypershunt scans its already-open file descriptors and, for any
*listening* socket whose address matches a configured listener,
adopts that descriptor instead of calling `bind()`.  Descriptors
no listener claims are closed (and logged).  This is *implicit*
socket activation -- hypershunt never reads `LISTEN_FDS`; it simply
uses whatever listening sockets it is handed.

- **Starting** -- with nothing inherited, every listener binds a
  fresh socket.  When a supervisor hands sockets in -- systemd
  `ListenStream=`/`ListenDatagram=` socket units, or
  `podman --preserve-fds` -- the matching listeners adopt them and
  skip the bind.
- **Reload (SIGHUP)** -- the same process throughout; unchanged
  listeners keep their open sockets untouched, so there is nothing
  to inherit.  Only added listeners bind; only removed ones close.
- **Upgrade (SIGUSR2)** -- the child inherits the parent's listening
  sockets across `fork()` + `exec()` and adopts them by address.
  The socket is never closed, so even connections waiting in the
  kernel accept queue survive the swap.

Matching is by bound address, so a pre-opened socket must be bound
to the exact address its listener declares.

**`--preserve-fds` in containers.**  `podman run --preserve-fds=N`
passes N extra descriptors (starting at fd 3) from the launcher
into the container.  Use it to hand hypershunt a socket bound
*outside* the container -- typically a privileged port opened by a
systemd `.socket` unit -- so an in-container process running as the
unprivileged UID 1000 can serve 80/443 without ever binding it
itself (the `keep-id` gotcha from [Container
twist](#container-twist)).  Declare a listener on the same address
the socket is bound to and hypershunt adopts it.

Because the SIGUSR2 fork/exec happens *inside* the container and
images are read-only, an in-place binary swap isn't the usual
container upgrade -- you roll a new image and a new container
instead.  `--preserve-fds` socket activation is what keeps the
listening socket (and its accept queue) alive across that swap.
Docker has no `--preserve-fds` equivalent and cannot pass listening
sockets into a container.

### What survives

Across both reload and upgrade:
- Established TCP connections.
- TLS sessions (rustls tickets survive process replacement).
- ACME-issued certificates (persisted under
  [`state-dir`](reference.md#state-dir)).
- The JWT signing key.

What doesn't:
- In-memory rate-limit bucket levels (rebuilt on first miss).
- Active health-check probe schedules (resume from the new
  process's startup).
- WebSocket and other long-lived upgrade tunnels under SIGUSR2
  -- they're capped by `graceful-drain-timeout`.

**See also**: [Reference -- server](reference.md#server),
[`graceful-drain-timeout`](reference.md#graceful-drain-timeout),
[`upgrade-startup-timeout`](reference.md#upgrade-startup-timeout).

## Behind another reverse proxy

When hypershunt sits behind a load balancer or CDN, three knobs need
to line up:

1. Tell the LB to send PROXY protocol headers (or trust the
   LB's `X-Forwarded-For`).
2. Enable [`accept-proxy-protocol`](reference.md#accept-proxy-protocol)
   on the hypershunt listener.
3. Restrict the allowed source via
   [`trusted-proxies`](reference.md#trusted-proxies).

```kdl
listener "tcp://0.0.0.0:8080" accept-proxy-protocol="v2" {
    trusted-proxies "10.0.0.0/8"
}

vhost "example.com" {
    location "/" {
        // Real client IP now in the policy
        policy {
            allow address "10.0.0.0/8"
            deny code=403
        }
        proxy { upstream "http://backend:9000" }
    }
}
```

After the PROXY header is parsed, the carried source address
becomes the peer hypershunt sees -- access policies, rate-limit
buckets, and access logs all reflect the real client IP.

When the LB writes `X-Forwarded-For` instead, hypershunt appends the
new hop to the existing chain.  Don't trust an inbound
`X-Forwarded-For` from untrusted peers -- pair the listener
with a [`policy`](reference.md#policy-location) that requires
the connection to come from your LB subnet.

### TLS at the LB

When the LB terminates TLS and forwards plaintext to hypershunt, the
listener stays plain `tcp://`.  Set the
`Strict-Transport-Security` and friends via
[`response-headers`](reference.md#response-headers) in hypershunt so
they apply consistently regardless of LB config.

When the LB does TCP-mode pass-through (sniproxy), hypershunt owns
the TLS termination and runs as normal.

**See also**: [PROXY protocol on the receive
side](#proxy-protocol-on-the-receive-side),
[Reference -- trusted-proxies](reference.md#trusted-proxies).

## Production checklist

Before pointing real traffic at an hypershunt deployment, walk this
list:

- [ ] [`state-dir`](reference.md#state-dir) is on a persistent
      volume that survives container restarts.  ACME-issued
      certificates and the JWT signing key live there.
- [ ] [`user=`](reference.md#user) and [`group=`](reference.md#group)
      are set; the process drops privileges after binding.
- [ ] [`cert-key-mode`](reference.md#cert-key-mode) is set to
      `"0600"` (the default) for private-key files.
- [ ] Every public listener carries
      [`tls "acme"`](reference.md#tls-acme) or
      [`tls "ref"`](reference.md#tls-ref) backed by a real CA
      (not `"self-signed"`).
- [ ] [`tls-options min-version="1.3"`](reference.md#min-version)
      unless legacy clients require 1.2.
- [ ] [`ocsp`](reference.md#ocsp) is on (the default) so
      revocations propagate.
- [ ] HTTP/3 is paired with HTTP/1.1+h2 on the same port -- the
      Alt-Svc auto-injection only fires when both exist.
- [ ] [`response-headers`](reference.md#response-headers) sets
      `Strict-Transport-Security`, `Content-Security-Policy`,
      `X-Content-Type-Options: nosniff`, and `Referrer-Policy`
      for every HTML-serving location.
- [ ] [`error-page`](reference.md#error-page) covers at least
      `404` and `500` so users don't see hypershunt's defaults.
- [ ] [`access-log`](reference.md#access-log) is set to one of
      `"combined"` or `"json"` with a path under
      `/var/log/hypershunt/`, and logrotate is configured to
      `postrotate kill -HUP`.
- [ ] [`timeouts`](reference.md#timeouts) has sensible
      `request-header` and `handler` values for your workload
      (defaults are reasonable for general web traffic).
- [ ] [`health`](reference.md#health) is enabled and the
      container's `HEALTHCHECK` hits `/.well-known/health`.
- [ ] [`status`](reference.md#status) handler is gated behind a
      [`policy`](reference.md#policy-location) (IP allowlist or
      auth).
- [ ] If you're behind a load balancer:
      [`accept-proxy-protocol`](reference.md#accept-proxy-protocol)
      + [`trusted-proxies`](reference.md#trusted-proxies).
- [ ] Rate-limit any login or signup endpoint --
      [`rate-limit`](reference.md#rate-limit) with `key
      "client-ip"`.

Run `hypershunt --check-config /etc/hypershunt.kdl` in CI to catch typos
before they ship.

**See also**: every reference section above.
