# Configuration reference

Every directive hypershunt accepts in `hypershunt.kdl`, organised by the
top-level node it appears under.  This document describes
**semantics** — what each directive controls, its default, and how
it interacts with siblings.  For the formal KDL grammar (syntax
only) see the [grammar](grammar.md).  For walkthrough-style "how do
I X?" answers see the [configuration guide](guide.md).

Every directive heading appears exactly once.  Where two siblings
share a name (e.g. `tls` on a listener and `tls` inside a
`certificate`), the slug is disambiguated and the link comes from
the parent.

---

## server

The `server` node carries process-wide settings: privilege drop,
state directory, global TLS defaults, the chosen authentication
backend, GeoIP, named policies, custom error pages, access logging,
and reload tuning.  It is optional — a config without a `server`
block runs as the calling user with defaults everywhere.

```kdl
server user="hypershunt" state-dir="/var/lib/hypershunt"
```

### user

**Property** on [`server`](#server).  Optional.

POSIX user name to drop privileges to.  When hypershunt starts as root
(typically to bind ports below 1024), it sets the user's
supplementary groups, switches to the user's primary group, and
finally to the user itself, in that order, immediately after
binding sockets.  When unset, hypershunt runs as the calling user and
logs a warning if that user is root.

```kdl
server user="hypershunt"
```

**Default:** none (no privilege drop).
**See also:** [`group`](#group),
[`inherit-supplementary-groups`](#inherit-supplementary-groups),
[Running unprivileged](guide.md#running-unprivileged).

### group

**Property** on [`server`](#server).  Optional.

POSIX group name to set as the process's primary group during the
privilege drop.  When unset, hypershunt uses the [`user`](#user)'s own
primary group from `/etc/passwd`.

```kdl
server user="hypershunt" group="hypershunt"
```

**Default:** the user's primary group.
**See also:** [`user`](#user),
[`inherit-supplementary-groups`](#inherit-supplementary-groups).

### state-dir

**Property** on [`server`](#server).  Required when any listener
uses [`tls "acme"`](#tls-acme) or any [`auth "jwt"`](#auth-jwt)
backend; optional otherwise.

Filesystem directory where hypershunt persists data that needs to
survive restarts: ACME-issued certificates and account keys, the
ES256 signing key for JWT cookies, and ACME challenge state.  The
directory must be writable by the post-privilege-drop user.  Hypershunt
creates subdirectories under it (`acme/`, `jwt/`) as needed.

```kdl
server state-dir="/var/lib/hypershunt"
```

**Default:** none — features that require it refuse to start.
**See also:** [`cert-key-mode`](#cert-key-mode),
[`tls "acme"`](#tls-acme), [`auth "jwt"`](#auth-jwt).

### inherit-supplementary-groups

**Property** on [`server`](#server).  Optional boolean.

Skip the `setgroups()` step of the privilege drop.  Useful inside
containers launched with `podman --group-add keep-groups`, where
supplementary groups have been deliberately propagated and hypershunt
should leave them alone.  Outside containers this should remain
`#false` — the default `setgroups([gid])` is the safer choice.

```kdl
server user="hypershunt" inherit-supplementary-groups=#true
```

**Default:** `#false`.
**See also:** [`user`](#user), [`group`](#group).

### graceful-drain-timeout

**Property** on [`server`](#server).  Optional integer.

Maximum seconds an hypershunt process waits for in-flight requests to
finish during a SIGTERM, SIGHUP-driven listener removal, or
SIGUSR2 hand-off before force-closing remaining connections.
`0` means "wait forever".

```kdl
server graceful-drain-timeout=30
```

**Default:** `0` (wait indefinitely).
**See also:** [`upgrade-startup-timeout`](#upgrade-startup-timeout),
[Reloading and zero-downtime upgrade](guide.md#reloading-and-zero-downtime-upgrade).

### upgrade-startup-timeout

**Property** on [`server`](#server).  Optional integer.

Maximum seconds the parent process waits for the child to signal
readiness during a SIGUSR2 binary hand-off.  If the child fails to
report ready within this window, the parent reaps it and keeps
serving.

```kdl
server upgrade-startup-timeout=60
```

**Default:** `60`.
**See also:** [`graceful-drain-timeout`](#graceful-drain-timeout).

### lame-duck-timeout

**Property** on [`server`](#server).  Optional integer.

Seconds an HTTP (TCP) listener keeps **accepting and serving** after
SIGTERM before it stops accepting and drains.  Throughout this window
readiness paths (e.g. [`/readyz`](#health)) return `503` while the
server still answers requests, so a load balancer / kubelet
deregisters this instance *before* new connections start being
refused — the clean way to drain during a rolling update.  Liveness
stays `200`.  `0` stops accepting immediately on SIGTERM (no
lame-duck).

```kdl
server lame-duck-timeout=10
```

**Default:** `0`.
**See also:** [`health`](#health),
[`graceful-drain-timeout`](#graceful-drain-timeout).

### cert-key-mode

**Property** on [`server`](#server).  Optional octal string.

POSIX file mode hypershunt applies to private keys it writes under
[`state-dir`](#state-dir) (ACME-issued keys and the JWT signing
key).  Accepts either a leading `0` (`"0640"`) or a leading `0o`
(`"0o640"`).

```kdl
server state-dir="/var/lib/hypershunt" cert-key-mode="0640"
```

**Default:** `"0600"` (owner read/write only).
**See also:** [`state-dir`](#state-dir).

### tls-options

**Child** of [`server`](#server).  Optional.

Server-wide defaults inherited by every listener TLS source
(unless the listener overrides the same key locally).  Carries the
same property and child surface as a listener-level
[`tls`](#tls-listener) node.

```kdl
server {
    tls-options min-version="1.3" ocsp=#true {
        cipher "TLS_AES_256_GCM_SHA384"
        cipher "TLS_CHACHA20_POLY1305_SHA256"
    }
}
```

**See also:** [`min-version`](#min-version), [`cipher`](#cipher),
[`ocsp`](#ocsp), [`mtls`](#mtls).

#### min-version

**Property** on [`tls-options`](#tls-options) and
[`tls`](#tls-listener).  Optional.

Lowest TLS protocol version hypershunt will accept.  Accepts `"1.2"`
or `"1.3"`.

```kdl
tls-options min-version="1.3"
```

**Default:** `"1.2"`.

#### cipher

**Repeated child** of [`tls-options`](#tls-options) and
[`tls`](#tls-listener).  Optional.

Cipher suite to enable, named with rustls's identifier string
(e.g. `"TLS_AES_256_GCM_SHA384"`).  Each `cipher` child contributes
one suite; the listed suites replace rustls's default cipher list
in declaration order.  When no `cipher` child is present, rustls's
defaults apply.

```kdl
tls-options {
    cipher "TLS_AES_256_GCM_SHA384"
    cipher "TLS_CHACHA20_POLY1305_SHA256"
}
```

**Default:** rustls defaults (currently the three TLS 1.3 AEAD
suites plus a small TLS 1.2 set).

#### ocsp

**Property** on [`tls-options`](#tls-options) and
[`tls`](#tls-listener).  Optional boolean.

Master switch for OCSP stapling, with *staple-when-available*
semantics.  When `#true` (the default) and the certificate records an
OCSP responder URL, hypershunt fetches an OCSP response from it,
caches it, and staples it to each TLS handshake until `nextUpdate`.
A certificate **without** a responder URL is served without a staple
-- this is normal, not an error.  Public CAs have been dropping OCSP
since the CA/Browser Forum made it optional in 2023; ACME CAs such as
Let's Encrypt stopped publishing responder URLs in 2025, so stapling
is simply unavailable for those certificates.  Set to `#false` to
disable stapling entirely (the refresh task is never started).

```kdl
tls "files" cert="cert.pem" key="key.pem" ocsp=#false
```

**Default:** `#true`.
**See also:** [`ocsp-timeout`](#ocsp-timeout),
[`ocsp-min-refresh`](#ocsp-min-refresh),
[`ocsp-failure-backoff`](#ocsp-failure-backoff).

#### ocsp-timeout

**Property** on [`tls-options`](#tls-options) and
[`tls`](#tls-listener).  Optional integer.

Per-request HTTP timeout (seconds) when contacting the OCSP
responder.

```kdl
tls-options ocsp-timeout=10
```

**Default:** `10`.

#### ocsp-min-refresh

**Property** on [`tls-options`](#tls-options) and
[`tls`](#tls-listener).  Optional integer.

Floor for the in-memory refresh interval (seconds).  Even if the
responder reports a `nextUpdate` far in the future, hypershunt will
re-fetch at least this often so revocations propagate.

```kdl
tls-options ocsp-min-refresh=3600
```

**Default:** `3600` (one hour).

#### ocsp-failure-backoff

**Property** on [`tls-options`](#tls-options) and
[`tls`](#tls-listener).  Optional integer.

Delay (seconds) between OCSP fetch attempts after a failure.

```kdl
tls-options ocsp-failure-backoff=300
```

**Default:** `300` (five minutes).

#### mtls

**Child** of [`tls-options`](#tls-options) and
[`tls`](#tls-listener).  Optional.

Enables mutual TLS: clients must present a certificate signed by
one of the trust anchors listed in [`ca`](#ca), unless
[`mode`](#mode) is `"optional"`.  When set on
`tls-options` the same mTLS profile applies to every listener that
doesn't override it.

```kdl
tls "files" cert="server.pem" key="server.key" {
    mtls mode="required" {
        ca "/etc/hypershunt/clients-ca.pem"
        revocation "/etc/hypershunt/clients.crl"
    }
}
```

**See also:** [`ca`](#ca), [`mode`](#mode),
[`revocation`](#revocation), [`refresh`](#refresh).

##### ca

**Repeated child** of [`mtls`](#mtls).  Required, at least one.

PEM file containing one or more trust anchors used to verify
client certificates.  Multiple `ca` children stack — a client
certificate is accepted if any anchor in any file signs it.

```kdl
mtls {
    ca "/etc/hypershunt/internal-ca.pem"
    ca "/etc/hypershunt/partner-ca.pem"
}
```

##### mode

**Property** on [`mtls`](#mtls).  Optional string.

`"required"` rejects connections that don't present a valid client
certificate.  `"optional"` lets unauthenticated connections through
but still validates a presented certificate — the authenticated
identity is then available to policy and the `auth-request`
handler.

```kdl
mtls mode="optional" { ca "/etc/hypershunt/clients-ca.pem" }
```

**Default:** `"required"`.

##### revocation

**Repeated child** of [`mtls`](#mtls).  Optional.

PEM file containing a Certificate Revocation List checked at
handshake time.  Multiple `revocation` children stack.

```kdl
mtls {
    ca "/etc/hypershunt/clients-ca.pem"
    revocation "/etc/hypershunt/clients.crl"
}
```

##### refresh

**Property** on [`mtls`](#mtls).  Optional integer.

Seconds between automatic reloads of the [`revocation`](#revocation)
CRL files.  `0` disables reloading — hypershunt reads them once at
startup and never again.

```kdl
mtls refresh=600 { ca "/etc/hypershunt/clients-ca.pem" }
```

**Default:** `0` (no reload).

### auth

**Child** of [`server`](#server).  Optional.  At most one.

Selects the authentication backend used by every `location` whose
[`policy`](#policy-location) refers to an authenticated identity
(via `authenticated`, `user`, or `group` predicates) and by any
location that contains a [`basic-auth`](#basic-auth) directive.

The positional argument names the backend kind: `"pam"`,
`"ldap"`, `"file"`, `"subrequest"`, `"jwt"`, or `"oidc"`.  `"oidc"`
is never used standalone — it appears as the inner backend of
`auth "jwt" backend="oidc"`.

```kdl
server { auth "ldap" url="ldap://localhost" \
    bind-dn="uid={user},ou=people,dc=ex,dc=com" \
    base-dn="ou=groups,dc=ex,dc=com" }
```

**See also:** [`auth "pam"`](#auth-pam),
[`auth "ldap"`](#auth-ldap), [`auth "file"`](#auth-file),
[`auth "subrequest"`](#auth-subrequest), [`auth "jwt"`](#auth-jwt).

#### auth "pam"

**Variant** of [`auth`](#auth) selected by the positional kind
`"pam"`.

Validates HTTP Basic credentials through a PAM stack named by
[`service`](#service).  Group memberships come from the POSIX
group database after authentication succeeds.  On Linux you'll
typically point `service` at a custom PAM file (e.g.
`/etc/pam.d/hypershunt`) rather than reusing `login`, because the
default `login` stack expects a TTY.

```kdl
server { auth "pam" service="hypershunt" }
```

##### service

**Property** on [`auth "pam"`](#auth-pam).  Optional string.

Name of the PAM service file under `/etc/pam.d/` to load.

```kdl
auth "pam" service="hypershunt"
```

**Default:** `"login"`.

#### auth "ldap"

**Variant** of [`auth`](#auth) selected by the positional kind
`"ldap"`.

Validates HTTP Basic credentials by performing a simple bind
against an LDAP server.  Group memberships come from a follow-up
search keyed by [`group-filter`](#group-filter) and read from
[`group-attr`](#group-attr).

```kdl
server {
    auth "ldap" url="ldaps://ldap.example.com:636" \
        bind-dn="uid={user},ou=people,dc=example,dc=com" \
        base-dn="ou=groups,dc=example,dc=com"
}
```

##### url

**Property** on [`auth "ldap"`](#auth-ldap).  Required.

LDAP server URL.  Scheme must be one of `ldap://`, `ldaps://`, or
`ldapi://` (Unix-socket).

##### bind-dn

**Property** on [`auth "ldap"`](#auth-ldap).  Required.

DN template used to bind as the authenticating user.  Must
contain the literal substring `{user}`, which hypershunt replaces with
the HTTP Basic username (LDAP-escaped) before binding.

```kdl
auth "ldap" url="..." \
    bind-dn="uid={user},ou=people,dc=example,dc=com" \
    base-dn="..."
```

##### base-dn

**Property** on [`auth "ldap"`](#auth-ldap).  Required.

DN under which group membership is searched.

##### group-filter

**Property** on [`auth "ldap"`](#auth-ldap).  Optional string.

LDAP search filter used to find groups containing the
authenticated user.  Must contain `{user}` (replaced with the
LDAP-escaped username) or `{dn}` (replaced with the bind DN).

```kdl
auth "ldap" url="..." bind-dn="..." base-dn="..." \
    group-filter="(member={dn})"
```

**Default:** `"(memberUid={user})"`.

##### group-attr

**Property** on [`auth "ldap"`](#auth-ldap).  Optional string.

Attribute name read from each matching group entry to populate
the user's group list.

**Default:** `"cn"`.

##### starttls

**Property** on [`auth "ldap"`](#auth-ldap).  Optional boolean.

Send STARTTLS on the initial connection.  Only meaningful with the
`ldap://` scheme; `ldaps://` is already TLS-from-the-handshake.

**Default:** `#false`.

##### timeout

**Property** on [`auth "ldap"`](#auth-ldap).  Optional integer.

LDAP operation timeout (seconds).  Applies to both the bind and
the group-membership search.

**Default:** `5`.

#### auth "file"

**Variant** of [`auth`](#auth) selected by the positional kind
`"file"`.

Validates HTTP Basic credentials against an htpasswd-style file.
Each non-blank, non-comment line is `username:hash`.  Recognised
hash schemes are bcrypt (`$2y$`, `$2b$`, `$2a$`), SHA-512 crypt
(`$6$`), and Argon2id (`$argon2id$`).  Plain, MD5-crypt, DES, and
SHA-1 are rejected at parse time.

Groups can be expressed by appending `:group1,group2` after the
hash (one extra colon-separated field).  The file is re-read when
its mtime changes; parses happen on demand and are cached for
[`cache`](#cache) seconds.

```kdl
server { auth "file" path="/etc/hypershunt/htpasswd" cache=60 }
```

##### path

**Property** on [`auth "file"`](#auth-file).  Required.

Filesystem path to the htpasswd file.

##### cache

**Property** on [`auth "file"`](#auth-file).  Optional integer.

Seconds for which a successful hash-verification is cached.
Reduces per-request bcrypt/Argon2 cost.

**Default:** `60`.

#### auth "subrequest"

**Variant** of [`auth`](#auth) selected by the positional kind
`"subrequest"`.

Delegates authentication to an external HTTP service, in the
nginx `auth_request` tradition.  For each protected request hypershunt
issues a GET to [`url`](#url-subrequest) carrying selected request
headers (see [`forward-header`](#forward-header)).  HTTP 200
means "allow"; the authenticated username and group list are read
from the response headers named by
[`user-header`](#user-header) and
[`groups-header`](#groups-header).  Any other status code means
"deny".

```kdl
server {
    auth "subrequest" url="http://auth.internal/check" \
        user-header="X-Auth-User" groups-header="X-Auth-Groups" {
        forward-header "Authorization"
        forward-header "Cookie"
    }
}
```

##### url (subrequest)

**Property** on [`auth "subrequest"`](#auth-subrequest).  Required.

URL of the external authenticator.  Must use the `http://` scheme.

##### forward-header

**Repeated child** of [`auth "subrequest"`](#auth-subrequest).
Optional.

Name of a request header to copy from the inbound request to the
subrequest.  Typically you'll include `"Authorization"` and
`"Cookie"`.

##### user-header

**Property** on [`auth "subrequest"`](#auth-subrequest).  Optional.

Name of the response header carrying the authenticated username.

**Default:** none (no username recorded).

##### groups-header

**Property** on [`auth "subrequest"`](#auth-subrequest).  Optional.

Name of the response header carrying a comma-separated group list.

**Default:** none (empty group list).

##### timeout (subrequest)

**Property** on [`auth "subrequest"`](#auth-subrequest).  Optional
integer.

Per-subrequest timeout (seconds).

**Default:** `5`.

#### auth "jwt"

**Guide:** [JWT sessions](guide.md#jwt-sessions).

**Variant** of [`auth`](#auth) selected by the positional kind
`"jwt"`.

Two modes:

- **Standalone** — no `backend=` property.  Validates incoming
  ES256 JWTs presented as a `Cookie:` (named by
  [`cookie-name`](#cookie-name)) or `Authorization: Bearer <jwt>`.
  No new tokens are issued; useful when a peer service does the
  issuing and hypershunt just verifies.
- **Wrapped** — `backend="pam" | "ldap" | "file" | "subrequest"
  | "oidc"`.  Hypershunt runs the inner backend on credential requests,
  issues a fresh JWT cookie on success, and accepts that cookie
  for subsequent requests.  The inner backend's properties live on
  the same `auth` node with a kind prefix (e.g. `pam-service=` for
  the wrapped PAM backend, `oidc-issuer=` for the wrapped OIDC
  backend).  Repeating children of the inner backend (such as
  `forward-header` for subrequest or `scope` for OIDC) use the
  same prefix (`subrequest-forward-header`, `oidc-scope`).

JWT mode requires [`state-dir`](#state-dir).  Hypershunt stores the
signing key at `{state-dir}/jwt/ec-key.pem`, generating it on
first start.  The JWKS document is served at
`/.well-known/jwks.json` on every vhost.

```kdl
server state-dir="/var/lib/hypershunt" {
    auth "jwt" backend="ldap" cookie-name="session" validity=3600 \
        ldap-url="ldaps://ldap.example.com" \
        ldap-bind-dn="uid={user},ou=people,dc=example,dc=com" \
        ldap-base-dn="ou=groups,dc=example,dc=com"
}
```

##### cookie-name

**Property** on [`auth "jwt"`](#auth-jwt).  Optional string.

Name of the cookie that carries the issued JWT.

**Default:** `"hypershunt_session"`.

##### validity

**Property** on [`auth "jwt"`](#auth-jwt).  Optional integer.

Lifetime in seconds of issued cookies.

**Default:** `300`.

##### backend

**Property** on [`auth "jwt"`](#auth-jwt).  Optional string.

When set, names the inner credential backend that JWT wraps.  One
of `"pam"`, `"ldap"`, `"file"`, `"subrequest"`, or `"oidc"`.
Inner-backend properties appear with a `<kind>-` prefix on the
same node (e.g. `pam-service=`, `ldap-url=`, `oidc-issuer=`).
Repeating inner children appear in the body with the same prefix.

When absent, hypershunt runs as a standalone JWT validator.

```kdl
auth "jwt" backend="oidc" oidc-issuer="https://accounts.example.com" \
    oidc-client-id="hypershunt" oidc-redirect-uri="https://app/cb"
```

#### auth "oidc"

**Guide:** [OIDC single sign-on](guide.md#oidc-single-sign-on).

**Inner variant** of [`auth "jwt"`](#auth-jwt) selected by
`backend="oidc"`.

Browser SSO via OpenID Connect (RFC 6749 / OIDC Core 1.0).  All
property and child names below appear with the `oidc-` prefix on
the `auth "jwt"` node.

When `bearer=#true`, hypershunt additionally accepts IdP-issued bearer
JWTs on `Authorization: Bearer <jwt>` and validates them against
the cached JWKS and the [`bearer-audience`](#bearer-audience)
allowlist; this turns the same `auth` block into both a browser
SSO front-end and an API resource server.

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
    }
}
```

##### issuer

**Property** on [`auth "oidc"`](#auth-oidc) (prefix `oidc-`).
Required.

OIDC issuer URL.  Hypershunt runs discovery at `<issuer>/.well-known/
openid-configuration` to learn the authorisation, token, JWKS,
and end-session endpoints.  Must be `https://` or
`http://localhost`/`http://127.0.0.1` (development only).

##### client-id

**Property** on [`auth "oidc"`](#auth-oidc) (prefix `oidc-`).
Required.

OAuth client identifier registered with the IdP.

##### client-secret

**Property** on [`auth "oidc"`](#auth-oidc) (prefix `oidc-`).
Optional.

Inline client secret.  Useful for development only; prefer
[`client-secret-file`](#client-secret-file) so the secret stays
out of the config file.

##### client-secret-file

**Property** on [`auth "oidc"`](#auth-oidc) (prefix `oidc-`).
Optional.

Path to a file containing the client secret.  Hypershunt reads the file
once at startup and uses the trimmed contents.  Wins over
[`client-secret`](#client-secret) when both are set.

##### redirect-uri

**Property** on [`auth "oidc"`](#auth-oidc) (prefix `oidc-`).
Required.

Absolute URL the IdP redirects to after authorisation.  Must
exactly match the value registered with the IdP and resolve to a
path served by hypershunt (typically the value of
[`callback-path`](#callback-path), e.g. `/oidc/callback`).

##### scope

**Repeated child** of [`auth "oidc"`](#auth-oidc) (prefix `oidc-`).
Optional.

OAuth scopes to request.  `openid` is added automatically if not
listed.  When [`refresh=#true`](#refresh) is set, `offline_access`
is also added automatically.

```kdl
oidc-scope "openid"
oidc-scope "profile"
oidc-scope "email"
oidc-scope "groups"
```

**Default:** `["openid", "profile", "email"]`.

##### username-claim

**Property** on [`auth "oidc"`](#auth-oidc) (prefix `oidc-`).
Optional string.

Name of the claim read from the ID token (and merged UserInfo
response) to populate the authenticated username.

**Default:** `"sub"`.

##### groups-claim

**Property** on [`auth "oidc"`](#auth-oidc) (prefix `oidc-`).
Optional string.

Name of the claim read to populate the group list.  Accepts either
a JSON array of strings or a single space-delimited string.

**Default:** `"groups"`.

##### login-path

**Property** on [`auth "oidc"`](#auth-oidc) (prefix `oidc-`).
Optional string.

Path served by hypershunt that starts the authorisation-code flow.
Browsers GET this with a `?next=<original-url>` query when their
JWT cookie is missing/expired and hypershunt needs them to log in.

```kdl
oidc-login-path="/auth/login"
```

**Default:** `"/oidc/login"`.

##### callback-path

**Property** on [`auth "oidc"`](#auth-oidc) (prefix `oidc-`).
Optional string.

Path served by hypershunt that the IdP redirects to with the
authorisation code.  Must match the path portion of
[`redirect-uri`](#redirect-uri).

**Default:** `"/oidc/callback"`.

##### state-ttl

**Property** on [`auth "oidc"`](#auth-oidc) (prefix `oidc-`).
Optional integer.

Lifetime (seconds) of the CSRF state stored between the login
redirect and the callback.

**Default:** `600`.

##### refresh

**Property** on [`auth "oidc"`](#auth-oidc) (prefix `oidc-`).
Optional boolean.

Enable the refresh-token flow.  When `#true`, hypershunt stores the
refresh token in a separate HttpOnly cookie
([`refresh-cookie`](#refresh-cookie)) and silently renews the
session JWT before it expires.  Implies `offline_access` is added
to [`scope`](#scope).

**Default:** `#false`.

##### refresh-ttl

**Property** on [`auth "oidc"`](#auth-oidc) (prefix `oidc-`).
Optional integer.

Lifetime (seconds) of the refresh-token cookie.

**Default:** `86400` (one day).

##### refresh-cookie

**Property** on [`auth "oidc"`](#auth-oidc) (prefix `oidc-`).
Optional string.

Name of the refresh-token cookie.

**Default:** `"__hypershunt_oidc_refresh"`.

##### logout-path

**Property** on [`auth "oidc"`](#auth-oidc) (prefix `oidc-`).
Optional string.

Path served by hypershunt that triggers logout.  Hypershunt drops the
session cookie + server-side refresh state and (when
[`idp-logout=#true`](#idp-logout)) redirects through the IdP's
`end_session_endpoint`.

**Default:** `"/oidc/logout"`.

##### post-logout-uri

**Property** on [`auth "oidc"`](#auth-oidc) (prefix `oidc-`).
Optional string.

URL the browser lands on after logout completes.  Must be a
same-origin absolute path (must start with a single `/`).

**Default:** `"/"`.

##### idp-logout

**Property** on [`auth "oidc"`](#auth-oidc) (prefix `oidc-`).
Optional boolean.

When `#true`, hypershunt sends the logout flow through the IdP's
`end_session_endpoint` (if discovery surfaced one).  When
`#false`, logout tears down only the local cookies.

**Default:** `#true`.

##### userinfo

**Property** on [`auth "oidc"`](#auth-oidc) (prefix `oidc-`).
Optional boolean.

Fetch the `/userinfo` endpoint after callback and after every
refresh, merging the result into the claims used to populate the
session.  UserInfo claims win over ID-token claims when both are
non-empty.  Required for IdPs (notably Google) that omit
`groups` or `email` from the ID token.

**Default:** `#false`.

##### discovery-refresh

**Property** on [`auth "oidc"`](#auth-oidc) (prefix `oidc-`).
Optional integer.

Seconds between automatic re-runs of OIDC discovery (JWKS
included).  Lets hypershunt pick up IdP key rotation without a
restart.  `0` disables periodic discovery.

**Default:** `3600`.

##### discovery-retry

**Property** on [`auth "oidc"`](#auth-oidc) (prefix `oidc-`).
Optional boolean.

When `#true`, hypershunt starts even if initial discovery fails and
keeps retrying in the background with exponential backoff (cap 5
minutes); OIDC endpoints return `503` + `Retry-After` until the
client is ready.  When `#false`, discovery failure is fatal at
startup.

**Default:** `#true`.

##### backchannel-logout

**Property** on [`auth "oidc"`](#auth-oidc) (prefix `oidc-`).
Optional boolean.

Accept IdP-pushed `logout_token` POSTs at
[`backchannel-logout-path`](#backchannel-logout-path) and drop
matching server-side refresh state.  The user's in-flight JWT
cookie remains valid until its own [`validity`](#validity) elapses
-- pair short `validity` with backchannel logout when fast
revocation matters.

**Default:** `#true`.

##### backchannel-logout-path

**Property** on [`auth "oidc"`](#auth-oidc) (prefix `oidc-`).
Optional string.

Path served by hypershunt that accepts back-channel logout POSTs.

**Default:** `"/oidc/backchannel-logout"`.

##### backchannel-max-iat-skew

**Property** on [`auth "oidc"`](#auth-oidc) (prefix `oidc-`).
Optional integer.

Maximum seconds the back-channel `logout_token`'s `iat` claim
may be in the past or future relative to the local clock.

**Default:** `120`.

##### backchannel-jti-ttl

**Property** on [`auth "oidc"`](#auth-oidc) (prefix `oidc-`).
Optional integer.

Lifetime (seconds) of the `jti` replay-protection cache used by
the back-channel logout endpoint.

**Default:** `300`.

##### bearer

**Property** on [`auth "oidc"`](#auth-oidc) (prefix `oidc-`).
Optional boolean.

Accept IdP-issued bearer JWTs presented as
`Authorization: Bearer <jwt>`.  Requires at least one
[`bearer-audience`](#bearer-audience).  Validated tokens are
cached by SHA-256(token) until their own `exp`.

**Default:** `#false`.

##### bearer-audience

**Repeated child** of [`auth "oidc"`](#auth-oidc) (prefix `oidc-`).
Required when `bearer=#true`.

Accepted token audience.  The token's `aud` claim must match at
least one listed audience.

```kdl
oidc-bearer=#true {
    oidc-bearer-audience "https://api.example.com"
}
```

##### bearer-cache-size

**Property** on [`auth "oidc"`](#auth-oidc) (prefix `oidc-`).
Optional integer.

Maximum entries in the LRU cache of validated bearer tokens.

**Default:** `1024`.

##### revoke-on-logout

**Property** on [`auth "oidc"`](#auth-oidc) (prefix `oidc-`).
Optional boolean.

Send an RFC 7009 revocation to the IdP for the refresh token on
logout.  Best-effort; logout completes locally regardless of the
IdP response.

**Default:** `#true`.

##### require-iss

**Property** on [`auth "oidc"`](#auth-oidc) (prefix `oidc-`).
Optional boolean.

Reject callback URLs that lack the RFC 9207 `iss` parameter.  When
the parameter is present hypershunt always checks it; this knob
controls what happens when it's absent.

**Default:** `#false`.

##### resource

**Repeated child** of [`auth "oidc"`](#auth-oidc) (prefix `oidc-`).
Optional.

RFC 8707 resource indicators.  Each value names a resource the
access token is intended for; the IdP narrows the token `aud`
accordingly.  Must be an absolute `http://` or `https://` URL
with no fragment.

### geoip

**Child** of [`server`](#server).  Optional.

Loads a MaxMind GeoIP2 country database.  Required when any
[`policy`](#policy-location) uses the `country` predicate.

```kdl
server { geoip db="/var/lib/GeoIP/GeoLite2-Country.mmdb" }
```

##### db

**Property** on [`geoip`](#geoip).  Required.

Filesystem path to the `.mmdb` file.  The file is opened once at
startup; hypershunt does not watch it.  Use SIGHUP to pick up a new
file.

### health

**Child** of [`server`](#server).  Optional.

The built-in Kubernetes-style health endpoints are **served by
default** — no configuration is required.  This block only *tunes*
them: override the paths, or disable them server-wide with
`enabled=#false`.  They are intercepted before vhost routing so they
work without a `Host` header and cannot be shadowed by a user
`location`.  Two classes, both answering `GET`/`HEAD` with a small
JSON body and `Cache-Control: no-cache, no-store`:

- **liveness** (`/healthz`, `/livez` by default) — always `200`
  (`{"status":"ok","check":"livez"}`) while the process runs.
- **readiness** (`/readyz` by default) — `200` normally, but `503`
  (`{"status":"draining",...}` + `Retry-After`) once the server is
  gracefully draining (SIGTERM / upgrade hand-off), so a load
  balancer / kubelet deregisters this instance before it goes away.
  See [`lame-duck-timeout`](#lame-duck-timeout) to keep accepting
  during that window.

Liveness never flips to `503` while draining — a draining process is
still alive and must not be restarted.

```kdl
server {
    health {
        liveness-path "/livez"     // repeatable; overrides the defaults
        readiness-path "/readyz"   // repeatable; overrides the defaults
    }
}
```

##### enabled

**Property** on [`health`](#health).  Optional boolean.  Server-wide
default; a listener's [`health=`](#health-listener) overrides it per
listener.  Bare `health` (no properties) is equivalent to `health
enabled=#true`.

**Default:** `#true` — the endpoints are served even when no `health`
block is present; set `enabled=#false` to turn them off server-wide.

##### liveness-path / readiness-path

**Repeating children** of [`health`](#health).  Optional.

Override the default liveness / readiness path sets.  When either is
given it *replaces* that set's defaults.  Paths must be absolute, and
a path cannot be both a liveness and a readiness path.

**Default:** liveness `/healthz` + `/livez`; readiness `/readyz`.

### health (listener)

**Property** on [`listener`](#listener).  Optional boolean.

Per-listener override of the server-wide health default.  Set
`health=#false` to keep the endpoints off a public listener (so
liveness/readiness aren't exposed to the internet), or `health=#true`
to force them on.  Ignored on L4 proxy listeners.

```kdl
listener "tcp://[::]:443" health=#false        // public: no health
listener "tcp://10.0.0.1:9000"                 // admin: health on
```

**Default:** unset (inherits `server` `health enabled`).

### policy (server)

**Child** of [`server`](#server).  Optional, repeatable.

Defines a *named* policy that can be re-used from any number of
locations or stream listeners via `apply "<name>"`.  See the
location-level [`policy`](#policy-location) entry for the
predicate/action grammar — the body is identical.

```kdl
server {
    policy "internal-only" {
        allow address "10.0.0.0/8" "192.168.0.0/16"
        deny code=403
    }
}
vhost "internal.example.com" {
    location "/" { policy { apply "internal-only" }; static root="/var/www/internal" }
}
```

### error-page

**Child** of [`server`](#server).  Optional, repeatable.

Replaces hypershunt's built-in HTML body for one status code with a
custom one.  Exactly one of [`path=`](#path-error-page) (filesystem
path to an HTML file, served as `Content-Type: text/html`) or
[`html=`](#html-error-page) (inline HTML literal) must be set.

```kdl
server {
    error-page 404 path="/etc/hypershunt/error/404.html"
    error-page 500 html="<h1>Sorry, something broke.</h1>"
}
```

##### path (error-page)

**Property** on [`error-page`](#error-page).

##### html (error-page)

**Property** on [`error-page`](#error-page).

### access-log

**Child** of [`server`](#server).  Optional.

Configures the access log.  The positional argument is the format
(`"tracing"`, `"json"`, `"common"`, or `"combined"`); the optional
[`path=`](#path-access-log) property names the file to write
non-`tracing` formats to.

`"tracing"` emits structured `INFO`-level events through the
`tracing` crate — where they go is controlled by
`RUST_LOG` and the tracing subscriber set up in `src/main.rs`; the
`path=` property is ignored.  The other three formats are written
to the named file (stderr if absent) with `O_APPEND` and a
nightly-style log-rotation hand-off: hypershunt re-opens the file on
SIGHUP, so log rotation can rename-and-signal in the usual style.

```kdl
server { access-log "combined" path="/var/log/hypershunt/access.log" }
```

##### path (access-log)

**Property** on [`access-log`](#access-log).

---

## certificate

The `certificate` node defines a *named* TLS certificate that
multiple listeners can share with [`tls "ref"`](#tls-ref).
Required when two or more listeners would otherwise need identical
[`tls "acme"`](#tls-acme) blocks — a single ACME manager and
renewal loop runs for the shared cert, instead of each listener
racing on the same on-disk slot.

The body holds exactly one [`tls`](#tls-certificate) child whose
kind is `"files"`, `"acme"`, or `"self-signed"`.  `"ref"` is not
allowed inside `certificate` (a certificate cannot reference
itself).

```kdl
certificate "edge" {
    tls "acme" email="ops@example.com" {
        domain "example.com"
        domain "www.example.com"
    }
}
listener "tcp://[::]:443" { tls "ref" name="edge" }
listener "udp://[::]:443" { tls "ref" name="edge" }   // HTTP/3
```

### tls (certificate)

**Child** of [`certificate`](#certificate).  Required.

A single [`tls "<kind>"`](#tls-listener) source descriptor; refer
to the listener-level [`tls`](#tls-listener) entry for the full
property and child surface.  Inside a `certificate` the `"ref"`
kind is rejected.

---

## listener

A `listener` accepts connections on one socket address and routes
them through the protocol stack you wire up.  The positional
argument is the bind URL (see [bind URL](#bind-url)); everything
else — TLS, alpn, timeouts, policy, the L4 proxy mode — is
controlled by properties and children.

The same listener has two **modes**: HTTP mode (when no
[`proxy`](#proxy-listener) child is present) and L4 proxy mode (when
one is).  The two modes carry different sets of legal directives.
Mixing them produces a parse-time error.

```kdl
listener "tcp://[::]:80" { }                          // plain HTTP/1.1+h2
listener "tcp://[::]:443" { tls "self-signed" }       // HTTPS
listener "udp://[::]:443" { tls "self-signed" }       // HTTP/3
listener "tcp://[::]:5432" { proxy "tcp://10.0.0.5:5432" } // L4 TCP proxy
```

### bind URL

**Positional argument** on [`listener`](#listener) and on the L4
[`proxy`](#proxy-listener) child.  Required.

URL whose scheme picks the socket family:

| Scheme              | Socket                              |
|---------------------|-------------------------------------|
| `tcp://host:port`   | AF_INET / AF_INET6, SOCK_STREAM     |
| `udp://host:port`   | AF_INET / AF_INET6, SOCK_DGRAM      |
| `unix-stream:/path` | AF_UNIX, SOCK_STREAM                |
| `unix-dgram:/path`  | AF_UNIX, SOCK_DGRAM                 |
| `unix-seqpacket:/path` | AF_UNIX, SOCK_SEQPACKET (Linux)  |

`host` accepts a hostname, an IPv4 literal (`0.0.0.0`,
`192.0.2.1`), or a bracketed IPv6 literal (`[::]`, `[2001:db8::1]`).
Port `0` lets the kernel pick (mostly useful in tests).  Unix
paths must be absolute.

```kdl
listener "tcp://0.0.0.0:80"
listener "tcp://[::]:443"
listener "udp://[::]:443" { tls "self-signed" }  // udp needs tls or proxy
listener "unix-stream:/run/hypershunt.sock"
```

The bind URL also determines what the encryption layer means:
[`tls`](#tls-listener) selects HTTPS on a byte-stream socket, HTTP/3
on `udp://`, and — when paired with a `proxy` child — a
DTLS-terminating datagram proxy on `udp://` (reserved).  `tls` is
rejected on `unix-dgram:` / `unix-seqpacket:` (QUIC/DTLS are
UDP-only).

### accept-proxy-protocol

**Property** on [`listener`](#listener).  Optional string.

When set, hypershunt expects every inbound connection to start with a
HAProxy PROXY-protocol v1 (`"v1"`) or v2 (`"v2"`) header.  The
header is consumed and the carried source address becomes the
peer address used by access policies, the `X-Forwarded-For` chain,
and rate-limiter buckets.  A connection that doesn't carry the
expected header is dropped.

Combine with [`trusted-proxies`](#trusted-proxies) to limit which
peer IPs may send PROXY headers.

```kdl
listener "tcp://127.0.0.1:8080" accept-proxy-protocol="v2" {
    trusted-proxies "10.0.0.0/8"
}
```

**Default:** none (no PROXY protocol expected).
**See also:** [`trusted-proxies`](#trusted-proxies),
[`proxy-protocol`](#proxy-protocol) (the outbound counterpart on
the L4 proxy child).

### vhost (listener child)

**Child** of [`listener`](#listener).  One or more positional
strings; repeatable.

Selects which [`vhost`](#vhost)s this listener serves, by their
reference handle (a vhost's [`name`](#name-vhost), defaulting to its host
pattern).  Each `vhost` child contributes one or more names;
multiple children concatenate, preserving order.  A listener `vhost`
is a *reference* to a top-level vhost, never a definition, so it
carries no block.

- **No `vhost` child** -> the listener serves the **implicit set**:
  every vhost not marked [`explicit-only`](#explicit-only), in
  declaration order.
- **One or more `vhost` children** -> the listener serves **exactly**
  the listed vhosts, in the given order.  This is how you serve
  different vhost sets on different ports, and how two vhosts that
  share a host (distinguished by `name`) serve different content per
  listener.

The **first** vhost in the effective list (or, for the implicit set,
the first declared vhost) is the listener's **default**: the vhost
served when the request `Host` matches no literal name and no regex
pattern.  Use [`reject-unknown-host`](#reject-unknown-host) to drop
the default and return `404` instead.

```kdl
// Per-port subsets, and a shared host with different content per port.
// "lan" is explicit-only so the shared host appears at most once in
// any implicit set.
vhost "example.com" name="lan" explicit-only=#true {
    location "/" { static root="/srv/lan" }
}
vhost "example.com" name="pub" { location "/" { static root="/srv/pub" } }
vhost "admin" explicit-only=#true {
    location "/" { proxy { upstream "http://127.0.0.1:9000" } }
}

listener "tcp://[::]:80"  { vhost "lan" "admin" }   // set [lan, admin]
listener "tcp://[::]:443" { tls "self-signed"; vhost "pub" }
listener "tcp://[::]:8080"                           // implicit: just "pub"
```

**Default:** none (the listener serves the implicit set).
**See also:** [`name`](#name-vhost), [`explicit-only`](#explicit-only),
[`reject-unknown-host`](#reject-unknown-host).

### reject-unknown-host

**Property** on [`listener`](#listener).  Optional boolean.

When `#true`, a request whose `Host` matches no vhost on this
listener gets a `404` instead of falling back to the listener's
default (first) vhost.  Use it on a listener that must serve only
known hosts, so probes with arbitrary `Host` headers don't reach a
catch-all site.

```kdl
listener "tcp://[::]:80" reject-unknown-host=#true { vhost "example.com" }
```

**Default:** `#false` (unknown hosts fall back to the default vhost).

### max-connections

**Property** on [`listener`](#listener).  Optional integer.

Cap on simultaneous accepted connections.  Past the cap the
listener stops calling `accept(2)` until an existing connection
closes.  Backpressure shows up as `accept(2)` delay on the
kernel's listen queue rather than an explicit error.

```kdl
listener "tcp://[::]:80" max-connections=10000 { }
```

**Default:** none (no hypershunt-side cap; the kernel's `somaxconn`
applies).

### max-request-body

**Property** on [`listener`](#listener) and on
[`location`](#location).  Optional integer.

Cap on inbound request body size in bytes.  Bodies with a
`Content-Length` larger than the cap return `413` before the
handler runs; chunked bodies that exceed the cap mid-stream also
return `413`.  When set on both `listener` and `location`, the
location value wins (and can only be smaller in practice — the
listener cap is enforced first, before routing).

```kdl
listener "tcp://[::]:80" max-request-body=1048576 { }
vhost "example.com" {
    location "/upload/" max-request-body=104857600 {
        proxy { upstream "http://uploader:9000" }
    }
}
```

**Default:** none (no cap).

### tls (listener)

**Guide:** [HTTPS / TLS termination](guide.md#https--tls-termination).

**Child** of [`listener`](#listener).  Optional, at most one.
Byte-stream (`tcp://`, `unix-stream:`) or `udp://` listeners.

Enables TLS termination.  On a byte-stream listener it serves
HTTPS; on a `udp://` listener the very same block serves HTTP/3
(QUIC's encryption layer *is* TLS 1.3) — see
[tls on udp:// (HTTP/3)](#tls-on-udp-http3).  It is rejected on
`unix-dgram:` / `unix-seqpacket:` (QUIC is UDP-only).  The
positional argument names the cert source kind; the rest of the
surface depends on the kind.  All four kinds inherit
[`tls-options`](#tls-options) settings (min-version, ciphers,
OCSP knobs, mTLS) from the server-level block and accept
listener-level overrides.

```kdl
listener "tcp://[::]:443" {
    tls "files" cert="/etc/hypershunt/cert.pem" key="/etc/hypershunt/key.pem"
}
```

#### tls "files"

**Variant** of [`tls`](#tls-listener) selected by the kind
`"files"`.  Reads a PEM certificate and PEM private key from the
filesystem.

Required properties: `cert=`, `key=`.  Both must be readable by
the post-privilege-drop user.

```kdl
tls "files" cert="/etc/hypershunt/cert.pem" key="/etc/hypershunt/key.pem"
```

#### tls "acme"

**Variant** of [`tls`](#tls-listener) selected by the kind
`"acme"`.  Acquires and renews a certificate via ACME (Let's
Encrypt by default).

Body must contain at least one [`domain`](#domain) child.  At
least one domain is required; multiple domains share the same
issued certificate as Subject Alternative Names.  Set
[`challenge`](#challenge) to `"dns-01"` to use a
[`dns-provider`](#dns-provider) instead of the default HTTP-01.
ACME requires [`state-dir`](#state-dir).

```kdl
tls "acme" email="ops@example.com" {
    domain "example.com"
    domain "www.example.com"
}
```

##### domain

**Repeated child** of [`tls "acme"`](#tls-acme).  Required, at
least one.

Domain name to include on the issued certificate.  Wildcards
(`*.example.com`) require [`challenge="dns-01"`](#challenge).

##### email

**Property** on [`tls "acme"`](#tls-acme).  Optional string.

Email address registered with the ACME server for renewal
notifications and rate-limit identification.

##### name (acme)

**Property** on [`tls "acme"`](#tls-acme).  Optional string.

Directory name under `{state-dir}/acme/` where the issued
certificate is stored.  Defaults to the first listed domain.  Set
explicitly to share an on-disk slot between configurations.

##### staging

**Property** on [`tls "acme"`](#tls-acme).  Optional boolean.

When `#true`, talk to Let's Encrypt's staging server
(`acme-staging-v02.api.letsencrypt.org/directory`) instead of
production.  Staging has far looser
[rate limits](https://letsencrypt.org/docs/rate-limits/), so test
new configs against it first; staging certificates are not publicly
trusted.  Can also be forced without editing the config via the
[`HYPERSHUNT_ACME_STAGING`](#hypershunt_acme_staging) environment
variable.  An explicit [`server=`](#server-acme) takes precedence
over both.

When switching from staging to production, delete the cached
staging certificate under [`state-dir`](#state-dir) first: the two
share the same on-disk slot and hypershunt only re-issues when the
stored cert nears expiry, so a valid staging cert would otherwise
suppress the production issuance.

**Default:** `#false`.

##### server (acme)

**Property** on [`tls "acme"`](#tls-acme).  Optional string.

ACME directory URL to use in place of Let's Encrypt.  Useful with
private CAs that speak ACME (e.g. step-ca, smallstep).

**Default:** `https://acme-v02.api.letsencrypt.org/directory`.

##### HYPERSHUNT_ACME_STAGING

**Environment variable.**  When set to any value, forces every
`tls "acme"` certificate to issue from Let's Encrypt's staging CA,
exactly as if [`staging=#true`](#staging) were set on each.  Useful
for containers and CI where you'd rather not edit the config.  An
explicit [`server=`](#server-acme) still takes precedence.

##### retry-interval

**Property** on [`tls "acme"`](#tls-acme).  Optional integer.

Seconds to wait between attempts when a renewal fails.  Lets
Encrypt's rate limit is 5 failed validations per account per
hostname per hour; the default keeps comfortably within it.

**Default:** `3600` (one hour).

##### challenge

**Property** on [`tls "acme"`](#tls-acme).  Optional string.

Which ACME challenge type to satisfy: `"http-01"`, `"dns-01"`, or
`"tls-alpn-01"`.  Wildcards force `"dns-01"`.  When `"dns-01"`
is set, a [`dns-provider`](#dns-provider) child is required.

**Default:** `"http-01"`.

##### dns-provider

**Child** of [`tls "acme"`](#tls-acme).  Required when
[`challenge="dns-01"`](#challenge); forbidden otherwise.

Names the plugin used to write `_acme-challenge.<domain>` TXT
records during the DNS-01 challenge.  The positional argument is
the provider kind: `"acme-dns"`, `"cloudflare"`, `"route53"`, or
`"exec"`.  The Route 53 provider requires building hypershunt with the
`dns-route53` Cargo feature.

###### acme-dns

**Variant** of [`dns-provider`](#dns-provider) for an
[acme-dns](https://github.com/joohoi/acme-dns) instance.  Required
properties: `api-url=`, `username=`, `password=`, `subdomain=`.

```kdl
dns-provider "acme-dns" api-url="https://acme-dns.internal" \
    username="..." password="..." subdomain="abcdef.acme-dns.internal"
```

###### cloudflare

**Variant** of [`dns-provider`](#dns-provider) for Cloudflare DNS.
Required properties: `zone-id=`, `api-token=` (a scoped token with
`Zone:DNS:Edit` is recommended over a global key).

###### route53

**Variant** of [`dns-provider`](#dns-provider) for AWS Route 53.
Required property: `hosted-zone-id=`.  Credentials are read from
the usual AWS chain (environment, profile, IMDS).

###### exec

**Variant** of [`dns-provider`](#dns-provider) that shells out to
an external program.  Required property: `program=` (executable
path).  Optional repeated `arg "..."` children supply additional
argv elements.  The program is invoked once to add the TXT record
and once to remove it, with the operation passed as the first
positional argument (`add` or `remove`).

```kdl
dns-provider "exec" program="/usr/local/bin/dns-update.sh" {
    arg "--zone"
    arg "example.com"
}
```

#### tls "self-signed"

**Variant** of [`tls`](#tls-listener) selected by the kind
`"self-signed"`.  Generates an in-memory self-signed certificate
on each start; useful only for development and CI.  Accepts no
kind-specific properties or children — adding `cert=`, `domain=`,
or similar is a parse error so a misplaced cert path doesn't get
silently ignored.

```kdl
tls "self-signed"
```

#### tls "ref"

**Variant** of [`tls`](#tls-listener) selected by the kind
`"ref"`.  Points at a named [`certificate`](#certificate)
defined at the top level so multiple listeners can share one
acceptor (and, for ACME, one renewal loop).

Required property: `name=` (the certificate's name).

```kdl
certificate "edge" {
    tls "acme" { domain "example.com" }
}
listener "tcp://[::]:443" { tls "ref" name="edge" }
```

### tls on udp:// (HTTP/3)

**Guide:** [HTTP/3](guide.md#http3).

On a `udp://` listener a [`tls`](#tls-listener) block selects
HTTP/3 termination.  QUIC encryption *is* TLS 1.3 (RFC 9001), so
the same cert sources (`"files"`, `"acme"`, `"self-signed"`,
`"ref"`) and the same plumbing apply, exactly mirroring TCP/TLS.
There is no plaintext HTTP/3, so a `udp://` listener with no `tls`
(and no `proxy`) is a config error.

```kdl
listener "udp://[::]:443" {
    tls "ref" name="edge"
}
```

**See also:** [Alt-Svc auto-advertisement](guide.md#http3),
[`quic-transport`](#quic-transport).

### tls + proxy on udp:// (DTLS, reserved)

On a `udp://` listener a [`tls`](#tls-listener) block *together with*
a [`proxy`](#proxy-listener) child selects a DTLS-terminating
datagram proxy: the `tls` block supplies the server cert source, the
`proxy` the datagram backend.  The presence of `proxy` is what
distinguishes this from plain HTTP/3 (`tls` alone).

DTLS termination is **not yet implemented** — no DTLS-capable crate
exists in the stack today — so this combination is reserved and
startup fails with "not yet implemented".  (On byte-stream listeners
`tls` + `proxy` is the unrelated, fully-supported TLS-terminating
stream proxy.)

```kdl
listener "udp://[::]:5684" {
    tls "self-signed"            // DTLS cert source (reserved)
    proxy "udp://10.0.0.5:5684"
}
```

### alpn

**Repeated child** of [`listener`](#listener) and
[`vhost`](#vhost).  Optional.

Overrides the protocol identifiers offered during the TLS
ALPN negotiation.  Defaults are `["h2", "http/1.1"]` for byte-stream
listeners, `["h3"]` for QUIC.

On a vhost, ALPN is selected from the ClientHello SNI before the
handshake completes, so different vhosts on the same listener can
negotiate different protocols (e.g. one host disables h2 without
affecting siblings).  Per-vhost ALPN is TCP/TLS only; regex
vhosts and QUIC fall back to the listener default.

```kdl
listener "tcp://[::]:443" {
    tls "self-signed"
    alpn "h2"
    alpn "http/1.1"
}
vhost "legacy.example.com" {
    alpn "http/1.1"   // disable h2 for this host
}
```

### quic-transport

**Child** of [`listener`](#listener).  Optional.  `udp://`
listeners only.

Per-listener quinn transport tuning.  All knobs are properties;
unset knobs use quinn's defaults.

```kdl
listener "udp://[::]:443" {
    tls "ref" name="edge"
    quic-transport max-idle-timeout=30 keep-alive-interval=10
}
```

##### max-concurrent-bidi-streams

**Property** on [`quic-transport`](#quic-transport).  Optional
integer.

Maximum concurrent bidirectional streams per QUIC connection.

##### max-idle-timeout

**Property** on [`quic-transport`](#quic-transport).  Optional
integer.

Idle timeout (seconds) after which a QUIC connection is dropped.

##### keep-alive-interval

**Property** on [`quic-transport`](#quic-transport).  Optional
integer.

Interval (seconds) between keep-alive frames sent on otherwise
idle connections.  `0` disables keep-alives.

##### zero-rtt

**Property** on [`quic-transport`](#quic-transport).  Optional
boolean.

Allow 0-RTT early data.  Carries replay risk — only enable for
endpoints whose handlers are idempotent.

**Default:** `#false`.

##### retry-tokens

**Property** on [`quic-transport`](#quic-transport).  Optional
boolean.

Use QUIC stateless retry tokens to mitigate amplification DoS.

**Default:** `#true`.

##### retry-token-lifetime

**Property** on [`quic-transport`](#quic-transport).  Optional
integer.

Lifetime (seconds) of issued retry tokens.

### trusted-proxies

**Repeated child** of [`listener`](#listener).  Optional.

CIDR or bare IP allowlist of peers permitted to send PROXY
protocol headers (when
[`accept-proxy-protocol`](#accept-proxy-protocol) is set) or
appear in an `X-Forwarded-For` chain that hypershunt should believe.
Connections from peers outside the list are dropped before any
header parsing.

```kdl
listener "tcp://0.0.0.0:8080" accept-proxy-protocol="v2" {
    trusted-proxies "10.0.0.0/8"
    trusted-proxies "172.16.0.0/12"
}
```

**Default:** none.  Cannot appear without
[`accept-proxy-protocol`](#accept-proxy-protocol).

### proxy (listener)

**Guide:** [Layer-4 proxy](guide.md#layer-4-proxy).

**Child** of [`listener`](#listener).  Optional, at most one.
Activates **L4 proxy mode**.

Forwards raw bytes (byte-stream listeners) or datagrams (datagram
listeners) to a single upstream of the same family.  HTTP routing
does not apply; vhosts, locations, and the [`timeouts`](#timeouts)
block are rejected at parse time.  Cross-family pairings (e.g. a
`udp://` listener with a `tcp://` upstream) are rejected too.

The first positional argument is the upstream
[bind URL](#bind-url); unlike listener bind URLs, the upstream
host must be a **literal IP address** (hostnames are not
resolved).  Scalar attributes (`proxy-protocol=`,
`flow-idle-timeout=`) are properties on the node; structured
attributes (`tls`, `dtls`, `policy`) live in the body.

```kdl
listener "tcp://[::]:5432" {
    proxy "tcp://10.0.0.5:5432" proxy-protocol="v2" {
        tls skip-verify=#false
    }
}
```

#### tls (upstream)

**Child** of [`proxy`](#proxy-listener).  Optional, byte-stream
upstreams only.

Wraps the upstream connection in TLS.  Properties:
`skip-verify=` (boolean; default `#false`) disables certificate
verification — only useful with self-signed backends.

#### dtls (upstream)

**Child** of [`proxy`](#proxy-listener).  Reserved.  `udp://`
upstreams only.

Reserved syntax for DTLS origination.  Startup fails with "not
yet implemented".

#### proxy-protocol

**Property** on [`proxy`](#proxy-listener) and on the handler-mode
[`proxy`](#proxy-handler).  Optional string.

Prepends a HAProxy PROXY-protocol v1 (`"v1"`) or v2 (`"v2"`)
header to each upstream connection, carrying the original client
address.  Byte-stream upstreams only.

```kdl
proxy "tcp://10.0.0.5:5432" proxy-protocol="v2"
```

#### flow-idle-timeout

**Property** on [`proxy`](#proxy-listener).  Optional integer.

Per-flow idle timeout (seconds) for datagram listeners.  Hypershunt
maintains one upstream socket per `(peer_addr, peer_port)` pair;
flows that see no traffic in either direction for this long are
torn down.  Has no effect on byte-stream listeners.

**Default:** `30`.

### timeouts

**Child** of [`listener`](#listener).  Optional.  HTTP mode only.

Tunes the request lifecycle.  All knobs are properties on the
node.

```kdl
listener "tcp://[::]:80" {
    timeouts request-header=30 handler=60 keepalive=75
}
```

##### request-header

**Property** on [`timeouts`](#timeouts).  Optional integer.

Maximum seconds hypershunt waits for a complete request header.
Defends against Slowloris-style header drip.

**Default:** `30`.  `0` means "unlimited".

##### handler

**Property** on [`timeouts`](#timeouts).  Optional integer.

Maximum seconds the handler may take to start producing a
response.  Hitting the cap returns `408`.

**Default:** no cap.

##### keepalive

**Property** on [`timeouts`](#timeouts).  Optional integer.

Maximum seconds an HTTP/1.1 connection sits idle between
requests before hypershunt closes it.  `0` disables keep-alive
(hypershunt sets `Connection: close` on every response).

**Default:** hyper's default (currently ~75 seconds).

### policy (listener)

**Child** of [`listener`](#listener).  Optional.  L4 proxy mode
only.

Same statement grammar as the location-level
[`policy`](#policy-location), but only the `address` and `country`
predicates are legal — `authenticated`, `user`, and `group`
require an HTTP authentication layer that L4 mode doesn't have.

```kdl
listener "tcp://0.0.0.0:5432" {
    proxy "tcp://10.0.0.5:5432"
    policy {
        allow address "10.0.0.0/8"
        deny code=403
    }
}
```

---

## vhost

Virtual hosts route requests by `Host` header.  The positional
argument is the host-match pattern; setting `regex=#true` turns it
into an anchored regex.  Vhosts are defined once at the top level;
each [`listener`](#listener) then serves either every vhost (the
default) or an explicit subset via its
[`vhost`](#vhost-listener-child) child.

Matching order per request, **within the matched listener's set**:
exact literal `Host` (O(1)), then regex patterns in the listener's
list order, then the listener's default (its first vhost, unless
[`reject-unknown-host`](#reject-unknown-host) is set).

```kdl
vhost "example.com" { alpn "http/1.1"; location "/" { static root="/var/www" } }
vhost #".+\.example\.com"# regex=#true { location "/" { static root="/var/www" } }
```

### name (vhost)

**Property** on [`vhost`](#vhost).  Optional string.

The reference handle a listener [`vhost`](#vhost-listener-child)
list uses to select this vhost.  It is distinct from the host-match
pattern, so two vhosts can share a host (e.g. two `example.com`
served on different listeners) yet be referenced unambiguously.
Defaults to the positional host pattern, so a vhost needs an
explicit `name` only when its pattern would otherwise collide or
when you want a clean handle for a regex vhost.  Handles must be
unique across all vhosts.

```kdl
vhost "example.com" name="lan" { location "/" { static root="/srv/lan" } }
vhost "example.com" name="pub" { location "/" { static root="/srv/pub" } }

listener "tcp://10.0.0.1:80" { vhost "lan" }   // internal interface
listener "tcp://[::]:80"     { vhost "pub" }   // public interface
```

**Default:** the positional host pattern.

### explicit-only

**Property** on [`vhost`](#vhost).  Optional boolean.

When `#true`, the vhost is left out of a listener's *implicit* set
(the all-vhosts default).  It is then reachable only on listeners
that name it in their [`vhost`](#vhost-listener-child) list.  Use it
for an admin or internal vhost that should never be exposed by a
listener that didn't ask for it.

```kdl
vhost "admin" explicit-only=#true { location "/" { static root="/srv/admin" } }
listener "tcp://[::]:8443" { tls "self-signed"; vhost "admin" }
```

**Default:** `#false`.

### regex

**Property** on [`vhost`](#vhost) and [`alias`](#alias).  Optional
boolean.

Treat the positional name as an anchored Perl-compatible regex
instead of an exact literal.  Regexes are checked in declaration
order, after all literal vhosts have failed.  Regex vhosts cannot
participate in per-SNI ALPN selection — they fall back to the
listener default.

**Default:** `#false`.

### alias

**Repeated child** of [`vhost`](#vhost).  Optional.

Additional name (or regex) that maps to the same vhost.

```kdl
vhost "example.com" {
    alias "www.example.com"
    alias #".+\.example\.com"# regex=#true
}
```

### alpn (vhost)

**Repeated child** of [`vhost`](#vhost).  Optional.

Same shape as the listener-level [`alpn`](#alpn).  Per-vhost ALPN
overrides the listener default during ClientHello dispatch.
TCP/TLS only.

### location

**Child** of [`vhost`](#vhost).  Optional, repeatable.

Matches a URL path prefix and runs a handler (one of
[`static`](#static), [`proxy`](#proxy-handler),
[`redirect`](#redirect), [`respond`](#respond),
[`fastcgi`](#fastcgi), [`scgi`](#scgi),
[`cgi`](#cgi), [`status`](#status), [`auth-request`](#auth-request)).
Locations are matched by longest-prefix; the longest matching
prefix among the vhost's locations wins.

Locations can also carry policies, header rules, rate limits,
request matchers, and URL rewrites.  Exactly one handler is
required per location.

```kdl
location "/api/" {
    proxy { upstream "http://backend.internal:9000" }
}
```

#### max-request-body (location)

**Property** on [`location`](#location).  Optional integer.

Per-location override of the listener-level
[`max-request-body`](#max-request-body).  Tightens the cap for one
location (typically a `/login` endpoint or similar).  Cannot relax
the listener cap, since the listener cap is enforced before
routing.

#### policy (location)

**Guide:** [Access policies](guide.md#access-policies).

**Child** of [`location`](#location).  Optional.

Access-control rules evaluated before the handler runs.
Statements run top-to-bottom; the first match decides the outcome.
A `policy` block with no matching rule returns `403`.

```kdl
location "/admin/" {
    policy {
        allow address "10.0.0.0/8" "192.168.0.0/16"
        allow user "alice" "bob"
        deny code=403
    }
    static root="/var/www/admin"
}
```

##### Statements

Each statement is one of:

- `allow [<predicate>]` — permit the request.
- `deny [code=<integer>] [<predicate>]` — reject with the given
  status (default `403`).
- `redirect to=<url> [code=<integer>] [<predicate>]` — 30x
  redirect (default `302`).
- `apply "<name>"` — splice the rules of a server-level named
  [`policy`](#policy-server) at this point.  First-match semantics
  continue across the inlined rules.  Cycles are rejected at
  startup.

A statement with no predicate is unconditional — it matches every
request, useful as a catch-all at the end of a block.

##### Predicates

A statement may carry an inline predicate, a child block, or
nothing at all.

Predicate types:

- `address "<cidr-or-ip>"+` — source IP or CIDR; multiple values
  are OR-combined.
- `country "<iso2>"+` — ISO 3166-1 alpha-2 country code; requires
  [`geoip`](#geoip).
- `user "<name>"+` — authenticated username; requires an
  [`auth`](#auth) backend.
- `group "<name>"+` — authenticated group membership.
- `authenticated` — any authenticated request.
- `not <pred-type> <values>*` — negation of the inner predicate.

Inline form (one statement, one predicate):

```kdl
allow address "10.0.0.0/8" "192.168.0.0/16"
deny country "RU" "CN"
allow authenticated
```

Block form (multiple predicates AND-evaluated):

```kdl
allow {
    address "10.0.0.0/8"
    user "alice" "bob"
}
```

Auth predicates (`authenticated`, `user`, `group`) automatically
return `401` for anonymous users — no explicit `deny code=401`
needed.  Wrapping them in `not` suppresses the auto-challenge.

#### basic-auth

**Guide:** [HTTP Basic auth](guide.md#http-basic-auth--htpasswd-file).

**Child** of [`location`](#location).  Optional.

Sends a `401 Unauthorized` + `WWW-Authenticate: Basic
realm="..."` challenge when the request does not carry valid
Basic credentials for the server-level [`auth`](#auth) backend.
The same authentication then feeds the location's
[`policy`](#policy-location); use both together to require login
*and* gate on group membership.

```kdl
location "/admin/" {
    basic-auth realm="Admin Area"
    policy { allow group "admin"; deny code=403 }
    static root="/var/www/admin"
}
```

##### realm

**Property** on [`basic-auth`](#basic-auth).  Optional string.

**Default:** `"Restricted"`.

#### request-headers

**Child** of [`location`](#location).  Optional.

Modifies the request headers passed to the handler (notably the
upstream of a [`proxy`](#proxy-handler) or
[`fastcgi`](#fastcgi)).  Operations execute top-to-bottom.

```kdl
location "/api/" {
    request-headers {
        set "X-Real-IP" "{client_ip}"
        add "X-Forwarded-For" "{client_ip}"
        remove "X-Internal-Debug"
    }
    proxy { upstream "http://backend:9000" }
}
```

Template variables available inside `set` / `add` values:

| Variable        | Substitution                                       |
|-----------------|----------------------------------------------------|
| `{client_ip}`   | Peer address (post-PROXY-protocol).                |
| `{user}`        | Authenticated username, or empty.                  |
| `{request_id}`  | Per-request UUIDv4 generated by hypershunt.             |

##### set (request-headers)

**Child** of [`request-headers`](#request-headers) and
[`response-headers`](#response-headers).

Two positional arguments: header name, value.  Replaces every
existing instance of that header.

##### add (request-headers)

**Child** of [`request-headers`](#request-headers) and
[`response-headers`](#response-headers).

Two positional arguments: header name, value.  Appends a new
header without touching existing ones.

##### remove (request-headers)

**Child** of [`request-headers`](#request-headers) and
[`response-headers`](#response-headers).

One positional argument: header name.  Removes every instance.

#### response-headers

**Child** of [`location`](#location).  Optional.

Same grammar as [`request-headers`](#request-headers), but applied
to outgoing responses.  Useful for adding strict security
headers (CSP, HSTS, X-Content-Type-Options) to every response
served from a location.

```kdl
response-headers {
    set "Strict-Transport-Security" "max-age=63072000; includeSubDomains; preload"
    set "Content-Security-Policy" "default-src 'self'"
    set "X-Content-Type-Options" "nosniff"
}
```

#### rate-limit

**Guide:** [Rate limiting](guide.md#rate-limiting).

**Child** of [`location`](#location).  Optional, repeatable.

Token-bucket rate limiter.  Multiple `rate-limit` blocks stack
AND-style: a request must satisfy every limiter to pass.  When a
limiter denies the request, hypershunt returns `429 Too Many Requests`
with a `Retry-After` header set to the seconds until the bucket
would next admit one request.

```kdl
location "/login/" {
    rate-limit rate=5 per="minute" burst=10 { key "client-ip" }
    rate-limit rate=100 per="hour" burst=100 { key "user" }
    static root="/var/www/login"
}
```

##### rate

**Property** on [`rate-limit`](#rate-limit).  Required integer.

Number of requests admitted per [`per`](#per) window in steady
state.

##### per

**Property** on [`rate-limit`](#rate-limit).  Optional string.

Window unit.  One of `"second"`, `"minute"`, `"hour"`.

**Default:** `"second"`.

##### burst

**Property** on [`rate-limit`](#rate-limit).  Optional integer.

Bucket capacity — maximum number of requests that can arrive
back-to-back without being rate-limited, before the steady-state
[`rate`](#rate) kicks in.

**Default:** equal to [`rate`](#rate).

##### key

**Child** of [`rate-limit`](#rate-limit).  Required.

Names the bucketing dimension.  Single positional argument is one
of `"client-ip"`, `"user"`, or `"header"`.  When `"header"`, a
second positional argument names the HTTP header whose value is
the bucket key.

```kdl
rate-limit rate=10 per="second" { key "client-ip" }
rate-limit rate=10 per="second" { key "user" }
rate-limit rate=10 per="second" { key "header" "X-API-Key" }
```

Missing-header / anonymous-user requests share the `""` bucket.

##### name

**Property** on [`rate-limit`](#rate-limit).  Optional string.

Display name surfaced on the `/status` page.  When unset, hypershunt
synthesises one from the location path and the limiter's
declaration order (`<loc>-rl-<idx>`).

#### match

**Child** of [`location`](#location).  Optional.

Predicate that gates the location: when the predicate is false,
the router skips this location and continues with the next
shorter-prefix match.  Used to dispatch by method, header, query,
or path-regex without splitting locations.

Predicates inside the body are AND-evaluated.  At least one
predicate is required.

```kdl
location "/api/" {
    match {
        method "POST" "PUT"
        header "Content-Type" "application/json"
    }
    proxy { upstream "http://json-api:9000" }
}
```

##### method

**Child** of [`match`](#match).  One or more positional method
names.  OR within the list.

##### header (match)

**Child** of [`match`](#match).  Positional: header name, then one
or more accepted values.  A value prefixed with `~` is compiled
as an anchored regex; otherwise the value is matched literally.
OR across multiple values.

```kdl
match {
    header "Accept" "~text/html.*"
    header "X-Tenant" "internal"
}
```

##### header-absent

**Child** of [`match`](#match).  Single positional argument: a
header name.  Predicate is true when the header is absent.

##### query

**Child** of [`match`](#match).  Positional: query parameter name,
then one or more accepted values.  Same regex/literal semantics
as [`header`](#header-match).

##### path

**Child** of [`match`](#match).  One or more positional regex
patterns matched against the request URI path.  OR within the
list.  Patterns are evaluated **unanchored** — a pattern matches
anywhere in the path unless you write `^...$` yourself.  (Note
the contrast with regex [`vhost`](#vhost) patterns, which *are*
anchored automatically.)

##### not (match)

**Child** of [`match`](#match).  Negates the AND of its inner
predicates.

#### rewrite

**Child** of [`location`](#location).  Optional.

Rewrites the request URI and re-routes the request through the
vhost.  Up to ten consecutive rewrites are allowed per request
(cycle detection); the eleventh returns `404`.

```kdl
location "/old/" {
    rewrite from="^/old/(.*)$" to="/new/$1"
    static root="/never"          // placeholder; rewrite fires first
}
```

##### from

**Property** on [`rewrite`](#rewrite).  Required string.

PCRE regex matched against the request URI path.  The regex is
compiled at parse time — malformed patterns fail config load.

##### to

**Property** on [`rewrite`](#rewrite).  Required string.

Replacement template, with `$1`, `$2`, ... capture-group
back-references.  Undefined captures expand to the empty string.

#### static

**Guide:** [Serving static files](guide.md#serving-static-files).

**Handler** child of [`location`](#location).  Serves static files.

Either [`root=`](#root-static) (filesystem mode) or
[`userdir=`](#userdir) (per-user mode) is required; setting both
is an error.  In filesystem mode hypershunt serves files under
[`root=`](#root-static); requests with directory paths fall back
to [`index-file`](#index-file) lookups or, when no index matches,
[`try-files`](#try-files) candidates, then a directory listing
(only when [`directory-listing=#true`](#directory-listing)), then
`404`.

Streams the file body in 64 KB chunks; supports `Range` and
conditional `If-None-Match` (via ETag).

```kdl
location "/" {
    static root="/var/www/site" strip-prefix=#false {
        index-file "index.html"
        index-file "index.htm"
    }
}
```

##### root (static)

**Property** on [`static`](#static).  Required (unless
[`userdir=`](#userdir) is set).

Filesystem root for served files.

##### userdir

**Property** on [`static`](#static).  Required (unless
[`root=`](#root-static) is set).

Activates per-user mode.  The first path component after the
matched prefix is treated as `~user`; hypershunt resolves the user's
home directory and serves files from `<home>/<userdir>/...`.
Only users with UID >= [`userdir-min-uid`](#userdir-min-uid)
participate; an optional [`userdir-allowlist`](#userdir-allowlist)
restricts further.

```kdl
location "/~" {
    static userdir="public_html" userdir-min-uid=1000 {
        userdir-allowlist "alice"
        userdir-allowlist "bob"
    }
}
```

##### userdir-allowlist

**Repeated child** of [`static`](#static).  Optional.

Limits per-user mode to the listed usernames.  Unset means "any
user satisfying [`userdir-min-uid`](#userdir-min-uid)".

##### userdir-min-uid

**Property** on [`static`](#static).  Optional integer.

Minimum POSIX UID eligible for per-user serving.  Defends against
accidentally exposing system accounts.

**Default:** `1000`.

##### strip-prefix (static)

**Property** on [`static`](#static).  Optional boolean.

When `#true`, the matched location prefix is stripped before
joining the request path with [`root=`](#root-static).  Useful
when the URL prefix doesn't exist on disk (e.g. a location at
`/assets/` serving from `/var/www/static/`).

**Default:** `#false`.

##### directory-listing

**Property** on [`static`](#static).  Optional boolean.

When `#true`, requests whose resolved path is a directory and
whose index-file lookup misses produce an HTML listing.  When
`#false` (default), the same case returns `404`.

**Default:** `#false`.

##### index-file

**Repeated child** of [`static`](#static).  Optional.

Filenames tried, in order, when the resolved path is a directory.

**Default:** `["index.html", "index.htm"]`.

##### try-files

**Repeated child** of [`static`](#static).  Optional.

Ordered list of candidate filename templates.  Each template may
contain `{path}` (the request path with the location prefix
stripped) and `{query}` (the query string).  The first existing
regular file is served.  When no candidate exists, the response
is `404` — the [`index-file`](#index-file) flow is bypassed.
Useful for SPA-style fallbacks.

```kdl
static root="/var/www/spa" {
    try-files "{path}"
    try-files "/index.html"
}
```

##### fallback-redirect

**Property** on [`static`](#static).  Optional string.

When set and a request resolves to a directory with no matching
[`index-file`](#index-file) or [`try-files`](#try-files) candidate
*and* [`directory-listing`](#directory-listing) is `#false`, the
handler emits a `302 Found` to the named URL with
`Cache-Control: no-store` instead of a `404`.  Requests to
non-existent paths still produce `404` — only the "directory
with no index" case is redirected.

The packaged default config uses this to point `/` at `/docs/`
while the operator's webroot is empty; the moment an
`index.html` appears in the webroot the redirect stops firing.

```kdl
static root="/var/www/hypershunt" fallback-redirect="/docs/" {
    index-file "index.html"
}
```

**Default:** unset (no fallback; `404` as usual).

#### proxy (handler)

**Guide:** [Reverse proxy](guide.md#reverse-proxy),
[Load balancing](guide.md#load-balancing).

**Handler** child of [`location`](#location).  Reverse-proxies the
request to one or more HTTP(S) upstreams.

At least one [`upstream`](#upstream) child is required.  All
upstreams in the pool serve traffic according to the chosen
[`lb-policy`](#lb-policy); active or passive health checks can
take individual upstreams in and out of rotation.

```kdl
location "/api/" {
    proxy strip-prefix=#true {
        upstream "http://api1.internal:9000" weight=2
        upstream "http://api2.internal:9000" weight=1
        lb-policy "least-conn"
        active-health path="/healthz" interval=10
        retry max=2 { on-status 502; on-status 503 }
    }
}
```

Handler-mode `proxy` carries:

- Scalar properties: `strip-prefix=`,
  [`proxy-protocol=`](#proxy-protocol), [`scheme=`](#scheme),
  [`pool-idle-timeout=`](#pool-idle-timeout),
  [`pool-max-idle=`](#pool-max-idle),
  [`connect-timeout=`](#connect-timeout).
- Children: [`upstream`](#upstream), [`tls`](#tls-proxy-upstream),
  [`lb-policy`](#lb-policy), [`active-health`](#active-health),
  [`passive-health`](#passive-health), [`retry`](#retry).

##### upstream

**Repeated child** of [`proxy`](#proxy-handler).  Required, at
least one.

Single positional argument: the upstream URL.  Scheme is one of
`http://`, `https://`, or `unix-stream:/path` (a Unix-stream
upstream is reached via `http://localhost` over the socket,
regardless of the path used).  Optional `weight=<integer>`
property; `0` parks the upstream (it stays in the pool but
receives no traffic until the weight is raised).

```kdl
upstream "http://backend.internal:9000"
upstream "http://backup.internal:9000" weight=0
```

##### strip-prefix (proxy)

**Property** on [`proxy`](#proxy-handler).  Optional boolean.

When `#true`, the matched location prefix is stripped from the
request URI before forwarding.

**Default:** `#false`.

##### scheme

**Property** on [`proxy`](#proxy-handler).  Optional string.

Forces a particular wire protocol to the upstream.  One of:

- `"auto"` (default) — the hyper-util client negotiates HTTP/1.1
  vs HTTP/2 via ALPN.
- `"h2c"` — HTTP/2 prior-knowledge over plaintext.  Requires
  `http://` upstreams.  Used by the cross-protocol WebSocket
  bridge.
- `"h3"` (alias `"http3"`) — HTTP/3 over QUIC.  Requires
  `https://` upstreams.

##### pool-idle-timeout

**Property** on [`proxy`](#proxy-handler).  Optional integer.

Seconds a cached upstream connection sits idle before the reaper
closes it.  `0` disables reuse entirely.

**Default:** `90`.

##### pool-max-idle

**Property** on [`proxy`](#proxy-handler).  Optional integer.

Cap on idle upstream connections per host.  HTTP/1.1 and HTTP/2
only.

##### connect-timeout

**Property** on [`proxy`](#proxy-handler).  Optional integer.

Per-attempt TCP connect timeout (seconds).

##### tls (proxy upstream)

**Child** of [`proxy`](#proxy-handler).  Optional.

Per-pool TLS knobs.  Only meaningful when at least one upstream
is `https://`.  Single property: `skip-verify=` (boolean;
default `#false`) disables certificate verification.

##### lb-policy

**Child** of [`proxy`](#proxy-handler).  Optional.

Selects the load-balancing algorithm.  Single positional argument:

- `"round-robin"` (default)
- `"least-conn"` — pick the upstream with the fewest in-flight
  requests.
- `"random"`
- `"ip-hash"` — hash the client IP; the same client always lands
  on the same upstream (as long as the pool doesn't change).
- `"header-hash"` — hash a named request header (the
  `header=<name>` property is required); useful for session
  affinity by `Cookie` or `X-Session-Id`.

```kdl
lb-policy "header-hash" header="X-Session-Id"
```

##### active-health

**Child** of [`proxy`](#proxy-handler).  Optional.

Spawns a background task that probes each upstream and flips its
`healthy` flag.  All knobs are properties.

```kdl
active-health path="/healthz" interval=10 timeout=2 \
    expect-status=200 unhealthy-after=3 healthy-after=2
```

###### path

**Property** on [`active-health`](#active-health).  Optional
string.

**Default:** `"/"`.

###### interval

**Property** on [`active-health`](#active-health).  Optional
integer.

Probe interval (seconds).  `0` disables the task.

**Default:** `10`.

###### timeout (active-health)

**Property** on [`active-health`](#active-health).  Optional
integer.

Per-probe timeout (seconds).

**Default:** `2`.

###### expect-status

**Property** on [`active-health`](#active-health).  Optional
integer.

HTTP status code that counts as a successful probe.

**Default:** `200`.

###### unhealthy-after

**Property** on [`active-health`](#active-health).  Optional
integer.

Consecutive failures before an upstream is marked unhealthy.

**Default:** `2`.

###### healthy-after

**Property** on [`active-health`](#active-health).  Optional
integer.

Consecutive successes before a previously-unhealthy upstream is
restored.

**Default:** `1`.

##### passive-health

**Child** of [`proxy`](#proxy-handler).  Optional.

Ejects upstreams that fail real requests, no probing required.

```kdl
passive-health eject-after=5 eject-for=30
```

###### eject-after

**Property** on [`passive-health`](#passive-health).  Optional
integer.

Consecutive request failures before the upstream is ejected.

**Default:** `4294967295` (i.e. never — you must opt in).

###### eject-for

**Property** on [`passive-health`](#passive-health).  Optional
integer.

Ejection duration (seconds).  After this window the upstream
re-enters rotation.

**Default:** `30`.

##### retry

**Child** of [`proxy`](#proxy-handler).  Optional.

Retries failed requests up to [`max`](#max-retry) additional
attempts.

```kdl
retry max=3 {
    on-status 502
    on-status 503
    on-status 504
}
```

When `max > 0`, hypershunt buffers the request body in memory so it
can be replayed across attempts — bear that in mind for large
uploads.

###### max (retry)

**Property** on [`retry`](#retry).  Optional integer.

Maximum number of *additional* attempts after the first failure.
`0` (the default) disables retries and avoids the body-buffering
cost.

###### on-status

**Repeated child** of [`retry`](#retry).  Required when
[`max`](#max-retry) > 0.

HTTP status code that triggers a retry.  Listing the codes
explicitly avoids accidentally retrying non-idempotent responses
like `409` or `422`.

#### redirect

**Handler** child of [`location`](#location).  Returns a 30x
redirect.

```kdl
location "/old/" {
    redirect to="/new/" code=301
}
```

##### to (redirect)

**Property** on [`redirect`](#redirect).  Required string.

Target URL.  Supports the same template variables as
[`request-headers`](#request-headers) `set`, plus `{host}` (the
request's `Host` header) and `{path_and_query}` (the request URI
path with the original query string).

```kdl
redirect to="https://{host}{path_and_query}" code=301
```

##### code (redirect)

**Property** on [`redirect`](#redirect).  Optional integer.

HTTP status code.

**Default:** `301`.

#### respond

**Handler** child of [`location`](#location).  Returns a fixed,
inline (or file-backed) static response: a status code, an optional
body, and an optional `Content-Type`.  Useful for health/ack
endpoints, maintenance pages, fixed tokens, custom block messages,
and small stubs.  Composes with the location's
[`response-headers`](#response-headers).

```kdl
location "/health"  { respond status=200 body="OK\n" }
location "/ping"    { respond status=204 }
location "/blocked" { respond status=403 body="denied" content-type="text/plain" }
location "/maint"   { respond status=503 file="maint.html" content-type="text/html" }
location "/whoami"  { respond status=200 body="{client_ip} -> {host}{path}\n" }
```

##### status (respond)

**Property** on [`respond`](#respond).  Optional integer (100–599).

HTTP status code.

**Default:** `200`.

##### body (respond)

**Property** on [`respond`](#respond).  Optional string.  Mutually
exclusive with [`file`](#file-respond).

Inline response body.  Supports the same template variables as
[`redirect`](#to-redirect) `to` (e.g. `{host}`, `{path}`,
`{client_ip}`).

When neither `body` nor `file` is given, the response has an empty
body (`Content-Length: 0`).

##### file (respond)

**Property** on [`respond`](#respond).  Optional string.  Mutually
exclusive with [`body`](#body-respond).

Path to a file whose contents form the response body.  The file is
read on each request, so edits take effect without a reload.  A
**relative path resolves against the directory of the config file**
(not the process working directory).  A missing or unreadable file
yields `500`.  File bodies are emitted verbatim (no templating).

##### content-type (respond)

**Property** on [`respond`](#respond).  Optional string.

`Content-Type` for the response.  **Default:** `text/plain;
charset=utf-8` when a body is present (no default for an empty body).
A [`response-headers`](#response-headers) `set "Content-Type" …`
rule overrides it.

#### fastcgi

**Guide:** [CGI, FastCGI, SCGI](guide.md#cgi-fastcgi-scgi).

**Handler** child of [`location`](#location).  Forwards to a
FastCGI backend.  Speaks the binary FastCGI protocol over a
Unix-stream or TCP socket.

```kdl
location "/php/" {
    fastcgi socket="unix-stream:/run/php-fpm.sock" \
        root="/var/www/example" \
        index="index.php"
}
```

##### socket (fastcgi)

**Property** on [`fastcgi`](#fastcgi) and [`scgi`](#scgi).
Required string.

FastCGI/SCGI backend address.  Use
`unix-stream:<absolute-path>` for a Unix socket or `host:port`
for TCP.

##### root (fastcgi)

**Property** on [`fastcgi`](#fastcgi) and [`scgi`](#scgi).
Required string.

`DOCUMENT_ROOT` passed to the backend.  Hypershunt also synthesises
`SCRIPT_FILENAME` from `root` + the request path.

##### index (fastcgi)

**Property** on [`fastcgi`](#fastcgi) and [`scgi`](#scgi).
Optional string.

Filename appended to directory requests before `SCRIPT_FILENAME`
is computed (e.g. `"index.php"`).

#### scgi

**Handler** child of [`location`](#location).  Forwards to an
SCGI backend.  Same property set as [`fastcgi`](#fastcgi); the
only difference is wire protocol.

```kdl
location "/" {
    scgi socket="unix-stream:/run/myapp.sock" \
         root="/var/www/myapp" \
         index="dispatch.py"
}
```

#### cgi

**Handler** child of [`location`](#location).  Unix only.

Forks a per-request CGI process from the directory named by
[`root=`](#root-cgi).  The path component after the location
prefix selects the executable; arguments after the executable
become the script's argv tail.  Hypershunt sets the standard CGI/1.1
environment variables and pipes the request body to the child's
stdin.

```kdl
location "/cgi-bin/" { cgi root="/var/www/cgi-bin" }
```

##### root (cgi)

**Property** on [`cgi`](#cgi).  Required string.

Filesystem directory whose direct children are eligible CGI
programs.  Hypershunt refuses to execute anything outside this
directory.

#### status

**Handler** child of [`location`](#location).  No properties or
children.

Renders the built-in status page: load averages, per-route
request and latency counters, active rate-limit buckets, listener
summary, certificate status.  Responds with HTML by default; an
`Accept: application/json` header switches to JSON.

```kdl
location "/.hypershunt/status" {
    policy { allow address "10.0.0.0/8"; deny code=403 }
    status
}
```

The status endpoint exposes operational detail — gate it behind
a policy in production.

#### auth-request

**Handler** child of [`location`](#location).  No properties or
children.

Server side of the subrequest-auth pattern.  Returns `200 OK`
with the authenticated identity exposed as `X-Auth-User` and
`X-Auth-Groups` headers.  Useful as the URL referenced by an
[`auth "subrequest"`](#auth-subrequest) backend running on a
peer hypershunt instance.

Access enforcement (401/403) happens before the handler runs, so
the handler only fires when access is allowed.  Combine with a
[`policy`](#policy-location) block to gate which authenticated
identities a subrequest peer can ask about.

```kdl
vhost "auth.internal" {
    location "/check" {
        policy { allow address "10.0.0.0/8"; deny code=403 }
        basic-auth realm="Internal"
        auth-request
    }
}
```
