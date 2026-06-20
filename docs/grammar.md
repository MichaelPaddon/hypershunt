# hypershunt config grammar

Formal grammar for `hypershunt.kdl`.  This document describes **syntax
only**.  See the [Configuration reference](reference.md) for
defaults, semantics, validation rules, and worked examples.

Each named production below is a heading.  Nonterminals and the
abstract terminal types ([`<string>`](#string),
[`<integer>`](#integer), [`<boolean>`](#boolean),
[`<bind-url>`](#bind-url), [`<host>`](#host)) link to their
definition.

## Design rules

This grammar follows five canonical rules.  They make the syntax
predictable: a reader who learns the rules can guess the shape of
nodes they haven't seen.

1. **Positional argument = identity.**  Used only when the value
   is the node's primary "what" — something a reader can spot by
   position without a label.  Examples: `vhost "example.com"`,
   `location "/api"`, `error-page 404`, `auth "pam"`.
2. **Property = attribute.**  Everything else uses `key=value`
   property syntax.  A given attribute has exactly one home — it
   is *never* also accepted as a positional or a child.
3. **Child = structured subtree.**  A child node is used only
   when the thing has its own arguments or properties.  A child
   whose body is a single scalar value is a smell — promote it
   to a property on the parent.
4. **Lists = repeated single-arg children.**  When a node accepts
   a list of values, the list appears as repeated children with
   one positional argument each (`domain "a.example"; domain
   "b.example"`), never as a variadic argument list on one node.
   The single exception is predicate value-sets (`match` /
   `policy` predicates), where the variadic shape is the
   predicate's content.
5. **Bool toggle = property, or presence.**  A boolean knob
   either appears as `key=#true|#false`, or as a bare node whose
   presence is the toggle.  Block forms wrapping a single bool
   are not used.

## Notation

hypershunt uses [KDL v2](https://kdl.dev) as its configuration
language.  KDL distinguishes positional arguments (bare values),
named properties (`key=value`), and child blocks (`{ ... }`); the
grammar below shows each explicitly.

Operators:

- `x?` — `x` is optional
- `x*` — zero or more repetitions of `x`
- `x+` — one or more repetitions of `x`
- `x | y` — either `x` or `y`
- `( ... )` — grouping
- `{ ... }` — KDL child block
- `key=value` — a KDL named property
- `"literal"` — literal KDL string or node name

### `<string>`

Any KDL string.

### `<integer>`

A KDL integer.

### `<boolean>`

`#true` or `#false`.

---

## Top-level

A configuration file is a sequence of top-level nodes.

### `config`

[`<server>`](#server)? ( [`<listener>`](#listener) |
[`<certificate>`](#certificate) )+ [`<vhost>`](#vhost)*

### `server`

`"server"` [`<server-prop>`](#server-prop)* ( `{`
[`<server-child>`](#server-child)* `}` )?

### `listener`

See [`listener`](#listener-1) below for the full shape including
properties and children.

### `certificate`

`"certificate"` [`<string>`](#string) `{` [`<tls-node>`](#tls-node)
`}`

### `vhost`

`"vhost"` [`<string>`](#string)
[`<vhost-prop>`](#vhost-prop)* `{`
[`<vhost-child>`](#vhost-child)* `}`

### `vhost-prop`

- `regex=`[`<boolean>`](#boolean)
- `name=`[`<string>`](#string)
- `explicit-only=`[`<boolean>`](#boolean)

`name` is the reference handle a listener `vhost` list uses; it
defaults to the host pattern (the positional argument).
`explicit-only` keeps the vhost out of a listener's implicit set.

---

## `<bind-url>`

A listener bind address is a URL whose scheme selects the socket
family.

- `"tcp://"` [`<host>`](#host) `":"` [`<integer>`](#integer)
- `"udp://"` [`<host>`](#host) `":"` [`<integer>`](#integer)
- `"unix-stream:"` [`<string>`](#string)
- `"unix-dgram:"` [`<string>`](#string)
- `"unix-seqpacket:"` [`<string>`](#string)

### `<host>`

A [`<string>`](#string) holding a hostname, IPv4 literal, or
bracketed IPv6 literal (`[::1]`).

Examples:

    "tcp://0.0.0.0:80"
    "tcp://[::]:443"
    "udp://[::]:443"
    "unix-stream:/run/hypershunt.sock"
    "unix-dgram:/run/hypershunt.dgram"
    "unix-seqpacket:/run/hypershunt.seq"

---

## server

### `server-prop`

- `state-dir=`[`<string>`](#string)
- `user=`[`<string>`](#string)
- `group=`[`<string>`](#string)
- `inherit-supplementary-groups=`[`<boolean>`](#boolean)
- `graceful-drain-timeout=`[`<integer>`](#integer)
- `upgrade-startup-timeout=`[`<integer>`](#integer)
- `lame-duck-timeout=`[`<integer>`](#integer)
- `cert-key-mode=`[`<string>`](#string)

### `server-child`

- [`<tls-options-block>`](#tls-options-block)
- [`<auth-backend>`](#auth-backend)
- `"geoip"` `db=`[`<string>`](#string)
- `"health"` ( `enabled=`[`<boolean>`](#boolean) )? ( `{`
  [`<health-child>`](#health-child)* `}` )?
- [`<policy-def>`](#policy-def)
- [`<error-page-def>`](#error-page-def)
- [`<access-log-block>`](#access-log-block)

### `health-child`

- `"liveness-path"` [`<string>`](#string)
- `"readiness-path"` [`<string>`](#string)

Both are repeating single-argument children (rule 4); each overrides
its default path set when present.

### `tls-options-block`

`"tls-options"` [`<tls-option-prop>`](#tls-option-prop)* ( `{`
[`<tls-option-child>`](#tls-option-child)* `}` )?

The same property and child surface is also valid directly on a
listener-level [`<tls-node>`](#tls-node).

### `tls-option-prop`

- `min-version=`( `"1.2"` | `"1.3"` )
- `ocsp=`[`<boolean>`](#boolean)
- `ocsp-timeout=`[`<integer>`](#integer)
- `ocsp-min-refresh=`[`<integer>`](#integer)
- `ocsp-failure-backoff=`[`<integer>`](#integer)

### `tls-option-child`

- `"cipher"` [`<string>`](#string)
- [`<mtls-block>`](#mtls-block)

`cipher` is a repeating single-argument child (rule 4).

`cipher` is a repeating single-argument child (rule 4).

### `mtls-block`

`"mtls"` `{` [`<mtls-child>`](#mtls-child)* `}`

### `mtls-child`

- `"ca"` [`<string>`](#string)
- `"revocation"` [`<string>`](#string)
- `"mode"` ( `"required"` | `"optional"` )
- `"refresh"` [`<integer>`](#integer)

`ca` and `revocation` are repeating single-argument children
(rule 4).  `mode` and `refresh` are at most one each.

### `policy-def`

`"policy"` [`<string>`](#string) `{`
[`<policy-statement>`](#policy-statement)* `}`

### `error-page-def`

- `"error-page"` [`<integer>`](#integer) `path=`[`<string>`](#string)
- `"error-page"` [`<integer>`](#integer) `html=`[`<string>`](#string)

### `access-log-block`

`"access-log"` [`<access-log-format>`](#access-log-format) (
`path=`[`<string>`](#string) )?

### `access-log-format`

`"tracing"` | `"json"` | `"common"` | `"combined"`

---

## auth

### `auth-backend`

- `"auth"` `"pam"` ( `service=`[`<string>`](#string) )?
- `"auth"` `"ldap"` `url=`[`<string>`](#string)
  `bind-dn=`[`<string>`](#string) `base-dn=`[`<string>`](#string)
  ( `group-filter=`[`<string>`](#string) )?
  ( `group-attr=`[`<string>`](#string) )?
  ( `starttls=`[`<boolean>`](#boolean) )?
  ( `timeout=`[`<integer>`](#integer) )?
- `"auth"` `"file"` `path=`[`<string>`](#string)
  ( `cache=`[`<integer>`](#integer) )?
- `"auth"` `"subrequest"` `url=`[`<string>`](#string)
  ( `user-header=`[`<string>`](#string) )?
  ( `groups-header=`[`<string>`](#string) )?
  ( `timeout=`[`<integer>`](#integer) )?
  `{` [`<subrequest-child>`](#subrequest-child)* `}`
- `"auth"` `"jwt"`
  ( `cookie-name=`[`<string>`](#string) )?
  ( `validity=`[`<integer>`](#integer) )?
  ( `backend=`[`<jwt-backend-kind>`](#jwt-backend-kind)
  [`<jwt-inner-prop>`](#jwt-inner-prop)* )?
  ( `{` [`<jwt-inner-child>`](#jwt-inner-child)* `}` )?

### `subrequest-child`

- `"forward-header"` [`<string>`](#string)

Repeating single-argument child (rule 4).

### `jwt-backend-kind`

`"pam"` | `"ldap"` | `"file"` | `"subrequest"` | `"oidc"`

When `auth "jwt"` has a `backend=` property, the inner backend's
properties appear on the same `auth` node with a kind prefix, and
the inner backend's repeating children appear in the `auth`
node's body with the same prefix.  Names follow rule 2 ("one
home"): each property maps 1:1 to its standalone counterpart.

### `jwt-inner-prop`

The full set of properties valid on `auth "jwt"` when `backend=`
is set is the union of JWT's own properties (`cookie-name`,
`validity`, `backend`) plus the chosen inner backend's properties,
prefixed.

- `pam-service=`[`<string>`](#string)
- `ldap-url=`[`<string>`](#string),
  `ldap-bind-dn=`[`<string>`](#string),
  `ldap-base-dn=`[`<string>`](#string),
  `ldap-group-filter=`[`<string>`](#string),
  `ldap-group-attr=`[`<string>`](#string),
  `ldap-starttls=`[`<boolean>`](#boolean),
  `ldap-timeout=`[`<integer>`](#integer)
- `file-path=`[`<string>`](#string),
  `file-cache=`[`<integer>`](#integer)
- `subrequest-url=`[`<string>`](#string),
  `subrequest-user-header=`[`<string>`](#string),
  `subrequest-groups-header=`[`<string>`](#string),
  `subrequest-timeout=`[`<integer>`](#integer)
- `oidc-issuer=`[`<string>`](#string),
  `oidc-client-id=`[`<string>`](#string),
  `oidc-client-secret=`[`<string>`](#string),
  `oidc-client-secret-file=`[`<string>`](#string),
  `oidc-redirect-uri=`[`<string>`](#string),
  `oidc-username-claim=`[`<string>`](#string),
  `oidc-groups-claim=`[`<string>`](#string),
  `oidc-login-path=`[`<string>`](#string),
  `oidc-callback-path=`[`<string>`](#string),
  `oidc-state-ttl=`[`<integer>`](#integer),
  `oidc-refresh=`[`<boolean>`](#boolean),
  `oidc-refresh-ttl=`[`<integer>`](#integer),
  `oidc-refresh-cookie=`[`<string>`](#string),
  `oidc-logout-path=`[`<string>`](#string),
  `oidc-post-logout-uri=`[`<string>`](#string),
  `oidc-idp-logout=`[`<boolean>`](#boolean),
  `oidc-userinfo=`[`<boolean>`](#boolean),
  `oidc-discovery-refresh=`[`<integer>`](#integer),
  `oidc-discovery-retry=`[`<boolean>`](#boolean),
  `oidc-backchannel-logout=`[`<boolean>`](#boolean),
  `oidc-backchannel-logout-path=`[`<string>`](#string),
  `oidc-backchannel-max-iat-skew=`[`<integer>`](#integer),
  `oidc-backchannel-jti-ttl=`[`<integer>`](#integer),
  `oidc-bearer=`[`<boolean>`](#boolean),
  `oidc-bearer-cache-size=`[`<integer>`](#integer),
  `oidc-revoke-on-logout=`[`<boolean>`](#boolean),
  `oidc-require-iss=`[`<boolean>`](#boolean)

### `jwt-inner-child`

Prefixed children for repeating values of the wrapped backend:

- `"subrequest-forward-header"` [`<string>`](#string)
- `"oidc-scope"` [`<string>`](#string)
- `"oidc-bearer-audience"` [`<string>`](#string)
- `"oidc-resource"` [`<string>`](#string)

---

## listener

### `listener`

`"listener"` [`<bind-url>`](#bind-url)
[`<listener-prop>`](#listener-prop)* `{`
[`<listener-child>`](#listener-child)* `}`

### `listener-prop`

- `accept-proxy-protocol=`( `"v1"` | `"v2"` )
- `reject-unknown-host=`[`<boolean>`](#boolean)
- `health=`[`<boolean>`](#boolean)
- `max-connections=`[`<integer>`](#integer)
- `max-request-body=`[`<integer>`](#integer)

### `listener-child`

- `"trusted-proxies"` [`<string>`](#string)
- `"vhost"` [`<string>`](#string)+
- [`<tls-node>`](#tls-node)
- `"alpn"` [`<string>`](#string)
- [`<quic-transport-block>`](#quic-transport-block)
- `"proxy"` [`<bind-url>`](#bind-url) ( `{`
  [`<l4-proxy-opt>`](#l4-proxy-opt)* `}` )?
- [`<policy-block>`](#policy-block)
- [`<timeouts-block>`](#timeouts-block)

`trusted-proxies` and `alpn` are repeating single-argument
children (rule 4).  A `vhost` child is a *reference* (one or more
top-level vhost names) selecting which vhosts this listener serves;
it carries no block.  Multiple `vhost` children concatenate, in
order.  With no `vhost` child the listener serves every vhost not
marked `explicit-only`.  The first listed (or, implicitly, the
first declared) vhost is the listener's default; `reject-unknown-host`
suppresses that default so an unmatched Host yields `404`.

### `tls-node`

`"tls"` [`<tls-kind>`](#tls-kind)
[`<tls-kind-property>`](#tls-kind-property)* ( `{`
[`<tls-option-child>`](#tls-option-child)* `}` )?

On a byte-stream listener (`tcp://`, `unix-stream:`) a `tls` node
selects HTTPS; on a `udp://` listener it selects HTTP/3 (QUIC's
encryption layer *is* TLS 1.3, RFC 9001, so the same node serves
both).  On `udp://`, a `tls` node alongside a `proxy` child selects a
DTLS-terminating datagram proxy (reserved — not yet implemented).
`tls` is rejected on `unix-dgram:` / `unix-seqpacket:`.

### `tls-kind`

`"files"` | `"acme"` | `"self-signed"` | `"ref"`

### `tls-kind-property`

The properties valid on a `tls` node depend on the kind.

- `"files"`: `cert=`[`<string>`](#string) `key=`[`<string>`](#string)
- `"acme"`: `name=`[`<string>`](#string)?
  `email=`[`<string>`](#string)?
  `staging=`[`<boolean>`](#boolean)?
  `server=`[`<string>`](#string)?
  `retry-interval=`[`<integer>`](#integer)?
  `challenge=`( `"http-01"` | `"dns-01"` | `"tls-alpn-01"` )?
- `"self-signed"`: none
- `"ref"`: `name=`[`<string>`](#string) (names a top-level
  [`<certificate>`](#certificate))

Additionally for `"acme"` the body may contain repeating
`"domain"` [`<string>`](#string) children (rule 4) and at most one
[`<dns-provider-block>`](#dns-provider-block).

### `quic-transport-block`

`"quic-transport"` (
`max-concurrent-bidi-streams=`[`<integer>`](#integer) )?
( `max-idle-timeout=`[`<integer>`](#integer) )?
( `keep-alive-interval=`[`<integer>`](#integer) )?
( `zero-rtt=`[`<boolean>`](#boolean) )?
( `retry-tokens=`[`<boolean>`](#boolean) )?
( `retry-token-lifetime=`[`<integer>`](#integer) )?

### `dns-provider-block`

`"dns-provider"` ( `"acme-dns"` | `"cloudflare"` |
`"exec"` ) [`<dns-provider-property>`](#dns-provider-property)*
( `{` `"arg"` [`<string>`](#string) `}` )?

### `dns-provider-property`

Properties vary by provider kind.

- `"acme-dns"`: `api-url=`[`<string>`](#string)
  `username=`[`<string>`](#string)
  `password=`[`<string>`](#string)
  `subdomain=`[`<string>`](#string)
- `"cloudflare"`: `zone-id=`[`<string>`](#string)
  `api-token=`[`<string>`](#string)
- `"exec"`: `program=`[`<string>`](#string); the optional `arg`
  repeating child carries one positional string per argv element.

### `timeouts-block`

`"timeouts"` ( `request-header=`[`<integer>`](#integer) )?
( `handler=`[`<integer>`](#integer) )?
( `keepalive=`[`<integer>`](#integer) )?

The `proxy` node also carries the scalar attributes
`proxy-protocol=`( `"v1"` | `"v2"` ) and
`flow-idle-timeout=`[`<integer>`](#integer) as properties on the
`proxy` node itself.  The body holds only the structured children
listed in [`<l4-proxy-opt>`](#l4-proxy-opt).

### `l4-proxy-opt`

- `"tls"` ( `skip-verify=`[`<boolean>`](#boolean) )?
- `"dtls"` ( `skip-verify=`[`<boolean>`](#boolean) )?
- [`<policy-block>`](#policy-block)

---

## vhost

### `vhost-child`

- `"alias"` [`<string>`](#string) ( `regex=`[`<boolean>`](#boolean) )?
- `"alpn"` [`<string>`](#string)
- [`<location>`](#location)

`alpn` is a repeating single-argument child (rule 4).

---

## location

### `location`

`"location"` [`<string>`](#string)
( `max-request-body=`[`<integer>`](#integer) )? `{`
[`<location-child>`](#location-child)* `}`

### `location-child`

- [`<handler>`](#handler)
- [`<policy-block>`](#policy-block)
- [`<basic-auth-block>`](#basic-auth-block)
- [`<request-headers-block>`](#request-headers-block)
- [`<response-headers-block>`](#response-headers-block)
- [`<rate-limit-block>`](#rate-limit-block)
- [`<match-block>`](#match-block)
- [`<rewrite-directive>`](#rewrite-directive)

### `rate-limit-block`

`"rate-limit"` `rate=`[`<integer>`](#integer)
( `per=`( `"second"` | `"minute"` | `"hour"` ) )?
( `burst=`[`<integer>`](#integer) )?
( `name=`[`<string>`](#string) )?
`{` [`<rate-limit-key>`](#rate-limit-key) `}`

### `rate-limit-key`

- `"key"` `"client-ip"`
- `"key"` `"user"`
- `"key"` `"header"` [`<string>`](#string)

### `rewrite-directive`

`"rewrite"` `from=`[`<string>`](#string)
`to=`[`<string>`](#string)

### `match-block`

`"match"` `{` [`<match-predicate>`](#match-predicate)+ `}`

### `match-predicate`

- `"method"` [`<string>`](#string)+
- `"header"` [`<string>`](#string) [`<string>`](#string)+
- `"header-absent"` [`<string>`](#string)
- `"query"` [`<string>`](#string) [`<string>`](#string)+
- `"path"` [`<string>`](#string)+
- `"not"` `{` [`<match-predicate>`](#match-predicate)+ `}`

Match predicates use variadic positional arguments because the
value set IS the predicate's content (rule 4, exception clause).

---

## handlers

### `handler`

- [`<static-handler>`](#static-handler)
- [`<proxy-handler>`](#proxy-handler)
- [`<redirect-handler>`](#redirect-handler)
- [`<respond-handler>`](#respond-handler)
- [`<fastcgi-handler>`](#fastcgi-handler)
- [`<scgi-handler>`](#scgi-handler)
- [`<cgi-handler>`](#cgi-handler)
- `"status"`
- `"auth-request"`

### `static-handler`

`"static"` ( `root=`[`<string>`](#string) |
`userdir=`[`<string>`](#string) )
( `strip-prefix=`[`<boolean>`](#boolean) )?
( `directory-listing=`[`<boolean>`](#boolean) )?
( `fallback-redirect=`[`<string>`](#string) )?
( `userdir-min-uid=`[`<integer>`](#integer) )?
( `{` [`<static-child>`](#static-child)* `}` )?

### `static-child`

- `"userdir-allowlist"` [`<string>`](#string)
- `"index-file"` [`<string>`](#string)
- `"try-files"` [`<string>`](#string)

All repeating single-argument children (rule 4).

### `proxy-handler`

`"proxy"` ( `strip-prefix=`[`<boolean>`](#boolean) )?
( `proxy-protocol=`( `"v1"` | `"v2"` ) )?
( `scheme=`[`<proxy-scheme>`](#proxy-scheme) )?
( `pool-idle-timeout=`[`<integer>`](#integer) )?
( `pool-max-idle=`[`<integer>`](#integer) )?
( `connect-timeout=`[`<integer>`](#integer) )?
`{` [`<proxy-child>`](#proxy-child)+ `}`

### `proxy-scheme`

`"auto"` | `"h2c"` | `"h3"` | `"http3"`

### `proxy-child`

- `"upstream"` [`<string>`](#string)
  ( `weight=`[`<integer>`](#integer) )?
- `"tls"` ( `skip-verify=`[`<boolean>`](#boolean) )?
- `"lb-policy"` [`<lb-policy-kind>`](#lb-policy-kind)
  ( `header=`[`<string>`](#string) )?
- [`<active-health-block>`](#active-health-block)
- [`<passive-health-block>`](#passive-health-block)
- [`<retry-block>`](#retry-block)

`upstream` is the only required child (at least one).  It is a
repeating single-argument child (rule 4); `weight=` is an
optional per-upstream property.

### `lb-policy-kind`

`"round-robin"` | `"least-conn"` | `"random"` | `"ip-hash"` |
`"header-hash"`

### `active-health-block`

`"active-health"` ( `path=`[`<string>`](#string) )?
( `interval=`[`<integer>`](#integer) )?
( `timeout=`[`<integer>`](#integer) )?
( `expect-status=`[`<integer>`](#integer) )?
( `unhealthy-after=`[`<integer>`](#integer) )?
( `healthy-after=`[`<integer>`](#integer) )?

### `passive-health-block`

`"passive-health"` ( `eject-after=`[`<integer>`](#integer) )?
( `eject-for=`[`<integer>`](#integer) )?

### `retry-block`

`"retry"` ( `max=`[`<integer>`](#integer) )? `{`
( `"on-status"` [`<integer>`](#integer) )* `}`

`on-status` is a repeating single-argument child (rule 4).

### `redirect-handler`

`"redirect"` `to=`[`<string>`](#string)
( `code=`[`<integer>`](#integer) )?

### `respond-handler`

`"respond"` ( `status=`[`<integer>`](#integer) )?
( `body=`[`<string>`](#string) | `file=`[`<string>`](#string) )?
( `content-type=`[`<string>`](#string) )?

`status` defaults to `200` (range 100–599).  `body` and `file` are
mutually exclusive; with neither, the body is empty.

### `fastcgi-handler`

`"fastcgi"` `socket=`[`<string>`](#string)
`root=`[`<string>`](#string) ( `index=`[`<string>`](#string) )?

### `scgi-handler`

`"scgi"` `socket=`[`<string>`](#string)
`root=`[`<string>`](#string) ( `index=`[`<string>`](#string) )?

### `cgi-handler`

`"cgi"` `root=`[`<string>`](#string)

---

## access control

### `policy-block`

`"policy"` ( [`<string>`](#string) )? `{`
[`<policy-statement>`](#policy-statement)* `}`

The positional argument is the policy's name (`policy-def`); a
`policy` node without a name is the inline form.

### `policy-statement`

- `"allow"` ( [`<predicate>`](#predicate) )?
- `"deny"` ( `code=`[`<integer>`](#integer) )? (
  [`<predicate>`](#predicate) )?
- `"redirect"` `to=`[`<string>`](#string) (
  `code=`[`<integer>`](#integer) )? (
  [`<predicate>`](#predicate) )?
- `"apply"` [`<string>`](#string)

### `predicate`

- [`<pred-type>`](#pred-type) [`<string>`](#string)*
- `"not"` [`<pred-type>`](#pred-type) [`<string>`](#string)*
- `{` [`<pred-node>`](#pred-node)+ `}`

### `pred-type`

`"address"` | `"country"` | `"user"` | `"group"` |
`"authenticated"`

### `pred-node`

- `"address"` [`<string>`](#string)+
- `"country"` [`<string>`](#string)+
- `"user"` [`<string>`](#string)+
- `"group"` [`<string>`](#string)+
- `"authenticated"`
- `"not"` [`<pred-type>`](#pred-type) [`<string>`](#string)*

Predicate values use variadic positional arguments (rule 4
exception).

---

## header operations

### `basic-auth-block`

`"basic-auth"` ( `realm=`[`<string>`](#string) )?

### `request-headers-block`

`"request-headers"` `{` [`<header-op>`](#header-op)* `}`

### `response-headers-block`

`"response-headers"` `{` [`<header-op>`](#header-op)* `}`

### `header-op`

- `"set"` [`<string>`](#string) [`<string>`](#string)
- `"add"` [`<string>`](#string) [`<string>`](#string)
- `"remove"` [`<string>`](#string)

Header ops are inherently two-argument operations (name + value)
rather than lists, so they keep positional args.
