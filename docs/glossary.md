# Glossary

Short definitions for the acronyms and terms used throughout these
docs, each noting how it relates to hypershunt.  Use the search box to
jump here from anywhere.

## ACME

*Automatic Certificate Management Environment* (RFC 8555) — the protocol
Let's Encrypt and similar CAs use to issue TLS certificates without
human interaction.  hypershunt speaks ACME to obtain and renew
certificates automatically; see [HTTPS / TLS termination](guide.md#https--tls-termination)
and the [`tls "acme"`](reference.md#listener) listener block.

## HTTP-01

An ACME *challenge type* that proves you control a domain by serving a
token at `http://<domain>/.well-known/acme-challenge/<token>` over port
80.  hypershunt answers HTTP-01 challenges itself during certificate
issuance.

## TLS-ALPN-01

An ACME challenge type that proves domain control during the TLS
handshake using a special ALPN protocol (`acme-tls/1`) on port 443,
rather than a plaintext HTTP request.  Useful when port 80 is closed.

## ALPN

*Application-Layer Protocol Negotiation* — a TLS extension where client
and server agree on the application protocol (e.g. `h2`, `http/1.1`)
during the handshake.  hypershunt uses ALPN to negotiate HTTP/2 vs
HTTP/1.1 and to advertise HTTP/3; see [`alpn`](reference.md#listener).

## QUIC / HTTP/3

QUIC is a UDP-based transport with built-in TLS 1.3; HTTP/3 is HTTP
carried over QUIC.  hypershunt serves HTTP/3 on `udp://` listeners; see
[HTTP/3](guide.md#http3).

## mTLS

*Mutual TLS* — TLS where the **client** also presents a certificate, so
both ends authenticate each other.  hypershunt can require and verify
client certificates to gate access to a service; configured via the
`mtls` block under server `tls-options`.

## JWT

*JSON Web Token* (RFC 7519) — a signed, self-contained token carrying
claims (e.g. username, groups, expiry).  hypershunt issues JWTs as
session cookies after a successful login and validates them on later
requests; see [JWT sessions](guide.md#jwt-sessions).

## OIDC

*OpenID Connect* — an authentication layer on top of OAuth 2.0 that lets
an external identity provider (IdP) sign users in.  hypershunt acts as
an OIDC client for browser single sign-on; see
[OIDC single sign-on](guide.md#oidc-single-sign-on).

## OAuth 2.0

The authorization framework OIDC builds on.  Relevant here mainly
through the *authorization-code + PKCE* flow hypershunt uses to log
browsers in against an IdP.

## PKCE

*Proof Key for Code Exchange* (RFC 7636) — an OAuth extension that
protects the authorization-code flow from interception by binding the
code to a one-time secret.  hypershunt always uses PKCE in its OIDC
login flow.

## Bearer token

An access token sent in the `Authorization: Bearer <token>` header.  In
bearer mode hypershunt validates IdP-issued JWT bearer tokens directly,
acting as an OAuth resource server for APIs; see
[Bearer-token resource server](guide.md#bearer-token-resource-server).

## Subrequest auth

An authentication pattern where hypershunt makes an internal HTTP
request to an external authorization service for each incoming request;
a `200` allows it and identity headers flow back.  See
[Subrequest auth](guide.md#subrequest-auth).

## htpasswd

A flat file of `username:hashed-password` lines (the classic Apache
format) used for HTTP Basic authentication.  hypershunt can authenticate
Basic credentials against an htpasswd file; see
[`basic-auth`](reference.md#basic-auth).

## PROXY protocol

A small header (v1 text / v2 binary) that a front-end proxy prepends to
a forwarded connection so the backend learns the **original** client
address and port.  hypershunt both accepts it on a listener and can emit
it toward upstreams; see
[PROXY protocol on the receive side](guide.md#proxy-protocol-on-the-receive-side).

## CGI

*Common Gateway Interface* — runs a fresh process per request, passing
request data through environment variables and stdin/stdout.  Unix-only
in hypershunt; see [CGI, FastCGI, SCGI](guide.md#cgi-fastcgi-scgi).

## FastCGI

A binary, connection-oriented evolution of CGI that keeps a persistent
application process (e.g. PHP-FPM) and multiplexes requests over a
socket — far cheaper than fork-per-request.

## SCGI

*Simple CGI* — like FastCGI but with a minimal netstring-framed header
block instead of the FastCGI binary record protocol.

## vhost

*Virtual host* — a named site selected by the request's `Host` header,
letting one server serve many domains.  hypershunt matches literal
hostnames first, then regex patterns; see
[Virtual hosts](guide.md#virtual-hosts) and [`vhost`](reference.md#vhost).
By default every listener serves every vhost; a listener can instead
serve a chosen subset — see
[Per-listener vhost scoping](guide.md#per-listener-vhost-scoping).

## explicit-only vhost

A vhost marked [`explicit-only=#true`](reference.md#explicit-only) is
left out of a listener's implicit (all-vhosts) set, so only listeners
that name it in their [`vhost`](reference.md#vhost-listener-child) list
can reach it.  Used for admin or internal sites that shouldn't be
exposed by a listener that didn't ask for them.

## location

A path-prefix block inside a vhost that binds a URL prefix to a handler
(static files, proxy, redirect, CGI, …).  Longest-prefix match wins.
See [`location`](reference.md#vhost).

## upstream

A single backend address in a reverse-proxy pool.  A `proxy` block holds
one or more `upstream` entries; the load-balancer picks one per request.
See [Load balancing](guide.md#load-balancing).

## Load-balancing policy

The rule for choosing an upstream: `round-robin`, `least-conn`,
`random`, `ip-hash`, or `header-hash`.  Set with `lb-policy`.

## Rate-limit key

What a [rate limit](guide.md#rate-limiting) counts requests *per* —
`client-ip`, `user`, or a named request `header`.  Requests sharing a
key share one token bucket.

## Burst

The maximum number of requests a rate-limit bucket allows to arrive at
once before the steady `rate` throttles them.  Defaults to the rate.

## state-dir

The directory where hypershunt persists data that must survive restarts
— chiefly ACME certificates and the JWT signing key.  Set with
[`server state-dir`](reference.md#state-dir).
