# Recipes

Complete, copy-pasteable `hypershunt.kdl` files for common
deployments.  Unlike the [guide](guide.md), which explains one feature
at a time, each recipe here is a **whole config** you can drop in and
adapt.  Replace the example hostnames, paths, and upstream addresses
with your own.

> [!TIP]
> Validate any config before running it:
> `hypershunt --check-config -c hypershunt.kdl`.

## Static website with HTTPS

A public site on ports 80 and 443, with a Let's Encrypt certificate
obtained and renewed automatically.  Port 80 stays open so the ACME
[HTTP-01](glossary.md#http-01) challenge can be answered; it also
serves the site (you can redirect it to HTTPS instead — see the next
recipe).

```kdl
server user="hypershunt" state-dir="/var/lib/hypershunt"

listener "tcp://[::]:80"
listener "tcp://[::]:443" {
    tls "acme" email="ops@example.com" {
        domain "example.com"
        domain "www.example.com"
    }
}

vhost "example.com" {
    alias "www.example.com"
    location "/" {
        static root="/var/www/example" index-file="index.html"
    }
}
```

**See also:** [HTTPS / TLS termination](guide.md#https--tls-termination),
[Serving static files](guide.md#serving-static-files).

## Redirect all HTTP to HTTPS

Force every plaintext request to HTTPS while still answering ACME
challenges (hypershunt serves the challenge before the redirect fires).

```kdl
server user="hypershunt" state-dir="/var/lib/hypershunt"

listener "tcp://[::]:80"
listener "tcp://[::]:443" {
    tls "acme" email="ops@example.com" { domain "example.com" }
}

vhost "example.com" {
    // Plaintext requests get a permanent redirect to the TLS site,
    // preserving the original path and query.
    location "/" {
        redirect to="https://{host}{path_and_query}" code=301
    }
}
```

**See also:** [URL redirects](guide.md#url-redirects).

## Reverse proxy with load balancing

Spread `/` across a pool of backends, weighted, with least-connection
balancing and passive ejection of a backend that starts failing.

```kdl
server user="hypershunt" state-dir="/var/lib/hypershunt"

listener "tcp://[::]:443" {
    tls "acme" email="ops@example.com" { domain "app.example.com" }
}

vhost "app.example.com" {
    location "/" {
        proxy {
            upstream "http://10.0.0.11:9000" weight=2
            upstream "http://10.0.0.12:9000" weight=1
            lb-policy "least-conn"
            passive-health { eject-after 3; eject-for 30 }
        }
    }
}
```

**See also:** [Reverse proxy](guide.md#reverse-proxy),
[Load balancing](guide.md#load-balancing),
[Health checks](guide.md#health-checks).

## PHP application (FastCGI / PHP-FPM)

Serve static assets directly and hand `.php` requests to a PHP-FPM
pool over its Unix socket.

```kdl
server user="hypershunt"

listener "tcp://[::]:80"

vhost "blog.example.com" {
    location "/" {
        static root="/var/www/blog" index-file="index.php"
    }
    // Longest-prefix match: requests to /index.php (the front
    // controller) route here instead of the static handler.
    location "/index.php" {
        fastcgi socket="unix-stream:/run/php/php-fpm.sock" \
            root="/var/www/blog" \
            index="index.php"
    }
}
```

**See also:** [CGI, FastCGI, SCGI](guide.md#cgi-fastcgi-scgi).

## OIDC single sign-on with rate limiting

Protect an app behind an OpenID Connect provider and throttle the
login path so a flood of callbacks can't hammer the IdP.

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

listener "tcp://[::]:443" {
    tls "acme" email="ops@example.com" { domain "app.example.com" }
}

vhost "app.example.com" {
    location "/" {
        // Anonymous browsers are bounced to the IdP automatically.
        policy { allow authenticated; deny code=401 }
        rate-limit rate=30 per="minute" burst=30 { key "client-ip" }
        proxy { upstream "http://127.0.0.1:9000" }
    }
}
```

**See also:** [OIDC single sign-on](guide.md#oidc-single-sign-on),
[Rate limiting](guide.md#rate-limiting),
[Access policies](guide.md#access-policies).

## IP-restricted admin area with Basic auth

Require both a trusted source network **and** valid credentials — two
independent gates, either of which can refuse the request.

```kdl
server user="hypershunt" {
    auth "file" path="/etc/hypershunt/htpasswd" cache=60
}

listener "tcp://[::]:443" {
    tls "acme" email="ops@example.com" { domain "ops.example.com" }
}

vhost "ops.example.com" {
    location "/admin/" {
        policy {
            allow address "10.0.0.0/8" "192.168.0.0/16"
            deny code=403
        }
        basic-auth realm="Admin"
        policy { allow group "admins"; deny code=403 }
        static root="/var/www/admin"
    }
}
```

**See also:** [Access policies](guide.md#access-policies),
[HTTP Basic auth](reference.md#basic-auth).

## mTLS-protected internal service

Require clients to present a certificate signed by your internal CA
before the request reaches the backend — useful for service-to-service
traffic.

```kdl
server user="hypershunt"

listener "tcp://[::]:8443" {
    tls "files" cert="/etc/hypershunt/edge.pem" \
            key="/etc/hypershunt/edge.key" {
        mtls mode="required" {
            ca "/etc/hypershunt/internal-ca.pem"
        }
    }
}

vhost "internal.example.com" {
    location "/" {
        proxy { upstream "http://127.0.0.1:9000" }
    }
}
```

**See also:** [mtls](reference.md#mtls).

## Layer-4 TCP proxy (e.g. PostgreSQL)

Forward a raw TCP port to a backend with no HTTP processing.  Adding a
`proxy` child switches the whole listener into L4 mode, so it carries
no vhosts.  L4 upstreams must be **literal IPs**.

```kdl
server user="hypershunt"

listener "tcp://0.0.0.0:5432" {
    proxy "tcp://10.0.0.5:5432"
}
```

To terminate TLS at the edge and re-originate it to the backend:

```kdl
listener "tcp://0.0.0.0:5432" {
    tls "files" cert="/etc/hypershunt/edge.pem" \
            key="/etc/hypershunt/edge.key"
    proxy "tcp://10.0.0.5:5432" { tls skip-verify=#false }
}
```

**See also:** [Layer-4 proxy](guide.md#layer-4-proxy).

## Behind another reverse proxy (PROXY protocol)

When hypershunt sits behind an L4 load balancer (HAProxy, AWS NLB,
Cloudflare Spectrum), enable PROXY protocol so it learns the real
client IP — and restrict who may send those headers.

```kdl
server user="hypershunt"

listener "tcp://0.0.0.0:8080" accept-proxy-protocol="v2" {
    trusted-proxies "10.0.0.0/8"
    trusted-proxies "172.16.0.0/12"
}

vhost "app.example.com" {
    location "/" {
        // The carried client IP now drives this policy.
        policy { deny country "RU"; allow }
        proxy { upstream "http://127.0.0.1:9000" }
    }
}
```

> [!WARNING]
> Without `trusted-proxies`, anyone who can reach the listener can
> forge a PROXY header and claim any client IP.

**See also:**
[PROXY protocol on the receive side](guide.md#proxy-protocol-on-the-receive-side).
