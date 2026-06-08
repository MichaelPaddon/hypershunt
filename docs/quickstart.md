# Quick start

Get hypershunt serving in under five minutes using the official
container image.  No build, no install.

## Prerequisites

- `podman` or `docker` installed.
- Ports `80` and `443` free on your host (or pick different host
  ports below).

The examples use `podman`; replace with `docker` (and drop the
`:Z` SELinux relabel flag) on systems without podman.

## Serve the bundled landing page

```sh
podman run --rm -p 8080:80 ghcr.io/michaelpaddon/hypershunt:latest
```

Open <http://localhost:8080>.  You'll see hypershunt's built-in
landing page served from `/var/www/hypershunt/` inside the container.
The image runs as root just long enough to bind ports, then
drops to the `hypershunt` user.

Stop with `Ctrl-C`.

## Serve your own directory

Bind-mount a host directory at `/var/www/hypershunt`:

```sh
podman run --rm -p 8080:80 \
    -v "$PWD/public:/var/www/hypershunt:ro,Z" \
    ghcr.io/michaelpaddon/hypershunt:latest
```

Anything you put in `./public` is now reachable at
`http://localhost:8080/`.  The container's bundled config
[serves files](guide.md#serving-static-files) from that path with
`index.html` / `index.htm` as directory indices.

## Use your own config

For anything beyond "serve a directory", bind-mount an
`hypershunt.kdl` at `/etc/hypershunt.kdl`:

```sh
cat > hypershunt.kdl <<'EOF'
listener "tcp://[::]:80"

vhost "localhost" {
    location "/api/" {
        proxy { upstream "http://10.0.0.5:9000" }
    }
    location "/" {
        static root="/var/www/hypershunt"
    }
}
EOF

podman run --rm -p 8080:80 \
    -v "$PWD/hypershunt.kdl:/etc/hypershunt.kdl:ro,Z" \
    -v "$PWD/public:/var/www/hypershunt:ro,Z" \
    ghcr.io/michaelpaddon/hypershunt:latest
```

This vhost reverse-proxies `/api/` to a back-end and serves
everything else from the mounted directory.  See the
[configuration guide](guide.md) for every common scenario and the
[reference](reference.md) for every directive.

## HTTPS with a self-signed cert (30 seconds)

```sh
cat > hypershunt.kdl <<'EOF'
listener "tcp://[::]:443" { tls "self-signed" }

vhost "localhost" {
    location "/" { static root="/var/www/hypershunt" }
}
EOF

podman run --rm -p 8443:443 \
    -v "$PWD/hypershunt.kdl:/etc/hypershunt.kdl:ro,Z" \
    -v "$PWD/public:/var/www/hypershunt:ro,Z" \
    ghcr.io/michaelpaddon/hypershunt:latest
```

Open <https://localhost:8443>.  Your browser will warn about the
self-signed certificate -- that's expected.  Self-signed is for
local development only; for a real deployment use [Let's Encrypt
via ACME](guide.md#https-tls-termination).

## Production-shaped HTTPS

A realistic public-facing deployment needs three things on top
of the dev shape: ACME issuance, a persistent state directory
for the issued certificate, and the host's port 80/443 (not
random high ports) so Let's Encrypt's HTTP-01 challenge can
reach you:

```sh
cat > hypershunt.kdl <<'EOF'
server state-dir="/var/lib/hypershunt" user="hypershunt"

listener "tcp://[::]:80"
listener "tcp://[::]:443" {
    tls "acme" email="you@example.com" { domain "example.com" }
}

vhost "example.com" {
    location "/" { static root="/var/www/hypershunt" }
}
EOF

podman run -d --name hypershunt \
    -p 80:80 -p 443:443 \
    -v "$PWD/hypershunt.kdl:/etc/hypershunt.kdl:ro,Z" \
    -v "$PWD/public:/var/www/hypershunt:ro,Z" \
    -v "hypershunt-state:/var/lib/hypershunt:Z" \
    ghcr.io/michaelpaddon/hypershunt:latest
```

A few things changed:

- `-d --name hypershunt` runs the container detached.
- The `hypershunt-state` named volume persists the ACME-issued
  certificate across container restarts -- without it every
  restart triggers a fresh ACME request and rate-limits become
  a problem.
- `server state-dir=`, `tls "acme"`, and `user=` are required
  for a production-shape config (see the [production
  checklist](guide.md#production-checklist)).

Stop and remove with:

```sh
podman stop hypershunt && podman rm hypershunt
```

## Where next

- [Configuration guide](guide.md) -- 35 scenario-driven chapters
  covering everything from virtual hosts to OIDC sign-on.
- [Configuration reference](reference.md) -- every directive
  hypershunt accepts, with semantics, defaults, and worked KDL
  examples.
- [Grammar](grammar.md) -- the formal KDL syntax.
- Running in production: [unprivileged &
  containers](guide.md#running-unprivileged) and [reload &
  zero-downtime upgrade](guide.md#reloading-and-zero-downtime-upgrade).

## Troubleshooting

**`bind: address already in use`** -- another process is on
that port.  Either stop the conflicting service or change the
host port (`-p 8080:80`).

**SELinux denials on RHEL/Fedora** -- the `:Z` flag on the
volume mount relabels the bind-mount for container access.
Skip the flag on Debian/Ubuntu (or Docker) where SELinux isn't
enforced.

**Permission denied reading mounted files** -- hypershunt runs as
the in-container `hypershunt` user, a fixed **UID/GID 1000**.  Make
sure your mounted directories are readable by it; a simple
`chmod -R o+rX public` resolves most cases.  To instead align host
ownership with the container, map your host user onto UID/GID 1000:

```sh
podman run ... --userns=keep-id:uid=1000,gid=1000 ...
```

Caveat: `keep-id` starts the process as UID 1000 (not container-root),
so it can no longer bind ports below 1024 -- combining it with
`-p 80:80`/`-p 443:443` fails with `EACCES`.  Keep the default
namespace for privileged ports, or publish to a high in-container
port; see [Container
twist](guide.md#container-twist) for the options.

**ACME issuance fails** -- the `state-dir` volume must be
writable, and Let's Encrypt must be able to reach your hypershunt on
port 80 for the HTTP-01 challenge.  Hypershunt falls back to a
self-signed certificate and retries hourly while the issuance
is failing -- check the container logs for the ACME error.

Validate any config file before running:

```sh
podman run --rm \
    -v "$PWD/hypershunt.kdl:/etc/hypershunt.kdl:ro,Z" \
    ghcr.io/michaelpaddon/hypershunt:latest \
    --check-config
```

Exit code 0 means the config parses and validates; non-zero
prints the first error.
