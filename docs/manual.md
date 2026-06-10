<!-- GENERATED from docs/hypershunt.1 at build time (build.rs). DO NOT EDIT BY HAND. -->

# NAME

hypershunt - HTTP server and reverse proxy

# SYNOPSIS

**hypershunt** \[**-c**\|**--config** *file*\] \[**--check-config**\]  
**hypershunt** **--version**\|**--help**

# DESCRIPTION

**hypershunt** is a lightweight HTTP/HTTPS server and reverse proxy. It supports virtual host routing, automatic TLS via Let's Encrypt, static file serving, HTTP redirects, configurable timeouts, and ES256 JWT session authentication.

Configuration is read from a KDL file (default: *hypershunt.kdl* in the working directory). All sockets are bound before privileges are dropped, so **hypershunt** can be started as root to bind ports 80 and 443 and will then switch to an unprivileged user as specified in the configuration.

# OPTIONS

**-c*** file***, ***--config*** file**  
Read configuration from *file* instead of the default *hypershunt.kdl*.

**--check-config**  
Parse and validate the configuration, then exit without binding any sockets. Exits 0 on success, or non-zero with diagnostics on standard error if the configuration has parse or semantic errors. Useful for CI and as a pre-flight check before sending **SIGHUP** to hot-reload a running instance.

**-h**, **--help**  
Print a usage summary and exit. Use **--help** for the full description and **-h** for the short form.

**-V**, **--version**  
Print the version and exit.

# CONFIGURATION

Configuration is written in KDL. The top-level nodes are:

> **server**  
> Global settings: privilege drop user/group, state directory for ACME certificates and JWT signing keys, authentication back-end, and global TLS defaults.
>
> **listener**  
> Opens a TCP socket (via **bind** or an inherited file descriptor via **fd**) and begins accepting connections. Each listener optionally has a **tls** child (self-signed, PEM file, or ACME/Let's Encrypt) and a **timeouts** child. By default a listener serves every defined virtual host. Add one or more **vhost** reference children to serve only a chosen subset (different sets of virtual hosts on different ports).
>
> **vhost**  
> Maps one or more hostnames to URL routing rules. Names are matched against the **Host** request header; a leading **~** treats the name as a regular expression.
>
> **location**  
> Maps a URL path prefix to a handler: **static**, **proxy**, **redirect**, or **fastcgi**.

See the configuration reference for the full directive list: [](https://github.com/MichaelPaddon/hypershunt/blob/main/docs/reference.md)

# FILES

*/etc/hypershunt.kdl*  
Default system-wide configuration file when **hypershunt** is installed as a service.

*/var/lib/hypershunt/*  
Default state directory for ACME account keys, issued certificates, and JWT signing keys (set via **server state-dir** in the configuration). The JWT EC private key is stored at */var/lib/hypershunt/jwt/ec-key.pem* and generated on first startup with mode 0600.

*/var/www/hypershunt/*  
Default document root served by the packaged configuration.

# ENVIRONMENT

**RUST_LOG**  
Controls log verbosity. The default is **hypershunt=info**. Examples: **hypershunt=debug**, **hypershunt=trace**. See [](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html) for the full filter syntax.

# SIGNALS

**SIGINT**, **SIGTERM**  
Initiates graceful shutdown. Listening sockets stop accepting new connections; in-flight requests are given up to 30 seconds to complete before the process exits.

**SIGHUP**  
Hot-reloads the configuration from the same path given at startup. Routing (vhosts, locations, handlers, header rules, access policies, rate limits), the listener set (listeners are added or drained), and named TLS certificates are applied atomically; on any parse or bind error the running configuration is left serving unchanged. Changes to the authentication back-end are refused with a logged warning and require a restart.

**SIGUSR2**  
Performs a seamless binary upgrade: re-execs the on-disk **hypershunt** binary, handing the inherited listening sockets to the new process so no connections are dropped across the swap.

# EXAMPLES

Start with the default configuration file in the current directory:

>     hypershunt

Start with an explicit configuration file:

>     hypershunt --config /etc/hypershunt.kdl

Run with debug logging enabled:

>     RUST_LOG=hypershunt=debug hypershunt --config /etc/hypershunt.kdl

# SEE ALSO

**systemctl**(1)

Documentation: [](https://github.com/MichaelPaddon/hypershunt/tree/main/docs) (**quickstart.md**, **guide.md**, **reference.md**, **grammar.md**).

# BUGS

HAProxy PROXY protocol over QUIC is not supported; the wire format is still an IETF draft. Terminate QUIC at HAProxy and forward HTTP/1.1 or HTTP/2 over TCP to hypershunt if source-IP preservation on HTTP/3 traffic is required.

# AUTHOR

Michael Paddon
