#!/bin/bash
# Suite: SIGHUP hot config reload (#6).  Verifies the v1 scope:
# routing changes apply hot; listener add/remove and parse errors
# are atomic rejections that leave the old config serving.
#
# All suites share the start_server / stop_server helpers in lib.sh
# but reload tests rewrite the config file in-place between calls, so
# this suite manages its own config file lifecycle via $TMPDIR.

# --- helpers ---------------------------------------------------------

# Rewrite the active config file, then send SIGHUP.  The reload is
# synchronous from the kernel's POV but the reload task processes the
# signal asynchronously, so we briefly poll to ensure the change has
# landed.  `expect` is a fragment of access-log output (or empty if
# the reload should be rejected) that confirms the new config is live.
reload_via_sighup() {
    local config="$1"
    [ -n "${HYPERSHUNT_PID:-}" ] || { fail "reload/no_pid"; return 1; }
    kill -HUP "$HYPERSHUNT_PID" || return 1
    # Give the reload task one event-loop tick to process the signal.
    sleep 0.2
}

# --- suites ----------------------------------------------------------

suite_reload_routing_hot_swap() {
    echo "=== SIGHUP: routing hot-swap ==="
    mkdir -p /tmp/reload-a /tmp/reload-b
    printf "old-root\n" >/tmp/reload-a/index.html
    printf "new-root\n" >/tmp/reload-b/index.html

    cat >"$TMPDIR/reload.kdl" <<'EOF'
listener "tcp://127.0.0.1:18301"
vhost "h" {
    location "/" {
        static root="/tmp/reload-a" {
index-file index.html
}
    }
}
EOF
    start_server "$TMPDIR/reload.kdl" 18301 \
        || { fail "reload/routing/start"; return; }

    assert_body "reload/routing/before" "old-root" \
        "http://127.0.0.1:18301/" -H "Host: h"

    # Rewrite to point at /tmp/reload-b.
    cat >"$TMPDIR/reload.kdl" <<'EOF'
listener "tcp://127.0.0.1:18301"
vhost "h" {
    location "/" {
        static root="/tmp/reload-b" {
index-file index.html
}
    }
}
EOF
    reload_via_sighup "$TMPDIR/reload.kdl"
    assert_body "reload/routing/after" "new-root" \
        "http://127.0.0.1:18301/" -H "Host: h"

    stop_server
    rm -rf /tmp/reload-a /tmp/reload-b
}

# A slow download started before SIGHUP must complete from the *old*
# vhost root; the post-reload request sees the new root.  Verifies
# the per-connection AppState snapshot semantics.
suite_reload_mid_flight_download() {
    echo "=== SIGHUP: in-flight download survives reload ==="
    mkdir -p /tmp/reload-a /tmp/reload-b
    # 256 KB of recognisable old-content; smaller new-content file.
    dd if=/dev/zero bs=1024 count=256 2>/dev/null \
        | tr '\0' 'A' >/tmp/reload-a/big.bin
    printf "new-root\n" >/tmp/reload-b/index.html

    cat >"$TMPDIR/reload.kdl" <<'EOF'
listener "tcp://127.0.0.1:18302"
vhost "h" {
    location "/" {
        static root="/tmp/reload-a" {
index-file index.html
}
    }
}
EOF
    start_server "$TMPDIR/reload.kdl" 18302 \
        || { fail "reload/mid-flight/start"; return; }

    # Start a rate-limited download in the background.  256 KB at
    # 50 KB/s ~ 5 s, plenty of time to send a SIGHUP mid-flight.
    local out="$TMPDIR/big-out.bin"
    curl -s --limit-rate 50K -o "$out" \
        "http://127.0.0.1:18302/big.bin" -H "Host: h" &
    local curl_pid=$!
    sleep 1

    # Reload to a brand-new root.
    cat >"$TMPDIR/reload.kdl" <<'EOF'
listener "tcp://127.0.0.1:18302"
vhost "h" {
    location "/" {
        static root="/tmp/reload-b" {
index-file index.html
}
    }
}
EOF
    reload_via_sighup "$TMPDIR/reload.kdl"

    # A fresh request must hit the new root immediately.
    assert_body "reload/mid-flight/new_root_visible" "new-root" \
        "http://127.0.0.1:18302/" -H "Host: h"

    # The in-flight download must still complete, and its bytes must
    # match the *old* file (so the per-connection snapshot held).
    wait "$curl_pid"
    if [ -f "$out" ] && [ "$(wc -c <"$out")" = "262144" ]; then
        if cmp -s "$out" /tmp/reload-a/big.bin; then
            pass "reload/mid-flight/download_completes_from_old_root"
        else
            fail "reload/mid-flight/download_completes_from_old_root" \
                "byte mismatch against old root"
        fi
    else
        fail "reload/mid-flight/download_completes_from_old_root" \
            "expected 262144 bytes, got $(wc -c <"$out" 2>/dev/null || echo 0)"
    fi

    stop_server
    rm -rf /tmp/reload-a /tmp/reload-b "$out"
}

# SIGHUP can add (and later remove) plain HTTP listeners.  The
# operator's edit applies hot; the rest of the running config is
# undisturbed.
suite_reload_listener_add_and_delete() {
    echo "=== SIGHUP: plain HTTP listener add + delete ==="
    mkdir -p /tmp/reload-c
    printf "alive\n" >/tmp/reload-c/index.html

    cat >"$TMPDIR/reload.kdl" <<'EOF'
listener "tcp://127.0.0.1:18303"
vhost "h" {
    location "/" {
        static root="/tmp/reload-c" {
index-file index.html
}
    }
}
EOF
    start_server "$TMPDIR/reload.kdl" 18303 \
        || { fail "reload/listener_add/start"; return; }

    # Add :18304 via SIGHUP.
    cat >"$TMPDIR/reload.kdl" <<'EOF'
listener "tcp://127.0.0.1:18303"
listener "tcp://127.0.0.1:18304"
vhost "h" {
    location "/" {
        static root="/tmp/reload-c" {
index-file index.html
}
    }
}
EOF
    reload_via_sighup "$TMPDIR/reload.kdl"
    # Give the new listener task a moment to enter its accept loop.
    sleep 0.3

    assert_body "reload/listener_add/new_port_serving" "alive" \
        "http://127.0.0.1:18304/" -H "Host: h"
    assert_body "reload/listener_add/original_still_serving" "alive" \
        "http://127.0.0.1:18303/" -H "Host: h"

    # Now remove the original; only :18304 should remain.
    cat >"$TMPDIR/reload.kdl" <<'EOF'
listener "tcp://127.0.0.1:18304"
vhost "h" {
    location "/" {
        static root="/tmp/reload-c" {
index-file index.html
}
    }
}
EOF
    reload_via_sighup "$TMPDIR/reload.kdl"
    sleep 0.3

    # :18303 is closed.  curl --max-time 2 returns 000 either way
    # (ECONNREFUSED is normal; we just don't want a 200 from the
    # still-running listener).
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
        --connect-timeout 1 "http://127.0.0.1:18303/" 2>/dev/null) \
        || code="000"
    if [ "$code" = "000" ]; then
        pass "reload/listener_delete/old_port_closed"
    else
        fail "reload/listener_delete/old_port_closed" \
            "old port still responds $code after SIGHUP delete"
    fi

    # The remaining listener keeps serving.
    assert_body "reload/listener_delete/remaining_serves" "alive" \
        "http://127.0.0.1:18304/" -H "Host: h"

    stop_server
    rm -rf /tmp/reload-c
}

# SIGHUP can add a TLS-terminating listener: build_tls_listener runs
# at reload time, wires up the cert source (self-signed here is
# instant) and the new HTTPS port starts serving.
suite_reload_tls_listener_add() {
    echo "=== SIGHUP: TLS listener add (self-signed) ==="
    mkdir -p /tmp/reload-cc
    printf "alive\n" >/tmp/reload-cc/index.html

    cat >"$TMPDIR/reload.kdl" <<'EOF'
listener "tcp://127.0.0.1:18313"
vhost "h" {
    location "/" {
        static root="/tmp/reload-cc" {
index-file index.html
}
    }
}
EOF
    start_server "$TMPDIR/reload.kdl" 18313 \
        || { fail "reload/tls_add/start"; return; }

    cat >"$TMPDIR/reload.kdl" <<'EOF'
listener "tcp://127.0.0.1:18313"
listener "tcp://127.0.0.1:18314" {
    tls "self-signed"
}
vhost "h" {
    location "/" {
        static root="/tmp/reload-cc" {
index-file index.html
}
    }
}
EOF
    reload_via_sighup "$TMPDIR/reload.kdl"
    sleep 0.5

    assert_body "reload/tls_add/new_listener_serves_https" "alive" \
        "https://127.0.0.1:18314/" -H "Host: h" -k
    assert_body "reload/tls_add/original_still_serving" "alive" \
        "http://127.0.0.1:18313/" -H "Host: h"

    stop_server
    rm -rf /tmp/reload-cc
}

# SIGHUP can define a new named certificate AND add a TLS listener
# that references it via `tls cert="<name>"`.  Verifies both
# pieces lift on the same reload.
suite_reload_named_cert_define() {
    echo "=== SIGHUP: define a new named cert + ref it ==="
    mkdir -p /tmp/reload-nc
    printf "alive\n" >/tmp/reload-nc/index.html

    cat >"$TMPDIR/reload.kdl" <<'EOF'
listener "tcp://127.0.0.1:18333"
vhost "h" {
    location "/" {
        static root="/tmp/reload-nc" {
index-file index.html
}
    }
}
EOF
    start_server "$TMPDIR/reload.kdl" 18333 \
        || { fail "reload/named_cert/start"; return; }

    cat >"$TMPDIR/reload.kdl" <<'EOF'
certificate "internal" { tls "self-signed" }
listener "tcp://127.0.0.1:18333"
listener "tcp://127.0.0.1:18334" { tls "ref" name="internal"
}
vhost "h" {
    location "/" {
        static root="/tmp/reload-nc" {
index-file index.html
}
    }
}
EOF
    reload_via_sighup "$TMPDIR/reload.kdl"
    sleep 0.5

    assert_body "reload/named_cert/tls_serves_with_named_cert" "alive" \
        "https://127.0.0.1:18334/" -H "Host: h" -k
    assert_body "reload/named_cert/plain_still_serves" "alive" \
        "http://127.0.0.1:18333/" -H "Host: h"

    stop_server
    rm -rf /tmp/reload-nc
}

# SIGHUP can add a stream-proxy listener.  Use a localhost
# echo-via-hypershunt-backend setup: the new stream listener forwards
# to the existing HTTP port, which serves our static file.
suite_reload_stream_listener_add() {
    echo "=== SIGHUP: stream-proxy listener add ==="
    mkdir -p /tmp/reload-st
    printf "alive\n" >/tmp/reload-st/index.html

    cat >"$TMPDIR/reload.kdl" <<'EOF'
listener "tcp://127.0.0.1:18323"
vhost "h" {
    location "/" {
        static root="/tmp/reload-st" {
index-file index.html
}
    }
}
EOF
    start_server "$TMPDIR/reload.kdl" 18323 \
        || { fail "reload/stream_add/start"; return; }

    cat >"$TMPDIR/reload.kdl" <<'EOF'
listener "tcp://127.0.0.1:18323"
listener "tcp://127.0.0.1:18324" {
    stream {
        upstream "127.0.0.1:18323"
    }
}
vhost "h" {
    location "/" {
        static root="/tmp/reload-st" {
index-file index.html
}
    }
}
EOF
    reload_via_sighup "$TMPDIR/reload.kdl"
    sleep 0.5

    # Connecting to the new stream listener should land on the
    # HTTP backend on the original port -- end-to-end, the content
    # served comes from the static handler.
    assert_body "reload/stream_add/new_listener_forwards" "alive" \
        "http://127.0.0.1:18324/" -H "Host: h"
    assert_body "reload/stream_add/original_still_serving" "alive" \
        "http://127.0.0.1:18323/" -H "Host: h"

    stop_server
    rm -rf /tmp/reload-st
}

# Editing the auth backend via SIGHUP is rejected loudly rather than
# silently ignored.  v1 carries the authenticator forward across
# reload, so an operator who edits PAM/LDAP/file auth and HUPs would
# otherwise believe their change took effect.
suite_reload_rejects_auth_change() {
    echo "=== SIGHUP: server.auth change is rejected (v1) ==="
    mkdir -p /tmp/reload-auth
    printf "alive\n" >/tmp/reload-auth/index.html
    # bcrypt hash of "secret" (shared with suite_auth_file.sh).
    local BCRYPT_SECRET='$2b$04$i/SRyovMJVctpkrEQIDueOlFCVtPDnuvkT1s12Guzwahgf0Fg1Lp.'
    printf 'alice:%s\n' "$BCRYPT_SECRET" >/tmp/reload-auth/htpasswd

    cat >"$TMPDIR/reload.kdl" <<'EOF'
server { auth "file" path="/tmp/reload-auth/htpasswd"
}
listener "tcp://127.0.0.1:18306"
vhost "h" {
    location "/" {
        static root="/tmp/reload-auth" {
index-file index.html
}
        policy { allow authenticated }
    }
}
EOF
    start_server "$TMPDIR/reload.kdl" 18306 \
        || { fail "reload/auth/start"; return; }

    # Drop the auth block from the new config -- exactly the kind of
    # edit v1 must refuse rather than silently ignore.
    cat >"$TMPDIR/reload.kdl" <<'EOF'
listener "tcp://127.0.0.1:18306"
vhost "h" {
    location "/" {
        static root="/tmp/reload-auth" {
index-file index.html
}
    }
}
EOF
    reload_via_sighup "$TMPDIR/reload.kdl"

    # The old auth policy must still be enforced -- a request without
    # credentials gets 401, proving the reload was refused.
    assert_status "reload/auth/still_requires_credentials" "401" \
        "http://127.0.0.1:18306/" -H "Host: h"
    # And valid credentials still work via the old authenticator.
    assert_status "reload/auth/old_creds_still_work" "200" \
        "http://127.0.0.1:18306/" -H "Host: h" -u "alice:secret"

    stop_server
    rm -rf /tmp/reload-auth
}

# Parse error in the new config: old config keeps serving.
suite_reload_rejects_parse_error() {
    echo "=== SIGHUP: parse error is rejected (atomic) ==="
    mkdir -p /tmp/reload-d
    printf "still-here\n" >/tmp/reload-d/index.html

    cat >"$TMPDIR/reload.kdl" <<'EOF'
listener "tcp://127.0.0.1:18305"
vhost "h" {
    location "/" {
        static root="/tmp/reload-d" {
index-file index.html
}
    }
}
EOF
    start_server "$TMPDIR/reload.kdl" 18305 \
        || { fail "reload/parse_error/start"; return; }

    # Mangle the config.
    printf "this is not kdl {{{\n" >"$TMPDIR/reload.kdl"
    reload_via_sighup "$TMPDIR/reload.kdl"

    # Old config still serves.
    assert_body "reload/parse_error/old_still_serving" "still-here" \
        "http://127.0.0.1:18305/" -H "Host: h"

    stop_server
    rm -rf /tmp/reload-d
}

# `hypershunt --check-config <path>` exits 0 on a valid config, non-zero
# on parse errors -- the operator-facing pre-flight for reload.
suite_check_config_flag() {
    echo "=== --check-config exit codes ==="
    cat >"$TMPDIR/check-good.kdl" <<'EOF'
listener "tcp://127.0.0.1:0"
vhost "h" {
    location "/" { static root="/tmp" {
index-file index.html
} }
}
EOF
    if "$HYPERSHUNT" --check-config --config "$TMPDIR/check-good.kdl" \
        >/dev/null 2>&1; then
        pass "check-config/valid_exits_0"
    else
        fail "check-config/valid_exits_0" "expected exit 0"
    fi

    printf "garbage{{{\n" >"$TMPDIR/check-bad.kdl"
    if ! "$HYPERSHUNT" --check-config --config "$TMPDIR/check-bad.kdl" \
        >/dev/null 2>&1; then
        pass "check-config/invalid_exits_nonzero"
    else
        fail "check-config/invalid_exits_nonzero" "expected non-zero exit"
    fi
}
