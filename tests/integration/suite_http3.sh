#!/bin/bash
# Suite: HTTP/3 inbound + Alt-Svc auto-advertisement.
#
# Exercises the udp: listener kind plus the same-port Alt-Svc
# auto-injection (Phase 1 + 2 surface).  Uses the h3get helper
# binary because Debian's packaged curl doesn't include HTTP/3.

suite_http3_basic() {
    echo "=== HTTP/3 basic GET ==="
    cat >"$TMPDIR/h3.kdl" <<'EOF'
listener "udp://127.0.0.1:18443" {
    quic { tls "self-signed" }
}
vhost localhost {
    location "/" {
        static root="/tmp/www" {
index-file index.html;
}
    }
}
EOF
    # Use the plain TCP wait loop on port 18443 won't work (no TCP
    # listener); kick off and sleep briefly to let quinn bind UDP.
    "$HYPERSHUNT" --config "$TMPDIR/h3.kdl" >"$TMPDIR/hypershunt.out" 2>&1 &
    HYPERSHUNT_PID=$!
    sleep 0.5
    if ! kill -0 "$HYPERSHUNT_PID" 2>/dev/null; then
        fail "h3/server_start" "hypershunt exited during startup"
        cat "$TMPDIR/hypershunt.out" >&2
        HYPERSHUNT_PID=""
        return
    fi

    assert_h3_status "h3/200" 200 "https://127.0.0.1:18443/"
    assert_h3_body   "h3/body" "Hello hypershunt" "https://127.0.0.1:18443/"

    stop_server
}

suite_http3_middleware() {
    echo "=== HTTP/3 + middleware (policy + response-headers) ==="
    # The full handler pipeline -- access policy, response header
    # rewriting -- must run identically on the h3 path as on h1/h2.
    # A regression that bypassed policy on h3 would be a security
    # hole; a regression that bypassed response-headers would
    # silently break observability rewrites.
    cat >"$TMPDIR/h3_mid.kdl" <<'EOF'
listener "udp://127.0.0.1:18445" {
    quic { tls "self-signed" }
}
vhost localhost {
    location "/open" {
        static root="/tmp/www" strip-prefix=#true {
index-file index.html
}
        response-headers {
            set "X-Hypershunt-Middleware" "h3-saw-this"
        }
    }
    location "/locked" {
        static root="/tmp/www" strip-prefix=#true {
index-file index.html
}
        policy {
            allow address "10.99.99.0/24"
            deny code=403
        }
    }
}
EOF
    "$HYPERSHUNT" --config "$TMPDIR/h3_mid.kdl" >"$TMPDIR/hypershunt.out" 2>&1 &
    HYPERSHUNT_PID=$!
    sleep 0.5
    if ! kill -0 "$HYPERSHUNT_PID" 2>/dev/null; then
        fail "h3_mid/server_start" "hypershunt exited during startup"
        cat "$TMPDIR/hypershunt.out" >&2
        HYPERSHUNT_PID=""
        return
    fi

    # /open is anonymous and gets the response-header rewrite.
    assert_h3_status "h3_mid/open_200" 200 \
        "https://127.0.0.1:18445/open"
    assert_h3_header "h3_mid/open_header" \
        "x-hypershunt-middleware" "h3-saw-this" \
        "https://127.0.0.1:18445/open"

    # /locked denies any source not in 10.99.99.0/24.  The test
    # client (h3get on loopback) is 127.0.0.1, so policy must
    # respond 403.  If h3 were silently bypassing policy this
    # would come back 200.
    assert_h3_status "h3_mid/locked_403" 403 \
        "https://127.0.0.1:18445/locked"

    stop_server
}

suite_http3_alt_svc() {
    echo "=== Alt-Svc auto-advertisement on same-port TCP+UDP pair ==="
    cat >"$TMPDIR/h3_altsvc.kdl" <<'EOF'
listener "tcp://127.0.0.1:18444" { tls "self-signed"
}
listener "udp://127.0.0.1:18444" { quic { tls "self-signed" }
}
vhost localhost {
    location "/" {
        static root="/tmp/www" {
index-file index.html;
}
    }
}
EOF
    "$HYPERSHUNT" --config "$TMPDIR/h3_altsvc.kdl" \
        >"$TMPDIR/hypershunt.out" 2>&1 &
    HYPERSHUNT_PID=$!
    # Wait on the TCP side because curl can probe that natively.
    local tries=0
    while true; do
        local code
        code=$(curl -sk -o /dev/null -w "%{http_code}" \
            --max-time 0.5 --connect-timeout 0.5 \
            "https://127.0.0.1:18444/") || code=""
        [ -n "$code" ] && [ "$code" != "000" ] && break
        tries=$((tries + 1))
        if [ "$tries" -ge 60 ]; then
            fail "h3/altsvc_start" "tcp side never came up"
            stop_server
            return
        fi
        sleep 0.1
    done

    # TCP response advertises h3 via Alt-Svc on the matching port.
    assert_header "h3/altsvc_tcp" \
        "alt-svc" "h3=\":18444\"" \
        "https://127.0.0.1:18444/" -k

    # The UDP listener should still serve a real h3 GET on the same
    # port; verifies the two listeners actually coexist.
    assert_h3_status "h3/altsvc_udp" 200 "https://127.0.0.1:18444/"

    stop_server
}
