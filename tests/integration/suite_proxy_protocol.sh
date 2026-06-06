#!/bin/bash
# Suite: inbound PROXY protocol (accept-proxy-protocol + trusted-proxies).
#
# Uses curl --haproxy-protocol to prepend a PROXY v1 header from a
# loopback client, and verifies hypershunt surfaces the spoofed peer IP via
# a `{client_ip}` template in a response header.  The allowlist case
# rejects the same client when the loopback range is not trusted.

suite_proxy_protocol_v1_loopback_trusted() {
    echo "=== accept-proxy-protocol v1 (loopback trusted) ==="
    cat >"$TMPDIR/pp_trusted.kdl" <<'EOF'
listener "tcp://127.0.0.1:8190" accept-proxy-protocol="v1" {
    trusted-proxies "127.0.0.0/8"
}
vhost localhost {
    location "/" {
        response-headers { set "X-Client-IP" "{client_ip}" }
        static root="/tmp/www" {
index-file index.html;
}
    }
}
EOF
    # Cannot use the standard start_server probe -- a plain GET without
    # a PROXY header gets dropped at parse, so the probe never sees a
    # response.  Spin up directly and wait for the port to bind.
    "$HYPERSHUNT" --config "$TMPDIR/pp_trusted.kdl" \
        >"$TMPDIR/hypershunt.out" 2>&1 &
    HYPERSHUNT_PID=$!
    local tries=0
    while ! (echo > /dev/tcp/127.0.0.1/8190) 2>/dev/null; do
        tries=$((tries + 1))
        if [ "$tries" -ge 60 ]; then
            fail "pp_v1/start" "listener never bound"
            stop_server
            return
        fi
        sleep 0.05
    done

    # curl --haproxy-protocol prepends "PROXY TCP4 <local> <remote> ..."
    # so hypershunt sees the spoofed loopback peer through PROXY v1.  When
    # trusted, the header is honoured and surfaces in {client_ip}.
    local headers
    headers=$(curl -s -D - -o /dev/null \
        --haproxy-protocol \
        "http://127.0.0.1:8190/")
    if echo "$headers" | grep -qi '^HTTP/.* 200'; then
        pass "pp_v1/trusted_200"
    else
        fail "pp_v1/trusted_200" "expected 200, got: $headers"
    fi
    if echo "$headers" | grep -qi '^X-Client-IP: 127\.'; then
        pass "pp_v1/trusted_client_ip"
    else
        fail "pp_v1/trusted_client_ip" \
            "expected X-Client-IP starting 127., got: $headers"
    fi

    stop_server
}

suite_proxy_protocol_required_when_configured() {
    echo "=== accept-proxy-protocol requires a header ==="
    # Same listener as above, but now connect WITHOUT a PROXY header.
    # hypershunt should fail to parse the (HTTP) bytes as a PROXY header
    # and close the connection.  curl reports a transport-layer error
    # (empty reply / connection reset).
    cat >"$TMPDIR/pp_required.kdl" <<'EOF'
listener "tcp://127.0.0.1:8191" accept-proxy-protocol="v1" {
    trusted-proxies "127.0.0.0/8"
}
vhost localhost {
    location "/" {
        static root="/tmp/www" {
index-file index.html;
}
    }
}
EOF
    "$HYPERSHUNT" --config "$TMPDIR/pp_required.kdl" \
        >"$TMPDIR/hypershunt.out" 2>&1 &
    HYPERSHUNT_PID=$!
    local tries=0
    while ! (echo > /dev/tcp/127.0.0.1/8191) 2>/dev/null; do
        tries=$((tries + 1))
        if [ "$tries" -ge 60 ]; then
            fail "pp_required/start" "listener never bound"
            stop_server
            return
        fi
        sleep 0.05
    done

    # No PROXY header => malformed; hypershunt drops the connection.
    # curl exits non-zero on a transport-level failure.
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 \
        "http://127.0.0.1:8191/") || true
    # On a clean reject we see code "000" (no response).  Anything
    # other than a successful response is a pass.
    if [ "$code" = "000" ] || [ -z "$code" ]; then
        pass "pp_required/no_header_dropped"
    else
        fail "pp_required/no_header_dropped" \
            "expected connection drop, got HTTP $code"
    fi

    stop_server
}

suite_proxy_protocol_allowlist_rejects() {
    echo "=== trusted-proxies allowlist rejects untrusted peer ==="
    # Peer is loopback (127.0.0.1) but the allowlist only admits
    # 10.0.0.0/8.  Even with a valid PROXY header, hypershunt must drop
    # the connection before parsing it.
    cat >"$TMPDIR/pp_untrusted.kdl" <<'EOF'
listener "tcp://127.0.0.1:8192" accept-proxy-protocol="v1" {
    trusted-proxies "10.0.0.0/8"
}
vhost localhost {
    location "/" {
        static root="/tmp/www" {
index-file index.html;
}
    }
}
EOF
    "$HYPERSHUNT" --config "$TMPDIR/pp_untrusted.kdl" \
        >"$TMPDIR/hypershunt.out" 2>&1 &
    HYPERSHUNT_PID=$!
    local tries=0
    while ! (echo > /dev/tcp/127.0.0.1/8192) 2>/dev/null; do
        tries=$((tries + 1))
        if [ "$tries" -ge 60 ]; then
            fail "pp_allowlist/start" "listener never bound"
            stop_server
            return
        fi
        sleep 0.05
    done

    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 \
        --haproxy-protocol \
        "http://127.0.0.1:8192/") || true
    if [ "$code" = "000" ] || [ -z "$code" ]; then
        pass "pp_allowlist/untrusted_dropped"
    else
        fail "pp_allowlist/untrusted_dropped" \
            "expected connection drop, got HTTP $code"
    fi

    stop_server
}
