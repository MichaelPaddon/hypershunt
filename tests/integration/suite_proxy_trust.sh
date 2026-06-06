#!/bin/bash
# Suite: proxy trust + timeout knobs (Phase 5 surface).
#
# Exercises `tls { skip-verify }` on the proxy handler against a
# self-signed h1/h2 upstream, and `connect-timeout` against an
# unreachable address.

suite_proxy_skip_verify() {
    echo "=== Proxy tls { skip-verify } ==="
    # Upstream: a second hypershunt instance with a self-signed cert.
    cat >"$TMPDIR/upstream_tls.kdl" <<'EOF'
listener "tcp://127.0.0.1:18450" {
    tls "self-signed"
}
vhost localhost {
    location "/" {
        static root="/tmp/www" {
index-file index.html;
}
    }
}
EOF
    "$HYPERSHUNT" --config "$TMPDIR/upstream_tls.kdl" \
        >"$TMPDIR/upstream_tls.out" 2>&1 &
    local up_pid=$!
    BACKEND_PIDS+=("$up_pid")
    # Wait for the upstream to come up.
    local tries=0
    while true; do
        local code
        code=$(curl -sk -o /dev/null -w "%{http_code}" \
            --max-time 0.5 --connect-timeout 0.5 \
            "https://127.0.0.1:18450/") || code=""
        [ -n "$code" ] && [ "$code" != "000" ] && break
        tries=$((tries + 1))
        if [ "$tries" -ge 60 ]; then
            fail "proxy_skip_verify/upstream_start" "tls upstream never came up"
            kill "$up_pid" 2>/dev/null || true
            return
        fi
        sleep 0.1
    done

    # Frontend proxy with skip-verify ON.  Without this knob the
    # webpki verifier would reject the self-signed cert, surfacing
    # as a 502 from hypershunt.
    cat >"$TMPDIR/proxy_skip.kdl" <<'EOF'
listener "tcp://127.0.0.1:8091"
vhost localhost {
    location "/" {
        proxy {

            upstream "https://127.0.0.1:18450/"
            tls skip-verify=#true
}
    }
}
EOF
    start_server "$TMPDIR/proxy_skip.kdl" 8091 \
        || { fail "proxy_skip_verify/frontend" "frontend failed";
             kill "$up_pid" 2>/dev/null || true; return; }

    assert_status "proxy_skip_verify/200"  200 "http://127.0.0.1:8091/"
    assert_body   "proxy_skip_verify/body" "Hello hypershunt" \
        "http://127.0.0.1:8091/"

    stop_server
    kill "$up_pid" 2>/dev/null || true
    wait "$up_pid" 2>/dev/null || true
    BACKEND_PIDS=("${BACKEND_PIDS[@]/$up_pid}")

    # Counter-check: without skip-verify, the same setup should 502.
    "$HYPERSHUNT" --config "$TMPDIR/upstream_tls.kdl" \
        >"$TMPDIR/upstream_tls.out" 2>&1 &
    up_pid=$!
    BACKEND_PIDS+=("$up_pid")
    tries=0
    while true; do
        local code
        code=$(curl -sk -o /dev/null -w "%{http_code}" \
            --max-time 0.5 --connect-timeout 0.5 \
            "https://127.0.0.1:18450/") || code=""
        [ -n "$code" ] && [ "$code" != "000" ] && break
        tries=$((tries + 1))
        if [ "$tries" -ge 60 ]; then
            fail "proxy_skip_verify/upstream_restart" "did not come back up"
            kill "$up_pid" 2>/dev/null || true
            return
        fi
        sleep 0.1
    done
    cat >"$TMPDIR/proxy_noskip.kdl" <<'EOF'
listener "tcp://127.0.0.1:8092"
vhost localhost {
    location "/" {
        proxy {

            upstream "https://127.0.0.1:18450/"
}
    }
}
EOF
    start_server "$TMPDIR/proxy_noskip.kdl" 8092 \
        || { fail "proxy_skip_verify/noskip_frontend" "frontend failed";
             kill "$up_pid" 2>/dev/null || true; return; }

    assert_status "proxy_skip_verify/no_skip_is_502" \
        502 "http://127.0.0.1:8092/"

    stop_server
    kill "$up_pid" 2>/dev/null || true
    wait "$up_pid" 2>/dev/null || true
    BACKEND_PIDS=("${BACKEND_PIDS[@]/$up_pid}")
}

suite_proxy_connect_timeout() {
    echo "=== Proxy connect-timeout ==="
    # TEST-NET-1 (RFC 5737) is reserved and not routable.  Sending
    # a SYN there should yield a long OS-level wait; the
    # connect-timeout knob caps it at 1 s so the proxy returns 502
    # quickly enough that the test stays under 5 s end-to-end.
    cat >"$TMPDIR/proxy_ctimeout.kdl" <<'EOF'
listener "tcp://127.0.0.1:8093"
vhost localhost {
    location "/" {
        proxy connect-timeout=1 {

            upstream "http://192.0.2.1:81/"
}
    }
}
EOF
    # Skip the standard start_server probe -- it issues GET / which
    # always takes ~1 s because of the connect-timeout we're testing.
    # The probe uses --max-time 0.5 so it would never see a response
    # before timing out 60 times.  Sleep briefly and verify hypershunt
    # bound the listener via /dev/tcp.
    "$HYPERSHUNT" --config "$TMPDIR/proxy_ctimeout.kdl" \
        >"$TMPDIR/hypershunt.out" 2>&1 &
    HYPERSHUNT_PID=$!
    local tries=0
    while ! (echo > /dev/tcp/127.0.0.1/8093) 2>/dev/null; do
        tries=$((tries + 1))
        if [ "$tries" -ge 60 ]; then
            fail "proxy_ctimeout/frontend" "listener never bound"
            stop_server
            return
        fi
        sleep 0.05
    done

    local start end elapsed
    start=$(date +%s%N)
    assert_status "proxy_ctimeout/502" 502 \
        "http://127.0.0.1:8093/" --max-time 5
    end=$(date +%s%N)
    elapsed=$(( (end - start) / 1000000 )) # ms

    # Should complete in well under 5 s.  Allow generous slack for
    # slow CI: pass if under 3 s.
    if [ "$elapsed" -lt 3000 ]; then
        pass "proxy_ctimeout/fast (${elapsed}ms)"
    else
        fail "proxy_ctimeout/fast" \
            "connect-timeout=1 should make this fast; took ${elapsed}ms"
    fi

    stop_server
}
