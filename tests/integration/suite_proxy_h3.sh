#!/bin/bash
# Suite: HTTP/3 reverse proxy (scheme=h3 forced, and scheme=auto
# with Alt-Svc auto-upgrade).
#
# Spawns a second hypershunt instance as the upstream so the frontend
# can speak h3 to it.  The upstream exposes the built-in status
# page so we can read `http3.requests_total` to confirm requests
# actually arrived over h3.

# Start an upstream hypershunt listening on the given TCP+UDP port pair.
# Same-port listeners trigger hypershunt's auto-Alt-Svc behaviour: TCP
# responses advertise the matching h3 endpoint, which is exactly
# what the auto-upgrade path in the proxy looks for.
_start_h3_upstream() {
    local port="$1" cfg="$2"
    cat >"$cfg" <<EOF
listener "tcp://127.0.0.1:${port}" {
    tls "self-signed"
}
listener "udp://127.0.0.1:${port}" {
    quic { tls "self-signed" }
}
vhost localhost {
    location "/" {
        static root="/tmp/www" {
            index-file "index.html"
        }
    }
    location "/status" {
        status
    }
}
EOF
    "$HYPERSHUNT" --config "$cfg" >"$TMPDIR/upstream.out" 2>&1 &
    UPSTREAM_PID=$!
    # Wait on the TCP side.
    local tries=0
    while true; do
        local code
        code=$(curl -sk -o /dev/null -w "%{http_code}" \
            --max-time 0.5 --connect-timeout 0.5 \
            "https://127.0.0.1:${port}/") || code=""
        [ -n "$code" ] && [ "$code" != "000" ] && return 0
        tries=$((tries + 1))
        if [ "$tries" -ge 60 ]; then
            echo "  ERROR: upstream did not start on port $port" >&2
            cat "$TMPDIR/upstream.out" >&2
            return 1
        fi
        sleep 0.1
    done
}

_stop_h3_upstream() {
    if [ -n "${UPSTREAM_PID:-}" ]; then
        kill -TERM "$UPSTREAM_PID" 2>/dev/null || true
        # Same SIGKILL-after-grace escalation as stop_server: the QUIC
        # drain holds for up to 30 s on stale connections, which adds
        # up across the h3 suites.
        local waited=0
        while kill -0 "$UPSTREAM_PID" 2>/dev/null; do
            sleep 0.1
            waited=$((waited + 1))
            if [ "$waited" -ge 20 ]; then
                kill -KILL "$UPSTREAM_PID" 2>/dev/null || true
                break
            fi
        done
        wait "$UPSTREAM_PID" 2>/dev/null || true
        UPSTREAM_PID=""
    fi
}

# Read the upstream's `quic_requests_total` counter from its status
# JSON.  Echoes the number to stdout, or 0 if the page can't be
# parsed.
_upstream_h3_requests() {
    local port="$1"
    curl -sk --max-time 2 \
        "https://127.0.0.1:${port}/status?format=json" 2>/dev/null \
      | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
    print(d.get("http3", {}).get("requests_total", 0))
except Exception:
    print(0)
'
}

suite_proxy_h3_forced() {
    echo "=== Reverse proxy with scheme=h3 ==="
    _start_h3_upstream 18445 "$TMPDIR/upstream_h3.kdl" \
        || { fail "proxy_h3/upstream" "upstream failed"; return; }

    cat >"$TMPDIR/proxy_h3.kdl" <<'EOF'
listener "tcp://127.0.0.1:8087"
vhost localhost {
    location "/" {
        proxy scheme="h3" {

            upstream "https://127.0.0.1:18445/"

            tls skip-verify=#true
}
    }
}
EOF
    start_server "$TMPDIR/proxy_h3.kdl" 8087 \
        || { fail "proxy_h3/frontend" "frontend failed"; _stop_h3_upstream; return; }

    local before after
    before=$(_upstream_h3_requests 18445)

    assert_status "proxy_h3/200"  200 "http://127.0.0.1:8087/"
    assert_body   "proxy_h3/body" "Hello hypershunt" "http://127.0.0.1:8087/"

    # Counter must have advanced by at least 1; that proves the
    # request actually reached the upstream over h3 rather than
    # silently falling back to h1/h2.
    after=$(_upstream_h3_requests 18445)
    if [ "$after" -gt "$before" ]; then
        pass "proxy_h3/observed_on_upstream"
    else
        fail "proxy_h3/observed_on_upstream" \
            "quic_requests_total stayed at $before"
    fi

    stop_server
    _stop_h3_upstream
}

suite_proxy_h3_altsvc_expires() {
    echo "=== Alt-Svc auto-upgrade cache TTL expires ==="
    # Upstream advertises h3 with a short ma=2 instead of the default
    # 86400 via response-headers.  After ma seconds elapse, the cache
    # entry expires and the proxy should fall back to h1/h2 on
    # subsequent requests.
    cat >"$TMPDIR/upstream_ttl.kdl" <<'EOF'
listener "tcp://127.0.0.1:18447" { tls "self-signed"
}
listener "udp://127.0.0.1:18447" { quic { tls "self-signed" }
}
vhost localhost {
    location "/" {
        static root="/tmp/www" {
index-file index.html;
}
        response-headers {
            set "Alt-Svc" "h3=\":18447\"; ma=2"
        }
    }
    location "/status" {
        status
    }
}
EOF
    "$HYPERSHUNT" --config "$TMPDIR/upstream_ttl.kdl" \
        >"$TMPDIR/upstream_ttl.out" 2>&1 &
    UPSTREAM_PID=$!
    local tries=0
    while true; do
        local code
        code=$(curl -sk -o /dev/null -w "%{http_code}" \
            --max-time 0.5 --connect-timeout 0.5 \
            "https://127.0.0.1:18447/") || code=""
        [ -n "$code" ] && [ "$code" != "000" ] && break
        tries=$((tries + 1))
        if [ "$tries" -ge 60 ]; then
            fail "proxy_altsvc_ttl/upstream" "upstream never came up"
            return
        fi
        sleep 0.1
    done

    cat >"$TMPDIR/proxy_ttl.kdl" <<'EOF'
listener "tcp://127.0.0.1:8089"
vhost localhost {
    location "/" {
        proxy {

            upstream "https://127.0.0.1:18447/"
            tls skip-verify=#true
}
    }
}
EOF
    "$HYPERSHUNT" --config "$TMPDIR/proxy_ttl.kdl" \
        >"$TMPDIR/hypershunt.out" 2>&1 &
    HYPERSHUNT_PID=$!
    tries=0
    while ! (echo > /dev/tcp/127.0.0.1/8089) 2>/dev/null; do
        tries=$((tries + 1))
        if [ "$tries" -ge 60 ]; then
            fail "proxy_altsvc_ttl/frontend" "frontend never bound"
            stop_server
            _stop_h3_upstream
            return
        fi
        sleep 0.05
    done

    local h3_before h3_after_warm h3_after_expire

    h3_before=$(_upstream_h3_requests 18447)

    # Request 1 (cold cache): goes via h1/h2.
    assert_status "proxy_altsvc_ttl/req1" 200 "http://127.0.0.1:8089/"

    # Request 2 (warm cache, ma=2 not yet elapsed): goes via h3.
    assert_status "proxy_altsvc_ttl/req2" 200 "http://127.0.0.1:8089/"
    h3_after_warm=$(_upstream_h3_requests 18447)
    if [ "$h3_after_warm" -gt "$h3_before" ]; then
        pass "proxy_altsvc_ttl/req2_via_h3"
    else
        fail "proxy_altsvc_ttl/req2_via_h3" \
            "expected h3 upgrade for second request \
             ($h3_before -> $h3_after_warm)"
    fi

    # Wait past the ma=2 cache window.  Add slack for clock drift.
    sleep 3

    # Request 3 (expired cache): falls back to h1/h2.  The
    # quic_requests_total counter must NOT advance over this
    # request because the path doesn't touch QUIC.
    assert_status "proxy_altsvc_ttl/req3" 200 "http://127.0.0.1:8089/"
    h3_after_expire=$(_upstream_h3_requests 18447)
    if [ "$h3_after_expire" -eq "$h3_after_warm" ]; then
        pass "proxy_altsvc_ttl/req3_via_h1h2"
    else
        fail "proxy_altsvc_ttl/req3_via_h1h2" \
            "expected h1/h2 after cache expiry; counter advanced \
             $h3_after_warm -> $h3_after_expire"
    fi

    stop_server
    _stop_h3_upstream
}

suite_proxy_h3_autoupgrade() {
    echo "=== Reverse proxy auto-upgrade via Alt-Svc ==="
    _start_h3_upstream 18446 "$TMPDIR/upstream_auto.kdl" \
        || { fail "proxy_auto/upstream" "upstream failed"; return; }

    cat >"$TMPDIR/proxy_auto.kdl" <<'EOF'
listener "tcp://127.0.0.1:8088"
vhost localhost {
    location "/" {
        proxy {

            upstream "https://127.0.0.1:18446/"
            // scheme defaults to "auto" -- forces h1/h2 on the first
            // hit, observes the upstream's Alt-Svc header, and
            // upgrades subsequent requests to h3.
            tls skip-verify=#true
}
    }
}
EOF
    # Bypass start_server's curl probe: that probe would *itself*
    # be a request through the proxy, which would prime the Alt-Svc
    # cache before the test's "first request" actually runs.  Wait
    # for the TCP listen socket to bind instead.
    "$HYPERSHUNT" --config "$TMPDIR/proxy_auto.kdl" \
        >"$TMPDIR/hypershunt.out" 2>&1 &
    HYPERSHUNT_PID=$!
    local tries=0
    while ! (echo > /dev/tcp/127.0.0.1/8088) 2>/dev/null; do
        tries=$((tries + 1))
        if [ "$tries" -ge 60 ]; then
            fail "proxy_auto/frontend" "frontend never bound port 8088"
            stop_server
            _stop_h3_upstream
            return
        fi
        sleep 0.05
    done

    local before mid after
    before=$(_upstream_h3_requests 18446)

    # First request: must succeed via h1/h2 (no Alt-Svc cache yet).
    assert_status "proxy_auto/first" 200 "http://127.0.0.1:8088/"
    mid=$(_upstream_h3_requests 18446)
    if [ "$mid" -eq "$before" ]; then
        pass "proxy_auto/first_via_h1h2"
    else
        fail "proxy_auto/first_via_h1h2" \
            "first request unexpectedly arrived over h3 (cnt $before -> $mid)"
    fi

    # Second request: Alt-Svc cache is armed; we should now upgrade.
    assert_status "proxy_auto/second" 200 "http://127.0.0.1:8088/"
    after=$(_upstream_h3_requests 18446)
    if [ "$after" -gt "$mid" ]; then
        pass "proxy_auto/second_via_h3"
    else
        fail "proxy_auto/second_via_h3" \
            "upgrade didn't happen (cnt $mid -> $after)"
    fi

    stop_server
    _stop_h3_upstream
}
