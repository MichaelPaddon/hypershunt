#!/bin/bash
# Suite: multi-upstream reverse-proxy load balancing.
#
# Covers round-robin distribution, header-hash affinity, retry
# fall-through on 5xx, and the active health-check task ejecting
# a backend that goes away.

# Spawn a tiny Python HTTP backend that returns `name` as its body
# on every request.  Stores PID in BACKEND_PIDS so the global
# cleanup() trap reaps it.
_lb_spawn_backend() {
    local port="$1" name="$2"
    python3 - "$port" "$name" <<'PYEOF' >/dev/null 2>&1 &
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
port = int(sys.argv[1])
name = sys.argv[2].encode()
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", len(name))
        self.end_headers()
        self.wfile.write(name)
    def log_message(self, *a): pass
HTTPServer(("127.0.0.1", port), H).serve_forever()
PYEOF
    BACKEND_PIDS+=("$!")
    sleep 0.3
}

# Spawn a backend that returns a fixed `status` to every request.
_lb_spawn_status_backend() {
    local port="$1" status="$2"
    python3 - "$port" "$status" <<'PYEOF' >/dev/null 2>&1 &
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
port = int(sys.argv[1])
status = int(sys.argv[2])
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.end_headers()
    def log_message(self, *a): pass
HTTPServer(("127.0.0.1", port), H).serve_forever()
PYEOF
    BACKEND_PIDS+=("$!")
    sleep 0.3
}

# 10 backend requests across three RR upstreams must visit every
# upstream at least once.  (Exact ratios are weight-dependent and
# can drift under in-flight skew; visiting all three is the
# regression we actually care about.)
suite_proxy_lb_round_robin() {
    echo "=== Proxy LB: round-robin distribution ==="
    _lb_spawn_backend 9201 "alpha"
    _lb_spawn_backend 9202 "bravo"
    _lb_spawn_backend 9203 "charlie"

    cat >"$TMPDIR/lb_rr.kdl" <<'EOF'
listener "tcp://127.0.0.1:8201"
vhost localhost {
    location "/" {
        proxy {

            upstream "http://127.0.0.1:9201"
            upstream "http://127.0.0.1:9202"
            upstream "http://127.0.0.1:9203"
            lb-policy "round-robin"
}
    }
}
EOF
    start_server "$TMPDIR/lb_rr.kdl" 8201 \
        || { fail "lb_rr/server_start" "hypershunt failed"; return; }

    local seen=""
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        seen+="$(curl -s --max-time 5 http://127.0.0.1:8201/) "
    done
    for who in alpha bravo charlie; do
        if echo "$seen" | grep -q "$who"; then
            pass "lb_rr/visited_$who"
        else
            fail "lb_rr/visited_$who" "never landed on $who; seen=$seen"
        fi
    done

    stop_server
}

# header-hash with a stable X-Session-Id header must route every
# request to the same upstream.  Different header values must be
# capable of resolving to different upstreams (sanity).
suite_proxy_lb_header_hash() {
    echo "=== Proxy LB: header-hash affinity ==="
    _lb_spawn_backend 9211 "ha"
    _lb_spawn_backend 9212 "hb"

    cat >"$TMPDIR/lb_hh.kdl" <<'EOF'
listener "tcp://127.0.0.1:8211"
vhost localhost {
    location "/" {
        proxy {

            upstream "http://127.0.0.1:9211"
            upstream "http://127.0.0.1:9212"
            lb-policy "header-hash" header="X-Session-Id"
}
    }
}
EOF
    start_server "$TMPDIR/lb_hh.kdl" 8211 \
        || { fail "lb_hh/server_start" "hypershunt failed"; return; }

    # Same session id, 6 calls: every response identical.
    local first=""
    local stable=1
    for _ in 1 2 3 4 5 6; do
        local got
        got=$(curl -s --max-time 5 \
            -H "X-Session-Id: sticky-1" \
            http://127.0.0.1:8211/)
        if [ -z "$first" ]; then
            first="$got"
        elif [ "$got" != "$first" ]; then
            stable=0
        fi
    done
    if [ "$stable" -eq 1 ]; then
        pass "lb_hh/sticky_one_session"
    else
        fail "lb_hh/sticky_one_session" "varied across calls"
    fi

    # Probe several session ids; at least two distinct upstreams
    # should be hit over the sample space.
    local distinct=""
    for sid in s1 s2 s3 s4 s5 s6 s7 s8; do
        local got
        got=$(curl -s --max-time 5 \
            -H "X-Session-Id: $sid" \
            http://127.0.0.1:8211/)
        case "$distinct" in
            *"$got"*) ;;
            *) distinct+=" $got" ;;
        esac
    done
    if [ "$(echo "$distinct" | wc -w)" -ge 2 ]; then
        pass "lb_hh/spreads_across_sessions"
    else
        fail "lb_hh/spreads_across_sessions" "single bucket: $distinct"
    fi

    stop_server
}

# retry { max 1; on-status 503 } with backend A always returning
# 503 and backend B returning 200: every request should resolve to
# 200 from B regardless of which backend RR picks first.
suite_proxy_lb_retry() {
    echo "=== Proxy LB: retry falls through on 503 ==="
    _lb_spawn_status_backend 9221 503
    _lb_spawn_backend       9222 "served-by-b"

    cat >"$TMPDIR/lb_retry.kdl" <<'EOF'
listener "tcp://127.0.0.1:8221"
vhost localhost {
    location "/" {
        proxy {

            upstream "http://127.0.0.1:9221"
            upstream "http://127.0.0.1:9222"
            lb-policy "round-robin"
            retry max=1 {
on-status 503
}
}
    }
}
EOF
    start_server "$TMPDIR/lb_retry.kdl" 8221 \
        || { fail "lb_retry/server_start" "hypershunt failed"; return; }

    # 4 calls -- both initial picks (RR cycles A,B,A,B) should yield
    # the working backend's body after the retry.
    local all_ok=1
    for _ in 1 2 3 4; do
        local got
        got=$(curl -s --max-time 5 http://127.0.0.1:8221/)
        if [ "$got" != "served-by-b" ]; then
            all_ok=0
            break
        fi
    done
    if [ "$all_ok" -eq 1 ]; then
        pass "lb_retry/always_resolves_to_b"
    else
        fail "lb_retry/always_resolves_to_b" "saw '$got'"
    fi

    stop_server
}

# Active health check ejects a backend that went away.  Two RR
# upstreams; we kill one mid-test and a short interval window
# later all traffic should be on the survivor.
suite_proxy_lb_active_health() {
    echo "=== Proxy LB: active health check ejects dead backend ==="
    _lb_spawn_backend 9231 "live-a"
    _lb_spawn_backend 9232 "live-b"
    local a_pid="${BACKEND_PIDS[-2]}"

    cat >"$TMPDIR/lb_hc.kdl" <<'EOF'
listener "tcp://127.0.0.1:8231"
vhost localhost {
    location "/" {
        proxy {

            upstream "http://127.0.0.1:9231"
            upstream "http://127.0.0.1:9232"
            lb-policy "round-robin"
            active-health path="/" interval=1 timeout=1 unhealthy-after=1 healthy-after=1
}
    }
}
EOF
    start_server "$TMPDIR/lb_hc.kdl" 8231 \
        || { fail "lb_hc/server_start" "hypershunt failed"; return; }

    # Both should be reachable up-front.
    local up_seen=""
    for _ in 1 2 3 4 5 6; do
        up_seen+="$(curl -s --max-time 5 http://127.0.0.1:8231/) "
    done
    if echo "$up_seen" | grep -q "live-a" \
        && echo "$up_seen" | grep -q "live-b"; then
        pass "lb_hc/both_reachable_initially"
    else
        fail "lb_hc/both_reachable_initially" "seen=$up_seen"
    fi

    # Kill backend A and wait long enough for two probe ticks +
    # ejection: interval=1s, unhealthy-after=1.
    kill "$a_pid" 2>/dev/null || true
    wait "$a_pid" 2>/dev/null || true
    BACKEND_PIDS=("${BACKEND_PIDS[@]/$a_pid}")
    sleep 4

    local after=""
    for _ in 1 2 3 4 5 6; do
        local got
        got=$(curl -s --max-time 5 http://127.0.0.1:8231/)
        after+="$got "
    done
    if ! echo "$after" | grep -q "live-a" \
        && echo "$after" | grep -q "live-b"; then
        pass "lb_hc/dead_backend_ejected"
    else
        fail "lb_hc/dead_backend_ejected" \
            "still seeing live-a or no live-b: $after"
    fi

    stop_server
}
