#!/bin/bash
# Suite: status page, health endpoints, and compression.

suite_status_page() {
    echo "=== Status page ==="
    cat >"$TMPDIR/status.kdl" <<'EOF'
listener "tcp://127.0.0.1:8084"
vhost localhost {
    location "/" {
        status
    }
}
EOF
    start_server "$TMPDIR/status.kdl" 8084 \
        || { fail "status/server_start" "hypershunt failed"; return; }

    assert_status "status/html_200"    200 "http://127.0.0.1:8084/"
    assert_body   "status/html_body"   "hypershunt" "http://127.0.0.1:8084/"
    assert_status "status/json_200"    200 "http://127.0.0.1:8084/" \
        -H "Accept: application/json"
    assert_body   "status/json_fields" "requests" \
        "http://127.0.0.1:8084/" -H "Accept: application/json"

    stop_server
}

suite_status_metrics() {
    echo "=== Status page: extended metrics ==="
    # One live backend and one dead port so the per-upstream health
    # table shows both, and the dead upstream drives connect-errors.
    _status_spawn_backend 9301 "alpha"

    cat >"$TMPDIR/status-metrics.kdl" <<'EOF'
listener "tcp://127.0.0.1:8086"
vhost localhost {
    location "/status" { status }
    location "/files" { static root="/tmp/www" strip-prefix=#true }
    location "/api" {
        proxy {
            upstream "http://127.0.0.1:9301"
            upstream "http://127.0.0.1:9399"
        }
    }
}
EOF
    start_server "$TMPDIR/status-metrics.kdl" 8086 \
        || { fail "status_metrics/server_start" "hypershunt failed"; return; }

    local url="http://127.0.0.1:8086"
    # Warm up the per-vhost / per-handler / proxy counters before
    # asserting the snapshot reflects them.
    curl -s "$url/files/hello.txt"  >/dev/null
    curl -s "$url/api/" >/dev/null
    curl -s "$url/api/" >/dev/null
    curl -s "$url/missing" >/dev/null

    local js="$url/status?format=json"
    # The newly-surfaced subsystem blocks must all be present.
    assert_body "status_metrics/has_stream"     '"stream"'         "$js"
    assert_body "status_metrics/has_datagram"   '"datagram"'       "$js"
    assert_body "status_metrics/has_proxy_lb"   '"proxy_lb"'       "$js"
    assert_body "status_metrics/has_upstream"   '"proxy_upstream"' "$js"
    assert_body "status_metrics/has_oidc"       '"oidc"'           "$js"
    assert_body "status_metrics/has_http_conns" '"http_conns"'     "$js"
    assert_body "status_metrics/has_by_handler" '"by_handler"'     "$js"
    assert_body "status_metrics/has_by_vhost"   '"by_vhost"'       "$js"
    assert_body "status_metrics/has_upstreams"  '"upstreams"'      "$js"

    # The per-upstream health table lists both configured backends.
    assert_body "status_metrics/upstream_live" "127.0.0.1:9301" "$js"
    assert_body "status_metrics/upstream_dead" "127.0.0.1:9399" "$js"

    # Per-handler / per-vhost breakdown reflects the warm-up traffic.
    assert_body "status_metrics/handler_proxy"  '"handler":"proxy"'  "$js"
    assert_body "status_metrics/handler_static" '"handler":"static"' "$js"
    assert_body "status_metrics/vhost_localhost" '"vhost":"localhost"' "$js"

    stop_server
}

# Minimal HTTP backend returning a fixed body; PID reaped by cleanup().
_status_spawn_backend() {
    local port="$1" name="$2"
    python3 - "$port" "$name" <<'PYEOF' >/dev/null 2>&1 &
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
port = int(sys.argv[1]); name = sys.argv[2].encode()
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", len(name))
        self.end_headers(); self.wfile.write(name)
    def log_message(self, *a): pass
HTTPServer(("127.0.0.1", port), H).serve_forever()
PYEOF
    BACKEND_PIDS+=("$!")
    sleep 0.3
}

suite_compression() {
    echo "=== Compression ==="
    cat >"$TMPDIR/compress.kdl" <<'EOF'
listener "tcp://127.0.0.1:8085"
vhost localhost {
    location "/" {
        static root="/tmp/www"
    }
}
EOF
    start_server "$TMPDIR/compress.kdl" 8085 \
        || { fail "compress/server_start" "hypershunt failed"; return; }

    assert_header "compress/gzip"   "Content-Encoding" "gzip" \
        "http://127.0.0.1:8085/big.txt" -H "Accept-Encoding: gzip"
    assert_header "compress/brotli" "Content-Encoding" "br" \
        "http://127.0.0.1:8085/big.txt" -H "Accept-Encoding: br"
    assert_header "compress/zstd"   "Content-Encoding" "zstd" \
        "http://127.0.0.1:8085/big.txt" -H "Accept-Encoding: zstd"

    # Preference ordering: when a client offers all three encodings,
    # hypershunt picks zstd (best ratio at similar CPU for text).
    assert_header "compress/prefers_zstd_over_all" \
        "Content-Encoding" "zstd" \
        "http://127.0.0.1:8085/big.txt" \
        -H "Accept-Encoding: gzip, br, zstd"
    # zstd-only Accept-Encoding must still negotiate zstd.
    assert_header "compress/zstd_only" "Content-Encoding" "zstd" \
        "http://127.0.0.1:8085/big.txt" -H "Accept-Encoding: zstd"

    # Roundtrip: the zstd-encoded body must decode back to the
    # original file byte-for-byte.  Use the zstd CLI we shipped in
    # the Containerfile so this doesn't depend on curl's --compressed
    # support (Debian curl may or may not have zstd compiled in).
    local got want
    want=$(md5sum /tmp/www/big.txt | awk '{print $1}')
    got=$(curl -s -H "Accept-Encoding: zstd" \
        --output - "http://127.0.0.1:8085/big.txt" \
        | zstd -dc | md5sum | awk '{print $1}')
    if [ "$want" = "$got" ]; then
        pass "compress/zstd_roundtrip"
    else
        fail "compress/zstd_roundtrip" \
            "decoded md5 $got != original $want"
    fi

    stop_server
}

suite_health_endpoint() {
    echo "=== Health endpoint ==="
    cat >"$TMPDIR/health.kdl" <<'EOF'
listener "tcp://127.0.0.1:8092"
vhost localhost {
    location "/" {
        redirect to="/other" code=301
    }
}
EOF
    start_server "$TMPDIR/health.kdl" 8092 \
        || { fail "health/server_start" "hypershunt failed"; return; }

    # /healthz, /livez, /readyz are intercepted before routing.
    assert_status "health/healthz_200"  200 "http://127.0.0.1:8092/healthz"
    assert_status "health/livez_200"    200 "http://127.0.0.1:8092/livez"
    assert_status "health/readyz_200"   200 "http://127.0.0.1:8092/readyz"
    assert_header "health/content_type" "Content-Type" "application/json" \
        "http://127.0.0.1:8092/healthz"
    assert_body   "health/body_ok"      '"ok"' "http://127.0.0.1:8092/healthz"
    # Other paths fall through to the redirect handler.
    assert_status "health/other_301" 301 \
        "http://127.0.0.1:8092/" --no-location

    stop_server
}
