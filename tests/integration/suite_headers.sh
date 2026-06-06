#!/bin/bash
# Suite: response and request header injection.

suite_response_headers() {
    echo "=== Response header injection ==="
    cat >"$TMPDIR/resphdrs.kdl" <<'EOF'
listener "tcp://127.0.0.1:8096"
vhost localhost {
    location "/" {
        response-headers {
            set "X-Frame-Options" "DENY"
        }
        static root="/tmp/www"
    }
}
EOF
    start_server "$TMPDIR/resphdrs.kdl" 8096 \
        || { fail "resp_headers/server_start" "hypershunt failed"; return; }

    assert_status "resp_headers/200" 200 \
        "http://127.0.0.1:8096/hello.txt"
    assert_header "resp_headers/x_frame" "X-Frame-Options" "DENY" \
        "http://127.0.0.1:8096/hello.txt"

    stop_server
}

suite_request_headers() {
    echo "=== Request header injection ==="
    # Minimal backend: echoes the X-Injected request header as the body.
    python3 - <<'PYEOF' >/dev/null 2>&1 &
from http.server import HTTPServer, BaseHTTPRequestHandler
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        v = self.headers.get("x-injected", "absent").encode()
        self.send_response(200)
        self.send_header("Content-Length", len(v))
        self.end_headers()
        self.wfile.write(v)
    def log_message(self, *a): pass
HTTPServer(("127.0.0.1", 9004), H).serve_forever()
PYEOF
    local backend_pid=$!
    BACKEND_PIDS+=("$backend_pid")
    sleep 0.3

    cat >"$TMPDIR/reqhdrs.kdl" <<'EOF'
listener "tcp://127.0.0.1:8097"
vhost localhost {
    location "/" {
        request-headers {
            set "X-Injected" "hello-from-hypershunt"
        }
        proxy {
 upstream "http://127.0.0.1:9004";
}
    }
}
EOF
    start_server "$TMPDIR/reqhdrs.kdl" 8097 \
        || { fail "req_headers/server_start" "hypershunt failed"; return; }

    assert_body "req_headers/injected" "hello-from-hypershunt" \
        "http://127.0.0.1:8097/"

    stop_server
    kill "$backend_pid" 2>/dev/null || true
    wait "$backend_pid" 2>/dev/null || true
    BACKEND_PIDS=("${BACKEND_PIDS[@]/$backend_pid}")
}
