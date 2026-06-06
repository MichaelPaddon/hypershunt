#!/bin/bash
# Suite: HTTP reverse proxy (TCP and Unix socket upstreams).

suite_reverse_proxy() {
    echo "=== Reverse proxy ==="
    python3 -m http.server 9001 --directory /tmp/www \
        >/dev/null 2>&1 &
    local backend_pid=$!
    BACKEND_PIDS+=("$backend_pid")
    sleep 0.3

    cat >"$TMPDIR/proxy.kdl" <<'EOF'
listener "tcp://127.0.0.1:8086"
vhost localhost {
    location "/" {
        proxy {
 upstream "http://127.0.0.1:9001";
}
    }
}
EOF
    start_server "$TMPDIR/proxy.kdl" 8086 \
        || { fail "proxy/server_start" "hypershunt failed"; return; }

    assert_status "proxy/200"  200 "http://127.0.0.1:8086/"
    assert_body   "proxy/body" "Hello hypershunt" "http://127.0.0.1:8086/"

    stop_server
    kill "$backend_pid" 2>/dev/null || true
    wait "$backend_pid" 2>/dev/null || true
    BACKEND_PIDS=("${BACKEND_PIDS[@]/$backend_pid}")
}

suite_reverse_proxy_unix() {
    echo "=== Reverse proxy (Unix socket) ==="
    local sock="$TMPDIR/proxy_backend.sock"
    python3 - "$sock" <<'PYEOF' >/dev/null 2>&1 &
import socket, sys, threading
srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
srv.bind(sys.argv[1])
srv.listen(10)
body = b"proxy-unix-ok"
def handle(conn):
    try:
        conn.recv(4096)
        conn.sendall(
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Length: 13\r\n"
            b"Connection: close\r\n"
            b"\r\n"
            + body
        )
    finally:
        conn.close()
while True:
    conn, _ = srv.accept()
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
PYEOF
    local backend_pid=$!
    BACKEND_PIDS+=("$backend_pid")
    sleep 0.3

    cat >"$TMPDIR/proxy_unix.kdl" <<EOF
listener "tcp://127.0.0.1:8090"
vhost localhost {
    location "/" {
        proxy {
 upstream "unix:$sock";
}
    }
}
EOF
    start_server "$TMPDIR/proxy_unix.kdl" 8090 \
        || { fail "proxy_unix/server_start" "hypershunt failed"; return; }

    assert_status "proxy_unix/200"  200 "http://127.0.0.1:8090/"
    assert_body   "proxy_unix/body" "proxy-unix-ok" "http://127.0.0.1:8090/"

    stop_server
    kill "$backend_pid" 2>/dev/null || true
    wait "$backend_pid" 2>/dev/null || true
    BACKEND_PIDS=("${BACKEND_PIDS[@]/$backend_pid}")
}

suite_proxy_x_forwarded_for() {
    echo "=== Proxy X-Forwarded-For ==="
    # Backend echoes the X-Forwarded-For request header as the response body.
    python3 - <<'PYEOF' >/dev/null 2>&1 &
from http.server import HTTPServer, BaseHTTPRequestHandler
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        v = self.headers.get("x-forwarded-for", "absent").encode()
        self.send_response(200)
        self.send_header("Content-Length", len(v))
        self.end_headers()
        self.wfile.write(v)
    def log_message(self, *a): pass
HTTPServer(("127.0.0.1", 9007), H).serve_forever()
PYEOF
    local backend_pid=$!
    BACKEND_PIDS+=("$backend_pid")
    sleep 0.3

    cat >"$TMPDIR/proxy_xff.kdl" <<'EOF'
listener "tcp://127.0.0.1:8105"
vhost localhost {
    location "/" {
        proxy {
 upstream "http://127.0.0.1:9007";
}
    }
}
EOF
    start_server "$TMPDIR/proxy_xff.kdl" 8105 \
        || { fail "proxy_xff/server_start" "hypershunt failed"; return; }

    # Proxy must append the client address to X-Forwarded-For.
    assert_body "proxy_xff/header_set" "127.0.0.1" \
        "http://127.0.0.1:8105/"
    # Existing X-Forwarded-For must be extended, not replaced.
    assert_body "proxy_xff/header_extended" "10.0.0.1" \
        "http://127.0.0.1:8105/" -H "X-Forwarded-For: 10.0.0.1"

    stop_server
    kill "$backend_pid" 2>/dev/null || true
    wait "$backend_pid" 2>/dev/null || true
    BACKEND_PIDS=("${BACKEND_PIDS[@]/$backend_pid}")
}

suite_proxy_strip_prefix() {
    echo "=== Proxy strip-prefix ==="
    # Backend echoes the request path so we can verify prefix stripping.
    python3 - <<'PYEOF' >/dev/null 2>&1 &
from http.server import HTTPServer, BaseHTTPRequestHandler
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        v = self.path.encode()
        self.send_response(200)
        self.send_header("Content-Length", len(v))
        self.end_headers()
        self.wfile.write(v)
    def log_message(self, *a): pass
HTTPServer(("127.0.0.1", 9008), H).serve_forever()
PYEOF
    local backend_pid=$!
    BACKEND_PIDS+=("$backend_pid")
    sleep 0.3

    cat >"$TMPDIR/proxy_strip.kdl" <<'EOF'
listener "tcp://127.0.0.1:8106"
vhost localhost {
    location "/api/" {
        proxy {
 upstream "http://127.0.0.1:9008"; strip-prefix #true;
}
    }
}
EOF
    start_server "$TMPDIR/proxy_strip.kdl" 8106 \
        || { fail "proxy_strip/server_start" "hypershunt failed"; return; }

    # /api/data → upstream sees /data (prefix stripped).
    assert_body "proxy_strip/stripped" "/data" \
        "http://127.0.0.1:8106/api/data"
    # /api/ → upstream sees / (prefix is the whole matched path).
    assert_body "proxy_strip/root" "/" \
        "http://127.0.0.1:8106/api/"

    stop_server
    kill "$backend_pid" 2>/dev/null || true
    wait "$backend_pid" 2>/dev/null || true
    BACKEND_PIDS=("${BACKEND_PIDS[@]/$backend_pid}")
}
