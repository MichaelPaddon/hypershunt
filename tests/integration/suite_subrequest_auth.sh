#!/bin/bash
# Suite: subrequest (external HTTP) authenticator.
#
# Spins up a Python HTTP server that acts as the auth decision endpoint.
# Two hypershunt configs are tested: one pointing at /allow (returns 200 →
# principal becomes Authenticated) and one at /deny (returns 403 →
# principal stays Anonymous → policy denies).

suite_subrequest_auth() {
    echo "=== Subrequest authentication ==="

    # Auth decision backend: /allow → 200, anything else → 403.
    python3 - <<'PYEOF' >/dev/null 2>&1 &
from http.server import HTTPServer, BaseHTTPRequestHandler
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        code = 200 if self.path == "/allow" else 403
        self.send_response(code)
        if code == 200:
            self.send_header("X-Auth-User", "subuser")
        self.send_header("Content-Length", "0")
        self.end_headers()
    def log_message(self, *a): pass
HTTPServer(("127.0.0.1", 9009), H).serve_forever()
PYEOF
    local backend_pid=$!
    BACKEND_PIDS+=("$backend_pid")
    sleep 0.3

    # -- Config pointing at /allow: request should be allowed (200) ----
    cat >"$TMPDIR/subreq_allow.kdl" <<'EOF'
server {
    auth "subrequest" url="http://127.0.0.1:9009/allow"
}
listener "tcp://127.0.0.1:8103"
vhost localhost {
    location "/" {
        static root="/tmp/www" {
index-file index.html;
}
        policy {
            allow authenticated
            deny code=401
        }
    }
}
EOF
    start_server "$TMPDIR/subreq_allow.kdl" 8103 \
        || { fail "subreq/allow_server_start" "hypershunt failed"; return; }

    assert_status "subreq/allow_200" 200 "http://127.0.0.1:8103/"

    stop_server

    # -- Config pointing at /deny: request should be denied (401) ------
    cat >"$TMPDIR/subreq_deny.kdl" <<'EOF'
server {
    auth "subrequest" url="http://127.0.0.1:9009/deny"
}
listener "tcp://127.0.0.1:8103"
vhost localhost {
    location "/" {
        static root="/tmp/www" {
index-file index.html;
}
        policy {
            allow authenticated
            deny code=401
        }
    }
}
EOF
    start_server "$TMPDIR/subreq_deny.kdl" 8103 \
        || { fail "subreq/deny_server_start" "hypershunt failed"; return; }

    assert_status "subreq/deny_401" 401 "http://127.0.0.1:8103/"

    stop_server
    kill "$backend_pid" 2>/dev/null || true
    wait "$backend_pid" 2>/dev/null || true
    BACKEND_PIDS=("${BACKEND_PIDS[@]/$backend_pid}")
}
