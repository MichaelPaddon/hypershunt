#!/bin/bash
# Suite: TLS with a self-signed certificate.

suite_tls() {
    echo "=== TLS (self-signed) ==="
    cat >"$TMPDIR/tls.kdl" <<'EOF'
listener "tcp://127.0.0.1:8443" {
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
    start_server "$TMPDIR/tls.kdl" 8443 "https" \
        || { fail "tls/server_start" "hypershunt failed"; return; }

    assert_status "tls/200"  200 "https://127.0.0.1:8443/" -k
    assert_body   "tls/body" "Hello hypershunt" "https://127.0.0.1:8443/" -k

    stop_server
}
