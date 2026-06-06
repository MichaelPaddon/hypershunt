#!/bin/bash
# Suite: CGI handler.

suite_cgi() {
    echo "=== CGI ==="
    mkdir -p /tmp/cgi-bin
    cat > /tmp/cgi-bin/hello.sh <<'SCRIPT'
#!/bin/sh
printf "Status: 200 OK\r\n"
printf "Content-Type: text/plain\r\n"
printf "\r\n"
printf "CGI works\r\n"
SCRIPT
    chmod +x /tmp/cgi-bin/hello.sh

    cat >"$TMPDIR/cgi.kdl" <<'EOF'
listener "tcp://127.0.0.1:8087"
vhost localhost {
    location "/" {
        cgi root="/tmp/cgi-bin"
    }
}
EOF
    start_server "$TMPDIR/cgi.kdl" 8087 \
        || { fail "cgi/server_start" "hypershunt failed"; return; }

    assert_status "cgi/200"           200 "http://127.0.0.1:8087/hello.sh"
    assert_body   "cgi/body"          "CGI works" \
        "http://127.0.0.1:8087/hello.sh"
    assert_status "cgi/404_missing"   404 \
        "http://127.0.0.1:8087/nosuchscript.sh"
    # Directory request (trailing slash) must return 404 per CgiHandler.
    assert_status "cgi/404_directory" 404 "http://127.0.0.1:8087/"

    stop_server
}
