#!/bin/bash
# Suite: static file serving and redirects.

suite_static_files() {
    echo "=== Static files ==="
    cat >"$TMPDIR/static.kdl" <<'EOF'
listener "tcp://127.0.0.1:8080"
vhost localhost {
    location "/" {
        static root="/tmp/www" {
index-file index.html;
}
    }
}
EOF
    start_server "$TMPDIR/static.kdl" 8080 \
        || { fail "static/server_start" "hypershunt failed"; return; }

    assert_status "static/200_index"   200 "http://127.0.0.1:8080/"
    assert_status "static/200_file"    200 "http://127.0.0.1:8080/hello.txt"
    assert_status "static/404_missing" 404 "http://127.0.0.1:8080/nosuchfile"
    assert_body   "static/body"        "Hello hypershunt" "http://127.0.0.1:8080/"

    # Conditional GET: server must return 304 when ETag matches.
    local etag
    etag=$(curl -sI --max-time 5 "http://127.0.0.1:8080/hello.txt" \
           | grep -i '^etag:' | tr -d '\r' | sed 's/[Ee][Tt][Aa][Gg]: //') \
           || etag=""
    if [ -n "$etag" ]; then
        assert_status "static/304_etag" 304 \
            "http://127.0.0.1:8080/hello.txt" \
            -H "If-None-Match: ${etag}"
    else
        fail "static/etag_present" "no ETag header"
    fi

    # Range request must return 206 Partial Content.
    assert_status "static/206_range" 206 \
        "http://127.0.0.1:8080/hello.txt" -H "Range: bytes=0-2"

    # Dotfiles must not be served.
    printf 'secret\n' > /tmp/www/.hidden
    assert_status "static/dotfile_404" 404 \
        "http://127.0.0.1:8080/.hidden"

    stop_server
}

suite_redirect() {
    echo "=== Redirect ==="
    cat >"$TMPDIR/redirect.kdl" <<'EOF'
listener "tcp://127.0.0.1:8081"
vhost localhost {
    location "/old" {
        redirect to="/new" code=301
    }
    location "/" {
        static root="/tmp/www"
    }
}
EOF
    start_server "$TMPDIR/redirect.kdl" 8081 \
        || { fail "redirect/server_start" "hypershunt failed"; return; }

    assert_status "redirect/301"           301 \
        "http://127.0.0.1:8081/old" --no-location
    assert_header "redirect/location_hdr"  "Location" "/new" \
        "http://127.0.0.1:8081/old" --no-location

    stop_server
}

suite_static_mime_types() {
    echo "=== Static file MIME types ==="
    # Create files with distinct extensions; verify Content-Type.
    printf '<html></html>'    > /tmp/www/page.html
    printf 'body { }'        > /tmp/www/style.css
    printf 'console.log(1);' > /tmp/www/app.js
    printf '{"ok":true}'     > /tmp/www/data.json

    cat >"$TMPDIR/mime.kdl" <<'EOF'
listener "tcp://127.0.0.1:8107"
vhost localhost {
    location "/" {
        static root="/tmp/www"
    }
}
EOF
    start_server "$TMPDIR/mime.kdl" 8107 \
        || { fail "mime/server_start" "hypershunt failed"; return; }

    assert_header "mime/html" "Content-Type" "text/html" \
        "http://127.0.0.1:8107/page.html"
    assert_header "mime/css"  "Content-Type" "text/css" \
        "http://127.0.0.1:8107/style.css"
    assert_header "mime/js"   "Content-Type" "javascript" \
        "http://127.0.0.1:8107/app.js"
    assert_header "mime/json" "Content-Type" "application/json" \
        "http://127.0.0.1:8107/data.json"

    stop_server
}

suite_redirect_variables() {
    echo "=== Redirect variable substitution ==="
    # Verify that {host}, {scheme}, {path}, and {query} are substituted
    # correctly in redirect targets.
    cat >"$TMPDIR/redirect_vars.kdl" <<'EOF'
listener "tcp://127.0.0.1:8108"
vhost localhost {
    location "/to-https" {
        redirect to="https://{host}{path_and_query}" code=301
    }
    location "/echo-path" {
        redirect to="/dest{path}" code=302
    }
}
EOF
    start_server "$TMPDIR/redirect_vars.kdl" 8108 \
        || { fail "redirect_vars/server_start" "hypershunt failed"; return; }

    # {host} and {path_and_query} expand to the actual request values.
    assert_header "redirect_vars/host" "Location" \
        "https://localhost/to-https?q=1" \
        "http://127.0.0.1:8108/to-https?q=1" \
        -H "Host: localhost" --no-location

    # {path} expands to just the path without query string.
    assert_header "redirect_vars/path" "Location" "/dest/echo-path" \
        "http://127.0.0.1:8108/echo-path" --no-location

    stop_server
}
