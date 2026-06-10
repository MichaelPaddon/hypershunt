#!/bin/bash
# Suite: virtual host routing (literal, alias, regex, null default).

suite_multi_vhost() {
    echo "=== Multiple vhosts ==="
    mkdir -p /tmp/www-a /tmp/www-b
    printf "site-a content\n" > /tmp/www-a/index.html
    printf "site-b content\n" > /tmp/www-b/index.html

    cat >"$TMPDIR/multi.kdl" <<'EOF'
listener "tcp://127.0.0.1:8093"
vhost "site-a.local" {
    location "/" {
        static root="/tmp/www-a" {
index-file index.html;
}
    }
}
vhost "site-b.local" {
    location "/" {
        static root="/tmp/www-b" {
index-file index.html;
}
    }
}
EOF
    start_server "$TMPDIR/multi.kdl" 8093 \
        || { fail "multi_vhost/server_start" "hypershunt failed"; return; }

    assert_body "multi_vhost/site_a" "site-a content" \
        "http://127.0.0.1:8093/" -H "Host: site-a.local"
    assert_body "multi_vhost/site_b" "site-b content" \
        "http://127.0.0.1:8093/" -H "Host: site-b.local"
    # Unknown host falls back to the first vhost (site-a.local).
    assert_body "multi_vhost/fallback" "site-a content" \
        "http://127.0.0.1:8093/" -H "Host: unknown.local"

    stop_server
}

suite_vhost_aliases() {
    echo "=== Vhost aliases ==="
    cat >"$TMPDIR/alias.kdl" <<'EOF'
listener "tcp://127.0.0.1:8094"
vhost "main.local" {
    alias www.main.local
    location "/" {
        redirect to="/main" code=301
    }
}
EOF
    start_server "$TMPDIR/alias.kdl" 8094 \
        || { fail "aliases/server_start" "hypershunt failed"; return; }

    assert_header "aliases/canonical_loc" "Location" "/main" \
        "http://127.0.0.1:8094/" -H "Host: main.local" --no-location
    assert_header "aliases/alias_loc" "Location" "/main" \
        "http://127.0.0.1:8094/" -H "Host: www.main.local" --no-location

    stop_server
}

suite_regex_vhost() {
    echo "=== Regex vhost ==="
    cat >"$TMPDIR/regex.kdl" <<'EOF'
listener "tcp://127.0.0.1:8095" reject-unknown-host=#true
vhost "static.local" {
    location "/" {
        redirect to="/static" code=301
    }
}
vhost ".+\\.regex\\.local" regex=#true {
    location "/" {
        redirect to="/regex" code=301
    }
}
EOF
    start_server "$TMPDIR/regex.kdl" 8095 \
        || { fail "regex_vhost/server_start" "hypershunt failed"; return; }

    # Literal match takes priority.
    assert_header "regex_vhost/literal" "Location" "/static" \
        "http://127.0.0.1:8095/" -H "Host: static.local" --no-location
    # Regex match for a subdomain pattern.
    assert_header "regex_vhost/regex" "Location" "/regex" \
        "http://127.0.0.1:8095/" -H "Host: api.regex.local" --no-location
    # Unmatched host on a reject-unknown-host listener → 404.
    assert_status "regex_vhost/no_match" 404 \
        "http://127.0.0.1:8095/" -H "Host: other.local"

    stop_server
}
