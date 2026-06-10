#!/bin/bash
# Suite: IP access control, redirect actions, and custom error pages.

suite_ip_access() {
    echo "=== IP access control ==="
    cat >"$TMPDIR/access.kdl" <<'EOF'
listener "tcp://127.0.0.1:8082" { vhost "allow-site" }
listener "tcp://127.0.0.1:8089" { vhost "deny-site" }
vhost "allow-site" {
    location "/" {
        static root="/tmp/www" {
index-file index.html;
}
        policy {
            allow address "127.0.0.1/32"
            deny
        }
    }
}
vhost "deny-site" {
    location "/" {
        static root="/tmp/www" {
index-file index.html;
}
        policy {
            deny address "127.0.0.1/32"
            allow
        }
    }
}
EOF
    start_server "$TMPDIR/access.kdl" 8082 \
        || { fail "access/server_start" "hypershunt failed"; return; }

    assert_status "access/allow_loopback" 200 "http://127.0.0.1:8082/"
    assert_status "access/deny_loopback"  403 "http://127.0.0.1:8089/"

    stop_server
}

suite_access_redirect() {
    echo "=== Access redirect action ==="
    cat >"$TMPDIR/accredirect.kdl" <<'EOF'
listener "tcp://127.0.0.1:8099"
vhost localhost {
    location "/" {
        static root="/tmp/www"
        policy {
            redirect to="/login" code=302
        }
    }
}
EOF
    start_server "$TMPDIR/accredirect.kdl" 8099 \
        || { fail "access_redirect/server_start" "hypershunt failed"; return; }

    assert_status "access_redirect/302" 302 \
        "http://127.0.0.1:8099/" --no-location
    assert_header "access_redirect/location" "Location" "/login" \
        "http://127.0.0.1:8099/" --no-location

    stop_server
}

suite_custom_error_pages() {
    echo "=== Custom error pages ==="
    cat >"$TMPDIR/errpage.kdl" <<'EOF'
server {
    error-page 403 html="<p>Custom forbidden</p>"
}
listener "tcp://127.0.0.1:8098"
vhost localhost {
    location "/" {
        static root="/tmp/www"
        policy { deny code=403 }
    }
}
EOF
    start_server "$TMPDIR/errpage.kdl" 8098 \
        || { fail "error_pages/server_start" "hypershunt failed"; return; }

    assert_status "error_pages/403"         403 "http://127.0.0.1:8098/"
    assert_body   "error_pages/custom_body" "Custom forbidden" \
        "http://127.0.0.1:8098/"

    stop_server
}
