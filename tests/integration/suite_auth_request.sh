#!/bin/bash
# Suite: auth-request handler (hypershunt as the auth decision endpoint).
#
# The auth-request handler is the server side of nginx-style subrequest
# auth.  It returns 200 OK with X-Auth-User / X-Auth-Groups identity
# headers when the surrounding policy allows the request.
# Anonymous requests are blocked by the policy before the handler runs,
# so they receive 401 instead.

suite_auth_request() {
    echo "=== auth-request handler ==="

    if ! command -v useradd >/dev/null 2>&1; then
        echo "  SKIP: useradd not found"
        return
    fi
    useradd -M -s /usr/sbin/nologin hypershunttest 2>/dev/null || true
    if ! echo "hypershunttest:hypershuntpass" | chpasswd 2>/dev/null; then
        echo "  SKIP: chpasswd failed"
        return
    fi

    cat >"$TMPDIR/auth_request.kdl" <<'EOF'
server {
    auth "pam"
}
listener "tcp://127.0.0.1:8104"
vhost localhost {
    location "/" {
        auth-request
        basic-auth realm="Auth Request Test"
        policy {
            allow authenticated
            deny code=401
        }
    }
}
EOF
    start_server "$TMPDIR/auth_request.kdl" 8104 \
        || { fail "auth_request/server_start" "hypershunt failed"; return; }

    # No credentials: policy blocks before handler → 401 challenge.
    assert_status "auth_request/anon_401"     401 "http://127.0.0.1:8104/"
    assert_header "auth_request/www_auth"     "WWW-Authenticate" "Basic" \
        "http://127.0.0.1:8104/"

    # Valid credentials: handler runs and returns 200 with identity headers.
    assert_status "auth_request/authed_200"   200 "http://127.0.0.1:8104/" \
        -u "hypershunttest:hypershuntpass"
    assert_header "auth_request/user_header"  "X-Auth-User" "hypershunttest" \
        "http://127.0.0.1:8104/" -u "hypershunttest:hypershuntpass"

    # Wrong password: PAM rejects → anonymous → policy denies → 401.
    assert_status "auth_request/bad_creds_401" 401 "http://127.0.0.1:8104/" \
        -u "hypershunttest:wrongpassword"

    stop_server
}
