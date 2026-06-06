#!/bin/bash
# Suite: JWT session cookie issuance and validation.
#
# Tests the full JWT flow: unauthenticated challenge, Basic-auth issues
# a cookie, cookie replay bypasses credential check, tampered cookie
# is rejected, and /.well-known/jwks.json is served.
#
# Depends on a PAM user existing; creates one if needed (same user as
# suite_auth so both suites can run independently in any order).

suite_jwt() {
    echo "=== JWT sessions ==="

    if ! command -v useradd >/dev/null 2>&1; then
        echo "  SKIP: useradd not found"
        return
    fi
    useradd -M -s /usr/sbin/nologin hypershunttest 2>/dev/null || true
    if ! echo "hypershunttest:hypershuntpass" | chpasswd 2>/dev/null; then
        echo "  SKIP: chpasswd failed"
        return
    fi

    local state_dir="$TMPDIR/jwt-state"
    mkdir -p "$state_dir"

    cat >"$TMPDIR/jwt.kdl" <<EOF
server state-dir="$state_dir" {
    auth "jwt" backend="pam"
}
listener "tcp://127.0.0.1:8102"
vhost localhost {
    location "/" {
        static root="/tmp/www" {
index-file index.html;
}
        basic-auth realm="JWT Realm"
        policy {
            allow authenticated
            deny code=401
        }
    }
}
EOF
    start_server "$TMPDIR/jwt.kdl" 8102 \
        || { fail "jwt/server_start" "hypershunt failed"; return; }

    # JWKS endpoint must be available on all vhosts regardless of config.
    assert_status "jwt/jwks_200" 200 \
        "http://127.0.0.1:8102/.well-known/jwks.json"
    assert_header "jwt/jwks_content_type" "Content-Type" "application/json" \
        "http://127.0.0.1:8102/.well-known/jwks.json"
    assert_body "jwt/jwks_ec_key" '"kty":"EC"' \
        "http://127.0.0.1:8102/.well-known/jwks.json"

    # Unauthenticated request must be challenged.
    assert_status "jwt/no_creds_401" 401 "http://127.0.0.1:8102/"
    assert_header "jwt/challenge_header" "WWW-Authenticate" "JWT Realm" \
        "http://127.0.0.1:8102/"

    # Basic auth issues a session cookie alongside the 200 response.
    local cookie_jar="$TMPDIR/jwt-cookies.txt"
    local auth_code
    auth_code=$(curl -s -u "hypershunttest:hypershuntpass" \
        -c "$cookie_jar" -o /dev/null -w "%{http_code}" \
        --max-time 5 "http://127.0.0.1:8102/") || auth_code="000"
    if [ "$auth_code" = "200" ]; then
        pass "jwt/basic_auth_200"
    else
        fail "jwt/basic_auth_200" "expected 200, got $auth_code"
    fi
    if grep -q "hypershunt_session" "$cookie_jar" 2>/dev/null; then
        pass "jwt/cookie_issued"
    else
        fail "jwt/cookie_issued" "Set-Cookie for hypershunt_session not found"
    fi

    # Cookie replay succeeds without re-supplying credentials.
    local replay_code
    replay_code=$(curl -s -b "$cookie_jar" \
        -o /dev/null -w "%{http_code}" \
        --max-time 5 "http://127.0.0.1:8102/") || replay_code="000"
    if [ "$replay_code" = "200" ]; then
        pass "jwt/cookie_replay_200"
    else
        fail "jwt/cookie_replay_200" "expected 200, got $replay_code"
    fi

    # A tampered (garbage) cookie must be rejected.
    assert_status "jwt/bad_cookie_401" 401 "http://127.0.0.1:8102/" \
        -H "Cookie: hypershunt_session=garbage.token.value"

    stop_server
}
