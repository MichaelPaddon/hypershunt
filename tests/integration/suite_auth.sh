#!/bin/bash
# Suite: HTTP Basic auth (PAM and LDAP).

suite_auth() {
    echo "=== HTTP Basic auth ==="

    # Create a PAM-visible test user; skip if useradd is unavailable.
    if ! command -v useradd >/dev/null 2>&1; then
        echo "  SKIP: useradd not found"
        return
    fi
    useradd -M -s /usr/sbin/nologin hypershunttest 2>/dev/null || true
    if ! echo "hypershunttest:hypershuntpass" | chpasswd 2>/dev/null; then
        echo "  SKIP: chpasswd failed"
        return
    fi

    cat >"$TMPDIR/auth.kdl" <<'EOF'
server {
    auth "pam"
}
listener "tcp://127.0.0.1:8083"
vhost localhost {
    location "/" {
        static root="/tmp/www" {
index-file index.html;
}
        basic-auth realm="Test Realm"
        policy {
            allow authenticated
            deny code=401
        }
    }
}
EOF
    start_server "$TMPDIR/auth.kdl" 8083 \
        || { fail "auth/server_start" "hypershunt failed"; return; }

    # No credentials: must challenge with 401 + WWW-Authenticate.
    assert_status "auth/challenge_401"    401 "http://127.0.0.1:8083/"
    assert_header "auth/www_authenticate" "WWW-Authenticate" "Basic" \
        "http://127.0.0.1:8083/"
    assert_header "auth/realm"            "WWW-Authenticate" "Test Realm" \
        "http://127.0.0.1:8083/"

    # Correct credentials: must get 200.
    assert_status "auth/valid_creds" 200 "http://127.0.0.1:8083/" \
        -u "hypershunttest:hypershuntpass"

    # Wrong credentials: must get 401 again.
    assert_status "auth/bad_creds" 401 "http://127.0.0.1:8083/" \
        -u "hypershunttest:wrongpassword"

    stop_server
}

suite_ldap_auth() {
    echo "=== LDAP authentication ==="

    setup_ldap || return

    cat >"$TMPDIR/ldap.kdl" <<'EOF'
server {
    auth "ldap" url="ldap://127.0.0.1:3890" bind-dn="uid={user},ou=people,dc=test,dc=local" base-dn="ou=groups,dc=test,dc=local"
}
listener "tcp://127.0.0.1:8090" default-vhost="ldap-auth"
listener "tcp://127.0.0.1:8091" default-vhost="ldap-group"
vhost "ldap-auth" {
    location "/" {
        static root="/tmp/www" {
index-file index.html;
}
        basic-auth realm="LDAP Test"
        policy {
            allow authenticated
            deny code=401
        }
    }
}
vhost "ldap-group" {
    location "/" {
        static root="/tmp/www" {
index-file index.html;
}
        basic-auth realm="LDAP Group Test"
        policy {
            allow group testgroup
            deny code=403
        }
    }
}
EOF
    start_server "$TMPDIR/ldap.kdl" 8090 \
        || { fail "ldap/server_start" "hypershunt failed"; teardown_ldap; return; }

    # -- Credential validation (port 8090) --

    assert_status "ldap/challenge_401"    401 "http://127.0.0.1:8090/"
    assert_header "ldap/www_authenticate" "WWW-Authenticate" "LDAP Test" \
        "http://127.0.0.1:8090/"
    assert_status "ldap/valid_creds"    200 "http://127.0.0.1:8090/" \
        -u "alice:alicepass"
    assert_status "ldap/wrong_password" 401 "http://127.0.0.1:8090/" \
        -u "alice:badpass"
    # Empty password must be rejected before any LDAP bind attempt.
    assert_status "ldap/empty_password" 401 "http://127.0.0.1:8090/" \
        -u "alice:"

    # -- Group-based access control (port 8091) --

    # alice is in testgroup → allow.
    assert_status "ldap/group_allowed" 200 "http://127.0.0.1:8091/" \
        -u "alice:alicepass"
    # bob is not in testgroup → deny 403.
    assert_status "ldap/group_denied"  403 "http://127.0.0.1:8091/" \
        -u "bob:bobpass"

    stop_server
    teardown_ldap
}
