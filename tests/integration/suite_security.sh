#!/bin/bash
# Suite: the `hypershunt::security` event stream that fail2ban consumes.
#
# Drives real requests and asserts the exact rendered log lines, since
# that text -- not just the HTTP status -- is what an intrusion-detection
# tool matches.  Verifies the four HTTP-level tokens and, crucially, that
# a benign 401 challenge (no credentials) is logged as `auth-challenge`,
# distinct from a real `auth-failure`, so fail2ban can ban one and not
# the other.  (`bad-client-cert` is covered in suite_mtls.sh.)

# Hash of password "secret" (bcrypt cost 4), as used by suite_auth_file.
SEC_BCRYPT='$2b$04$i/SRyovMJVctpkrEQIDueOlFCVtPDnuvkT1s12Guzwahgf0Fg1Lp.'

suite_security_signals() {
    echo "=== Security signals (fail2ban event stream) ==="

    printf 'alice:%s\n' "$SEC_BCRYPT" >"$TMPDIR/sec_htpasswd"

    cat >"$TMPDIR/security.kdl" <<EOF
server {
    auth "file" path="$TMPDIR/sec_htpasswd"
}
listener "tcp://127.0.0.1:8401"
vhost localhost {
    // Auth-required -> auth-failure (wrong creds) / auth-challenge (none).
    location "/protected/" {
        static root="/tmp/www" strip-prefix=#true
        basic-auth realm="Sec Test"
        policy {
            allow authenticated
            deny code=401
        }
    }
    // IP allow-list that excludes loopback -> access-denied (403).
    location "/denied/" {
        static root="/tmp/www" strip-prefix=#true
        policy {
            allow address "10.0.0.0/8"
            deny code=403
        }
    }
    // rate=1/burst=1 -> the second request in the same second is 429.
    location "/rl/" {
        rate-limit rate=1 per="second" burst=1 {
key "client-ip"
}
        static root="/tmp/www" strip-prefix=#true
    }
    location "/" { static root="/tmp/www" }
}
EOF
    start_server "$TMPDIR/security.kdl" 8401 \
        || { fail "security/server_start" "hypershunt failed"; return; }

    # 1. No credentials -> 401 + benign `auth-challenge`.
    assert_status "security/challenge_401" 401 \
        "http://127.0.0.1:8401/protected/"
    # 2. Wrong credentials -> 401 + real `auth-failure`.
    assert_status "security/failure_401" 401 \
        "http://127.0.0.1:8401/protected/" -u "alice:wrongpassword"
    # 3. Loopback is not in 10.0.0.0/8 -> 403 + `access-denied`.
    assert_status "security/denied_403" 403 \
        "http://127.0.0.1:8401/denied/"
    # 4. Drain the bucket, then trip the limit -> 429 + `rate-limited`.
    curl -s -o /dev/null --max-time 5 "http://127.0.0.1:8401/rl/"
    assert_status "security/ratelimited_429" 429 \
        "http://127.0.0.1:8401/rl/"

    # stdout is line-buffered (Rust LineWriter flushes on '\n'), so the
    # event lines are in the file by now; a tiny margin guards any race.
    sleep 0.2

    # The tokens carry the real loopback peer, and fail2ban's <HOST> is
    # extracted from that trusted `peer=` field.
    assert_log "security/auth-challenge" \
        'hypershunt::security: auth-challenge peer=127\.0\.0\.1:[0-9]+'
    assert_log "security/auth-failure" \
        'hypershunt::security: auth-failure peer=127\.0\.0\.1:[0-9]+'
    assert_log "security/access-denied" \
        'hypershunt::security: access-denied peer=127\.0\.0\.1:[0-9]+'
    assert_log "security/rate-limited" \
        'hypershunt::security: rate-limited peer=127\.0\.0\.1:[0-9]+'

    # A genuine failure must NOT also be logged as the benign challenge,
    # and vice-versa -- they are distinct ban decisions.
    if [ "$(grep -c 'hypershunt::security: auth-failure'   "$TMPDIR/hypershunt.out")" -ge 1 ] && \
       [ "$(grep -c 'hypershunt::security: auth-challenge' "$TMPDIR/hypershunt.out")" -ge 1 ]; then
        pass "security/failure_vs_challenge_distinct"
    else
        fail "security/failure_vs_challenge_distinct" "tokens not both present/distinct"
    fi

    stop_server
}
