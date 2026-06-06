#!/bin/bash
# Suite: file-backed HTTP Basic auth (`auth file { path ... }`).
#
# Validates each supported hash scheme (bcrypt, sha512-crypt,
# argon2id), the optional groups column, and mtime-triggered reload
# of the htpasswd file.

# Hashes of the password "secret".  Generated with:
#   bcrypt::hash("secret", 4)
#   pwhash::sha512_crypt::hash("secret")
#   argon2 v0.5 defaults, salt=b"saltsaltsalt"
BCRYPT_SECRET='$2b$04$i/SRyovMJVctpkrEQIDueOlFCVtPDnuvkT1s12Guzwahgf0Fg1Lp.'
SHA512_SECRET='$6$wdTYM11KPnaeMj7y$elomcOiJCI.tIJCwOK8.evAgZi8E1qhwp7kRRxMCLAWRbNfzmP3I6X0SS4GmgByp1RrLSmJUCabKn3vxGnXf81'
ARGON2_SECRET='$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0$ki2QQIMdi3gALFf4XR64Y9rn4F8+JEUu2h0iBExveQo'

suite_auth_file_basic() {
    echo "=== HTTP Basic auth via file (bcrypt/sha512/argon2id) ==="

    # One htpasswd file with three users, one per scheme.  carol is
    # also tagged with two groups so we can exercise the group column.
    cat >"$TMPDIR/htpasswd" <<EOF
alice:$BCRYPT_SECRET
bob:$SHA512_SECRET
carol:$ARGON2_SECRET:admins,users
EOF

    cat >"$TMPDIR/auth_file.kdl" <<EOF
server {
    auth "file" path="$TMPDIR/htpasswd"
}
listener "tcp://127.0.0.1:8193"
listener "tcp://127.0.0.1:8194" default-vhost="groups-only"
vhost localhost {
    location "/" {
        static root="/tmp/www" {
index-file index.html;
}
        basic-auth realm="File Test"
        policy {
            allow authenticated
            deny code=401
        }
    }
}
vhost "groups-only" {
    location "/" {
        static root="/tmp/www" {
index-file index.html;
}
        basic-auth realm="File Group Test"
        policy {
            allow group admins
            deny code=403
        }
    }
}
EOF
    start_server "$TMPDIR/auth_file.kdl" 8193 \
        || { fail "auth_file/server_start" "hypershunt failed"; return; }

    # No credentials -> 401.
    assert_status "auth_file/challenge_401" 401 "http://127.0.0.1:8193/"

    # Each scheme: correct password authenticates.
    assert_status "auth_file/bcrypt_ok" 200 "http://127.0.0.1:8193/" \
        -u "alice:secret"
    assert_status "auth_file/sha512_ok" 200 "http://127.0.0.1:8193/" \
        -u "bob:secret"
    assert_status "auth_file/argon2_ok" 200 "http://127.0.0.1:8193/" \
        -u "carol:secret"

    # Wrong password -> 401 regardless of scheme.
    assert_status "auth_file/bcrypt_wrong" 401 "http://127.0.0.1:8193/" \
        -u "alice:nope"
    assert_status "auth_file/sha512_wrong" 401 "http://127.0.0.1:8193/" \
        -u "bob:nope"
    assert_status "auth_file/argon2_wrong" 401 "http://127.0.0.1:8193/" \
        -u "carol:nope"

    # Unknown user -> 401.
    assert_status "auth_file/unknown_user" 401 "http://127.0.0.1:8193/" \
        -u "mallory:secret"

    # Group column: carol is in `admins`, others are not.
    assert_status "auth_file/group_allowed" 200 "http://127.0.0.1:8194/" \
        -u "carol:secret"
    assert_status "auth_file/group_denied"  403 "http://127.0.0.1:8194/" \
        -u "alice:secret"

    stop_server
}

suite_auth_file_reload_on_mtime() {
    echo "=== auth file reloads on mtime change ==="

    cat >"$TMPDIR/htpasswd2" <<EOF
alice:$BCRYPT_SECRET
EOF

    cat >"$TMPDIR/auth_file_reload.kdl" <<EOF
server {
    auth "file" path="$TMPDIR/htpasswd2" cache=1
}
listener "tcp://127.0.0.1:8195"
vhost localhost {
    location "/" {
        static root="/tmp/www" {
index-file index.html;
}
        basic-auth realm="Reload"
        policy { allow authenticated; deny code=401 }
    }
}
EOF
    start_server "$TMPDIR/auth_file_reload.kdl" 8195 \
        || { fail "auth_file/reload_start" "hypershunt failed"; return; }

    # Before reload: alice authenticates, bob does not exist.
    assert_status "auth_file/reload_pre_alice" 200 "http://127.0.0.1:8195/" \
        -u "alice:secret"
    assert_status "auth_file/reload_pre_bob"   401 "http://127.0.0.1:8195/" \
        -u "bob:secret"

    # Rewrite the file: alice is now gone, bob is added.  Sleep past
    # the cache TTL + a filesystem timestamp granularity margin so
    # the next stat sees a fresh mtime.
    sleep 2
    cat >"$TMPDIR/htpasswd2" <<EOF
bob:$SHA512_SECRET
EOF

    assert_status "auth_file/reload_post_alice" 401 "http://127.0.0.1:8195/" \
        -u "alice:secret"
    assert_status "auth_file/reload_post_bob"   200 "http://127.0.0.1:8195/" \
        -u "bob:secret"

    stop_server
}
