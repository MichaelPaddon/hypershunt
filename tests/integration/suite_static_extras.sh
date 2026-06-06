#!/bin/bash
# Suite: directory listings and ~user paths on the static handler.
#
# These features are independent, but they share the same handler
# and the same parse-time validation so we exercise them together.

# Directory listings.  Verifies:
#   - GET / returns HTML listing rows for visible entries
#   - dotfiles are excluded
#   - GET on a directory without trailing / returns 301
#   - directory-listing #false still returns 403 when no index
suite_directory_listing() {
    echo "=== Directory listing ==="
    mkdir -p /tmp/www_dirlist /tmp/www_dirlist/sub
    printf 'visible\n' > /tmp/www_dirlist/visible.txt
    printf 'hidden\n'  > /tmp/www_dirlist/.hidden

    cat >"$TMPDIR/dirlist.kdl" <<'EOF'
listener "tcp://127.0.0.1:8901"
vhost localhost {
    location "/listing/" {
        static root="/tmp/www_dirlist" strip-prefix=#true directory-listing=#true
    }
    location "/strict/" {
        static root="/tmp/www_dirlist" strip-prefix=#true directory-listing=#false
    }
}
EOF
    start_server "$TMPDIR/dirlist.kdl" 8901 \
        || { fail "dirlist/server_start" "hypershunt failed"; return; }

    # Golden path: 200 + HTML, with both the file and the subdir
    # surfaced; the dotfile must not be.
    assert_status "dirlist/index_200" 200 \
        "http://127.0.0.1:8901/listing/"
    assert_header "dirlist/content_type" "Content-Type" "text/html" \
        "http://127.0.0.1:8901/listing/"
    assert_body   "dirlist/has_file" "visible.txt" \
        "http://127.0.0.1:8901/listing/"
    assert_body   "dirlist/has_subdir" "sub/" \
        "http://127.0.0.1:8901/listing/"

    # The dotfile name must not appear -- grep against the raw body.
    local body
    body=$(curl -s --max-time 5 "http://127.0.0.1:8901/listing/")
    if echo "$body" | grep -q '\.hidden'; then
        fail "dirlist/dotfile_hidden" "found .hidden in listing"
    else
        pass "dirlist/dotfile_hidden"
    fi

    # Trailing-slash redirect: a directory request without `/` must
    # 301 so relative links resolve against the browser's URL.
    assert_status "dirlist/missing_slash_301" 301 \
        "http://127.0.0.1:8901/listing/sub"
    assert_header "dirlist/location_header" "Location" "/listing/sub/" \
        "http://127.0.0.1:8901/listing/sub"

    # Nested listing works the same.
    assert_status "dirlist/nested_200" 200 \
        "http://127.0.0.1:8901/listing/sub/"

    # Listing disabled -> the existing "no index found" behaviour
    # (403) is preserved unchanged.
    assert_status "dirlist/disabled_403" 403 \
        "http://127.0.0.1:8901/strict/"

    stop_server
    rm -rf /tmp/www_dirlist
}

# User-directory paths.  Verifies:
#   - /~<user>/foo serves $HOME/public_html/foo
#   - allowlist blocks an existing user not on the list
#   - unknown users 404
#   - system UIDs (here `root`) are rejected when min-uid > 0
suite_userdir() {
    echo "=== User directories (~user) ==="

    # Create a test user with a populated public_html.  Use a high
    # UID so the userdir-min-uid gate doesn't catch us by accident.
    local user=hypershunttest1
    local home=/home/$user
    if ! getent passwd "$user" >/dev/null; then
        useradd -m -u 2001 -s /bin/false "$user" 2>/dev/null \
            || { fail "userdir/useradd" "useradd failed"; return; }
    fi
    mkdir -p "$home/public_html/sub"
    printf 'alice home\n' > "$home/public_html/index.html"
    printf 'asset content\n' > "$home/public_html/asset.txt"
    printf 'sub index\n' > "$home/public_html/sub/index.html"
    # hypershunt is going to read these as the running user (root inside
    # the container), so the perms don't strictly matter, but mirror
    # a real "served by the unprivileged hypershunt account" setup.
    chmod -R a+rX "$home/public_html"
    # A second user that exists but is NOT on the allowlist.
    local other=hypershunttest2
    if ! getent passwd "$other" >/dev/null; then
        useradd -m -u 2002 -s /bin/false "$other" 2>/dev/null || true
    fi
    mkdir -p "/home/$other/public_html"
    printf 'should not be served\n' > "/home/$other/public_html/index.html"
    chmod -R a+rX "/home/$other/public_html"

    # First config: open mode (no allowlist).
    cat >"$TMPDIR/userdir.kdl" <<EOF
listener "tcp://127.0.0.1:8902"
vhost localhost {
    location "/" {
        static userdir="public_html" userdir-min-uid=1000 {
index-file "index.html"
}
    }
}
EOF
    start_server "$TMPDIR/userdir.kdl" 8902 \
        || { fail "userdir/server_start" "hypershunt failed"; return; }

    # /~hypershunttest1/ -> public_html/index.html
    assert_status "userdir/index_200" 200 \
        "http://127.0.0.1:8902/~$user/"
    assert_body   "userdir/index_body" "alice home" \
        "http://127.0.0.1:8902/~$user/"
    # /~hypershunttest1/asset.txt -> public_html/asset.txt
    assert_status "userdir/asset_200" 200 \
        "http://127.0.0.1:8902/~$user/asset.txt"
    assert_body   "userdir/asset_body" "asset content" \
        "http://127.0.0.1:8902/~$user/asset.txt"
    # Nested directory: /~hypershunttest1/sub/
    assert_status "userdir/nested_200" 200 \
        "http://127.0.0.1:8902/~$user/sub/"
    # Unknown user -> 404 (must not 500 or leak existence info).
    assert_status "userdir/unknown_404" 404 \
        "http://127.0.0.1:8902/~hypershunt_no_such_user_zzz/"
    # System UID (root) blocked by userdir-min-uid.
    assert_status "userdir/root_404" 404 \
        "http://127.0.0.1:8902/~root/"
    # Bad-charset username -> 404 before even hitting getpwnam.
    assert_status "userdir/badchar_404" 404 \
        "http://127.0.0.1:8902/~not%40valid/x"

    stop_server

    # Second config: allowlist set; only hypershunttest1 may be served.
    cat >"$TMPDIR/userdir_allow.kdl" <<EOF
listener "tcp://127.0.0.1:8903"
vhost localhost {
    location "/" {
        static userdir="public_html" userdir-min-uid=1000 {
userdir-allowlist "$user"
            index-file "index.html"
}
    }
}
EOF
    start_server "$TMPDIR/userdir_allow.kdl" 8903 \
        || { fail "userdir_allow/server_start" "hypershunt failed"; return; }

    # Allowlisted user is reachable.
    assert_status "userdir_allow/listed_200" 200 \
        "http://127.0.0.1:8903/~$user/"
    # Non-listed user exists and has a public_html, but must 404.
    assert_status "userdir_allow/unlisted_404" 404 \
        "http://127.0.0.1:8903/~$other/"

    stop_server

    # Clean up after ourselves so back-to-back container runs stay
    # idempotent.
    userdel -rf "$user" 2>/dev/null || true
    userdel -rf "$other" 2>/dev/null || true
}
