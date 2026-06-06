#!/bin/bash
# Suite: per-location URL rewrite directives.

# Basic capture-group rewrite: /old/* hops to /new/* and is
# served from a separate webroot, proving the rewrite re-routed.
suite_rewrite_capture_group() {
    echo "=== Rewrite: capture-group re-routes ==="
    mkdir -p /tmp/www_new
    echo "new-body" > /tmp/www_new/foo
    cat >"$TMPDIR/rw_basic.kdl" <<'EOF'
listener "tcp://127.0.0.1:8501"
vhost localhost {
    location "/old/" {
        rewrite from="^/old/(.*)$" to="/new/$1"
        static root="/tmp/www_never"
    }
    location "/new/" {
        static root="/tmp/www_new" strip-prefix=#true
    }
}
EOF
    start_server "$TMPDIR/rw_basic.kdl" 8501 \
        || { fail "rw_basic/server_start" "hypershunt failed"; return; }

    assert_body "rw_basic/old_rewrites_to_new" "new-body" \
        "http://127.0.0.1:8501/old/foo"
    assert_status "rw_basic/missing_target_404" 404 \
        "http://127.0.0.1:8501/old/missing"

    stop_server
    rm -rf /tmp/www_new
}

# A rewrite whose regex never matches the request URI must not
# alter the URI; the location's own handler runs.
suite_rewrite_no_match_is_noop() {
    echo "=== Rewrite: non-matching regex is a no-op ==="
    cat >"$TMPDIR/rw_noop.kdl" <<'EOF'
listener "tcp://127.0.0.1:8502"
vhost localhost {
    location "/" {
        rewrite from="^/old/.*$" to="/new/x"
        static root="/tmp/www"
    }
}
EOF
    start_server "$TMPDIR/rw_noop.kdl" 8502 \
        || { fail "rw_noop/server_start" "hypershunt failed"; return; }

    # `/` matches the location but the rewrite regex doesn't,
    # so the static handler runs on the original URI.
    assert_body "rw_noop/served_unchanged" "Hello hypershunt" \
        "http://127.0.0.1:8502/"

    stop_server
}

# Multi-hop rewrite chain across three locations: A -> B -> C,
# where only C has a real handler.
suite_rewrite_chains_through_three_locations() {
    echo "=== Rewrite: three-hop chain settles at terminal ==="
    mkdir -p /tmp/www_c
    echo "served-from-c" > /tmp/www_c/foo
    cat >"$TMPDIR/rw_chain.kdl" <<'EOF'
listener "tcp://127.0.0.1:8504"
vhost localhost {
    location "/a/" {
        rewrite from="^/a/(.*)$" to="/b/$1"
        static root="/never"
    }
    location "/b/" {
        rewrite from="^/b/(.*)$" to="/c/$1"
        static root="/never"
    }
    location "/c/" {
        static root="/tmp/www_c" strip-prefix=#true
    }
}
EOF
    start_server "$TMPDIR/rw_chain.kdl" 8504 \
        || { fail "rw_chain/server_start" "hypershunt failed"; return; }

    assert_body "rw_chain/settles_at_c" "served-from-c" \
        "http://127.0.0.1:8504/a/foo"

    stop_server
    rm -rf /tmp/www_c
}

# A rewrite that loops onto itself triggers the cycle cap and
# returns 404, not an infinite loop / hang.
suite_rewrite_cycle_bails() {
    echo "=== Rewrite: self-referential cycle bails out ==="
    cat >"$TMPDIR/rw_cycle.kdl" <<'EOF'
listener "tcp://127.0.0.1:8503"
vhost localhost {
    location "/" {
        rewrite from="^/(.*)$" to="/$1"
        static root="/tmp/www"
    }
}
EOF
    start_server "$TMPDIR/rw_cycle.kdl" 8503 \
        || { fail "rw_cycle/server_start" "hypershunt failed"; return; }

    assert_status "rw_cycle/loop_yields_404" 404 \
        "http://127.0.0.1:8503/anything"

    stop_server
}
