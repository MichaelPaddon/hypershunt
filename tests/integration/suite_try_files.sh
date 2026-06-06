#!/bin/bash
# Suite: static handler `try-files` directive.

# Classic SPA fallback: any request whose path doesn't map to a
# real file ends up serving /index.html.
suite_try_files_spa_fallback() {
    echo "=== try-files: SPA fallback to /index.html ==="
    mkdir -p /tmp/www_spa
    echo "<!doctype html><div id=root></div>" > /tmp/www_spa/index.html
    echo "real-asset"                          > /tmp/www_spa/asset.js
    cat >"$TMPDIR/tf_spa.kdl" <<'EOF'
listener "tcp://127.0.0.1:8601"
vhost localhost {
    location "/" {
        static root="/tmp/www_spa" {
try-files "{path}"
try-files "{path}.html"
try-files "/index.html"
}
    }
}
EOF
    start_server "$TMPDIR/tf_spa.kdl" 8601 \
        || { fail "tf_spa/server_start" "hypershunt failed"; return; }

    # Real asset under root: served directly.
    assert_body "tf_spa/real_asset" "real-asset" \
        "http://127.0.0.1:8601/asset.js"
    # Client-side route -> no file -> /index.html fallback.
    assert_body "tf_spa/spa_route" "<div id=root>" \
        "http://127.0.0.1:8601/users/42"
    # Another SPA route: same fallback.
    assert_body "tf_spa/deep_spa_route" "<div id=root>" \
        "http://127.0.0.1:8601/settings/profile/edit"

    stop_server
    rm -rf /tmp/www_spa
}

# All candidates miss -> 404 (no implicit handler fallback).
suite_try_files_all_miss_404() {
    echo "=== try-files: all candidates miss -> 404 ==="
    mkdir -p /tmp/www_empty
    cat >"$TMPDIR/tf_404.kdl" <<'EOF'
listener "tcp://127.0.0.1:8602"
vhost localhost {
    location "/" {
        static root="/tmp/www_empty" {
try-files "{path}"
try-files "/missing.html"
}
    }
}
EOF
    start_server "$TMPDIR/tf_404.kdl" 8602 \
        || { fail "tf_404/server_start" "hypershunt failed"; return; }

    assert_status "tf_404/all_miss" 404 \
        "http://127.0.0.1:8602/anything"

    stop_server
    rm -rf /tmp/www_empty
}

# Realistic SPA: HTML clients get index.html on unknown routes;
# API clients (Accept: application/json) get 404 instead.
# Combines try-files with a matcher on the Accept header.
suite_try_files_gated_by_accept() {
    echo "=== try-files: SPA fallback gated by Accept header ==="
    mkdir -p /tmp/www_gated
    echo "<!doctype html><h1>spa" > /tmp/www_gated/index.html
    cat >"$TMPDIR/tf_gated.kdl" <<'EOF'
listener "tcp://127.0.0.1:8604"
vhost localhost {
    location "/" {
        match { header "Accept" "~text/html" }
        static root="/tmp/www_gated" {
try-files "{path}"
try-files "/index.html"
}
    }
    location "/" {
        static root="/tmp/www_gated"
    }
}
EOF
    start_server "$TMPDIR/tf_gated.kdl" 8604 \
        || { fail "tf_gated/server_start" "hypershunt failed"; return; }

    # Browser-style request: matcher accepts, try-files
    # falls back to index.html.
    assert_body "tf_gated/html_client_gets_spa" "<h1>spa" \
        "http://127.0.0.1:8604/spa/route" \
        -H "Accept: text/html"
    # API-style request: matcher rejects, sibling location
    # serves the static handler without try-files, so an
    # unknown path 404s.
    assert_status "tf_gated/api_client_gets_404" 404 \
        "http://127.0.0.1:8604/spa/route" \
        -H "Accept: application/json"

    stop_server
    rm -rf /tmp/www_gated
}

# Rewrite into a try-files location: legacy URLs get rewritten,
# the post-rewrite path then runs through the SPA fallback.
suite_rewrite_into_try_files() {
    echo "=== Combo: rewrite then try-files ==="
    mkdir -p /tmp/www_combo/v2
    echo "<!doctype html><div>shell" > /tmp/www_combo/index.html
    echo "real-v2-asset" > /tmp/www_combo/v2/asset.js
    cat >"$TMPDIR/combo_rw_tf.kdl" <<'EOF'
listener "tcp://127.0.0.1:8605"
vhost localhost {
    location "/legacy/" {
        rewrite from="^/legacy/(.*)$" to="/v2/$1"
        static root="/never"
    }
    location "/" {
        static root="/tmp/www_combo" {
try-files "{path}"
try-files "/index.html"
}
    }
}
EOF
    start_server "$TMPDIR/combo_rw_tf.kdl" 8605 \
        || { fail "combo_rw_tf/server_start" "hypershunt failed"; return; }

    # /legacy/asset.js -> /v2/asset.js -> real file served.
    assert_body "combo_rw_tf/legacy_real_asset" \
        "real-v2-asset" \
        "http://127.0.0.1:8605/legacy/asset.js"
    # /legacy/some/route -> /v2/some/route -> doesn't exist
    # -> try-files falls back to /index.html.
    assert_body "combo_rw_tf/legacy_spa_route" \
        "<div>shell" \
        "http://127.0.0.1:8605/legacy/some/route"

    stop_server
    rm -rf /tmp/www_combo
}

# Symlink escape: a try-files candidate whose resolved path is
# a symlink pointing outside the configured root must be
# rejected.  try-files itself only stats the candidate (which
# follows the symlink and looks like a normal file), but the
# main static-handler safety net canonicalises both root and
# the served path and rejects when they diverge.  Expected:
# 403, not 200.
suite_try_files_symlink_escape() {
    echo "=== try-files: symlink escape rejected ==="
    mkdir -p /tmp/www_sym
    # Place the symlink target outside the configured root.
    mkdir -p /tmp/outside_sym
    echo "secret" > /tmp/outside_sym/secret.txt
    ln -sfn /tmp/outside_sym/secret.txt /tmp/www_sym/escape
    cat >"$TMPDIR/tf_sym.kdl" <<'EOF'
listener "tcp://127.0.0.1:8606"
vhost localhost {
    location "/" {
        static root="/tmp/www_sym" {
try-files "{path}"
try-files "/index.html"
}
    }
}
EOF
    start_server "$TMPDIR/tf_sym.kdl" 8606 \
        || { fail "tf_sym/server_start" "hypershunt failed"; return; }

    # The candidate `/escape` exists (as a symlink), so try-files
    # accepts it; the static handler's canonical-root check then
    # refuses to serve a file outside the root.
    assert_status "tf_sym/escape_rejected" 403 \
        "http://127.0.0.1:8606/escape"

    stop_server
    rm -rf /tmp/www_sym /tmp/outside_sym
}

# {path}.html suffix-extension lookup: request /foo serves /foo.html.
suite_try_files_html_suffix() {
    echo "=== try-files: implicit .html suffix ==="
    mkdir -p /tmp/www_html
    echo "page-body" > /tmp/www_html/page.html
    cat >"$TMPDIR/tf_html.kdl" <<'EOF'
listener "tcp://127.0.0.1:8603"
vhost localhost {
    location "/" {
        static root="/tmp/www_html" {
try-files "{path}"
try-files "{path}.html"
}
    }
}
EOF
    start_server "$TMPDIR/tf_html.kdl" 8603 \
        || { fail "tf_html/server_start" "hypershunt failed"; return; }

    assert_body "tf_html/implicit_html_lookup" "page-body" \
        "http://127.0.0.1:8603/page"

    stop_server
    rm -rf /tmp/www_html
}
