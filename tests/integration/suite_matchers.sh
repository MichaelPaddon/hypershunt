#!/bin/bash
# Suite: per-location request matchers.
#
# Verifies that `match { method | header | query }` predicates
# narrow which location a request hits, and that the router
# falls through to the next-best candidate (longer prefix first,
# declaration order on ties) when a matcher rejects.

# Method dispatch: two locations at the same prefix, one
# matching only POST and one matching everything else.
suite_match_method_dispatch() {
    echo "=== Match: method dispatch ==="
    cat >"$TMPDIR/m_method.kdl" <<'EOF'
listener "tcp://127.0.0.1:8401"
vhost localhost {
    location "/" {
        match { method "POST" }
        static root="/tmp/www_post"
    }
    location "/" {
        static root="/tmp/www"
    }
}
EOF
    mkdir -p /tmp/www_post
    echo "post-body" > /tmp/www_post/index.html
    start_server "$TMPDIR/m_method.kdl" 8401 \
        || { fail "m_method/server_start" "hypershunt failed"; return; }

    # GET -> the unmatched location (the default content).
    assert_body "m_method/get_falls_through" "Hello hypershunt" \
        "http://127.0.0.1:8401/" -X GET
    # POST -> the method-matched location, serving its alternate root.
    assert_body "m_method/post_takes_match" "post-body" \
        "http://127.0.0.1:8401/" -X POST

    stop_server
    rm -rf /tmp/www_post
}

# Header regex predicate; falls through to a shorter prefix
# location when the header is absent.
suite_match_header_regex() {
    echo "=== Match: header regex with shorter-prefix fall-through ==="
    cat >"$TMPDIR/m_hdr.kdl" <<'EOF'
listener "tcp://127.0.0.1:8402"
vhost localhost {
    location "/" {
        static root="/tmp/www"
    }
    location "/api/" {
        match { header "X-API-Version" "~^v[23]$" }
        static root="/tmp/www_api"
    }
}
EOF
    mkdir -p /tmp/www_api/api
    echo "api-v2-body" > /tmp/www_api/api/index.html
    start_server "$TMPDIR/m_hdr.kdl" 8402 \
        || { fail "m_hdr/server_start" "hypershunt failed"; return; }

    # With the header: hits the /api/ location.
    assert_body "m_hdr/v2_matches" "api-v2-body" \
        "http://127.0.0.1:8402/api/" -H "X-API-Version: v2"
    assert_body "m_hdr/v3_matches" "api-v2-body" \
        "http://127.0.0.1:8402/api/" -H "X-API-Version: v3"
    # v1 fails the regex -> fall through to /, which serves the
    # default web root and 404s on /api/ unless setup_webroot
    # created it.  We assert via status code so the test stays
    # independent of which content (if any) lives under /api/ in
    # the generic root.
    assert_status "m_hdr/v1_falls_through" 404 \
        "http://127.0.0.1:8402/api/" -H "X-API-Version: v1"
    # Header missing -> same fall-through.
    assert_status "m_hdr/missing_falls_through" 404 \
        "http://127.0.0.1:8402/api/"

    stop_server
    rm -rf /tmp/www_api
}

# Query parameter predicate.
suite_match_query() {
    echo "=== Match: query parameter ==="
    cat >"$TMPDIR/m_q.kdl" <<'EOF'
listener "tcp://127.0.0.1:8403"
vhost localhost {
    location "/" {
        match { query "format" "json" }
        static root="/tmp/www_json"
    }
    location "/" {
        static root="/tmp/www"
    }
}
EOF
    mkdir -p /tmp/www_json
    echo "json-body" > /tmp/www_json/index.html
    start_server "$TMPDIR/m_q.kdl" 8403 \
        || { fail "m_q/server_start" "hypershunt failed"; return; }

    assert_body "m_q/json_matches" "json-body" \
        "http://127.0.0.1:8403/?format=json"
    assert_body "m_q/other_value_falls_through" "Hello hypershunt" \
        "http://127.0.0.1:8403/?format=xml"
    assert_body "m_q/no_query_falls_through" "Hello hypershunt" \
        "http://127.0.0.1:8403/"

    stop_server
    rm -rf /tmp/www_json
}

# Path regex predicate routes by file extension; non-image
# requests fall through to the catch-all location.
suite_match_path_regex() {
    echo "=== Match: path regex ==="
    mkdir -p /tmp/www_img
    echo "image-body" > /tmp/www_img/cat.jpg
    cat >"$TMPDIR/m_path.kdl" <<'EOF'
listener "tcp://127.0.0.1:8405"
vhost localhost {
    location "/" {
        match { path "[.](jpg|png)$" }
        static root="/tmp/www_img"
    }
    location "/" {
        static root="/tmp/www"
    }
}
EOF
    start_server "$TMPDIR/m_path.kdl" 8405 \
        || { fail "m_path/server_start" "hypershunt failed"; return; }

    assert_body "m_path/jpg_hits_match" "image-body" \
        "http://127.0.0.1:8405/cat.jpg"
    assert_body "m_path/non_image_falls_through" "Hello hypershunt" \
        "http://127.0.0.1:8405/"

    stop_server
    rm -rf /tmp/www_img
}

# header-absent: route anonymous (no Authorization) requests
# through the matcher; authenticated requests fall through.
suite_match_header_absent() {
    echo "=== Match: header-absent ==="
    mkdir -p /tmp/www_anon
    echo "anon-body" > /tmp/www_anon/index.html
    cat >"$TMPDIR/m_absent.kdl" <<'EOF'
listener "tcp://127.0.0.1:8406"
vhost localhost {
    location "/" {
        match { header-absent "Authorization" }
        static root="/tmp/www_anon"
    }
    location "/" {
        static root="/tmp/www"
    }
}
EOF
    start_server "$TMPDIR/m_absent.kdl" 8406 \
        || { fail "m_absent/server_start" "hypershunt failed"; return; }

    # No Authorization: hits the matcher's location.
    assert_body "m_absent/no_header_matches" "anon-body" \
        "http://127.0.0.1:8406/"
    # With Authorization: header-absent predicate fails -> the
    # other location wins.
    assert_body "m_absent/header_present_falls_through" \
        "Hello hypershunt" \
        "http://127.0.0.1:8406/" -H "Authorization: Bearer x"

    stop_server
    rm -rf /tmp/www_anon
}

# Negation: not { method "GET" } -> match anything except GET.
suite_match_negation() {
    echo "=== Match: negation block ==="
    mkdir -p /tmp/www_notget
    echo "non-get" > /tmp/www_notget/index.html
    cat >"$TMPDIR/m_not.kdl" <<'EOF'
listener "tcp://127.0.0.1:8407"
vhost localhost {
    location "/" {
        match { not { method "GET" } }
        static root="/tmp/www_notget"
    }
    location "/" {
        static root="/tmp/www"
    }
}
EOF
    start_server "$TMPDIR/m_not.kdl" 8407 \
        || { fail "m_not/server_start" "hypershunt failed"; return; }

    # GET: negation fails -> fall through to the default root.
    assert_body "m_not/get_falls_through" "Hello hypershunt" \
        "http://127.0.0.1:8407/" -X GET
    # POST: negation matches -> hits the wrapped location.
    assert_body "m_not/post_matches" "non-get" \
        "http://127.0.0.1:8407/" -X POST

    stop_server
    rm -rf /tmp/www_notget
}

# All-predicates-must-match (AND across predicates).
suite_match_and_semantics() {
    echo "=== Match: AND across predicates ==="
    cat >"$TMPDIR/m_and.kdl" <<'EOF'
listener "tcp://127.0.0.1:8404"
vhost localhost {
    location "/" {
        match {
            method "POST"
            header "X-Tenant" "acme"
        }
        static root="/tmp/www_acme"
    }
    location "/" {
        static root="/tmp/www"
    }
}
EOF
    mkdir -p /tmp/www_acme
    echo "acme-body" > /tmp/www_acme/index.html
    start_server "$TMPDIR/m_and.kdl" 8404 \
        || { fail "m_and/server_start" "hypershunt failed"; return; }

    # Both predicates satisfied -> match.
    assert_body "m_and/both_satisfied" "acme-body" \
        "http://127.0.0.1:8404/" -X POST -H "X-Tenant: acme"
    # Method ok but wrong tenant -> fall through.
    assert_body "m_and/wrong_tenant" "Hello hypershunt" \
        "http://127.0.0.1:8404/" -X POST -H "X-Tenant: other"
    # Right tenant but wrong method -> fall through.
    assert_body "m_and/wrong_method" "Hello hypershunt" \
        "http://127.0.0.1:8404/" -X GET -H "X-Tenant: acme"

    stop_server
    rm -rf /tmp/www_acme
}
