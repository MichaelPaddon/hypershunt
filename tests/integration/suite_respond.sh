#!/bin/bash
# Suite: the `respond` handler -- inline + file-backed static responses,
# status codes, Content-Type defaulting, body templating, and the
# config-relative resolution of file= paths.

suite_respond() {
    echo "=== respond: inline / file / templated static responses ==="
    # maint.html sits next to the config; respond file="maint.html" must
    # resolve it relative to the config file's directory, not the CWD.
    cat >"$TMPDIR/maint.html" <<'EOF'
<h1>Down for maintenance</h1>
EOF
    cat >"$TMPDIR/respond.kdl" <<'EOF'
listener "tcp://127.0.0.1:18601"
vhost "r" {
    location "/ok"     { respond status=200 body="OK\n" content-type="text/plain" }
    location "/teapot" { respond status=418 body="brew\n" }
    location "/empty"  { respond status=403 }
    location "/maint"  { respond status=503 file="maint.html" content-type="text/html" }
    location "/whoami" { respond status=200 body="host={host} path={path}\n" }
}
EOF
    start_server "$TMPDIR/respond.kdl" 18601 \
        || { fail "respond/start"; return; }

    # Inline body + explicit Content-Type.
    assert_status "respond/ok_status" 200 "http://127.0.0.1:18601/ok"
    assert_body   "respond/ok_body" "OK" "http://127.0.0.1:18601/ok"
    assert_header "respond/ok_ctype" "Content-Type" "text/plain" \
        "http://127.0.0.1:18601/ok"

    # Arbitrary status code, default Content-Type.
    assert_status "respond/teapot_status" 418 "http://127.0.0.1:18601/teapot"
    assert_body   "respond/teapot_body" "brew" "http://127.0.0.1:18601/teapot"

    # No body -> the status alone (empty body).
    assert_status "respond/empty_status" 403 "http://127.0.0.1:18601/empty"

    # File-backed body, path resolved relative to the config file.
    assert_status "respond/maint_status" 503 "http://127.0.0.1:18601/maint"
    assert_body   "respond/maint_body" "Down for maintenance" \
        "http://127.0.0.1:18601/maint"
    assert_header "respond/maint_ctype" "Content-Type" "text/html" \
        "http://127.0.0.1:18601/maint"

    # Templated inline body expands request variables.
    assert_body "respond/whoami_template" "path=/whoami" \
        "http://127.0.0.1:18601/whoami"

    # HEAD reports Content-Length without sending a body.
    assert_header "respond/ok_head_len" "Content-Length" "3" \
        "http://127.0.0.1:18601/ok" -I

    stop_server
}
