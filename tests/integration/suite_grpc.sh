#!/bin/bash
# Suite: gRPC proxying -- h2c transport, trailer passthrough, and the
# mapping of hypershunt-generated failures onto gRPC status codes.
#
# Drives the shipped release binary with `curl --http2-prior-knowledge`
# against the test-only `grpc_echo` backend, which answers
# `application/grpc` with a `grpc-status` trailer.  The Rust unit tests
# cover the same ground through the in-process TestServer; this pins it
# end to end through the real binary and a real HTTP/2 client.

suite_grpc() {
    echo "=== gRPC (h2c transport + status mapping) ==="

    grpc_echo 127.0.0.1:9500 >"$TMPDIR/grpc_echo.out" 2>&1 &
    local backend_pid=$!
    BACKEND_PIDS+=("$backend_pid")
    sleep 0.3

    cat >"$TMPDIR/grpc.kdl" <<'EOF'
listener "tcp://127.0.0.1:8500"
vhost "localhost" {
    // Port 1 is reliably refused, so this location always fails to
    // reach a backend.
    location "/down/" {
        proxy {
 upstream "http://127.0.0.1:1"
 grpc
}
    }
    location "/deny/" {
        policy { deny code=403 }
        proxy {
 upstream "http://127.0.0.1:9500"
 grpc
}
    }
    // Deliberately not a catch-all: a request to some other path
    // must be able to miss the route so the 404 mapping is
    // exercised.
    location "/echo/" {
        proxy {
 upstream "http://127.0.0.1:9500"
 grpc
}
    }
}
EOF
    "$HYPERSHUNT" --config "$TMPDIR/grpc.kdl" \
        >"$TMPDIR/hypershunt.out" 2>&1 &
    HYPERSHUNT_PID=$!
    sleep 0.4
    if ! kill -0 "$HYPERSHUNT_PID" 2>/dev/null; then
        fail "grpc/server_start" "hypershunt exited"
        cat "$TMPDIR/hypershunt.out" >&2
        HYPERSHUNT_PID=""
        return
    fi

    local h2="--http2-prior-knowledge"
    local ct="content-type: application/grpc"

    # Happy path.  Reaching the backend at all proves h2c was
    # negotiated: grpc_echo speaks HTTP/2 only, so an HTTP/1.1
    # outbound leg could not have connected.  The `grpc-status: 0`
    # comes back as a real trailer from the backend.
    assert_status "grpc/unary/status_200" 200 \
        "http://127.0.0.1:8500/echo/pkg.Svc/M" \
        $h2 -X POST -H "$ct" -H "te: trailers" --data-binary "hello"
    assert_header "grpc/unary/trailer_ok" "grpc-status" "0" \
        "http://127.0.0.1:8500/echo/pkg.Svc/M" \
        $h2 -X POST -H "$ct" -H "te: trailers" --data-binary "hello"
    assert_body "grpc/unary/body_echoed" "hello" \
        "http://127.0.0.1:8500/echo/pkg.Svc/M" \
        $h2 -X POST -H "$ct" -H "te: trailers" --data-binary "hello"

    # Backend unreachable: a plain 502 tells a gRPC client nothing, so
    # it becomes a trailers-only 200 carrying UNAVAILABLE (14).
    assert_status "grpc/dead_upstream/status_200" 200 \
        "http://127.0.0.1:8500/down/M" $h2 -X POST -H "$ct"
    assert_header "grpc/dead_upstream/unavailable" "grpc-status" "14" \
        "http://127.0.0.1:8500/down/M" $h2 -X POST -H "$ct"

    # Access policy: PERMISSION_DENIED (7).
    assert_header "grpc/policy_deny/permission_denied" \
        "grpc-status" "7" \
        "http://127.0.0.1:8500/deny/M" $h2 -X POST -H "$ct"

    # No route: UNIMPLEMENTED (12), the code a gRPC client expects for
    # a method the server does not serve.
    assert_header "grpc/no_route/unimplemented" "grpc-status" "12" \
        "http://127.0.0.1:8500/nope/M" $h2 -X POST -H "$ct"

    # The mapping is keyed on the request content-type, so a
    # non-gRPC request to the same broken location is untouched.
    assert_status "grpc/non_grpc_request_still_502" 502 \
        "http://127.0.0.1:8500/down/M" $h2

    stop_server
}
