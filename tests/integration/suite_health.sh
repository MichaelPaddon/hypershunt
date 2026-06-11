#!/bin/bash
# Suite: built-in health endpoints -- custom paths, per-listener
# exposure, and drain-aware readiness (lame-duck) on SIGTERM.

suite_health_config() {
    echo "=== Health: custom paths + per-listener exposure ==="
    cat >"$TMPDIR/health.kdl" <<'EOF'
server {
    health {
        liveness-path "/alive"
        readiness-path "/ready"
    }
}
listener "tcp://127.0.0.1:18502"
listener "tcp://127.0.0.1:18503" health=#false
vhost "h" {
    location "/" { redirect to="/elsewhere" code=301 }
}
EOF
    start_server "$TMPDIR/health.kdl" 18502 \
        || { fail "health/endpoints/start"; return; }

    # Custom liveness/readiness paths are served on the default listener.
    assert_status "health/custom_alive" 200 "http://127.0.0.1:18502/alive"
    assert_status "health/custom_ready" 200 "http://127.0.0.1:18502/ready"
    # The built-in default paths are NOT health once overridden: they fall
    # through to routing (the catch-all redirect -> 301).
    assert_status "health/default_overridden" 301 \
        "http://127.0.0.1:18502/readyz"

    # health=#false: the second listener serves no health -- /alive falls
    # through to routing (301), it is not a 200 health response.
    assert_status "health/per_listener_off" 301 \
        "http://127.0.0.1:18503/alive"

    stop_server
}

# SIGTERM with a lame-duck window: the listener keeps accepting and
# serving for the window, but readiness flips to 503 immediately so a
# load balancer deregisters before connections start being refused.
# Liveness stays 200 (a draining process is still alive).
suite_health_lame_duck() {
    echo "=== Health: drain-aware readiness (lame-duck) ==="
    cat >"$TMPDIR/health.kdl" <<'EOF'
server lame-duck-timeout=5
listener "tcp://127.0.0.1:18501"
vhost "h" {
    location "/" { redirect to="/elsewhere" code=301 }
}
EOF
    start_server "$TMPDIR/health.kdl" 18501 \
        || { fail "health/lame-duck/start"; return; }

    assert_status "health/readyz_before" 200 "http://127.0.0.1:18501/readyz"
    assert_status "health/livez_before" 200 "http://127.0.0.1:18501/livez"

    # Begin graceful shutdown.  Within the 5s lame-duck window the server
    # is still accepting new connections, so a *fresh* probe observes the
    # 503 (not a connection refusal).
    kill -TERM "$HYPERSHUNT_PID"
    sleep 0.5

    assert_status "health/readyz_draining" 503 \
        "http://127.0.0.1:18501/readyz"
    assert_status "health/livez_draining" 200 \
        "http://127.0.0.1:18501/livez"

    # Let the window elapse; the server then stops accepting and exits.
    # stop_server sends a (redundant) TERM and reaps it.
    stop_server
}
