#!/bin/bash
# Suite: UDP layer-4 datagram proxy.  Stands up an echo backend on
# UDP/9100, points hypershunt at it as udp://127.0.0.1:9100, drives a
# client packet, and verifies the echo round-trips back through the
# proxy.  Also exercises unix-dgram → unix-dgram via socat.

suite_udp_proxy_inet() {
    echo "=== UDP proxy (inet) ==="
    # Python echo server on UDP/9100.
    python3 - <<'PYEOF' >/dev/null 2>&1 &
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 9100))
while True:
    data, peer = s.recvfrom(65535)
    s.sendto(data, peer)
PYEOF
    local backend_pid=$!
    BACKEND_PIDS+=("$backend_pid")
    sleep 0.3

    cat >"$TMPDIR/udp.kdl" <<'EOF'
listener "udp://127.0.0.1:8100" {
    proxy "udp://127.0.0.1:9100"
}
EOF
    "$HYPERSHUNT" --config "$TMPDIR/udp.kdl" >"$TMPDIR/hypershunt.out" 2>&1 &
    HYPERSHUNT_PID=$!
    sleep 0.4
    if ! kill -0 "$HYPERSHUNT_PID" 2>/dev/null; then
        fail "udp_proxy/server_start" "hypershunt exited"
        cat "$TMPDIR/hypershunt.out" >&2
        HYPERSHUNT_PID=""
        return
    fi

    # Drive one round-trip through the proxy and capture the echo.
    local got
    got=$(python3 - <<'PYEOF'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2.0)
s.sendto(b"udp-ok", ("127.0.0.1", 8100))
data, _ = s.recvfrom(1500)
print(data.decode())
PYEOF
    )
    if [[ "$got" == "udp-ok" ]]; then
        pass "udp_proxy/echo"
    else
        fail "udp_proxy/echo" "expected 'udp-ok', got '$got'"
    fi

    stop_server
    kill "$backend_pid" 2>/dev/null || true
    wait "$backend_pid" 2>/dev/null || true
    BACKEND_PIDS=("${BACKEND_PIDS[@]/$backend_pid}")
}

suite_udp_proxy_unix() {
    echo "=== UDP proxy (unix-dgram) ==="
    local listen_sock="$TMPDIR/udp-listen.sock"
    local backend_sock="$TMPDIR/udp-backend.sock"

    # Echo backend on a unix-dgram socket.
    python3 - "$backend_sock" <<'PYEOF' >/dev/null 2>&1 &
import socket, sys, os
path = sys.argv[1]
try: os.unlink(path)
except FileNotFoundError: pass
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
s.bind(path)
while True:
    data, peer = s.recvfrom(65535)
    if peer:
        s.sendto(data, peer)
PYEOF
    local backend_pid=$!
    BACKEND_PIDS+=("$backend_pid")
    sleep 0.3

    cat >"$TMPDIR/udp-unix.kdl" <<EOF
listener "unix-dgram:${listen_sock}" {
    proxy "unix-dgram:${backend_sock}"
}
EOF
    "$HYPERSHUNT" --config "$TMPDIR/udp-unix.kdl" >"$TMPDIR/hypershunt.out" 2>&1 &
    HYPERSHUNT_PID=$!
    sleep 0.4
    if ! kill -0 "$HYPERSHUNT_PID" 2>/dev/null; then
        fail "udp_proxy_unix/server_start" "hypershunt exited"
        cat "$TMPDIR/hypershunt.out" >&2
        HYPERSHUNT_PID=""
        return
    fi

    local got
    got=$(python3 - "$listen_sock" "$TMPDIR/udp-client.sock" <<'PYEOF'
import socket, sys, os
listen_path, client_path = sys.argv[1], sys.argv[2]
try: os.unlink(client_path)
except FileNotFoundError: pass
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
s.bind(client_path)
s.settimeout(2.0)
s.sendto(b"unix-dgram-ok", listen_path)
data, _ = s.recvfrom(1500)
print(data.decode())
PYEOF
    )
    if [[ "$got" == "unix-dgram-ok" ]]; then
        pass "udp_proxy_unix/echo"
    else
        fail "udp_proxy_unix/echo" "expected 'unix-dgram-ok', got '$got'"
    fi

    stop_server
    kill "$backend_pid" 2>/dev/null || true
    wait "$backend_pid" 2>/dev/null || true
    BACKEND_PIDS=("${BACKEND_PIDS[@]/$backend_pid}")
}
