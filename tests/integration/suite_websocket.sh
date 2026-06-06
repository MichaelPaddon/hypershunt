#!/bin/bash
# Suite: transparent WebSocket / HTTP-Upgrade reverse proxying.
#
# Stands up a Python `websockets` echo server, points hypershunt at it
# via a normal `proxy` location, drives a WS client through hypershunt,
# and round-trips a text frame.  This pins the inbound-h1
# detection + outbound-h1 tunnel + bidi-pump end-to-end through
# the shipped release binary (rather than the Rust unit test,
# which uses the in-process TestServer).

suite_websocket_h1_h1() {
    echo "=== WebSocket (h1 inbound -> h1 outbound) ==="
    # WS echo backend on 127.0.0.1:9300.
    python3 - <<'PYEOF' >/dev/null 2>&1 &
import asyncio
from websockets.asyncio.server import serve

async def echo(ws):
    async for msg in ws:
        await ws.send(msg)

async def main():
    async with serve(echo, "127.0.0.1", 9300):
        await asyncio.Future()

asyncio.run(main())
PYEOF
    local backend_pid=$!
    BACKEND_PIDS+=("$backend_pid")
    # WS server boot is async; give python a moment to bind.
    sleep 0.5

    cat >"$TMPDIR/ws.kdl" <<'EOF'
listener "tcp://127.0.0.1:8300"
vhost "localhost" {
    location "/" {
        proxy {
 upstream "http://127.0.0.1:9300"
}
    }
}
EOF
    "$HYPERSHUNT" --config "$TMPDIR/ws.kdl" >"$TMPDIR/hypershunt.out" 2>&1 &
    HYPERSHUNT_PID=$!
    sleep 0.4
    if ! kill -0 "$HYPERSHUNT_PID" 2>/dev/null; then
        fail "websocket/server_start" "hypershunt exited"
        cat "$TMPDIR/hypershunt.out" >&2
        HYPERSHUNT_PID=""
        return
    fi

    # Drive a single text frame through hypershunt and expect the echo
    # to come back unchanged.  Bounds the round-trip with a 2 s
    # timeout so a broken upgrade path can't hang the suite.
    local got
    got=$(python3 - <<'PYEOF'
import asyncio
from websockets.asyncio.client import connect

async def main():
    async with connect("ws://127.0.0.1:8300/echo") as ws:
        await ws.send("hello-hypershunt")
        reply = await asyncio.wait_for(ws.recv(), timeout=2.0)
        print(reply)

asyncio.run(main())
PYEOF
    )
    if [[ "$got" == "hello-hypershunt" ]]; then
        pass "websocket/h1_h1/echo"
    else
        fail "websocket/h1_h1/echo" \
            "expected 'hello-hypershunt', got '$got'"
    fi

    stop_server
    kill "$backend_pid" 2>/dev/null || true
    wait "$backend_pid" 2>/dev/null || true
    BACKEND_PIDS=("${BACKEND_PIDS[@]/$backend_pid}")
}

# h1 client -> hypershunt (scheme="h2c") -> h2 prior-knowledge backend.
#
# Exercises the cross-protocol upgrade bridge: hypershunt translates
# the inbound h1 `Upgrade:` into h2 `:method CONNECT` +
# `:protocol`, the backend returns 200, hypershunt synthesises the
# 101 + Sec-WebSocket-Accept back to the h1 client.
#
# Verified by hand-rolled HTTP/1.1 over TCP (rather than a real
# WS library) so this stays a HANDSHAKE test -- end-to-end byte
# pumping for WebSocket specifically requires the frame-mask
# translator tracked in issue #35.  Generic byte-tunnel users of
# this bridge work today.
suite_websocket_h1_h2c() {
    echo "=== WebSocket (h1 inbound -> h2c outbound) ==="
    # h2 prior-knowledge CONNECT-extended echo backend.
    h2c_connect_echo 127.0.0.1:9401 >"$TMPDIR/h2c.out" 2>&1 &
    local backend_pid=$!
    BACKEND_PIDS+=("$backend_pid")
    sleep 0.3

    cat >"$TMPDIR/ws_h2c.kdl" <<'EOF'
listener "tcp://127.0.0.1:8301"
vhost "localhost" {
    location "/" {
        proxy scheme="h2c" {
            upstream "http://127.0.0.1:9401"
        }
    }
}
EOF
    "$HYPERSHUNT" --config "$TMPDIR/ws_h2c.kdl" >"$TMPDIR/hypershunt.out" 2>&1 &
    HYPERSHUNT_PID=$!
    sleep 0.4
    if ! kill -0 "$HYPERSHUNT_PID" 2>/dev/null; then
        fail "websocket_h2c/server_start" "hypershunt exited"
        cat "$TMPDIR/hypershunt.out" >&2
        HYPERSHUNT_PID=""
        return
    fi

    # Hand-roll the h1 upgrade request and slurp the response head
    # via python (more portable than nc -q, which differs across
    # netcat flavours).  Bound the whole exchange with a timeout
    # so a broken bridge can't hang the suite.
    local response
    response=$(python3 - <<'PYEOF'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(2.0)
s.connect(("127.0.0.1", 8301))
s.sendall(
    b"GET /ws HTTP/1.1\r\n"
    b"Host: localhost\r\n"
    b"Connection: Upgrade\r\n"
    b"Upgrade: websocket\r\n"
    b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
    b"Sec-WebSocket-Version: 13\r\n"
    b"\r\n"
)
# Drain just the response head; we don't need a full WS handshake
# here (frame masking translation is tracked in issue #35).
buf = b""
while b"\r\n\r\n" not in buf:
    chunk = s.recv(4096)
    if not chunk:
        break
    buf += chunk
print(buf.decode("latin-1"))
PYEOF
    )

    # First line should be `HTTP/1.1 101 Switching Protocols`.
    if echo "$response" | head -1 | grep -q "^HTTP/1.1 101"; then
        pass "websocket/h1_h2c/101"
    else
        fail "websocket/h1_h2c/101" \
            "expected '101 Switching Protocols', got: $(echo "$response" | head -1)"
    fi

    # Sec-WebSocket-Accept derived from the RFC 6455 §1.3 sample
    # key `dGhlIHNhbXBsZSBub25jZQ==` is the well-known constant
    # `s3pPLMBiTxaQ9kYGzzhZRbK+xOo=`.  Hypershunt computes this
    # locally when bridging h1 -> h2 because RFC 8441 §5.1
    # elides the Key/Accept round-trip on the h2 side.
    if echo "$response" \
        | grep -Eqi "^Sec-WebSocket-Accept:[[:space:]]+s3pPLMBiTxaQ9kYGzzhZRbK\\+xOo="
    then
        pass "websocket/h1_h2c/accept"
    else
        fail "websocket/h1_h2c/accept" \
            "expected Sec-WebSocket-Accept header in response: $response"
    fi

    stop_server
    kill "$backend_pid" 2>/dev/null || true
    wait "$backend_pid" 2>/dev/null || true
    BACKEND_PIDS=("${BACKEND_PIDS[@]/$backend_pid}")
}
