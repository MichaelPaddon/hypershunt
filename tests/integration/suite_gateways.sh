#!/bin/bash
# Suite: SCGI and FastCGI gateway handlers.

suite_scgi() {
    echo "=== SCGI ==="
    # Minimal SCGI server: reads the netstring header block and sends a
    # fixed 200 response.
    python3 - <<'PYEOF' >/dev/null 2>&1 &
import socket, threading
def handle(conn):
    buf = b""
    while b":" not in buf:
        d = conn.recv(4096)
        if not d: return
        buf += d
    colon = buf.index(b":")
    length = int(buf[:colon])
    buf = buf[colon + 1:]
    while len(buf) < length + 1:
        d = conn.recv(4096)
        if not d: return
        buf += d
    resp = (b"Status: 200 OK\r\n"
            b"Content-Type: text/plain\r\n"
            b"Content-Length: 7\r\n"
            b"\r\n"
            b"scgi ok")
    conn.sendall(resp)
    conn.close()
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 9005))
srv.listen(10)
while True:
    conn, _ = srv.accept()
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
PYEOF
    local backend_pid=$!
    BACKEND_PIDS+=("$backend_pid")
    sleep 0.3

    cat >"$TMPDIR/scgi.kdl" <<'EOF'
listener "tcp://127.0.0.1:8100"
vhost localhost {
    location "/" {
        scgi socket="tcp:127.0.0.1:9005" root="/"
    }
}
EOF
    start_server "$TMPDIR/scgi.kdl" 8100 \
        || { fail "scgi/server_start" "hypershunt failed"; return; }

    assert_status "scgi/200"  200 "http://127.0.0.1:8100/"
    assert_body   "scgi/body" "scgi ok" "http://127.0.0.1:8100/"

    stop_server
    kill "$backend_pid" 2>/dev/null || true
    wait "$backend_pid" 2>/dev/null || true
    BACKEND_PIDS=("${BACKEND_PIDS[@]/$backend_pid}")
}

suite_fastcgi() {
    echo "=== FastCGI ==="
    # Minimal FastCGI server: reads FCGI records, responds after the
    # empty FCGI_STDIN that terminates the request stream.
    python3 - <<'PYEOF' >/dev/null 2>&1 &
import socket, struct, threading

FCGI_STDIN        = 5
FCGI_STDOUT       = 6
FCGI_END_REQUEST  = 3

def recv_exact(conn, n):
    buf = b""
    while len(buf) < n:
        d = conn.recv(n - len(buf))
        if not d: return None
        buf += d
    return buf

def read_record(conn):
    hdr = recv_exact(conn, 8)
    if not hdr: return None
    _ver, rtype, rid, clen, plen = struct.unpack(">BBHHBx", hdr)
    body = recv_exact(conn, clen) or b""
    if plen: recv_exact(conn, plen)
    return rtype, rid, body

def send_record(conn, rtype, rid, data):
    pad = (-len(data)) % 8
    conn.sendall(
        struct.pack(">BBHHBx", 1, rtype, rid, len(data), pad)
        + data + b"\x00" * pad)

def handle(conn):
    req_id = 1
    while True:
        rec = read_record(conn)
        if not rec: break
        rtype, req_id, body = rec
        if rtype == FCGI_STDIN and not body:
            resp = (b"Status: 200 OK\r\n"
                    b"Content-Type: text/plain\r\n"
                    b"\r\n"
                    b"fcgi ok")
            send_record(conn, FCGI_STDOUT, req_id, resp)
            send_record(conn, FCGI_STDOUT, req_id, b"")
            send_record(conn, FCGI_END_REQUEST, req_id,
                        struct.pack(">IB3x", 0, 0))
            conn.settimeout(2)
            try:
                while conn.recv(4096): pass
            except Exception: pass
            break
    conn.close()

srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 9006))
srv.listen(10)
while True:
    conn, _ = srv.accept()
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
PYEOF
    local backend_pid=$!
    BACKEND_PIDS+=("$backend_pid")
    sleep 0.3

    cat >"$TMPDIR/fastcgi.kdl" <<'EOF'
listener "tcp://127.0.0.1:8101"
vhost localhost {
    location "/" {
        fastcgi socket="tcp:127.0.0.1:9006" root="/"
    }
}
EOF
    start_server "$TMPDIR/fastcgi.kdl" 8101 \
        || { fail "fastcgi/server_start" "hypershunt failed"; return; }

    assert_status "fastcgi/200"  200 "http://127.0.0.1:8101/"
    assert_body   "fastcgi/body" "fcgi ok" "http://127.0.0.1:8101/"

    stop_server
    kill "$backend_pid" 2>/dev/null || true
    wait "$backend_pid" 2>/dev/null || true
    BACKEND_PIDS=("${BACKEND_PIDS[@]/$backend_pid}")
}
