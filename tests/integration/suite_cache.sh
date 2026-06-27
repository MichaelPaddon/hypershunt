#!/bin/bash
# Suite: HTTP response cache (RFC 9111, phase 1).
#
# A small counter backend makes cache hits observable: when a response
# is served from cache the backend counter does NOT advance, so the
# body stays "[count=1]".  Uncacheable responses (no-store, Set-Cookie,
# oversized, a different Vary variant) advance the counter, proving the
# request reached the origin.

# Start the shared counter backend on $1 and a cache-enabled
# hypershunt (proxying to it) on $2, then run the assertions.
suite_cache_proxy() {
    echo "=== Cache: proxy response caching ==="
    local hport=8307 bport=9307

    # Counter backend: per-path counters, with cache directives chosen
    # per route to exercise each cacheability rule.
    python3 - "$bport" <<'PYEOF' >/dev/null 2>&1 &
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
counts = {}
def bump(k):
    counts[k] = counts.get(k, 0) + 1
    return counts[k]
class H(BaseHTTPRequestHandler):
    def send(self, body, headers):
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)
    def do_GET(self):
        p = self.path.split("?")[0]
        if p == "/count":
            n = bump("count")
            self.send(("[count=%d]" % n).encode(),
                      [("Cache-Control", "max-age=300")])
        elif p == "/nostore":
            n = bump("nostore")
            self.send(("[count=%d]" % n).encode(),
                      [("Cache-Control", "no-store")])
        elif p == "/cookie":
            n = bump("cookie")
            self.send(("[count=%d]" % n).encode(),
                      [("Set-Cookie", "sid=abc"),
                       ("Cache-Control", "max-age=300")])
        elif p == "/vary":
            var = self.headers.get("X-Variant", "none")
            n = bump("vary-" + var)
            self.send(("[v=%s-%d]" % (var, n)).encode(),
                      [("Vary", "X-Variant"),
                       ("Cache-Control", "max-age=300")])
        elif p == "/big":
            n = bump("big")
            body = ("[count=%d]" % n).encode() + b"x" * 4096
            self.send(body, [("Cache-Control", "max-age=300")])
        elif p == "/etag":
            self.send(b"etagbody",
                      [("ETag", '"v1"'),
                       ("Cache-Control", "max-age=300")])
        else:
            # Liveness poll and anything else: never cached.
            self.send(b"ok", [("Cache-Control", "no-store")])
    def log_message(self, *a):
        pass
HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PYEOF
    BACKEND_PIDS+=("$!")
    sleep 0.3

    cat >"$TMPDIR/cache.kdl" <<EOF
server { cache max-size=1048576 }
listener "tcp://127.0.0.1:$hport"
vhost localhost {
    location "/" {
        cache ttl=300 max-object-size=1024
        proxy { upstream "http://127.0.0.1:$bport" }
    }
}
EOF
    start_server "$TMPDIR/cache.kdl" "$hport" \
        || { fail "cache/server_start" "hypershunt failed"; return; }

    local base="http://127.0.0.1:$hport"

    # MISS then HIT: the second request is served from cache, so the
    # backend counter does not advance.
    assert_body "cache/miss_first" "[count=1]" "$base/count"
    assert_body "cache/hit_second" "[count=1]" "$base/count"
    # A hit carries an Age header.
    assert_header "cache/hit_has_age" "age" "[0-9]" "$base/count"

    # Age grows while the entry sits in cache.
    sleep 1
    assert_header "cache/age_grows" "age" "[1-9]" "$base/count"

    # no-store is honoured: never cached, counter advances each time.
    assert_body "cache/nostore_1" "[count=1]" "$base/nostore"
    assert_body "cache/nostore_2" "[count=2]" "$base/nostore"

    # Set-Cookie responses are never cached (per-client state).
    assert_body "cache/cookie_1" "[count=1]" "$base/cookie"
    assert_body "cache/cookie_2" "[count=2]" "$base/cookie"

    # Vary: a variant is reused; a different variant value is a miss
    # and must not be served the first variant's body.
    assert_body "cache/vary_a_miss" "[v=a-1]" "$base/vary" \
        -H "X-Variant: a"
    assert_body "cache/vary_a_hit" "[v=a-1]" "$base/vary" \
        -H "X-Variant: a"
    assert_body "cache/vary_b_distinct" "[v=b-2]" "$base/vary" \
        -H "X-Variant: b"

    # Oversized response (> max-object-size) streams through uncached.
    assert_body "cache/big_1" "[count=1]" "$base/big"
    assert_body "cache/big_2" "[count=2]" "$base/big"

    # Conditional request against a cached entry returns 304 from the
    # cache layer (the backend response had an ETag).
    assert_status "cache/etag_store" 200 "$base/etag"
    assert_status "cache/etag_304" 304 "$base/etag" \
        -H 'If-None-Match: "v1"'

    stop_server
}
