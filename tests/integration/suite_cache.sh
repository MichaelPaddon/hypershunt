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
        elif p == "/reval":
            # Short freshness; revalidatable.  A conditional request
            # matching our ETag gets 304 without advancing the counter,
            # so a revalidation reuses the cached body.
            inm = self.headers.get("If-None-Match", "")
            if '"v1"' in inm:
                self.send_response(304)
                self.send_header("ETag", '"v1"')
                self.send_header("Cache-Control", "max-age=1")
                self.end_headers()
            else:
                n = bump("reval")
                self.send(("[count=%d]" % n).encode(),
                          [("ETag", '"v1"'),
                           ("Cache-Control", "max-age=1")])
        elif p == "/revalchange":
            # Short freshness; the content always changes, so a
            # revalidation returns a fresh 200 (counter advances).
            n = bump("revalchange")
            self.send(("[count=%d]" % n).encode(),
                      [("ETag", '"r%d"' % n),
                       ("Cache-Control", "max-age=1")])
        elif p == "/slow":
            # Slow origin: counts each request it actually serves and
            # sleeps so concurrent requests overlap.  With single-flight
            # only the leader reaches here, so the counter stays at 1.
            import time
            n = bump("slow")
            time.sleep(1)
            self.send(("[count=%d]" % n).encode(),
                      [("Cache-Control", "max-age=300")])
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
    # A different variant is a miss served its own body (per-variant
    # backend counter), never variant a's "[v=a-1]".
    assert_body "cache/vary_b_distinct" "[v=b-1]" "$base/vary" \
        -H "X-Variant: b"

    # Oversized response (> max-object-size) streams through uncached.
    assert_body "cache/big_1" "[count=1]" "$base/big"
    assert_body "cache/big_2" "[count=2]" "$base/big"

    # Conditional request against a cached entry returns 304 from the
    # cache layer (the backend response had an ETag).
    assert_status "cache/etag_store" 200 "$base/etag"
    assert_status "cache/etag_304" 304 "$base/etag" \
        -H 'If-None-Match: "v1"'

    # Revalidation: store with a 1 s lifetime, let it go stale, then a
    # request revalidates against the origin.  The backend answers 304
    # (counter frozen) so the cached body is reused -- [count=1], not a
    # full refetch that would yield [count=2].
    assert_body "cache/reval_store" "[count=1]" "$base/reval"
    sleep 2
    assert_body "cache/reval_304_reuses_body" "[count=1]" "$base/reval"

    # Revalidation where the origin has changed: a stale entry revalidates
    # and the origin returns a fresh 200, so the new body is served and
    # cached ([count=2]), then re-served from cache.
    assert_body "cache/revalchange_store" "[count=1]" "$base/revalchange"
    sleep 2
    assert_body "cache/revalchange_200_replaces" "[count=2]" \
        "$base/revalchange"
    assert_body "cache/revalchange_rehit" "[count=2]" "$base/revalchange"

    # Single-flight: five concurrent requests for an uncached, slow key.
    # Only the leader reaches the origin (counter == 1), so every
    # response carries [count=1]; without coalescing the origin would be
    # hit up to five times.
    local sf_ok=1 i
    local sf_pids=()
    for i in 1 2 3 4 5; do
        curl -s --max-time 10 "$base/slow" \
            >"$TMPDIR/slow_$i" 2>/dev/null &
        sf_pids+=("$!")
    done
    # Wait only on the curl jobs -- a bare `wait` would also block on
    # the long-running backend and server processes.
    for i in "${sf_pids[@]}"; do
        wait "$i" 2>/dev/null || true
    done
    for i in 1 2 3 4 5; do
        grep -qF "[count=1]" "$TMPDIR/slow_$i" 2>/dev/null || sf_ok=0
    done
    if [ "$sf_ok" = 1 ]; then
        pass "cache/single_flight_coalesces"
    else
        fail "cache/single_flight_coalesces" \
            "concurrent misses were not coalesced to one origin hit"
    fi

    stop_server
}

# Phase 3: client Cache-Control honouring + RFC 5861 stale serving.
suite_cache_phase3() {
    echo "=== Cache: client directives + stale-while/if ==="
    local hport=8308 bport=9308

    python3 - "$bport" <<'PYEOF' >/dev/null 2>&1 &
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
counts = {}
def bump(k):
    counts[k] = counts.get(k, 0) + 1
    return counts[k]
class H(BaseHTTPRequestHandler):
    def send(self, code, body, headers):
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)
    def do_GET(self):
        p = self.path.split("?")[0]
        inm = self.headers.get("If-None-Match", "")
        if p == "/h":
            n = bump("h")
            self.send(200, ("[count=%d]" % n).encode(),
                      [("Cache-Control", "max-age=300")])
        elif p == "/sie":
            # Revalidation always fails; the stale-if-error window lets
            # the cached copy be served instead of the 500.
            if inm:
                self.send(500, b"origin error", [])
            else:
                n = bump("sie")
                self.send(200, ("[count=%d]" % n).encode(),
                          [("ETag", '"s1"'),
                           ("Cache-Control",
                            "max-age=1, stale-if-error=60")])
        elif p == "/swr":
            n = bump("swr")
            self.send(200, ("[count=%d]" % n).encode(),
                      [("ETag", '"w%d"' % n),
                       ("Cache-Control",
                        "max-age=1, stale-while-revalidate=60")])
        else:
            self.send(200, b"ok", [("Cache-Control", "no-store")])
    def log_message(self, *a):
        pass
HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PYEOF
    BACKEND_PIDS+=("$!")
    sleep 0.3

    cat >"$TMPDIR/cache3.kdl" <<EOF
server { cache max-size=1048576 }
listener "tcp://127.0.0.1:$hport"
vhost localhost {
    location "/" {
        cache ttl=300 max-object-size=1024 honor-client-cache-control=#true
        proxy { upstream "http://127.0.0.1:$bport" }
    }
}
EOF
    start_server "$TMPDIR/cache3.kdl" "$hport" \
        || { fail "cache3/server_start" "hypershunt failed"; return; }
    local base="http://127.0.0.1:$hport"

    # Client no-store bypasses the cache (origin hit) and does not store,
    # so the previously cached value is still served afterwards.
    assert_body "cache/cc_store" "[count=1]" "$base/h"
    assert_body "cache/cc_no_store_bypass" "[count=2]" "$base/h" \
        -H "Cache-Control: no-store"
    assert_body "cache/cc_cache_intact" "[count=1]" "$base/h"

    # only-if-cached with nothing cached -> 504, no origin contact.
    assert_status "cache/cc_only_if_cached_504" 504 "$base/uncached" \
        -H "Cache-Control: only-if-cached"

    # stale-if-error: once stale, a failing revalidation serves the
    # stale body (HTTP 200, [count=1]) instead of the origin's 500.
    assert_body "cache/sie_store" "[count=1]" "$base/sie"
    sleep 2
    assert_status "cache/sie_serves_stale_200" 200 "$base/sie"
    assert_body "cache/sie_serves_stale_body" "[count=1]" "$base/sie"

    # stale-while-revalidate: once stale, the stale body is served at
    # once and a background refresh updates the cache for next time.
    assert_body "cache/swr_store" "[count=1]" "$base/swr"
    sleep 2
    assert_body "cache/swr_serves_stale" "[count=1]" "$base/swr"
    sleep 1
    assert_body "cache/swr_refreshed" "[count=2]" "$base/swr"

    stop_server
}
