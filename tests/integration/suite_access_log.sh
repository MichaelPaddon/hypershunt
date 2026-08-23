#!/bin/bash
# Suite: per-server access-log formats (json / common / combined).
#
# Each sub-test starts hypershunt pointed at a fresh access-log file with
# the format under test, makes a couple of requests, then validates
# the on-disk format of the captured lines.

suite_access_log_common() {
    echo "=== access-log format=common writes NCSA lines ==="

    local logfile="$TMPDIR/access_common.log"
    : > "$logfile"

    cat >"$TMPDIR/access_common.kdl" <<EOF
server {
    access-log "common" path="$logfile"
}
listener "tcp://127.0.0.1:8290"
vhost localhost {
    location "/" {
        static root="/tmp/www" {
index-file index.html;
}
    }
}
EOF
    start_server "$TMPDIR/access_common.kdl" 8290 \
        || { fail "access_log/common/start" "hypershunt failed"; return; }

    assert_status "access_log/common/200" 200 \
        "http://127.0.0.1:8290/" -H "Host: localhost"

    stop_server

    # Common log shape:
    #   <peer> - - [<date>] "GET / HTTP/1.1" 200 <bytes>
    if grep -E '^127\.0\.0\.1:[0-9]+ - - \[[^]]+\] "GET / HTTP/1\.1" 200 [0-9-]+' \
            "$logfile" >/dev/null; then
        pass "access_log/common/format_matches"
    else
        fail "access_log/common/format_matches" \
            "no matching common-format line; got:\n$(cat "$logfile")"
    fi
}

suite_access_log_combined() {
    echo "=== access-log format=combined appends referer + agent ==="

    local logfile="$TMPDIR/access_combined.log"
    : > "$logfile"

    cat >"$TMPDIR/access_combined.kdl" <<EOF
server {
    access-log "combined" path="$logfile"
}
listener "tcp://127.0.0.1:8291"
vhost localhost {
    location "/" {
        static root="/tmp/www" {
index-file index.html;
}
    }
}
EOF
    start_server "$TMPDIR/access_combined.kdl" 8291 \
        || { fail "access_log/combined/start" "hypershunt failed"; return; }

    curl -s -o /dev/null --max-time 5 \
        -H "Host: localhost" \
        -H "Referer: https://ref.example/" \
        -A "hypershunttest/1.0" \
        "http://127.0.0.1:8291/" || true

    stop_server

    # Combined log shape ends with: "<referer>" "<user-agent>".
    if grep -F '"https://ref.example/" "hypershunttest/1.0"' "$logfile" \
            >/dev/null; then
        pass "access_log/combined/referer_and_agent"
    else
        fail "access_log/combined/referer_and_agent" \
            "referer+agent tokens missing; got:\n$(cat "$logfile")"
    fi
}

suite_access_log_json() {
    echo "=== access-log format=json writes ndjson lines ==="

    local logfile="$TMPDIR/access_json.log"
    : > "$logfile"

    cat >"$TMPDIR/access_json.kdl" <<EOF
server {
    access-log "json" path="$logfile"
}
listener "tcp://127.0.0.1:8292"
vhost localhost {
    location "/" {
        static root="/tmp/www" {
index-file index.html;
}
    }
}
EOF
    start_server "$TMPDIR/access_json.kdl" 8292 \
        || { fail "access_log/json/start" "hypershunt failed"; return; }

    curl -s -o /dev/null --max-time 5 -H "Host: localhost" \
        -A "hypershunttest/json" "http://127.0.0.1:8292/" || true

    stop_server

    # The last line is the user-issued GET; the startup readiness
    # probe in start_server lands on an earlier line with curl's
    # default user-agent, so anchoring on `tail -n 1` avoids confusing
    # the two.
    local line
    line=$(tail -n 1 "$logfile")
    # Each JSON line must contain the documented field names.  We do
    # cheap substring checks so the suite doesn't take a hard dep on
    # jq, but the line MUST start with '{' and end with '}'.
    if [[ "$line" == \{* && "$line" == *\} ]]; then
        pass "access_log/json/wrapped_object"
    else
        fail "access_log/json/wrapped_object" \
            "not a JSON object; got: $line"
    fi
    for field in '"peer"' '"method":"GET"' '"path":"/"' \
                 '"status":200' '"protocol":"HTTP/1.1"' \
                 '"user_agent":"hypershunttest/json"'; do
        if [[ "$line" == *"$field"* ]]; then
            pass "access_log/json/has_$field"
        else
            fail "access_log/json/has_$field" \
                "missing $field in: $line"
        fi
    done
}

suite_access_log_fields() {
    echo "=== access-log field renders template variables ==="

    local logfile="$TMPDIR/access_fields.log"
    : > "$logfile"

    # `tenant` is derived from a request header, so two requests with
    # different headers must produce two different log values -- the
    # whole point of the feature.
    cat >"$TMPDIR/access_fields.kdl" <<EOF
server {
    variable "tenant" {
        match "{header:x-tenant}" {
            "^acme\$"  "acme"
            "^globex\$" "globex"
            _          "unknown"
        }
    }
    access-log "json" path="$logfile" {
        field "tenant" "{tenant}"
        field "lane" "{header:x-lane|none}"
    }
}
listener "tcp://127.0.0.1:8293"
vhost localhost {
    location "/" {
        static root="/tmp/www" {
index-file index.html;
}
    }
}
EOF
    start_server "$TMPDIR/access_fields.kdl" 8293 \
        || { fail "access_log/fields/start" "hypershunt failed"; return; }

    curl -s -o /dev/null --max-time 5 -H "Host: localhost" \
        -H "X-Tenant: acme" -H "X-Lane: fast" \
        "http://127.0.0.1:8293/" || true
    curl -s -o /dev/null --max-time 5 -H "Host: localhost" \
        -H "X-Tenant: globex" "http://127.0.0.1:8293/" || true
    # Unrouted built-in endpoint: must still log, with empty fields.
    curl -s -o /dev/null --max-time 5 -H "Host: localhost" \
        "http://127.0.0.1:8293/healthz" || true

    stop_server

    local acme_line globex_line health_line
    acme_line=$(grep '"tenant":"acme"' "$logfile" | tail -n 1)
    globex_line=$(grep '"tenant":"globex"' "$logfile" | tail -n 1)
    health_line=$(grep '"path":"/healthz"' "$logfile" | tail -n 1)

    if [[ "$acme_line" == *'"lane":"fast"'* ]]; then
        pass "access_log/fields/renders_per_request"
    else
        fail "access_log/fields/renders_per_request" \
            "expected tenant=acme lane=fast; got: $acme_line"
    fi

    if [[ -n "$globex_line" ]]; then
        pass "access_log/fields/varies_per_request"
    else
        fail "access_log/fields/varies_per_request" \
            "no globex line in:\n$(cat "$logfile")"
    fi

    # Fallback arm: no X-Lane header on the second request.
    if [[ "$globex_line" == *'"lane":"none"'* ]]; then
        pass "access_log/fields/fallback_applies"
    else
        fail "access_log/fields/fallback_applies" \
            "expected lane=none; got: $globex_line"
    fi

    # The pre-routing path has no location and therefore no templates,
    # but the keys must still be present so the schema is stable.
    if [[ "$health_line" == *'"tenant":""'* \
            && "$health_line" == *'"lane":""'* ]]; then
        pass "access_log/fields/unrouted_keeps_schema"
    else
        fail "access_log/fields/unrouted_keeps_schema" \
            "expected empty tenant/lane; got: $health_line"
    fi
}

suite_access_log_fields_common() {
    echo "=== access-log fields append stable columns to common ==="

    local logfile="$TMPDIR/access_fields_common.log"
    : > "$logfile"

    cat >"$TMPDIR/access_fields_common.kdl" <<EOF
server {
    access-log "common" path="$logfile" {
        field "vhost" "{host}"
        field "lane" "{header:x-lane}"
    }
}
listener "tcp://127.0.0.1:8294"
vhost localhost {
    location "/" {
        static root="/tmp/www" {
index-file index.html;
}
    }
}
EOF
    start_server "$TMPDIR/access_fields_common.kdl" 8294 \
        || { fail "access_log/fields_common/start" "hypershunt failed"; \
             return; }

    curl -s -o /dev/null --max-time 5 -H "Host: localhost" \
        -H "X-Lane: slow" "http://127.0.0.1:8294/" || true
    curl -s -o /dev/null --max-time 5 -H "Host: localhost" \
        "http://127.0.0.1:8294/healthz" || true

    stop_server

    local routed unrouted
    routed=$(grep '"GET / HTTP/1.1"' "$logfile" | tail -n 1)
    unrouted=$(grep '"GET /healthz HTTP/1.1"' "$logfile" | tail -n 1)

    if [[ "$routed" == *' "localhost" "slow"' ]]; then
        pass "access_log/fields_common/appends_values"
    else
        fail "access_log/fields_common/appends_values" \
            "expected trailing \"localhost\" \"slow\"; got: $routed"
    fi

    # Same column count on a line that never reached a location.
    if [[ "$unrouted" == *' "-" "-"' ]]; then
        pass "access_log/fields_common/pads_unrouted"
    else
        fail "access_log/fields_common/pads_unrouted" \
            "expected trailing \"-\" \"-\"; got: $unrouted"
    fi
}
