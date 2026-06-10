#!/bin/bash
# Suite: SIGUSR2 seamless binary upgrade (#14).  The parent forks +
# execs hypershunt into itself; child takes over the inherited socket
# while the parent drains.  Tests are self-contained: each manages
# its own PIDs because SIGUSR2 changes which process owns the
# listening fd, so the shared start_server/stop_server harness
# (built around a single $HYPERSHUNT_PID) doesn't apply.

# Wait until the parent at $1 has exited.  Returns 0 if it exits
# within $2 seconds; 1 otherwise.  Used after the upgrade triggers
# a drain so we can verify the child has fully taken over.
wait_for_pid_exit() {
    local pid="$1" deadline_secs="$2"
    local waited=0
    while kill -0 "$pid" 2>/dev/null; do
        sleep 0.1
        waited=$((waited + 1))
        if [ $waited -ge $((deadline_secs * 10)) ]; then
            return 1
        fi
    done
    return 0
}

# Find an hypershunt pid (other than $1) that is currently listening on
# TCP port $2.  We can't use ss/lsof (not in the test image), so we
# scan /proc/<pid>/cmdline for "hypershunt" and assume there's at most
# one parent + one child during a SIGUSR2 hand-off.
child_pid_on_port() {
    local parent="$1"
    local pid
    for pid in /proc/[0-9]*; do
        pid=${pid##*/}
        [ "$pid" = "$parent" ] && continue
        if tr '\0' ' ' <"/proc/$pid/cmdline" 2>/dev/null \
            | grep -q '^/usr/bin/hypershunt '; then
            echo "$pid"
            return
        fi
    done
}

# Start hypershunt in the background and wait until it's accepting on
# $port.  Echoes the PID on stdout; returns non-zero on timeout.
start_upgrade_target() {
    local config="$1" port="$2"
    "$HYPERSHUNT" --config "$config" >"$TMPDIR/upgrade.out" 2>&1 &
    local pid=$!
    local tries=0
    while true; do
        if curl -s -o /dev/null --max-time 0.5 --connect-timeout 0.5 \
            "http://127.0.0.1:${port}/" >/dev/null 2>&1; then
            echo "$pid"
            return 0
        fi
        if ! kill -0 "$pid" 2>/dev/null; then
            return 1
        fi
        tries=$((tries + 1))
        if [ $tries -ge 60 ]; then
            kill -KILL "$pid" 2>/dev/null
            return 1
        fi
        sleep 0.1
    done
}

# Best-effort cleanup: kill every hypershunt process currently running.
# Used at end-of-suite so a stuck parent doesn't bleed into the next
# test.
cleanup_hypershunts() {
    local pid
    for pid in /proc/[0-9]*; do
        pid=${pid##*/}
        if tr '\0' ' ' <"/proc/$pid/cmdline" 2>/dev/null \
            | grep -q '^/usr/bin/hypershunt '; then
            kill -KILL "$pid" 2>/dev/null || true
        fi
    done
}

# --- suites ----------------------------------------------------------

# Zero-downtime: a steady stream of requests through SIGUSR2 sees
# no failures.  The child takes over accepts while the parent
# drains, so every curl gets a 200.
suite_upgrade_zero_downtime() {
    echo "=== SIGUSR2: zero-downtime under steady traffic ==="
    mkdir -p /tmp/up-a
    printf "ok\n" >/tmp/up-a/index.html

    cat >"$TMPDIR/upgrade.kdl" <<'EOF'
server { health enabled="true"; upgrade-startup-timeout 5
}
listener "tcp://127.0.0.1:18401"
vhost "_default_" {
    location "/" { static root="/tmp/up-a" {
index-file index.html
} }
}
EOF
    local parent
    parent=$(start_upgrade_target "$TMPDIR/upgrade.kdl" 18401) \
        || { fail "upgrade/zero-downtime/start"; return; }

    # Steady traffic: 30 hits over ~3 s, straddling the upgrade.
    local fails=0
    (
        for _ in $(seq 1 30); do
            curl -s -o /dev/null -w "%{http_code}\n" --max-time 1 \
                http://127.0.0.1:18401/healthz \
                || echo "000"
            sleep 0.1
        done
    ) > "$TMPDIR/upgrade.codes" &
    local loop=$!
    sleep 1
    kill -USR2 "$parent"
    wait "$loop"

    # grep -c with no matches returns 1, so capture without || which
    # would emit a second "0" via `echo`.  set +e to ignore the exit.
    set +e
    fails=$(grep -vc '^200$' "$TMPDIR/upgrade.codes")
    set -e
    if [ "$fails" -eq 0 ]; then
        pass "upgrade/zero-downtime/no_request_failures"
    else
        fail "upgrade/zero-downtime/no_request_failures" \
            "$fails / 30 requests failed across the upgrade"
    fi

    # Parent must exit within a few seconds (idle drain).
    if wait_for_pid_exit "$parent" 10; then
        pass "upgrade/zero-downtime/parent_exited"
    else
        fail "upgrade/zero-downtime/parent_exited" \
            "parent pid=$parent still alive after 10s"
        kill -KILL "$parent" 2>/dev/null || true
    fi

    # A child hypershunt must be alive (separate PID from the parent).
    local child
    child=$(child_pid_on_port "$parent" 18401)
    if [ -n "$child" ]; then
        pass "upgrade/zero-downtime/child_alive"
    else
        fail "upgrade/zero-downtime/child_alive" \
            "no surviving hypershunt child (parent was $parent)"
    fi

    cleanup_hypershunts
    rm -rf /tmp/up-a "$TMPDIR/upgrade.codes" "$TMPDIR/upgrade.out"
}

# Slow download started before SIGUSR2 must finish from the parent
# (which keeps serving in-flight connections during drain).  The
# child accepts the next fresh request immediately.
suite_upgrade_slow_download_survives() {
    echo "=== SIGUSR2: slow download survives the hand-off ==="
    mkdir -p /tmp/up-b
    # 256 KB of recognisable content; --limit-rate 50K = ~5 s download.
    dd if=/dev/zero bs=1024 count=256 2>/dev/null \
        | tr '\0' 'B' >/tmp/up-b/big.bin

    cat >"$TMPDIR/upgrade.kdl" <<'EOF'
server upgrade-startup-timeout=5 graceful-drain-timeout=30
listener "tcp://127.0.0.1:18402"
vhost "_default_" {
    location "/" { static root="/tmp/up-b" }
}
EOF
    # Need a non-empty index to satisfy the start probe; serve big.bin
    # so / returns 200.
    ln -sf big.bin /tmp/up-b/index.html

    local parent
    parent=$(start_upgrade_target "$TMPDIR/upgrade.kdl" 18402) \
        || { fail "upgrade/slow-dl/start"; return; }

    local out="$TMPDIR/up-out.bin"
    curl -s --limit-rate 50K -o "$out" \
        http://127.0.0.1:18402/big.bin &
    local curl_pid=$!
    sleep 1
    kill -USR2 "$parent"

    # While the slow download is still mid-stream, a fresh request on
    # the same port must hit the *child* immediately (child took over
    # accepts).
    local fresh
    fresh=$(curl -s --max-time 2 \
        -o /dev/null -w "%{http_code}" \
        http://127.0.0.1:18402/big.bin 2>/dev/null || echo "000")
    if [ "$fresh" = "200" ]; then
        pass "upgrade/slow-dl/child_accepting_mid_drain"
    else
        fail "upgrade/slow-dl/child_accepting_mid_drain" "got $fresh"
    fi

    # Wait for the long download.
    wait "$curl_pid"
    if [ -f "$out" ] \
        && [ "$(wc -c <"$out")" = "262144" ] \
        && cmp -s "$out" /tmp/up-b/big.bin; then
        pass "upgrade/slow-dl/download_completes"
    else
        fail "upgrade/slow-dl/download_completes" \
            "bytes=$(wc -c <"$out" 2>/dev/null || echo 0)"
    fi

    # Parent should exit once the download has drained.
    if wait_for_pid_exit "$parent" 10; then
        pass "upgrade/slow-dl/parent_exits_after_drain"
    else
        fail "upgrade/slow-dl/parent_exits_after_drain" \
            "parent still alive"
        kill -KILL "$parent" 2>/dev/null || true
    fi

    cleanup_hypershunts
    rm -rf /tmp/up-b "$out" "$TMPDIR/upgrade.out"
}

# graceful-drain-timeout fires: if the parent has a still-alive
# connection when the timeout elapses, it force-closes and exits.
# We simulate "stuck connection" with a slow rate that exceeds the
# timeout; the connection should be terminated and the parent should
# exit by the deadline.
# SIGUSR2 across a config that removes one of the parent's
# listeners: the child must not just skip claiming the inherited
# fd, it must close it, so new clients get a fast ECONNREFUSED
# instead of hanging until their own timeout.
suite_upgrade_listener_delete_closes_fd() {
    echo "=== SIGUSR2: listener delete closes the inherited fd ==="
    mkdir -p /tmp/up-d
    printf "alive\n" >/tmp/up-d/index.html
    ln -sf index.html /tmp/up-d/i

    cat >"$TMPDIR/upgrade.kdl" <<'EOF'
listener "tcp://127.0.0.1:18411"
listener "tcp://127.0.0.1:18412"
vhost "_default_" {
    location "/" { static root="/tmp/up-d" {
index-file index.html
} }
}
EOF
    local parent
    parent=$(start_upgrade_target "$TMPDIR/upgrade.kdl" 18411) \
        || { fail "upgrade/listener_delete/start"; return; }

    # New config drops :18412.
    cat >"$TMPDIR/upgrade.kdl" <<'EOF'
listener "tcp://127.0.0.1:18411"
vhost "_default_" {
    location "/" { static root="/tmp/up-d" {
index-file index.html
} }
}
EOF
    kill -USR2 "$parent"

    # Parent should drain quickly (no in-flight connections).
    if wait_for_pid_exit "$parent" 5; then
        pass "upgrade/listener_delete/parent_exited"
    else
        fail "upgrade/listener_delete/parent_exited" \
            "parent still alive"
        kill -KILL "$parent" 2>/dev/null || true
    fi

    # The remaining listener serves.
    assert_body "upgrade/listener_delete/remaining_serves" "alive" \
        "http://127.0.0.1:18411/"

    # The dropped port must fast-fail (ECONNREFUSED, not hang) --
    # 1s --max-time is plenty if the fd was closed, far too short
    # if the leaked fd were still in LISTEN state.
    local code start_ms end_ms elapsed_ms
    start_ms=$(date +%s%3N)
    code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 1 \
        "http://127.0.0.1:18412/" 2>/dev/null) || code="000"
    end_ms=$(date +%s%3N)
    elapsed_ms=$(( end_ms - start_ms ))
    if [ "$code" = "000" ] && [ "$elapsed_ms" -lt 500 ]; then
        pass "upgrade/listener_delete/dropped_port_fast_refused"
    else
        fail "upgrade/listener_delete/dropped_port_fast_refused" \
            "code=$code elapsed_ms=$elapsed_ms (expected 000 in <500ms)"
    fi

    cleanup_hypershunts
    rm -rf /tmp/up-d
}

# SIGUSR2 across a config that adds a new (unprivileged) listener.
# The child's startup runs the full bind path, so add-via-upgrade
# uses identical machinery to startup.
suite_upgrade_listener_add() {
    echo "=== SIGUSR2: adding a listener via upgrade ==="
    mkdir -p /tmp/up-e
    printf "alive\n" >/tmp/up-e/index.html

    cat >"$TMPDIR/upgrade.kdl" <<'EOF'
listener "tcp://127.0.0.1:18421"
vhost "_default_" {
    location "/" { static root="/tmp/up-e" {
index-file index.html
} }
}
EOF
    local parent
    parent=$(start_upgrade_target "$TMPDIR/upgrade.kdl" 18421) \
        || { fail "upgrade/listener_add/start"; return; }

    cat >"$TMPDIR/upgrade.kdl" <<'EOF'
listener "tcp://127.0.0.1:18421"
listener "tcp://127.0.0.1:18422"
vhost "_default_" {
    location "/" { static root="/tmp/up-e" {
index-file index.html
} }
}
EOF
    kill -USR2 "$parent"
    if wait_for_pid_exit "$parent" 5; then
        pass "upgrade/listener_add/parent_exited"
    else
        fail "upgrade/listener_add/parent_exited"
        kill -KILL "$parent" 2>/dev/null || true
    fi

    assert_body "upgrade/listener_add/original_serves" "alive" \
        "http://127.0.0.1:18421/"
    assert_body "upgrade/listener_add/new_listener_serves" "alive" \
        "http://127.0.0.1:18422/"

    cleanup_hypershunts
    rm -rf /tmp/up-e
}

# SIGUSR2 across a config that uses per-listener vhost scoping.  The
# child re-parses the config and rebuilds its routing tables, so the
# scoping (an explicit vhost list + reject-unknown-host) must hold in
# the new process exactly as it did before the hand-off.
suite_upgrade_vhost_scoping() {
    echo "=== SIGUSR2: per-listener vhost scoping survives upgrade ==="
    cat >"$TMPDIR/upgrade.kdl" <<'EOF'
listener "tcp://127.0.0.1:18431" reject-unknown-host=#true {
    vhost "a.local"
}
vhost "a.local" { location "/" { redirect to="/a" code=301 } }
vhost "b.local" { location "/" { redirect to="/b" code=301 } }
EOF
    local parent
    parent=$(start_upgrade_target "$TMPDIR/upgrade.kdl" 18431) \
        || { fail "upgrade/scoping/start"; return; }

    # Before the upgrade: a.local served, b.local excluded -> 404.
    assert_header "upgrade/scoping/before_a" "Location" "/a" \
        "http://127.0.0.1:18431/" -H "Host: a.local" --no-location
    assert_status "upgrade/scoping/before_b" 404 \
        "http://127.0.0.1:18431/" -H "Host: b.local"

    # Re-exec with the same config; the child rebuilds its tables.
    kill -USR2 "$parent"
    if wait_for_pid_exit "$parent" 5; then
        pass "upgrade/scoping/parent_exited"
    else
        fail "upgrade/scoping/parent_exited"
        kill -KILL "$parent" 2>/dev/null || true
    fi

    # Scoping must hold in the new process.
    assert_header "upgrade/scoping/after_a" "Location" "/a" \
        "http://127.0.0.1:18431/" -H "Host: a.local" --no-location
    assert_status "upgrade/scoping/after_b" 404 \
        "http://127.0.0.1:18431/" -H "Host: b.local"

    cleanup_hypershunts
}

suite_upgrade_drain_timeout_fires() {
    echo "=== SIGUSR2: graceful-drain-timeout force-closes stuck conns ==="
    mkdir -p /tmp/up-c
    # File must be larger than the kernel's TCP send buffer (default
    # autotunes up to ~4 MB on Linux) so the server-side write blocks
    # on curl's slow reads rather than completing fast against the
    # buffer.  16 MB is comfortably above any default.
    local size_mb=16
    dd if=/dev/zero bs=1M count="$size_mb" 2>/dev/null \
        | tr '\0' 'C' >/tmp/up-c/big.bin
    local total=$((size_mb * 1024 * 1024))

    cat >"$TMPDIR/upgrade.kdl" <<'EOF'
server upgrade-startup-timeout=5 graceful-drain-timeout=2
listener "tcp://127.0.0.1:18403"
vhost "_default_" {
    location "/" { static root="/tmp/up-c" }
}
EOF
    ln -sf big.bin /tmp/up-c/index.html

    local parent
    parent=$(start_upgrade_target "$TMPDIR/upgrade.kdl" 18403) \
        || { fail "upgrade/drain-timeout/start"; return; }

    local out="$TMPDIR/up-stuck.bin"
    # 200 KB/s * (2 s drain + 1 s pre-signal + ~kernel buffer) is
    # well under 16 MB, so the curl can't finish before force-close.
    curl -s --limit-rate 200K -o "$out" \
        http://127.0.0.1:18403/big.bin >/dev/null 2>&1 &
    local curl_pid=$!
    sleep 1
    local started=$(date +%s)
    kill -USR2 "$parent"

    # Parent must exit no more than ~3 s after SIGUSR2 (2 s drain
    # timeout plus a tiny grace for the child to hand back).
    if wait_for_pid_exit "$parent" 6; then
        local elapsed=$(( $(date +%s) - started ))
        if [ "$elapsed" -le 5 ]; then
            pass "upgrade/drain-timeout/parent_exits_within_timeout"
        else
            fail "upgrade/drain-timeout/parent_exits_within_timeout" \
                "elapsed=${elapsed}s, expected <=5"
        fi
    else
        fail "upgrade/drain-timeout/parent_exits_within_timeout" \
            "parent did not exit within 6s"
        kill -KILL "$parent" 2>/dev/null || true
    fi

    # The slow download was force-closed, so the curl will have
    # received fewer bytes than the full file.
    wait "$curl_pid" 2>/dev/null || true
    local got
    got=$(wc -c <"$out" 2>/dev/null || echo 0)
    if [ "$got" -lt "$total" ]; then
        pass "upgrade/drain-timeout/stuck_conn_force_closed"
    else
        fail "upgrade/drain-timeout/stuck_conn_force_closed" \
            "download completed despite drain timeout (got=$got bytes)"
    fi

    cleanup_hypershunts
    rm -rf /tmp/up-c "$out" "$TMPDIR/upgrade.out"
}
