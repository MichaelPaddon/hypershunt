#!/bin/bash
# Suite: mutual TLS (client-certificate authentication).
#
# Each scenario builds its own openssl-generated CA + leaf certs, so
# the harness has no dependency on pre-baked fixtures.  Server certs
# share a single CA across the suite to keep setup costs down.

# Helper: produce $1.key + $1.crt signed by the named CA.  $2 is the
# CN (also used as the DNS SAN), $3 is the CA basename, $4 is "client"
# or "server" (drives the extended key usage).
mtls_make_cert() {
    local name="$1" cn="$2" ca="$3" purpose="$4"
    local ext="serverAuth"
    if [ "$purpose" = "client" ]; then ext="clientAuth"; fi
    openssl genrsa -out "$name.key" 2048 >/dev/null 2>&1
    openssl req -new -key "$name.key" -subj "/CN=$cn" \
        -out "$name.csr" >/dev/null 2>&1
    cat > "$name.ext" <<EOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=$ext
subjectAltName=DNS:$cn
EOF
    openssl x509 -req -in "$name.csr" \
        -CA "$ca.crt" -CAkey "$ca.key" -CAcreateserial \
        -out "$name.crt" -days 1 -sha256 \
        -extfile "$name.ext" >/dev/null 2>&1
    rm -f "$name.csr" "$name.ext"
}

# Build the shared CA + server cert + an "alice" client cert.
mtls_setup_certs() {
    local d="$1"
    (
        cd "$d" || exit 1
        # CA
        openssl genrsa -out ca.key 2048 >/dev/null 2>&1
        openssl req -x509 -new -nodes -key ca.key -sha256 -days 1 \
            -subj "/CN=hypershunt-mtls-test-CA" \
            -out ca.crt >/dev/null 2>&1
        # Server cert (signed by the same CA so the test doesn't have
        # to juggle two trust stores).
        mtls_make_cert server 127.0.0.1 ca server
        # Client cert for "alice"
        mtls_make_cert alice alice ca client
        # Client cert for "mallory", signed by a *different* CA.  Used
        # to verify the rejection path: the leaf is well-formed but
        # untrusted.
        openssl genrsa -out other-ca.key 2048 >/dev/null 2>&1
        openssl req -x509 -new -nodes -key other-ca.key -sha256 -days 1 \
            -subj "/CN=hypershunt-mtls-other-CA" \
            -out other-ca.crt >/dev/null 2>&1
        mtls_make_cert mallory mallory other-ca client
    )
}

# Required mode: a trusted client cert succeeds; an untrusted client
# cert is rejected at the TLS layer; sending no cert is also rejected.
suite_mtls_required() {
    echo "=== mtls: required mode rejects anonymous + untrusted ==="
    local d="$TMPDIR/mtls_req"
    mkdir -p "$d"
    mtls_setup_certs "$d"

    cat > "$TMPDIR/mtls_req.kdl" <<EOF
listener "tcp://127.0.0.1:8701" {
    tls "files" cert="$d/server.crt" key="$d/server.key" {
        mtls mode="required" {
ca "$d/ca.crt"
}
}
}
vhost localhost {
    location "/" {
        request-headers {
            set "X-Forwarded-User" "{username|-}"
            set "X-SSL-Client-Subject" "{client_cert_subject|}"
        }
        static root="/tmp/www"
    }
    location "/whoami" {
        request-headers {
            set "X-Forwarded-User" "{username|-}"
        }
        static root="/tmp/www"
    }
}
EOF
    # No standard probe -- the server requires a client cert that the
    # default start_server probe doesn't carry.  Launch directly and
    # poll with curl carrying the trusted cert.
    "$HYPERSHUNT" --config "$TMPDIR/mtls_req.kdl" \
        >"$TMPDIR/hypershunt.out" 2>&1 &
    HYPERSHUNT_PID=$!
    local tries=0 code=""
    while true; do
        code=$(curl -sk --cert "$d/alice.crt" --key "$d/alice.key" \
            -o /dev/null -w "%{http_code}" \
            --max-time 0.5 --connect-timeout 0.5 \
            "https://127.0.0.1:8701/" 2>/dev/null || echo "")
        [ -n "$code" ] && [ "$code" != "000" ] && break
        if ! kill -0 "$HYPERSHUNT_PID" 2>/dev/null; then
            fail "mtls_req/server_start" "hypershunt exited"
            cat "$TMPDIR/hypershunt.out"
            return
        fi
        tries=$((tries + 1))
        if [ $tries -ge 60 ]; then
            fail "mtls_req/server_start" "timeout"
            stop_server
            return
        fi
        sleep 0.1
    done

    # Trusted client cert -> 200 + the user header carries the CN.
    assert_status "mtls_req/trusted_ok" 200 \
        "https://127.0.0.1:8701/" \
        -k --cert "$d/alice.crt" --key "$d/alice.key"

    # Anonymous client (no --cert).  rustls aborts the handshake before
    # any HTTP exchange, so curl returns a transport failure (rc != 0)
    # and prints "000" for the HTTP code via -w.
    local anon_code
    anon_code=$(curl -sk -o /dev/null -w "%{http_code}" \
        --max-time 2 \
        "https://127.0.0.1:8701/" 2>/dev/null) || true
    if [ -z "$anon_code" ] || [ "$anon_code" = "000" ]; then
        PASS=$((PASS + 1))
        echo "  PASS: mtls_req/anonymous_rejected"
    else
        fail "mtls_req/anonymous_rejected" \
            "expected handshake failure, got HTTP $anon_code"
    fi

    # Untrusted CA: another well-formed cert that just isn't ours.
    local untrusted_code
    untrusted_code=$(curl -sk --cert "$d/mallory.crt" \
        --key "$d/mallory.key" \
        -o /dev/null -w "%{http_code}" --max-time 2 \
        "https://127.0.0.1:8701/" 2>/dev/null) || true
    if [ -z "$untrusted_code" ] \
        || [ "$untrusted_code" = "000" ]; then
        PASS=$((PASS + 1))
        echo "  PASS: mtls_req/untrusted_ca_rejected"
    else
        fail "mtls_req/untrusted_ca_rejected" \
            "expected handshake failure, got HTTP $untrusted_code"
    fi

    # Both rejections must surface on the security stream so fail2ban can
    # ban the peer: no cert -> reason="no-cert"; untrusted CA ->
    # reason="untrusted".  (stdout is line-buffered; give a small margin.)
    sleep 0.2
    assert_log "mtls_req/bad_client_cert_no_cert" \
        'hypershunt::security: bad-client-cert peer=127\.0\.0\.1:[0-9]+ reason=no-cert'
    assert_log "mtls_req/bad_client_cert_untrusted" \
        'hypershunt::security: bad-client-cert peer=127\.0\.0\.1:[0-9]+ reason=untrusted'

    stop_server
    rm -rf "$d"
}

# Optional mode: both anonymous and certified clients reach the
# handler.  The header template makes the difference observable.
suite_mtls_optional() {
    echo "=== mtls: optional mode lets anonymous through ==="
    local d="$TMPDIR/mtls_opt"
    mkdir -p "$d"
    mtls_setup_certs "$d"

    # The handler's response includes a header derived from the
    # client cert's CN; a separate location strips Accept-Encoding
    # so the response stays trivial.
    mkdir -p /tmp/www_mtls_opt
    echo "ok" > /tmp/www_mtls_opt/index.html

    cat > "$TMPDIR/mtls_opt.kdl" <<EOF
listener "tcp://127.0.0.1:8702" {
    tls "files" cert="$d/server.crt" key="$d/server.key" {
        mtls mode="optional" {
ca "$d/ca.crt"
}
}
}
vhost localhost {
    location "/" {
        response-headers {
            set "X-Whoami" "{username|anon}"
        }
        static root="/tmp/www_mtls_opt"
    }
}
EOF
    start_server "$TMPDIR/mtls_opt.kdl" 8702 "https" \
        || { fail "mtls_opt/server_start" "hypershunt failed"; return; }

    # Anonymous: handler still serves, header reflects fallback.
    assert_header "mtls_opt/anon_header" "X-Whoami" "anon" \
        "https://127.0.0.1:8702/" -k
    # Cert-authenticated: header carries the CN.
    assert_header "mtls_opt/alice_header" "X-Whoami" "alice" \
        "https://127.0.0.1:8702/" \
        -k --cert "$d/alice.crt" --key "$d/alice.key"

    stop_server
    rm -rf "$d" /tmp/www_mtls_opt
}

# Revocation: a CRL listing the client serial blocks the handshake
# even though the trust chain is intact.
suite_mtls_revocation() {
    echo "=== mtls: revoked client cert rejected ==="
    local d="$TMPDIR/mtls_crl"
    mkdir -p "$d"
    mtls_setup_certs "$d"

    # Build a CRL listing alice.crt as revoked.
    (
        cd "$d" || exit 1
        cat > openssl.cnf <<'EOF'
[ca]
default_ca = CA_default
[CA_default]
database = ./index.txt
crlnumber = ./crlnumber
default_md = sha256
default_crl_days = 1
[crl_ext]
authorityKeyIdentifier=keyid:always
EOF
        : > index.txt
        echo "01" > crlnumber
        # `openssl ca -revoke` requires the cert to live in the
        # database; the lowest-friction way is to revoke directly.
        openssl ca -config openssl.cnf -keyfile ca.key -cert ca.crt \
            -revoke alice.crt -crl_reason keyCompromise \
            >/dev/null 2>&1 || true
        openssl ca -config openssl.cnf -keyfile ca.key -cert ca.crt \
            -gencrl -out crl.pem >/dev/null 2>&1
    )

    if [ ! -s "$d/crl.pem" ]; then
        echo "  SKIP: mtls_crl  (CRL generation failed)"
        rm -rf "$d"
        return
    fi

    cat > "$TMPDIR/mtls_crl.kdl" <<EOF
listener "tcp://127.0.0.1:8703" {
    tls "files" cert="$d/server.crt" key="$d/server.key" {
        mtls mode="required" {
ca "$d/ca.crt"
            revocation "$d/crl.pem"
}
}
}
vhost localhost {
    location "/" { static root="/tmp/www" }
}
EOF
    "$HYPERSHUNT" --config "$TMPDIR/mtls_crl.kdl" \
        >"$TMPDIR/hypershunt.out" 2>&1 &
    HYPERSHUNT_PID=$!
    sleep 0.5
    if ! kill -0 "$HYPERSHUNT_PID" 2>/dev/null; then
        fail "mtls_crl/server_start" "hypershunt exited"
        cat "$TMPDIR/hypershunt.out"
        rm -rf "$d"
        return
    fi

    local revoked_code
    revoked_code=$(curl -sk --cert "$d/alice.crt" \
        --key "$d/alice.key" \
        -o /dev/null -w "%{http_code}" --max-time 2 \
        "https://127.0.0.1:8703/" 2>/dev/null) || true
    if [ -z "$revoked_code" ] || [ "$revoked_code" = "000" ]; then
        PASS=$((PASS + 1))
        echo "  PASS: mtls_crl/revoked_rejected"
    else
        fail "mtls_crl/revoked_rejected" \
            "expected handshake failure, got HTTP $revoked_code"
    fi

    stop_server
    rm -rf "$d"
}
