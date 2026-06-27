#!/bin/bash
# Integration smoke tests for hypershunt.
# Runs inside the container built from tests/integration/Containerfile.
# Exercises all major handler types and the security access-control path.

set -euo pipefail

HYPERSHUNT=/usr/bin/hypershunt
PASS=0
FAIL=0
HYPERSHUNT_PID=""
SLAPD_PID=""
BACKEND_PIDS=()
TMPDIR=$(mktemp -d)

# Load shared helpers (assert_*, start_server, stop_server, cleanup,
# setup_webroot, setup_ldap, teardown_ldap).
TESTS_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib.sh
source "$TESTS_DIR/lib.sh"

trap cleanup EXIT

# Source all suite files.
# shellcheck source=suite_static.sh
source "$TESTS_DIR/suite_static.sh"
# shellcheck source=suite_access.sh
source "$TESTS_DIR/suite_access.sh"
# shellcheck source=suite_auth.sh
source "$TESTS_DIR/suite_auth.sh"
# shellcheck source=suite_status.sh
source "$TESTS_DIR/suite_status.sh"
# shellcheck source=suite_proxy.sh
source "$TESTS_DIR/suite_proxy.sh"
# shellcheck source=suite_cgi.sh
source "$TESTS_DIR/suite_cgi.sh"
# shellcheck source=suite_gateways.sh
source "$TESTS_DIR/suite_gateways.sh"
# shellcheck source=suite_tls.sh
source "$TESTS_DIR/suite_tls.sh"
# shellcheck source=suite_stream.sh
source "$TESTS_DIR/suite_stream.sh"
# shellcheck source=suite_udp.sh
source "$TESTS_DIR/suite_udp.sh"
# shellcheck source=suite_websocket.sh
source "$TESTS_DIR/suite_websocket.sh"
# shellcheck source=suite_routing.sh
source "$TESTS_DIR/suite_routing.sh"
# shellcheck source=suite_health.sh
source "$TESTS_DIR/suite_health.sh"
# shellcheck source=suite_respond.sh
source "$TESTS_DIR/suite_respond.sh"
# shellcheck source=suite_headers.sh
source "$TESTS_DIR/suite_headers.sh"
# shellcheck source=suite_jwt.sh
source "$TESTS_DIR/suite_jwt.sh"
# shellcheck source=suite_subrequest_auth.sh
source "$TESTS_DIR/suite_subrequest_auth.sh"
# shellcheck source=suite_auth_request.sh
source "$TESTS_DIR/suite_auth_request.sh"
# shellcheck source=suite_http3.sh
source "$TESTS_DIR/suite_http3.sh"
# shellcheck source=suite_proxy_h3.sh
source "$TESTS_DIR/suite_proxy_h3.sh"
# shellcheck source=suite_proxy_trust.sh
source "$TESTS_DIR/suite_proxy_trust.sh"
# shellcheck source=suite_proxy_lb.sh
source "$TESTS_DIR/suite_proxy_lb.sh"
# shellcheck source=suite_rate_limit.sh
source "$TESTS_DIR/suite_rate_limit.sh"
# shellcheck source=suite_cache.sh
source "$TESTS_DIR/suite_cache.sh"
# shellcheck source=suite_security.sh
source "$TESTS_DIR/suite_security.sh"
# shellcheck source=suite_matchers.sh
source "$TESTS_DIR/suite_matchers.sh"
# shellcheck source=suite_rewrite.sh
source "$TESTS_DIR/suite_rewrite.sh"
# shellcheck source=suite_try_files.sh
source "$TESTS_DIR/suite_try_files.sh"
# shellcheck source=suite_mtls.sh
source "$TESTS_DIR/suite_mtls.sh"
# shellcheck source=suite_static_extras.sh
source "$TESTS_DIR/suite_static_extras.sh"
# shellcheck source=suite_proxy_protocol.sh
source "$TESTS_DIR/suite_proxy_protocol.sh"
# shellcheck source=suite_auth_file.sh
source "$TESTS_DIR/suite_auth_file.sh"
# shellcheck source=suite_access_log.sh
source "$TESTS_DIR/suite_access_log.sh"
# shellcheck source=suite_reload.sh
source "$TESTS_DIR/suite_reload.sh"
# shellcheck source=suite_upgrade.sh
source "$TESTS_DIR/suite_upgrade.sh"

# --- main -----------------------------------------------------------

setup_webroot

suite_static_files
suite_redirect
suite_ip_access
suite_auth
suite_status_page
suite_status_metrics
suite_compression
suite_reverse_proxy
suite_reverse_proxy_unix
suite_cgi
suite_tls
suite_stream_proxy
suite_stream_proxy_unix
suite_udp_proxy_inet
suite_udp_proxy_unix
suite_websocket_h1_h1
suite_websocket_h1_h2c
suite_ldap_auth
suite_health_endpoint
suite_health_config
suite_health_lame_duck
suite_respond
suite_multi_vhost
suite_vhost_aliases
suite_regex_vhost
suite_response_headers
suite_request_headers
suite_custom_error_pages
suite_access_redirect
suite_scgi
suite_fastcgi
suite_static_mime_types
suite_redirect_variables
suite_proxy_x_forwarded_for
suite_proxy_strip_prefix
suite_jwt
suite_subrequest_auth
suite_auth_request
suite_http3_basic
suite_http3_alt_svc
suite_http3_middleware
suite_proxy_h3_forced
suite_proxy_h3_autoupgrade
suite_proxy_h3_altsvc_expires
suite_proxy_skip_verify
suite_proxy_connect_timeout
suite_proxy_lb_round_robin
suite_proxy_lb_header_hash
suite_proxy_lb_retry
suite_proxy_lb_active_health
suite_rate_limit_burst_then_429
suite_rate_limit_stacked
suite_rate_limit_per_location_body
suite_rate_limit_per_ip_isolated
suite_rate_limit_user_key
suite_rate_limit_header_key
suite_cache_proxy
suite_match_method_dispatch
suite_match_header_regex
suite_match_query
suite_match_and_semantics
suite_match_path_regex
suite_match_header_absent
suite_match_negation
suite_rewrite_capture_group
suite_rewrite_no_match_is_noop
suite_rewrite_chains_through_three_locations
suite_rewrite_cycle_bails
suite_try_files_spa_fallback
suite_try_files_all_miss_404
suite_try_files_gated_by_accept
suite_try_files_symlink_escape
suite_rewrite_into_try_files
suite_try_files_html_suffix
suite_security_signals
suite_mtls_required
suite_mtls_optional
suite_mtls_revocation
suite_directory_listing
suite_userdir
suite_proxy_protocol_v1_loopback_trusted
suite_proxy_protocol_required_when_configured
suite_proxy_protocol_allowlist_rejects
suite_auth_file_basic
suite_auth_file_reload_on_mtime
suite_access_log_common
suite_access_log_combined
suite_access_log_json
suite_reload_routing_hot_swap
suite_reload_vhost_scoping
suite_reload_mid_flight_download
suite_reload_listener_add_and_delete
suite_reload_tls_listener_add
suite_reload_named_cert_define
suite_reload_stream_listener_add
suite_reload_rejects_auth_change
suite_reload_rejects_parse_error
suite_check_config_flag
suite_upgrade_zero_downtime
suite_upgrade_slow_download_survives
suite_upgrade_listener_delete_closes_fd
suite_upgrade_listener_add
suite_upgrade_vhost_scoping
suite_upgrade_drain_timeout_fires

echo ""
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
