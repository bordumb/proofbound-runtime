#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

python3 tools/ci/version.py --check
python3 tools/ci/changelog.py --staged
python3 tools/ci/documentation.py
python3 -m unittest tools.ci.test_documentation
python3 tools/release/observation_inputs.py --check
python3 -m unittest tools.ci.test_install_release
python3 -m unittest tools.ci.test_build_example
python3 -m unittest tools.ci.test_required_workflow
python3 -m unittest tools.ci.test_native_context
python3 -m unittest tools.ci.test_release_workflow
python3 -m unittest tools.ci.test_acceptance_action
python3 -m unittest tools.ci.test_acceptance_policy_compiler
python3 -m unittest tools.ci.test_plan_scaffold_contract
python3 -m unittest tools.ci.test_diagnostic_drafting_contract
python3 -m unittest tools.ci.test_diagnostic_artifact_producer
python3 -m unittest tools.ci.test_diagnostic_observer_protocol
python3 -m unittest tools.ci.test_diagnostic_trace_startup
python3 -m unittest tools.ci.test_diagnostic_trace_events
python3 -m unittest tools.ci.test_diagnostic_syscall_decoder
python3 -m unittest tools.ci.test_diagnostic_event_mapping
python3 -m unittest tools.ci.test_diagnostic_stream_capture
python3 -m unittest tools.ci.test_diagnostic_lifecycle
python3 -m unittest tools.ci.test_diagnostic_observer_adapter
python3 -m unittest tools.ci.test_diagnostic_object_resolution
python3 -m unittest tools.ci.test_diagnostic_candidate_resolution
python3 -m unittest tools.ci.test_diagnostic_command
python3 -m unittest tools.ci.test_sdk_contract tools.ci.test_sdk_packages
python3 -m unittest tools.ci.test_registry_packages
python3 -m unittest tools.ci.test_current_integration
python3 tools/release/build_verifier_package.py --check
python3 -m unittest tools.ci.test_verifier_package.VerifierPackagePreflightTests
python3 -m unittest discover -s sdk/python/tests
node --experimental-strip-types --test sdk/typescript/tests/test.mjs
python3 -m unittest tools.release.test_validate_release_state
python3 -m unittest tools.ci.test_timing
python3 -m unittest tools.ci.test_summarize_timings
python3 -m unittest tools.ci.test_tool_cache
python3 -m unittest tools.ci.test_lean_toolchain
python3 -m unittest tools.ci.test_wire_transition
python3 -m unittest tools.ci.test_wire_v2_vectors
python3 -m unittest tools.ci.test_service_observation_contract
python3 -m unittest tools.ci.test_service_launcher_contract
python3 -m unittest experiments.network_authority.test_record_common
python3 -m unittest experiments.network_authority.test_record_port_control
python3 -m unittest experiments.network_authority.test_record_endpoint_control
python3 -m unittest experiments.network_authority.test_explicit_broker
python3 -m unittest experiments.network_authority.test_broker_case_client
python3 -m unittest experiments.network_authority.test_record_broker_control
python3 -m unittest experiments.network_authority.test_preconnected_channel
python3 -m unittest experiments.network_authority.test_preconnected_case_client
python3 -m unittest experiments.network_authority.test_record_preconnected_control
python3 -m unittest experiments.network_authority.test_scripted_dns
python3 -m unittest experiments.network_authority.test_decision_http_fixture
python3 -m unittest experiments.network_authority.test_decision_proxy_fixture
python3 -m unittest experiments.network_authority.test_decision_socket_fixture
python3 -m unittest experiments.network_authority.test_routing_transport_case
python3 -m unittest experiments.network_authority.test_routing_child_control
python3 -m unittest experiments.network_authority.test_routing_landlock_control
python3 -m unittest experiments.network_authority.test_routing_endpoint_control
python3 -m unittest experiments.network_authority.test_routing_transport_client
python3 -m unittest experiments.network_authority.test_routing_mediated_client
python3 -m unittest experiments.network_authority.test_routing_mediator
python3 -m unittest experiments.network_authority.test_routing_cell
python3 -m unittest experiments.network_authority.test_run_routing_direct_case
python3 -m unittest experiments.network_authority.test_run_routing_broker_case
python3 -m unittest experiments.network_authority.test_run_routing_preconnected_case
python3 -m unittest experiments.network_authority.test_record_routing_transport
python3 -m unittest experiments.network_authority.test_run_routing_transport
python3 -m unittest experiments.network_authority.test_verify_routing_transport
python3 -m unittest experiments.network_authority.test_resolution_indirection_case
python3 -m unittest experiments.network_authority.test_resolution_indirection_client
python3 -m unittest experiments.network_authority.test_resolution_network_client
python3 -m unittest experiments.network_authority.test_resolution_broker
python3 -m unittest experiments.network_authority.test_resolution_cell
python3 -m unittest experiments.network_authority.test_run_resolution_direct_case
python3 -m unittest experiments.network_authority.test_run_resolution_broker_case
python3 -m unittest experiments.network_authority.test_run_resolution_preconnected_case
python3 -m unittest experiments.network_authority.test_record_resolution_indirection
python3 -m unittest experiments.network_authority.test_verify_resolution_indirection
python3 -m unittest experiments.network_authority.test_run_resolution_indirection
python3 -m unittest experiments.network_authority.test_bypass_lifecycle_case
python3 -m unittest experiments.network_authority.test_bypass_syscall_probe
python3 -m unittest experiments.network_authority.test_bypass_cell
python3 -m unittest experiments.network_authority.test_bypass_lifecycle_evidence
python3 -m unittest experiments.network_authority.test_run_bypass_lifecycle_case
python3 -m unittest experiments.network_authority.test_process_limit_control
python3 -m unittest experiments.network_authority.test_run_bypass_syscall_case
python3 -m unittest experiments.network_authority.test_connection_reuse_fixture
python3 -m unittest experiments.network_authority.test_connection_reuse_channel
python3 -m unittest experiments.network_authority.test_stopped_release_control
python3 -m unittest experiments.network_authority.test_connection_reuse_client
python3 -m unittest experiments.network_authority.test_run_connection_reuse_case
python3 -m unittest experiments.network_authority.test_record_bypass_lifecycle
python3 -m unittest experiments.network_authority.test_verify_bypass_lifecycle
python3 -m unittest experiments.network_authority.test_run_bypass_lifecycle
python3 -m unittest experiments.network_authority.test_measurement_domain
python3 -m unittest experiments.network_authority.test_measurement_observation
python3 -m unittest experiments.network_authority.test_run_network_measurement
python3 -m unittest experiments.network_authority.test_record_network_measurement
python3 -m unittest experiments.network_authority.test_comparison_domain
python3 -m unittest experiments.network_authority.test_compare_network_results
python3 -m unittest experiments.network_authority.test_verify_network_comparison
cargo fmt --all -- --check
cargo metadata --locked --offline --format-version 1 >/dev/null
cargo check --workspace --all-targets --locked --offline
cargo clippy --workspace --all-targets --locked --offline -- -D warnings
cargo test --workspace --locked --offline
git diff --cached --check
