#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

stage="${1:-all}"
case "$stage" in
  all|preflight|rust|formal) ;;
  *)
    printf '%s\n' "unknown CI stage: $stage" >&2
    exit 2
    ;;
esac

selected() {
  [[ "$stage" == "all" || "$stage" == "$1" ]]
}

timed_unit() {
  local name="$1"
  shift
  if [[ -n "${PBR_CI_TIMING_FILE:-}" ]]; then
    python3 tools/ci/timing.py run \
      --output "$PBR_CI_TIMING_FILE" \
      --stage "$stage" \
      --kind unit \
      --name "$name" \
      -- "$@"
  else
    "$@"
  fi
}

if selected "preflight"; then
  printf '%s\n' '[1/9] version metadata'
  timed_unit version-metadata python3 tools/ci/version.py --check

  printf '%s\n' '[2/9] changelog'
  timed_unit changelog python3 tools/ci/changelog.py

  printf '%s\n' '[3/9] documentation and feedback records'
  timed_unit documentation python3 tools/ci/documentation.py

  printf '%s\n' '[4/9] closed release observation inputs and installer'
  timed_unit observation-inputs python3 tools/release/observation_inputs.py --check
  timed_unit artifact-checker python3 tools/release/artifact_checker.py --self-check
  timed_unit install-release-tests python3 -m unittest tools.ci.test_install_release
  timed_unit build-example-tests python3 -m unittest tools.ci.test_build_example
  timed_unit workflow-tests python3 -m unittest tools.ci.test_required_workflow
  timed_unit native-context-tests python3 -m unittest tools.ci.test_native_context
  timed_unit release-workflow-tests python3 -m unittest tools.ci.test_release_workflow
  timed_unit acceptance-action-tests python3 -m unittest tools.ci.test_acceptance_action
  timed_unit acceptance-policy-compiler-tests python3 -m unittest tools.ci.test_acceptance_policy_compiler
  timed_unit plan-scaffold-contract-tests python3 -m unittest tools.ci.test_plan_scaffold_contract
  timed_unit release-state-tests python3 -m unittest tools.release.test_validate_release_state
  timed_unit timing-tests python3 -m unittest tools.ci.test_timing
  timed_unit timing-summary-tests python3 -m unittest tools.ci.test_summarize_timings
  timed_unit tool-cache-tests python3 -m unittest tools.ci.test_tool_cache
  timed_unit lean-toolchain-tests python3 -m unittest tools.ci.test_lean_toolchain
  timed_unit wire-transition-tests python3 -m unittest tools.ci.test_wire_transition
  timed_unit wire-v2-vector-tests python3 -m unittest tools.ci.test_wire_v2_vectors
  timed_unit performance-workflow-tests python3 -m unittest tools.ci.test_performance_workflow
  timed_unit performance-schema-tests python3 -m unittest experiments.performance.test_pure_result_schema experiments.performance.test_native_result_schema
  timed_unit performance-verifier-tests python3 -m unittest experiments.performance.test_discover_runtime_libraries experiments.performance.test_verify_pure experiments.performance.test_verify_native
  timed_unit network-record-port-tests python3 -m unittest experiments.network_authority.test_record_port_control
  timed_unit network-record-endpoint-tests python3 -m unittest experiments.network_authority.test_record_endpoint_control
  timed_unit network-broker-tests python3 -m unittest experiments.network_authority.test_explicit_broker
  timed_unit network-broker-client-tests python3 -m unittest experiments.network_authority.test_broker_case_client
  timed_unit network-record-broker-tests python3 -m unittest experiments.network_authority.test_record_broker_control
  timed_unit network-preconnected-tests python3 -m unittest experiments.network_authority.test_preconnected_channel
  timed_unit network-preconnected-client-tests python3 -m unittest experiments.network_authority.test_preconnected_case_client
  timed_unit network-record-preconnected-tests python3 -m unittest experiments.network_authority.test_record_preconnected_control
  timed_unit network-dns-tests python3 -m unittest experiments.network_authority.test_scripted_dns
  timed_unit network-http-fixture-tests python3 -m unittest experiments.network_authority.test_decision_http_fixture
  timed_unit network-proxy-fixture-tests python3 -m unittest experiments.network_authority.test_decision_proxy_fixture
  timed_unit network-socket-fixture-tests python3 -m unittest experiments.network_authority.test_decision_socket_fixture
  timed_unit network-routing-transport-case-tests python3 -m unittest experiments.network_authority.test_routing_transport_case
  timed_unit network-routing-child-tests python3 -m unittest experiments.network_authority.test_routing_child_control
  timed_unit network-routing-landlock-tests python3 -m unittest experiments.network_authority.test_routing_landlock_control
  timed_unit network-routing-endpoint-tests python3 -m unittest experiments.network_authority.test_routing_endpoint_control
  timed_unit network-routing-client-tests python3 -m unittest experiments.network_authority.test_routing_transport_client
  timed_unit network-routing-mediated-tests python3 -m unittest experiments.network_authority.test_routing_mediated_client
  timed_unit network-routing-mediator-tests python3 -m unittest experiments.network_authority.test_routing_mediator
  timed_unit network-routing-cell-tests python3 -m unittest experiments.network_authority.test_routing_cell
  timed_unit network-direct-case-tests python3 -m unittest experiments.network_authority.test_run_routing_direct_case
  timed_unit network-broker-case-tests python3 -m unittest experiments.network_authority.test_run_routing_broker_case
  timed_unit network-preconnected-case-tests python3 -m unittest experiments.network_authority.test_run_routing_preconnected_case
  timed_unit network-record-routing-tests python3 -m unittest experiments.network_authority.test_record_routing_transport
  timed_unit network-run-routing-tests python3 -m unittest experiments.network_authority.test_run_routing_transport
  timed_unit network-verify-routing-tests python3 -m unittest experiments.network_authority.test_verify_routing_transport
fi

if selected "rust"; then
  printf '%s\n' '[5/9] Rust formatting, linting, tests, and locked metadata'
  timed_unit rust-format cargo fmt --all -- --check
  timed_unit rust-metadata bash -c 'cargo metadata --locked --offline --format-version 1 >/dev/null'
  timed_unit rust-check cargo check --workspace --all-targets --locked --offline
  timed_unit rust-clippy cargo clippy --workspace --all-targets --locked --offline -- -D warnings
  timed_unit rust-tests cargo test --workspace --locked --offline

  printf '%s\n' '[6/9] independent authority conformance'
  timed_unit authority-conformance python3 tools/conformance/authority_reference.py
fi

if selected "formal"; then
  printf '%s\n' '[7/9] Lean model, generated source translation, and claim audit executable'
  timed_unit lean-build lake build
  timed_unit authority-refinement bash tools/ci/authority-refinement.sh
  timed_unit binding-refinement bash tools/ci/binding-refinement.sh
  timed_unit policy-refinement bash tools/ci/policy-refinement.sh
  timed_unit receipt-refinement bash tools/ci/receipt-refinement.sh
fi

if selected "rust"; then
  printf '%s\n' '[8/9] dependency licenses, versions, and sources'
  timed_unit dependency-policy cargo deny --locked check bans licenses sources
fi

if selected "formal"; then
  printf '%s\n' '[9/9] Proofbound evidence and status derivation'
  timed_unit fresh-evidence bash tools/ci/manifests.sh
fi
