#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

printf '%s\n' '[1/9] version metadata'
python3 tools/ci/version.py --check

printf '%s\n' '[2/9] changelog'
python3 tools/ci/changelog.py

printf '%s\n' '[3/9] documentation and feedback records'
python3 tools/ci/documentation.py

printf '%s\n' '[4/9] closed release observation inputs and installer'
python3 tools/release/observation_inputs.py --check
python3 tools/release/artifact_checker.py --self-check
python3 -m unittest tools.ci.test_install_release
python3 -m unittest tools.ci.test_build_example
python3 -m unittest experiments.network_authority.test_record_port_control
python3 -m unittest experiments.network_authority.test_record_endpoint_control
python3 -m unittest experiments.network_authority.test_explicit_broker
python3 -m unittest experiments.network_authority.test_broker_case_client

printf '%s\n' '[5/9] Rust formatting, linting, tests, and locked metadata'
cargo fmt --all -- --check
cargo metadata --locked --offline --format-version 1 >/dev/null
cargo check --workspace --all-targets --locked --offline
cargo clippy --workspace --all-targets --locked --offline -- -D warnings
cargo test --workspace --locked --offline

printf '%s\n' '[6/9] independent authority conformance'
python3 tools/conformance/authority_reference.py

printf '%s\n' '[7/9] Lean model, generated source translation, and claim audit executable'
lake build
bash tools/ci/authority-refinement.sh
bash tools/ci/binding-refinement.sh
bash tools/ci/policy-refinement.sh
bash tools/ci/receipt-refinement.sh

printf '%s\n' '[8/9] dependency licenses, versions, and sources'
cargo deny --locked check bans licenses sources

printf '%s\n' '[9/9] Proofbound evidence and status derivation'
bash tools/ci/manifests.sh
