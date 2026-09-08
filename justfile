set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

bootstrap:
    cargo fetch --locked
    lake update

fmt:
    cargo fmt --all -- --check

rust:
    cargo check --workspace --all-targets --locked --offline
    cargo clippy --workspace --all-targets --locked --offline -- -D warnings
    cargo test --workspace --locked --offline

formal:
    lake build
    bash tools/ci/authority-refinement.sh

bounded:
    cargo kani -q -p proofbound-runtime-core --harness normalization_does_not_amplify_bounded_catalog
    cargo kani -q -p proofbound-runtime-core --harness policy_compilation_does_not_amplify_bounded_catalog
    cargo kani -q -p proofbound-runtime-receipt-kani --harness receipt_eligibility_is_exact_for_bounded_state_model

docs:
    python3 tools/ci/documentation.py

metadata:
    python3 tools/ci/version.py --check
    python3 tools/ci/changelog.py
    cargo metadata --locked --offline --format-version 1 >/dev/null

manifests:
    bash tools/ci/manifests.sh

dependencies:
    cargo deny --locked check bans licenses sources

fast-checks:
    bash tools/ci/pre-commit.sh

hooks:
    pre-commit install --hook-type pre-commit

check: fast-checks

ci:
    bash tools/ci/ci.sh

release-receipt context observation_inputs output:
    bash tools/release/proofbound-release.sh "{{context}}" "{{observation_inputs}}" "{{output}}"
