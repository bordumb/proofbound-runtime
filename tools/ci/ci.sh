#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

printf '%s\n' '[1/8] version metadata'
python3 tools/ci/version.py --check

printf '%s\n' '[2/8] changelog'
python3 tools/ci/changelog.py

printf '%s\n' '[3/8] documentation and feedback records'
python3 tools/ci/documentation.py

printf '%s\n' '[4/8] Rust formatting, linting, tests, and locked metadata'
cargo fmt --all -- --check
cargo metadata --locked --offline --format-version 1 >/dev/null
cargo check --workspace --all-targets --locked --offline
cargo clippy --workspace --all-targets --locked --offline -- -D warnings
cargo test --workspace --locked --offline

printf '%s\n' '[5/8] independent authority conformance'
python3 tools/conformance/authority_reference.py

printf '%s\n' '[6/8] Lean model, generated source translation, and claim audit executable'
lake build
bash tools/ci/authority-refinement.sh

printf '%s\n' '[7/8] dependency licenses, versions, and sources'
cargo deny --locked check bans licenses sources

printf '%s\n' '[8/8] Proofbound Tier 2 evidence and status derivation'
bash tools/ci/manifests.sh
