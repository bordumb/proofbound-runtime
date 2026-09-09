#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

python3 tools/ci/version.py --check
python3 tools/ci/changelog.py --staged
python3 tools/ci/documentation.py
python3 tools/release/observation_inputs.py --check
python3 -m unittest tools.ci.test_install_release
cargo fmt --all -- --check
cargo metadata --locked --offline --format-version 1 >/dev/null
cargo check --workspace --all-targets --locked --offline
cargo clippy --workspace --all-targets --locked --offline -- -D warnings
cargo test --workspace --locked --offline
bash tools/ci/manifests.sh
git diff --cached --check
