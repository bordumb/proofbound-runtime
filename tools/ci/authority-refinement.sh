#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

output_root=".lake/build/lib/lean/ProofboundRuntimeCore"
mkdir -p "$output_root"

lake build Aeneas

lake env lean \
  formal/generated/ProofboundRuntimeCore/Types.lean \
  -o "$output_root/Types.olean"
lake env lean \
  formal/bridges/ProofboundRuntimeCore/FunsExternal.lean \
  -o "$output_root/FunsExternal.olean"
lake env lean \
  formal/generated/ProofboundRuntimeCore/Funs.lean \
  -o "$output_root/Funs.olean"
lake env lean \
  formal/ProofboundRuntime/Refinement/Authority.lean
lake env lean \
  formal/ProofboundRuntime/Refinement/AuthorityNormalization.lean
