#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

output_root=".lake/build/lib/lean/ProofboundRuntimePolicy"
mkdir -p "$output_root"
refinement_root=".lake/build/lib/lean/ProofboundRuntime/Refinement"
mkdir -p "$refinement_root"

lake build Aeneas

lake env lean \
  formal/generated/ProofboundRuntimePolicy/Types.lean \
  -o "$output_root/Types.olean"
lake env lean \
  formal/generated/ProofboundRuntimePolicy/Funs.lean \
  -o "$output_root/Funs.olean"
lake env lean \
  formal/ProofboundRuntime/Refinement/PolicyCompilation.lean \
  -o "$refinement_root/PolicyCompilation.olean"
lake env lean \
  formal/ProofboundRuntime/Refinement/PolicyCompilationClaim.lean \
  -o "$refinement_root/PolicyCompilationClaim.olean"
