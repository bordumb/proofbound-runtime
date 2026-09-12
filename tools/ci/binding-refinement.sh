#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

output_root=".lake/build/lib/lean/ProofboundRuntimeBinding"
mkdir -p "$output_root"
refinement_root=".lake/build/lib/lean/ProofboundRuntime/Refinement"
mkdir -p "$refinement_root"

lake build Aeneas ProofboundRuntime.Binding

lake env lean \
  formal/generated/ProofboundRuntimeBinding/Types.lean \
  -o "$output_root/Types.olean"
lake env lean \
  formal/generated/ProofboundRuntimeBinding/Funs.lean \
  -o "$output_root/Funs.olean"
lake env lean \
  formal/ProofboundRuntime/Refinement/ReceiptBinding.lean \
  -o "$refinement_root/ReceiptBinding.olean"
lake env lean \
  formal/ProofboundRuntime/Refinement/ReceiptBindingClaim.lean \
  -o "$refinement_root/ReceiptBindingClaim.olean"
