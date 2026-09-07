#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

output_root=".lake/build/lib/lean/ProofboundRuntimeReceipt"
mkdir -p "$output_root"

lake build Aeneas

lake env lean \
  formal/generated/ProofboundRuntimeReceipt/Types.lean \
  -o "$output_root/Types.olean"
lake env lean \
  formal/bridges/ProofboundRuntimeReceipt/FunsExternal.lean \
  -o "$output_root/FunsExternal.olean"
lake env lean \
  formal/generated/ProofboundRuntimeReceipt/Funs.lean \
  -o "$output_root/Funs.olean"
lake env lean \
  formal/ProofboundRuntime/Refinement/ReceiptEligibility.lean
lake env lean \
  formal/ProofboundRuntime/Refinement/ReceiptEligibilityClaim.lean
