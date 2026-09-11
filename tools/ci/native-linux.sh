#!/usr/bin/env bash
set -euo pipefail

supervisor_leaf="proofbound-supervisor"
repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
expected_architecture="${PROOFBOUND_EXPECTED_ARCH:-$(uname -m)}"
runtime_bins_prebuilt="${PROOFBOUND_RUNTIME_BINS_PREBUILT:-}"
if [[ -z "$runtime_bins_prebuilt" ]]; then
  if [[ -n "${PROOFBOUND_RUNTIME_BIN_DIR:-}" ]]; then
    runtime_bins_prebuilt=1
  else
    runtime_bins_prebuilt=0
  fi
fi
runtime_bin_directory="${PROOFBOUND_RUNTIME_BIN_DIR:-$PWD/target/debug}"
evidence_directory="${PROOFBOUND_EVIDENCE_DIRECTORY:-}"

if [[ "${PROOFBOUND_NATIVE_INNER:-}" == "1" ]]; then
  if [[ "$(id -u)" == "0" ]]; then
    echo "native corpus must execute as a non-root user" >&2
    exit 1
  fi
  actual_architecture="$(uname -m)"
  if [[ "$actual_architecture" != "$expected_architecture" ]]; then
    echo "native corpus architecture mismatch: expected $expected_architecture, observed $actual_architecture" >&2
    exit 1
  fi
  current_cgroup="$(awk -F: '$1 == "0" { print $3 }' /proc/self/cgroup)"
  case "$current_cgroup" in
    */"$supervisor_leaf") ;;
    *)
      echo "native corpus is not in the identified supervisor leaf: $current_cgroup" >&2
      exit 1
      ;;
  esac
  delegation_relative="${current_cgroup%/"$supervisor_leaf"}"
  delegation_root="/sys/fs/cgroup${delegation_relative}"
  if [[ -n "$(<"$delegation_root/cgroup.procs")" ]]; then
    echo "delegation root contains direct processes" >&2
    exit 1
  fi
  echo +memory +pids >"$delegation_root/cgroup.subtree_control"
  for controller in memory pids; do
    if ! grep -qw "$controller" "$delegation_root/cgroup.subtree_control"; then
      echo "$controller controller was not enabled below the delegation root" >&2
      exit 1
    fi
  done

  export PROOFBOUND_CGROUP_ROOT="$delegation_root"
  export PROOFBOUND_NATIVE_REQUIRED=1
  test -x "$PROOFBOUND_NATIVE_FIXTURE"
  "$PROOFBOUND_NATIVE_FIXTURE" preflight
  "$PROOFBOUND_NATIVE_FIXTURE" fd-exec-preflight "$PROOFBOUND_NATIVE_FIXTURE"
  "$PROOFBOUND_NATIVE_FIXTURE" landlock-exec-only-denied "$PROOFBOUND_NATIVE_FIXTURE"
  "$PROOFBOUND_NATIVE_FIXTURE" landlock-fd-exec-preflight "$PROOFBOUND_NATIVE_FIXTURE"
  uname -a
  systemd --version | head -n 1
  if [[ "${PROOFBOUND_NATIVE_SWAP_ONLY:-0}" == "1" ]]; then
    cargo test --locked -p proofbound-runtime-linux --test native_linux \
      production_launcher_enforces_native_swap_presence_matrix -- \
      --test-threads=1 --nocapture
    exit 0
  fi
  cargo test --locked -p proofbound-runtime-linux --test native_linux -- --test-threads=1 --nocapture

  if [[ "$runtime_bins_prebuilt" != "1" ]]; then
    cargo build --locked --workspace
  fi
  for binary in pbr pbr-native-launcher pbr-verify; do
    test -x "$runtime_bin_directory/$binary"
  done
  e2e_root="$(mktemp -d "$PWD/target/native-cli-e2e.XXXXXX")"
  trap 'rm -rf -- "$e2e_root"' EXIT
  plan="$e2e_root/plan.cbor"
  receipt="$e2e_root/receipt.cbor"
  result="$e2e_root/run-result.json"
  verification="$e2e_root/verification.json"
  preflight="$e2e_root/preflight.json"
  python3 tools/ci/encode_plan_v2.py \
    --output "$plan" \
    --id ci.native-cli-e2e \
    --executable "$PROOFBOUND_NATIVE_FIXTURE" \
    --argument positive \
    --working-directory . \
    --write output \
    --execute "$PROOFBOUND_NATIVE_FIXTURE" \
    --processes 1 \
    --wall-time-ms 5000 \
    --stdout-bytes 4096 \
    --stderr-bytes 4096 \
    --memory-bytes 268435456 \
    --swap-bytes 0

  "$runtime_bin_directory/pbr" plan check --plan "$plan"
  cgroup_before="$(
    stat -Lc '%d:%i:%f' "$PROOFBOUND_CGROUP_ROOT"
    sed -n '1p' "$PROOFBOUND_CGROUP_ROOT/cgroup.controllers"
    sed -n '1p' "$PROOFBOUND_CGROUP_ROOT/cgroup.subtree_control"
    sed -n '1p' "$PROOFBOUND_CGROUP_ROOT/cgroup.procs"
  )"
  test ! -e "$e2e_root/output"
  test ! -e "$receipt"
  "$runtime_bin_directory/pbr" preflight \
    --plan "$plan" \
    --receipt "$receipt" \
    --cgroup-root "$PROOFBOUND_CGROUP_ROOT" >"$preflight"
  test ! -e "$e2e_root/output"
  test ! -e "$receipt"
  cgroup_after="$(
    stat -Lc '%d:%i:%f' "$PROOFBOUND_CGROUP_ROOT"
    sed -n '1p' "$PROOFBOUND_CGROUP_ROOT/cgroup.controllers"
    sed -n '1p' "$PROOFBOUND_CGROUP_ROOT/cgroup.subtree_control"
    sed -n '1p' "$PROOFBOUND_CGROUP_ROOT/cgroup.procs"
  )"
  test "$cgroup_before" = "$cgroup_after"
  python3 -c '
import hashlib
import json
import os
import stat
import sys

report_path, plan_path, executable_path, cgroup_root, receipt_path, expected_arch = sys.argv[1:]
with open(report_path, encoding="utf-8") as source:
    report = json.load(source)
assert set(report) == {
    "caveat", "command", "inputs", "output_root", "plan_id", "plan_source",
    "platform", "ready", "receipt", "schema",
}
assert report["schema"] == "proofbound-runtime-preflight/1"
assert report["ready"] is True
assert report["caveat"] == "preflight.point-in-time"
assert report["plan_id"] == "ci.native-cli-e2e"
assert report["inputs"] == []
assert report["command"]["interpreter"] is None
assert report["command"]["executable"]["resolved"] == os.path.realpath(executable_path)
assert report["command"]["working_directory"]["resolved"] == os.path.dirname(plan_path)
assert report["output_root"] == {
    "requested": "output",
    "resolved_parent": os.path.dirname(plan_path),
    "resolved_target": os.path.join(os.path.dirname(plan_path), "output"),
}
assert report["receipt"] == {"resolved_target": receipt_path}
assert report["platform"]["architecture"] == expected_arch
assert report["platform"]["cgroup_v2"]["directory"] == cgroup_root
assert "pids" in report["platform"]["cgroup_v2"]["controllers"]

def expected_artifact(path, role):
    with open(path, "rb") as source:
        data = source.read()
    return {
        "role": role,
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "mode": stat.S_IMODE(os.stat(path).st_mode),
    }

assert report["plan_source"]["artifact"] == expected_artifact(plan_path, "execution-plan")
assert report["command"]["executable"]["artifact"] == expected_artifact(
    executable_path, "runtime-executable"
)
' "$preflight" "$plan" "$PROOFBOUND_NATIVE_FIXTURE" \
    "$PROOFBOUND_CGROUP_ROOT" "$receipt" "$expected_architecture"

  occupied_receipt="$e2e_root/occupied-receipt.cbor"
  printf '%s\n' 'preserve-me' >"$occupied_receipt"
  set +e
  "$runtime_bin_directory/pbr" preflight \
    --plan "$plan" \
    --receipt "$occupied_receipt" \
    --cgroup-root "$PROOFBOUND_CGROUP_ROOT" \
    >"$e2e_root/occupied-receipt-result.json" \
    2>"$e2e_root/occupied-receipt-error.txt"
  occupied_receipt_status=$?
  set -e
  test "$occupied_receipt_status" -eq 2
  test "$(<"$occupied_receipt")" = 'preserve-me'
  test "$(<"$e2e_root/occupied-receipt-error.txt")" = 'pbr: receipt.path.exists'
  python3 -c '
import json
import sys
with open(sys.argv[1], encoding="utf-8") as source:
    assert json.load(source) == {
        "schema": "proofbound-runtime-preflight/1",
        "ready": False,
        "phase": "receipt-target",
        "code": "receipt.path.exists",
    }
' "$e2e_root/occupied-receipt-result.json"

  mkdir "$e2e_root/output"
  set +e
  "$runtime_bin_directory/pbr" preflight \
    --plan "$plan" \
    --receipt "$receipt" \
    --cgroup-root "$PROOFBOUND_CGROUP_ROOT" \
    >"$e2e_root/occupied-output-result.json" \
    2>"$e2e_root/occupied-output-error.txt"
  occupied_output_status=$?
  set -e
  test "$occupied_output_status" -eq 2
  test -d "$e2e_root/output"
  test "$(<"$e2e_root/occupied-output-error.txt")" = 'pbr: output.root.exists'
  python3 -c '
import json
import sys
with open(sys.argv[1], encoding="utf-8") as source:
    assert json.load(source) == {
        "schema": "proofbound-runtime-preflight/1",
        "ready": False,
        "phase": "output-root",
        "code": "output.root.exists",
    }
' "$e2e_root/occupied-output-result.json"
  rmdir "$e2e_root/output"

  "$runtime_bin_directory/pbr" run \
    --plan "$plan" \
    --receipt "$receipt" \
    --cgroup-root "$PROOFBOUND_CGROUP_ROOT" >"$result"
  commitment="$(python3 -c '
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    result = json.load(source)
assert result["schema"] == "proofbound-runtime-run-result/2"
assert result["outcome"] == {"kind": "exited", "code": 0}
assert result["execution_id"]
assert result["commitment"].startswith("hex:")
print("sha256:" + result["commitment"].removeprefix("hex:"))
' "$result")"
  "$runtime_bin_directory/pbr-verify" \
    --expected-commitment "$commitment" \
    "$receipt" >"$verification"
  python3 -c '
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    verification = json.load(source)
assert verification == {
    "eligibility": {"reasons": [], "status": "reusable"},
    "receipt_commitment": sys.argv[2],
    "valid": True,
}
  ' "$verification" "$commitment"
  "$runtime_bin_directory/pbr" inspect "$receipt" >/dev/null
  example_bundle_result="$e2e_root/example-bundle-result.json"
  python3 tools/release/build_example.py \
    --output-directory "$e2e_root" >"$example_bundle_result"
  example_archive="$(python3 -c '
import json
import sys
with open(sys.argv[1], encoding="utf-8") as source:
    print(json.load(source)["archive"])
' "$example_bundle_result")"
  example_source="$e2e_root/example-source"
  mkdir "$example_source"
  tar -xzf "$example_archive" -C "$example_source" --strip-components=1
  example_result="$e2e_root/maintained-example-result.json"
  "$example_source/run-example.sh" \
    "$runtime_bin_directory" \
    "$PROOFBOUND_CGROUP_ROOT" \
    "$e2e_root/maintained-example" >"$example_result"
  python3 -c '
import json
import os
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    result = json.load(source)
assert set(result) == {"commitment", "output", "receipt", "schema", "verification"}
assert result["schema"] == "proofbound-runtime-example-result/1"
for field in ("output", "receipt", "verification"):
    assert os.path.isfile(result[field])
assert result["commitment"].startswith("sha256:")
' "$example_result"
  if [[ -n "$evidence_directory" ]]; then
    mkdir -p "$evidence_directory"
    install -m 0644 "$plan" "$evidence_directory/plan.cbor"
    install -m 0644 "$preflight" "$evidence_directory/preflight.json"
    install -m 0644 "$receipt" "$evidence_directory/execution-receipt.cbor"
    install -m 0644 "$example_result" "$evidence_directory/example-result.json"
    install -m 0644 "$verification" "$evidence_directory/verification.json"
    printf '%s\n' "$commitment" >"$evidence_directory/receipt-commitment.txt"
    python3 -c '
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    print(json.load(source)["execution_id"])
' "$result" >"$evidence_directory/execution-id.txt"
    python3 tools/ci/native_context.py \
      --architecture "$expected_architecture" \
      --cgroup-root "$PROOFBOUND_CGROUP_ROOT" \
      --fixture "$PROOFBOUND_NATIVE_FIXTURE" \
      --runtime-bin-directory "$runtime_bin_directory" \
      --output "$evidence_directory/native-context.json"
  fi
  exit 0
fi

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "native Linux corpus requires Linux" >&2
  exit 1
fi
if [[ "$(id -u)" == "0" ]]; then
  echo "outer native corpus runner must be non-root" >&2
  exit 1
fi

fixture="$repository_root/target/native-boundary-probe"
mkdir -p "$repository_root/target"
cc -O2 -static -Wall -Wextra -Werror \
  "$repository_root/crates/proofbound-runtime-linux/tests/fixtures/native-boundary-probe.c" \
  -o "$fixture"
if file "$fixture" | grep -q "dynamically linked"; then
  echo "native boundary fixture must be statically linked" >&2
  exit 1
fi

unit_suffix="${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}-$(uname -m)"

run_native_service() {
  local swap_only="$1"
  sudo systemd-run \
    --quiet \
    --wait \
    --collect \
    --pipe \
    --service-type=exec \
    --unit="proofbound-runtime-native-$unit_suffix-$PROOFBOUND_NATIVE_SWAP_MODE" \
    --property="User=$(id -un)" \
    --property="Group=$(id -gn)" \
    --property="Delegate=pids memory" \
    --property="DelegateSubgroup=$supervisor_leaf" \
    --working-directory="$repository_root" \
    --setenv=PROOFBOUND_NATIVE_INNER=1 \
    --setenv="PROOFBOUND_NATIVE_FIXTURE=$fixture" \
    --setenv="PROOFBOUND_NATIVE_SWAP_MODE=$PROOFBOUND_NATIVE_SWAP_MODE" \
    --setenv="PROOFBOUND_NATIVE_SWAP_ONLY=$swap_only" \
    --setenv="PROOFBOUND_EXPECTED_ARCH=$expected_architecture" \
    --setenv="PROOFBOUND_RUNTIME_BINS_PREBUILT=$runtime_bins_prebuilt" \
    --setenv="PROOFBOUND_RUNTIME_BIN_DIR=$runtime_bin_directory" \
    --setenv="PROOFBOUND_EVIDENCE_DIRECTORY=$evidence_directory" \
    --setenv="PATH=$PATH" \
    /usr/bin/env bash tools/ci/native-linux.sh
}

swap_file="/mnt/proofbound-runtime-native-$unit_suffix.swap"
original_swap_paths=()
original_swap_priorities=()
while read -r path _ _ _ priority; do
  original_swap_paths+=("$path")
  original_swap_priorities+=("$priority")
done < <(tail -n +2 /proc/swaps)

restore_original_swap() {
  local index path priority
  for index in "${!original_swap_paths[@]}"; do
    path="${original_swap_paths[$index]}"
    priority="${original_swap_priorities[$index]}"
    if ! awk -v candidate="$path" 'NR > 1 && $1 == candidate { found = 1 } END { exit !found }' /proc/swaps; then
      sudo swapon --priority "$priority" "$path"
    fi
  done
}

cleanup_swap_state() {
  if awk -v path="$swap_file" 'NR > 1 && $1 == path { found = 1 } END { exit !found }' /proc/swaps; then
    sudo swapoff "$swap_file"
  fi
  sudo rm -f -- "$swap_file"
  restore_original_swap
}
trap cleanup_swap_state EXIT

if [[ "${#original_swap_paths[@]}" -gt 0 ]]; then
  if [[ "${GITHUB_ACTIONS:-}" != "true" ]]; then
    echo "native absent-swap phase will not alter swap outside a disposable GitHub runner" >&2
    exit 1
  fi
  for path in "${original_swap_paths[@]}"; do
    sudo swapoff "$path"
  done
fi
test "$(wc -l </proc/swaps)" -eq 1
PROOFBOUND_NATIVE_SWAP_MODE=absent run_native_service 0

if [[ "${#original_swap_paths[@]}" -gt 0 ]]; then
  restore_original_swap
else
  sudo fallocate -l 256M "$swap_file"
  sudo chmod 0600 "$swap_file"
  sudo mkswap "$swap_file" >/dev/null
  sudo swapon "$swap_file"
fi
PROOFBOUND_NATIVE_SWAP_MODE=present run_native_service 1
if [[ -n "$evidence_directory" ]]; then
  python3 -c '
import json
import os
import sys

output, architecture, revision = sys.argv[1:]
record = {
    "architecture": architecture,
    "phases": {"absent": "passed", "present": "passed"},
    "schema": "proofbound-runtime-native-swap-matrix/1",
    "source_revision": revision,
}
descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
with os.fdopen(descriptor, "w", encoding="utf-8") as destination:
    json.dump(record, destination, sort_keys=True, separators=(",", ":"))
    destination.write("\n")
' "$evidence_directory/native-swap-matrix.json" \
    "$expected_architecture" "$(git rev-parse HEAD)"
fi
cleanup_swap_state
trap - EXIT
