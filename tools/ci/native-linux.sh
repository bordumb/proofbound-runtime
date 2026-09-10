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
  echo +pids >"$delegation_root/cgroup.subtree_control"
  if ! grep -qw pids "$delegation_root/cgroup.subtree_control"; then
    echo "pids controller was not enabled below the delegation root" >&2
    exit 1
  fi

  export PROOFBOUND_CGROUP_ROOT="$delegation_root"
  export PROOFBOUND_NATIVE_REQUIRED=1
  test -x "$PROOFBOUND_NATIVE_FIXTURE"
  "$PROOFBOUND_NATIVE_FIXTURE" preflight
  "$PROOFBOUND_NATIVE_FIXTURE" fd-exec-preflight "$PROOFBOUND_NATIVE_FIXTURE"
  "$PROOFBOUND_NATIVE_FIXTURE" landlock-exec-only-denied "$PROOFBOUND_NATIVE_FIXTURE"
  "$PROOFBOUND_NATIVE_FIXTURE" landlock-fd-exec-preflight "$PROOFBOUND_NATIVE_FIXTURE"
  uname -a
  systemd --version | head -n 1
  cargo test --locked -p proofbound-runtime-linux --test native_linux -- --test-threads=1 --nocapture

  if [[ "$runtime_bins_prebuilt" != "1" ]]; then
    cargo build --locked --workspace
  fi
  for binary in pbr pbr-native-launcher pbr-verify; do
    test -x "$runtime_bin_directory/$binary"
  done
  e2e_root="$(mktemp -d "$PWD/target/native-cli-e2e.XXXXXX")"
  trap 'rm -rf -- "$e2e_root"' EXIT
  plan="$e2e_root/plan.toml"
  receipt="$e2e_root/receipt.json"
  result="$e2e_root/run-result.json"
  verification="$e2e_root/verification.json"
  preflight="$e2e_root/preflight.json"
  printf '%s\n' \
    'schema = "proofbound-runtime-plan/1"' \
    'id = "ci.native-cli-e2e"' \
    '' \
    '[command]' \
    "executable = \"$PROOFBOUND_NATIVE_FIXTURE\"" \
    'arguments = ["positive"]' \
    'working_directory = "."' \
    '' \
    '[authority]' \
    'network = "deny"' \
    'environment = []' \
    'read = []' \
    'runtime_read = []' \
    'write = ["output"]' \
    "execute = [\"$PROOFBOUND_NATIVE_FIXTURE\"]" \
    '' \
    '[limits]' \
    'wall_time_ms = 5000' \
    'stdout_bytes = 4096' \
    'stderr_bytes = 4096' \
    'processes = 1' >"$plan"

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

  occupied_receipt="$e2e_root/occupied-receipt.json"
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
assert result["schema"] == "proofbound-runtime-run-result/1"
assert result["outcome"] == {"kind": "exited", "code": 0}
assert result["execution_id"]
print(result["commitment"])
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
  example_result="$e2e_root/maintained-example-result.json"
  "$repository_root/examples/hello-static/run-example.sh" \
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
    install -m 0644 "$plan" "$evidence_directory/plan.toml"
    install -m 0644 "$preflight" "$evidence_directory/preflight.json"
    install -m 0644 "$receipt" "$evidence_directory/execution-receipt.json"
    install -m 0644 "$example_result" "$evidence_directory/example-result.json"
    install -m 0644 "$verification" "$evidence_directory/verification.json"
    printf '%s\n' "$commitment" >"$evidence_directory/receipt-commitment.txt"
    python3 -c '
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    print(json.load(source)["execution_id"])
' "$result" >"$evidence_directory/execution-id.txt"
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
exec sudo systemd-run \
  --quiet \
  --wait \
  --collect \
  --pipe \
  --service-type=exec \
  --unit="proofbound-runtime-native-$unit_suffix" \
  --property="User=$(id -un)" \
  --property="Group=$(id -gn)" \
  --property=Delegate=pids \
  --property="DelegateSubgroup=$supervisor_leaf" \
  --working-directory="$repository_root" \
  --setenv=PROOFBOUND_NATIVE_INNER=1 \
  --setenv="PROOFBOUND_NATIVE_FIXTURE=$fixture" \
  --setenv="PROOFBOUND_EXPECTED_ARCH=$expected_architecture" \
  --setenv="PROOFBOUND_RUNTIME_BINS_PREBUILT=$runtime_bins_prebuilt" \
  --setenv="PROOFBOUND_RUNTIME_BIN_DIR=$runtime_bin_directory" \
  --setenv="PROOFBOUND_EVIDENCE_DIRECTORY=$evidence_directory" \
  --setenv="PATH=$PATH" \
  /usr/bin/env bash tools/ci/native-linux.sh
