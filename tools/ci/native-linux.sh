#!/usr/bin/env bash
set -euo pipefail

supervisor_leaf="proofbound-supervisor"

if [[ "${PROOFBOUND_NATIVE_INNER:-}" == "1" ]]; then
  if [[ "$(id -u)" == "0" ]]; then
    echo "native corpus must execute as a non-root user" >&2
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

  cargo build --locked --workspace
  e2e_root="$(mktemp -d "$PWD/target/native-cli-e2e.XXXXXX")"
  trap 'rm -rf -- "$e2e_root"' EXIT
  plan="$e2e_root/plan.toml"
  receipt="$e2e_root/receipt.json"
  result="$e2e_root/run-result.json"
  verification="$e2e_root/verification.json"
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

  target/debug/pbr plan check --plan "$plan"
  target/debug/pbr run \
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
print(result["commitment"])
' "$result")"
  target/debug/pbr-verify \
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
  target/debug/pbr inspect "$receipt" >/dev/null
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

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
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
  --setenv="PATH=$PATH" \
  /usr/bin/env bash tools/ci/native-linux.sh
