#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 5 ]]; then
  echo "usage: native-performance.sh <result-root> <source-commit> <architecture> <runtime-bin-directory> <runner-image>" >&2
  exit 2
fi

result_root="$1"
source_commit="$2"
expected_architecture="$3"
runtime_bin_directory="$4"
runner_image="$5"
repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
supervisor_leaf="proofbound-supervisor"

for path in "$result_root" "$runtime_bin_directory"; do
  if [[ "$path" != /* || ! -d "$path" ]]; then
    echo "native benchmark directories must exist and be absolute" >&2
    exit 2
  fi
done
if [[ ! "$source_commit" =~ ^[0-9a-f]{40}$ ]]; then
  echo "native benchmark source must be one exact commit" >&2
  exit 2
fi
if [[ -z "$runner_image" ]]; then
  echo "native benchmark runner image must be named" >&2
  exit 2
fi

work_root="$result_root/workload"
workload_executable="$work_root/hello-static"
plan="$work_root/plan.toml"
expected_output="$work_root/expected-output.txt"

if [[ "${PROOFBOUND_NATIVE_PERFORMANCE_INNER:-}" == "1" ]]; then
  if [[ "$(id -u)" == "0" ]]; then
    echo "native benchmark must execute as a non-root user" >&2
    exit 1
  fi
  if [[ "$(uname -m)" != "$expected_architecture" ]]; then
    echo "native benchmark architecture mismatch" >&2
    exit 1
  fi
  current_cgroup="$(awk -F: '$1 == "0" { print $3 }' /proc/self/cgroup)"
  case "$current_cgroup" in
    */"$supervisor_leaf") ;;
    *)
      echo "native benchmark is not in the identified supervisor leaf" >&2
      exit 1
      ;;
  esac
  delegation_relative="${current_cgroup%/"$supervisor_leaf"}"
  delegation_root="/sys/fs/cgroup${delegation_relative}"
  if [[ -n "$(<"$delegation_root/cgroup.procs")" ]]; then
    echo "native benchmark delegation root contains direct processes" >&2
    exit 1
  fi
  echo +pids >"$delegation_root/cgroup.subtree_control"
  if ! grep -qw pids "$delegation_root/cgroup.subtree_control"; then
    echo "pids controller was not enabled below the delegation root" >&2
    exit 1
  fi
  exec "$result_root/pbr-bench" native \
    --source-commit "$source_commit" \
    --result-root "$result_root" \
    --cgroup-root "$delegation_root" \
    --runtime-bin-directory "$runtime_bin_directory" \
    --plan "$plan" \
    --workload-executable "$workload_executable" \
    --expected-output "$expected_output" \
    --runner-image "$runner_image" \
    >"$result_root/result.json" \
    2>"$result_root/producer.stderr"
fi

if [[ "$(uname -s)" != "Linux" || "$(id -u)" == "0" ]]; then
  echo "native benchmark outer runner requires non-root Linux" >&2
  exit 1
fi
if [[ "$(uname -m)" != "$expected_architecture" ]]; then
  echo "native benchmark outer architecture mismatch" >&2
  exit 1
fi
for binary in pbr pbr-native-launcher pbr-verify; do
  if [[ ! -x "$runtime_bin_directory/$binary" ]]; then
    echo "missing native benchmark Runtime binary: $binary" >&2
    exit 2
  fi
done
if [[ ! -x "$result_root/pbr-bench" || -e "$work_root" ]]; then
  echo "native benchmark result root is not fresh" >&2
  exit 2
fi

mkdir -m 0700 "$work_root"
cc -O2 -static -Wall -Wextra -Werror \
  "$repository_root/examples/hello-static/hello.c" \
  -o "$workload_executable"
if file "$workload_executable" | grep -q 'dynamically linked'; then
  echo "native benchmark workload must be statically linked" >&2
  exit 2
fi
printf '%s\n' 'hello from a bounded Proofbound Runtime execution' >"$expected_output"
workload_toml="$(python3 -c 'import json, sys; print(json.dumps(sys.argv[1]))' "$workload_executable")"
printf '%s\n' \
  'schema = "proofbound-runtime-plan/1"' \
  'id = "benchmark.hello-static"' \
  '' \
  '[command]' \
  "executable = $workload_toml" \
  'arguments = []' \
  'working_directory = "."' \
  '' \
  '[authority]' \
  'network = "deny"' \
  'environment = []' \
  'read = []' \
  'runtime_read = []' \
  'write = ["output"]' \
  "execute = [$workload_toml]" \
  '' \
  '[limits]' \
  'wall_time_ms = 5000' \
  'stdout_bytes = 4096' \
  'stderr_bytes = 4096' \
  'processes = 1' >"$plan"

unit_suffix="${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}-$(uname -m)"
exec sudo systemd-run \
  --quiet \
  --wait \
  --collect \
  --pipe \
  --service-type=exec \
  --unit="proofbound-runtime-performance-$unit_suffix" \
  --property="User=$(id -un)" \
  --property="Group=$(id -gn)" \
  --property=Delegate=pids \
  --property=DelegateSubgroup=proofbound-supervisor \
  --working-directory="$repository_root" \
  --setenv=PROOFBOUND_NATIVE_PERFORMANCE_INNER=1 \
  --setenv="PATH=$PATH" \
  /usr/bin/env bash tools/ci/native-performance.sh \
    "$result_root" \
    "$source_commit" \
    "$expected_architecture" \
    "$runtime_bin_directory" \
    "$runner_image"
