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
