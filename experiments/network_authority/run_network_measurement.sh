#!/usr/bin/env bash
set -euo pipefail

usage='usage: run_network_measurement.sh <landlock-port|cgroup-endpoint|explicit-broker|preconnected-channel> <new-absolute-result-directory>'

if [[ $# -ne 2 ]]; then
  if [[ $# -ne 5 || "${1:-}" != "--inside" ]]; then
    echo "$usage" >&2
    exit 2
  fi
fi
if [[ "$(uname -s)" != "Linux" ]]; then
  echo 'network measurement requires native Linux' >&2
  exit 3
fi

script_path="$(readlink -f "${BASH_SOURCE[0]}")"
repository_root="$(cd "$(dirname "$script_path")/../.." && pwd)"

if [[ "$1" != "--inside" ]]; then
  mechanism="$1"
  output_directory="$2"
  case "$mechanism" in
    landlock-port|cgroup-endpoint|explicit-broker|preconnected-channel) ;;
    *) echo 'network measurement mechanism is invalid' >&2; exit 2 ;;
  esac
  if [[ "$output_directory" != /* || -e "$output_directory" || -L "$output_directory" ]]; then
    echo 'measurement result directory must be one absent absolute path' >&2
    exit 2
  fi
  if [[ ! -d "$(dirname "$output_directory")" ]]; then
    echo 'measurement result parent directory does not exist' >&2
    exit 2
  fi
  if [[ $EUID -ne 0 ]]; then
    echo 'measurement namespace setup requires root; invoke this script through sudo' >&2
    exit 3
  fi
  if [[ -n "$(git -C "$repository_root" status --porcelain)" ]]; then
    echo 'network measurement requires a clean exact Git commit' >&2
    exit 2
  fi
  source_commit="$(git -C "$repository_root" rev-parse --verify 'HEAD^{commit}')"
  work_root="$(mktemp -d)"
  # The measured client deliberately drops to uid/gid 65534.  Permit traversal
  # to its separately owned output directories while keeping the key directory
  # below this root mode 0700.
  chmod 0711 "$work_root"
  cleanup_outer() {
    rm -rf -- "$work_root"
  }
  trap cleanup_outer EXIT
  mkdir -p "$work_root/evidence"
  inner_stdout="$work_root/inner.stdout"
  inner_stderr="$work_root/inner.stderr"
  set +e
  unshare --net --mount-proc -- \
    "$script_path" --inside "$mechanism" "$work_root" "$repository_root" "$source_commit" \
    >"$inner_stdout" 2>"$inner_stderr" &
  namespace_pid=$!
  wait "$namespace_pid"
  inside_exit=$?
  set -e
  if [[ "$(git -C "$repository_root" rev-parse --verify 'HEAD^{commit}')" != "$source_commit" || \
        -n "$(git -C "$repository_root" status --porcelain)" ]]; then
    echo 'network measurement source changed during observation' >&2
    exit 4
  fi
  if [[ -e "/proc/$namespace_pid/ns/net" || -e "/proc/$namespace_pid/ns/mnt" ]]; then
    echo 'measurement namespace handles survived process reap' >&2
    exit 4
  fi
  if [[ $inside_exit -ne 0 ]]; then
    compiler_identity='cc unavailable'
    if command -v cc >/dev/null 2>&1; then
      compiler_identity="$(cc --version | head -n 1)"
    fi
    python3 -m experiments.network_authority.record_network_measurement_failure \
      --output "$output_directory" \
      --source-root "$repository_root" \
      --stdout "$inner_stdout" \
      --stderr "$inner_stderr" \
      --source-commit "$source_commit" \
      --mechanism "$mechanism" \
      --architecture "$(uname -m)" \
      --kernel-release "$(uname -r)" \
      --compiler "$compiler_identity" \
      --python "$(python3 --version)" \
      --exit-status "$inside_exit"
    python3 -m experiments.network_authority.verify_network_measurement \
      "$output_directory"
    cat "$inner_stdout"
    cat "$inner_stderr" >&2
    echo "network measurement inner runner failed: exit=$inside_exit" >&2
    exit "$inside_exit"
  fi
  cat "$inner_stdout"
  cat "$inner_stderr" >&2
  python3 -c \
    'import sys; from pathlib import Path; from experiments.network_authority.record_common import canonical_json,write_new; write_new(Path(sys.argv[1]), canonical_json({"mount_namespace_handle_absent":True,"namespace_process_pid":int(sys.argv[2]),"namespace_process_reaped":True,"network_namespace_handle_absent":True,"schema":"proofbound-runtime-network-measurement-namespace-cleanup/1"}))' \
    "$work_root/evidence/observation/namespace-cleanup.json" "$namespace_pid"
  python3 -m experiments.network_authority.record_network_measurement \
    --output "$output_directory" \
    --source-root "$repository_root" \
    --evidence-root "$work_root/evidence" \
    --source-commit "$source_commit" \
    --mechanism "$mechanism" \
    --architecture "$(uname -m)" \
    --kernel-release "$(uname -r)" \
    --compiler "$(cc --version | head -n 1)" \
    --python "$(python3 --version)"
  python3 -m experiments.network_authority.verify_network_measurement \
    "$output_directory"
  python3 -c \
    'import json,sys; result=json.load(open(sys.argv[1], encoding="utf-8")); raise SystemExit(result["conclusion"] != "network-measurement-complete")' \
    "$output_directory/RESULT.json"
  printf '%s\n' "$output_directory"
  exit 0
fi

mechanism="$2"
work_root="$3"
expected_root="$4"
source_commit="$5"
if [[ "$repository_root" != "$expected_root" || $EUID -ne 0 ]]; then
  echo 'measurement namespace handoff identity mismatch' >&2
  exit 4
fi
case "$mechanism" in
  landlock-port|cgroup-endpoint|explicit-broker|preconnected-channel) ;;
  *) echo 'measurement namespace mechanism changed' >&2; exit 4 ;;
esac
cd "$repository_root"
export PYTHONDONTWRITEBYTECODE=1

for command in cc cmp cp git ip openssl python3 stat; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "measurement prerequisite is unavailable: $command" >&2
    exit 3
  fi
done
ip link set lo up
if [[ "$(stat -f -c %T /sys/fs/cgroup)" != "cgroup2fs" ]]; then
  echo 'network measurement requires cgroup v2 observations' >&2
  exit 3
fi
if [[ "$mechanism" == "cgroup-endpoint" && ! -f /sys/kernel/btf/vmlinux ]]; then
  echo 'endpoint measurement requires kernel BTF' >&2
  exit 3
fi

evidence_root="$work_root/evidence"
artifact_root="$evidence_root/artifacts"
observation_root="$evidence_root/observation"
private_root="$work_root/private"
staged_root="$work_root/staged"
staged_network="$staged_root/experiments/network_authority"
mkdir -p "$artifact_root" "$private_root" "$staged_network"
chmod 0700 "$private_root"
chmod 0755 "$staged_root" "$staged_root/experiments" "$staged_network"

# The request clients run after the mechanism control drops to uid/gid 65534.
# A hosted checkout may live below a root- or runner-private ancestor, so stage
# the exact client closure beneath the deliberately traversable measurement
# root.  Keep the staged tree outside evidence: its original source bytes are
# already published by the recorder, and cmp binds every executed copy to
# those source inputs before any sample begins.
staged_files=(
  __init__.py
  decision_http_fixture.py
  decision_socket_fixture.py
  record_common.py
  routing_transport_case.py
  routing_transport_client.py
)
if [[ "$mechanism" == "explicit-broker" || "$mechanism" == "preconnected-channel" ]]; then
  staged_files+=(explicit_broker.py routing_mediated_client.py)
fi
cp -- experiments/__init__.py "$staged_root/experiments/__init__.py"
chmod 0644 "$staged_root/experiments/__init__.py"
cmp --silent experiments/__init__.py "$staged_root/experiments/__init__.py"
for name in "${staged_files[@]}"; do
  cp -- "experiments/network_authority/$name" "$staged_network/$name"
  chmod 0644 "$staged_network/$name"
  cmp --silent "experiments/network_authority/$name" "$staged_network/$name"
done
staged_client="$staged_network/routing_transport_client.py"
if [[ "$mechanism" == "explicit-broker" || "$mechanism" == "preconnected-channel" ]]; then
  staged_client="$staged_network/routing_mediated_client.py"
fi

compile_control() {
  local source="$1"
  local output="$2"
  cc -std=c11 -Wall -Wextra -Werror -O2 "$source" -o "$output"
}

selected_control=''
selected_child=''
case "$mechanism" in
  landlock-port)
    compile_control experiments/network_authority/routing_landlock_control.c \
      "$artifact_root/routing-landlock-control"
    compile_control experiments/network_authority/routing_child_control.c \
      "$artifact_root/routing-child-control"
    selected_control="$artifact_root/routing-landlock-control"
    selected_child="$artifact_root/routing-child-control"
    ;;
  cgroup-endpoint)
    compile_control experiments/network_authority/routing_endpoint_control.c \
      "$artifact_root/routing-endpoint-control"
    compile_control experiments/network_authority/routing_child_control.c \
      "$artifact_root/routing-child-control"
    selected_control="$artifact_root/routing-endpoint-control"
    selected_child="$artifact_root/routing-child-control"
    ;;
  explicit-broker)
    compile_control experiments/network_authority/broker_child_control.c \
      "$artifact_root/broker-child-control"
    selected_control="$artifact_root/broker-child-control"
    selected_child="$artifact_root/broker-child-control"
    ;;
  preconnected-channel)
    compile_control experiments/network_authority/preconnected_child_control.c \
      "$artifact_root/preconnected-child-control"
    selected_control="$artifact_root/preconnected-child-control"
    selected_child="$artifact_root/preconnected-child-control"
    ;;
esac

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj '/CN=allowed.test' \
  -addext 'subjectAltName=DNS:allowed.test' \
  -keyout "$private_root/allowed-key.pem" \
  -out "$artifact_root/certificate" \
  >"$private_root/certificate.stdout" \
  2>"$private_root/certificate.stderr"
chmod 0600 "$private_root/allowed-key.pem"
chmod 0644 "$artifact_root/certificate"
cp -- "$artifact_root/certificate" "$artifact_root/trust-root"

cgroup_parent=''
if [[ "$mechanism" == "cgroup-endpoint" ]]; then
  current_cgroup="$(awk -F: '$1 == "0" && $2 == "" { print $3 }' /proc/self/cgroup)"
  if [[ "$current_cgroup" != /* || "$current_cgroup" == *'..'* ]]; then
    echo 'measurement cgroup identity is invalid' >&2
    exit 4
  fi
  cgroup_parent="/sys/fs/cgroup$current_cgroup"
fi

runner=(
  python3 -m experiments.network_authority.run_network_measurement
  --mechanism "$mechanism"
  --source-root "$repository_root"
  --domain "$repository_root/experiments/network_authority/measurement-domain.toml"
  --matrix "$repository_root/experiments/network_authority/decision-matrix.toml"
  --observation-root "$observation_root"
  --landlock-control "$selected_control"
  --endpoint-control "$selected_control"
  --routing-child-control "$selected_child"
  --broker-child-control "$selected_child"
  --preconnected-child-control "$selected_child"
  --client "$staged_client"
  --allowed-certificate "$artifact_root/certificate"
  --allowed-private-key "$private_root/allowed-key.pem"
  --denied-certificate "$artifact_root/certificate"
  --denied-private-key "$private_root/allowed-key.pem"
  --source-commit "$source_commit"
)
if [[ -n "$cgroup_parent" ]]; then
  runner+=(--cgroup-parent "$cgroup_parent")
fi
"${runner[@]}"
