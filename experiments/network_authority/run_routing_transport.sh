#!/usr/bin/env bash
set -euo pipefail

usage='usage: run_routing_transport.sh <landlock-port|cgroup-endpoint|explicit-broker|preconnected-channel> <new-absolute-result-directory>'

if [[ $# -ne 2 ]]; then
  if [[ $# -ne 5 || "${1:-}" != "--inside" ]]; then
    echo "$usage" >&2
    exit 2
  fi
fi
if [[ "$(uname -s)" != "Linux" ]]; then
  echo 'routing transport experiment requires native Linux' >&2
  exit 3
fi

script_path="$(readlink -f "${BASH_SOURCE[0]}")"
repository_root="$(cd "$(dirname "$script_path")/../.." && pwd)"

if [[ "$1" != "--inside" ]]; then
  mechanism="$1"
  output_directory="$2"
  case "$mechanism" in
    landlock-port|cgroup-endpoint|explicit-broker|preconnected-channel) ;;
    *) echo 'routing transport mechanism is invalid' >&2; exit 2 ;;
  esac
  if [[ "$output_directory" != /* || -e "$output_directory" || -L "$output_directory" ]]; then
    echo 'result directory must be one absent absolute path' >&2
    exit 2
  fi
  if [[ ! -d "$(dirname "$output_directory")" ]]; then
    echo 'result parent directory does not exist' >&2
    exit 2
  fi
  if [[ $EUID -ne 0 ]]; then
    echo 'routing namespace setup requires root; invoke this script through sudo' >&2
    exit 3
  fi
  if [[ -n "$(git -C "$repository_root" status --porcelain)" ]]; then
    echo 'routing experiment requires a clean exact Git commit' >&2
    exit 2
  fi
  source_commit="$(git -C "$repository_root" rev-parse --verify 'HEAD^{commit}')"
  exec unshare --net --mount-proc -- \
    "$script_path" --inside "$mechanism" "$output_directory" "$repository_root" "$source_commit"
fi

mechanism="$2"
output_directory="$3"
expected_root="$4"
source_commit="$5"
if [[ "$repository_root" != "$expected_root" || $EUID -ne 0 ]]; then
  echo 'routing namespace handoff identity mismatch' >&2
  exit 4
fi
case "$mechanism" in
  landlock-port|cgroup-endpoint|explicit-broker|preconnected-channel) ;;
  *) echo 'routing namespace mechanism changed' >&2; exit 4 ;;
esac
cd "$repository_root"

for command in cc chown cmp cp git ip openssl python3 stat; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "routing experiment prerequisite is unavailable: $command" >&2
    exit 3
  fi
done
if [[ "$mechanism" == "cgroup-endpoint" ]]; then
  if [[ "$(stat -f -c %T /sys/fs/cgroup)" != "cgroup2fs" ]]; then
    echo 'routing endpoint experiment requires cgroup v2' >&2
    exit 3
  fi
  if [[ ! -f /sys/kernel/btf/vmlinux || -L /sys/kernel/btf/vmlinux ]]; then
    echo 'routing endpoint experiment requires regular kernel BTF' >&2
    exit 3
  fi
fi

work_root="$(mktemp -d)"
cgroup_directories=()
cleanup() {
  local directory
  for directory in "${cgroup_directories[@]}"; do
    if [[ -d "$directory" ]]; then
      rmdir -- "$directory" >/dev/null 2>&1 || true
    fi
  done
  rm -rf -- "$work_root"
}
trap cleanup EXIT

chmod 0755 "$work_root"
evidence_root="$work_root/evidence"
artifact_root="$evidence_root/artifacts"
case_parent="$evidence_root/cases"
private_root="$work_root/private"
log_root="$work_root/orchestration-logs"
staged_root="$artifact_root/staged"
staged_network="$staged_root/experiments/network_authority"
mkdir -p "$artifact_root" "$case_parent" "$private_root" "$log_root" "$staged_network"
chmod 0755 "$staged_root" "$staged_root/experiments" "$staged_network"
ip link set lo up
ip address add fd00::1/128 dev lo nodad
ip address add fd00::2/128 dev lo nodad

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

case "$mechanism" in
  landlock-port)
    compile_control experiments/network_authority/routing_landlock_control.c "$artifact_root/routing-landlock-control"
    compile_control experiments/network_authority/routing_child_control.c "$artifact_root/routing-child-control"
    ;;
  cgroup-endpoint)
    compile_control experiments/network_authority/routing_endpoint_control.c "$artifact_root/routing-endpoint-control"
    compile_control experiments/network_authority/routing_child_control.c "$artifact_root/routing-child-control"
    ;;
  explicit-broker)
    compile_control experiments/network_authority/broker_child_control.c "$artifact_root/broker-child-control"
    ;;
  preconnected-channel)
    compile_control experiments/network_authority/preconnected_child_control.c "$artifact_root/preconnected-child-control"
    ;;
esac

generate_certificate() {
  local name="$1"
  local stem="$2"
  openssl req \
    -x509 -newkey rsa:2048 -nodes -days 1 \
    -subj "/CN=$name" \
    -addext "subjectAltName=DNS:$name" \
    -keyout "$private_root/$stem-key.pem" \
    -out "$artifact_root/$stem-certificate.pem" \
    >"$private_root/$stem-certificate.stdout" \
    2>"$private_root/$stem-certificate.stderr"
  chmod 0600 "$private_root/$stem-key.pem"
  chmod 0644 "$artifact_root/$stem-certificate.pem"
}

generate_certificate allowed.test allowed
generate_certificate denied.test denied

mapfile -t routing_cases < <(
  python3 -c \
    'from pathlib import Path; from experiments.network_authority.routing_transport_case import load_routing_matrix; matrix=load_routing_matrix(Path("experiments/network_authority/decision-matrix.toml").resolve()); print("\n".join(case.identifier for case in matrix.cases))'
)
if [[ ${#routing_cases[@]} -ne 16 ]]; then
  echo 'routing case inventory is not exact' >&2
  exit 4
fi

current_cgroup=''
cgroup_parent=''
if [[ "$mechanism" == "cgroup-endpoint" ]]; then
  current_cgroup="$(awk -F: '$1 == "0" && $2 == "" { print $3 }' /proc/self/cgroup)"
  if [[ "$current_cgroup" != /* || "$current_cgroup" == *'..'* ]]; then
    echo 'current cgroup identity is invalid' >&2
    exit 4
  fi
  cgroup_parent="/sys/fs/cgroup$current_cgroup"
fi

for case_id in "${routing_cases[@]}"; do
  case_root="$case_parent/$case_id"
  runner_stdout="$log_root/$case_id.stdout"
  runner_stderr="$log_root/$case_id.stderr"
  common_arguments=(
    --case "$case_id"
    --repository-root "$repository_root"
    --matrix "$repository_root/experiments/network_authority/decision-matrix.toml"
    --case-root "$case_root"
    --raw-output "$case_root/raw-cell.json"
    --client "$staged_client"
    --allowed-certificate "$artifact_root/allowed-certificate.pem"
    --allowed-private-key "$private_root/allowed-key.pem"
    --denied-certificate "$artifact_root/denied-certificate.pem"
    --denied-private-key "$private_root/denied-key.pem"
  )
  set +e
  case "$mechanism" in
    landlock-port)
      python3 -m experiments.network_authority.run_routing_direct_case \
        "${common_arguments[@]}" \
        --mechanism landlock-port \
        --mechanism-control "$artifact_root/routing-landlock-control" \
        --child-control "$artifact_root/routing-child-control" \
        >"$runner_stdout" 2>"$runner_stderr"
      case_exit=$?
      ;;
    cgroup-endpoint)
      cgroup_arguments=()
      if [[ "$case_id" != "non-scoped-ipv6-scope-id" && "$case_id" != "alternate-address-text" ]]; then
        cgroup_directory="$cgroup_parent/proofbound-routing-$$-${#cgroup_directories[@]}"
        mkdir "$cgroup_directory"
        cgroup_directories+=("$cgroup_directory")
        cgroup_arguments=(--cgroup-directory "$cgroup_directory")
      fi
      python3 -m experiments.network_authority.run_routing_direct_case \
        "${common_arguments[@]}" \
        --mechanism cgroup-endpoint \
        --mechanism-control "$artifact_root/routing-endpoint-control" \
        --child-control "$artifact_root/routing-child-control" \
        "${cgroup_arguments[@]}" \
        >"$runner_stdout" 2>"$runner_stderr"
      case_exit=$?
      ;;
    explicit-broker)
      python3 -m experiments.network_authority.run_routing_broker_case \
        "${common_arguments[@]}" \
        --child-control "$artifact_root/broker-child-control" \
        >"$runner_stdout" 2>"$runner_stderr"
      case_exit=$?
      ;;
    preconnected-channel)
      python3 -m experiments.network_authority.run_routing_preconnected_case \
        "${common_arguments[@]}" \
        --child-control "$artifact_root/preconnected-child-control" \
        >"$runner_stdout" 2>"$runner_stderr"
      case_exit=$?
      ;;
  esac
  set -e
  mkdir -p "$case_root"
  mv "$runner_stdout" "$case_root/runner.stdout"
  mv "$runner_stderr" "$case_root/runner.stderr"
  printf '%s\n' "$case_exit" >"$case_root/runner.exit"
done

python3 -m experiments.network_authority.record_routing_transport \
  --output "$output_directory" \
  --source-root "$repository_root" \
  --evidence-root "$evidence_root" \
  --source-commit "$source_commit" \
  --mechanism "$mechanism" \
  --architecture "$(uname -m)" \
  --kernel-release "$(uname -r)" \
  --compiler "$(cc --version | head -n 1)" \
  --openssl "$(openssl version)" \
  --python "$(python3 --version)"

python3 -c \
  'import json,sys; result=json.load(open(sys.argv[1], encoding="utf-8")); raise SystemExit(result["conclusion"] != "routing-transport-slice-matched")' \
  "$output_directory/RESULT.json"

printf '%s\n' "$output_directory"
