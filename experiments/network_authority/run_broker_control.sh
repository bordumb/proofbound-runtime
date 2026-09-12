#!/usr/bin/env bash
set -euo pipefail

usage='usage: run_broker_control.sh <new-absolute-result-directory>'

if [[ $# -ne 1 ]]; then
  if [[ $# -ne 4 || "${1:-}" != "--inside" ]]; then
    echo "$usage" >&2
    exit 2
  fi
fi
if [[ "$(uname -s)" != "Linux" ]]; then
  echo 'network authority experiment requires native Linux' >&2
  exit 3
fi

script_path="$(readlink -f "${BASH_SOURCE[0]}")"
repository_root="$(cd "$(dirname "$script_path")/../.." && pwd)"

if [[ "$1" != "--inside" ]]; then
  output_directory="$1"
  if [[ "$output_directory" != /* || -e "$output_directory" || -L "$output_directory" ]]; then
    echo 'result directory must be one absent absolute path' >&2
    exit 2
  fi
  if [[ ! -d "$(dirname "$output_directory")" ]]; then
    echo 'result parent directory does not exist' >&2
    exit 2
  fi
  if [[ $EUID -ne 0 ]]; then
    echo 'network namespace setup requires root; invoke this script through sudo' >&2
    exit 3
  fi
  if [[ -n "$(git -C "$repository_root" status --porcelain)" ]]; then
    echo 'network experiment requires a clean exact Git commit' >&2
    exit 2
  fi
  source_commit="$(git -C "$repository_root" rev-parse --verify 'HEAD^{commit}')"
  exec unshare --net --mount-proc -- \
    "$script_path" --inside "$output_directory" "$repository_root" "$source_commit"
fi

output_directory="$2"
expected_root="$3"
source_commit="$4"
if [[ "$repository_root" != "$expected_root" || $EUID -ne 0 ]]; then
  echo 'network namespace handoff identity mismatch' >&2
  exit 4
fi
cd "$repository_root"

for command in cc chown cmp cp ip openssl python3; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "network experiment prerequisite is unavailable: $command" >&2
    exit 3
  fi
done

work_root="$(mktemp -d)"
fixture_pids=()
cleanup() {
  local process
  for process in "${fixture_pids[@]}"; do
    kill "$process" >/dev/null 2>&1 || true
  done
  wait "${fixture_pids[@]}" >/dev/null 2>&1 || true
  rm -rf -- "$work_root"
}
trap cleanup EXIT

chmod 0755 "$work_root"
mkdir -p \
  "$work_root/home" \
  "$work_root/stdout" \
  "$work_root/stderr" \
  "$work_root/broker-stdout" \
  "$work_root/broker-stderr" \
  "$work_root/fixture-stdout" \
  "$work_root/fixture-stderr" \
  "$work_root/state" \
  "$work_root/client-package/experiments/network_authority"
chown 65534:65534 "$work_root/home"
ip link set lo up

client_package="$work_root/client-package/experiments/network_authority"
for name in __init__.py broker_case_client.py explicit_broker.py record_common.py; do
  source_file="$repository_root/experiments/network_authority/$name"
  cp -- "$source_file" "$client_package/$name"
  chmod 0644 "$client_package/$name"
  cmp --silent "$source_file" "$client_package/$name"
done

cc -std=c11 -Wall -Wextra -Werror -O2 \
  "$repository_root/experiments/network_authority/broker_child_control.c" \
  -o "$work_root/broker-child-control"

generate_certificate() {
  local name="$1"
  local stem="$2"
  openssl req \
    -x509 \
    -newkey rsa:2048 \
    -nodes \
    -days 1 \
    -subj "/CN=$name" \
    -addext "subjectAltName=DNS:$name" \
    -keyout "$work_root/$stem-key.pem" \
    -out "$work_root/$stem-certificate.pem" \
    >"$work_root/$stem-certificate.stdout" \
    2>"$work_root/$stem-certificate.stderr"
  chmod 0600 "$work_root/$stem-key.pem"
  chmod 0644 "$work_root/$stem-certificate.pem"
}

generate_certificate allowed.test allowed
generate_certificate denied.test denied

python3 -m experiments.network_authority.explicit_broker fixture \
  --bind-ip 127.0.0.1 \
  --port 443 \
  --certificate "$work_root/allowed-certificate.pem" \
  --private-key "$work_root/allowed-key.pem" \
  --ready-file "$work_root/allowed-fixture.ready" \
  >"$work_root/fixture-stdout/allowed.log" \
  2>"$work_root/fixture-stderr/allowed.log" &
allowed_fixture_pid=$!
fixture_pids+=("$allowed_fixture_pid")
python3 -m experiments.network_authority.explicit_broker fixture \
  --bind-ip 127.0.0.2 \
  --port 443 \
  --certificate "$work_root/denied-certificate.pem" \
  --private-key "$work_root/denied-key.pem" \
  --ready-file "$work_root/denied-fixture.ready" \
  >"$work_root/fixture-stdout/denied.log" \
  2>"$work_root/fixture-stderr/denied.log" &
denied_fixture_pid=$!
fixture_pids+=("$denied_fixture_pid")

fixtures_ready=false
for _ in $(seq 1 100); do
  if [[ -f "$work_root/allowed-fixture.ready" && -f "$work_root/denied-fixture.ready" ]]; then
    fixtures_ready=true
    break
  fi
  sleep 0.05
done
if [[ "$fixtures_ready" != true ]]; then
  echo 'explicit broker TLS fixtures did not become ready' >&2
  exit 4
fi

cases=(
  allowed-request
  target-substitution
  direct-tcp-denied
  direct-udp-denied
  wrong-certificate-denied
  zero-frame-denied
  oversized-frame-denied
  truncated-frame-denied
  duplicate-key-denied
  invalid-utf8-denied
  noncanonical-frame-denied
  fork-direct-tcp-denied
  broker-crash-denied
  foreign-descriptor-denied
)
declare -A case_exits=()

for case_id in "${cases[@]}"; do
  set +e
  python3 -m experiments.network_authority.run_broker_case \
    --case "$case_id" \
    --repository-root "$repository_root" \
    --wrapper "$work_root/broker-child-control" \
    --client "$client_package/broker_case_client.py" \
    --state-directory "$work_root/state/$case_id" \
    --broker-stdout "$work_root/broker-stdout/$case_id.log" \
    --broker-stderr "$work_root/broker-stderr/$case_id.log" \
    --allowed-endpoint-ip 127.0.0.1 \
    --denied-endpoint-ip 127.0.0.2 \
    --endpoint-port 443 \
    --allowed-certificate "$work_root/allowed-certificate.pem" \
    >"$work_root/stdout/$case_id.log" \
    2>"$work_root/stderr/$case_id.log"
  case_exit=$?
  set -e
  case_exits["$case_id"]="$case_exit"
done

set +e
wait "$allowed_fixture_pid"
allowed_fixture_exit=$?
wait "$denied_fixture_pid"
denied_fixture_exit=$?
set -e
fixture_pids=()

cleanup_observed=false
if [[ "$allowed_fixture_exit" -eq 0 && "$denied_fixture_exit" -eq 7 ]]; then
  cleanup_observed=true
fi

python3 -m experiments.network_authority.record_broker_control \
  --output "$output_directory" \
  --source-root "$repository_root" \
  --work-root "$work_root" \
  --source-commit "$source_commit" \
  --architecture "$(uname -m)" \
  --kernel-release "$(uname -r)" \
  --compiler "$(cc --version | head -n 1)" \
  --openssl "$(openssl version)" \
  --python "$(python3 --version)" \
  --cleanup-observed "$cleanup_observed" \
  --allowed-request "${case_exits[allowed-request]}" \
  --target-substitution "${case_exits[target-substitution]}" \
  --direct-tcp-denied "${case_exits[direct-tcp-denied]}" \
  --direct-udp-denied "${case_exits[direct-udp-denied]}" \
  --wrong-certificate-denied "${case_exits[wrong-certificate-denied]}" \
  --zero-frame-denied "${case_exits[zero-frame-denied]}" \
  --oversized-frame-denied "${case_exits[oversized-frame-denied]}" \
  --truncated-frame-denied "${case_exits[truncated-frame-denied]}" \
  --duplicate-key-denied "${case_exits[duplicate-key-denied]}" \
  --invalid-utf8-denied "${case_exits[invalid-utf8-denied]}" \
  --noncanonical-frame-denied "${case_exits[noncanonical-frame-denied]}" \
  --fork-direct-tcp-denied "${case_exits[fork-direct-tcp-denied]}" \
  --broker-crash-denied "${case_exits[broker-crash-denied]}" \
  --foreign-descriptor-denied "${case_exits[foreign-descriptor-denied]}"

python3 -c \
  'import json,sys; result=json.load(open(sys.argv[1], encoding="utf-8")); raise SystemExit(result["conclusion"] != "explicit-broker-binds-fixed-service-control")' \
  "$output_directory/RESULT.json"

printf '%s\n' "$output_directory"
