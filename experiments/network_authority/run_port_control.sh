#!/usr/bin/env bash
set -euo pipefail

usage='usage: run_port_control.sh <new-absolute-result-directory>'

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

for command in cc curl ip openssl python3 ss; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "network experiment prerequisite is unavailable: $command" >&2
    exit 3
  fi
done

work_root="$(mktemp -d)"
server_pids=()
cleanup() {
  local process
  for process in "${server_pids[@]}"; do
    kill "$process" >/dev/null 2>&1 || true
  done
  wait "${server_pids[@]}" >/dev/null 2>&1 || true
  rm -rf -- "$work_root"
}
trap cleanup EXIT

mkdir -p "$work_root/home" "$work_root/stdout" "$work_root/stderr"
ip link set lo up

cc -std=c11 -Wall -Wextra -Werror -O2 \
  "$repository_root/experiments/network_authority/landlock_port_control.c" \
  -o "$work_root/landlock-port-control"
landlock_abi="$("$work_root/landlock-port-control" --print-abi)"
if [[ ! "$landlock_abi" =~ ^[0-9]+$ || "$landlock_abi" -lt 4 ]]; then
  echo 'Landlock ABI 4 or newer is required' >&2
  exit 3
fi

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

openssl s_server \
  -quiet \
  -www \
  -accept 127.0.0.1:443 \
  -cert "$work_root/allowed-certificate.pem" \
  -key "$work_root/allowed-key.pem" \
  >"$work_root/allowed-server.log" 2>&1 &
server_pids+=("$!")
openssl s_server \
  -quiet \
  -www \
  -accept 127.0.0.2:443 \
  -cert "$work_root/denied-certificate.pem" \
  -key "$work_root/denied-key.pem" \
  >"$work_root/denied-server.log" 2>&1 &
server_pids+=("$!")
openssl s_server \
  -quiet \
  -www \
  -accept 127.0.0.1:8443 \
  -cert "$work_root/allowed-certificate.pem" \
  -key "$work_root/allowed-key.pem" \
  >"$work_root/other-port-server.log" 2>&1 &
server_pids+=("$!")

listeners_ready=false
for _ in $(seq 1 100); do
  listener_count="$(ss -H -ltn | awk '$4 == "127.0.0.1:443" || $4 == "127.0.0.2:443" || $4 == "127.0.0.1:8443" { count += 1 } END { print count + 0 }')"
  if [[ "$listener_count" -eq 3 ]]; then
    listeners_ready=true
    break
  fi
  sleep 0.05
done
if [[ "$listeners_ready" != true ]]; then
  echo 'loopback TLS fixtures did not become ready' >&2
  exit 4
fi

run_curl() {
  local case_id="$1"
  shift
  env -i \
    HOME="$work_root/home" \
    PATH=/usr/bin:/bin \
    "$work_root/landlock-port-control" \
    curl \
    --noproxy '*' \
    --silent \
    --show-error \
    --fail \
    --connect-timeout 3 \
    --max-time 5 \
    "$@" \
    >"$work_root/stdout/$case_id.log" \
    2>"$work_root/stderr/$case_id.log"
}

set +e
run_curl \
  allowed-service \
  --cacert "$work_root/allowed-certificate.pem" \
  --resolve allowed.test:443:127.0.0.1 \
  https://allowed.test/
allowed_service=$?
run_curl \
  same-port-service-substitution \
  --cacert "$work_root/denied-certificate.pem" \
  --resolve denied.test:443:127.0.0.2 \
  https://denied.test/
same_port_service_substitution=$?
run_curl \
  other-port-denied \
  --cacert "$work_root/allowed-certificate.pem" \
  --resolve allowed.test:8443:127.0.0.1 \
  https://allowed.test:8443/
other_port_denied=$?
run_curl \
  wrong-certificate-denied \
  --cacert "$work_root/denied-certificate.pem" \
  --resolve allowed.test:443:127.0.0.2 \
  https://allowed.test/
wrong_certificate_denied=$?
set -e

python3 -m experiments.network_authority.record_port_control \
  --output "$output_directory" \
  --source-root "$repository_root" \
  --work-root "$work_root" \
  --source-commit "$source_commit" \
  --architecture "$(uname -m)" \
  --kernel-release "$(uname -r)" \
  --landlock-abi "$landlock_abi" \
  --compiler "$(cc --version | head -n 1)" \
  --curl "$(curl --version | head -n 1)" \
  --openssl "$(openssl version)" \
  --python "$(python3 --version)" \
  --allowed-service "$allowed_service" \
  --same-port-service-substitution "$same_port_service_substitution" \
  --other-port-denied "$other_port_denied" \
  --wrong-certificate-denied "$wrong_certificate_denied"

python3 -c \
  'import json,sys; result=json.load(open(sys.argv[1], encoding="utf-8")); raise SystemExit(result["conclusion"] != "port-only-landlock-cannot-select-service")' \
  "$output_directory/RESULT.json"

printf '%s\n' "$output_directory"
