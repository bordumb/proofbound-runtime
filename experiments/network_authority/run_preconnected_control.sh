#!/usr/bin/env bash
set -euo pipefail

usage='usage: run_preconnected_control.sh <new-absolute-result-directory>'

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
cleanup() {
  rm -rf -- "$work_root"
}
trap cleanup EXIT

chmod 0755 "$work_root"
mkdir -p \
  "$work_root/home" \
  "$work_root/stdout" \
  "$work_root/stderr" \
  "$work_root/fixture-stdout" \
  "$work_root/fixture-stderr" \
  "$work_root/state" \
  "$work_root/client-package/experiments/network_authority"
chown 65534:65534 "$work_root/home"
ip link set lo up

client_package="$work_root/client-package/experiments/network_authority"
for name in __init__.py preconnected_case_client.py preconnected_channel.py record_common.py; do
  source_file="$repository_root/experiments/network_authority/$name"
  cp -- "$source_file" "$client_package/$name"
  chmod 0644 "$client_package/$name"
  cmp --silent "$source_file" "$client_package/$name"
done

cc -std=c11 -Wall -Wextra -Werror -O2 \
  "$repository_root/experiments/network_authority/preconnected_child_control.c" \
  -o "$work_root/preconnected-child-control"

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

cases=(
  allowed-request
  undeclared-path-exposure
  connect-shape-exposure
  direct-tcp-denied
  direct-udp-denied
  fork-direct-tcp-denied
  alternate-endpoint-denied-certificate
  alternate-endpoint-allowed-certificate
  wrong-certificate-denied
  plaintext-endpoint-denied
  connector-crash-denied
  wrong-cookie-denied
  non-unix-descriptor-denied
  foreign-descriptor-denied
)
declare -A case_exits=()

for case_id in "${cases[@]}"; do
  set +e
  python3 -m experiments.network_authority.run_preconnected_case \
    --case "$case_id" \
    --repository-root "$repository_root" \
    --wrapper "$work_root/preconnected-child-control" \
    --client "$client_package/preconnected_case_client.py" \
    --state-directory "$work_root/state/$case_id" \
    --client-started-file "$work_root/home/$case_id.started" \
    --fixture-stdout "$work_root/fixture-stdout/$case_id.log" \
    --fixture-stderr "$work_root/fixture-stderr/$case_id.log" \
    --allowed-endpoint-ip 127.0.0.1 \
    --alternate-endpoint-ip 127.0.0.2 \
    --endpoint-port 443 \
    --allowed-certificate "$work_root/allowed-certificate.pem" \
    --allowed-private-key "$work_root/allowed-key.pem" \
    --denied-certificate "$work_root/denied-certificate.pem" \
    --denied-private-key "$work_root/denied-key.pem" \
    >"$work_root/stdout/$case_id.log" \
    2>"$work_root/stderr/$case_id.log"
  case_exit=$?
  set -e
  case_exits["$case_id"]="$case_exit"
done

cleanup_observed="$({
  python3 - "$work_root/state" "${cases[@]}" <<'PY'
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
cases = sys.argv[2:]
observed = all(
    json.loads((root / case / "case-observations.json").read_bytes()).get(
        "fixture_reaped"
    )
    is True
    for case in cases
)
print("true" if observed else "false")
PY
} 2>/dev/null || printf 'false\n')"

python3 -m experiments.network_authority.record_preconnected_control \
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
  --undeclared-path-exposure "${case_exits[undeclared-path-exposure]}" \
  --connect-shape-exposure "${case_exits[connect-shape-exposure]}" \
  --direct-tcp-denied "${case_exits[direct-tcp-denied]}" \
  --direct-udp-denied "${case_exits[direct-udp-denied]}" \
  --fork-direct-tcp-denied "${case_exits[fork-direct-tcp-denied]}" \
  --alternate-endpoint-denied-certificate "${case_exits[alternate-endpoint-denied-certificate]}" \
  --alternate-endpoint-allowed-certificate "${case_exits[alternate-endpoint-allowed-certificate]}" \
  --wrong-certificate-denied "${case_exits[wrong-certificate-denied]}" \
  --plaintext-endpoint-denied "${case_exits[plaintext-endpoint-denied]}" \
  --connector-crash-denied "${case_exits[connector-crash-denied]}" \
  --wrong-cookie-denied "${case_exits[wrong-cookie-denied]}" \
  --non-unix-descriptor-denied "${case_exits[non-unix-descriptor-denied]}" \
  --foreign-descriptor-denied "${case_exits[foreign-descriptor-denied]}"

python3 -c \
  'import json,sys; result=json.load(open(sys.argv[1], encoding="utf-8")); raise SystemExit(result["conclusion"] != "preconnected-channel-binds-one-authenticated-session-control")' \
  "$output_directory/RESULT.json"

printf '%s\n' "$output_directory"
