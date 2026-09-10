#!/usr/bin/env bash
set -euo pipefail

usage='usage: run_endpoint_control.sh <new-absolute-result-directory>'

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
    echo 'network and cgroup setup requires root; invoke this script through sudo' >&2
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

for command in awk cc chown curl ip openssl python3 sha256sum ss stat; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "network experiment prerequisite is unavailable: $command" >&2
    exit 3
  fi
done
if [[ "$(stat -f -c %T /sys/fs/cgroup)" != "cgroup2fs" ]]; then
  echo 'endpoint experiment requires a cgroup v2 filesystem' >&2
  exit 3
fi
if [[ ! -f /sys/kernel/btf/vmlinux || -L /sys/kernel/btf/vmlinux ]]; then
  echo 'endpoint experiment requires regular kernel BTF' >&2
  exit 3
fi

work_root="$(mktemp -d)"
server_pids=()
cgroup_directory=''
cleanup() {
  local process
  for process in "${server_pids[@]}"; do
    kill "$process" >/dev/null 2>&1 || true
  done
  wait "${server_pids[@]}" >/dev/null 2>&1 || true
  if [[ -n "$cgroup_directory" && -d "$cgroup_directory" ]]; then
    rmdir -- "$cgroup_directory" >/dev/null 2>&1 || true
  fi
  rm -rf -- "$work_root"
}
trap cleanup EXIT

chmod 0755 "$work_root"
mkdir -p "$work_root/home" "$work_root/stdout" "$work_root/stderr" "$work_root/child"
chown 65534:65534 "$work_root/home" "$work_root/stdout" "$work_root/stderr" "$work_root/child"
ip link set lo up

cc -std=c11 -Wall -Wextra -Werror -O2 \
  "$repository_root/experiments/network_authority/cgroup_endpoint_control.c" \
  -o "$work_root/cgroup-endpoint-control"

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

cat >"$work_root/case-driver.sh" <<'DRIVER'
#!/usr/bin/env bash
set -u

work_root="$1"

run_curl() {
  local case_id="$1"
  shift
  env -i \
    HOME="$work_root/home" \
    PATH=/usr/bin:/bin \
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
  allowed-endpoint \
  --cacert "$work_root/allowed-certificate.pem" \
  --resolve allowed.test:443:127.0.0.1 \
  https://allowed.test/
allowed_endpoint=$?
run_curl \
  same-port-endpoint-substitution \
  --cacert "$work_root/denied-certificate.pem" \
  --resolve denied.test:443:127.0.0.2 \
  https://denied.test/
same_port_endpoint_substitution=$?
run_curl \
  other-port-denied \
  --cacert "$work_root/allowed-certificate.pem" \
  --resolve allowed.test:8443:127.0.0.1 \
  https://allowed.test:8443/
other_port_denied=$?
run_curl \
  wrong-certificate-denied \
  --cacert "$work_root/allowed-certificate.pem" \
  --resolve wrong.test:443:127.0.0.1 \
  https://wrong.test/
wrong_certificate_denied=$?
set -e

printf '%s\n' \
  "allowed_endpoint=$allowed_endpoint" \
  "same_port_endpoint_substitution=$same_port_endpoint_substitution" \
  "other_port_denied=$other_port_denied" \
  "wrong_certificate_denied=$wrong_certificate_denied" \
  >"$work_root/child/case-exits.txt"
DRIVER
chmod 0755 "$work_root/case-driver.sh"

current_cgroup="$(awk -F: '$1 == "0" && $2 == "" { print $3 }' /proc/self/cgroup)"
if [[ "$current_cgroup" != /* || "$current_cgroup" == *'..'* ]]; then
  echo 'current cgroup identity is invalid' >&2
  exit 4
fi
cgroup_parent="/sys/fs/cgroup$current_cgroup"
cgroup_directory="$cgroup_parent/proofbound-network-$$"
if [[ ! -d "$cgroup_parent" || -e "$cgroup_directory" || -L "$cgroup_directory" ]]; then
  echo 'fresh endpoint cgroup cannot be created safely' >&2
  exit 4
fi
mkdir "$cgroup_directory"

"$work_root/cgroup-endpoint-control" \
  "$cgroup_directory" \
  127.0.0.1 \
  443 \
  "$work_root/loader-state" \
  -- \
  "$work_root/case-driver.sh" "$work_root"

for name in connect4-program.bin connect6-program.bin connect4-verifier.log connect6-verifier.log; do
  mv "$work_root/loader-state/$name" "$work_root/$name"
done
boundary_observations="$work_root/loader-state/boundary-observations.txt"

read_observation() {
  local name="$1"
  local value
  value="$(awk -F= -v key="$name" '$1 == key { print $2 }' "$boundary_observations")"
  if [[ ! "$value" =~ ^[1-9][0-9]*$ ]]; then
    echo "invalid endpoint boundary observation: $name" >&2
    exit 4
  fi
  printf '%s' "$value"
}

cgroup_id="$(read_observation cgroup_id)"
connect4_program_id="$(read_observation connect4_program_id)"
connect6_program_id="$(read_observation connect6_program_id)"

read_case_exit() {
  local name="$1"
  local value
  value="$(awk -F= -v key="$name" '$1 == key { print $2 }' "$work_root/child/case-exits.txt")"
  if [[ ! "$value" =~ ^[0-9]+$ || "$value" -gt 255 ]]; then
    echo "invalid endpoint case exit: $name" >&2
    exit 4
  fi
  printf '%s' "$value"
}

allowed_endpoint="$(read_case_exit allowed_endpoint)"
same_port_endpoint_substitution="$(read_case_exit same_port_endpoint_substitution)"
other_port_denied="$(read_case_exit other_port_denied)"
wrong_certificate_denied="$(read_case_exit wrong_certificate_denied)"

cleanup_observed=false
if rmdir -- "$cgroup_directory"; then
  cleanup_observed=true
  cgroup_directory=''
fi

btf_sha256="$(sha256sum /sys/kernel/btf/vmlinux | awk '{ print $1 }')"
btf_size="$(stat -c %s /sys/kernel/btf/vmlinux)"

python3 "$repository_root/experiments/network_authority/record_endpoint_control.py" \
  --output "$output_directory" \
  --source-root "$repository_root" \
  --work-root "$work_root" \
  --source-commit "$source_commit" \
  --architecture "$(uname -m)" \
  --kernel-release "$(uname -r)" \
  --btf-sha256 "$btf_sha256" \
  --btf-size "$btf_size" \
  --compiler "$(cc --version | head -n 1)" \
  --curl "$(curl --version | head -n 1)" \
  --openssl "$(openssl version)" \
  --python "$(python3 --version)" \
  --cgroup-id "$cgroup_id" \
  --connect4-program-id "$connect4_program_id" \
  --connect6-program-id "$connect6_program_id" \
  --cleanup-observed "$cleanup_observed" \
  --allowed-endpoint "$allowed_endpoint" \
  --same-port-endpoint-substitution "$same_port_endpoint_substitution" \
  --other-port-denied "$other_port_denied" \
  --wrong-certificate-denied "$wrong_certificate_denied"

python3 -c \
  'import json,sys; result=json.load(open(sys.argv[1], encoding="utf-8")); raise SystemExit(result["conclusion"] != "endpoint-control-selects-routing-tuple-only")' \
  "$output_directory/RESULT.json"

printf '%s\n' "$output_directory"
