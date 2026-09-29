#!/usr/bin/env bash
set -euo pipefail

test "$(uname -s)" = Linux
test "${PROOFBOUND_NATIVE_INNER:-}" = 1
: "${PROOFBOUND_TOFU_BIN:?}"
: "${PROOFBOUND_RUNTIME_BIN_DIR:?}"
: "${PROOFBOUND_CGROUP_ROOT:?}"
: "${PROOFBOUND_EVIDENCE_DIRECTORY:?}"
test -x "$PROOFBOUND_TOFU_BIN"

root="$(mktemp -d "$PWD/target/native-opentofu.XXXXXX")"
fixture_pid=""
cleanup() {
  if [[ -n "$fixture_pid" ]]; then
    kill "$fixture_pid" 2>/dev/null || true
    wait "$fixture_pid" 2>/dev/null || true
  fi
  rm -rf -- "$root"
}
trap cleanup EXIT

cp examples/opentofu-egress/main.tf examples/opentofu-egress/.terraform.lock.hcl "$root/"
host_address="$(python3 - <<'PY'
import ipaddress
import subprocess

lines = subprocess.check_output(["ip", "-4", "-o", "addr", "show", "up"], text=True)
for line in lines.splitlines():
    fields = line.split()
    if "inet" not in fields:
        continue
    address = ipaddress.ip_interface(fields[fields.index("inet") + 1]).ip
    if address.is_private and not address.is_loopback and not address.is_link_local:
        print(address)
        break
else:
    raise SystemExit("no private fixture host address")
PY
)"
printf 'nameserver 127.0.0.1\n' >"$root/resolver.conf"
python3 - "$root/fixture-token" <<'PY'
import pathlib
import secrets
import sys
pathlib.Path(sys.argv[1]).write_text(secrets.token_hex(32) + "\n", encoding="ascii")
PY
chmod 600 "$root/fixture-token"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -keyout "$root/fixture-key.pem" -out "$root/fixture-cert.pem" \
  -subj /CN=api.fixture.test \
  -addext subjectAltName=DNS:api.fixture.test >/dev/null 2>&1
python3 tools/ci/opentofu_fixture.py \
  --address "$host_address" --api-port 48443 --dns-port 45353 \
  --cert "$root/fixture-cert.pem" --key "$root/fixture-key.pem" \
  --token-file "$root/fixture-token" --ready "$root/fixture-ready" \
  --events "$root/fixture-events.jsonl" &
fixture_pid=$!
for _ in {1..100}; do
  if [[ -f "$root/fixture-ready" ]]; then break; fi
  if ! kill -0 "$fixture_pid" 2>/dev/null; then
    echo "OpenTofu fixture stopped during startup" >&2
    exit 1
  fi
  sleep 0.02
done
test -f "$root/fixture-ready"

"$PROOFBOUND_TOFU_BIN" -chdir="$root" providers mirror -platform="linux_$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')" "$root/mirror"
cat >"$root/cli.tfrc" <<EOF
provider_installation {
  filesystem_mirror { path = "$root/mirror" }
}
EOF

export TF_CLI_CONFIG_FILE="$root/cli.tfrc"
export TF_IN_AUTOMATION=1
export TF_VAR_fixture_url="https://api.fixture.test:48443"
export TF_VAR_fixture_token="$(cat "$root/fixture-token")"
export CHECKPOINT_DISABLE=1

export TF_DATA_DIR=output-init/.terraform
export TMPDIR=output-init
python3 tools/ci/encode_plan_v2.py \
  --output "$root/init-plan.cbor" --id ci.native-opentofu-init \
  --executable "$PROOFBOUND_TOFU_BIN" \
  --argument init --argument=-backend=false --argument=-input=false \
  --argument=-lockfile=readonly --argument=-no-color \
  --working-directory . --read main.tf --read .terraform.lock.hcl \
  --read cli.tfrc --read mirror --write output-init \
  --execute "$PROOFBOUND_TOFU_BIN" \
  --environment TF_CLI_CONFIG_FILE --environment TF_DATA_DIR \
  --environment TF_IN_AUTOMATION --environment TMPDIR \
  --environment CHECKPOINT_DISABLE \
  --processes 128 --wall-time-ms 120000 --stdout-bytes 65536 \
  --stderr-bytes 65536 --memory-bytes 1073741824 --swap-bytes 0
"$PROOFBOUND_RUNTIME_BIN_DIR/pbr" run --plan "$root/init-plan.cbor" \
  --receipt "$root/init-receipt.cbor" \
  --cgroup-root "$PROOFBOUND_CGROUP_ROOT" >"$root/init-result.json"

mapfile -t provider_binaries < <(find "$root/output-init/.terraform/providers" -type f \
  \( -name 'terraform-provider-http*' -o -name 'terraform-provider-restapi*' \) | sort)
test "${#provider_binaries[@]}" -eq 2
test "$(basename "${provider_binaries[0]}")" != "$(basename "${provider_binaries[1]}")"

python3 - "$root/network.json" "$host_address" "$root/resolver.conf" \
  "$PROOFBOUND_RUNTIME_BIN_DIR/pbr-egress-proxy" <<'PY'
import ipaddress
import json
import sys

path, host, configuration, proxy = sys.argv[1:]
network = {
    "mode": "declared-egress",
    "endpoints": [{
        "destination": {"kind": "dns-name", "name": "api.fixture.test", "address_scope": "global-or-private"},
        "port": 48443, "protocol": "tcp",
        "tls_sni": {"mode": "required", "name": "api.fixture.test"},
    }],
    "resolver": {
        "address": {"family": "ipv4", "bytes": [127, 0, 0, 1]},
        "port": 45353, "configuration": configuration,
        "maximum_cname_depth": 4, "maximum_answer_count": 16,
        "maximum_response_bytes": 65535,
        "resolution_deadline_ms": 5000, "attempt_deadline_ms": 2000,
        "address_order": "ipv4-then-ipv6-lexicographic",
    },
    "limits": {
        "connections": 64, "concurrent_connections": 16,
        "attempts_per_connection": 2, "resolutions": 32,
        "dns_messages": 128, "client_to_remote_bytes": 1048576,
        "remote_to_client_bytes": 1048576, "connection_idle_ms": 30000,
    },
    "proxy_executable": proxy,
    "proxy_runtime_read": [],
    "proxy_environment": ["HTTPS_PROXY", "https_proxy"],
}
if not ipaddress.IPv4Address(host).is_private:
    raise SystemExit("fixture address is outside the declared private scope")
with open(path, "w", encoding="utf-8") as destination:
    json.dump(network, destination, sort_keys=True)
PY

export TF_DATA_DIR=output-init/.terraform
export TMPDIR=output-apply
python3 tools/ci/encode_plan_v3.py \
  --output "$root/apply-plan.cbor" --network-file "$root/network.json" \
  --id ci.native-opentofu-apply \
  --executable "$PROOFBOUND_TOFU_BIN" \
  --argument apply --argument=-auto-approve --argument=-input=false \
  --argument=-no-color --argument=-lock=false \
  --argument=-state=output-apply/state.tfstate \
  --working-directory . --read main.tf --read .terraform.lock.hcl \
  --read cli.tfrc --read output-init \
  --write output-apply --execute "$PROOFBOUND_TOFU_BIN" \
  --execute "${provider_binaries[0]}" --execute "${provider_binaries[1]}" \
  --environment TF_CLI_CONFIG_FILE --environment TF_DATA_DIR \
  --environment TF_IN_AUTOMATION --environment TMPDIR \
  --environment TF_VAR_fixture_url --environment TF_VAR_fixture_token \
  --environment CHECKPOINT_DISABLE \
  --processes 512 --wall-time-ms 120000 --stdout-bytes 65536 \
  --stderr-bytes 65536 --memory-bytes 2147483648 --swap-bytes 0
"$PROOFBOUND_RUNTIME_BIN_DIR/pbr" run --plan "$root/apply-plan.cbor" \
  --receipt "$root/apply-receipt.cbor" \
  --cgroup-root "$PROOFBOUND_CGROUP_ROOT" >"$root/apply-result.json"

for phase in init apply; do
  commitment="$(python3 - "$root/$phase-result.json" "$phase" <<'PY'
import json
import sys
result = json.load(open(sys.argv[1], encoding="utf-8"))
expected_schema = "proofbound-runtime-run-result/3" if sys.argv[2] == "apply" else "proofbound-runtime-run-result/2"
assert result["schema"] == expected_schema, result
assert result["outcome"] == {"kind": "exited", "code": 0}, result
print("sha256:" + result["commitment"].removeprefix("hex:"))
PY
)"
  "$PROOFBOUND_RUNTIME_BIN_DIR/pbr-verify" \
    --expected-commitment "$commitment" \
    "$root/$phase-receipt.cbor" >"$root/$phase-verification.json"
done

"$PROOFBOUND_TOFU_BIN" -chdir="$root" show -json "$root/output-apply/state.tfstate" >"$root/state.json"
python3 - "$root" <<'PY'
import json
from pathlib import Path
import sys

root = Path(sys.argv[1])
for phase in ("init", "apply"):
    result = json.loads((root / f"{phase}-verification.json").read_text())
    assert result["valid"] is True, result
    assert result["eligibility"] == {"status": "reusable", "reasons": []}, result
state = json.loads((root / "state.json").read_text())
outputs = state["values"]["outputs"]
assert json.loads(outputs["health_body"]["value"]) == {"ok": True}, outputs
assert outputs["record_id"]["value"] == "proofbound-fixture", outputs
events = [json.loads(line) for line in (root / "fixture-events.jsonl").read_text().splitlines()]
assert any(event.get("channel") == "dns" and event.get("name") == "api.fixture.test" for event in events), events
assert any(event.get("channel") == "api" and event.get("path") == "/health" for event in events), events
assert any(event.get("channel") == "api" and event.get("method") == "POST" and event.get("path") == "/records" for event in events), events
token = (root / "fixture-token").read_bytes().strip()
retained = [root / f"{phase}-{kind}.{suffix}"
            for phase in ("init", "apply")
            for kind, suffix in (("plan", "cbor"), ("receipt", "cbor"),
                                 ("result", "json"), ("verification", "json"))]
retained.append(root / "fixture-events.jsonl")
assert all(token not in path.read_bytes() for path in retained)
print("OpenTofu init and apply: two exact provider plugins, local API, verified receipts")
PY

evidence="$PROOFBOUND_EVIDENCE_DIRECTORY/opentofu-egress"
mkdir -p "$evidence"
for phase in init apply; do
  cp "$root/$phase-plan.cbor" "$root/$phase-receipt.cbor" \
    "$root/$phase-result.json" "$root/$phase-verification.json" "$evidence/"
done
cp "$root/fixture-events.jsonl" "$evidence/"
python3 - "$evidence/identities.json" "$PROOFBOUND_TOFU_BIN" \
  "${provider_binaries[0]}" "${provider_binaries[1]}" <<'PY'
import hashlib
import json
from pathlib import Path
import platform
import sys

output = Path(sys.argv[1])
identities = []
for name, source in zip(("tofu", "provider-1", "provider-2"), sys.argv[2:]):
    path = Path(source)
    identities.append({"role": name, "filename": path.name,
                       "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
output.write_text(json.dumps({"architecture": platform.machine(),
                              "executables": identities}, sort_keys=True) + "\n")
PY
