#!/usr/bin/env bash
set -euo pipefail

test "$(uname -s)" = Linux
test "$(id -u)" -ne 0
test "${PROOFBOUND_NATIVE_INNER:-}" = 1
: "${PROOFBOUND_CGROUP_ROOT:?}"
: "${PROOFBOUND_RUNTIME_BIN_DIR:?}"
: "${PROOFBOUND_NATIVE_FIXTURE:?}"
: "${PROOFBOUND_EGRESS_FIXTURE:?}"

root="$(mktemp -d "$PWD/target/native-egress.XXXXXX")"
server_pid=""
unix_path="/tmp/pbr-egress-host-$$.sock"
cleanup() {
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -f -- "$unix_path"
  rm -rf -- "$root"
}
trap cleanup EXIT
printf 'nameserver 127.0.0.1\n' >"$root/resolver.conf"
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
host_ipv6="$(python3 - <<'PY'
import ipaddress
import subprocess

lines = subprocess.check_output(["ip", "-6", "-o", "addr", "show", "up"], text=True)
ula = ipaddress.IPv6Network("fc00::/7")
for line in lines.splitlines():
    fields = line.split()
    if "inet6" not in fields or any(flag in fields for flag in ("temporary", "tentative", "dadfailed")):
        continue
    address = ipaddress.ip_interface(fields[fields.index("inet6") + 1]).ip
    if address in ula or address.is_global:
        print(address)
        break
else:
    raise SystemExit("no admissible local IPv6 fixture address; native named-IPv6 case is required")
PY
)"
python3 - "$root/network.json" "$PROOFBOUND_RUNTIME_BIN_DIR/pbr-egress-proxy" \
  "$root/resolver.conf" "$root/scope-cases.json" "$host_ipv6" <<'PY'
import ipaddress
import json
import sys

path, proxy, configuration, scope_path, host_ipv6 = sys.argv[1:]
network = {
    "mode": "declared-egress",
    "endpoints": [{
        "destination": {"kind": "ipv4", "bytes": [127, 0, 0, 1]},
        "port": 48123,
        "protocol": "tcp",
        "tls_sni": "not-inspected",
    }, {
        "destination": {"kind": "ipv6", "bytes": [0] * 15 + [1]},
        "port": 48124,
        "protocol": "tcp",
        "tls_sni": "not-inspected",
    }, {
        "destination": {"kind": "dns-name", "name": "echo.fixture.test", "address_scope": "global-or-private"},
        "port": 48125,
        "protocol": "tcp",
        "tls_sni": "not-inspected",
    }, {
        "destination": {"kind": "dns-name", "name": "echo6.fixture.test", "address_scope": "global-or-private"},
        "port": 48127,
        "protocol": "tcp",
        "tls_sni": "not-inspected",
    }, {
        "destination": {"kind": "dns-name", "name": "secure.fixture.test", "address_scope": "global-or-private"},
        "port": 48126,
        "protocol": "tcp",
        "tls_sni": {"mode": "required", "name": "secure.fixture.test"},
    }, {
        "destination": {"kind": "dns-name", "name": "private-denied.fixture.test", "address_scope": "global"},
        "port": 48125,
        "protocol": "tcp",
        "tls_sni": "not-inspected",
    }, {
        "destination": {"kind": "dns-name", "name": "loopback-denied.fixture.test", "address_scope": "global-or-private"},
        "port": 48123,
        "protocol": "tcp",
        "tls_sni": "not-inspected",
    }, {
        "destination": {"kind": "dns-name", "name": "alias.fixture.test", "address_scope": "global-or-private"},
        "port": 48125,
        "protocol": "tcp",
        "tls_sni": "not-inspected",
    }, {
        "destination": {"kind": "dns-name", "name": "zero-ttl.fixture.test", "address_scope": "global-or-private"},
        "port": 48125,
        "protocol": "tcp",
        "tls_sni": "not-inspected",
    }, {
        "destination": {"kind": "dns-name", "name": "flip.fixture.test", "address_scope": "global-or-private"},
        "port": 48125,
        "protocol": "tcp",
        "tls_sni": "not-inspected",
    }, {
        "destination": {"kind": "dns-name", "name": "malformed.fixture.test", "address_scope": "global-or-private"},
        "port": 48125,
        "protocol": "tcp",
        "tls_sni": "not-inspected",
    }, {
        "destination": {"kind": "dns-name", "name": "truncated.fixture.test", "address_scope": "global-or-private"},
        "port": 48125,
        "protocol": "tcp",
        "tls_sni": "not-inspected",
    }, {
        "destination": {"kind": "dns-name", "name": "excess.fixture.test", "address_scope": "global-or-private"},
        "port": 48125,
        "protocol": "tcp",
        "tls_sni": "not-inspected",
    }],
    "resolver": {
        "address": {"family": "ipv4", "bytes": [127, 0, 0, 1]},
        "port": 5353,
        "configuration": configuration,
        "maximum_cname_depth": 4,
        "maximum_answer_count": 16,
        "maximum_response_bytes": 65535,
        "resolution_deadline_ms": 1000,
        "attempt_deadline_ms": 500,
        "address_order": "ipv4-then-ipv6-lexicographic",
    },
    "limits": {
        "connections": 10,
        "concurrent_connections": 8,
        "attempts_per_connection": 2,
        "resolutions": 10,
        "dns_messages": 20,
        "client_to_remote_bytes": 100000,
        "remote_to_client_bytes": 100000,
        "connection_idle_ms": 1000,
    },
    "proxy_executable": proxy,
    "proxy_runtime_read": [],
    "proxy_environment": ["HTTPS_PROXY"],
}
classes = [
    ("s01", "0.0.0.1", "special"),
    ("s02", "127.0.0.1", "special"),
    ("s03", "169.254.1.1", "special"),
    ("s04", "192.0.0.1", "special"),
    ("s05", "192.0.2.1", "special"),
    ("s06", "198.18.0.1", "special"),
    ("s07", "198.51.100.1", "special"),
    ("s08", "203.0.113.1", "special"),
    ("s09", "224.0.0.1", "special"),
    ("s10", "240.0.0.1", "special"),
    ("s11", "::", "special"),
    ("s12", "::1", "special"),
    ("s13", "::ffff:127.0.0.1", "special"),
    ("s14", "64:ff9b::1", "special"),
    ("s15", "100::1", "special"),
    ("s16", "2001::1", "special"),
    ("s17", "2001:db8::1", "special"),
    ("s18", "fe80::1", "special"),
    ("s19", "ff02::1", "special"),
    ("p01", "10.0.0.1", "private"),
    ("p02", "100.64.0.1", "private"),
    ("p03", "172.16.0.1", "private"),
    ("p04", "192.168.0.1", "private"),
    ("p05", "fc00::1", "private"),
]
scope_cases = []
for identifier, address, address_class in classes:
    ipaddress.ip_address(address)
    for scope in ("global", "global-or-private"):
        name = f"{identifier}-{scope}.fixture.test"
        case = f"proxy-scope-{identifier}-{scope}"
        expected = "answered" if address_class == "private" and scope == "global-or-private" else "no-admissible-answer"
        scope_cases.append({"case": case, "name": name, "address": address,
                            "scope": scope, "expected_outcome": expected})
        network["endpoints"].append({
            "destination": {"kind": "dns-name", "name": name, "address_scope": scope},
            "port": 48125, "protocol": "tcp", "tls_sni": "not-inspected",
        })
with open(path, "w", encoding="utf-8") as destination:
    json.dump(network, destination, sort_keys=True)
with open(scope_path, "w", encoding="utf-8") as destination:
    json.dump(scope_cases, destination, sort_keys=True)
PY
python3 tools/ci/encode_plan_v3.py \
  --output "$root/plan.cbor" \
  --network-file "$root/network.json" \
  --id ci.native-egress-positive \
  --executable "$PROOFBOUND_NATIVE_FIXTURE" \
  --argument positive \
  --working-directory . \
  --write egress-output \
  --execute "$PROOFBOUND_NATIVE_FIXTURE" \
  --processes 8 \
  --wall-time-ms 10000 \
  --stdout-bytes 4096 \
  --stderr-bytes 4096 \
  --memory-bytes 268435456 \
  --swap-bytes 0
"$PROOFBOUND_RUNTIME_BIN_DIR/pbr" run \
  --plan "$root/plan.cbor" \
  --receipt "$root/receipt.cbor" \
  --cgroup-root "$PROOFBOUND_CGROUP_ROOT" >"$root/result.json"
commitment="$(python3 - "$root/result.json" <<'PY'
import json
import sys
result = json.load(open(sys.argv[1], encoding="utf-8"))
assert result["schema"] == "proofbound-runtime-run-result/3", result
assert result["outcome"] == {"kind": "exited", "code": 0}, result
print("sha256:" + result["commitment"].removeprefix("hex:"))
PY
)"
"$PROOFBOUND_RUNTIME_BIN_DIR/pbr-verify" \
  --expected-commitment "$commitment" \
  "$root/receipt.cbor" >"$root/verification.json"
python3 - "$root/verification.json" <<'PY'
import json
import sys
verification = json.load(open(sys.argv[1], encoding="utf-8"))
assert verification["valid"] is True, verification
assert verification["eligibility"] == {"status": "reusable", "reasons": []}, verification
PY

cat >"$root/echo.py" <<'PY'
import ipaddress
import json
import pathlib
import selectors
import socket
import struct
import sys

ready = pathlib.Path(sys.argv[1])
unix_path = sys.argv[2]
host_address = sys.argv[3]
host_ipv6 = sys.argv[5]
listeners = []
selector = selectors.DefaultSelector()
for family, address in (
    (socket.AF_INET, ("127.0.0.1", 48123)),
    (socket.AF_INET6, ("::1", 48124)),
    (socket.AF_INET, (host_address, 48125)),
    (socket.AF_INET, (host_address, 48126)),
    (socket.AF_INET6, (host_ipv6, 48127)),
    (socket.AF_UNIX, unix_path),
    (socket.AF_UNIX, "\0pbr-egress-host"),
):
    server = socket.socket(family, socket.SOCK_STREAM)
    if family == socket.AF_INET:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(address)
    server.listen(16)
    selector.register(server, selectors.EVENT_READ, "listener")
    listeners.append(server)
dns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
dns.bind(("127.0.0.1", 5353))
selector.register(dns, selectors.EVENT_READ, "dns-udp")
dns_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
dns_tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
dns_tcp.bind(("127.0.0.1", 5353))
dns_tcp.listen(16)
selector.register(dns_tcp, selectors.EVENT_READ, "dns-tcp")
answer_address = ipaddress.IPv4Address(host_address).packed
echo_name = b"\x04echo\x07fixture\x04test\x00"
echo6_name = b"\x05echo6\x07fixture\x04test\x00"
alias_name = b"\x05alias\x07fixture\x04test\x00"
zero_ttl_name = b"\x08zero-ttl\x07fixture\x04test\x00"
flip_name = b"\x04flip\x07fixture\x04test\x00"
malformed_name = b"\x09malformed\x07fixture\x04test\x00"
truncated_name = b"\x09truncated\x07fixture\x04test\x00"
excess_name = b"\x06excess\x07fixture\x04test\x00"
dns_answers = {
    echo_name: answer_address,
    echo6_name: ipaddress.IPv6Address(host_ipv6).packed,
    b"\x06secure\x07fixture\x04test\x00": answer_address,
    b"\x0eprivate-denied\x07fixture\x04test\x00": answer_address,
    b"\x0floopback-denied\x07fixture\x04test\x00": ipaddress.IPv4Address("127.0.0.1").packed,
    alias_name: answer_address,
    zero_ttl_name: answer_address,
    flip_name: answer_address,
    malformed_name: answer_address,
    truncated_name: answer_address,
    excess_name: answer_address,
}
def wire_name(value):
    return b"".join(bytes([len(label)]) + label.encode("ascii") for label in value.split(".")) + b"\x00"

scope_answers = {
    wire_name(item["name"]): ipaddress.ip_address(item["address"])
    for item in json.load(open(sys.argv[4], encoding="utf-8"))
}
flip_answers = 0
def answer_dns(query):
    global flip_answers
    if query[4:6] != b"\x00\x01":
        return None
    dns_name = next((name for name in (*dns_answers, *scope_answers)
                     if query[12:12 + len(name)] == name), None)
    if dns_name is None or len(query) < 12 + len(dns_name) + 4:
        return None
    offset = 12 + len(dns_name)
    kind, query_class = struct.unpack("!HH", query[offset:offset + 4])
    if query_class != 1 or kind not in (1, 28):
        return None
    if dns_name in scope_answers:
        address = scope_answers[dns_name]
        answer_count = int((kind == 1 and address.version == 4) or
                           (kind == 28 and address.version == 6))
        response = query[:2] + b"\x81\x80\x00\x01" + struct.pack("!H", answer_count) + b"\x00" * 4
        response += query[12:offset + 4]
        if answer_count:
            response += b"\xc0\x0c" + struct.pack("!HHIH", kind, 1, 0, len(address.packed))
            response += address.packed
        return response
    if dns_name == echo6_name:
        answer_count = int(kind == 28)
        response = query[:2] + b"\x81\x80\x00\x01" + struct.pack("!H", answer_count) + b"\x00" * 4
        response += query[12:offset + 4]
        if answer_count:
            response += b"\xc0\x0c" + struct.pack("!HHIH", 28, 1, 60, 16)
            response += dns_answers[dns_name]
        return response
    answer_count = 1 if kind == 1 or dns_name == alias_name else 0
    if dns_name == excess_name and kind == 1:
        answer_count = 17
    response = query[:2] + b"\x81\x80\x00\x01" + struct.pack("!H", answer_count) + b"\x00" * 4
    response += query[12:offset + 4]
    if dns_name == alias_name:
        response += b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 60, len(echo_name)) + echo_name
    elif dns_name == truncated_name and kind == 1:
        return response
    elif answer_count:
        ttl = 0 if dns_name == zero_ttl_name else 1 if dns_name == flip_name else 60
        address = dns_answers[dns_name]
        if dns_name == flip_name:
            flip_answers += 1
            if flip_answers > 1:
                address = ipaddress.IPv4Address("127.0.0.1").packed
        record = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, ttl, 4) + address
        response += record * answer_count
    if dns_name == malformed_name:
        response = bytes([response[0] ^ 1]) + response[1:]
    return response

def read_exact(client, size):
    result = bytearray()
    while len(result) < size:
        part = client.recv(size - len(result))
        if not part:
            raise EOFError("truncated DNS over TCP request")
        result.extend(part)
    return bytes(result)

ready.touch()
while True:
    for key, _ in selector.select():
        if key.data == "dns-udp":
            query, peer = dns.recvfrom(4096)
            response = answer_dns(query)
            if response is not None:
                dns.sendto(response, peer)
            continue
        if key.data == "dns-tcp":
            client, _ = dns_tcp.accept()
            with client:
                client.settimeout(2)
                try:
                    length = struct.unpack("!H", read_exact(client, 2))[0]
                    response = answer_dns(read_exact(client, length)) if 0 < length <= 4096 else None
                except (EOFError, TimeoutError):
                    response = None
                if response is not None:
                    client.sendall(struct.pack("!H", len(response)) + response)
            continue
        client, _ = key.fileobj.accept()
        with client:
            if key.fileobj.family in (socket.AF_INET, socket.AF_INET6):
                while data := client.recv(4096):
                    client.sendall(data)
PY
python3 "$root/echo.py" "$root/server-ready" "$unix_path" "$host_address" \
  "$root/scope-cases.json" "$host_ipv6" &
server_pid=$!
for _ in {1..100}; do
  if [[ -f "$root/server-ready" ]]; then break; fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    echo "egress fixture server stopped during startup" >&2
    exit 1
  fi
  sleep 0.01
done
test -f "$root/server-ready"
cp "$PROOFBOUND_EGRESS_FIXTURE" "$root/second-executable"
chmod 0555 "$root/second-executable"

run_case() {
  local case_name="$1"
  local expected_reusable="$2"
  local output="output-$case_name"
  local extra_argument=()
  local extra_executable=()
  local network_file="$root/network.json"
  local processes=8
  if [[ $# -eq 3 ]]; then extra_argument=(--argument "$3"); fi
  if [[ "$case_name" == proxy-concurrent ]]; then processes=16; fi
  if [[ "$case_name" == proxy-plugin ]]; then
    extra_executable=(--execute "$root/second-executable")
  fi
  if [[ "$case_name" == limit-* || "$case_name" == proxy-idle-timeout ||
        "$case_name" == proxy-dns-oversized ]]; then
    network_file="$root/$case_name-network.json"
    python3 - "$root/network.json" "$network_file" "$case_name" <<'PY'
import json
import sys

source, output, case = sys.argv[1:]
network = json.load(open(source, encoding="utf-8"))
limits = network["limits"]
if case == "limit-connections":
    limits["connections"] = 1
    limits["concurrent_connections"] = 1
elif case == "limit-concurrent":
    limits["concurrent_connections"] = 1
elif case == "limit-resolutions":
    limits["resolutions"] = 1
elif case == "limit-dns-messages":
    limits["dns_messages"] = 2
elif case == "limit-client-bytes":
    limits["client_to_remote_bytes"] = 1
elif case == "limit-remote-bytes":
    limits["remote_to_client_bytes"] = 1
elif case == "proxy-idle-timeout":
    limits["connection_idle_ms"] = 100
elif case == "proxy-dns-oversized":
    network["resolver"]["maximum_response_bytes"] = 32
else:
    raise SystemExit("unknown limit case")
with open(output, "w", encoding="utf-8") as destination:
    json.dump(network, destination, sort_keys=True)
PY
  fi
  python3 tools/ci/encode_plan_v3.py \
    --output "$root/$case_name.cbor" \
    --network-file "$network_file" \
    --id "ci.native-egress-$case_name" \
    --executable "$PROOFBOUND_EGRESS_FIXTURE" \
    --argument "$case_name" \
    "${extra_argument[@]}" \
    --working-directory . \
    --write "$output" \
    --execute "$PROOFBOUND_EGRESS_FIXTURE" \
    "${extra_executable[@]}" \
    --processes "$processes" \
    --wall-time-ms 10000 \
    --stdout-bytes 4096 \
    --stderr-bytes 4096 \
    --memory-bytes 268435456 \
    --swap-bytes 0
  if [[ "$case_name" == inherited-host-socket ]]; then
    python3 - "$PROOFBOUND_RUNTIME_BIN_DIR/pbr" "$root/$case_name.cbor" \
      "$root/$case_name-receipt.cbor" "$PROOFBOUND_CGROUP_ROOT" <<'PY' >"$root/$case_name-result.json"
import socket
import subprocess
import sys

binary, plan, receipt, cgroup = sys.argv[1:]
with socket.create_connection(("127.0.0.1", 48123), timeout=2) as inherited:
    result = subprocess.run(
        [binary, "run", "--plan", plan, "--receipt", receipt, "--cgroup-root", cgroup],
        pass_fds=(inherited.fileno(),), capture_output=True, check=False,
    )
sys.stdout.buffer.write(result.stdout)
sys.stderr.buffer.write(result.stderr)
raise SystemExit(result.returncode)
PY
  else
    "$PROOFBOUND_RUNTIME_BIN_DIR/pbr" run \
      --plan "$root/$case_name.cbor" \
      --receipt "$root/$case_name-receipt.cbor" \
      --cgroup-root "$PROOFBOUND_CGROUP_ROOT" >"$root/$case_name-result.json"
  fi
  local case_commitment
  case_commitment="$(python3 - "$root/$case_name-result.json" <<'PY'
import json
import sys
result = json.load(open(sys.argv[1], encoding="utf-8"))
assert result["schema"] == "proofbound-runtime-run-result/3", result
assert result["outcome"] == {"kind": "exited", "code": 0}, result
print("sha256:" + result["commitment"].removeprefix("hex:"))
PY
)"
  "$PROOFBOUND_RUNTIME_BIN_DIR/pbr-verify" \
    --expected-commitment "$case_commitment" \
    "$root/$case_name-receipt.cbor" >"$root/$case_name-verification.json"
  python3 - "$root/$case_name-verification.json" "$expected_reusable" <<'PY'
import json
import sys
verification = json.load(open(sys.argv[1], encoding="utf-8"))
assert verification["valid"] is True, verification
expected = sys.argv[2] == "yes"
assert (verification["eligibility"]["status"] == "reusable") == expected, verification
PY
  "$PROOFBOUND_RUNTIME_BIN_DIR/pbr" inspect "$root/$case_name-receipt.cbor" \
    >"$root/$case_name-inspection.json"
  python3 - "$root/$case_name-inspection.json" "$case_name" "$root/scope-cases.json" <<'PY'
import json
import sys

receipt = json.load(open(sys.argv[1], encoding="utf-8"))
case = sys.argv[2]
observation = receipt["network"]["observation"]
connections = observation["connections"]
request_rejections = {
    "proxy-absolute-form": "method-not-connect",
    "proxy-malformed-version": "request-malformed",
    "proxy-oversized-head": "request-head-too-large",
    "proxy-noncanonical-port": "target-noncanonical",
    "proxy-noncanonical-ipv4": "target-noncanonical",
    "proxy-undeclared-name": "endpoint-undeclared",
    "proxy-undeclared-port": "endpoint-undeclared",
    "proxy-undeclared-address": "endpoint-undeclared",
    "proxy-literal-of-name": "endpoint-undeclared",
}
if case in request_rejections:
    expected_reason = request_rejections[case]
    assert connections == [], observation
    assert len(observation["rejections"]) == 1, observation
    assert observation["rejections"][0]["reason"] == expected_reason, observation
    assert observation["counters"]["rejection_reason_counts"][expected_reason] == 1, observation
    assert observation["counters"]["rejections"] == 1, observation
if case == "proxy-undeclared-name":
    assert "unknown.fixture.test" not in json.dumps(receipt), receipt
if case in ("proxy-private-scope-denied", "proxy-loopback-rebinding-denied"):
    assert len(connections) == 1, observation
    assert connections[0]["close_reason"] == "no-admissible-answer", observation
    assert connections[0]["attempts"] == [], observation
    assert connections[0]["selected_attempt"] is None, observation
    resolutions = observation["resolutions"]
    assert len(resolutions) == 1, observation
    assert resolutions[0]["outcome"] == "no-admissible-answer", observation
if case.startswith("proxy-scope-"):
    scope_cases = json.load(open(sys.argv[3], encoding="utf-8"))
    expected = next(item for item in scope_cases if item["case"] == case)
    assert len(connections) == 1 and connections[0]["attempts"] == [], observation
    assert connections[0]["close_reason"] == "no-admissible-answer", observation
    resolutions = observation["resolutions"]
    assert len(resolutions) == 1, observation
    assert resolutions[0]["outcome"] == expected["expected_outcome"], observation
    assert len(resolutions[0]["answers"]) == 1, observation
    assert resolutions[0]["answers"][0]["ttl"] == 0, observation
if case == "proxy-cname-chain":
    assert len(connections) == 1 and connections[0]["selected_attempt"] is not None, observation
    assert len(observation["resolutions"]) == 1, observation
    assert observation["resolutions"][0]["outcome"] == "answered", observation
    assert len(observation["resolutions"][0]["cname_links"]) == 1, observation
if case == "proxy-ttl-zero":
    assert len(connections) == 1 and connections[0]["attempts"] == [], observation
    assert connections[0]["close_reason"] == "no-admissible-answer", observation
    assert observation["resolutions"][0]["answers"][0]["ttl"] == 0, observation
if case == "proxy-dns-change":
    assert len(connections) == 2 and len(observation["resolutions"]) == 2, observation
    assert connections[0]["selected_attempt"] is not None, observation
    assert connections[1]["close_reason"] == "no-admissible-answer", observation
if case in ("proxy-dns-malformed", "proxy-dns-truncated", "proxy-dns-excess",
            "proxy-dns-oversized"):
    assert len(connections) == 1 and connections[0]["attempts"] == [], observation
    assert connections[0]["close_reason"] == "resolution-failed", observation
    assert observation["resolutions"][0]["outcome"] == "failed", observation
if case == "proxy-idle-timeout":
    assert len(connections) == 1, observation
    assert connections[0]["close_reason"] == "idle-timeout", observation
if case == "proxy-concurrent":
    assert len(connections) == 8, observation
    events = sorted((item["open_sequence"], 1) for item in connections)
    events += [(item["close_sequence"], -1) for item in connections]
    live = peak = 0
    for _, change in sorted(events):
        live += change
        peak = max(peak, live)
    assert peak >= 4 and live == 0, observation
if case.startswith("limit-"):
    expected = {
        "limit-connections": "egress-limit-connections",
        "limit-concurrent": "egress-limit-concurrent",
        "limit-resolutions": "egress-limit-resolutions",
        "limit-dns-messages": "egress-limit-dns-messages",
        "limit-client-bytes": "egress-limit-client-bytes",
        "limit-remote-bytes": "egress-limit-remote-bytes",
    }[case]
    assert observation["limit_events"] == [expected], observation
    if case in ("limit-client-bytes", "limit-remote-bytes"):
        counts = observation["counters"]["rejection_reason_counts"]
        assert counts["limit-bytes-exhausted"] >= 1, observation
if case.startswith("proxy-sni-"):
    assert len(connections) == 1, observation
    expected = {
        "proxy-sni-matched": "matched", "proxy-sni-split": "matched",
        "proxy-sni-absent": "denied-absent",
        "proxy-sni-mismatch": "denied-mismatch",
        "proxy-sni-ech": "denied-ech",
        "proxy-sni-malformed": "denied-malformed",
        "proxy-sni-oversized": "denied-too-large",
    }[case]
    assert connections[0]["sni_result"] == expected, observation
    if expected.startswith("denied-"):
        assert connections[0]["attempts"] == [], observation
        assert connections[0]["close_reason"] == "sni-denied", observation
PY
  printf 'native-egress case passed: %s\n' "$case_name"
}

run_case proxy-literal yes
run_case proxy-ipv6 yes
run_case proxy-named yes
run_case proxy-named-ipv6 yes
run_case proxy-http10 yes
run_case proxy-headers yes
run_case proxy-sequential yes
run_case proxy-reconnect yes
run_case proxy-concurrent yes
run_case proxy-descendant yes
run_case proxy-plugin yes "$root/second-executable"
run_case proxy-sni-matched yes
run_case proxy-sni-split yes
run_case proxy-sni-absent no
run_case proxy-sni-mismatch no
run_case proxy-sni-ech no
run_case proxy-sni-malformed no
run_case proxy-sni-oversized no
run_case proxy-undeclared-port no
run_case proxy-undeclared-address no
run_case proxy-undeclared-name no
run_case proxy-literal-of-name no "$host_address"
run_case proxy-noncanonical-ipv4 no
run_case proxy-private-scope-denied yes
run_case proxy-loopback-rebinding-denied yes
run_case proxy-cname-chain yes
run_case proxy-ttl-zero yes
run_case proxy-dns-change yes
run_case proxy-dns-malformed yes
run_case proxy-dns-truncated yes
run_case proxy-dns-excess yes
run_case proxy-dns-oversized yes
run_case proxy-idle-timeout yes
run_case inherited-host-socket yes
run_case limit-connections no
run_case limit-concurrent no
run_case limit-resolutions no
run_case limit-dns-messages no
run_case limit-client-bytes no
run_case limit-remote-bytes no
while IFS=$'\t' read -r scope_case scope_name; do
  run_case "$scope_case" yes "$scope_name"
done < <(python3 - "$root/scope-cases.json" <<'PY'
import json
import sys
for item in json.load(open(sys.argv[1], encoding="utf-8")):
    print(item["case"] + "\t" + item["name"])
PY
)
run_case proxy-absolute-form no
run_case proxy-noncanonical-port no
run_case proxy-malformed-version no
run_case proxy-oversized-head no
run_case direct-ipv4 yes
run_case direct-ipv6 yes
run_case direct-tcp-fast-open yes
run_case udp yes
for case_name in quic-udp icmp-datagram raw packet netlink vsock sctp mptcp \
  unshare setns clone-namespace clone3 ptrace pidfd-getfd io-uring \
  kill-parent pidfd-signal host-unix-abstract descendant-scm-rights; do
  run_case "$case_name" yes
done
run_case host-unix-path yes "$unix_path"
printf '#!/bin/true\n' >"$root/undeclared-interpreter"
chmod 0555 "$root/undeclared-interpreter"
python3 tools/ci/encode_plan_v3.py \
  --output "$root/undeclared-interpreter-plan.cbor" \
  --network-file "$root/network.json" \
  --id ci.native-egress-undeclared-interpreter \
  --executable "$PROOFBOUND_EGRESS_FIXTURE" \
  --argument proxy-fault-hold \
  --working-directory . \
  --write output-undeclared-interpreter \
  --execute "$PROOFBOUND_EGRESS_FIXTURE" \
  --execute "$root/undeclared-interpreter" \
  --processes 8 \
  --wall-time-ms 10000 \
  --stdout-bytes 4096 \
  --stderr-bytes 4096 \
  --memory-bytes 268435456 \
  --swap-bytes 0
if "$PROOFBOUND_RUNTIME_BIN_DIR/pbr" run \
  --plan "$root/undeclared-interpreter-plan.cbor" \
  --receipt "$root/undeclared-interpreter-receipt.cbor" \
  --cgroup-root "$PROOFBOUND_CGROUP_ROOT" \
  >"$root/undeclared-interpreter-result.json" \
  2>"$root/undeclared-interpreter-error.txt"; then
  echo "undeclared script interpreter was accepted" >&2
  exit 1
fi
grep -Fq 'plan.authority.execute.interpreter-not-member' \
  "$root/undeclared-interpreter-error.txt"
test ! -e "$root/undeclared-interpreter-receipt.cbor"
for fault in crash stop; do
  python3 tools/ci/encode_plan_v3.py \
    --output "$root/proxy-$fault-plan.cbor" \
    --network-file "$root/network.json" \
    --id "ci.native-egress-proxy-$fault" \
    --executable "$PROOFBOUND_EGRESS_FIXTURE" \
    --argument proxy-fault-hold \
    --working-directory . \
    --write "output-proxy-$fault" \
    --execute "$PROOFBOUND_EGRESS_FIXTURE" \
    --processes 8 \
    --wall-time-ms 10000 \
    --stdout-bytes 4096 \
    --stderr-bytes 4096 \
    --memory-bytes 268435456 \
    --swap-bytes 0
  python3 tools/ci/native_egress_proxy_faults.py \
    --binary "$PROOFBOUND_RUNTIME_BIN_DIR/pbr" \
    --proxy "$PROOFBOUND_RUNTIME_BIN_DIR/pbr-egress-proxy" \
    --fixture "$PROOFBOUND_EGRESS_FIXTURE" \
    --plan "$root/proxy-$fault-plan.cbor" \
    --receipt "$root/proxy-$fault-receipt.cbor" \
    --cgroup-root "$PROOFBOUND_CGROUP_ROOT" \
    --fault "$fault"
done
python3 tools/ci/native_egress_mutations.py \
  --directory "$root" --verifier "$PROOFBOUND_RUNTIME_BIN_DIR/pbr-verify"
