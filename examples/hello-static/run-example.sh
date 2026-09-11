#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: run-example.sh <runtime-bin-directory> <cgroup-root> <new-work-directory>" >&2
  exit 2
fi
if [[ "$(uname -s)" != "Linux" ]]; then
  echo "the execution example requires a supported native Linux host" >&2
  exit 3
fi

bundle_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
runtime_directory="$(cd "$1" && pwd)"
cgroup_root="$2"
work_directory="$3"
if [[ "$work_directory" != /* ]]; then
  echo "the work directory must be an absolute path" >&2
  exit 2
fi
if [[ -e "$work_directory" ]]; then
  echo "the work directory must not already exist: $work_directory" >&2
  exit 2
fi
for binary in pbr pbr-native-launcher pbr-verify; do
  if [[ ! -x "$runtime_directory/$binary" ]]; then
    echo "missing executable runtime member: $runtime_directory/$binary" >&2
    exit 2
  fi
done
for command in cc file python3; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "missing example prerequisite: $command" >&2
    exit 2
  fi
done

mkdir -m 0700 "$work_directory"
executable="$work_directory/hello-static"
plan="$work_directory/plan.cbor"
receipt="$work_directory/receipt.cbor"
run_result="$work_directory/run-result.json"
verification="$work_directory/verification.json"
doctor="$work_directory/doctor.json"

cc -O2 -static -Wall -Wextra -Werror "$bundle_root/hello.c" -o "$executable"
if file "$executable" | grep -q 'dynamically linked'; then
  echo "the example compiler did not produce a static executable" >&2
  exit 2
fi
python3 "$bundle_root/encode-plan-v2.py" \
  --output "$plan" \
  --id example.hello-static \
  --executable "$executable" \
  --working-directory . \
  --write output \
  --execute "$executable" \
  --processes 1 \
  --wall-time-ms 5000 \
  --stdout-bytes 4096 \
  --stderr-bytes 4096 \
  --memory-bytes 268435456 \
  --swap-bytes 0

"$runtime_directory/pbr" doctor --cgroup-root "$cgroup_root" >"$doctor"
"$runtime_directory/pbr" plan check --plan "$plan" >/dev/null
"$runtime_directory/pbr" run \
  --plan "$plan" \
  --receipt "$receipt" \
  --cgroup-root "$cgroup_root" >"$run_result"
commitment="$(python3 -c '
import json
import sys
with open(sys.argv[1], encoding="utf-8") as source:
    result = json.load(source)
assert result["schema"] == "proofbound-runtime-run-result/2"
assert result["outcome"] == {"kind": "exited", "code": 0}
assert result["commitment"].startswith("hex:")
print("sha256:" + result["commitment"].removeprefix("hex:"))
' "$run_result")"
"$runtime_directory/pbr-verify" \
  --expected-commitment "$commitment" \
  "$receipt" >"$verification"
python3 -c '
import json
import sys
with open(sys.argv[1], encoding="utf-8") as source:
    report = json.load(source)
assert report["valid"] is True
assert report["eligibility"] == {"status": "reusable", "reasons": []}
' "$verification"
test "$(<"$work_directory/output/hello.txt")" = \
  'hello from a bounded Proofbound Runtime execution'

python3 -c '
import json
import sys
print(json.dumps({
    "commitment": sys.argv[1],
    "output": sys.argv[2],
    "receipt": sys.argv[3],
    "schema": "proofbound-runtime-example-result/1",
    "verification": sys.argv[4],
}, sort_keys=True, separators=(",", ":")))
' "$commitment" "$work_directory/output/hello.txt" "$receipt" "$verification"
