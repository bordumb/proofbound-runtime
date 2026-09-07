#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: tools/release/proofbound-release.sh <absent-output-directory>" >&2
  exit 2
fi

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
output_directory="${1%/}"
if [[ -z "$output_directory" ]]; then
  echo "release receipt output directory must not be empty" >&2
  exit 2
fi
verification_path="$output_directory.verification.json"

if [[ -e "$output_directory" || -L "$output_directory" ]]; then
  echo "release receipt output already exists: $output_directory" >&2
  exit 2
fi
if [[ -e "$verification_path" || -L "$verification_path" ]]; then
  echo "release verification output already exists: $verification_path" >&2
  exit 2
fi

if [[ -n "${PROOFBOUND_BIN:-}" ]]; then
  proofbound_bin="$PROOFBOUND_BIN"
elif command -v proofbound >/dev/null 2>&1; then
  proofbound_bin="$(command -v proofbound)"
elif [[ -x "$repository_root/../proof-bound/target/debug/proofbound" ]]; then
  proofbound_bin="$repository_root/../proof-bound/target/debug/proofbound"
else
  echo "release receipt failed: set PROOFBOUND_BIN or install proofbound" >&2
  exit 2
fi

if [[ -n "${PROOFBOUND_VERIFY_BIN:-}" ]]; then
  proofbound_verify_bin="$PROOFBOUND_VERIFY_BIN"
elif command -v proofbound-verify >/dev/null 2>&1; then
  proofbound_verify_bin="$(command -v proofbound-verify)"
elif [[ -x "$repository_root/../proof-bound/target/debug/proofbound-verify" ]]; then
  proofbound_verify_bin="$repository_root/../proof-bound/target/debug/proofbound-verify"
else
  echo "release receipt failed: set PROOFBOUND_VERIFY_BIN or install proofbound-verify" >&2
  exit 2
fi

mkdir -p "$(dirname "$output_directory")"
temporary_verification="$(mktemp "$verification_path.tmp.XXXXXX")"
trap 'rm -f -- "$temporary_verification"' EXIT

cd "$repository_root"
set +e
check_output="$("$proofbound_bin" check --root "$repository_root" --json 2>&1)"
check_status=$?
set -e
if [[ $check_status -ne 0 || "$check_output" == *'"schema":"proofbound-error/1"'* ]]; then
  printf '%s\n' "$check_output" >&2
  if [[ $check_status -ne 0 ]]; then
    exit "$check_status"
  fi
  exit 1
fi

"$proofbound_bin" release --root "$repository_root" --output "$output_directory"
"$proofbound_verify_bin" --release "$output_directory" --json >"$temporary_verification"
python3 - "$temporary_verification" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_bytes())
if report.get("verdict") != "receipt-consistent":
    raise SystemExit(
        "release receipt verification failed: "
        f"unexpected verdict {report.get('verdict')!r}"
    )
PY
mv "$temporary_verification" "$verification_path"
trap - EXIT

printf 'Proofbound release: %s\n' "$output_directory"
printf 'Independent verification: %s\n' "$verification_path"
