#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

if [[ -n "${PROOFBOUND_BIN:-}" ]]; then
  proofbound_bin="$PROOFBOUND_BIN"
elif command -v proofbound >/dev/null 2>&1; then
  proofbound_bin="$(command -v proofbound)"
elif [[ -x "$repo_root/../proof-bound/target/debug/proofbound" ]]; then
  proofbound_bin="$repo_root/../proof-bound/target/debug/proofbound"
else
  printf '%s\n' 'manifest check failed: set PROOFBOUND_BIN or install proofbound' >&2
  exit 2
fi

check_root="$repo_root"
temporary_root=""
check_output_file=""
check_pid=""
heartbeat_pid=""

cleanup() {
  if [[ -n "$check_pid" ]]; then
    kill "$check_pid" 2>/dev/null || true
  fi
  if [[ -n "$heartbeat_pid" ]]; then
    kill "$heartbeat_pid" 2>/dev/null || true
  fi
  if [[ -n "$check_output_file" ]]; then
    rm -f -- "$check_output_file"
  fi
  if [[ -n "$temporary_root" ]]; then
    rm -rf -- "$temporary_root"
  fi
}
trap cleanup EXIT

if ! git rev-parse --verify HEAD^{commit} >/dev/null 2>&1; then
  temporary_root="$(mktemp -d)"
  check_root="$temporary_root/repository"
  mkdir -p "$check_root"
  rsync -a \
    --exclude .git \
    --exclude .proofbound \
    --exclude target \
    "$repo_root/" "$check_root/"
  git -C "$check_root" init -q -b main
  git -C "$check_root" add --all
  git -C "$check_root" \
    -c user.name='Proofbound Runtime bootstrap' \
    -c user.email='bootstrap@invalid' \
    -c commit.gpgsign=false \
    commit -q -m 'Bootstrap manifest validation'
  if [[ ! -d "$repo_root/.lake/packages/proofbound" ]]; then
    printf '%s\n' 'manifest check failed: run just bootstrap before checking a repository without a commit' >&2
    exit 2
  fi
  mkdir -p "$check_root/.lake/packages"
  rsync -a "$repo_root/.lake/packages/" "$check_root/.lake/packages/"
  lake --dir "$check_root" build >/dev/null
  printf '%s\n' 'manifest check: using a disposable bootstrap commit'
fi

check_output_file="$(mktemp)"
"$proofbound_bin" check --root "$check_root" --fresh --json \
  >"$check_output_file" 2>&1 &
check_pid=$!
(
  elapsed_seconds=0
  while kill -0 "$check_pid" 2>/dev/null; do
    sleep 60
    elapsed_seconds=$((elapsed_seconds + 60))
    if kill -0 "$check_pid" 2>/dev/null; then
      printf '%s\n' \
        "Proofbound fresh check still running (${elapsed_seconds}s)" >&2
    fi
  done
) &
heartbeat_pid=$!
set +e
wait "$check_pid"
check_status=$?
check_pid=""
kill "$heartbeat_pid" 2>/dev/null
wait "$heartbeat_pid" 2>/dev/null
heartbeat_pid=""
set -e
check_output="$(<"$check_output_file")"
rm -f -- "$check_output_file"
check_output_file=""
if [[ $check_status -ne 0 || "$check_output" == *'"schema":"proofbound-error/1"'* ]]; then
  printf '%s\n' "$check_output" >&2
  compiled_project="$check_root/.proofbound/compiled/project.json"
  if [[ -f "$compiled_project" ]] && command -v jq >/dev/null 2>&1; then
    printf '%s\n' 'Proofbound failed evidence units:' >&2
    jq '.unit_runs[] | select(.outcome == "unavailable-or-failed" or .outcome == "failed")' \
      "$compiled_project" >&2
  fi
  if [[ $check_status -ne 0 ]]; then
    exit "$check_status"
  fi
  exit 1
fi
printf '%s\n' 'Proofbound manifest compilation: ok'

"$proofbound_bin" status --root "$check_root"
