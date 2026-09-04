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

if ! git rev-parse --verify HEAD^{commit} >/dev/null 2>&1; then
  temporary_root="$(mktemp -d)"
  trap 'rm -rf -- "$temporary_root"' EXIT
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

set +e
check_output="$("$proofbound_bin" check --root "$check_root" --json 2>&1)"
check_status=$?
set -e
if [[ $check_status -ne 0 || "$check_output" == *'"schema":"proofbound-error/1"'* ]]; then
  printf '%s\n' "$check_output" >&2
  if [[ $check_status -ne 0 ]]; then
    exit "$check_status"
  fi
  exit 1
fi
printf '%s\n' 'Proofbound manifest compilation: ok'

"$proofbound_bin" status --root "$check_root"
