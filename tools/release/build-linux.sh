#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: tools/release/build-linux.sh <output-directory>" >&2
  exit 2
fi
if [[ "$(uname -s)" != "Linux" ]]; then
  echo "release build requires native Linux" >&2
  exit 3
fi

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
output_directory="$1"
case "$(uname -m)" in
  x86_64)
    architecture="x86_64"
    target="x86_64-unknown-linux-gnu"
    ;;
  aarch64)
    architecture="aarch64"
    target="aarch64-unknown-linux-gnu"
    ;;
  *)
    echo "release build architecture is unsupported: $(uname -m)" >&2
    exit 3
    ;;
esac

version="$(tr -d '\n' <"$repository_root/VERSION")"
commit="$(git -C "$repository_root" rev-parse HEAD)"
source_date_epoch="$(git -C "$repository_root" show -s --format=%ct HEAD)"
toolchain="$(rustc --version)"
bundle_name="proofbound-runtime-v${version}-${target}.tar.gz"
mkdir -p "$repository_root/target"
work_root="$(mktemp -d "$repository_root/target/proofbound-release.XXXXXX")"
trap 'rm -rf -- "$work_root"' EXIT

export CARGO_INCREMENTAL=0
export SOURCE_DATE_EPOCH="$source_date_epoch"
export RUSTFLAGS="--remap-path-prefix=$repository_root=/workspace -C link-arg=-Wl,--build-id=none"
umask 022

build_bundle() {
  local build_name="$1"
  local target_directory="$work_root/$build_name-target"
  local stage="$work_root/$build_name-stage"
  local bundle="$work_root/$build_name-$bundle_name"

  CARGO_TARGET_DIR="$target_directory" cargo build \
    --locked \
    --release \
    --bins \
    --target "$target"
  mkdir -p "$stage"
  install -m 0755 "$target_directory/$target/release/pbr" "$stage/pbr"
  install -m 0755 \
    "$target_directory/$target/release/pbr-native-launcher" \
    "$stage/pbr-native-launcher"
  install -m 0755 "$target_directory/$target/release/pbr-verify" "$stage/pbr-verify"
  python3 - "$stage" "$architecture" "$target" "$version" "$commit" "$toolchain" <<'PY'
import hashlib
import json
import os
import pathlib
import sys

stage = pathlib.Path(sys.argv[1])
artifacts = []
for name in ("pbr", "pbr-native-launcher", "pbr-verify"):
    data = (stage / name).read_bytes()
    artifacts.append(
        {
            "name": name,
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
        }
    )
manifest = {
    "architecture": sys.argv[2],
    "artifacts": artifacts,
    "commit": sys.argv[5],
    "schema": "proofbound-runtime-release-manifest/1",
    "target": sys.argv[3],
    "toolchain": sys.argv[6],
    "version": sys.argv[4],
}
(stage / "RELEASE-MANIFEST.json").write_bytes(
    json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode() + b"\n"
)
os.chmod(stage / "RELEASE-MANIFEST.json", 0o644)
PY
  tar \
    --sort=name \
    --mtime="@$source_date_epoch" \
    --owner=0 \
    --group=0 \
    --numeric-owner \
    -C "$stage" \
    -cf - \
    RELEASE-MANIFEST.json pbr pbr-native-launcher pbr-verify | gzip -n >"$bundle"
}

mkdir -p "$output_directory"
build_bundle first
build_bundle second
cmp "$work_root/first-$bundle_name" "$work_root/second-$bundle_name"
install -m 0644 "$work_root/first-$bundle_name" "$output_directory/$bundle_name"
(
  cd "$output_directory"
  sha256sum "$bundle_name" >"$bundle_name.sha256"
)
printf '%s\n' "$output_directory/$bundle_name"
