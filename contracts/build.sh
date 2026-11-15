#!/usr/bin/env bash
# Reproducible build of the test contracts.
#
#   contracts/build.sh                      build, write corpus/contracts/<name>.wasm and <name>.json
#   contracts/build.sh --clean              the same, after removing the target directory
#   contracts/build.sh --verify             fresh build in a scratch target directory; fail unless it
#                                           equals the vendored wasm and json byte for byte
#   contracts/build.sh --check-reproducible two fresh builds in two empty target directories;
#                                           print both wasm sha256 values and fail if they differ
#
# What makes the build reproducible:
# - the toolchain from contracts/rust-toolchain.toml (checked against rustc), `--locked` dependencies,
#   the release profile in contracts/Cargo.toml (codegen-units 1, LTO, stripped symbols);
# - `--remap-path-prefix` for CARGO_HOME and this directory, so no machine path is embedded;
# - a fixed environment: LC_ALL=C, TZ=UTC, SOURCE_DATE_EPOCH=0, no inherited RUSTFLAGS;
# - spec shaking by tools/wasm-post (what `stellar contract build` does for soroban-sdk 29),
#   which rewrites only the contractspecv0 section.
#
# Source tree hash: sha256 of the sorted `sha256sum` listing of every file under contracts/ except
# target directories, paths relative to contracts/ (the "source_tree_rule" field repeats this).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
OUT="$ROOT/corpus/contracts"
TARGET_TRIPLE="wasm32v1-none"
CONTRACTS=(shape-emitter custom-account token-shape)

mode=build
clean=0
for arg in "$@"; do
  case "$arg" in
    --clean) clean=1 ;;
    --verify) mode=verify ;;
    --check-reproducible) mode=repro ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "build.sh: unknown argument: $arg" >&2; exit 2 ;;
  esac
done

cd "$HERE"
export LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH=0 CARGO_INCREMENTAL=0
unset RUSTFLAGS CARGO_BUILD_RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTC_WRAPPER CARGO_BUILD_RUSTC_WRAPPER
# soroban-sdk 29 refuses a wasm build unless the build system shakes the spec; tools/wasm-post does.
export SOROBAN_SDK_BUILD_SYSTEM_SUPPORTS_SPEC_SHAKING_V2=1

TOOLCHAIN="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' rust-toolchain.toml)"
RUSTC_V="$(rustc -vV)"
RUSTC_RELEASE="$(sed -n 's/^release: //p' <<<"$RUSTC_V")"
RUSTC_COMMIT="$(sed -n 's/^commit-hash: //p' <<<"$RUSTC_V")"
if [[ "$RUSTC_RELEASE" != "$TOOLCHAIN" ]]; then
  echo "build.sh: rustc is $RUSTC_RELEASE, rust-toolchain.toml pins $TOOLCHAIN" >&2
  exit 1
fi
SDK_VERSION="$(awk '/^name = "soroban-sdk"$/{getline; gsub(/version = |"/, ""); print; exit}' Cargo.lock)"
if [[ "$SDK_VERSION" != "29.0.1" ]]; then
  echo "build.sh: Cargo.lock resolves soroban-sdk $SDK_VERSION, pins.toml requires 29.0.1" >&2
  exit 1
fi
CARGO_HOME_DIR="${CARGO_HOME:-$HOME/.cargo}"
CARGO_HOME_DIR="$(cd "$CARGO_HOME_DIR" && pwd)"
SEP=$'\x1f'
export CARGO_ENCODED_RUSTFLAGS="--remap-path-prefix=${CARGO_HOME_DIR}=/cargo${SEP}--remap-path-prefix=${HERE}=/contracts"
BUILD_CMD="SOROBAN_SDK_BUILD_SYSTEM_SUPPORTS_SPEC_SHAKING_V2=1 CARGO_ENCODED_RUSTFLAGS='--remap-path-prefix=\$CARGO_HOME=/cargo --remap-path-prefix=<contracts>=/contracts' cargo build --locked --release --target $TARGET_TRIPLE -p shape-emitter -p custom-account -p token-shape; wasm-post shake <built>.wasm <name>.wasm"

source_tree_sha256() {
  find . -type d -name target -prune -o -type f -print | sed 's|^\./||' | LC_ALL=C sort \
    | xargs -d '\n' sha256sum | sha256sum | cut -d' ' -f1
}
source_tree_count() {
  find . -type d -name target -prune -o -type f -print | wc -l | tr -d ' '
}

# build <target dir> <output dir>: compile, shake and write <name>.wasm and <name>.json.
build() {
  local tdir="$1" odir="$2"
  mkdir -p "$odir"
  cargo build --quiet --locked --release --target-dir "$tdir" -p wasm-post
  cargo build --quiet --locked --release --target-dir "$tdir" --target "$TARGET_TRIPLE" \
    -p shape-emitter -p custom-account -p token-shape
  local tree count
  tree="$(source_tree_sha256)"
  count="$(source_tree_count)"
  for name in "${CONTRACTS[@]}"; do
    local built="$tdir/$TARGET_TRIPLE/release/${name//-/_}.wasm"
    "$tdir/release/wasm-post" shake "$built" "$odir/$name.wasm" 2>/dev/null
    local info
    info="$("$tdir/release/wasm-post" info "$odir/$name.wasm")"
    cat >"$odir/$name.json" <<EOF
{
  "name": "$name",
  "wasm": "corpus/contracts/$name.wasm",
  "wasm_sha256": "$(sha256sum "$odir/$name.wasm" | cut -d' ' -f1)",
  "source_tree_sha256": "$tree",
  "source_tree_files": $count,
  "source_tree_rule": "sha256 of the LC_ALL=C-sorted sha256sum listing of every file under contracts/ except target directories, paths relative to contracts/",
  "toolchain": {"rustc": "$RUSTC_RELEASE", "commit": "$RUSTC_COMMIT", "target": "$TARGET_TRIPLE"},
  "soroban_sdk": "$SDK_VERSION",
  "build_command": "$(sed 's/"/\\"/g' <<<"$BUILD_CMD")",
  "wasm_info": $info
}
EOF
  done
}

case "$mode" in
  build)
    if [[ $clean == 1 ]]; then rm -rf "$HERE/target"; fi
    build "$HERE/target" "$OUT"
    for name in "${CONTRACTS[@]}"; do
      echo "$(sha256sum "$OUT/$name.wasm" | cut -d' ' -f1)  corpus/contracts/$name.wasm"
    done
    ;;
  verify)
    scratch="$HERE/target/verify"
    rm -rf "$scratch"
    build "$scratch/target" "$scratch/out"
    status=0
    for name in "${CONTRACTS[@]}"; do
      for ext in wasm json; do
        if cmp -s "$scratch/out/$name.$ext" "$OUT/$name.$ext"; then
          echo "same   corpus/contracts/$name.$ext"
        else
          echo "DIFFER corpus/contracts/$name.$ext" >&2
          status=1
        fi
      done
    done
    exit $status
    ;;
  repro)
    status=0
    for run in a b; do
      rm -rf "$HERE/target/repro-$run"
      build "$HERE/target/repro-$run/target" "$HERE/target/repro-$run/out"
    done
    for name in "${CONTRACTS[@]}"; do
      a="$(sha256sum "$HERE/target/repro-a/out/$name.wasm" | cut -d' ' -f1)"
      b="$(sha256sum "$HERE/target/repro-b/out/$name.wasm" | cut -d' ' -f1)"
      echo "$name run 1: $a"
      echo "$name run 2: $b"
      [[ "$a" == "$b" ]] || { echo "build.sh: $name is not reproducible" >&2; status=1; }
    done
    exit $status
    ;;
esac
