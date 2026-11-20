#!/usr/bin/env bash
# Weekly next-protocol stellar-core build (docs/maintenance.md, section 5.4): stellar-core at the tip of an
# unpinned branch, configured with --enable-next-protocol-version-unsafe-for-production, so the generator can
# run scenarios at the next protocol weeks before a release exists. The build runs in a container of the pinned
# build image (pins.toml [images] vnext_build_base) with the toolchain stellar-core's own testing Dockerfile
# installs; the result is cached by commit and is never a pinned artefact.
#
#   resolve  the branch's commit (git ls-remote), or XDRCHECK_VNEXT_COMMIT
#   cached   a finished build of that commit under the cache is reused as it is
#   build    shallow clone with submodules, then autogen, install-rust, configure with the next-protocol flag,
#            make, inside the build container (needs docker; about an hour on a 4-core runner)
#   inspect  `stellar-core version` of the binary: the ledger protocol it supports must be above
#            pins.toml protocol.max_supported, or the build is not a next-protocol build
#
# Output, under ${XDRCHECK_CACHE:-~/.cache/xdrcheck}/stellar-core-vnext/<commit>/:
#   pkg/usr/bin/stellar-core            the binary
#   pkg/usr/lib/x86_64-linux-gnu/       the C++ runtime libraries it needs (the generator adds this directory
#                                       to LD_LIBRARY_PATH, as for the pinned release)
#   manifest.json                       ref, commit, configure flags, build image, binary sha256, the
#                                       `stellar-core version` output and the ledger protocol it supports
# and <out dir>/vnext-core/manifest.json (the job uploads pkg/ and the manifest as its artefact).
#
# Usage: scripts/nightly/vnext-core.sh <out dir>
#   XDRCHECK_VNEXT_REF       branch or tag to build (default master)
#   XDRCHECK_VNEXT_COMMIT    build this commit instead of resolving the ref (no network for the resolve step)
#   XDRCHECK_VNEXT_PLAN=1    print the plan (commit, cache path, every command) and write plan.json; build nothing
#   XDRCHECK_STELLAR_CORE_REPO  repository to clone (default the public stellar-core repository)
# Exit 0 the build is there (cached or new) or the plan was printed; 1 a step failed.
source "$(dirname "$0")/lib.sh"
nightly_init vnext-core "${1:?usage: vnext-core.sh <out dir>}"

ref="${XDRCHECK_VNEXT_REF:-master}"
origin="${XDRCHECK_STELLAR_CORE_REPO:-https://github.com/stellar/stellar-core.git}"
image=$(pin images.vnext_build_base)
max=$(pin protocol.max_supported)
flags="--enable-next-protocol-version-unsafe-for-production"
report="$OUT/vnext-core"
mkdir -p "$report"

# --- resolve ---
t0=$(date +%s)
commit="${XDRCHECK_VNEXT_COMMIT:-}"
if [ -z "$commit" ]; then
  commit=$(git ls-remote "$origin" "refs/heads/$ref" "refs/tags/$ref" 2>>"$NIGHTLY_LOG" | awk 'NR == 1 { print $1 }')
fi
if ! [[ "$commit" =~ ^[0-9a-f]{40}$ ]]; then
  result resolve FAIL $(($(date +%s) - t0)) "no commit for $ref in $origin"
  nightly_finish
fi
result resolve PASS $(($(date +%s) - t0)) "$ref is ${commit:0:12}"

dest="${XDRCHECK_CACHE:-$HOME/.cache/xdrcheck}/stellar-core-vnext/$commit"
short=${commit:0:12}
name="xdrcheck-vnext-core-$short-$$"
# The commands of the build step, in order; the plan prints them and the build runs them.
build_script=$(
  cat <<'EOS'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get -y -qq install git build-essential pkg-config autoconf automake libtool bison flex sed perl libpq-dev \
  parallel clang-20 libc++abi-20-dev libc++-20-dev libclang-rt-20-dev curl ca-certificates >/dev/null
cd /src
./autogen.sh
./install-rust.sh
export PATH="$HOME/.cargo/bin:$PATH"
./configure CC=clang-20 CXX=clang++-20 CFLAGS='-O3 -g1 -fno-omit-frame-pointer' \
  CXXFLAGS='-O3 -g1 -fno-omit-frame-pointer -stdlib=libc++' $CONFIGURE_FLAGS
make -j"$(nproc)"
mkdir -p /out/pkg/usr/bin /out/pkg/usr/lib/x86_64-linux-gnu
install -m 0755 src/stellar-core /out/pkg/usr/bin/stellar-core
for lib in $(ldd src/stellar-core | awk '/libc\+\+|libunwind/ { print $3 }'); do cp -L "$lib" /out/pkg/usr/lib/x86_64-linux-gnu/; done
/out/pkg/usr/bin/stellar-core version > /out/version.txt
chown -R "$OWNER" /out
EOS
)

write_manifest() { # <file> <status>
  python3 -I - "$1" "$2" "$ref" "$commit" "$origin" "$flags" "$image" "$dest" <<'PY'
import hashlib, json, os, re, sys
out, status, ref, commit, origin, flags, image, dest = sys.argv[1:]
m = {"schema": "xcc.vnext-core/v1", "status": status, "ref": ref, "commit": commit, "repository": origin,
     "configure_flags": flags.split(), "build_image": image, "path": os.path.join(dest, "pkg/usr/bin/stellar-core")}
binary = os.path.join(dest, "pkg/usr/bin/stellar-core")
if os.path.isfile(binary):
    m["binary_sha256"] = hashlib.sha256(open(binary, "rb").read()).hexdigest()
version = os.path.join(dest, "version.txt")
if os.path.isfile(version):
    text = open(version).read()
    m["version_output"] = text.strip().splitlines()
    p = re.search(r"ledger protocol version:\s*(\d+)", text)
    m["ledger_protocol"] = int(p.group(1)) if p else None
json.dump(m, open(out, "w"), indent=2)
open(out, "a").write("\n")
PY
}

if [ -n "${XDRCHECK_VNEXT_PLAN:-}" ]; then
  {
    echo "plan: stellar-core $ref at $commit, next-protocol build ($flags)"
    echo "cache: $dest"
    if [ -f "$dest/manifest.json" ]; then echo "cached: yes (the build step would be skipped)"; else echo "cached: no"; fi
    echo "\$ git clone --filter=blob:none --no-checkout $origin <work>/src"
    echo "\$ git -C <work>/src checkout --detach $commit && git -C <work>/src submodule update --init --recursive --depth 1"
    echo "\$ docker run --name $name -v <work>/src:/src -v <work>/out:/out -e CONFIGURE_FLAGS='$flags' $image bash -c <build script>"
    echo "--- build script ---"
    echo "$build_script"
    echo "--- inspect: the version output's ledger protocol must be above $max ---"
  } | tee "$report/plan.txt"
  python3 -I -c 'import json, sys
json.dump({"ref": sys.argv[1], "commit": sys.argv[2], "cache": sys.argv[3], "configure_flags": sys.argv[4].split(),
           "build_image": sys.argv[5], "max_supported": int(sys.argv[6])}, open(sys.argv[7], "w"), indent=2)' \
    "$ref" "$commit" "$dest" "$flags" "$image" "$max" "$report/plan.json"
  result build SKIPPED 0 "XDRCHECK_VNEXT_PLAN is set: plan only ($report/plan.txt)"
  nightly_finish
fi

# --- cached ---
if [ -f "$dest/manifest.json" ] && [ -x "$dest/pkg/usr/bin/stellar-core" ]; then
  cp "$dest/manifest.json" "$report/manifest.json"
  result build PASS 0 "cached build of ${commit:0:12}: $dest"
else
  # --- build (network: clone, packages, rustup) ---
  t0=$(date +%s)
  work="$dest.work"
  rm -rf "$work" "$dest"
  mkdir -p "$work/out"
  build() {
    git clone --quiet --filter=blob:none --no-checkout "$origin" "$work/src"
    git -C "$work/src" checkout --quiet --detach "$commit"
    git -C "$work/src" submodule update --quiet --init --recursive --depth 1
    docker run --rm --name "$name" -v "$work/src:/src" -v "$work/out:/out" -e CONFIGURE_FLAGS="$flags" \
      -e OWNER="$(id -u):$(id -g)" "$image" bash -c "$build_script"
  }
  if ! build >>"$NIGHTLY_LOG" 2>&1; then
    docker rm -f "$name" >/dev/null 2>&1 || true
    result build FAIL $(($(date +%s) - t0)) "the next-protocol build of ${commit:0:12} failed; see $NIGHTLY_LOG"
    nightly_finish
  fi
  mkdir -p "$dest"
  mv "$work/out/pkg" "$work/out/version.txt" "$dest/"
  rm -rf "$work"
  write_manifest "$dest/manifest.json" built
  cp "$dest/manifest.json" "$report/manifest.json"
  result build PASS $(($(date +%s) - t0)) "built ${commit:0:12} into $dest"
fi

# --- inspect ---
protocol=$(python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1])).get("ledger_protocol") or 0)' "$dest/manifest.json")
if [ "$protocol" -gt "$max" ]; then
  result inspect PASS 0 "the binary supports ledger protocol $protocol (pins.toml max_supported $max)"
else
  result inspect FAIL 0 "the binary supports ledger protocol $protocol, not above max_supported $max: not a next-protocol build"
fi
nightly_finish
