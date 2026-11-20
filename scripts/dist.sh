#!/usr/bin/env bash
# Prebuilt binaries, the release asset list and the container image (docs/release.md sections 8 to 10).
#
# Usage:
#   scripts/dist.sh bin              build dist/xdrcheck-<version>-<os>-<arch>.tar.gz for each platform of
#                                    DIST_PLATFORMS whose tools all build here; print what was left out and why
#   scripts/dist.sh sums             write dist/xdrcheck-<version>.provenance.json and dist/SHA256SUMS over every
#                                    asset of the version in dist/ (corpus archive, npm package, binaries)
#   scripts/dist.sh verify [DIR]     every file SHA256SUMS lists is in DIR (default dist) with that sha256, and
#                                    every asset of the version in DIR is listed
#   scripts/dist.sh image            build the container image from dist/ (the corpus archive and the Linux
#                                    binaries of this machine's architecture), smoke-test it offline, remove it
#   scripts/dist.sh assemble         sums, verify, image: the release asset set in dist/, checked
#
# Environment:
#   VERSION          the release version (default: what scripts/release.sh derives for COMMIT)
#   COMMIT           the commit the binaries are built from (default HEAD); the tree must be clean for a release
#   DIST_PLATFORMS   space-separated platforms (default: linux-amd64 linux-arm64 darwin-amd64 darwin-arm64)
#   DIST_STRICT=1    fail when a requested platform cannot be built completely (the release workflow sets it)
#   KEEP_IMAGE=1     keep the image after the smoke test (named xdrcheck-dist:<version>)
#
# Nothing is published, pushed or uploaded: everything is written under dist/.
set -euo pipefail
cd "$(dirname "$0")/.."
root=$PWD
export LC_ALL=C
py() { python3 -I "$@"; }

commit=$(git rev-parse --verify "${COMMIT:-HEAD}^{commit}")
epoch=$(git log -1 --format=%ct "$commit")
vline=$(COMMIT=$commit scripts/release.sh version)
read -r version channel <<< "$vline"
platforms=${DIST_PLATFORMS:-linux-amd64 linux-arm64 darwin-amd64 darwin-arm64}
image="xdrcheck-dist:$version"

# The tools of each platform. The Go tools (xdrcheck, xdrlint, the minimal and demo adapters) build everywhere Go
# does; on macOS xdrcheck runs without the Linux-only memory controls (cgroups, parent-death signal). xdrcheck-corpus, the
# corpus author's tool, is built for Linux only.
tools_for() {
  case "$1" in
    linux-*) echo "xdrcheck xdrcheck-corpus xdrlint adapters/minimal adapters/demo" ;;
    darwin-*) echo "xdrcheck xdrlint adapters/minimal adapters/demo" ;;
    *) echo "dist: unknown platform $1 (want linux-amd64, linux-arm64, darwin-amd64 or darwin-arm64)" >&2; return 2 ;;
  esac
}

rust_triple() {
  case "$1" in
    linux-amd64) echo x86_64-unknown-linux-gnu ;;
    linux-arm64) echo aarch64-unknown-linux-gnu ;;
    darwin-amd64) echo x86_64-apple-darwin ;;
    darwin-arm64) echo aarch64-apple-darwin ;;
  esac
}

# Reproducible gzip'd tar of DIR's single top-level directory TOP: the release archive's options.
pack() { # pack WORKDIR TOP OUT
  tar --sort=name --format=ustar --mtime="@$epoch" --owner=0 --group=0 --numeric-owner \
    --mode='u=rwX,go=rX,a-st' -C "$1" -cf - "$2" | gzip -n -9 > "$3.tmp"
  mv "$3.tmp" "$3"
}

# build_rust PLATFORM OUT_FILE: xdrcheck-corpus for PLATFORM, or print why it cannot be built here and return 1.
build_rust() {
  local triple host linker env_linker cc_var
  triple=$(rust_triple "$1")
  host=$(rustc -vV | sed -n 's/^host: //p')
  if [ "$triple" != "$host" ]; then
    if ! rustup target list --installed 2>/dev/null | grep -qx "$triple"; then
      echo "no Rust standard library for $triple (rustup target add $triple)"; return 1
    fi
    env_linker="CARGO_TARGET_$(echo "$triple" | tr 'a-z-' 'A-Z_')_LINKER"
    linker=${!env_linker:-}
    if [ -z "$linker" ]; then
      case "$triple" in
        aarch64-unknown-linux-gnu) linker=aarch64-linux-gnu-gcc ;;
        x86_64-unknown-linux-gnu) linker=x86_64-linux-gnu-gcc ;;
        *) echo "no cross linker for $triple on this machine; build it on a $1 host"; return 1 ;;
      esac
      command -v "$linker" > /dev/null || { echo "no cross C toolchain for $triple ($linker: zstd-sys compiles C)"; return 1; }
      export "$env_linker=$linker"
      cc_var="CC_$(echo "$triple" | tr '-' '_')"
      export "$cc_var=$linker"
    fi
  fi
  # A target directory of its own: no debug info, symbols stripped, and the build machine's paths mapped away.
  local tdir="$root/target/dist"
  RUSTFLAGS="--remap-path-prefix=$root=. --remap-path-prefix=$HOME=~" \
    CARGO_PROFILE_RELEASE_DEBUG=0 CARGO_PROFILE_RELEASE_STRIP=symbols \
    cargo build --locked --release --quiet -p xdrcheck-corpus --target "$triple" --target-dir "$tdir" >&2 || {
      echo "cargo build for $triple failed"; return 1; }
  cp "$tdir/$triple/release/xdrcheck-corpus" "$2"
}

# The executable format and architecture of FILE, as the platform name it was built for.
arch_of() {
  py - "$1" <<'PY'
import struct, sys
b = open(sys.argv[1], "rb").read(20)
if b[:4] == b"\x7fELF":
    m = struct.unpack("<H", b[18:20])[0]
    print({0x3E: "linux-amd64", 0xB7: "linux-arm64"}.get(m, "linux-?"))
elif b[:4] == b"\xcf\xfa\xed\xfe":
    cpu = struct.unpack("<I", b[4:8])[0]
    print({0x01000007: "darwin-amd64", 0x0100000C: "darwin-arm64"}.get(cpu, "darwin-?"))
else:
    print("unknown")
PY
}

bin_cmd() {
  local built=() left=() p
  mkdir -p dist
  # global: the EXIT trap reads it after the function returns
  work=$(mktemp -d "$root/dist/.dist-bin.XXXXXX")
  trap 'rm -rf "$work"' EXIT
  gover=$(go env GOVERSION)
  rustver=$(rustc -V)
  # The tools are built from the working tree: it must be the commit, or the build says it is not.
  [ "$commit" = "$(git rev-parse HEAD)" ] || { echo "dist: COMMIT must be the checked-out commit for bin" >&2; exit 2; }
  dirty=false
  if [ -n "$(git status --porcelain -- go lint crates Cargo.toml Cargo.lock rust-toolchain.toml)" ]; then
    dirty=true
    [ "${DIST_STRICT:-}" != 1 ] || { echo "dist: the tools' sources differ from $commit (DIST_STRICT=1)" >&2; exit 1; }
    echo "dist: warning: the tools' sources differ from $commit; BUILDINFO.json says so (source.dirty)"
  fi
  for p in $platforms; do
    local tools os arch top stage missing=() t why
    tools=$(tools_for "$p")
    os=${p%-*}; arch=${p#*-}
    top="xdrcheck-$version-$p"
    stage="$work/$top"
    mkdir -p "$stage/bin"
    for t in $tools; do
      case "$t" in
        xdrcheck|adapters/*)
          (cd go && CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath -buildvcs=false \
             -ldflags='-s -w -buildid=' -o "$stage/bin/" "./${t/xdrcheck/cmd/xdrcheck}") ||
            missing+=("$t (go build failed)") ;;
        xdrlint)
          (cd lint && CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath -buildvcs=false \
             -ldflags='-s -w -buildid=' -o "$stage/bin/" ./cmd/xdrlint) ||
            missing+=("xdrlint (go build failed)") ;;
        xdrcheck-corpus)
          if ! why=$(build_rust "$p" "$stage/bin/xdrcheck-corpus"); then missing+=("xdrcheck-corpus: $why"); fi ;;
      esac
    done
    if [ ${#missing[@]} -gt 0 ]; then
      left+=("$p: $(IFS=';'; echo "${missing[*]}")")
      continue
    fi
    for t in "$stage"/bin/*; do
      a=$(arch_of "$t")
      [ "$a" = "$p" ] || { echo "dist: $(basename "$t") for $p is a $a executable" >&2; exit 1; }
    done
    cp LICENSE NOTICE "$stage/"
    py - "$stage" "$version" "$channel" "$p" "$commit" "$gover" "$rustver" "$dirty" <<'PY'
import json, os, sys
stage, version, channel, platform, commit, gover, rustver, dirty = sys.argv[1:9]
tools = sorted(os.listdir(os.path.join(stage, "bin")))
info = {
    "version": version, "channel": channel, "platform": platform,
    "source": {"commit": commit, "dirty": dirty == "true",
               "build": "Go: CGO_ENABLED=0, -trimpath, no build ID; Rust: release profile, stripped, paths remapped"},
    "tools": tools,
    "toolchains": {"go": gover, **({"rust": rustver} if "xdrcheck-corpus" in tools else {})},
}
if platform.startswith("linux") and "xdrcheck-corpus" in tools:
    info["note"] = "xdrcheck-corpus links against the build machine's glibc; the Go tools are static"
open(os.path.join(stage, "BUILDINFO.json"), "w").write(json.dumps(info, indent=2) + "\n")
PY
    pack "$work" "$top" "dist/$top.tar.gz"
    built+=("$p")
    echo "dist: dist/$top.tar.gz ($(stat -c %s "dist/$top.tar.gz") bytes): $(cd "$stage/bin" && ls | tr '\n' ' ')"
  done
  for l in "${left[@]}"; do echo "dist: not built: $l"; done
  [ ${#built[@]} -gt 0 ] || { echo "dist: no platform could be built" >&2; exit 1; }
  if [ ${#left[@]} -gt 0 ] && [ "${DIST_STRICT:-}" = 1 ]; then
    echo "dist: DIST_STRICT=1 and ${#left[@]} platform(s) could not be built" >&2; exit 1
  fi
  sums_cmd
}

# The assets of this version in DIR.
assets_in() {
  (cd "$1" && for f in "xdrcheck-$version.tar.gz" "xdrcheck-$version.tgz" \
       "xdrcheck-$version.provenance.json" xdrcheck-"$version"-*-*.tar.gz; do
     if [ -f "$f" ]; then echo "$f"; fi; done) | sort
}

sums_cmd() {
  [ -f "dist/xdrcheck-$version.tar.gz" ] || echo "dist: no corpus archive dist/xdrcheck-$version.tar.gz yet (make release)"
  rm -f "dist/xdrcheck-$version.provenance.json"
  # shellcheck disable=SC2046
  py - "dist" "$version" "$channel" "$commit" "$epoch" $(assets_in dist) <<'PY'
import hashlib, json, os, re, sys
d, version, channel, commit, epoch, *files = sys.argv[1:]
def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()
assets = []
for f in files:
    a = {"file": f, "sha256": sha(os.path.join(d, f)), "bytes": os.path.getsize(os.path.join(d, f))}
    if f.endswith(".tgz"):
        a["kind"] = "npm-package"
    elif f.startswith("xdrcheck-"):
        a["kind"] = "corpus"
    else:
        a["kind"] = "binaries"
        a["platform"] = re.sub(r"\.tar\.gz$", "", f)[len("xdrcheck-%s-" % version):]
    assets.append(a)
prov = {
    "schema": "xcc.release-assets/v1",
    "version": version,
    "channel": channel,
    "protocol": int(version.split(".")[0]),
    "tag": "v" + version,
    "source": {"commit": commit, "commit_time": int(epoch)},
    "assets": assets,
}
open(os.path.join(d, "xdrcheck-%s.provenance.json" % version), "w").write(json.dumps(prov, indent=2) + "\n")
PY
  (cd dist && assets_in . | xargs sha256sum > SHA256SUMS.tmp && mv SHA256SUMS.tmp SHA256SUMS)
  echo "dist: dist/SHA256SUMS lists $(wc -l < dist/SHA256SUMS) assets of $version ($channel)"
}

verify_cmd() {
  local d=${1:-dist}
  [ -f "$d/SHA256SUMS" ] || { echo "dist verify: no $d/SHA256SUMS" >&2; exit 1; }
  (cd "$d" && sha256sum --check --strict --quiet SHA256SUMS) || { echo "dist verify: a checksum does not match" >&2; exit 1; }
  local f
  while read -r f; do
    grep -q "  $f\$" "$d/SHA256SUMS" || { echo "dist verify: $f is not in SHA256SUMS" >&2; exit 1; }
  done < <(assets_in "$d")
  echo "dist verify: $(wc -l < "$d/SHA256SUMS") assets match SHA256SUMS"
}

image_cmd() {
  local arch corpus bins # ctx stays global: the EXIT trap reads it
  case "$(uname -m)" in x86_64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; *) echo "dist image: unsupported machine $(uname -m)" >&2; exit 2 ;; esac
  corpus="xdrcheck-$version.tar.gz"
  bins="xdrcheck-$version-linux-$arch.tar.gz"
  for f in "$corpus" "$bins"; do
    [ -f "dist/$f" ] || { echo "dist image: dist/$f is missing (make release, make dist-bin)" >&2; exit 1; }
  done
  verify_cmd dist
  ctx=$(mktemp -d "$root/dist/.dist-image.XXXXXX")
  trap 'rm -rf "$ctx"; [ "${KEEP_IMAGE:-}" = 1 ] || docker image rm -f "$image" > /dev/null 2>&1 || true' EXIT
  cp "dist/$corpus" "dist/$bins" release/Dockerfile "$ctx/"
  grep -E "  ($corpus|$bins)\$" dist/SHA256SUMS > "$ctx/SHA256SUMS"
  echo "dist image: building $image (linux/$arch) from $corpus and $bins"
  docker build --quiet --network=none --platform "linux/$arch" \
    --build-arg "VERSION=$version" --build-arg "REVISION=$commit" \
    -t "$image" "$ctx" > /dev/null
  smoke
  echo "dist image: ok ($(docker image inspect "$image" --format '{{.Size}}') bytes)"
  [ "${KEEP_IMAGE:-}" = 1 ] && echo "dist image: kept as $image (KEEP_IMAGE=1)" || echo "dist image: removed $image"
}

# The smoke test: each tool starts, the corpus verifies, and the demo replay finds its planted bug while the
# minimal adapter passes the same entries; all with no network.
smoke() {
  local run=(docker run --rm --network none "$image")
  # Each tool's help, captured first: a tool that prints its usage may exit non-zero, which is not the point here.
  starts() { local o; o=$("${run[@]}" "${@:2}" 2>&1 || true); grep -q "$1" <<< "$o"; }
  starts '^usage: xdrcheck <command>' xdrcheck || { echo "dist image: xdrcheck does not start" >&2; exit 1; }
  echo "dist image: xdrcheck starts"
  starts '^Usage: xdrcheck-corpus' xdrcheck-corpus --help || { echo "dist image: xdrcheck-corpus does not start" >&2; exit 1; }
  starts 'xdrlint' xdrlint -h || { echo "dist image: xdrlint does not start" >&2; exit 1; }
  echo "dist image: xdrcheck-corpus and xdrlint start"
  "${run[@]}" xdrcheck-corpus --corpus corpus verify --checks schema,ids,hashes > /dev/null ||
    { echo "dist image: xdrcheck-corpus verify failed on the bundled corpus" >&2; exit 1; }
  echo "dist image: the bundled corpus verifies (schema, ids, hashes)"
  local entries='cap-0015/*,cap-0027/*' out code
  set +e
  out=$("${run[@]}" xdrcheck replay --adapter demo --target-version demo --input sep54-dir --entries "$entries" --report /tmp/demo 2>&1)
  code=$?
  set -e
  echo "$out" | grep '^xdrcheck replay' || true
  if [ "$code" -ne 1 ] || ! echo "$out" | grep -q 'Failing: [1-9]'; then
    echo "$out" | tail -20 >&2
    echo "dist image: the demo replay did not find its planted bug (exit $code)" >&2; exit 1
  fi
  echo "dist image: the demo replay finds the planted bug (exit 1)"
  out=$("${run[@]}" xdrcheck replay --adapter minimal --target-version smoke --input sep54-dir --entries "$entries" --report /tmp/minimal 2>&1) ||
    { echo "$out" | tail -20 >&2; echo "dist image: the minimal adapter's replay failed" >&2; exit 1; }
  echo "$out" | grep '^xdrcheck replay' || true
  echo "dist image: the minimal adapter passes the same entries (exit 0)"
}

case "${1:-}" in
  bin) bin_cmd ;;
  sums) sums_cmd ;;
  verify) verify_cmd "${2:-dist}" ;;
  image) image_cmd ;;
  assemble) sums_cmd; verify_cmd dist; image_cmd ;;
  *) echo "usage: $0 bin | sums | verify [DIR] | image | assemble" >&2; exit 2 ;;
esac
