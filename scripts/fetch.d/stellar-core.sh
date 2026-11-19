#!/usr/bin/env bash
# Fetch the pinned stellar-core release package and the runtime libraries it needs outside a container,
# verify every download and the extracted binary against pins.toml, and unpack them into the cache:
#
#   ${XDRCHECK_CACHE:-$HOME/.cache/xdrcheck}/stellar-core/<version>/dl/    the .deb files as downloaded
#   ${XDRCHECK_CACHE:-$HOME/.cache/xdrcheck}/stellar-core/<version>/pkg/   dpkg-deb -x of all of them
#
# The generator (crates/xdrcheck-gen) runs pkg/usr/bin/stellar-core with LD_LIBRARY_PATH=pkg/usr/lib/x86_64-linux-gnu.
# Idempotent: files already present with the right hash are not downloaded again. Network: this script only.
#
# [stellar_core.runtime_debs] entries are either `"<file>.deb" = "<sha256>"` (downloaded from llvm_base_url)
# or `"<file>.deb" = { url = "<full url>", sha256 = "<sha256>" }` for a library from another pool. The primary
# URLs are snapshot.ubuntu.com URLs, which keep superseded -updates builds; `llvm_fallback_base_url` and an
# entry's `fallback_url` (the plain archive pool) are tried when the primary download fails. The sha256 decides
# either way.
# XDRCHECK_PINS names another pins file (tests only); the default is the repository's pins.toml.
set -euo pipefail
cd "$(dirname "$0")/../.."
pins="${XDRCHECK_PINS:-pins.toml}"

# pin <dotted key>: print a scalar (an empty line for a missing key); for runtime_debs print
# "<file> <url or -> <fallback url or -> <sha256>" per library.
pin() { python3 -I -c 'import sys, tomllib
d = tomllib.load(open(sys.argv[1], "rb"))
for k in sys.argv[2].split("."): d = d.get(k, "")
if not isinstance(d, dict): print(d)
else:
    for name, v in d.items():
        if isinstance(v, dict): print(name, v["url"], v.get("fallback_url", "-"), v["sha256"])
        elif name.endswith(".deb"): print(name, "-", "-", v)' "$pins" "$1"; }

version="$(pin stellar_core.version)"
deb_url="$(pin stellar_core.deb_url)"
deb_sha="$(pin stellar_core.deb_sha256)"
bin_sha="$(pin stellar_core.binary_sha256)"
llvm_base="$(pin stellar_core.runtime_debs.llvm_base_url)"
llvm_fallback="$(pin stellar_core.runtime_debs.llvm_fallback_base_url)"

cache="${XDRCHECK_CACHE:-$HOME/.cache/xdrcheck}/stellar-core/$version"
dl="$cache/dl"
pkg="$cache/pkg"
mkdir -p "$dl"

# fetch <url> <file name> <sha256> [fallback url]
fetch() {
  local url="$1" out="$dl/$2" want="$3" fallback="${4:-}" have
  if [ -f "$out" ] && [ "$(sha256sum "$out" | cut -d' ' -f1)" = "$want" ]; then
    echo "stellar-core: have $2"
    return
  fi
  echo "stellar-core: download $url"
  if ! curl --fail --silent --show-error --location --retry 3 --output "$out.part" "$url"; then
    [ -n "$fallback" ] || exit 1
    echo "stellar-core: download $fallback (fallback)"
    curl --fail --silent --show-error --location --retry 3 --output "$out.part" "$fallback"
  fi
  have="$(sha256sum "$out.part" | cut -d' ' -f1)"
  if [ "$have" != "$want" ]; then
    rm -f "$out.part"
    echo "stellar-core: sha256 mismatch for $2: want $want, have $have" >&2
    exit 1
  fi
  mv "$out.part" "$out"
}

debs=()
fetch "$deb_url" "$(basename "$deb_url")" "$deb_sha"
debs+=("$dl/$(basename "$deb_url")")
while read -r name url fallback sha; do
  if [ "$url" = "-" ]; then
    url="$llvm_base/$name"
    fallback="${llvm_fallback:+$llvm_fallback/$name}"
  fi
  [ "$fallback" = "-" ] && fallback=""
  fetch "$url" "$name" "$sha" "$fallback"
  debs+=("$dl/$name")
done < <(pin stellar_core.runtime_debs)

# The extracted tree is current when the binary checks out and it was made from exactly these packages.
stamp="$(cd "$dl" && sha256sum "${debs[@]##*/}")"
binary="$pkg/usr/bin/stellar-core"
if [ -x "$binary" ] && [ "$(sha256sum "$binary" | cut -d' ' -f1)" = "$bin_sha" ] &&
  [ "$(cat "$pkg/.debs.sha256" 2>/dev/null)" = "$stamp" ]; then
  echo "stellar-core: $version already extracted"
  exit 0
fi

# Extract into a fresh directory and move it into place only once the binary hash checks out.
tmp="$(mktemp -d "$cache/pkg.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT
for d in "${debs[@]}"; do dpkg-deb -x "$d" "$tmp"; done
have="$(sha256sum "$tmp/usr/bin/stellar-core" | cut -d' ' -f1)"
if [ "$have" != "$bin_sha" ]; then
  echo "stellar-core: binary sha256 mismatch: want $bin_sha, have $have" >&2
  exit 1
fi
printf '%s\n' "$stamp" > "$tmp/.debs.sha256"
rm -rf "$pkg"
mv "$tmp" "$pkg"
trap - EXIT
echo "stellar-core: $version ready ($binary)"
