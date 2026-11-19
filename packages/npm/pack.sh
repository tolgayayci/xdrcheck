#!/usr/bin/env bash
# Pack the npm package around one release archive: the archive is embedded under archive/ and its name, version,
# sha256 and size are written to release.json, which the runner checks before reading it.
#
# Usage: packages/npm/pack.sh ARCHIVE [OUT_DIR]   (OUT_DIR default: dist) → OUT_DIR/xdrcheck-<version>.tgz
#
# Only `npm pack`: nothing is installed, fetched or published. package.json keeps "private": true, so an
# accidental `npm publish` is refused; publishing needs the maintainers' approval each time (docs/maintenance.md).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
[ "$#" -ge 1 ] || { echo "usage: $0 ARCHIVE [OUT_DIR]" >&2; exit 2; }
archive=$(realpath "$1")
mkdir -p "${2:-dist}"
out=$(realpath "${2:-dist}")
name=$(basename "$archive")
version=${name#xdrcheck-}
version=${version%.tar.gz}
pkg_version=$(node -p 'require(process.argv[1]).version' "$here/package.json")
[ "$version" = "$pkg_version" ] || {
  echo "pack: the archive is version $version, packages/npm/package.json says $pkg_version" >&2
  exit 1
}

stage=$(mktemp -d "$out/.npm-pack.XXXXXX")
trap 'rm -rf "$stage"' EXIT
cp -r "$here/package.json" "$here/bin" "$here/lib" "$stage/"
mkdir "$stage/archive"
cp "$archive" "$stage/archive/$name"
node -e '
const [file, name, version] = process.argv.slice(1);
const { createHash } = require("node:crypto");
const b = require("node:fs").readFileSync(file);
const info = { version, archive: name, top: `xdrcheck-${version}`, sha256: createHash("sha256").update(b).digest("hex"), bytes: b.length };
process.stdout.write(JSON.stringify(info, null, 2) + "\n");' "$archive" "$name" "$version" > "$stage/release.json"

(cd "$stage" && npm_config_cache="$stage/.npm-cache" npm_config_update_notifier=false npm_config_fund=false \
  npm pack --ignore-scripts --loglevel=warn --pack-destination "$out" >/dev/null)
tgz="$out/xdrcheck-$version.tgz"
echo "pack: $tgz ($(stat -c %s "$tgz") bytes) sha256 $(sha256sum "$tgz" | cut -d' ' -f1)"
