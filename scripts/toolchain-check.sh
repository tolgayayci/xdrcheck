#!/usr/bin/env bash
# Check each toolchain the build needs against pins.toml; exit 1 if one is missing or at another version.
set -uo pipefail
cd "$(dirname "$0")/.."
# Use the toolchains mise pins for this project when mise is present.
command -v mise >/dev/null && eval "$(mise env -s bash 2>/dev/null)"
pin() { python3 -c "import tomllib,sys;d=tomllib.load(open('pins.toml','rb'));print(eval('d'+''.join(f'[{k!r}]' for k in sys.argv[1].split('.'))))" "$1"; }
fail=0
check() { # name, wanted, actual
  if [ "$2" = "$3" ]; then printf 'ok   %-8s %s\n' "$1" "$3"; else printf 'FAIL %-8s want %s, have %s\n' "$1" "$2" "${3:-missing}"; fail=1; fi
}
check go "$(pin go.toolchain)" "$(go env GOVERSION 2>/dev/null | sed 's/^go//')"
check node "$(pin js.node)" "$(node --version 2>/dev/null | sed 's/^v//')"
check python "$(pin python.version)" "$(python3 -c 'import platform;print(platform.python_version())' 2>/dev/null)"
check rust "$(pin rust.toolchain)" "$(rustc --version 2>/dev/null | awk '{print $2}')"
check java "$(pin java.jdk | sed -E 's/^temurin-([0-9.]+)\+.*/\1/')" "$(java -version 2>&1 | head -1 | sed -E 's/.*version "([0-9.]+)".*/\1/')"
printf 'info docker   %s\n' "$(docker --version 2>/dev/null || echo missing)"
printf 'info zstd     %s\n' "$(zstd --version 2>/dev/null || echo missing)"
exit $fail
