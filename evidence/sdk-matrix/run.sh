#!/usr/bin/env bash
# One command: install pinned SDKs (if missing), build probes, regenerate vectors, run the matrix.
#   bash run.sh            # everything (about 5 minutes once installed)
#   bash run.sh "go v0.8"  # one SDK/version (substring filter on "<sdk> <version>")
set -euo pipefail
cd "$(dirname "$0")"
PY=$HOME/.local/share/mise/installs/python/3.13.16/bin/python3.13   # system python3 has no ensurepip

for v in 16.3.0 16.3.1 16.4.1 17.2.0 17.2.1 17.3.0 17.4.0; do
  [ -d js/$v/node_modules/@stellar/stellar-sdk ] || (mkdir -p js/$v && cd js/$v &&
    echo '{"name":"probe","private":true,"type":"module"}' > package.json &&
    npm install --ignore-scripts --no-audit --no-fund --save-exact @stellar/stellar-sdk@$v >/dev/null)
done
for v in 17.0.0 17.0.1; do
  [ -x py/venv-$v/bin/python ] || ($PY -m venv py/venv-$v && py/venv-$v/bin/pip install -q "stellar-sdk==$v")
done
for v in v0.7.1 v0.7.2 v0.7.3 v0.8.0; do
  (mkdir -p go/$v && cd go/$v && { [ -f go.mod ] || { go mod init probe >/dev/null 2>&1; go get github.com/stellar/go-stellar-sdk@$v; }; } &&
    ln -sf ../common/main.go main.go && go mod tidy >/dev/null 2>&1 && go build -o probe .)
done
for v in 28.0.0 28.0.1 30.0.0; do
  d=x${v//./_}; sk=0.0.13; [ $v = 30.0.0 ] && sk=1.0.0
  (cd rust/$d && XDR_VERSION=$v SK_VERSION=$sk CARGO_TARGET_DIR=../target-$d cargo build --release -q)
done
python3 -I vectors/gen_vectors.py
python3 -I run_all.py "$@"
python3 -I make_matrix.py
