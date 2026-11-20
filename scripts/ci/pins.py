#!/usr/bin/env python3
"""Read the values CI needs from pins.toml, the single source of versions, so no workflow names a version.

Usage:
  pins.py get <dotted.key>           print one value; exit 1 if the key is missing
  pins.py images <dotted.key>...     print each image reference (name:tag@sha256:digest), one per line
  pins.py wallet-backend-commits     print every wallet-backend acceptance commit (pre-fix and fixed), one per line
  pins.py cache-key <words>...       print a short hash of the resolved values, for cache keys:
                                     each word is `images=<k1,k2>`, `wallet-backend` or a dotted key
"""
import hashlib
import os
import sys
import tomllib

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
with open(os.path.join(ROOT, "pins.toml"), "rb") as f:
    PINS = tomllib.load(f)


def get(key):
    node = PINS
    for part in key.split("."):
        if not isinstance(node, dict) or part not in node:
            sys.exit(f"pins.py: pins.toml has no `{key}`")
        node = node[part]
    return node


def images(keys):
    refs = []
    for key in keys:
        ref = get(key)
        if not isinstance(ref, str) or "@sha256:" not in ref:
            sys.exit(f"pins.py: `{key}` is not an image reference pinned by digest")
        refs.append(ref)
    return refs


def wallet_backend_commits():
    """The commits the replay acceptance builds a binary for; `current` is only linted, never built."""
    commits = []
    for row in get("pipelines.wallet_backend.acceptance"):
        commits += [row["prefix"], row["fixed"]]
    return sorted(set(commits))


def cache_key(words):
    parts = []
    for word in words:
        if word.startswith("images="):
            parts += images([k for k in word[len("images="):].split(",") if k])
        elif word == "wallet-backend":
            parts += wallet_backend_commits() + [str(get("pipelines.wallet_backend.go_toolchain"))]
        else:
            parts.append(str(get(word)))
    return hashlib.sha256("\n".join(parts).encode()).hexdigest()[:20]


def main(argv):
    if len(argv) >= 2 and argv[0] == "get":
        print(get(argv[1]))
    elif argv and argv[0] == "images":
        print("\n".join(images(argv[1:])))
    elif argv == ["wallet-backend-commits"]:
        print("\n".join(wallet_backend_commits()))
    elif argv and argv[0] == "cache-key":
        print(cache_key(argv[1:]))
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main(sys.argv[1:])
