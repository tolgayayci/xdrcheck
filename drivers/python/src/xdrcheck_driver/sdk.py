"""The SDK under test and the facts about it that `describe` reports, all read from the installed distributions
at start-up, never from the driver's own configuration: versions from the distribution metadata, each wheel's
sha256 from pip's installation report, which `make build` writes into the venv next to the packages it
installed (the way npm keeps node_modules/.package-lock.json).
"""
from __future__ import annotations

import inspect
import json
import os
import platform
import re
import sys
from importlib import metadata

PACKAGE = "stellar-sdk"
# The libraries whose versions decide decoding and numeric behaviour.
DEPENDENCIES = ["xdrlib3"]
REPORT = "xdrcheck-install-report.json"


def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _wheel_hashes() -> dict[tuple[str, str], str]:
    try:
        with open(os.path.join(sys.prefix, REPORT), encoding="utf-8") as f:
            report = json.load(f)
    except (OSError, ValueError):
        return {}
    out = {}
    for item in report.get("install", []):
        md = item.get("metadata") or {}
        sha = ((item.get("download_info") or {}).get("archive_info") or {}).get("hashes", {}).get("sha256")
        if md.get("name") and md.get("version") and sha:
            out[(normalize(md["name"]), md["version"])] = f"sha256:{sha}"
    return out


def describe_sdk() -> dict:
    hashes = _wheel_hashes()
    dist = metadata.distribution(PACKAGE)
    name, version = normalize(dist.metadata["Name"]), dist.version
    sdk = {"ecosystem": "pypi", "package": name, "version": version}
    if (name, version) in hashes:
        sdk["integrity"] = hashes[(name, version)]
    deps = []
    for dep in DEPENDENCIES:
        try:
            d = metadata.distribution(dep)
        except metadata.PackageNotFoundError:
            continue
        e = {"package": normalize(d.metadata["Name"]), "version": d.version}
        if (e["package"], d.version) in hashes:
            e["integrity"] = hashes[(e["package"], d.version)]
        deps.append(e)
    sdk["dependencies"] = deps
    return sdk


def runtime() -> dict:
    return {
        "name": platform.python_implementation().lower(),
        "version": platform.python_version(),
        "os": sys.platform,
        "arch": platform.machine(),
    }


def default_depth() -> int | None:
    """The default decode depth in the SDK's own units (one per type level), as the generated code reads it."""
    from stellar_sdk.xdr import base

    d = getattr(base, "DEFAULT_XDR_MAX_DEPTH", None)
    return d if isinstance(d, int) else None


def xdr_types() -> dict[str, type]:
    """Every generated XDR class by lower-cased name (the corpus spells ScVal, the SDK SCVal)."""
    from stellar_sdk import xdr

    out = {}
    for name in dir(xdr):
        c = getattr(xdr, name)
        if inspect.isclass(c) and c.__module__.startswith("stellar_sdk.xdr.") and hasattr(c, "from_xdr_bytes"):
            out[name.lower()] = c
    return out
