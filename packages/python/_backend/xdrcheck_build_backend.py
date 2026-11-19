"""A PEP 517 build backend for this one-module package, using the standard library only.

It builds a pure-Python wheel holding xdrcheck.py and its dist-info (METADATA from pyproject.toml's
[project] table, WHEEL, RECORD), and an sdist of the package directory's tracked inputs. Nothing is fetched, so
`pip install` of the directory works offline. Archive members carry a fixed timestamp, so builds are byte-identical.
"""
from __future__ import annotations

import base64
import hashlib
import io
import os
import tarfile
import tomllib
import zipfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODULE = "xdrcheck.py"
SDIST_FILES = ["pyproject.toml", MODULE, "_backend/xdrcheck_build_backend.py"]
EPOCH = (1980, 1, 1, 0, 0, 0)


def _project() -> dict:
    with open(os.path.join(HERE, "pyproject.toml"), "rb") as f:
        return tomllib.load(f)["project"]


def _names() -> tuple[str, str, str]:
    p = _project()
    dist = p["name"].replace("-", "_")
    return p["name"], dist, p["version"]


def _metadata() -> str:
    p = _project()
    lines = ["Metadata-Version: 2.4", f"Name: {p['name']}", f"Version: {p['version']}"]
    if p.get("description"):
        lines.append(f"Summary: {p['description']}")
    if p.get("license"):
        lines.append(f"License-Expression: {p['license']}")
    if p.get("requires-python"):
        lines.append(f"Requires-Python: {p['requires-python']}")
    for extra, reqs in (p.get("optional-dependencies") or {}).items():
        lines.append(f"Provides-Extra: {extra}")
        lines.extend(f'Requires-Dist: {r}; extra == "{extra}"' for r in reqs)
    return "\n".join(lines) + "\n"


def _wheel_text() -> str:
    return "Wheel-Version: 1.0\nGenerator: xdrcheck_build_backend\nRoot-Is-Purelib: true\nTag: py3-none-any\n"


def _record_hash(data: bytes) -> str:
    return "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()


def _dist_info(metadata_directory: str) -> str:
    _, dist, version = _names()
    name = f"{dist}-{version}.dist-info"
    d = os.path.join(metadata_directory, name)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "METADATA"), "w", encoding="utf-8") as f:
        f.write(_metadata())
    with open(os.path.join(d, "WHEEL"), "w", encoding="utf-8") as f:
        f.write(_wheel_text())
    return name


def get_requires_for_build_wheel(config_settings=None):
    return []


def get_requires_for_build_sdist(config_settings=None):
    return []


def prepare_metadata_for_build_wheel(metadata_directory, config_settings=None):
    return _dist_info(metadata_directory)


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    _, dist, version = _names()
    info = f"{dist}-{version}.dist-info"
    with open(os.path.join(HERE, MODULE), "rb") as f:
        module = f.read()
    files = [
        (MODULE, module),
        (f"{info}/METADATA", _metadata().encode()),
        (f"{info}/WHEEL", _wheel_text().encode()),
    ]
    record = "".join(f"{n},{_record_hash(b)},{len(b)}\n" for n, b in files) + f"{info}/RECORD,,\n"
    files.append((f"{info}/RECORD", record.encode()))
    whl = f"{dist}-{version}-py3-none-any.whl"
    with zipfile.ZipFile(os.path.join(wheel_directory, whl), "w", zipfile.ZIP_DEFLATED) as z:
        for n, b in files:
            zi = zipfile.ZipInfo(n, EPOCH)
            zi.external_attr = 0o644 << 16
            zi.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(zi, b)
    return whl


def build_sdist(sdist_directory, config_settings=None):
    _, dist, version = _names()
    top = f"{dist}-{version}"
    name = f"{top}.tar.gz"
    pkg_info = _metadata().encode()
    with tarfile.open(os.path.join(sdist_directory, name), "w:gz", format=tarfile.PAX_FORMAT) as t:
        for rel in SDIST_FILES + ["PKG-INFO"]:
            if rel == "PKG-INFO":
                data = pkg_info
            else:
                with open(os.path.join(HERE, rel), "rb") as f:
                    data = f.read()
            ti = tarfile.TarInfo(f"{top}/{rel}")
            ti.size, ti.mode, ti.mtime = len(data), 0o644, 0
            t.addfile(ti, io.BytesIO(data))
    return name
