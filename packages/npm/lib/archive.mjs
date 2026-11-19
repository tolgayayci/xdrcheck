// Finding and reading the corpus release archive (docs/release.md): a gzip-compressed ustar file with one
// top-level directory and two corpus roots, corpus/ and stress/. The archive is read into memory and never
// extracted, so the runner needs no tar program and writes nothing.
import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { gunzipSync } from "node:zlib";

/** The package's own directory (holding release.json and, when embedded, archive/). */
export const PACKAGE_DIR = join(dirname(fileURLToPath(import.meta.url)), "..");

export class ToolError extends Error {}

const sha256 = (b) => createHash("sha256").update(b).digest("hex");

/** release.json, written by pack.sh: the archive's name, version, sha256 and size. */
export function releaseInfo(pkgDir = PACKAGE_DIR) {
  const p = join(pkgDir, "release.json");
  if (!existsSync(p)) throw new ToolError(`${p} is missing: this package was not packed by pack.sh`);
  return JSON.parse(readFileSync(p, "utf8"));
}

/** Files of a ustar (or GNU tar) stream as a Map from path to bytes; directories are left out. */
export function untar(buf) {
  const files = new Map();
  const str = (b) => {
    const i = b.indexOf(0);
    return b.subarray(0, i < 0 ? b.length : i).toString("utf8");
  };
  let longName = null;
  for (let off = 0; off + 512 <= buf.length; ) {
    const h = buf.subarray(off, off + 512);
    if (h.every((x) => x === 0)) break;
    const size = parseInt(str(h.subarray(124, 136)).trim() || "0", 8);
    const type = String.fromCharCode(h[156] || 0x30);
    const prefix = str(h.subarray(345, 500));
    let name = longName ?? (prefix ? `${prefix}/${str(h.subarray(0, 100))}` : str(h.subarray(0, 100)));
    longName = null;
    const data = buf.subarray(off + 512, off + 512 + size);
    off += 512 + Math.ceil(size / 512) * 512;
    if (type === "L") {
      longName = str(data);
    } else if (type === "x") {
      const m = data.toString("utf8").match(/(?:^|\n)\d+ path=([^\n]*)\n/);
      if (m) longName = m[1];
    } else if (type === "0" || type === "\0") {
      files.set(name, data);
    } else if (type !== "5" && type !== "g") {
      throw new ToolError(`archive member ${name}: unsupported tar entry type ${JSON.stringify(type)}`);
    }
  }
  return files;
}

/**
 * A read-only view of one release: `read(root, path)` and `list(root, prefix)` over the corpus roots `corpus`
 * and `stress`. From the archive (verified against release.json) or from an extracted top-level directory.
 */
export function openRelease({ archive, dir, pkgDir = PACKAGE_DIR } = {}) {
  if (dir) return dirRelease(dir);
  const info = releaseInfo(pkgDir);
  const path = archive ?? join(pkgDir, "archive", info.archive);
  if (!existsSync(path)) {
    throw new ToolError(`the release archive ${path} is not there; pass --archive PATH (${info.archive}, sha256 ${info.sha256})`);
  }
  const gz = readFileSync(path);
  const got = sha256(gz);
  if (got !== info.sha256) {
    throw new ToolError(`${path}: sha256 ${got}, but this package was packed for ${info.archive} with sha256 ${info.sha256}`);
  }
  const files = untar(gunzipSync(gz));
  const top = info.top;
  const read = (root, p) => {
    const b = files.get(`${top}/${root}/${p}`);
    if (!b) throw new ToolError(`${root}/${p} is not in the archive`);
    return b;
  };
  const list = (root, prefix) => {
    const head = `${top}/${root}/${prefix}`;
    return [...files.keys()].filter((k) => k.startsWith(head)).map((k) => k.slice(top.length + root.length + 2)).sort();
  };
  return { source: `${path} (sha256 ${got})`, version: info.version, read, list };
}

function dirRelease(dir) {
  const read = (root, p) => {
    try {
      return readFileSync(join(dir, root, p));
    } catch (e) {
      throw new ToolError(`${root}/${p}: ${e.message}`);
    }
  };
  const list = (root, prefix) => {
    const base = join(dir, root);
    const out = [];
    const walk = (d) => {
      if (!existsSync(d)) return;
      for (const n of readdirSync(d)) {
        const p = join(d, n);
        if (statSync(p).isDirectory()) walk(p);
        else out.push(relative(base, p).split(sep).join("/"));
      }
    };
    walk(join(base, prefix));
    return out.filter((p) => p.startsWith(prefix)).sort();
  };
  let version = "unknown";
  try {
    version = JSON.parse(readFileSync(join(dir, "PROVENANCE.json"), "utf8")).version;
  } catch {
    // an extracted directory without provenance: version unknown
  }
  return { source: dir, version, read, list };
}

/** Every manifest entry of a corpus root, as { id, root, json }. */
export function entries(release, root) {
  return release
    .list(root, "manifest/")
    .filter((p) => p.endsWith(".json"))
    .map((p) => ({ id: p.slice("manifest/".length, -".json".length), root, json: JSON.parse(release.read(root, p)) }));
}

/** A variant's blob, checked against its stated sha256 and length. */
export function blob(release, root, variant) {
  const sha = variant.blob?.sha256 ?? "";
  const p = variant.blob?.path ?? `blobs/${sha.slice(0, 2)}/${sha}.xdr`;
  const b = release.read(root, p);
  if (sha256(b) !== sha || (variant.blob?.bytes != null && b.length !== variant.blob.bytes)) {
    throw new ToolError(`${root}/${p}: does not match the manifest's sha256 and length`);
  }
  return b;
}
