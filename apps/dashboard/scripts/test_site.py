#!/usr/bin/env python3
"""Offline checks of the two static sites (apps/dashboard/site, apps/landing/site). Standard library only.

- every data file loads, carries its schema, and the cross references inside it resolve (entries named by rows
  and findings, finding IDs named by entries, CAP rows named by findings);
- every relative link and asset in the HTML, CSS and JavaScript points at a file that exists;
- every hash route the pages build (`#/view/...`) names a view the dashboard has, and every view module exists;
- no page loads anything from another origin: the only absolute URLs are plain links (`<a href>`), and those are
  the documentation site, the landing, the dashboard and the issues this kit filed;
- the JavaScript parses (`node --check`, when node is installed);
- the landing's numbers come from its data file: no digit run of four or more in its HTML text;
- every command the pages print (the replay and conformance lines on entry, CAP and sibling pages) names an
  `xdrcheck` subcommand and flags that the command-line reference (docs/cli.md) documents, and every pipeline
  commit it names is pinned in pins.toml;
- every data file a view fetches exists, and every view has a tab or is reached from one;
- a self-hosted font ships with its licence text.

Usage: test_site.py   (exit 1 on any problem)
"""
import json, os, re, shlex, shutil, subprocess, sys, tomllib

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".."))
DASH = os.path.join(ROOT, "apps/dashboard/site")
LAND = os.path.join(ROOT, "apps/landing/site")
problems = []


def bad(msg):
    problems.append(msg)


def files(base, exts):
    for d, _, fs in os.walk(base):
        for f in fs:
            if f.endswith(exts):
                yield os.path.join(d, f)


def load(name):
    with open(os.path.join(DASH, "data", name), encoding="utf-8") as f:
        return json.load(f)


def check_data():
    data = {n: load(n + ".json") for n in ("summary", "scan", "corpus", "findings", "matrix", "replay", "siblings")}
    for n, d in data.items():
        if not str(d.get("schema", "")).startswith("xdrcheck.site."):
            bad(f"data/{n}.json: no site schema")
    entries = {e["id"] for e in data["corpus"]["entries"]}
    rows = {r["group"] for r in data["corpus"]["rows"]}
    findings = {f["id"] for f in data["findings"]["findings"]}
    for r in data["corpus"]["rows"]:
        for e in r["entries"]:
            if e not in entries:
                bad(f"row {r['group']} names unknown entry {e}")
        for f in r["findings"]:
            if f not in findings:
                bad(f"row {r['group']} names unknown finding {f}")
    for e in data["corpus"]["entries"]:
        for f in e["findings"]:
            if f not in findings:
                bad(f"entry {e['id']} names unknown finding {f}")
        for g in e["rows"]:
            if g not in rows:
                bad(f"entry {e['id']} names unknown row {g}")
    for f in data["findings"]["findings"]:
        for e in f["entries"]:
            if e not in entries:
                bad(f"{f['id']} names unknown entry {e}")
        if f["upstream"] and f["upstream"]["kind"] == "filed" and f["state"] != "filed":
            bad(f"{f['id']} links an issue but is not filed")
        if f["state"] != "filed" and f["upstream"] and "url" in f["upstream"]:
            bad(f"{f['id']} carries an upstream URL but was not filed by this kit")
    s = data["summary"]
    if s["corpus"]["entries"] != len(entries):
        bad("summary entry count differs from corpus.json")
    if s["findings"]["records"] != len(findings):
        bad("summary finding count differs from findings.json")
    with open(os.path.join(LAND, "data", "summary.json"), encoding="utf-8") as f:
        if json.load(f) != s:
            bad("the landing's summary.json differs from the dashboard's")
    allowed = set(s["links"].values()) | {f["upstream"]["url"] for f in data["findings"]["findings"]
                                         if f["upstream"] and f["upstream"]["kind"] == "filed"}
    return data, allowed


VIEWS = None


def check_routes():
    global VIEWS
    app = open(os.path.join(DASH, "js/app.js"), encoding="utf-8").read()
    m = re.search(r"const VIEWS = \{(.*?)\};", app, re.S)
    VIEWS = dict(re.findall(r"(\w+): \"(\w+)\"", m.group(1)))
    for name, mod in VIEWS.items():
        if not os.path.isfile(os.path.join(DASH, "js/views", mod + ".js")):
            bad(f"route {name}: js/views/{mod}.js is missing")
    for path in files(DASH, (".js", ".html")):
        text = open(path, encoding="utf-8").read()
        for v in re.findall(r"href\(\"(\w+)\"", text) + re.findall(r"href=\"(?:\./)?#/(\w+)", text):
            if v not in VIEWS:
                bad(f"{os.path.relpath(path, ROOT)}: route #/{v} names no view")


ABS = re.compile(r"""(?:https?:)?//[^\s"'`)<>]+""")


def check_links(base, allowed):
    for path in files(base, (".html", ".css", ".js")):
        rel = os.path.relpath(path, ROOT)
        text = open(path, encoding="utf-8").read()
        # assets and links relative to the page
        refs = re.findall(r"""(?:src|href)=["']([^"'#]+)["']""", text) + re.findall(r"""url\(["']?([^"')]+)["']?\)""", text)
        refs += re.findall(r"""import\(?\s*["'](\.[^"']+\.js)["']""", text) + re.findall(r"""from\s+["'](\.[^"']+)["']""", text)
        for ref in refs:
            if ref.startswith(("http:", "https:", "//", "data:", "mailto:")):
                continue
            target = os.path.normpath(os.path.join(os.path.dirname(path) if not ref.startswith("/") else base, ref.lstrip("/")))
            if ref.endswith("/"):
                target = os.path.join(target, "index.html")
            if not os.path.exists(target):
                bad(f"{rel}: {ref} does not exist")
        # nothing loaded from another origin
        for m in re.finditer(r"""<(?:script|link|img|iframe|source|video|audio)\b[^>]*\b(?:src|href)=["']((?:https?:)?//[^"']+)""", text):
            if 'rel="canonical"' not in m.group(0):
                bad(f"{rel}: loads {m.group(1)} from another origin")
        if path.endswith(".css") and re.search(r"@import|url\(\s*[\"']?(?:https?:)?//", text):
            bad(f"{rel}: stylesheet loads from another origin")
        if path.endswith(".js") and re.search(r"fetch\(\s*[\"'`](?:https?:)?//", text):
            bad(f"{rel}: script fetches from another origin")
        for u in ABS.findall(text):
            u = u.rstrip(".,;").split("#")[0]
            if u.startswith("//") or "www.w3.org/2000/svg" in u or u.startswith("http://localhost"):
                continue
            if u not in allowed and u.rstrip("/") + "/" not in allowed and not (path.endswith(".html") and 'rel="canonical" href="' + u in text):
                bad(f"{rel}: absolute URL {u} is not one of the site links")


def check_js():
    node = shutil.which("node")
    if not node:
        print("test_site: node not found, JavaScript syntax not checked")
        return
    for path in files(DASH, (".js",)):
        r = subprocess.run([node, "--check", path], capture_output=True, text=True)
        if r.returncode:
            bad(f"{os.path.relpath(path, ROOT)}: {r.stderr.strip().splitlines()[-1] if r.stderr.strip() else 'syntax error'}")
    for path in files(LAND, (".js",)):
        r = subprocess.run([node, "--check", path], capture_output=True, text=True)
        if r.returncode:
            bad(f"{os.path.relpath(path, ROOT)}: syntax error")


def check_landing_numbers():
    html = open(os.path.join(LAND, "index.html"), encoding="utf-8").read()
    text = re.sub(r"<(script|style)\b.*?</\1>", "", html, flags=re.S)
    text = re.sub(r"<[^>]+>", " ", text)
    for m in re.finditer(r"\d[\d,.]{3,}", text):
        bad(f"apps/landing/site/index.html: number {m.group(0)!r} typed into the page; read it from data/summary.json")


def cli_flags():
    """{"xdrcheck replay": {"adapter", ...}, ...} from the --help blocks of docs/cli.md."""
    text = open(os.path.join(ROOT, "docs/cli.md"), encoding="utf-8").read()
    out = {}
    for m in re.finditer(r"#### `([\w -]+?) --help`\n+```text\n(.*?)```", text, re.S):
        out[m.group(1)] = set(re.findall(r"^\s+-{1,2}([a-z][\w-]*)", m.group(2), re.M))
    return out


def check_commands(data):
    helps = cli_flags()
    pins = tomllib.load(open(os.path.join(ROOT, "pins.toml"), "rb"))["pipelines"]
    commits = {pins["stellar_etl"]["commit"], pins["wallet_backend"]["current"]}
    commits |= {x for a in pins["wallet_backend"]["acceptance"] for x in (a["prefix"], a["fixed"])}
    corpus = data["corpus"]
    cmds = [(k, t["cmd"].replace("{id}", "cap-0040/signed-payload-signer-added")) for k, t in corpus["cli"].items()]
    cmds += [(r["group"], c["cmd"]) for r in corpus["rows"] for c in r["cli"]]
    sib = open(os.path.join(DASH, "js/views/siblings.js"), encoding="utf-8").read()
    cmds += [("siblings.js", "xdrcheck " + c.split('"')[0] + "F-0001") for c in re.findall(r'cmd: "xdrcheck ([^"]+--finding )"', sib)]
    if not any("siblings" in c for _, c in cmds):
        bad("siblings.js: the siblings command was not found to check")
    for where, cmd in cmds:
        words = shlex.split(cmd)
        if words[0] != "xdrcheck":
            bad(f"{where}: command does not start with xdrcheck: {cmd}")
            continue
        key = next((" ".join(words[:n]) for n in (3, 2) if " ".join(words[:n]) in helps), None)
        if not key:
            bad(f"{where}: no --help block in docs/cli.md for {' '.join(words[:3])}")
            continue
        for w in words:
            if w.startswith("-"):
                f = w.lstrip("-").split("=")[0]
                if f not in helps[key]:
                    bad(f"{where}: {key} has no flag --{f} in docs/cli.md")
        if "--target-version" in words:
            v = words[words.index("--target-version") + 1]
            if v != "dev" and v not in commits:
                bad(f"{where}: --target-version {v} is not a commit pinned in pins.toml")
    for e in corpus["entries"]:
        for k in e["cli"]:
            if k not in corpus["cli"]:
                bad(f"entry {e['id']}: command template {k} is not defined")


def check_views(data):
    app = open(os.path.join(DASH, "js/app.js"), encoding="utf-8").read()
    html = open(os.path.join(DASH, "index.html"), encoding="utf-8").read()
    m = re.search(r"const NEEDS = \{(.*?)\};", app, re.S)
    for view, names in re.findall(r"(\w+): \[([^\]]*)\]", m.group(1)):
        for n in re.findall(r'"(\w+)"', names):
            if not os.path.isfile(os.path.join(DASH, "data", n + ".json")):
                bad(f"view {view} fetches data/{n}.json, which does not exist")
        if f'data-view="{view}"' not in html:
            bad(f"view {view} has no tab in index.html")
    for base in (DASH, LAND):
        fonts = os.path.join(base, "fonts")
        if os.path.isdir(fonts) and any(f.endswith((".woff2", ".woff", ".ttf")) for f in os.listdir(fonts)):
            if not os.path.isfile(os.path.join(fonts, "OFL.txt")):
                bad(f"{os.path.relpath(fonts, ROOT)}: fonts without their licence text")


def check_landing_keys(summary):
    """Every figure the landing fills (data-k, data-list) resolves in summary.json."""
    html = open(os.path.join(LAND, "index.html"), encoding="utf-8").read()
    for attr, path in re.findall(r'data-(k|list)="([^"]+)"', html):
        v = summary
        for k in path.split("."):
            v = len(v) if k == "length" and isinstance(v, list) else (v.get(k) if isinstance(v, dict) else None)
        if attr == "k" and not isinstance(v, (int, str)) or attr == "list" and not isinstance(v, list):
            bad(f"apps/landing/site/index.html: data-{attr}=\"{path}\" does not resolve in summary.json")


def main():
    data, allowed = check_data()
    check_commands(data)
    check_views(data)
    check_landing_keys(data["summary"])
    check_routes()
    check_links(DASH, allowed)
    check_links(LAND, allowed)
    check_js()
    check_landing_numbers()
    for p in problems:
        print("test_site: " + p, file=sys.stderr)
    print(f"test_site: {len(problems)} problem(s)" if problems else "test_site: both sites pass")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
