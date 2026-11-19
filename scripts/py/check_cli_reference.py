#!/usr/bin/env python3
"""Keep the command-line reference (docs/cli.md) equal to the tools' own help output.

The page holds one generated block per tool, between `<!-- BEGIN GENERATED: help <tool> -->` and
`<!-- END GENERATED -->`. Each block is the tool's top-level help followed by the help of every subcommand the
top-level help lists, captured from the built binaries:

    xdrcheck-corpus   target/release/xdrcheck-corpus   (`make build`)
    xdrcheck          go/bin/xdrcheck                  (`make build`)
    xdrlint      lint/bin/xdrlint            (`make build`)

Usage:
    check_cli_reference.py           compare the page with fresh help output; exit 1 on any difference
    check_cli_reference.py --write   rewrite the generated blocks in place

The page's table of make targets (rows starting with "| `make <target>`") must list exactly the targets that
`make help` prints: those of the Makefile and of every fragment it includes (mk/*.mk), which make help reads
through MAKEFILE_LIST. Help text is copied as printed, except that an internal work-item label in parentheses (the
form `(X-NN)` or `(task X-NN)`) is removed, since the page is public documentation. Exit codes: 0 equal (or
written), 1 the page differs, 2 a binary is missing or a marker pair is broken.
"""
import difflib
import os
import re
import subprocess
import sys

ROOT = subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip()
PAGE = os.path.join(ROOT, "docs", "cli.md")
TOOLS = [
    ("xdrcheck-corpus", "target/release/xdrcheck-corpus"),
    ("xdrcheck", "go/bin/xdrcheck"),
    ("xdrlint", "lint/bin/xdrlint"),
]
PLAN_LABEL = re.compile(r" ?\((?:task )?[A-Z]-\d{2}\)")
BLOCK = re.compile(r"(<!-- BEGIN GENERATED: help (?P<tool>[\w-]+) -->\n)(?P<body>.*?)(<!-- END GENERATED -->)", re.S)


def run(binary, args):
    env = dict(os.environ, COLUMNS="100", NO_COLOR="1", LC_ALL="C")
    # Flag defaults read from the environment would print the caller's own path into the help text.
    env.pop("XDRCHECK_OVERLAY", None)
    env.pop("XCC_OVERLAY", None)  # the earlier name, which the tools still read
    p = subprocess.run([os.path.join(ROOT, binary)] + args, cwd=ROOT, env=env, capture_output=True, text=True)
    out = (p.stdout + p.stderr).replace("\r\n", "\n")
    out = "\n".join(PLAN_LABEL.sub("", line).rstrip() for line in out.split("\n"))
    return out.strip("\n") + "\n"


def section(title, text):
    return f"#### `{title}`\n\n```text\n{text}```\n"


def corpus_subcommands(top):
    subs, inside = [], False
    for line in top.split("\n"):
        if line.startswith("Commands:"):
            inside = True
            continue
        if inside:
            m = re.match(r"^  ([a-z][a-z0-9-]*)\s{2,}", line)
            if not m:
                break
            if m.group(1) != "help":
                subs.append(m.group(1))
    return subs


def xdrcheck_groups(top):
    groups, inside = [], False
    for line in top.split("\n"):
        if line.startswith("commands:"):
            inside = True
            continue
        if inside:
            m = re.match(r"^  ([a-z][a-z0-9-]*)\s+", line)
            if not m:
                break
            groups.append(m.group(1))
    return groups


def generate(tool, binary):
    parts = []
    if tool == "xdrcheck-corpus":
        top = run(binary, ["--help"])
        parts.append(section("xdrcheck-corpus --help", top))
        for sub in corpus_subcommands(top):
            parts.append(section(f"xdrcheck-corpus {sub} --help", run(binary, [sub, "--help"])))
    elif tool == "xdrcheck":
        top = run(binary, ["--help"])
        parts.append(section("xdrcheck --help", top))
        for group in xdrcheck_groups(top):
            text = run(binary, [group, "--help"])
            parts.append(section(f"xdrcheck {group} --help", text))
            m = re.match(rf"usage: xdrcheck {group} ([a-z0-9|-]+) ", text)
            if m and "|" in m.group(1):
                for sub in m.group(1).split("|"):
                    parts.append(section(f"xdrcheck {group} {sub} --help", run(binary, [group, sub, "--help"])))
    else:
        parts.append(section(f"{tool} -h", run(binary, ["-h"])))
    return "\n".join(parts) + "\n"


def main():
    write = sys.argv[1:] == ["--write"]
    if sys.argv[1:] and not write:
        print(__doc__, file=sys.stderr)
        return 2
    missing = [b for _, b in TOOLS if not os.access(os.path.join(ROOT, b), os.X_OK)]
    if missing:
        print(f"check_cli_reference: not built: {', '.join(missing)} (run make build)", file=sys.stderr)
        return 2
    page = open(PAGE, encoding="utf-8").read()
    found = {m.group("tool") for m in BLOCK.finditer(page)}
    wanted = {t for t, _ in TOOLS}
    if found != wanted:
        print(f"check_cli_reference: {PAGE}: generated blocks {sorted(found)}, expected {sorted(wanted)}", file=sys.stderr)
        return 2
    help_targets = set(re.findall(r"^([a-z][a-z0-9-]*)\s", subprocess.check_output(["make", "-s", "help"], cwd=ROOT, text=True), re.M))
    page_targets = set(re.findall(r"^\| `make ([a-z][a-z0-9-]*)", page, re.M))
    if help_targets != page_targets:
        print(f"check_cli_reference: make targets missing from docs/cli.md: {sorted(help_targets - page_targets)}; "
              f"listed but not in `make help`: {sorted(page_targets - help_targets)}")
        return 1
    fresh = {t: generate(t, b) for t, b in TOOLS}
    new = BLOCK.sub(lambda m: m.group(1) + "\n" + fresh[m.group("tool")] + m.group(4), page)
    if write:
        if new != page:
            open(PAGE, "w", encoding="utf-8").write(new)
        print("check_cli_reference: docs/cli.md written")
        return 0
    if new != page:
        sys.stdout.writelines(difflib.unified_diff(page.splitlines(True), new.splitlines(True), "docs/cli.md", "help output"))
        print("check_cli_reference: docs/cli.md differs from the tools' help; run scripts/py/check_cli_reference.py --write")
        return 1
    print("check_cli_reference: docs/cli.md matches the help of xdrcheck-corpus, xdrcheck and xdrlint")
    return 0


if __name__ == "__main__":
    sys.exit(main())
