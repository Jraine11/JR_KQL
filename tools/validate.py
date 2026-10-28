#!/usr/bin/env python3
"""Validate the query library, and optionally sync embedded snippets.

Checks:
  - every query has a header with the required keys for its type
  - every parameter listed in the header is defined with `let`
  - IDs are unique
  - snippets embedded in queries match their master copy in functions/
  - detections filter on their own Lookback window
  - no tracked file contains a term from local/denylist.txt (if that file exists)

Usage:
  python3 tools/validate.py          # check only, exit 1 on problems
  python3 tools/validate.py --sync   # rewrite embedded snippets from functions/, then check
"""
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
QUERY_DIRS = ["functions", "identity", "malware"]
DENYLIST = ROOT / "local" / "denylist.txt"

BASE_KEYS = {"id", "name", "type", "status", "time_column", "tables", "requires", "parameters"}
TYPE_KEYS = {
    "snippet": set(),
    "investigate": {"entities"},
    "hunt": {"entities"},
    "detect": {"entities", "severity", "frequency", "tactics", "mitre"},
}
HEADER_LINE = re.compile(r"^// (\w+):\s+(.*)$")
BLOCK = r"// BEGIN {name}\n.*?// END {name}\n"


def header(text):
    keys = {}
    for line in text.splitlines():
        m = HEADER_LINE.match(line)
        if not m:
            break
        keys[m[1]] = m[2].strip()
    return keys


def listed(value):
    return [v.strip() for v in value.split(",") if v.strip() and v.strip() != "none"]


def snippet_block(text, name):
    m = re.search(BLOCK.format(name=re.escape(name)), text, re.S)
    return m[0] if m else None


def main():
    sync = "--sync" in sys.argv
    errors = []
    files = sorted(p for d in QUERY_DIRS for p in (ROOT / d).rglob("*.kql"))
    snippets = {p.stem: snippet_block(p.read_text(), p.stem) for p in (ROOT / "functions").glob("*.kql")}
    seen_ids = {}

    for path in files:
        rel = path.relative_to(ROOT)
        text = path.read_text()
        hdr = header(text)
        qtype = hdr.get("type", "")

        missing = (BASE_KEYS | TYPE_KEYS.get(qtype, set())) - hdr.keys()
        if qtype not in TYPE_KEYS:
            errors.append(f"{rel}: unknown type '{qtype}'")
        if missing:
            errors.append(f"{rel}: header missing {sorted(missing)}")
        seen_ids.setdefault(hdr.get("id"), []).append(rel)

        for param in listed(hdr.get("parameters", "none")):
            if not re.search(rf"^let {param}\s*=", text, re.M):
                errors.append(f"{rel}: parameter '{param}' is not defined with let")

        for name in listed(hdr.get("requires", "none")):
            master = snippets.get(name)
            if master is None:
                errors.append(f"{rel}: requires unknown snippet '{name}'")
                continue
            copy = snippet_block(text, name)
            if copy is None:
                errors.append(f"{rel}: requires '{name}' but has no BEGIN/END {name} block")
            elif copy != master:
                if sync:
                    text = text.replace(copy, master)
                    path.write_text(text)
                    print(f"synced {name} into {rel}")
                else:
                    errors.append(f"{rel}: embedded '{name}' differs from functions/{name}.kql (run --sync)")

        if qtype == "detect" and not re.search(r"ago\(Lookback\)", text):
            errors.append(f"{rel}: detection does not filter on ago(Lookback)")

    for qid, paths in seen_ids.items():
        if len(paths) > 1:
            errors.append(f"duplicate id {qid}: {', '.join(map(str, paths))}")

    if DENYLIST.exists():
        terms = [t.strip().lower() for t in DENYLIST.read_text().splitlines() if t.strip() and not t.startswith("#")]
        tracked = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True).stdout.split()
        for name in tracked:
            path = ROOT / name
            if name.startswith("local/") or not path.is_file():
                continue
            for n, line in enumerate(path.read_text(errors="ignore").splitlines(), 1):
                for term in terms:
                    if term in line.lower():
                        errors.append(f"{name}:{n}: contains denylisted term")

    for e in errors:
        print("ERROR", e)
    print(f"{len(files)} queries checked, {len(errors)} problem(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
