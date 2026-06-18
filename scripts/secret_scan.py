#!/usr/bin/env python3
"""
secret_scan.py — fail-closed pre-commit/CI guard against committing secrets.

Scope: catches the failure mode this project actually risks — leaking the
Semantic Scholar API key, which must live ONLY in the OS keychain / env, never
in git — plus common high-signal credential formats. It is deliberately
high-precision: it flags literal secret VALUES, not variable names or env
lookups. (The launcher reads SEMANTIC_SCHOLAR_API_KEY from the keychain, which
is correct and must not trip the scanner.)

Exit non-zero if a likely secret is found, so it can gate a commit/push.
Append `pragma: allowlist secret` to a line to suppress a known false positive.

Usage:
    python scripts/secret_scan.py FILE [FILE ...]
    python scripts/secret_scan.py              # scan staged files, else tracked
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ALLOW = "pragma: allowlist secret"

# Structural patterns — value formats that are almost always a real credential.
PATTERNS = [
    (
        "private key block",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
    ),
    ("github token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("github fine-grained pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b")),
    ("aws access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("openai-style key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("google api key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
]

# The project-specific risk: a literal S2 key assigned to the env var. An env
# lookup / keychain read is not a literal and must not trip.
RE_S2 = re.compile(r"""SEMANTIC_SCHOLAR_API_KEY\s*[=:]\s*["']([^"'\n]{8,})["']""")

# Generic secret-ish var assigned a long literal that is not a placeholder.
RE_GENERIC = re.compile(
    r"""(?ix)\b(?:api[_-]?key|secret|token|password|passwd|client[_-]?secret|access[_-]?key)\b"""
    r"""\s*[=:]\s*["']([^"'\n]{16,})["']"""
)
PLACEHOLDER = re.compile(
    r"(?i)(x{4,}|your[_-]|example|placeholder|redacted|dummy|fake|test|sample|"
    r"<[^>]+>|\$\{|\bos\.|getenv|environ|changeme|none|null|\.\.\.)"
)


def looks_real(value: str) -> bool:
    if PLACEHOLDER.search(value):
        return False
    if len(set(value)) < 6:  # e.g. "aaaaaaaa" or "--------"
        return False
    classes = sum(
        bool(re.search(p, value)) for p in (r"[a-z]", r"[A-Z0-9]", r"[^A-Za-z0-9]")
    )
    return classes >= 2


def scan_line(line: str):
    hits = [name for name, rx in PATTERNS if rx.search(line)]
    m = RE_S2.search(line)
    if m and looks_real(m.group(1)):
        hits.append("Semantic Scholar API key literal")
    m = RE_GENERIC.search(line)
    if m and looks_real(m.group(1)):
        hits.append("hardcoded credential literal")
    return hits


def iter_files(argv):
    if argv:
        return [Path(a) for a in argv]
    try:
        staged = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
            capture_output=True,
            text=True,
        ).stdout.split()
        if staged:
            return [Path(p) for p in staged]
        tracked = subprocess.run(
            ["git", "ls-files"], capture_output=True, text=True
        ).stdout.split()
        return [Path(p) for p in tracked]
    except Exception:
        return []


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    findings = []
    for p in iter_files(argv):
        if not p.is_file():
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        for n, line in enumerate(text.splitlines(), 1):
            if ALLOW in line:
                continue
            for hit in scan_line(line):
                findings.append((str(p), n, hit, line.strip()[:80]))
    for path, n, hit, _snippet in findings:
        print(f"  SECRET  {path}:{n}: {hit}")
    if findings:
        print(
            f"\n{len(findings)} potential secret(s) found — refusing. Move secrets to the "
            f"keychain/env; append '{ALLOW}' to whitelist a confirmed false positive."
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
