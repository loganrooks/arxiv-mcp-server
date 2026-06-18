#!/usr/bin/env python3
"""
check_citations.py — deterministic citation guardrail (a resolver/linter).

Enforces this project's citation policy (see docs/governance/review-protocol.md).

SCOPE — what this does and does NOT establish:
  * It checks WELL-FORMEDNESS (no opaque tokens, valid IDs) and, with --online,
    RESOLVABILITY (the locator points to a real record). In ledger terms it can
    support a `Resolved` label.
  * It does NOT check `Concordant` (does the source say what we claim it says)
    or `Corroborated` (does the source actually support the claim) — those are
    human/agent judgements, done separately in Phase 4. A green run means the
    citations resolve, NOT that they are correct or that they support anything.

OFFLINE (default, no network): structural checks that catch the failures we
actually inherited —
  * opaque citation tokens (ChatGPT's `citeturn… / fileciteturn… / turnNNlabelN`
    artifacts), which resolve to nothing outside the original session;
  * malformed arXiv-style identifiers;
  * a summary of every resolvable locator (arXiv ID, DOI, URL) found.
Exit code is non-zero if any opaque token is found (policy violation), so this
can gate a run in CI / a pre-commit hook.

ONLINE (--online): additionally resolves each arXiv ID against the public arXiv
API and HEAD-checks each URL. Stdlib only (urllib). Run this locally — it makes
network requests.

Usage:
    python check_citations.py FILE [FILE ...]
    python check_citations.py --online report.md
    python check_citations.py --json report.md
"""

from __future__ import annotations
import argparse, json, re, sys, time
from pathlib import Path

# --- patterns -------------------------------------------------------------
# Opaque tokens: the ChatGPT deep-research citation artifacts. They look like
# `citeturn40view0`, `fileciteturn0file0`, `turn39academia0`, and often run
# together: `citeturn40view0turn39academia0`.
RE_OPAQUE = re.compile(
    r"(?:file)?cite(?:turn[0-9a-z]+)+|turn\d+(?:view|academia|search|file|image|news)\d+",
    re.I,
)
# arXiv IDs: 4-digit YYMM . 4-or-5 digits, optional version.
RE_ARXIV = re.compile(r"\b(\d{4})\.(\d{4,5})(v\d+)?\b")
RE_ARXIV_URL = re.compile(r"arxiv\.org/(?:abs|pdf)/(\d{4}\.\d{4,5})(v\d+)?", re.I)
RE_DOI = re.compile(r"\b10\.\d{4,9}/[-._;()/:A-Za-z0-9]+\b")
RE_URL = re.compile(r"https?://[^\s)\]>\"']+")
# Code spans/fences are "mention, not use": a token quoted in backticks to be
# *discussed* is not a citation. Strip them before the opaque-token scan so the
# guardrail flags tokens used AS citations, not prose that talks about them.
RE_FENCE = re.compile(r"```.*?```", re.S)
RE_INLINE = re.compile(r"`[^`]*`")

ARXIV_API = "http://export.arxiv.org/api/query?id_list={}"


def strip_code(text: str) -> str:
    return RE_INLINE.sub(" ", RE_FENCE.sub(" ", text))


def scan_text(text: str) -> dict:
    prose = strip_code(text)  # opaque tokens only count when used, not quoted
    opaque = sorted(set(m.group(0) for m in RE_OPAQUE.finditer(prose)))
    arxiv = sorted(set(f"{a}.{b}{c or ''}" for a, b, c in RE_ARXIV.findall(text)))
    arxiv_urls = sorted(set(f"{a}{b or ''}" for a, b in RE_ARXIV_URL.findall(text)))
    dois = sorted(set(RE_DOI.findall(text)))
    urls = sorted(set(RE_URL.findall(text)))
    # arXiv-ish strings that are *almost* IDs (e.g. truncated) -> flag as malformed
    malformed = sorted(set(re.findall(r"\b\d{4}\.\d{1,3}\b", text)))
    return {
        "opaque_tokens": opaque,
        "arxiv_ids": sorted(set(arxiv) | set(arxiv_urls)),
        "dois": dois,
        "urls": urls,
        "malformed_arxiv": malformed,
    }


def resolve_arxiv(arxiv_id: str) -> bool:
    import urllib.request

    bare = arxiv_id.split("v")[0]
    try:
        with urllib.request.urlopen(ARXIV_API.format(bare), timeout=20) as r:
            body = r.read().decode("utf-8", "replace")
        # arXiv returns an Atom feed; a real hit contains an <entry> with the id.
        return ("<entry>" in body) and (bare in body)
    except Exception:
        return False


def head_ok(url: str) -> bool:
    import urllib.request, urllib.error

    req = urllib.request.Request(
        url, method="HEAD", headers={"User-Agent": "check_citations/1.0"}
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return 200 <= r.status < 400
    except urllib.error.HTTPError as e:
        return 200 <= e.code < 400
    except Exception:
        return False


def check_file(path: Path, online: bool) -> dict:
    if not path.is_file():
        return {
            "file": str(path),
            "opaque_tokens": [],
            "arxiv_ids": [],
            "dois": [],
            "urls": [],
            "malformed_arxiv": [],
            "errors": [f"file not found: {path}"],
            "warnings": [],
        }
    text = path.read_text(encoding="utf-8", errors="replace")
    res = scan_text(text)
    res["file"] = str(path)
    res["errors"] = []
    res["warnings"] = []
    if res["opaque_tokens"]:
        res["errors"].append(
            f"{len(res['opaque_tokens'])} opaque citation token(s) — unresolvable, policy violation "
            f"(e.g. {', '.join(res['opaque_tokens'][:3])})"
        )
    if res["malformed_arxiv"]:
        res["warnings"].append(
            f"{len(res['malformed_arxiv'])} possible malformed arXiv id(s): {res['malformed_arxiv'][:5]}"
        )
    if not res["arxiv_ids"] and not res["dois"] and not res["urls"]:
        res["warnings"].append("no resolvable locators (arXiv/DOI/URL) found at all")
    if online:
        res["unresolved_arxiv"] = [a for a in res["arxiv_ids"] if not resolve_arxiv(a)]
        if res["unresolved_arxiv"]:
            res["errors"].append(
                f"{len(res['unresolved_arxiv'])} arXiv id(s) did not resolve: {res['unresolved_arxiv']}"
            )
        dead = [u for u in res["urls"] if not head_ok(u)]
        res["dead_urls"] = dead
        if dead:
            res["warnings"].append(
                f"{len(dead)} URL(s) failed a HEAD check (may be transient): {dead[:5]}"
            )
            time.sleep(0)  # placeholder politeness hook
    return res


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Deterministic citation guardrail.")
    ap.add_argument("files", nargs="+", type=Path)
    ap.add_argument(
        "--online",
        action="store_true",
        help="resolve arXiv IDs and HEAD-check URLs (network)",
    )
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv)

    results = [check_file(p, args.online) for p in args.files]
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            print(f"\n=== {r['file']} ===")
            print(
                f"  arXiv IDs : {len(r['arxiv_ids'])}   DOIs: {len(r['dois'])}   URLs: {len(r['urls'])}"
            )
            print(f"  opaque tokens : {len(r['opaque_tokens'])}")
            if args.online:
                print(
                    f"  unresolved arXiv : {len(r.get('unresolved_arxiv', []))}   dead URLs: {len(r.get('dead_urls', []))}"
                )
            for e in r["errors"]:
                print(f"  ERROR   {e}")
            for w in r["warnings"]:
                print(f"  warn    {w}")
            if not r["errors"]:
                print("  PASS (no policy violations)")
    failed = any(r["errors"] for r in results)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
