"""Survey the public MCP server ecosystem with mcp-audit.

Harvests MCP server repositories from public curated lists, shallow-clones a
deterministic sample, runs the scanner over each, and aggregates the results.

Safety properties (these matter — we're pulling arbitrary third-party code):
  * Cloned repositories are NEVER executed, imported, or built. They are only
    read as text by the scanner.
  * Clones are shallow (--depth 1) and deleted immediately after scanning.
  * The sample is seeded, so a given --sample-size reproduces the same set.

Usage:
    python research/ecosystem_scan.py --sample-size 100 --out research/results.json
"""
from __future__ import annotations

import argparse
import json
import random
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from collections import Counter
from pathlib import Path

SOURCE_LISTS = [
    "https://raw.githubusercontent.com/punkpeye/awesome-mcp-servers/main/README.md",
    "https://raw.githubusercontent.com/wong2/awesome-mcp-servers/main/README.md",
]

REPO_RE = re.compile(r"https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:[)#?/]|\.git|$)")

# Aggregators, spec repos, and SDKs — not MCP *servers*, would skew the survey.
EXCLUDE_OWNERS = {"modelcontextprotocol", "punkpeye", "wong2", "appcypher", "github"}
EXCLUDE_REPO_WORDS = {"awesome", "spec", "sdk", "docs", "registry", "directory", "list"}

CLONE_TIMEOUT_S = 90
SCAN_TIMEOUT_S = 120


def harvest_repos() -> list[str]:
    """Return de-duplicated 'owner/repo' strings from the curated lists."""
    seen: dict[str, None] = {}
    for url in SOURCE_LISTS:
        try:
            with urllib.request.urlopen(url, timeout=60) as resp:
                text = resp.read().decode("utf-8", errors="ignore")
        except Exception as exc:  # noqa: BLE001 - best effort, keep going
            print(f"  ! could not fetch {url}: {exc}", file=sys.stderr)
            continue
        for owner, repo in REPO_RE.findall(text):
            owner_l, repo_l = owner.lower(), repo.lower()
            if owner_l in EXCLUDE_OWNERS:
                continue
            if any(word in repo_l for word in EXCLUDE_REPO_WORDS):
                continue
            seen.setdefault(f"{owner}/{repo}", None)
    return list(seen)


def scan_repo(slug: str, workdir: Path) -> dict | None:
    """Shallow-clone and scan one repo. Returns a result dict, or None on failure."""
    dest = workdir / slug.replace("/", "__")
    clone = subprocess.run(
        ["git", "clone", "--depth", "1", "--quiet", f"https://github.com/{slug}.git", str(dest)],
        capture_output=True, text=True, timeout=CLONE_TIMEOUT_S,
    )
    if clone.returncode != 0:
        return None

    try:
        proc = subprocess.run(
            [sys.executable, "-m", "mcp_audit", "scan", str(dest), "--format", "json"],
            capture_output=True, text=True, timeout=SCAN_TIMEOUT_S,
        )
        # Exit 0 = clean, exit 1 = findings at/above --fail-on. Anything else is
        # the scanner falling over, which must NOT be recorded as "clean" — an
        # earlier version of this script did exactly that and silently turned
        # crashes into zero-finding rows, corrupting the survey in both
        # directions.
        if proc.returncode not in (0, 1):
            return {"repo": slug, "error": f"exit {proc.returncode}: {proc.stderr.strip()[:200]}"}
        if not proc.stdout.strip():
            return {"repo": slug, "error": "empty output"}

        findings = json.loads(proc.stdout)
        # Strip local absolute paths — we publish aggregates, not filesystem layout.
        for f in findings:
            f["file"] = str(Path(f["file"]).relative_to(dest)) if str(dest) in f["file"] else f["file"]
        return {"repo": slug, "findings": findings}
    except subprocess.TimeoutExpired:
        return {"repo": slug, "error": f"timeout after {SCAN_TIMEOUT_S}s"}
    except (json.JSONDecodeError, ValueError) as exc:
        return {"repo": slug, "error": f"unparseable output: {exc}"}
    finally:
        shutil.rmtree(dest, ignore_errors=True)


def aggregate(results: list[dict]) -> dict:
    rule_counts: Counter = Counter()
    severity_counts: Counter = Counter()
    repos_with_finding = 0
    repos_by_rule: Counter = Counter()

    scanned = [r for r in results if "findings" in r]
    errored = [r for r in results if "error" in r]

    for r in scanned:
        findings = r["findings"]
        if findings:
            repos_with_finding += 1
        for rule in {f["rule_id"] for f in findings}:
            repos_by_rule[rule] += 1
        for f in findings:
            rule_counts[f["rule_id"]] += 1
            severity_counts[f["severity"]] += 1

    n = len(scanned)
    return {
        "repos_scanned_successfully": n,
        "repos_errored": len(errored),
        "error_reasons": dict(Counter(r["error"].split(":")[0] for r in errored)),
        "repos_with_at_least_one_finding": repos_with_finding,
        "pct_repos_with_finding": round(100 * repos_with_finding / n, 1) if n else 0.0,
        "total_findings": sum(rule_counts.values()),
        "findings_by_rule": dict(rule_counts.most_common()),
        "repos_affected_by_rule": dict(repos_by_rule.most_common()),
        "findings_by_severity": dict(severity_counts),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sample-size", type=int, default=100)
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--out", type=Path, default=Path("research/results.json"))
    args = parser.parse_args()

    print("Harvesting repository list...")
    repos = harvest_repos()
    print(f"  found {len(repos)} candidate MCP server repositories")

    random.Random(args.seed).shuffle(repos)
    sample = repos[: args.sample_size]
    print(f"  sampling {len(sample)} (seed={args.seed})\n")

    results: list[dict] = []
    unclonable = 0
    with tempfile.TemporaryDirectory(prefix="mcp_eco_") as tmp:
        workdir = Path(tmp)
        for i, slug in enumerate(sample, start=1):
            res = scan_repo(slug, workdir)
            if res is None:
                unclonable += 1
                print(f"[{i}/{len(sample)}] {slug}: skipped (clone failed)", flush=True)
                continue
            results.append(res)
            if "error" in res:
                print(f"[{i}/{len(sample)}] {slug}: SCAN ERROR — {res['error'][:80]}", flush=True)
            else:
                print(f"[{i}/{len(sample)}] {slug}: {len(res['findings'])} finding(s)", flush=True)

    summary = aggregate(results)
    summary["repos_unclonable"] = unclonable
    summary["sample_size_requested"] = args.sample_size
    summary["seed"] = args.seed
    summary["candidate_pool_size"] = len(repos)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps({"summary": summary, "results": results}, indent=2), encoding="utf-8")

    print("\n=== SUMMARY ===")
    print(json.dumps(summary, indent=2))
    print(f"\nwrote {args.out}")


if __name__ == "__main__":
    main()
