#!/usr/bin/env python3
"""
Mnemosyne version bumper — updates every version string across the core repo.

Usage:
    python scripts/bump_version.py 2.8.0 2.9.0
    python scripts/bump_version.py 2.8.0 2.9.0 --commit   (commit + push)
    python scripts/bump_version.py 2.8.0 2.9.0 --dry-run   (show what would change)

This replaces grep-and-replace guesswork with a deterministic file list.
After running, it verifies no stale OLD version remains and prints a summary.
"""

import argparse
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# ── File registry: every file that carries a version string ────────────────
# Format: (path_from_repo_root, pattern_to_replace)
# pattern should contain {old} and {new} placeholders, or be a function

FILES = [
    # Source of truth
    ("mnemosyne/__init__.py",              '__version__ = "{old}"'),
    # README badges
    ("README.md",                          '?v={old}'),           # PyPI badge cache-buster
    # Plugin YAMLs
    ("hermes_plugin/plugin.yaml",          'version: {old}'),
    ("hermes_memory_provider/plugin.yaml", 'version: {old}'),
    # Docs
    ("docs/api-reference.md",              'v{old}'),
    ("docs/comparison.md",                 'v{old}'),
    # Devops guide example
    ("DEVOPS.md",                          '__version__ = "{old}"'),
    # Generated surface file
    ("mnemosyne_codebase_surface.json",    '"version": "{old}"'),
]


def bump_version(old: str, new: str, dry_run: bool = False) -> list[str]:
    """Replace old version with new in all registered files. Returns list of changed files."""
    changed = []
    for rel_path, pattern in FILES:
        filepath = REPO_ROOT / rel_path
        if not filepath.exists():
            print(f"  SKIP (not found): {rel_path}")
            continue

        original = filepath.read_text(encoding="utf-8")
        old_pattern = pattern.format(old=old)
        new_pattern = pattern.format(old=new)

        if old_pattern not in original:
            print(f"  SKIP (pattern not found): {rel_path}  (searched: {old_pattern[:60]})")
            continue

        updated = original.replace(old_pattern, new_pattern, 1)
        if updated == original:
            print(f"  SKIP (no change): {rel_path}")
            continue

        if dry_run:
            print(f"  WOULD UPDATE: {rel_path}")
        else:
            filepath.write_text(updated, encoding="utf-8")
            print(f"  UPDATED: {rel_path}")

        changed.append(rel_path)

    return changed


def verify_no_stale_version(old: str) -> int:
    """Grep the repo for stale old version strings. Returns count of remaining hits."""
    ignore_dirs = "|".join([
        "node_modules", "__pycache__", ".git", "venv", ".venv",
        "dist", "out", ".planning", "results"
    ])
    cmd = (
        f"cd {REPO_ROOT} && "
        f"grep -rn '{old}' . "
        f"--include='*.py' --include='*.md' --include='*.yaml' --include='*.json' --include='*.toml' "
        f"| grep -vE '({ignore_dirs})' "
        f"| grep -v 'model.*M{old}' "    # Model names like MiniMax-M2.7
        f"| grep -v '\\.{old}\\.'"        # QPS numbers like 2.795
        f"|| true"
    )
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
    hits = [l for l in result.stdout.strip().split("\n") if l]
    return hits


def main():
    parser = argparse.ArgumentParser(description="Bump Mnemosyne version across all files")
    parser.add_argument("old_version", help="Current version (e.g. 2.8.0)")
    parser.add_argument("new_version", help="New version (e.g. 2.9.0)")
    parser.add_argument("--dry-run", action="store_true", help="Show what would change without writing")
    parser.add_argument("--commit", action="store_true", help="Commit and push after bumping")
    args = parser.parse_args()

    old = args.old_version
    new = args.new_version

    print(f"Bumping version: {old} → {new}\n")

    # Step 1: Bump files
    changed = bump_version(old, new, dry_run=args.dry_run)
    print(f"\n{len(changed)} files changed")

    if args.dry_run:
        return

    if not changed:
        print("Nothing to bump. Already at target version?")
        return

    # Step 2: Verify
    print("\nVerifying no stale references remain...")
    stale = verify_no_stale_version(old)
    if stale:
        print(f"\n⚠️  WARNING: {len(stale)} potential stale references found:")
        for line in stale[:15]:
            print(f"  {line}")
        if len(stale) > 15:
            print(f"  ... and {len(stale) - 15} more")
        print("\nReview these manually before tagging. Some may be legitimate (historical CHANGELOG, benchmark data, model names).")
    else:
        print("  ✓ No stale references found")

    # Step 3: Commit (optional)
    if args.commit:
        print("\nCommitting and pushing...")
        subprocess.run(
            ["git", "add"] + [str(REPO_ROOT / f) for f in changed],
            cwd=REPO_ROOT, check=True
        )
        subprocess.run(
            ["git", "commit", "-m", f"chore: bump version {old} → {new}",
             "-m", f"Updated version strings across {len(changed)} files"],
            cwd=REPO_ROOT, check=True
        )
        subprocess.run(["git", "push"], cwd=REPO_ROOT, check=True)
        print(f"  ✓ Committed and pushed: {old} → {new}")
    else:
        print("\nReady to commit. Run with --commit to auto-commit and push.")

    print(f"\nNext: cd {REPO_ROOT} && git tag -a v{new} -m 'Release v{new}' && git push origin v{new}")


if __name__ == "__main__":
    main()
