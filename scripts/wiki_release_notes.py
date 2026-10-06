#!/usr/bin/env python3
"""
Generate a wiki Release-Notes-vX.Y.md page from the matching CHANGELOG section.

Usage:
  scripts/wiki_release_notes.py                       # uses VERSION file
  scripts/wiki_release_notes.py 2.143
  scripts/wiki_release_notes.py 2.143 --wiki /path/to/wiki
  scripts/wiki_release_notes.py 2.143 --print         # write to stdout, not file
  scripts/wiki_release_notes.py 2.143 --force         # overwrite if exists

Pairs with scripts/update-wiki-versions.sh which bumps version-string
references in the wiki. This script handles the per-release notes page only.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Optional


def extract_changelog_section(changelog: Path, version: str) -> str:
    """Return the body of the `## [VERSION]` section of CHANGELOG.md (without the heading)."""
    if not changelog.is_file():
        raise SystemExit(f"CHANGELOG not found: {changelog}")

    lines = changelog.read_text(encoding="utf-8").splitlines()
    in_block = False
    heading: Optional[str] = None
    out: list[str] = []
    for line in lines:
        if line.startswith("## ["):
            if in_block:
                break
            if line.startswith(f"## [{version}]"):
                in_block = True
                heading = line
                continue
        if in_block:
            out.append(line)

    if not in_block:
        raise SystemExit(
            f"No '## [{version}]' section in {changelog}.\n"
            f"Add a dated changelog block first."
        )

    # Strip leading/trailing blank lines.
    while out and not out[0].strip():
        out.pop(0)
    while out and not out[-1].strip():
        out.pop()

    return (heading or "") + "\n\n" + "\n".join(out) + "\n"


def render_page(version: str, changelog_section: str, prev_version: Optional[str]) -> str:
    """Render the full Release-Notes wiki page."""
    prev_link = ""
    if prev_version:
        prev_label = f"v{prev_version}"
        prev_slug = f"Release-Notes-v{prev_version}"
        prev_link = (
            f"For the previous release see "
            f"[Release Notes {prev_label}]({prev_slug}) and the "
        )
    else:
        prev_link = "See the "

    body = (
        f"# Release Notes — v{version}\n\n"
        f"{prev_link}"
        f"[full CHANGELOG](https://github.com/NeySlim/ultimate-ca-manager/blob/main/CHANGELOG.md).\n\n"
        f"---\n\n"
        f"{changelog_section}"
    )
    return body


def find_previous_version(wiki_dir: Path, current_version: str) -> Optional[str]:
    """Look for the most recent Release-Notes-vX.Y.md (excluding current)."""
    candidates: list[tuple[tuple[int, ...], str]] = []
    for path in wiki_dir.glob("Release-Notes-v*.md"):
        ver = path.stem.removeprefix("Release-Notes-v")
        if ver == current_version:
            continue
        # parse only the leading "X.Y[.Z]" part for ordering; ignore beta/rc/range
        head = ver.split("-")[0].split("_")[0]
        try:
            tup = tuple(int(p) for p in head.split("."))
        except ValueError:
            continue
        candidates.append((tup, ver))
    if not candidates:
        return None
    candidates.sort()
    # Filter out versions newer than current
    try:
        cur_tup = tuple(int(p) for p in current_version.split("-")[0].split("."))
    except ValueError:
        cur_tup = ()
    older = [v for tup, v in candidates if tup < cur_tup]
    return older[-1] if older else None


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("version", nargs="?", help="Release version (defaults to VERSION file).")
    parser.add_argument("--repo", default=".", help="Repo root containing CHANGELOG.md and VERSION (default: cwd).")
    parser.add_argument("--wiki", default=os.environ.get("UCM_WIKI_DIR"), help="Wiki repo path (or set UCM_WIKI_DIR).")
    parser.add_argument("--prev", help="Previous version for the back-link (auto-detected if omitted).")
    parser.add_argument("--print", action="store_true", help="Print to stdout instead of writing a file.")
    parser.add_argument("--force", action="store_true", help="Overwrite existing Release-Notes-vX.Y.md.")
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    repo = Path(args.repo).resolve()

    version = args.version
    if not version:
        vf = repo / "VERSION"
        if not vf.is_file():
            raise SystemExit("No version arg and no VERSION file found.")
        version = vf.read_text(encoding="utf-8").strip()

    changelog = repo / "CHANGELOG.md"
    section = extract_changelog_section(changelog, version)

    if args.print:
        print(render_page(version, section, args.prev))
        return 0

    if not args.wiki:
        raise SystemExit("--wiki <path> required (or set UCM_WIKI_DIR), unless --print is used.")
    wiki_dir = Path(args.wiki).resolve()
    if not wiki_dir.is_dir():
        raise SystemExit(f"Wiki dir not found: {wiki_dir}")

    prev = args.prev or find_previous_version(wiki_dir, version)
    page = render_page(version, section, prev)

    out_path = wiki_dir / f"Release-Notes-v{version}.md"
    if out_path.exists() and not args.force:
        raise SystemExit(f"{out_path} already exists. Re-run with --force to overwrite.")
    out_path.write_text(page, encoding="utf-8")
    print(f"Wrote {out_path}")
    if prev:
        print(f"Linked back to v{prev}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
