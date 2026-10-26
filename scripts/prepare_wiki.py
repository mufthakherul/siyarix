#!/usr/bin/env python3
"""Regenerate wiki-staging/ flat pages from docs/ (source of truth).

Mapping:
  docs/index.md       -> wiki-staging/Home.md
  docs/DOCS_MAP.md    -> wiki-staging/_Sidebar.md
  docs/<dir>/<page>.md -> wiki-staging/<dir>-<page>.md

Also converts MkDocs admonitions to GitHub Wiki callouts and rewrites
internal links to flat wiki page names (no .md extension).
"""

from __future__ import annotations

import argparse
import os
import re
from pathlib import Path

# Root-level docs that must not be published to the GitHub Wiki.
SKIP_REL_PATHS = frozenset(
    {
        "PRODUCTION_READINESS.md",
    }
)

ADMONITION_TYPES = {
    "note": "NOTE",
    "abstract": "NOTE",
    "info": "IMPORTANT",
    "tip": "TIP",
    "success": "TIP",
    "question": "NOTE",
    "warning": "WARNING",
    "caution": "CAUTION",
    "danger": "CAUTION",
    "failure": "CAUTION",
    "bug": "CAUTION",
    "example": "NOTE",
    "quote": "NOTE",
    "important": "IMPORTANT",
}

ADMONITION_RE = re.compile(
    r'^!!!\s+(?P<type>\w+)(?:\s+"(?P<title>[^"]*)")?\s*$'
)
LINK_RE = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
FRONT_MATTER_RE = re.compile(r"^---\r?\n.*?\r?\n---\r?\n?", re.DOTALL)


def flatten_name(rel_path: str) -> str:
    """Convert a docs-relative path into a flat GitHub Wiki filename."""
    normalized = rel_path.replace("\\", "/")
    if normalized == "index.md":
        return "Home.md"
    if normalized == "DOCS_MAP.md":
        return "_Sidebar.md"
    return normalized.replace("/", "-").lower()


def strip_front_matter(content: str) -> str:
    """Remove MkDocs YAML front matter if present."""
    if content.startswith("---"):
        return FRONT_MATTER_RE.sub("", content, count=1)
    return content


def convert_admonitions(content: str) -> str:
    """Convert MkDocs ``!!! type`` admonitions to GitHub ``> [!TYPE]`` alerts."""
    lines = content.splitlines(keepends=True)
    out: list[str] = []
    i = 0

    while i < len(lines):
        line = lines[i]
        # Match without keeping newline in the pattern
        bare = line.rstrip("\r\n")
        match = ADMONITION_RE.match(bare)
        if not match:
            out.append(line)
            i += 1
            continue

        newline = "\n" if line.endswith("\n") or line.endswith("\r\n") else ""
        if line.endswith("\r\n"):
            newline = "\n"

        raw_type = match.group("type").lower()
        title = match.group("title")
        gh_type = ADMONITION_TYPES.get(raw_type, raw_type.upper())

        body_lines: list[str] = []
        i += 1
        while i < len(lines):
            body = lines[i]
            bare_body = body.rstrip("\r\n")
            if bare_body == "":
                # Blank line: part of admonition only if a following indented line exists.
                j = i + 1
                while j < len(lines) and lines[j].rstrip("\r\n") == "":
                    j += 1
                if j < len(lines) and (
                    lines[j].startswith("    ") or lines[j].startswith("\t")
                ):
                    body_lines.append("")
                    i += 1
                    continue
                break
            if bare_body.startswith("    "):
                body_lines.append(bare_body[4:])
                i += 1
                continue
            if bare_body.startswith("\t"):
                body_lines.append(bare_body[1:])
                i += 1
                continue
            break

        out.append(f"> [!{gh_type}]{newline}")
        if title:
            out.append(f"> **{title}**{newline}")
        if not body_lines:
            continue
        for bl in body_lines:
            if bl == "":
                out.append(f">{newline}")
            else:
                out.append(f"> {bl}{newline}")

    # Preserve trailing newline behavior of original when possible
    result = "".join(out)
    if content.endswith("\n") and not result.endswith("\n"):
        result += "\n"
    return result


def _normalize_docs_path(path: str) -> str:
    return path.replace("\\", "/").lstrip("./")


def build_link_index(path_map: dict[str, str]) -> dict[str, str]:
    """Map many link forms -> flat wiki filename."""
    index: dict[str, str] = {}
    for rel, flat in path_map.items():
        key = _normalize_docs_path(rel)
        index[key] = flat
        index[key.lower()] = flat
        if key.endswith(".md"):
            index[key[:-3]] = flat
            index[key[:-3].lower()] = flat
    return index


def resolve_wiki_target(
    link: str,
    src_rel: str,
    link_index: dict[str, str],
) -> str | None:
    """Resolve a markdown href to a flat wiki filename, or None if external/unmapped."""
    if link.startswith(("http://", "https://", "mailto:", "ftp:", "#")):
        return None
    if re.match(r"^[a-z]+://", link, re.I):
        return None

    base, _, anchor = link.partition("#")
    base = base.strip()
    if not base:
        return None  # pure in-page anchor
    if any(base.endswith(ext) for ext in (".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp")):
        return None

    src_dir = str(Path(_normalize_docs_path(src_rel)).parent)
    if src_dir in (".", ""):
        candidate = _normalize_docs_path(base)
    else:
        candidate = _normalize_docs_path(
            os.path.normpath(str(Path(src_dir) / base))
        )

    # Reject escapes above docs root
    if candidate.startswith(".."):
        return None

    for key in (
        candidate,
        candidate.lower(),
        f"{candidate}.md" if not candidate.endswith(".md") else candidate,
        f"{candidate}.md".lower() if not candidate.endswith(".md") else candidate.lower(),
    ):
        if key in link_index:
            return link_index[key]
    return None


def update_links(content: str, src_rel: str, link_index: dict[str, str]) -> str:
    """Rewrite internal docs links to flat GitHub Wiki page names (no .md)."""

    def replace_link(match: re.Match[str]) -> str:
        text = match.group(1)
        original = match.group(2)
        base, _, anchor = original.partition("#")
        target = resolve_wiki_target(base.strip() or original, src_rel, link_index)
        if target is None:
            # Still strip .md from already-flat relative wiki-ish links if present
            return match.group(0)
        wiki_name = os.path.splitext(target)[0]
        suffix = f"#{anchor}" if anchor else ""
        return f"[{text}]({wiki_name}{suffix})"

    return LINK_RE.sub(replace_link, content)


def transform_page(content: str, src_rel: str, link_index: dict[str, str]) -> str:
    """Apply full docs -> wiki-staging transform pipeline."""
    content = strip_front_matter(content)
    content = convert_admonitions(content)
    content = update_links(content, src_rel, link_index)
    # Normalize to LF for consistent hashes across platforms
    content = content.replace("\r\n", "\n")
    if content and not content.endswith("\n"):
        content += "\n"
    return content


def collect_path_map(src_dir: Path) -> dict[str, str]:
    """docs-relative path (forward slashes) -> flat wiki filename."""
    path_map: dict[str, str] = {}
    for path in sorted(src_dir.rglob("*.md")):
        rel = path.relative_to(src_dir).as_posix()
        if rel in SKIP_REL_PATHS:
            continue
        path_map[rel] = flatten_name(rel)
    return path_map


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Regenerate wiki-staging/ from docs/ (SoT)"
    )
    parser.add_argument("--src", default="docs", help="Source directory")
    parser.add_argument("--dest", default="wiki-staging", help="Destination directory")
    parser.add_argument(
        "--check",
        action="store_true",
        help="Report drift only; do not write files",
    )
    args = parser.parse_args()

    src_dir = Path(args.src)
    dest_dir = Path(args.dest)

    if not src_dir.is_dir():
        print(f"Error: Source directory {src_dir} does not exist.")
        return 1

    path_map = collect_path_map(src_dir)
    link_index = build_link_index(path_map)
    dest_dir.mkdir(parents=True, exist_ok=True)

    written = 0
    unchanged = 0
    drifted = 0

    for rel, flat_name in path_map.items():
        src_path = src_dir / rel
        dest_path = dest_dir / flat_name
        raw = src_path.read_text(encoding="utf-8")
        updated = transform_page(raw, rel, link_index)

        existing = (
            dest_path.read_text(encoding="utf-8").replace("\r\n", "\n")
            if dest_path.exists()
            else None
        )
        if existing == updated:
            unchanged += 1
            print(f"OK      {rel} -> {flat_name}")
            continue

        drifted += 1
        if args.check:
            print(f"DRIFT   {rel} -> {flat_name}")
            continue

        dest_path.write_text(updated, encoding="utf-8", newline="\n")
        written += 1
        print(f"SYNC    {rel} -> {flat_name}")

    # Home.md version guard: docs/index.md SoT must keep the wiki on v1.2.0.
    home = dest_dir / "Home.md"
    if home.exists() and not args.check:
        for line in home.read_text(encoding="utf-8").splitlines()[:15]:
            if line.startswith("# ") and "Documentation" in line and "v1.2.0" not in line:
                print(f"WARNING: Home.md title missing v1.2.0: {line}")
                break

    mode = "check" if args.check else "write"
    print(
        f"Wiki preparation complete ({mode}): "
        f"{len(path_map)} paired, {written} written, "
        f"{unchanged} already in sync, {drifted} drifted before sync."
    )
    return 1 if args.check and drifted else 0


if __name__ == "__main__":
    raise SystemExit(main())
