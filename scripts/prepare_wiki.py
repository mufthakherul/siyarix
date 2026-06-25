import os
import re
import shutil
import argparse
from pathlib import Path


def flatten_name(path: str, root_dir: str) -> str:
    """
    Converts a nested path into a flat name.
    Example: architecture/overview.md -> architecture-overview.md
    Special cases: index.md -> Home.md, DOCS_MAP.md -> _Sidebar.md
    """
    rel_path = os.path.relpath(path, root_dir)

    if rel_path == "index.md":
        return "Home.md"
    if rel_path == "DOCS_MAP.md":
        return "_Sidebar.md"

    # Replace separators with dashes and lowercase everything
    flat_name = rel_path.replace(os.sep, "-").lower()
    return flat_name


def update_links(content: str, path_map: dict[str, str]) -> str:
    """
    Updates markdown links from nested paths to flattened wiki paths.
    GitHub Wiki links should NOT have the .md extension and should be relative.
    """
    # Regex to find markdown links [text](path)
    link_pattern = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")

    def replace_link(match):
        text = match.group(1)
        original_link = match.group(2)

        # Skip external links
        if original_link.startswith(("http", "https", "mailto:", "ftp:")):
            return match.group(0)

        # Remove anchors for matching
        base_link = original_link.split("#")[0]
        anchor = f"#{original_link.split('#')[1]}" if "#" in original_link else ""

        # If the link is in our map, replace it
        matched_key = None
        for key in path_map:
            if (
                key.endswith(base_link.replace("/", os.sep))
                or base_link.replace("/", os.sep) == key
            ):
                matched_key = key
                break

        if matched_key:
            new_name = path_map[matched_key]
            wiki_link_name = os.path.splitext(new_name)[0]
            return f"[{text}]({wiki_link_name}{anchor})"

        return match.group(0)

    return link_pattern.sub(replace_link, content)


def main():
    parser = argparse.ArgumentParser(description="Flatten docs for GitHub Wiki")
    parser.add_argument("--src", default="docs", help="Source directory")
    parser.add_argument("--dest", default="wiki-staging", help="Destination directory")
    args = parser.parse_args()

    src_dir = Path(args.src)
    dest_dir = Path(args.dest)

    if not src_dir.exists():
        print(f"Error: Source directory {src_dir} does not exist.")
        return

    if dest_dir.exists():
        shutil.rmtree(dest_dir)
    dest_dir.mkdir(parents=True)

    # 1. Map all files to their new flat names
    path_map = {}  # Original relative path -> New flat name
    for root, dirs, files in os.walk(src_dir):
        for file in files:
            if file.endswith(".md"):
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, src_dir)
                new_name = flatten_name(full_path, src_dir)
                path_map[rel_path] = new_name

    # 2. Process and copy files
    for rel_path, new_name in path_map.items():
        src_path = src_dir / rel_path
        dest_path = dest_dir / new_name

        print(f"Processing {rel_path} -> {new_name}")

        with open(src_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Update internal links
        updated_content = update_links(content, path_map)

        with open(dest_path, "w", encoding="utf-8") as f:
            f.write(updated_content)

    print("Wiki preparation complete.")


if __name__ == "__main__":
    main()
