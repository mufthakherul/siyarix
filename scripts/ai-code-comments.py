#!/usr/bin/env python3
"""
AI Code Comments Generator
Uses local Ollama LLM to add inline comments to code

Usage:
    python ai-code-comments.py --target src --style detailed
    python ai-code-comments.py --file myfile.py --dry-run
    python ai-code-comments.py --all --model mistral

Requirements:
    pip install requests click rich

Setup Ollama:
    1. Install: curl -fsSL https://ollama.com/install.sh | sh
    2. Start: ollama serve
    3. Pull model: ollama pull codellama
"""

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    import requests
except ImportError:
    print("Error: 'requests' package required. Run: pip install requests click rich")
    sys.exit(1)

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
    from rich.table import Table

    rich_available = True
except ImportError:
    rich_available = False


@dataclass
class Config:
    """Configuration for comment generation"""

    ollama_host: str = "http://localhost:11434"
    model: str = "codellama"
    style: str = "standard"
    scope: str = "all"
    output_language: str = "en"
    dry_run: bool = False
    verbose: bool = False
    max_file_size: int = 51200
    temperature: float = 0.2
    top_p: float = 0.95
    max_tokens: int = 512
    exclude_patterns: List[str] = None

    def __post_init__(self):
        if self.exclude_patterns is None:
            self.exclude_patterns = [
                "node_modules",
                "venv",
                ".venv",
                "__pycache__",
                ".git",
                "dist",
                "build",
                ".egg-info",
                ".mypy_cache",
                ".ruff_cache",
            ]


class LanguageConfig:
    """Language-specific configurations"""

    COMMENT_SYNTAX = {
        "python": "#",
        "javascript": "//",
        "typescript": "//",
        "go": "//",
        "rust": "//",
        "java": "//",
        "csharp": "//",
        "cpp": "//",
        "c": "//",
        "ruby": "#",
        "php": "//",
        "swift": "//",
        "kotlin": "//",
        "shell": "#",
        "powershell": "#",
        "sql": "--",
        "yaml": "#",
        "html": "<!--",
        "css": "/*",
        "scss": "//",
    }

    DOCSTRING_STYLES = {
        "google": '''"""{name}
{description}

Args:
    {args}

Returns:
    {returns}
"""
''',
        "numpy": '''"""
{name}
{description}

Parameters
----------
{args}

Returns
-------
{returns}
"""
''',
        "docstring": '''"""
{name}
{description}

Args:
    {args}

Returns:
    {returns}
"""
''',
    }


class OllamaClient:
    """Client for Ollama API"""

    def __init__(
        self,
        host: str,
        model: str,
        temperature: float = 0.2,
        top_p: float = 0.95,
        max_tokens: int = 512,
    ):
        self.host = host
        self.model = model
        self.temperature = temperature
        self.top_p = top_p
        self.max_tokens = max_tokens

    def generate(self, prompt: str) -> Optional[str]:
        """Generate response from LLM"""
        try:
            response = requests.post(
                f"{self.host}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": self.temperature,
                        "top_p": self.top_p,
                        "num_predict": self.max_tokens,
                    },
                },
                timeout=180,
            )
            if response.status_code == 200:
                return response.json().get("response", "").strip()
            else:
                print(f"Error: Ollama returned {response.status_code}")
                return None
        except requests.exceptions.ConnectionError:
            print(f"Error: Cannot connect to Ollama at {self.host}")
            print("Make sure Ollama is running: ollama serve")
            return None
        except Exception as e:
            print(f"Error calling Ollama: {e}")
            return None


class CodeAnalyzer:
    """Analyze code structure"""

    PYTHON_PATTERNS = {
        "function": r"(?:async\s+)?def\s+(\w+)\s*\(([^)]*)\)\s*(?:->\s*(\w+))?:",
        "class": r"^class\s+(\w+)(?:\(([^)]+)\))?:",
        "method": r"^\s{4,}def\s+(\w+)\s*\(([^)]*)\)",
    }

    JS_PATTERNS = {
        "function": r"(?:async\s+)?function\s+(\w+)\s*\(",
        "arrow": r"(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?\([^)]*\)\s*=>",
        "method": r"(?:async\s+)?(\w+)\s*\([^)]*\)\s*\{",
        "class": r"class\s+(\w+)\s*(?:extends\s+(\w+))?",
    }

    GO_PATTERNS = {
        "function": r"func\s+(?:\(\w+\s+\*?\w+\)\s+)?(\w+)\s*\(",
        "method": r"func\s+\((\w+)\s+\*?(\w+)\)\s+(\w+)\s*\(",
    }

    RUST_PATTERNS = {
        "function": r"fn\s+(\w+)\s*<[^>]*>\s*\([^)]*\)",
        "method": r"fn\s+(\w+)\s*\([^)]*\)",
        "struct": r"struct\s+(\w+)",
        "impl": r"impl(?:\s+<[^>]+>)?\s+(\w+)",
    }

    @staticmethod
    def get_language(path: str) -> str:
        """Detect language from file extension"""
        ext = Path(path).suffix.lower().lstrip(".")
        lang_map = {
            "py": "python",
            "js": "javascript",
            "ts": "typescript",
            "jsx": "javascript",
            "tsx": "typescript",
            "go": "go",
            "rs": "rust",
            "java": "java",
            "cs": "csharp",
            "cpp": "cpp",
            "cc": "cpp",
            "c": "c",
            "h": "c",
            "rb": "ruby",
            "php": "php",
            "swift": "swift",
            "kt": "kotlin",
            "sh": "shell",
            "bash": "shell",
            "ps1": "powershell",
            "sql": "sql",
            "yml": "yaml",
            "yaml": "yaml",
            "html": "html",
            "htm": "html",
            "css": "css",
            "scss": "scss",
        }
        return lang_map.get(ext, "unknown")

    @staticmethod
    def extract_elements(code: str, language: str) -> List[Dict]:
        """Extract code elements based on language"""
        elements = []

        if language == "python":
            for match in re.finditer(
                CodeAnalyzer.PYTHON_PATTERNS["function"], code, re.MULTILINE
            ):
                elements.append(
                    {
                        "type": "function",
                        "name": match.group(1),
                        "params": match.group(2),
                        "return": match.group(3) or "None",
                        "line": code[: match.start()].count("\n") + 1,
                    }
                )
            for match in re.finditer(
                CodeAnalyzer.PYTHON_PATTERNS["class"], code, re.MULTILINE
            ):
                elements.append(
                    {
                        "type": "class",
                        "name": match.group(1),
                        "bases": match.group(2) or "",
                        "line": code[: match.start()].count("\n") + 1,
                    }
                )

        elif language in ["javascript", "typescript"]:
            for match in re.finditer(CodeAnalyzer.JS_PATTERNS["function"], code):
                elements.append(
                    {
                        "type": "function",
                        "name": match.group(1),
                        "line": code[: match.start()].count("\n") + 1,
                    }
                )
            for match in re.finditer(CodeAnalyzer.JS_PATTERNS["arrow"], code):
                elements.append(
                    {
                        "type": "arrow_function",
                        "name": match.group(1),
                        "line": code[: match.start()].count("\n") + 1,
                    }
                )

        elif language == "go":
            for match in re.finditer(CodeAnalyzer.GO_PATTERNS["function"], code):
                elements.append(
                    {
                        "type": "function",
                        "name": match.group(1),
                        "line": code[: match.start()].count("\n") + 1,
                    }
                )

        elif language == "rust":
            for match in re.finditer(CodeAnalyzer.RUST_PATTERNS["function"], code):
                elements.append(
                    {
                        "type": "function",
                        "name": match.group(1),
                        "line": code[: match.start()].count("\n") + 1,
                    }
                )
            for match in re.finditer(CodeAnalyzer.RUST_PATTERNS["struct"], code):
                elements.append(
                    {
                        "type": "struct",
                        "name": match.group(1),
                        "line": code[: match.start()].count("\n") + 1,
                    }
                )

        return elements


class CommentGenerator:
    """Generate comments for code elements"""

    TEMPLATES = {
        "minimal": "# {name}\n",
        "standard": "# {name}: {description}\n",
        "detailed": "# {name}\n# {description}\n# Args: {args}\n# Returns: {returns}\n",
    }

    def __init__(
        self, client: OllamaClient, style: str, output_language: str, scope: str
    ):
        self.client = client
        self.style = style
        self.output_language = output_language
        self.scope = scope
        self.lang_config = LanguageConfig()

    def generate(self, element: Dict, language: str, full_code: str) -> Optional[str]:
        """Generate comment for a code element"""
        prompt = f"""Generate a {self.style} comment for this {language} code element.
The comment should be helpful, concise, and accurate.

Element: {element.get('type', 'unknown')}
Name: {element.get('name', 'unknown')}
Params: {element.get('params', 'N/A')}
Return: {element.get('return', 'N/A')}

Code snippet (first 300 chars):
{full_code[:300]}

Output language: {self.output_language}

Output ONLY the comment text, no code blocks or explanations. Start directly with the comment."""

        return self.client.generate(prompt)

    def apply_comment(
        self, lines: List[str], line_num: int, comment: str, language: str
    ) -> List[str]:
        """Apply comment to code"""
        syntax = self.lang_config.COMMENT_SYNTAX.get(language, "#")

        if self.style in ["docstring", "google", "numpy"] and language == "python":
            # Use docstring format for Python
            docstring = self.lang_config.DOCSTRING_STYLES.get(
                self.style, self.lang_config.DOCSTRING_STYLES["docstring"]
            )
            # Format docstring - simplified version
            comment_block = f'    """{comment}"""'
            lines.insert(line_num, comment_block)
        else:
            # Use line comment
            comment_lines = [
                f"{syntax} {line}" for line in comment.split("\n") if line.strip()
            ]
            for i, cl in enumerate(comment_lines):
                lines.insert(line_num + i, cl)

        return lines


class CodeCommentApp:
    """Main application class"""

    def __init__(self, config: Config):
        self.config = config
        self.client = OllamaClient(
            config.ollama_host,
            config.model,
            config.temperature,
            config.top_p,
            config.max_tokens,
        )
        self.analyzer = CodeAnalyzer()
        self.generator = CommentGenerator(
            self.client, config.style, config.output_language, config.scope
        )
        self.console = Console() if rich_available else None

    def scan_files(self, target: str) -> List[str]:
        """Scan for files to process"""
        files = []
        target_path = Path(target)

        if target_path.is_file():
            return [str(target_path)]

        if not target_path.is_dir():
            return []

        # Common code file extensions
        extensions = [
            ".py",
            ".js",
            ".ts",
            ".jsx",
            ".tsx",
            ".go",
            ".rs",
            ".java",
            ".cs",
            ".cpp",
            ".c",
            ".h",
            ".rb",
            ".php",
            ".swift",
            ".kt",
            ".sh",
            ".ps1",
            ".sql",
            ".yml",
            ".yaml",
        ]

        for ext in extensions:
            for f in target_path.rglob(f"*{ext}"):
                # Check exclusions
                excluded = any(ex in str(f) for ex in self.config.exclude_patterns)
                if not excluded:
                    files.append(str(f))

        return sorted(files)

    def process_file(self, filepath: str) -> Tuple[bool, str]:
        """Process a single file"""
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                original = f.read()

            if len(original) > self.config.max_file_size:
                if self.config.verbose:
                    print(
                        f"Skipping {filepath}: file too large ({len(original)} bytes)"
                    )
                return False, ""

            language = self.analyzer.get_language(filepath)
            if language == "unknown":
                return False, ""

            elements = self.analyzer.extract_elements(original, language)
            if not elements:
                return False, ""

            # Filter by scope
            if self.config.scope != "all":
                elements = [e for e in elements if e["type"] == self.config.scope]

            lines = original.split("\n")
            modified = False
            offset = 0

            for elem in elements[:10]:  # Limit per file
                line_num = elem["line"] - 1 + offset

                if line_num >= len(lines):
                    continue

                # Skip if line already has comment
                syntax = LanguageConfig.COMMENT_SYNTAX.get(language, "#")
                if lines[line_num].strip().startswith(syntax):
                    continue

                comment = self.generator.generate(elem, language, original)
                if comment:
                    lines = self.generator.apply_comment(
                        lines, line_num, comment, language
                    )
                    offset += len(comment.split("\n"))
                    modified = True

            return modified, "\n".join(lines)

        except Exception as e:
            if self.config.verbose:
                print(f"Error processing {filepath}: {e}")
            return False, ""

    def run(self, target: str) -> Dict:
        """Run the comment generation"""
        files = self.scan_files(target)

        if not files:
            return {"status": "error", "message": "No files found to process"}

        results = {
            "status": "success",
            "files_scanned": len(files),
            "files_modified": 0,
            "modified_files": [],
            "errors": [],
        }

        for i, filepath in enumerate(files):
            if self.config.verbose:
                print(f"Processing {i+1}/{len(files)}: {filepath}")

            modified, new_content = self.process_file(filepath)

            if modified and not self.config.dry_run:
                # Create backup
                backup_path = filepath + ".bak"
                with open(filepath, "r", encoding="utf-8") as f:
                    original = f.read()
                with open(backup_path, "w", encoding="utf-8") as f:
                    f.write(original)

                # Write new content
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write(new_content)

                results["files_modified"] += 1
                results["modified_files"].append(filepath)
            elif modified and self.config.dry_run:
                results["files_modified"] += 1
                results["modified_files"].append(filepath + " (dry-run)")

        return results


def create_parser() -> argparse.ArgumentParser:
    """Create command line parser"""
    parser = argparse.ArgumentParser(
        description="AI Code Comments Generator - Add inline comments using local LLM",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Comment all Python files in src directory
  python ai-code-comments.py --target src --style detailed

  # Comment a specific file (dry run)
  python ai-code-comments.py --file myfile.py --dry-run

  # Use different model
  python ai-code-comments.py --target . --model mistral

  # Generate docstrings
  python ai-code-comments.py --target src --style docstring

  # Run on all code files
  python ai-code-comments.py --target . --scope functions

Setup:
  1. Install Ollama: curl -fsSL https://ollama.com/install.sh | sh
  2. Start: ollama serve
  3. Pull model: ollama pull codellama
        """,
    )

    parser.add_argument(
        "--target",
        "-t",
        default="src",
        help='Target file, directory, or "all" (default: src)',
    )
    parser.add_argument("--file", "-f", default="", help="Specific file to process")
    parser.add_argument(
        "--style",
        "-s",
        choices=["minimal", "standard", "detailed", "docstring", "google", "numpy"],
        default="standard",
        help="Comment style (default: standard)",
    )
    parser.add_argument(
        "--scope",
        choices=["functions", "classes", "all"],
        default="all",
        help="What to comment (default: all)",
    )
    parser.add_argument(
        "--model", "-m", default="codellama", help="Ollama model (default: codellama)"
    )
    parser.add_argument(
        "--ollama-host",
        default="http://localhost:11434",
        help="Ollama host (default: http://localhost:11434)",
    )
    parser.add_argument(
        "--language",
        "-l",
        default="en",
        help="Output language for comments (default: en)",
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Preview changes without writing"
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument(
        "--temperature", type=float, default=0.2, help="LLM temperature (default: 0.2)"
    )
    parser.add_argument(
        "--max-tokens",
        type=int,
        default=512,
        help="Max tokens to generate (default: 512)",
    )

    return parser


def main():
    """Main entry point"""
    parser = create_parser()
    args = parser.parse_args()

    # Determine target
    target = args.file if args.file else args.target
    if not target:
        parser.error("No target specified. Use --target or --file")

    # Create config
    config = Config(
        ollama_host=args.ollama_host,
        model=args.model,
        style=args.style,
        scope=args.scope,
        output_language=args.language,
        dry_run=args.dry_run,
        verbose=args.verbose,
        temperature=args.temperature,
        max_tokens=args.max_tokens,
    )

    # Run app
    app = CodeCommentApp(config)
    results = app.run(target)

    # Output results
    if rich_available:
        console = Console()
        if results["status"] == "success":
            table = Table(title="AI Code Comments Results")
            table.add_column("Metric", style="cyan")
            table.add_column("Value", style="green")

            table.add_row("Files Scanned", str(results["files_scanned"]))
            table.add_row("Files Modified", str(results["files_modified"]))
            table.add_row("Status", "✅ Success")

            console.print(table)

            if results["modified_files"]:
                console.print("\n[bold]Modified files:[/bold]")
                for f in results["modified_files"]:
                    console.print(f"  • {f}")
        else:
            console.print(f"[bold red]Error:[/bold red] {results['message']}")
    else:
        print(json.dumps(results, indent=2))

    # Exit with appropriate code
    sys.exit(0 if results["status"] == "success" else 1)


if __name__ == "__main__":
    main()
