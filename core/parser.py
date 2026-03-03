"""
Enhanced Code Parser.
Extracts code context from the target directory with improved filtering and metadata.
"""
import os
from pathlib import Path
from .constants import SUPPORTED_EXTENSIONS, SKIP_DIRECTORIES


class CodeParser:
    def __init__(self, target_dir):
        self.target_dir = Path(target_dir).resolve()

    def get_all_files(self):
        """Walk the directory and collect all supported source files."""
        code_files = []
        for root, dirs, files in os.walk(self.target_dir):
            # Filter out skip directories in-place
            dirs[:] = [d for d in dirs if d not in SKIP_DIRECTORIES]

            for file in files:
                ext = Path(file).suffix
                if ext in SUPPORTED_EXTENSIONS:
                    code_files.append(Path(root) / file)
        return code_files

    def extract_context(self, max_chars: int = 100000) -> str:
        """
        Extract code context from the target directory.
        Respects max_chars to avoid overloading LLM context windows.
        """
        if not self.target_dir.exists() or not self.target_dir.is_dir():
            print(f"[-] Invalid target directory: {self.target_dir}")
            return ""

        files = self.get_all_files()
        context_blocks = []
        total_chars = 0

        # Sort files: entry points first, then by size (smaller first)
        priority_names = {"main.py", "app.py", "index.js", "server.js", "main.go",
                          "app.rb", "index.ts", "main.java"}

        def sort_key(f):
            name = f.name
            is_priority = 0 if name in priority_names else 1
            try:
                size = f.stat().st_size
            except OSError:
                size = 0
            return (is_priority, size)

        files.sort(key=sort_key)

        for file in files:
            try:
                with open(file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                if total_chars + len(content) > max_chars:
                    # Truncate large files
                    remaining = max_chars - total_chars
                    if remaining > 500:
                        content = content[:remaining] + "\n... [TRUNCATED]"
                    else:
                        break

                rel_path = file.relative_to(self.target_dir)
                line_count = content.count('\n')
                context_blocks.append(
                    f"--- FILE: {rel_path} ({line_count} lines) ---\n{content}\n"
                )
                total_chars += len(content)

            except Exception as e:
                print(f"[-] Error reading {file}: {e}")

        return "\n".join(context_blocks)

    def get_file_stats(self) -> dict:
        """Get statistics about the target codebase."""
        files = self.get_all_files()
        total_lines = 0
        by_extension = {}

        for file in files:
            ext = file.suffix
            by_extension[ext] = by_extension.get(ext, 0) + 1
            try:
                with open(file, 'r', encoding='utf-8', errors='ignore') as f:
                    total_lines += sum(1 for _ in f)
            except Exception:
                pass

        return {
            "total_files": len(files),
            "total_lines": total_lines,
            "by_extension": by_extension,
        }
