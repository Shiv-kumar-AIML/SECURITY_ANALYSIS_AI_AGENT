"""
Enhanced Code Parser.
Extracts code context from the target directory with improved filtering and metadata.
Supports both full-context mode (legacy) and smart-context mode (vectorless pipeline).
"""
import os
from pathlib import Path
from .constants import SUPPORTED_EXTENSIONS, SKIP_DIRECTORIES


class CodeParser:
    def __init__(self, target_dir):
        self.target_dir = Path(target_dir).resolve()
        # Pre-analysis results (populated by extract_smart_context)
        self.pre_analysis = None
        self.context_stats = None

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

    def extract_context(self, max_chars: int = 200000) -> str:
        """
        Extract code context from the target directory.
        Respects max_chars to avoid overloading LLM context windows.
        Prioritizes security-relevant files (routes, auth, middleware, config).
        """
        if not self.target_dir.exists() or not self.target_dir.is_dir():
            print(f"[-] Invalid target directory: {self.target_dir}")
            return ""

        files = self.get_all_files()
        context_blocks = []
        total_chars = 0

        # Sort files: entry points first, then security-relevant files, then by size
        priority_names = {"main.py", "app.py", "index.js", "server.js", "main.go",
                          "app.rb", "index.ts", "main.java"}

        # Security-relevant patterns to prioritize
        security_patterns = {
            "route", "auth", "login", "middleware", "password", "upload",
            "admin", "api", "config", "webhook", "payment", "token",
            "session", "otp", "verify", "reset", "signup", "register",
        }

        def sort_key(f):
            name = f.name.lower()
            path_str = str(f).lower()
            is_priority = 0 if f.name in priority_names else 1
            # Security-relevant files get priority 1, others get 2
            is_security = 1 if any(p in path_str for p in security_patterns) else 2
            try:
                size = f.stat().st_size
            except OSError:
                size = 0
            return (is_priority, is_security, size)

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

    def extract_smart_context(self, scanner_files: list = None,
                              max_chars: int = 200000) -> dict:
        """
        Extract optimized code context using the vectorless pre-analysis pipeline.
        Falls back to extract_context() if tree-sitter is unavailable or fails.

        Pipeline: AST Parse → Symbol Table → Call Graph → Smart Context Builder

        Returns:
            dict with 'context' (str), 'metadata' (dict), 'stats' (dict)
        """
        try:
            from .analysis.ast_parser import TreeSitterParser
            from .analysis.symbol_table import SymbolTable
            from .analysis.call_graph import CallGraph
            from .analysis.context_builder import SmartContextBuilder

            parser = TreeSitterParser()

            if not parser.available:
                # tree-sitter not installed — fall back to legacy
                return self._fallback_context(max_chars, reason="tree-sitter not installed")

            # Step 1: Parse repository AST
            ast_data = parser.parse_repository(str(self.target_dir))

            if not ast_data["files"]:
                return self._fallback_context(max_chars, reason="no parseable files found")

            # Step 2: Build symbol table
            symbol_table = SymbolTable()
            symbol_table.build_from_ast(ast_data)

            # Step 3: Build call graph
            call_graph = CallGraph(symbol_table)

            # Step 4: Build smart context
            full_context = self.extract_context(max_chars)
            context_builder = SmartContextBuilder(symbol_table, call_graph, target_path=str(self.target_dir))
            result = context_builder.build_context(
                full_context=full_context,
                scanner_files=scanner_files or [],
            )

            # Store for later use by coordinator
            self.pre_analysis = {
                "symbol_table": symbol_table,
                "call_graph": call_graph,
                "context_builder": context_builder,
                "ast_data": ast_data,
            }
            self.context_stats = result["stats"]

            return result

        except Exception as e:
            return self._fallback_context(max_chars, reason=f"pre-analysis error: {e}")

    def _fallback_context(self, max_chars: int, reason: str = "") -> dict:
        """Fall back to legacy full-context extraction."""
        full_context = self.extract_context(max_chars)
        return {
            "context": full_context,
            "metadata": {
                "functions_selected": 0,
                "functions_total": 0,
                "files_included": ["ALL (fallback)"],
                "sink_chains_found": 0,
                "dangerous_chains": 0,
                "used_fallback": True,
                "fallback_reason": reason,
            },
            "stats": {
                "original_chars": len(full_context),
                "filtered_chars": len(full_context),
                "reduction_percent": 0,
            },
        }

