"""
Smart Context Builder — builds minimal, security-focused LLM context
from pre-analysis results (symbol table + call graph + scanner findings).

This is the core of token cost reduction: instead of sending 200K chars
of raw code, it sends only ~20-30K chars of relevant functions.
"""
import os
from pathlib import Path
from typing import Dict, List, Optional, Set
from .symbol_table import SymbolTable, FunctionSymbol
from .call_graph import CallGraph


class SmartContextBuilder:
    """
    Builds filtered code context for LLM agents using pre-analysis data.
    
    Strategy:
    1. Include all functions containing dangerous sinks
    2. Include callers (1-2 levels up the call graph)  
    3. Include functions flagged by deterministic scanner
    4. Include entry points (route handlers, exported functions)
    5. Fallback: if filtered context < min_chars, use full repo context
    """

    # Minimum context size before fallback triggers
    MIN_CONTEXT_CHARS = 5000
    # Maximum context to send to LLM
    MAX_CONTEXT_CHARS = 60000

    def __init__(self, symbol_table: SymbolTable, call_graph: CallGraph, target_path: str = None):
        self.symbol_table = symbol_table
        self.call_graph = call_graph
        self.target_path = target_path

    def build_context(self, full_context: str = "",
                      scanner_files: List[str] = None) -> Dict:
        """
        Build optimized LLM context.

        Args:
            full_context: The original full repo context (fallback)
            scanner_files: Files flagged by deterministic scanner

        Returns:
            Dict with 'context' (string for LLM), 'metadata', and 'stats'
        """
        scanner_files = scanner_files or []
        selected_functions: Set[int] = set()
        selection_reasons: Dict[int, List[str]] = {}

        def _add(func: FunctionSymbol, reason: str):
            fid = id(func)
            selected_functions.add(fid)
            if fid not in selection_reasons:
                selection_reasons[fid] = []
            selection_reasons[fid].append(reason)

        # ── Step 1: Include ALL sink-containing functions ──
        for func in self.symbol_table.get_all_sinks():
            _add(func, f"contains_sink:{','.join(func.sink_categories)}")

        # ── Step 2: Include ALL source-containing functions ──
        for func in self.symbol_table.get_all_sources():
            _add(func, "contains_user_input_source")

        # ── Step 3: Include callers of sinks (1-2 levels up) ──
        for sink_func in self.symbol_table.get_all_sinks():
            # Level 1 callers
            callers_l1 = self.call_graph.get_callers_of(sink_func)
            for caller in callers_l1:
                _add(caller, f"calls_sink:{sink_func.name}")

                # Level 2 callers
                callers_l2 = self.call_graph.get_callers_of(caller)
                for caller2 in callers_l2:
                    _add(caller2, f"indirect_caller_of_sink:{sink_func.name}")

        # ── Step 4: Include dangerous call chains ──
        chains = self.call_graph.get_all_chains_to_sinks()
        for chain_data in chains:
            if chain_data["has_source"]:
                # This is a source→sink chain — highest priority
                for func in chain_data["chain"]:
                    _add(func, f"in_dangerous_chain:{chain_data['sink'].name}")

        # ── Step 5: Include entry points ──
        for func in self.call_graph.get_entry_points():
            # Only include if they connect to sinks
            callees = self.call_graph.get_callees_of(func)
            has_security_connection = any(
                id(c) in selected_functions for c in callees
            )
            if has_security_connection or func.is_source:
                _add(func, "entry_point_with_security_connection")

        # ── Step 6: Include scanner-flagged files ──
        for filepath in scanner_files:
            file_funcs = self.symbol_table.get_functions_in_file(filepath)
            for func in file_funcs:
                _add(func, f"scanner_flagged_file:{filepath}")

        # ── Step 7: Include security-relevant config/settings files ──
        # Settings files (settings.py, local.py, production.py, Dockerfile, etc.)
        # are pure variable assignments with NO functions — the LLM never sees them
        # from function-based analysis. But they contain critical security config:
        # SECRET_KEY, ALLOWED_HOSTS, CSRF settings, security headers, etc.
        config_file_contents = self._collect_security_config_files(
            full_context, scanner_files
        )
        # Log config files found for debugging
        if config_file_contents:
            import sys
            print(f"[SmartContext] Found {len(config_file_contents)} config files: {list(config_file_contents.keys())}", file=sys.stderr)
        else:
            import sys
            print(f"[SmartContext] WARNING: No config files found!", file=sys.stderr)

        # ── Collect selected functions ──
        selected = [
            f for f in self.symbol_table.functions
            if id(f) in selected_functions
        ]

        # ── Build context string ──
        context_parts = []
        total_chars = 0
        files_included = set()

        # Sort: sources first, then sinks, then others
        selected.sort(key=lambda f: (
            not f.is_source,
            not f.is_sink,
            f.file,
            f.line,
        ))

        # Add pre-analysis summary header
        stats = self.symbol_table.get_stats()
        graph_stats = self.call_graph.get_stats()
        header = self._build_header(stats, graph_stats, chains)
        context_parts.append(header)
        total_chars += len(header)

        # Add security-relevant config files BEFORE function code
        # so the LLM sees settings (SECRET_KEY, ALLOWED_HOSTS, etc.) first
        if config_file_contents:
            config_header = "\n═══ SECURITY-RELEVANT CONFIGURATION FILES ═══\n"
            config_header += "These files contain security settings. Check for:\n"
            config_header += "- Hardcoded secrets, weak SECRET_KEY, debug mode\n"
            config_header += "- Missing security headers (SECURE_SSL_REDIRECT, SESSION_COOKIE_SECURE, etc.)\n"
            config_header += "- Wildcard ALLOWED_HOSTS, CSRF exemptions, pickle usage\n"
            config_header += "- Hardcoded passwords with fallback defaults\n"
            config_header += "═" * 55 + "\n"
            context_parts.append(config_header)
            total_chars += len(config_header)

            for filepath, content in config_file_contents.items():
                file_block = f"\n--- CONFIG: {filepath} ---\n{content}\n"
                if total_chars + len(file_block) < self.MAX_CONTEXT_CHARS:
                    context_parts.append(file_block)
                    total_chars += len(file_block)
                    files_included.add(filepath)

        # Add selected function code
        current_file = None
        for func in selected:
            if total_chars > self.MAX_CONTEXT_CHARS:
                break

            # File header
            if func.file != current_file:
                current_file = func.file
                files_included.add(current_file)
                file_header = f"\n--- FILE: {current_file} ---\n"
                context_parts.append(file_header)
                total_chars += len(file_header)

            # Function body with annotation
            reasons = selection_reasons.get(id(func), ["included"])
            annotation = f"  // [SECURITY-RELEVANT: {', '.join(reasons)}]"
            func_block = f"\n{annotation}\n{func.body}\n"
            context_parts.append(func_block)
            total_chars += len(func_block)

        filtered_context = "\n".join(context_parts)

        # ── Fallback: if filtered context is too small, use full ──
        used_fallback = False
        if total_chars < self.MIN_CONTEXT_CHARS and full_context:
            filtered_context = header + "\n\n" + full_context
            total_chars = len(filtered_context)
            used_fallback = True
            files_included = {"ALL (fallback)"}

        return {
            "context": filtered_context,
            "metadata": {
                "functions_selected": len(selected),
                "functions_total": len(self.symbol_table.functions),
                "files_included": list(files_included),
                "sink_chains_found": len(chains),
                "dangerous_chains": len([c for c in chains if c["has_source"]]),
                "used_fallback": used_fallback,
            },
            "stats": {
                "original_chars": len(full_context) if full_context else 0,
                "filtered_chars": total_chars,
                "reduction_percent": round(
                    (1 - total_chars / max(len(full_context), 1)) * 100, 1
                ) if full_context else 0,
            },
        }

    # ─── Security config file patterns ───
    # These file names/paths contain security-critical settings
    # that the LLM must analyze for misconfigurations.
    SECURITY_CONFIG_NAMES = {
        # Python/Django/Flask settings
        'settings.py', 'local.py', 'production.py', 'staging.py',
        'base.py', 'config.py', 'conf.py',
        # JS/TS config
        'next.config.js', 'next.config.ts', 'next.config.mjs',
        'nuxt.config.js', 'nuxt.config.ts',
        'vite.config.js', 'vite.config.ts',
        'webpack.config.js',
        'server.js', 'server.ts', 'app.js', 'app.ts',
        # Infrastructure
        'Dockerfile', 'Dockerfile.production',
        'docker-compose.yml', 'docker-compose.yaml',
        'docker-compose.production.yml',
        'nginx.conf', '.htaccess',
        # CI/CD
        '.gitlab-ci.yml', '.github/workflows',
    }

    SECURITY_CONFIG_DIRS = {
        'settings', 'config', 'conf', 'deploy', 'infra',
    }

    # Max chars per config file to include
    MAX_CONFIG_FILE_CHARS = 4000
    # Max total chars for all config files
    MAX_TOTAL_CONFIG_CHARS = 20000

    def _collect_security_config_files(self, full_context: str,
                                        scanner_files: List[str]) -> Dict[str, str]:
        """
        Find and read security-relevant config/settings files.
        These are pure-assignment files (no functions) that contain
        critical security settings the LLM must analyze.
        """
        config_contents = {}
        total_chars = 0

        # Use the target path passed directly from CodeParser
        # (previously inferred from symbol table which was unreliable)
        target_path = self.target_path

        # Fallback: try to infer from symbol table if not provided
        if not target_path or not os.path.isdir(target_path):
            if self.symbol_table.functions:
                files = set(f.file for f in self.symbol_table.functions if f.file)
                if files:
                    try:
                        target_path = os.path.commonpath(list(files))
                    except ValueError:
                        pass

        if not target_path or not os.path.isdir(target_path):
            return config_contents

        skip_dirs = {'node_modules', '.git', '.venv', 'venv', '__pycache__',
                     'dist', 'build', '.next', '.tox', 'coverage', '.eggs'}

        for root, dirs, files in os.walk(target_path):
            # Skip irrelevant directories
            dirs[:] = [d for d in dirs if d not in skip_dirs]

            rel_root = os.path.relpath(root, target_path)
            # Check if the directory itself is a settings/config directory
            dir_basename = os.path.basename(root).lower()
            is_config_dir = dir_basename in self.SECURITY_CONFIG_DIRS

            for filename in files:
                if total_chars >= self.MAX_TOTAL_CONFIG_CHARS:
                    break

                filepath = os.path.join(root, filename)
                rel_path = os.path.relpath(filepath, target_path)

                # Match by filename or by being in a config directory
                is_config_file = (
                    filename in self.SECURITY_CONFIG_NAMES or
                    filename.lower() in self.SECURITY_CONFIG_NAMES or
                    (is_config_dir and filename.endswith('.py'))
                )

                if not is_config_file:
                    continue

                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read(self.MAX_CONFIG_FILE_CHARS)

                    if content.strip():
                        config_contents[rel_path] = content
                        total_chars += len(content)
                except Exception:
                    continue

        return config_contents

    def _build_header(self, sym_stats: Dict, graph_stats: Dict,
                      chains: List[Dict]) -> str:
        """Build a pre-analysis summary header for LLM context."""
        dangerous_chains = [c for c in chains if c["has_source"]]

        header_lines = [
            "═══ PRE-ANALYSIS SUMMARY (Compiled AST + Call Graph) ═══",
            f"Functions analyzed: {sym_stats['total_functions']}",
            f"Classes found: {sym_stats['total_classes']}",
            f"Dangerous sinks: {sym_stats['total_sinks']}",
            f"User input sources: {sym_stats['total_sources']}",
            f"Call graph edges: {graph_stats['total_edges']}",
            f"Entry points: {graph_stats['entry_points']}",
            "",
        ]

        if sym_stats["sink_categories"]:
            header_lines.append("Sink categories detected:")
            for cat, count in sym_stats["sink_categories"].items():
                if count > 0:
                    header_lines.append(f"  - {cat}: {count} functions")
            header_lines.append("")

        if dangerous_chains:
            header_lines.append(f"⚠ {len(dangerous_chains)} DANGEROUS CHAINS (source → sink):")
            for chain in dangerous_chains[:10]:
                func_names = " → ".join(f.name for f in chain["chain"])
                categories = ", ".join(chain["sink_categories"])
                header_lines.append(
                    f"  [{categories}] {func_names}"
                )
            header_lines.append("")

        header_lines.append(
            "Below is the security-relevant code extracted via AST analysis."
        )
        header_lines.append("Focus your analysis on the dangerous chains above.")
        header_lines.append("═" * 55)

        return "\n".join(header_lines)

    def get_analysis_summary(self) -> str:
        """Get a human-readable summary of the pre-analysis for CLI output."""
        stats = self.symbol_table.get_stats()
        graph_stats = self.call_graph.get_stats()

        lines = [
            f"  Functions: {stats['total_functions']}  |  "
            f"Sinks: {stats['total_sinks']}  |  "
            f"Sources: {stats['total_sources']}",
            f"  Call Graph Edges: {graph_stats['total_edges']}  |  "
            f"Sink Chains: {graph_stats['sink_chains']}  |  "
            f"Dangerous: {graph_stats['dangerous_chains']}",
        ]

        return "\n".join(lines)
