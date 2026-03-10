"""
Call Graph Builder — constructs a directed graph of function calls across files.
Enables tracing execution paths from entry points to dangerous sinks.
"""
from typing import Dict, List, Set, Optional, Tuple
from .symbol_table import SymbolTable, FunctionSymbol


class CallGraph:
    """
    Directed graph where:
    - Nodes = functions (FunctionSymbol)
    - Edges = function A calls function B
    
    Supports cross-file resolution via import tracking.
    """

    def __init__(self, symbol_table: SymbolTable):
        self.symbol_table = symbol_table

        # Adjacency lists: function_id → set of called function_ids
        self._callees: Dict[int, Set[int]] = {}  # who does X call?
        self._callers: Dict[int, Set[int]] = {}  # who calls X?

        # Import resolution: file → { alias → (source_file, original_name) }
        self._import_map: Dict[str, Dict[str, str]] = {}

        # Build the graph
        self._build_import_map()
        self._build_graph()

    def _build_import_map(self):
        """Build a map of imports for cross-file function resolution."""
        for imp in self.symbol_table.imports:
            file = imp["file"]
            text = imp.get("text", "")

            if file not in self._import_map:
                self._import_map[file] = {}

            # Python: from module import func
            if "from" in text and "import" in text:
                parts = text.replace("from", "").replace("import", " ").split()
                if len(parts) >= 2:
                    module = parts[0].strip()
                    for item in parts[1:]:
                        item = item.strip().rstrip(",")
                        if item and item != "as":
                            self._import_map[file][item] = module

            # JS: import { func } from './module'
            elif "import" in text:
                # Extract imported names between { }
                if "{" in text and "}" in text:
                    names_str = text[text.index("{") + 1:text.index("}")]
                    names = [n.strip().rstrip(",") for n in names_str.split(",")]
                    # Extract source module
                    if "from" in text:
                        source_part = text[text.index("from"):].replace("from", "").strip()
                        source = source_part.strip("'\"`;").strip()
                        for name in names:
                            if name:
                                self._import_map[file][name.split(" as ")[0].strip()] = source

    def _resolve_call(self, caller: FunctionSymbol, call_name: str) -> Optional[FunctionSymbol]:
        """
        Try to resolve a call name to an actual FunctionSymbol.
        Checks: same file → imported modules → global match.
        """
        # Strip method calls: obj.method → method
        base_name = call_name.split(".")[-1] if "." in call_name else call_name
        # Remove parentheses if any
        base_name = base_name.rstrip("()")

        if not base_name:
            return None

        # 1. Check same file first
        same_file_funcs = self.symbol_table.get_functions_in_file(caller.file)
        for func in same_file_funcs:
            if func.name == base_name and id(func) != id(caller):
                return func

        # 2. Check imported modules
        file_imports = self._import_map.get(caller.file, {})
        if base_name in file_imports:
            # Look for the function in any file
            candidates = self.symbol_table.get_functions_by_name(base_name)
            if candidates:
                return candidates[0]

        # 3. Global match (across all files)
        candidates = self.symbol_table.get_functions_by_name(base_name)
        if len(candidates) == 1:
            return candidates[0]

        return None

    def _build_graph(self):
        """Build the call graph from symbol table data."""
        for func in self.symbol_table.functions:
            func_id = id(func)
            if func_id not in self._callees:
                self._callees[func_id] = set()

            for call_name in func.calls:
                target = self._resolve_call(func, call_name)
                if target:
                    target_id = id(target)
                    self._callees[func_id].add(target_id)

                    if target_id not in self._callers:
                        self._callers[target_id] = set()
                    self._callers[target_id].add(func_id)

    # ─── Query Methods ────────────────────────────────────

    def get_callees_of(self, func: FunctionSymbol) -> List[FunctionSymbol]:
        """Get functions that are called by the given function."""
        callee_ids = self._callees.get(id(func), set())
        return [f for f in self.symbol_table.functions if id(f) in callee_ids]

    def get_callers_of(self, func: FunctionSymbol) -> List[FunctionSymbol]:
        """Get functions that call the given function."""
        caller_ids = self._callers.get(id(func), set())
        return [f for f in self.symbol_table.functions if id(f) in caller_ids]

    def get_chain_to_sink(self, sink_func: FunctionSymbol, max_depth: int = 5) -> List[List[FunctionSymbol]]:
        """
        Trace all call chains that lead to a sink function.
        Returns list of chains, each chain is [entry_point, ..., sink_func].
        """
        chains = []
        self._trace_callers(sink_func, [sink_func], chains, set(), max_depth)
        return chains

    def _trace_callers(self, func: FunctionSymbol, current_chain: List[FunctionSymbol],
                       all_chains: List, visited: Set[int], max_depth: int):
        """Recursively trace callers backward to build chains."""
        if len(current_chain) > max_depth:
            all_chains.append(list(reversed(current_chain)))
            return

        callers = self.get_callers_of(func)
        if not callers:
            # No more callers — this is an entry point
            all_chains.append(list(reversed(current_chain)))
            return

        for caller in callers:
            if id(caller) in visited:
                # Avoid cycles
                all_chains.append(list(reversed(current_chain)))
                continue

            visited.add(id(caller))
            self._trace_callers(
                caller,
                current_chain + [caller],
                all_chains,
                visited,
                max_depth
            )
            visited.discard(id(caller))

    def get_all_chains_to_sinks(self) -> List[Dict]:
        """
        Find all call chains that end at a dangerous sink.
        Returns structured chain data for context building.
        """
        sink_chains = []

        for sink_func in self.symbol_table.get_all_sinks():
            chains = self.get_chain_to_sink(sink_func)
            for chain in chains:
                sink_chains.append({
                    "sink": sink_func,
                    "chain": chain,
                    "sink_categories": sink_func.sink_categories,
                    "has_source": any(f.is_source for f in chain),
                    "has_sanitizer": any(f.has_sanitizer for f in chain),
                    "length": len(chain),
                    "files_involved": list(set(f.file for f in chain)),
                })

        # Sort: source→sink chains first (most dangerous), then by length
        sink_chains.sort(key=lambda c: (not c["has_source"], c["length"]))

        return sink_chains

    def get_entry_points(self) -> List[FunctionSymbol]:
        """
        Find likely entry points — functions that are called by no one
        or are exported/route handlers.
        """
        entry_points = []
        for func in self.symbol_table.functions:
            func_id = id(func)
            callers = self._callers.get(func_id, set())

            is_entry = (
                len(callers) == 0 or
                func.is_exported or
                any(kw in func.name.lower() for kw in [
                    "get", "post", "put", "delete", "patch",
                    "handler", "route", "endpoint", "view",
                    "main", "app", "index",
                ])
            )

            if is_entry:
                entry_points.append(func)

        return entry_points

    # ─── Statistics ───────────────────────────────────────

    def get_stats(self) -> Dict:
        """Get call graph statistics."""
        total_edges = sum(len(callees) for callees in self._callees.values())
        sink_chains = self.get_all_chains_to_sinks()

        return {
            "total_nodes": len(self.symbol_table.functions),
            "total_edges": total_edges,
            "entry_points": len(self.get_entry_points()),
            "sink_chains": len(sink_chains),
            "dangerous_chains": len([c for c in sink_chains if c["has_source"]]),
            "max_chain_depth": max((c["length"] for c in sink_chains), default=0),
        }

    def __repr__(self):
        stats = self.get_stats()
        return (
            f"<CallGraph: {stats['total_nodes']} nodes, "
            f"{stats['total_edges']} edges, "
            f"{stats['sink_chains']} sink chains, "
            f"{stats['dangerous_chains']} dangerous>"
        )
