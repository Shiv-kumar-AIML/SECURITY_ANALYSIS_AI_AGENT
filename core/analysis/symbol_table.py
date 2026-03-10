"""
Symbol Table — stores and indexes all extracted code symbols.
Provides fast lookup for functions, classes, imports, and dangerous sinks.
"""
from typing import Dict, List, Optional, Set


# ═══════════════════════════════════════════════════════════════
# DANGEROUS SINKS — operations that can be exploited if fed
# untrusted input. Grouped by vulnerability category.
# ═══════════════════════════════════════════════════════════════
DANGEROUS_SINKS = {
    # SQL Injection
    "sql": [
        "cursor.execute", "db.execute", "db.query", "connection.execute",
        "conn.execute", "pool.query", "sequelize.query", "knex.raw",
        "prisma.$queryRaw", "prisma.$executeRaw",
    ],
    # Command Injection
    "command": [
        "os.system", "os.popen", "subprocess.run", "subprocess.call",
        "subprocess.Popen", "exec", "child_process.exec", "child_process.spawn",
        "child_process.execSync", "child_process.execFile",
    ],
    # Code Injection
    "code": [
        "eval", "exec", "Function(", "setTimeout(", "setInterval(",
        "vm.runInNewContext", "vm.runInThisContext",
    ],
    # Path Traversal
    "path": [
        "fs.readFile", "fs.writeFile", "fs.readFileSync", "fs.writeFileSync",
        "fs.unlink", "fs.unlinkSync", "open(", "os.path.join",
        "path.join", "path.resolve",
    ],
    # Insecure Randomness
    "randomness": [
        "Math.random", "random.random", "random.randint",
    ],
    # XSS
    "xss": [
        "res.send", "res.write", "document.write", "innerHTML",
        "dangerouslySetInnerHTML", "render(",
    ],
    # Deserialization
    "deserialization": [
        "pickle.loads", "yaml.load", "JSON.parse", "unserialize",
    ],
    # SSRF
    "ssrf": [
        "requests.get", "requests.post", "fetch(", "axios.get",
        "axios.post", "http.get", "urllib.request.urlopen",
    ],
}

# Flatten all sinks into a single set for fast lookup
ALL_SINKS: Set[str] = set()
for category_sinks in DANGEROUS_SINKS.values():
    ALL_SINKS.update(category_sinks)

# ═══════════════════════════════════════════════════════════════
# DATA SOURCES — where untrusted user input enters
# ═══════════════════════════════════════════════════════════════
DATA_SOURCES = [
    # HTTP request data
    "request.body", "request.args", "request.form", "request.params",
    "request.query", "request.headers", "request.cookies",
    "req.body", "req.query", "req.params", "req.headers", "req.cookies",
    "request.GET", "request.POST", "request.FILES",
    # Next.js specific
    "req.json()", "request.json()", "await req.json()",
    "searchParams", "params",
    # File uploads
    "request.files", "req.file", "req.files",
    # WebSocket
    "message.data", "ws.on('message'",
    # Environment / config (partial trust)
    "process.env", "os.environ",
]

# ═══════════════════════════════════════════════════════════════
# SANITIZERS — operations that neutralize tainted data
# ═══════════════════════════════════════════════════════════════
SANITIZERS = [
    # Type casting
    "parseInt", "parseFloat", "Number(", "Boolean(",
    "int(", "float(", "str(",
    # Encoding
    "encodeURIComponent", "encodeURI", "escape(",
    "html.escape", "markupsafe.escape",
    # Hashing
    "bcrypt.hash", "bcrypt.compare", "crypto.createHash",
    "hashlib.sha256", "hashlib.md5",
    # Validation
    "validator.isEmail", "validator.isURL",
    "DOMPurify.sanitize", "xss(",
    # ORM parameterization (these are SAFE sinks)
    "prisma.", "sequelize.", "mongoose.",
]


class FunctionSymbol:
    """Represents a single function/method in the symbol table."""

    __slots__ = [
        'name', 'file', 'line', 'end_line', 'parameters', 'calls',
        'body', 'parent_class', 'is_sink', 'sink_categories',
        'is_source', 'is_exported', 'has_sanitizer',
    ]

    def __init__(self, name: str, file: str, line: int, end_line: int = 0,
                 parameters: str = "", calls: List[str] = None,
                 body: str = "", parent_class: str = None,
                 is_exported: bool = False):
        self.name = name
        self.file = file
        self.line = line
        self.end_line = end_line or line
        self.parameters = parameters
        self.calls = calls or []
        self.body = body
        self.parent_class = parent_class
        self.is_exported = is_exported

        # Auto-detect sink status
        self.sink_categories = self._detect_sinks()
        self.is_sink = len(self.sink_categories) > 0

        # Auto-detect if function body contains data sources
        self.is_source = self._detect_sources()

        # Auto-detect sanitizers
        self.has_sanitizer = self._detect_sanitizers()

    def _detect_sinks(self) -> List[str]:
        """Check if this function's body or calls contain dangerous sinks."""
        categories = []
        body_lower = self.body.lower()
        all_text = body_lower + " " + " ".join(c.lower() for c in self.calls)

        for category, sinks in DANGEROUS_SINKS.items():
            for sink in sinks:
                if sink.lower() in all_text:
                    if category not in categories:
                        categories.append(category)
        return categories

    def _detect_sources(self) -> bool:
        """Check if function body references user input sources."""
        body_lower = self.body.lower()
        for source in DATA_SOURCES:
            if source.lower() in body_lower:
                return True
        return False

    def _detect_sanitizers(self) -> bool:
        """Check if function body contains sanitization operations."""
        body_lower = self.body.lower()
        for sanitizer in SANITIZERS:
            if sanitizer.lower() in body_lower:
                return True
        return False

    @property
    def qualified_name(self) -> str:
        """Return fully qualified name (ClassName.method or function)."""
        if self.parent_class:
            return f"{self.parent_class}.{self.name}"
        return self.name

    def __repr__(self):
        sink_str = f" [SINK: {','.join(self.sink_categories)}]" if self.is_sink else ""
        source_str = " [SOURCE]" if self.is_source else ""
        return f"<Function {self.qualified_name} @ {self.file}:{self.line}{sink_str}{source_str}>"


class SymbolTable:
    """
    Index of all code symbols extracted from a repository.
    Provides fast lookup by name, file, sink status, etc.
    """

    def __init__(self):
        self.functions: List[FunctionSymbol] = []
        self.classes: List[Dict] = []
        self.imports: List[Dict] = []
        self.variables: List[Dict] = []

        # Indexes for fast lookup
        self._by_name: Dict[str, List[FunctionSymbol]] = {}
        self._by_file: Dict[str, List[FunctionSymbol]] = {}
        self._sinks: List[FunctionSymbol] = []
        self._sources: List[FunctionSymbol] = []

    def build_from_ast(self, ast_data: Dict):
        """
        Build symbol table from AST parser output.
        ast_data = result of TreeSitterParser.parse_repository()
        """
        for file_data in ast_data.get("files", []):
            filepath = file_data["file"]

            # Index imports
            for imp in file_data.get("imports", []):
                self.imports.append({
                    "file": filepath,
                    "text": imp.get("text", str(imp)),
                    "line": imp.get("line", 0),
                })

            # Index classes
            for cls in file_data.get("classes", []):
                self.classes.append({
                    "file": filepath,
                    "name": cls["name"],
                    "line": cls.get("line", 0),
                    "methods": cls.get("methods", []),
                })

            # Index variables
            for var in file_data.get("variables", []):
                self.variables.append({
                    "file": filepath,
                    "name": var["name"],
                    "line": var.get("line", 0),
                })

            # Index functions (most important)
            for func in file_data.get("functions", []):
                symbol = FunctionSymbol(
                    name=func["name"],
                    file=filepath,
                    line=func.get("line", 0),
                    end_line=func.get("end_line", 0),
                    parameters=func.get("parameters", ""),
                    calls=func.get("calls", []),
                    body=func.get("body", ""),
                    parent_class=func.get("class"),
                    is_exported=func.get("exported", False),
                )
                self._add_function(symbol)

    def _add_function(self, symbol: FunctionSymbol):
        """Add a function symbol to all indexes."""
        self.functions.append(symbol)

        # Name index
        if symbol.name not in self._by_name:
            self._by_name[symbol.name] = []
        self._by_name[symbol.name].append(symbol)

        # File index
        if symbol.file not in self._by_file:
            self._by_file[symbol.file] = []
        self._by_file[symbol.file].append(symbol)

        # Sink/source indexes
        if symbol.is_sink:
            self._sinks.append(symbol)
        if symbol.is_source:
            self._sources.append(symbol)

    # ─── Lookup Methods ───────────────────────────────────

    def get_function(self, name: str) -> Optional[FunctionSymbol]:
        """Get first function matching name."""
        funcs = self._by_name.get(name, [])
        return funcs[0] if funcs else None

    def get_functions_by_name(self, name: str) -> List[FunctionSymbol]:
        """Get all functions matching name (may be in multiple files)."""
        return self._by_name.get(name, [])

    def get_functions_in_file(self, filepath: str) -> List[FunctionSymbol]:
        """Get all functions in a specific file."""
        return self._by_file.get(filepath, [])

    def get_all_sinks(self) -> List[FunctionSymbol]:
        """Get all functions containing dangerous sinks."""
        return self._sinks

    def get_all_sources(self) -> List[FunctionSymbol]:
        """Get all functions containing user input sources."""
        return self._sources

    def get_sink_functions_by_category(self, category: str) -> List[FunctionSymbol]:
        """Get sink functions filtered by vulnerability category."""
        return [f for f in self._sinks if category in f.sink_categories]

    def find_callers_of(self, func_name: str) -> List[FunctionSymbol]:
        """Find all functions that call the given function."""
        callers = []
        for func in self.functions:
            for call in func.calls:
                # Match exact name or dotted name ending
                if call == func_name or call.endswith(f".{func_name}"):
                    callers.append(func)
                    break
        return callers

    def get_security_relevant_functions(self) -> List[FunctionSymbol]:
        """Get all functions that are security-relevant (sinks, sources, or call sinks)."""
        relevant = set()

        # Direct sinks and sources
        for func in self._sinks:
            relevant.add(id(func))
        for func in self._sources:
            relevant.add(id(func))

        # Functions that call sinks (1 level up)
        for sink in self._sinks:
            callers = self.find_callers_of(sink.name)
            for caller in callers:
                relevant.add(id(caller))

        return [f for f in self.functions if id(f) in relevant]

    # ─── Statistics ───────────────────────────────────────

    def get_stats(self) -> Dict:
        """Get summary statistics of the symbol table."""
        return {
            "total_functions": len(self.functions),
            "total_classes": len(self.classes),
            "total_imports": len(self.imports),
            "total_variables": len(self.variables),
            "total_sinks": len(self._sinks),
            "total_sources": len(self._sources),
            "files_indexed": len(self._by_file),
            "sink_categories": {
                cat: len(self.get_sink_functions_by_category(cat))
                for cat in DANGEROUS_SINKS.keys()
            },
        }

    def __repr__(self):
        stats = self.get_stats()
        return (
            f"<SymbolTable: {stats['total_functions']} functions, "
            f"{stats['total_sinks']} sinks, "
            f"{stats['total_sources']} sources, "
            f"{stats['files_indexed']} files>"
        )
