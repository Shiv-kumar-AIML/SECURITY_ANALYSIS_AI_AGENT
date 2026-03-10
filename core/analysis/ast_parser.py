"""
Enhanced Tree-sitter Parser — parses entire repositories into structured AST data.
Supports Python, JavaScript, TypeScript, JSX, TSX.
Used as the foundation for the vectorless pre-analysis pipeline.
"""
import os
from pathlib import Path
from typing import Dict, List, Any, Optional
from ..constants import SUPPORTED_EXTENSIONS, SKIP_DIRECTORIES

# Try to import tree-sitter; gracefully degrade if not installed
try:
    import tree_sitter
    import tree_sitter_python
    import tree_sitter_javascript
    HAS_TREE_SITTER = True
except ImportError:
    HAS_TREE_SITTER = False


class TreeSitterParser:
    """Parses source files into structured AST data using tree-sitter."""

    def __init__(self):
        if not HAS_TREE_SITTER:
            self.parsers = {}
            return

        self.parsers = {}

        # Python parser
        py_parser = tree_sitter.Parser()
        py_parser.language = tree_sitter.Language(tree_sitter_python.language())
        self.parsers['.py'] = py_parser

        # JavaScript/TypeScript parser
        js_parser = tree_sitter.Parser()
        js_parser.language = tree_sitter.Language(tree_sitter_javascript.language())
        self.parsers['.js'] = js_parser
        self.parsers['.jsx'] = js_parser
        self.parsers['.ts'] = js_parser
        self.parsers['.tsx'] = js_parser

    @property
    def available(self) -> bool:
        """Check if tree-sitter is available."""
        return HAS_TREE_SITTER and len(self.parsers) > 0

    def parse_repository(self, target_dir: str) -> Dict[str, Any]:
        """
        Parse ALL supported files in a repository.
        Returns a combined result with all files' AST data.
        """
        target_path = Path(target_dir).resolve()
        results = {
            "files": [],
            "total_functions": 0,
            "total_classes": 0,
            "total_imports": 0,
            "parse_errors": [],
        }

        if not self.available:
            return results

        for root, dirs, files in os.walk(target_path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRECTORIES]

            for filename in files:
                ext = Path(filename).suffix
                if ext not in self.parsers:
                    continue

                filepath = os.path.join(root, filename)
                file_data = self.parse_file(filepath)

                if file_data:
                    # Store relative path for readability
                    try:
                        file_data["file"] = str(Path(filepath).relative_to(target_path))
                    except ValueError:
                        file_data["file"] = filepath

                    results["files"].append(file_data)
                    results["total_functions"] += len(file_data.get("functions", []))
                    results["total_classes"] += len(file_data.get("classes", []))
                    results["total_imports"] += len(file_data.get("imports", []))
                else:
                    results["parse_errors"].append(filepath)

        return results

    def parse_file(self, filepath: str) -> Optional[Dict[str, Any]]:
        """Parse a single file and return structured AST data."""
        ext = Path(filepath).suffix
        if ext not in self.parsers:
            return None

        parser = self.parsers[ext]
        try:
            with open(filepath, 'rb') as f:
                content = f.read()
            tree = parser.parse(content)

            if ext == '.py':
                return self._extract_python_graph(tree, content, filepath)
            elif ext in ['.js', '.jsx', '.ts', '.tsx']:
                return self._extract_js_graph(tree, content, filepath)

        except Exception as e:
            return None

    def _extract_python_graph(self, tree, content_bytes: bytes, filepath: str) -> Dict[str, Any]:
        """Extract AST data for Python files."""
        root_node = tree.root_node
        functions = []
        classes = []
        imports = []
        variables = []

        def _get_text(node):
            if node is None:
                return ""
            return content_bytes[node.start_byte:node.end_byte].decode('utf8', errors='ignore')

        def walk(node, parent_class=None):
            if node.type == 'class_definition':
                name_node = node.child_by_field_name('name')
                class_name = _get_text(name_node)

                # Find methods inside the class
                methods = []
                for child in node.children:
                    if child.type == 'block':
                        for block_child in child.children:
                            if block_child.type == 'function_definition':
                                method_data = self._extract_function_node(
                                    block_child, content_bytes, class_name
                                )
                                methods.append(method_data)
                                functions.append(method_data)

                classes.append({
                    "name": class_name,
                    "line": node.start_point[0] + 1,
                    "methods": [m["name"] for m in methods],
                })

            elif node.type == 'function_definition' and parent_class is None:
                func_data = self._extract_function_node(node, content_bytes)
                functions.append(func_data)

            elif node.type in ['import_statement', 'import_from_statement']:
                imports.append({
                    "text": _get_text(node),
                    "line": node.start_point[0] + 1,
                })

            elif node.type == 'expression_statement':
                # Track top-level assignments for variable tracking
                for child in node.children:
                    if child.type == 'assignment':
                        left = child.child_by_field_name('left')
                        right = child.child_by_field_name('right')
                        if left:
                            variables.append({
                                "name": _get_text(left),
                                "value_type": right.type if right else "unknown",
                                "line": node.start_point[0] + 1,
                            })

            for child in node.children:
                if node.type == 'class_definition':
                    pass  # Already handled above
                else:
                    walk(child, parent_class)

        walk(root_node)

        return {
            "file": filepath,
            "language": "python",
            "imports": imports,
            "functions": functions,
            "classes": classes,
            "variables": variables,
        }

    def _extract_js_graph(self, tree, content_bytes: bytes, filepath: str) -> Dict[str, Any]:
        """Extract AST data for JS/TS files."""
        root_node = tree.root_node
        functions = []
        classes = []
        imports = []
        exports = []
        variables = []

        def _get_text(node):
            if node is None:
                return ""
            return content_bytes[node.start_byte:node.end_byte].decode('utf8', errors='ignore')

        def walk(node):
            # Function declarations: function foo() {}
            if node.type == 'function_declaration':
                func_data = self._extract_js_function_node(node, content_bytes)
                functions.append(func_data)

            # Arrow functions assigned to variables: const foo = () => {}
            elif node.type == 'lexical_declaration':
                for child in node.children:
                    if child.type == 'variable_declarator':
                        name_node = child.child_by_field_name('name')
                        value_node = child.child_by_field_name('value')
                        if value_node and value_node.type == 'arrow_function':
                            func_name = _get_text(name_node) if name_node else "anonymous"
                            body = _get_text(value_node)
                            calls = self._find_nodes_of_type(value_node, 'call_expression')
                            call_names = []
                            for call in calls:
                                func_node = call.child_by_field_name('function')
                                if func_node:
                                    call_names.append(_get_text(func_node))

                            functions.append({
                                "name": func_name,
                                "parameters": "",
                                "calls": call_names,
                                "body": body,
                                "line": value_node.start_point[0] + 1,
                                "end_line": value_node.end_point[0] + 1,
                                "class": None,
                            })
                        elif name_node:
                            variables.append({
                                "name": _get_text(name_node),
                                "value_type": value_node.type if value_node else "unknown",
                                "line": node.start_point[0] + 1,
                            })

            # Export statements
            elif node.type == 'export_statement':
                export_text = _get_text(node)
                exports.append({
                    "text": export_text[:200],  # Truncate long exports
                    "line": node.start_point[0] + 1,
                })
                # Check for exported functions
                for child in node.children:
                    if child.type == 'function_declaration':
                        func_data = self._extract_js_function_node(child, content_bytes)
                        func_data["exported"] = True
                        functions.append(func_data)
                    elif child.type == 'lexical_declaration':
                        # Recurse into exported const = arrow functions
                        walk(child)

            # Import statements
            elif node.type == 'import_statement':
                imports.append({
                    "text": _get_text(node),
                    "line": node.start_point[0] + 1,
                })

            # Class declarations
            elif node.type == 'class_declaration':
                name_node = node.child_by_field_name('name')
                class_name = _get_text(name_node) if name_node else "anonymous"
                methods = []
                body_node = node.child_by_field_name('body')
                if body_node:
                    for child in body_node.children:
                        if child.type == 'method_definition':
                            method_name_node = child.child_by_field_name('name')
                            method_name = _get_text(method_name_node) if method_name_node else "anonymous"
                            method_body = _get_text(child)
                            method_calls = self._find_nodes_of_type(child, 'call_expression')
                            call_names = [_get_text(c.child_by_field_name('function'))
                                          for c in method_calls if c.child_by_field_name('function')]
                            methods.append(method_name)
                            functions.append({
                                "name": method_name,
                                "parameters": "",
                                "calls": call_names,
                                "body": method_body,
                                "line": child.start_point[0] + 1,
                                "end_line": child.end_point[0] + 1,
                                "class": class_name,
                            })

                classes.append({
                    "name": class_name,
                    "line": node.start_point[0] + 1,
                    "methods": methods,
                })

            for child in node.children:
                if node.type not in ['class_declaration']:
                    walk(child)

        walk(root_node)

        return {
            "file": filepath,
            "language": "javascript",
            "imports": imports,
            "exports": exports,
            "functions": functions,
            "classes": classes,
            "variables": variables,
        }

    def _extract_function_node(self, node, content_bytes: bytes, parent_class: str = None) -> Dict:
        """Extract a Python function/method node into structured data."""
        def _get_text(n):
            if n is None:
                return ""
            return content_bytes[n.start_byte:n.end_byte].decode('utf8', errors='ignore')

        name_node = node.child_by_field_name('name')
        func_name = _get_text(name_node)

        params_node = node.child_by_field_name('parameters')
        params = _get_text(params_node)

        body = content_bytes[node.start_byte:node.end_byte].decode('utf8', errors='ignore')

        calls = self._find_nodes_of_type(node, 'call')
        call_names = []
        for call in calls:
            func_node = call.child_by_field_name('function')
            if func_node:
                call_names.append(_get_text(func_node))

        return {
            "name": func_name,
            "parameters": params,
            "calls": call_names,
            "body": body,
            "line": node.start_point[0] + 1,
            "end_line": node.end_point[0] + 1,
            "class": parent_class,
        }

    def _extract_js_function_node(self, node, content_bytes: bytes) -> Dict:
        """Extract a JS function declaration node into structured data."""
        def _get_text(n):
            if n is None:
                return ""
            return content_bytes[n.start_byte:n.end_byte].decode('utf8', errors='ignore')

        name_node = node.child_by_field_name('name')
        func_name = _get_text(name_node)

        params_node = node.child_by_field_name('parameters')
        params = _get_text(params_node) if params_node else "()"

        body = content_bytes[node.start_byte:node.end_byte].decode('utf8', errors='ignore')

        calls = self._find_nodes_of_type(node, 'call_expression')
        call_names = []
        for call in calls:
            func_node = call.child_by_field_name('function')
            if func_node:
                call_names.append(_get_text(func_node))

        return {
            "name": func_name,
            "parameters": params,
            "calls": call_names,
            "body": body,
            "line": node.start_point[0] + 1,
            "end_line": node.end_point[0] + 1,
            "class": None,
            "exported": False,
        }

    def _find_nodes_of_type(self, node, node_type: str) -> List[Any]:
        """Recursively find all descendant nodes of a given type."""
        results = []
        for child in node.children:
            if child.type == node_type:
                results.append(child)
            results.extend(self._find_nodes_of_type(child, node_type))
        return results
