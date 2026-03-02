import os
from pathlib import Path
import tree_sitter
import tree_sitter_python
import tree_sitter_javascript
from typing import Dict, List, Any

class TreeSitterParser:
    def __init__(self):
        # Initialize language parsers
        self.parsers = {}
        
        # Python
        py_parser = tree_sitter.Parser()
        py_parser.language = tree_sitter.Language(tree_sitter_python.language())
        self.parsers['.py'] = py_parser
        
        # JavaScript/TypeScript
        js_parser = tree_sitter.Parser()
        js_parser.language = tree_sitter.Language(tree_sitter_javascript.language())
        self.parsers['.js'] = js_parser
        self.parsers['.jsx'] = js_parser
        self.parsers['.ts'] = js_parser
        self.parsers['.tsx'] = js_parser

    def parse_file(self, filepath: str) -> Dict[str, Any]:
        """Parses a single file and returns structured graph data (functions, calls, variables)."""
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
            print(f"[-] Error parsing {filepath} via tree-sitter: {e}")
            return None

    def _extract_python_graph(self, tree, content_bytes: bytes, filepath: str) -> Dict[str, Any]:
        """Extracts AST nodes for Python to build CFG/Call Graph."""
        root_node = tree.root_node
        functions = []
        imports = []
        
        # Simple tree walk to extract basic elements
        def walk(node):
            if node.type == 'function_definition':
                # Extract function name
                name_node = node.child_by_field_name('name')
                func_name = content_bytes[name_node.start_byte:name_node.end_byte].decode('utf8') if name_node else "anonymous"
                
                # Extract parameters
                params_node = node.child_by_field_name('parameters')
                params = content_bytes[params_node.start_byte:params_node.end_byte].decode('utf8') if params_node else "()"
                
                # Extract function body text
                body = content_bytes[node.start_byte:node.end_byte].decode('utf8')
                
                # Find calls inside this function (basic Call Graph mapping)
                calls = self._find_nodes_of_type(node, 'call')
                call_names = []
                for call in calls:
                    func_node = call.child_by_field_name('function')
                    if func_node:
                        call_names.append(content_bytes[func_node.start_byte:func_node.end_byte].decode('utf8'))
                
                functions.append({
                    "name": func_name,
                    "parameters": params,
                    "calls": call_names,
                    "body": body # Keep body for LLM context, but structured per function
                })
                
            elif node.type in ['import_statement', 'import_from_statement']:
                imports.append(content_bytes[node.start_byte:node.end_byte].decode('utf8'))
                
            for child in node.children:
                walk(child)
                
        walk(root_node)
        
        return {
            "file": filepath,
            "language": "python",
            "imports": imports,
            "functions": functions
        }

    def _extract_js_graph(self, tree, content_bytes: bytes, filepath: str) -> Dict[str, Any]:
        """Extracts AST nodes for JS/TS."""
        root_node = tree.root_node
        functions = []
        imports = []
        
        def walk(node):
            if node.type in ['function_declaration', 'arrow_function']:
                # Extract name (might not exist for arrow functions)
                name_node = node.child_by_field_name('name')
                func_name = content_bytes[name_node.start_byte:name_node.end_byte].decode('utf8') if name_node else "anonymous"
                
                body = content_bytes[node.start_byte:node.end_byte].decode('utf8')
                
                calls = self._find_nodes_of_type(node, 'call_expression')
                call_names = []
                for call in calls:
                    func_node = call.child_by_field_name('function')
                    if func_node:
                        call_names.append(content_bytes[func_node.start_byte:func_node.end_byte].decode('utf8'))
                
                functions.append({
                    "name": func_name,
                    "calls": call_names,
                    "body": body
                })
                
            elif node.type == 'import_statement':
                imports.append(content_bytes[node.start_byte:node.end_byte].decode('utf8'))
                
            for child in node.children:
                walk(child)
                
        walk(root_node)
        
        return {
            "file": filepath,
            "language": "javascript",
            "imports": imports,
            "functions": functions
        }

    def _find_nodes_of_type(self, node, node_type: str) -> List[Any]:
        """Recursively finds all descendant nodes of a specific type."""
        results = []
        for child in node.children:
            if child.type == node_type:
                results.append(child)
            results.extend(self._find_nodes_of_type(child, node_type))
        return results
