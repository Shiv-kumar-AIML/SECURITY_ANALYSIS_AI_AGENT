import os
from pathlib import Path
from .constants import SUPPORTED_EXTENSIONS

class CodeParser:
    def __init__(self, target_dir):
        self.target_dir = Path(target_dir).resolve()

    def get_all_files(self):
        code_files = []
        # Exclude massive built folders and unneeded assets
        exclude_dirs = {'.git', 'node_modules', 'venv', 'env', '.venv', 'dist', 'build', '.next', 'out', 'coverage', '.cache'}
        exclude_files = {'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'Pipfile.lock', 'poetry.lock'}
        
        for root, dirs, files in os.walk(self.target_dir):
            # Prune excluded directories
            dirs[:] = [d for d in dirs if d not in exclude_dirs and not d.startswith('.')]
            
            for file in files:
                if file in exclude_files:
                    continue
                    
                ext = Path(file).suffix
                if ext in SUPPORTED_EXTENSIONS:
                    file_path = Path(root) / file
                    # Skip files larger than 100KB to prevent context limit errors
                    try:
                        if file_path.stat().st_size <= 100 * 1024: 
                            code_files.append(file_path)
                    except Exception:
                        pass
        return code_files

    def extract_context(self):
        if not self.target_dir.exists() or not self.target_dir.is_dir():
            print(f"[-] Invalid target directory: {self.target_dir}")
            return ""
            
        import json
        try:
            from .tree_sitter_parser import TreeSitterParser
            ts_parser = TreeSitterParser()
        except ImportError:
            ts_parser = None
            
        files = self.get_all_files()
        context_blocks = []
        for file in files:
            try:
                rel_path = file.relative_to(self.target_dir)
                added_ast = False
                
                # Try AST extraction first
                if ts_parser:
                    ext = file.suffix
                    if ext in ['.py', '.js', '.jsx', '.ts', '.tsx']:
                        graph = ts_parser.parse_file(str(file))
                        if graph and graph.get('functions'):
                            # Strip out body sizes > 2000 chars to save tokens
                            for func in graph['functions']:
                                if len(func.get('body', '')) > 2000:
                                    func['body'] = func['body'][:2000] + "... [TRUNCATED]"
                                    
                            json_graph = json.dumps(graph, indent=2)
                            context_blocks.append(f"--- AST GRAPH: {rel_path} ---\n{json_graph}\n")
                            added_ast = True
                            
                # Fallback to raw text if no AST or graph is empty
                if not added_ast:
                    with open(file, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    # Limit raw files to save tokens
                    if len(content) > 5000:
                        content = content[:5000] + "\n... [TRUNCATED]"
                    context_blocks.append(f"--- RAW FILE: {rel_path} ---\n{content}\n")
                    
            except Exception as e:
                print(f"[-] Error parsing {file}: {e}")
                
        # To prevent hitting LLM context limits entirely, chunk the final context
        # We will split it into manageable chunks inside the Orchestrator, but here we return a single string
        return "\n".join(context_blocks)