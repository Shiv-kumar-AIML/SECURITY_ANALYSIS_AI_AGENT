import json
from pathlib import Path
from core.parser import CodeParser
from core.analysis.ast_parser import TreeSitterParser

def test_ast_size():
    # Setup paths
    repo_path = Path(".scan_cache/clones/megamart-web")
    if not repo_path.exists():
        print("Repo not found")
        return
        
    print(f"Scanning {repo_path}")
    parser = CodeParser(repo_path)
    files = parser.get_all_files()
    
    ts_parser = TreeSitterParser()
    
    ast_graphs = []
    raw_size = 0
    for f in files:
        raw_size += f.stat().st_size
        graph = ts_parser.parse_file(str(f))
        if graph:
            ast_graphs.append(graph)
            
    json_output = json.dumps(ast_graphs, indent=2)
    new_size = len(json_output)
    
    print(f"Total Files: {len(files)}")
    print(f"Raw Size (bytes): {raw_size}")
    print(f"AST JSON Size (bytes): {new_size}")
    print(f"Reduction: {(1 - new_size/raw_size)*100:.2f}%")

if __name__ == "__main__":
    test_ast_size()
