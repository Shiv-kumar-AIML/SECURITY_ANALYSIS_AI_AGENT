import argparse
import sys
import os
from pathlib import Path
from core.parser import CodeParser
from core.orchestrator import SASTOrchestrator
from core.report_generator import ReportGenerator
from core.constants import SKILLS_DIR, DEFAULT_MODEL, BASE_DIR
from core.git_utils import clone_repo, is_git_url

def check_setup():
    if not SKILLS_DIR.exists():
        SKILLS_DIR.mkdir(parents=True)
        print(f"[*] Created skills directory at {SKILLS_DIR}")

def main():
    parser = argparse.ArgumentParser(description="Multi-Agent Enterprise SAST & SCA Scanner")
    parser.add_argument("target", help="Directory of the codebase OR a Git repository URL to scan")
    parser.add_argument("--model", help=f"Ollama/Gemini/OpenAI model to use (default: {DEFAULT_MODEL})", default=DEFAULT_MODEL)
    parser.add_argument("--gemini-key", help="Google Gemini API Key (switches engine from local Ollama to cloud Gemini)", default=None)
    parser.add_argument("--openai-key", help="OpenAI API Key (switches engine from local Ollama to cloud OpenAI)", default=None)
    args = parser.parse_args()

    check_setup()

    target_path = args.target
    if is_git_url(target_path):
        target_path = clone_repo(target_path)

    print(f"\n[+] Initializing SAST scan on: {Path(target_path).resolve()}")
    if args.openai_key:
        print(f"[+] Using Engine: OpenAI API")
    elif args.gemini_key:
        print(f"[+] Using Engine: Google Gemini API")
    else:
        print(f"[+] Using Engine: Local Ollama")
        
    print(f"[+] Using LLM Model: {args.model}")
    
    # 1. Parse Code
    print("\n[*] Parsing target codebase...")
    code_parser = CodeParser(target_path)
    target_code = code_parser.extract_context()
    
    if not target_code:
        print("[-] No supported source files found. Exiting.")
        sys.exit(1)
        
    print(f"[+] Extracted codebase context: {len(target_code)} characters.")
    
    # 2. Orchestrate Scan
    try:
        orchestrator = SASTOrchestrator(target_code, model_name=args.model, gemini_key=args.gemini_key, openai_key=args.openai_key)
        results = orchestrator.analyze()
    except KeyboardInterrupt:
        print("\n[-] Scan interrupted by user.")
        sys.exit(1)
    
    # 3. Generate Report
    print("\n[*] Generating verification report...")
    report_gen = ReportGenerator(results)
    report_file = report_gen.to_markdown()
    
    print(f"\n[+] Scan Complete! High-confidence report saved to: {report_file}")

if __name__ == "__main__":
    main()
