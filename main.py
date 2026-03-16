"""
Security Analysis Agent — Production Multi-Agent Security Scanner
Entry point with Rich CLI interface.
"""
import argparse
import sys
import os
import subprocess
import time
from urllib.parse import urlparse
from pathlib import Path

from core.parser import CodeParser
from core.orchestrator import SASTOrchestrator
from core.report_generator import ReportGenerator
from core.constants import SKILLS_DIR, DEFAULT_OLLAMA_MODEL, DEFAULT_OPENAI_MODEL, DEFAULT_GEMINI_MODEL, BASE_DIR, WORKSPACE_DIR
from core.tools.tool_registry import ToolRegistry
from core.scan_cache import ScanCache

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich import box
    HAS_RICH = True
except ImportError:
    HAS_RICH = False


BANNER = """
[bold bright_cyan]
  ╔═════════════════════════════════════════════════════════════╗
  ║          🛡️  SECURITY ANALYSIS AGENT  v2.0                  ║
  ║       Multi-Agent Reasoning-Based Vulnerability Scanner     ║
  ╚═════════════════════════════════════════════════════════════╝
[/bold bright_cyan]"""

BANNER_PLAIN = """
  ╔═════════════════════════════════════════════════════════════╗
  ║          🛡️  SECURITY ANALYSIS AGENT  v2.0                  ║
  ║       Multi-Agent Reasoning-Based Vulnerability Scanner     ║
  ╚═════════════════════════════════════════════════════════════╝
"""


def get_console():
    if HAS_RICH:
        return Console()
    return None


def check_setup():
    if not SKILLS_DIR.exists():
        SKILLS_DIR.mkdir(parents=True)


def clone_repo(repo_url: str, console=None, pull: bool = False) -> str:
    parsed = urlparse(repo_url)
    repo_name = os.path.basename(parsed.path).replace(".git", "")
    if not repo_name:
        repo_name = "cloned_repo"

    clone_dir = WORKSPACE_DIR / repo_name

    if clone_dir.exists():
        if pull:
            # Incremental mode: fetch latest commits so git diff sees new work
            msg = f"Pulling latest changes into {clone_dir.name}..."
            if console:
                console.print(f"  [cyan]▸[/cyan] {msg}")
            else:
                print(f"[*] {msg}")
            try:
                result = subprocess.run(
                    ["git", "-C", str(clone_dir), "pull", "--ff-only"],
                    capture_output=True, text=True, timeout=60,
                )
                if result.returncode == 0:
                    pulled = result.stdout.strip()
                    label = pulled if pulled else "Already up to date."
                    if console:
                        console.print(f"  [green]✓[/green] {label}")
                    else:
                        print(f"[+] {label}")
                else:
                    # Fall back to fetch + reset (handles force-pushes / diverged history)
                    subprocess.run(
                        ["git", "-C", str(clone_dir), "fetch", "--depth=100", "origin"],
                        check=True, capture_output=True, timeout=60,
                    )
                    subprocess.run(
                        ["git", "-C", str(clone_dir), "reset", "--hard", "origin/HEAD"],
                        check=True, capture_output=True, timeout=30,
                    )
                    if console:
                        console.print(f"  [green]✓[/green] Hard-reset to origin/HEAD.")
                    else:
                        print("[+] Hard-reset to origin/HEAD.")
            except Exception as e:
                msg = f"git pull failed ({e}). Scanning existing local copy."
                if console:
                    console.print(f"  [yellow]⚠[/yellow] {msg}")
                else:
                    print(f"[!] {msg}")
        else:
            msg = f"Repository already exists at {clone_dir}. Using existing code..."
            if console:
                console.print(f"  [yellow]⚠[/yellow] {msg}")
            else:
                print(f"[*] {msg}")
        return str(clone_dir)

    msg = f"Cloning repository from {repo_url}..."
    if console:
        console.print(f"  [cyan]▸[/cyan] {msg}")
    else:
        print(f"[*] {msg}")

    try:
        clone_dir.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["git", "clone", repo_url, str(clone_dir)],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
    except subprocess.CalledProcessError as e:
        msg = f"Failed to clone repository: {e}"
        if console:
            console.print(f"  [red]✗[/red] {msg}")
        else:
            print(f"[-] {msg}")
        sys.exit(1)

    return str(clone_dir)


def print_tool_status(console):
    """Print the status of all external scanning tools."""
    registry = ToolRegistry()
    status = registry.get_status_report()

    table = Table(
        title="🔧 Tool Status",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("Tool", style="bold")
    table.add_column("Status", justify="center")
    table.add_column("Description")

    descriptions = {
        "semgrep": "Pattern-based SAST scanner",
        "bandit": "Python-specific security linter",
        "trivy": "SCA, container & IaC scanner",
        "gitleaks": "Secret & credential detector",
        "npm_audit": "Node.js dependency auditor",
    }

    for tool_name, available in status.items():
        status_icon = "[green]✓ Installed[/green]" if available else "[dim]✗ Not Found[/dim]"
        desc = descriptions.get(tool_name, "")
        table.add_row(tool_name, status_icon, desc)

    console.print(table)
    console.print()


def print_scan_config(console, target_path, llm_provider, model, tools_only=False):
    """Print scan configuration panel."""
    
    # Capitalize cleanly for display
    display_provider = "Google Gemini" if llm_provider == "gemini" else "OpenAI API" if llm_provider == "openai" else "Local Ollama"
    
    config_text = Text()
    config_text.append("  Target:  ", style="dim")
    config_text.append(f"{Path(target_path).resolve()}\n", style="bold")
    config_text.append("  Provider: ", style="dim")
    config_text.append(f"{display_provider}\n", style="bold cyan")
    config_text.append("  Model:   ", style="dim")
    config_text.append(f"{model}\n", style="bold green")
    config_text.append("  Mode:    ", style="dim")
    config_text.append("Tools Only" if tools_only else "Multi-Agent (Full)", style="bold yellow")

    console.print(Panel(config_text, title="[bold]Scan Configuration[/bold]", border_style="bright_blue"))
    console.print()


def print_results_summary(console, scan_result):
    """Print a beautiful results summary."""
    from core.findings import Severity
    from core.report_generator import ReportGenerator

    confirmed = scan_result.get_confirmed()
    false_positives = [f for f in scan_result.findings if f.is_false_positive]
    scan_duration = scan_result.scan_end - scan_result.scan_start if scan_result.scan_end else 0

    # Deduplicate to match report counts
    report_gen = ReportGenerator(scan_result)
    unique_confirmed = report_gen._deduplicate(confirmed)

    # Severity summary table (using deduped counts = matches report)
    table = Table(
        title="📊 Findings Summary",
        box=box.HEAVY_EDGE,
        show_header=True,
        header_style="bold white",
    )
    table.add_column("Severity", style="bold", justify="center")
    table.add_column("Count", justify="center")
    table.add_column("", min_width=20)

    for sev in Severity:
        count = len([f for f in unique_confirmed if f.severity == sev])
        bar = "█" * min(count * 2, 30) or "—"
        table.add_row(
            f"{sev.emoji} {sev.value}",
            str(count),
            f"[{sev.color}]{bar}[/{sev.color}]",
        )

    console.print(table)
    console.print()

    # Stats panel
    stats = Text()
    stats.append("  Total Unique:     ", style="dim")
    stats.append(f"{len(unique_confirmed)}\n", style="bold bright_red" if len(unique_confirmed) > 0 else "bold green")
    if len(confirmed) != len(unique_confirmed):
        stats.append("  Duplicates Merged:", style="dim")
        stats.append(f" {len(confirmed) - len(unique_confirmed)}\n", style="bold")
    stats.append("  False Positives:  ", style="dim")
    stats.append(f"{len(false_positives)}\n", style="bold")
    stats.append("  Files Scanned:    ", style="dim")
    stats.append(f"{scan_result.files_scanned}\n", style="bold")
    stats.append("  Lines of Code:    ", style="dim")
    stats.append(f"{scan_result.total_lines}\n", style="bold")
    stats.append("  Scan Duration:    ", style="dim")
    stats.append(f"{scan_duration:.1f}s\n", style="bold")
    stats.append("  Risk Score:       ", style="dim")
    risk = scan_result.risk_score
    risk_color = "green" if risk < 3 else "yellow" if risk < 7 else "bright_red"
    stats.append(f"{risk:.1f}/10", style=f"bold {risk_color}")

    console.print(Panel(stats, title="[bold]Scan Statistics[/bold]", border_style="bright_green"))
    console.print()

    # Top findings preview
    if confirmed:
        console.print("[bold]🔍 Top Findings Preview:[/bold]\n")
        for i, f in enumerate(sorted(confirmed, key=lambda x: x.severity.score, reverse=True)[:5], 1):
            console.print(f"  {f.severity.emoji} [bold]{f.title}[/bold]")
            console.print(f"     [dim]{f.file_path}:{f.line_number} | {f.cwe_id} | Confidence: {f.confidence:.0%}[/dim]")
        console.print()


def main():
    parser = argparse.ArgumentParser(
        description="🛡️ Security Analysis Agent — Multi-Agent Reasoning-Based Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("target",
                        help="Directory of the codebase OR a Git repository URL to scan")
    parser.add_argument("--model",
                        help="LLM model to use (overrides provider defaults)",
                        default=None)
    parser.add_argument("--llm-provider",
                        help="LLM provider: openai, gemini, or ollama (falls back to keys if not set)",
                        choices=["openai", "gemini", "ollama"],
                        default=None)
    parser.add_argument("--gemini-key",
                        help="Google Gemini API Key",
                        default=None)
    parser.add_argument("--openai-key",
                        help="OpenAI API Key (or compatible)",
                        default=None)
    parser.add_argument("--openai-base-url",
                        help="OpenAI-compatible base URL",
                        default=None)
    parser.add_argument("--tools-only",
                        action="store_true",
                        help="Run only external tools (no LLM analysis)")
    parser.add_argument("--full-context",
                        action="store_true",
                        help="Disable smart context (send all code to LLM, legacy behavior)")
    parser.add_argument("--output-format",
                        choices=["markdown", "json", "sarif", "all"],
                        default="all",
                        help="Report output format (default: all)")
    parser.add_argument("--incremental",
                        action="store_true",
                        help="Only re-scan files changed since the last cached scan (git-aware)")
    args = parser.parse_args()

    from dotenv import load_dotenv
    load_dotenv()

    # Resolution prioritization: CLI Arguments first, then Env Variables, then Defaults
    llm_provider = args.llm_provider or os.getenv("LLM_PROVIDER")
    openai_key = args.openai_key or os.getenv("OPENAI_API_KEY")
    gemini_key = args.gemini_key or os.getenv("GEMINI_API_KEY")
    openai_base_url = args.openai_base_url or os.getenv("OPENAI_BASE_URL")

    console = get_console()
    check_setup()

    # Banner
    if console:
        console.print(BANNER)
    else:
        print(BANNER_PLAIN)

    # Handle Git URL
    target_path = args.target
    if target_path.startswith(("http://", "https://", "git@")):
        target_path = clone_repo(target_path, console, pull=args.incremental)

    # Determine llm_provider purely from explicit or fallback input
    if not llm_provider:
        if openai_key:
            llm_provider = "openai"
        elif gemini_key:
            llm_provider = "gemini"
        else:
            llm_provider = "ollama"
    
    llm_provider = llm_provider.lower()

    # Determine default model for the selected provider
    if llm_provider == "openai":
        provider_default_model = DEFAULT_OPENAI_MODEL
    elif llm_provider == "gemini":
        provider_default_model = DEFAULT_GEMINI_MODEL
    else:
        provider_default_model = DEFAULT_OLLAMA_MODEL

    model_name = args.model or provider_default_model

    # Print config
    if console:
        print_scan_config(console, target_path, llm_provider, model_name, args.tools_only)
        print_tool_status(console)
    else:
        print(f"[+] Target: {Path(target_path).resolve()}")
        print(f"[+] Provider: {llm_provider}")
        print(f"[+] Model: {model_name}")

    # ── Incremental scan: compute diff before parsing ───────────────────
    scan_cache = ScanCache(target_path)
    cached_findings = []
    files_to_rescan = None   # None → full scan; list → subset

    if args.incremental:
        if not scan_cache.is_warm():
            if console:
                console.print("  [yellow]⚠[/yellow] No previous cache found — running full scan to build baseline.")
            else:
                print("[*] Incremental: no previous cache — running full baseline scan.")
        else:
            changed, added, deleted = scan_cache.compute_diff()
            diff_info = scan_cache.summary(changed, added, deleted)

            if not changed and not added and not deleted:
                if console:
                    console.print("  [green]✓[/green] [bold]Incremental:[/bold] No files changed since last scan — reusing cached results.")
                else:
                    print("[+] Incremental: nothing changed — using cached results.")

                # Restore everything from cache and skip the scan entirely
                from core.findings import ScanResult
                scan_result = ScanResult(target_path=target_path)
                for f in scan_cache.get_cached_findings([]):
                    scan_result.add_finding(f)
                scan_result.scan_end = scan_result.scan_start

                report_gen = ReportGenerator(scan_result)
                reports_generated = []
                fmt = args.output_format
                if fmt in ("markdown", "all"):
                    reports_generated.append(("Markdown", report_gen.to_markdown()))
                if fmt in ("json", "all"):
                    reports_generated.append(("JSON", report_gen.to_json()))
                if fmt in ("sarif", "all"):
                    reports_generated.append(("SARIF", report_gen.to_sarif()))

                if console:
                    console.print("\n[bold]📄 Reports Generated (from cache):[/bold]\n")
                    for name, path in reports_generated:
                        console.print(f"  [green]✓[/green] {name}: [link={path}]{path}[/link]")
                else:
                    print("\n[+] Reports Generated (from cache):")
                    for name, path in reports_generated:
                        print(f"  - {name}: {path}")
                sys.exit(0)

            # Partial rescan: only changed + added files
            files_to_rescan = changed + added
            cached_findings = scan_cache.get_cached_findings(files_to_rescan + deleted)

            if console:
                console.print(f"  [cyan]▸[/cyan] [bold]Incremental scan:[/bold] "
                              f"{len(files_to_rescan)} changed / {len(deleted)} deleted "
                              f"(reusing cached findings for "
                              f"{diff_info['cached_files'] - len(files_to_rescan) - len(deleted)} unchanged files)")
            else:
                print(f"[*] Incremental: {len(files_to_rescan)} changed, {len(deleted)} deleted.")

    # ── Parse code ───────────────────────────────────────────────────────
    if console:
        console.rule("[bold]Parsing Target Codebase[/bold]")
    else:
        print("\n[*] Parsing target codebase...")

    code_parser = CodeParser(target_path)

    # Smart Context (default) vs Full Context (legacy)
    if args.full_context:
        if files_to_rescan is not None:
            target_code = code_parser.extract_context_for_files(files_to_rescan)
            if console:
                console.print(f"  [yellow]⚠[/yellow] Incremental full-context: [bold]{len(target_code)}[/bold] chars ({len(files_to_rescan)} files)")
            else:
                print(f"[*] Incremental full context: {len(target_code)} characters.")
        else:
            target_code = code_parser.extract_context()
            if console:
                console.print(f"  [yellow]⚠[/yellow] Full context mode (legacy): [bold]{len(target_code)}[/bold] chars")
            else:
                print(f"[*] Full context mode: {len(target_code)} characters.")
    else:
        if console:
            console.print("  [cyan]▸[/cyan] Running pre-analysis pipeline (AST → Symbol Table → Call Graph)...")
        else:
            print("[*] Running pre-analysis pipeline...")

        # In incremental mode, skip the heavy AST pipeline and build context
        # directly for the changed files.  The full smart-context pipeline is
        # only worth running for a complete codebase scan.
        if files_to_rescan is not None:
            target_code = code_parser.extract_context_for_files(files_to_rescan)
            if console:
                console.print(f"  [green]✓[/green] Incremental smart context: "
                              f"[bold]{len(target_code):,}[/bold] chars "
                              f"({len(files_to_rescan)} changed files)")
            else:
                print(f"[+] Incremental context: {len(target_code)} chars ({len(files_to_rescan)} files).")
        else:
            smart_result = code_parser.extract_smart_context()
            target_code = smart_result["context"]
            meta = smart_result["metadata"]
            stats = smart_result["stats"]

            if console:
                if meta.get("used_fallback"):
                    reason = meta.get("fallback_reason", "unknown")
                    console.print(f"  [yellow]⚠[/yellow] Fallback to full context: {reason}")
                    console.print(f"  [green]✓[/green] Context: [bold]{len(target_code)}[/bold] chars")
                else:
                    console.print(f"  [green]✓[/green] Functions analyzed: [bold]{meta['functions_total']}[/bold]")
                    console.print(f"  [green]✓[/green] Security-relevant selected: [bold]{meta['functions_selected']}[/bold]")
                    console.print(f"  [green]✓[/green] Sink chains found: [bold]{meta['sink_chains_found']}[/bold] ({meta['dangerous_chains']} dangerous)")
                    console.print(f"  [green]✓[/green] Context: [bold]{stats['filtered_chars']:,}[/bold] / {stats['original_chars']:,} chars [bold bright_green]({stats['reduction_percent']}% reduction)[/bold bright_green]")
            else:
                if meta.get("used_fallback"):
                    print(f"[*] Fallback to full context: {meta.get('fallback_reason', '')}")
                else:
                    print(f"[+] Smart context: {stats['filtered_chars']} / {stats['original_chars']} chars ({stats['reduction_percent']}% reduction)")

    if not target_code and not args.tools_only:
        msg = "No supported source files found. Exiting."
        if console:
            console.print(f"  [red]✗[/red] {msg}")
        else:
            print(f"[-] {msg}")
        sys.exit(1)

    if console:
        console.print()

    # Run Scan
    try:
        orchestrator = SASTOrchestrator(
            target_code=target_code,
            target_path=target_path,
            model_name=model_name,
            gemini_key=gemini_key,
            openai_key=openai_key,
            openai_base_url=openai_base_url,
            llm_provider=llm_provider,
        )

        if args.tools_only:
            scan_result = orchestrator.analyze_tools_only(console=console)
        else:
            scan_result = orchestrator.analyze(console=console)

    except KeyboardInterrupt:
        msg = "Scan interrupted by user."
        if console:
            console.print(f"\n  [yellow]⚠[/yellow] {msg}")
        else:
            print(f"\n[-] {msg}")
        sys.exit(1)

    # ── Merge cached findings from unchanged files ────────────────────────
    if cached_findings:
        for f in cached_findings:
            scan_result.add_finding(f)
        if console:
            console.print(f"  [dim]↩ Merged {len(cached_findings)} cached findings from unchanged files.[/dim]")

    # ── Persist cache after every successful scan ─────────────────────────
    if args.incremental or not scan_cache.is_warm():
        scan_cache.save(scan_result.get_confirmed())

    # Results summary
    if console:
        console.print()
        console.rule("[bold bright_green]Scan Complete[/bold bright_green]")
        console.print()
        print_results_summary(console, scan_result)
    else:
        confirmed = scan_result.get_confirmed()
        print(f"\n[+] Scan complete! {len(confirmed)} confirmed findings.")

    # Generate Reports
    report_gen = ReportGenerator(scan_result)

    reports_generated = []
    fmt = args.output_format

    if fmt in ("markdown", "all"):
        md_report = report_gen.to_markdown()
        reports_generated.append(("Markdown", md_report))

    if fmt in ("json", "all"):
        json_report = report_gen.to_json()
        reports_generated.append(("JSON", json_report))

    if fmt in ("sarif", "all"):
        sarif_report = report_gen.to_sarif()
        reports_generated.append(("SARIF", sarif_report))

    # Print report paths
    if console:
        console.print("[bold]📄 Reports Generated:[/bold]\n")
        for name, path in reports_generated:
            console.print(f"  [green]✓[/green] {name}: [link={path}]{path}[/link]")
        console.print()
    else:
        print("\n[+] Reports Generated:")
        for name, path in reports_generated:
            print(f"  - {name}: {path}")


if __name__ == "__main__":
    main()
