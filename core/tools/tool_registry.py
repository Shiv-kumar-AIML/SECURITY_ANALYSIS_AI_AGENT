"""
Tool Registry — auto-discovers and manages all available security scanning tools.
"""
from typing import List, Dict
from .base_tool import BaseTool
from .semgrep_scanner import SemgrepScanner
from .bandit_scanner import BanditScanner
from .trivy_scanner import TrivyScanner
from .gitleaks_scanner import GitleaksScanner
from .npm_audit import NpmAuditScanner
from .hardcoded_pattern_scanner import HardcodedPatternScanner
from ..findings import Finding


# All registered tool classes
ALL_TOOLS = [
    SemgrepScanner,
    BanditScanner,
    TrivyScanner,
    GitleaksScanner,
    NpmAuditScanner,
    HardcodedPatternScanner,
]


class ToolRegistry:
    """Manages discovery and execution of all external scanning tools."""

    def __init__(self):
        self.tools: List[BaseTool] = [ToolClass() for ToolClass in ALL_TOOLS]

    def get_available_tools(self) -> List[BaseTool]:
        """Return only tools that are installed on the system."""
        return [t for t in self.tools if t.is_available()]

    def get_unavailable_tools(self) -> List[BaseTool]:
        """Return tools that are NOT installed."""
        return [t for t in self.tools if not t.is_available()]

    def scan_all(self, target_path: str, console=None) -> List[Finding]:
        """Run all available tools and collect findings."""
        all_findings = []
        available = self.get_available_tools()

        if not available:
            if console:
                console.print("[dim]No external scanning tools detected. Using AI-only analysis.[/dim]")
            return all_findings

        for tool in available:
            try:
                if console:
                    console.print(f"  [cyan]▸[/cyan] Running [bold]{tool.name}[/bold]...")
                results = tool.scan(target_path)
                all_findings.extend(results)
                if console:
                    count = len(results)
                    color = "green" if count == 0 else "yellow"
                    console.print(f"    [{color}]└─ {count} finding(s)[/{color}]")
            except Exception as e:
                if console:
                    console.print(f"    [red]└─ Error: {e}[/red]")

        return all_findings

    def get_status_report(self) -> Dict[str, bool]:
        """Get availability status of all tools."""
        return {t.name: t.is_available() for t in self.tools}
