"""
CLI tool for viewing security scan reports and statistics.
"""
import json
import sys
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime
from collections import defaultdict

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.syntax import Syntax
    from rich.progress import Progress
    HAS_RICH = True
except ImportError:
    HAS_RICH = False


class SecurityReportCLI:
    """CLI for viewing security reports."""

    def __init__(self, reports_dir: str = "reports"):
        """Initialize CLI."""
        self.reports_dir = Path(reports_dir)
        self.console = Console() if HAS_RICH else None

    def list_reports(self):
        """List all available reports."""
        if not self.reports_dir.exists():
            print(f"❌ Reports directory not found: {self.reports_dir}")
            return

        json_reports = sorted(self.reports_dir.glob("*.json"), reverse=True)

        if not json_reports:
            print("📭 No reports found yet.")
            return

        print("\n" + "=" * 80)
        print("📊 SECURITY ANALYSIS REPORTS")
        print("=" * 80 + "\n")

        if HAS_RICH:
            table = Table(title="Available Reports", show_header=True, header_style="bold cyan")
            table.add_column("Report", style="yellow")
            table.add_column("Repository", style="magenta")
            table.add_column("PR", style="cyan")
            table.add_column("Findings", style="red")
            table.add_column("Generated", style="green")

            for report_path in json_reports:
                with open(report_path) as f:
                    report = json.load(f)

                timestamp = report.get("timestamp", "")
                if timestamp:
                    try:
                        dt = datetime.fromisoformat(timestamp)
                        formatted_time = dt.strftime("%Y-%m-%d %H:%M:%S")
                    except (ValueError, TypeError):
                        formatted_time = "Invalid"
                else:
                    formatted_time = "N/A"

                # Handle both report formats
                total_findings = report.get("total_findings", report.get("total_confirmed", 0))
                repo = report.get("repository", "?")
                if repo == "?":
                    # Try to extract from report_info (security_report format)
                    report_info = report.get("report_info", {})
                    target = report_info.get("target", "?")
                    if target != "?":
                        # Extract repo name from path
                        repo = target.split("/")[-1]
                pr = report.get("pull_request", "?")

                table.add_row(
                    report_path.name,
                    repo,
                    f"#{pr}" if pr != "?" else "N/A",
                    str(total_findings),
                    formatted_time,
                )

            self.console.print(table)
        else:
            for i, report_path in enumerate(json_reports, 1):
                with open(report_path) as f:
                    report = json.load(f)

                # Handle both report formats
                total_findings = report.get("total_findings", report.get("total_confirmed", 0))
                repo = report.get("repository", "?")
                if repo == "?":
                    # Try to extract from report_info (security_report format)
                    report_info = report.get("report_info", {})
                    target = report_info.get("target", "?")
                    if target != "?":
                        # Extract repo name from path
                        repo = target.split("/")[-1]
                pr = report.get("pull_request", "?")

                print(
                    f"{i}. {report_path.name} — "
                    f"Repo: {repo} | "
                    f"PR: {f'#{pr}' if pr != '?' else 'N/A'} | "
                    f"Findings: {total_findings}"
                )

        print()

    def show_report(self, report_name: str = None):
        """Show detailed report."""
        json_reports = sorted(self.reports_dir.glob("*.json"), reverse=True)

        if not json_reports:
            print("❌ No reports found.")
            return

        # Use latest if not specified
        if report_name is None:
            report_path = json_reports[0]
        else:
            report_path = self.reports_dir / report_name
            if not report_path.exists():
                print(f"❌ Report not found: {report_name}")
                return

        with open(report_path) as f:
            report = json.load(f)

        # Detect report format
        is_type1 = "findings_by_severity" in report

        if is_type1:
            # Type 1: webhook_server format
            timestamp = report.get("timestamp", "")
            repo = report.get("repository", "?")
            pr = report.get("pull_request", "?")
            files_scanned = report.get("files_scanned", 0)
            total_findings = report.get("total_findings", 0)
            sev_counts = report.get("findings_by_severity", {})
            findings = report.get("findings", [])
        else:
            # Type 2: security_report format
            report_info = report.get("report_info", {})
            timestamp = report_info.get("date", "")
            target = report_info.get("target", "?")
            repo = target.split("/")[-1] if target != "?" else "?"
            pr = report_info.get("pr_number", "?")
            files_scanned = report_info.get("files_scanned", 0)
            total_findings = report.get("total_confirmed", 0)
            sev_counts = report.get("summary", {})

            # Flatten findings from severity dict into array
            findings = []
            findings_by_sev = report.get("findings", {})
            if isinstance(findings_by_sev, dict):
                for severity, items in findings_by_sev.items():
                    if isinstance(items, list):
                        findings.extend(items)
            else:
                findings = findings_by_sev if isinstance(findings_by_sev, list) else []

        # Header
        print("\n" + "=" * 80)
        print(f"🔍 SECURITY ANALYSIS REPORT: {repo} PR #{pr}")
        print("=" * 80 + "\n")

        # Summary
        print(f"📋 Generated: {timestamp or 'N/A'}")
        print(f"📂 Repository: {repo}")
        print(f"🔗 Pull Request: #{pr}")
        print(f"📄 Files Scanned: {files_scanned}")
        print(f"🔴 Total Findings: {total_findings}\n")

        # Severity breakdown
        if HAS_RICH:
            severity_table = Table(title="Findings by Severity", show_header=True, header_style="bold")
            severity_table.add_column("Severity", style="bold")
            severity_table.add_column("Count", style="bold")

            severity_colors = {
                "CRITICAL": "[bold red]CRITICAL[/]",
                "HIGH": "[bold orange1]HIGH[/]",
                "MEDIUM": "[bold yellow]MEDIUM[/]",
                "LOW": "[bold green]LOW[/]",
            }

            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                count = sev_counts.get(sev, 0)
                color = severity_colors.get(sev, sev)
                severity_table.add_row(color, str(count))

            self.console.print(severity_table)
        else:
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                count = sev_counts.get(sev, 0)
                print(f"  {sev}: {count}")

        print()

        # Normalize findings for display (handle both formats)
        def normalize_finding(f):
            """Extract relevant info from finding regardless of format."""
            if not isinstance(f, dict):
                return None

            # Type 1 format
            if "severity" in f:
                return {
                    "severity": f.get("severity", "?"),
                    "title": f.get("title", "Unknown"),
                    "file": f.get("file", "?"),
                    "line": f.get("line", "?"),
                    "description": f.get("description", "")[:80],
                    "source": f.get("source", "UNKNOWN"),
                    "cwe": f.get("cwe", "Unknown"),
                    "owasp": f.get("owasp", "Unknown"),
                }
            # Type 2 format (security_report)
            elif "vulnerable_code" in f:
                vc = f.get("vulnerable_code", {})
                return {
                    "severity": "UNKNOWN",  # Not in type 2
                    "title": f.get("title", "Unknown"),
                    "file": vc.get("file", "?"),
                    "line": vc.get("line", "?"),
                    "description": f.get("description", "")[:80],
                    "source": f.get("source", "vulnerability_agent"),
                    "cwe": f.get("metadata", {}).get("cwe", "Unknown"),
                    "owasp": f.get("metadata", {}).get("owasp", "Unknown"),
                }
            return None

        # Findings by tool
        by_tool = defaultdict(list)
        for finding in findings:
            normalized = normalize_finding(finding)
            if normalized:
                by_tool[normalized["source"]].append(finding)

        print("🛠️  Findings by Tool:\n")
        for tool, tool_findings in sorted(by_tool.items()):
            print(f"  {tool}: {len(tool_findings)} findings")

        print()

        # Top vulnerabilities
        print("🚨 Top Vulnerabilities:\n")
        for i, finding in enumerate(findings[:10], 1):
            normalized = normalize_finding(finding)
            if not normalized:
                continue

            print(f"  {i}. [{normalized['severity']}] {normalized['title']}")
            print(f"     📍 {normalized['file']}:{normalized['line']}")
            print(f"     ℹ️  {normalized['description']}...")
            print()

        if len(findings) > 10:
            print(f"  ... and {len(findings) - 10} more findings\n")

        # CWE/OWASP stats
        by_cwe = defaultdict(int)
        by_owasp = defaultdict(int)

        for finding in findings:
            normalized = normalize_finding(finding)
            if normalized:
                cwe = normalized.get("cwe", "Unknown")
                owasp = normalized.get("owasp", "Unknown")
                if cwe and cwe != "Unknown":
                    by_cwe[cwe] += 1
                if owasp and owasp != "Unknown":
                    by_owasp[owasp] += 1

        if by_cwe:
            print("📌 Top CWEs:\n")
            for cwe, count in sorted(by_cwe.items(), key=lambda x: x[1], reverse=True)[:5]:
                print(f"  {cwe}: {count} occurrences")
            print()

        if by_owasp:
            print("📌 Top OWASP Categories:\n")
            for owasp, count in sorted(by_owasp.items(), key=lambda x: x[1], reverse=True)[:5]:
                print(f"  {owasp}: {count} occurrences")
            print()

        print("=" * 80 + "\n")

    def show_stats(self):
        """Show overall statistics."""
        json_reports = sorted(self.reports_dir.glob("*.json"), reverse=True)

        if not json_reports:
            print("❌ No reports found.")
            return

        total_findings = 0
        total_scans = len(json_reports)
        sev_totals = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        by_tool_total = defaultdict(int)

        for report_path in json_reports:
            with open(report_path) as f:
                report = json.load(f)

            # Handle both report formats
            is_type1 = "findings_by_severity" in report

            if is_type1:
                total_findings += report.get("total_findings", 0)
                for sev, count in report.get("findings_by_severity", {}).items():
                    if sev in sev_totals:
                        sev_totals[sev] += count
            else:
                total_findings += report.get("total_confirmed", 0)
                for sev, count in report.get("summary", {}).items():
                    if sev in sev_totals:
                        sev_totals[sev] += count

            for finding in report.get("findings", []):
                tool = finding.get("source", "UNKNOWN") if isinstance(finding, dict) else "UNKNOWN"
                # Convert enum to string if needed
                if hasattr(tool, 'value'):
                    tool = tool.value
                by_tool_total[tool] += 1

        print("\n" + "=" * 80)
        print("📊 OVERALL STATISTICS")
        print("=" * 80 + "\n")

        print(f"📈 Total Scans: {total_scans}")
        print(f"🔴 Total Findings: {total_findings}")
        print(f"🔢 Average per Scan: {total_findings / total_scans:.1f}\n")

        print("Severity Distribution:\n")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = sev_totals[sev]
            pct = (count / total_findings * 100) if total_findings > 0 else 0
            bar = "█" * int(pct / 2)
            print(f"  {sev:8}: {count:3} ({pct:5.1f}%) {bar}")

        print("\n\nTop Tools:\n")
        for tool, count in sorted(by_tool_total.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {tool}: {count} findings")

        print("\n" + "=" * 80 + "\n")

    def compare_reports(self):
        """Compare last two reports."""
        json_reports = sorted(self.reports_dir.glob("*.json"), reverse=True)

        if len(json_reports) < 2:
            print("❌ Need at least 2 reports to compare.")
            return

        report1_path = json_reports[0]
        report2_path = json_reports[1]

        with open(report1_path) as f:
            report1 = json.load(f)
        with open(report2_path) as f:
            report2 = json.load(f)

        print("\n" + "=" * 80)
        print("📊 REPORT COMPARISON")
        print("=" * 80 + "\n")

        # Handle both report formats
        r1_findings = report1.get("total_findings", report1.get("total_confirmed", 0))
        r2_findings = report2.get("total_findings", report2.get("total_confirmed", 0))
        diff = r1_findings - r2_findings

        print(f"Latest Scan:  {r1_findings} findings")
        print(f"Previous Scan: {r2_findings} findings")

        if r2_findings > 0:
            pct_change = (diff / r2_findings * 100)
            print(f"Change: {diff:+d} ({pct_change:+.1f}%)\n")
        else:
            print(f"Change: {diff:+d} (N/A)\n")

        if diff < 0:
            print("✅ Great! Fewer vulnerabilities found!")
        elif diff > 0:
            print("⚠️  New vulnerabilities detected!")
        else:
            print("➡️  Same number of vulnerabilities")

        print("\n" + "=" * 80 + "\n")


def main():
    """Main CLI entry point."""
    if not HAS_RICH:
        print("⚠️  Install 'rich' for better formatting: pip install rich")

    cli = SecurityReportCLI()

    if len(sys.argv) < 2:
        # Show help
        print("""
🔐 PENTAS Security Reporter CLI

Usage:
  python -m backend.cli list          - List all reports
  python -m backend.cli show [name]   - Show detailed report (latest if no name)
  python -m backend.cli stats         - Show statistics across all scans
  python -m backend.cli compare       - Compare last two scans

Examples:
  python -m backend.cli list
  python -m backend.cli show testing_repo_PR5_20260320_114030.json
  python -m backend.cli stats
  python -m backend.cli compare
""")
        return

    command = sys.argv[1].lower()

    if command == "list":
        cli.list_reports()
    elif command == "show":
        report_name = sys.argv[2] if len(sys.argv) > 2 else None
        cli.show_report(report_name)
    elif command == "stats":
        cli.show_stats()
    elif command == "compare":
        cli.compare_reports()
    else:
        print(f"❌ Unknown command: {command}")
        print("Available: list, show, stats, compare")


if __name__ == "__main__":
    main()
