"""
Generate detailed security reports in multiple formats.
Saves findings to files for easy access.
"""
import json
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime


class ReportGenerator:
    """Generate security reports in JSON, HTML, and Markdown formats."""

    def __init__(self, output_dir: str = "reports"):
        """Initialize report generator."""
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_json_report(
        self,
        findings: List[Any],
        repo_name: str,
        pr_number: int,
        files_scanned: int,
    ) -> str:
        """
        Generate JSON report with full details.

        Returns:
            Path to generated report
        """
        timestamp = datetime.now().isoformat()
        filename = f"{repo_name}_PR{pr_number}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = self.output_dir / filename

        # Convert findings to dictionaries with all fields
        findings_dict = []
        for f in findings:
            source = f.source
            if hasattr(source, 'value'):
                source = source.value

            severity = f.severity
            if hasattr(severity, 'value'):
                severity = severity.value

            findings_dict.append({
                "title": f.title,
                "description": f.description,
                "severity": severity,
                "file": f.file_path,
                "line": f.line_number,
                "cwe": f.cwe_id,
                "owasp": f.owasp_category,
                "source": str(source),
                "confidence": f.confidence,
                "code_snippet": getattr(f, 'code_snippet', None),
                "remediation": getattr(f, 'remediation', None),
                "remediation_code": getattr(f, 'remediation_code', None),
                "reasoning_chain": getattr(f, 'reasoning_chain', None),
                "references": f.references,
            })

        report = {
            "timestamp": timestamp,
            "repository": repo_name,
            "pull_request": pr_number,
            "files_scanned": files_scanned,
            "total_findings": len(findings),
            "findings_by_severity": self._count_by_severity(findings_dict),
            "findings": findings_dict,
        }

        with open(filepath, "w") as f:
            json.dump(report, f, indent=2)

        return str(filepath)

    def generate_markdown_report(
        self,
        findings: List[Any],
        repo_name: str,
        pr_number: int,
        files_scanned: int,
    ) -> str:
        """
        Generate Markdown report with full details.

        Returns:
            Path to generated report
        """
        filename = f"{repo_name}_PR{pr_number}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        filepath = self.output_dir / filename

        # Count by severity
        by_severity = self._count_by_severity_objects(findings)

        content = f"""# 🛡️ Security Vulnerability Report

**Repository:** {repo_name}
**Pull Request:** #{pr_number}
**Files Scanned:** {files_scanned}
**Total Findings:** {len(findings)}
**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## 📊 Summary

| Severity | Count |
|----------|-------|
| 🔴 **CRITICAL** | {by_severity.get("CRITICAL", 0)} |
| 🟠 **HIGH** | {by_severity.get("HIGH", 0)} |
| 🟡 **MEDIUM** | {by_severity.get("MEDIUM", 0)} |
| 🔵 **LOW** | {by_severity.get("LOW", 0)} |

---

"""

        # Detailed findings by severity
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            findings_at_sev = [
                f for f in findings
                if (f.severity.value if hasattr(f.severity, 'value') else str(f.severity)) == severity
            ]

            if findings_at_sev:
                emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(severity, "")
                content += f"## {emoji} {severity} Severity Findings\n\n"

                for i, f in enumerate(findings_at_sev, 1):
                    sev_val = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
                    cwe_display = f.cwe_id or "N/A"
                    owasp_display = f.owasp_category or "N/A"

                    content += f"### {emoji} {i}. {f.title}\n\n"
                    content += f"**Tags**: `{cwe_display}` | `{owasp_display}` | Confidence: `{int(f.confidence * 100)}%`\n\n"
                    content += f"**Description:**\n{f.description}\n\n"

                    # Vulnerable code section
                    content += f"**Vulnerable Code:**\n"
                    content += f"- **File**: `{f.file_path}`\n"
                    content += f"- **Line**: Line {f.line_number}\n\n"

                    if f.code_snippet:
                        # Try to detect language from file extension
                        ext = (f.file_path or "").split(".")[-1].lower()
                        lang_map = {"py": "python", "js": "javascript", "ts": "typescript",
                                    "tsx": "typescript", "java": "java", "go": "go", "rb": "ruby"}
                        lang = lang_map.get(ext, "")
                        content += f"```{lang}\n{f.code_snippet}\n```\n\n"

                    # Why This Is Vulnerable section
                    content += f"**Why This Is Vulnerable:**\n{f.description}\n\n"

                    # Solution / Remediation section
                    if f.remediation or f.remediation_code:
                        content += f"**Solution / Remediation:**\n"
                        if f.remediation:
                            content += f"{f.remediation}\n\n"
                        if f.remediation_code:
                            content += f"```{lang if f.code_snippet else ''}\n{f.remediation_code}\n```\n\n"

                    if f.references:
                        content += "**References:**\n"
                        for ref in f.references:
                            content += f"- {ref}\n"
                        content += "\n"

                    content += "---\n\n"

        with open(filepath, "w") as f:
            f.write(content)

        return str(filepath)

    def generate_html_report(
        self,
        findings: List[Any],
        repo_name: str,
        pr_number: int,
        files_scanned: int,
    ) -> str:
        """
        Generate HTML report.

        Returns:
            Path to generated report
        """
        filename = f"{repo_name}_PR{pr_number}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        filepath = self.output_dir / filename

        by_severity = self._count_by_severity_objects(findings)

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Analysis Report - {repo_name} PR #{pr_number}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: #0d1117;
            color: #c9d1d9;
            line-height: 1.6;
            padding: 20px;
        }}
        .container {{ max-width: 1000px; margin: 0 auto; }}
        header {{
            background: #161b22;
            padding: 30px;
            border-radius: 6px;
            margin-bottom: 30px;
            border-left: 4px solid #58a6ff;
        }}
        h1 {{ color: #58a6ff; margin-bottom: 10px; }}
        .meta {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }}
        .meta-item {{
            background: #0d1117;
            padding: 15px;
            border-radius: 6px;
            border: 1px solid #30363d;
        }}
        .meta-label {{ font-size: 12px; color: #8b949e; text-transform: uppercase; }}
        .meta-value {{ font-size: 18px; font-weight: bold; color: #58a6ff; margin-top: 5px; }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }}
        .severity-card {{
            padding: 20px;
            border-radius: 6px;
            text-align: center;
            border: 2px solid;
        }}
        .severity-card.critical {{ border-color: #da3633; background: rgba(218, 54, 51, 0.1); }}
        .severity-card.high {{ border-color: #f85149; background: rgba(248, 81, 73, 0.1); }}
        .severity-card.medium {{ border-color: #d29922; background: rgba(210, 153, 34, 0.1); }}
        .severity-card.low {{ border-color: #3fb950; background: rgba(63, 185, 80, 0.1); }}
        .severity-card .number {{ font-size: 32px; font-weight: bold; }}
        .severity-card .label {{ font-size: 12px; text-transform: uppercase; margin-top: 10px; }}
        .findings-section {{ margin-bottom: 40px; }}
        .finding {{
            background: #161b22;
            border-left: 4px solid;
            padding: 20px;
            margin-bottom: 15px;
            border-radius: 6px;
        }}
        .finding.critical {{ border-color: #da3633; }}
        .finding.high {{ border-color: #f85149; }}
        .finding.medium {{ border-color: #d29922; }}
        .finding.low {{ border-color: #3fb950; }}
        .finding-title {{
            font-size: 16px;
            font-weight: bold;
            margin-bottom: 10px;
            color: #58a6ff;
        }}
        .finding-meta {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 15px 0;
            font-size: 12px;
        }}
        .finding-meta-item {{ color: #8b949e; }}
        .finding-description {{ margin: 15px 0; color: #c9d1d9; }}
        .code-block {{
            background: #0d1117;
            border: 1px solid #30363d;
            border-radius: 6px;
            padding: 15px;
            margin: 15px 0;
            overflow-x: auto;
            font-family: "SF Mono", Consolas, monospace;
            font-size: 13px;
            white-space: pre-wrap;
        }}
        .code-block.vulnerable {{ border-left: 3px solid #f85149; }}
        .code-block.remediation {{ border-left: 3px solid #3fb950; }}
        .section-label {{
            font-size: 12px;
            color: #8b949e;
            text-transform: uppercase;
            margin-bottom: 8px;
            font-weight: bold;
        }}
        .remediation-text {{ margin: 10px 0; color: #c9d1d9; }}
        footer {{
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #30363d;
            color: #8b949e;
            font-size: 12px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔍 Security Analysis Report</h1>
            <div class="meta">
                <div class="meta-item">
                    <div class="meta-label">Repository</div>
                    <div class="meta-value">{repo_name}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Pull Request</div>
                    <div class="meta-value">#{pr_number}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Files Scanned</div>
                    <div class="meta-value">{files_scanned}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Total Findings</div>
                    <div class="meta-value">{len(findings)}</div>
                </div>
            </div>
        </header>

        <div class="summary">
            <div class="severity-card critical">
                <div class="number">{by_severity.get("CRITICAL", 0)}</div>
                <div class="label">Critical</div>
            </div>
            <div class="severity-card high">
                <div class="number">{by_severity.get("HIGH", 0)}</div>
                <div class="label">High</div>
            </div>
            <div class="severity-card medium">
                <div class="number">{by_severity.get("MEDIUM", 0)}</div>
                <div class="label">Medium</div>
            </div>
            <div class="severity-card low">
                <div class="number">{by_severity.get("LOW", 0)}</div>
                <div class="label">Low</div>
            </div>
        </div>

        <div class="findings-section">
"""

        # Add findings by severity
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            findings_at_sev = [
                f for f in findings
                if (f.severity.value if hasattr(f.severity, 'value') else str(f.severity)) == severity
            ]

            if findings_at_sev:
                html += f"<h2>{severity} Severity ({len(findings_at_sev)})</h2>\n"

                for f in findings_at_sev:
                    sev_val = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
                    code_snippet = getattr(f, 'code_snippet', None) or ''
                    remediation = getattr(f, 'remediation', None) or ''
                    remediation_code = getattr(f, 'remediation_code', None) or ''

                    # Escape HTML in code snippets
                    import html as html_lib
                    code_snippet_escaped = html_lib.escape(code_snippet) if code_snippet else ''
                    remediation_code_escaped = html_lib.escape(remediation_code) if remediation_code else ''

                    html += f"""
            <div class="finding {sev_val.lower()}">
                <div class="finding-title">{html_lib.escape(f.title)}</div>
                <div class="finding-meta">
                    <div class="finding-meta-item"><strong>File:</strong> {f.file_path}:{f.line_number}</div>
                    <div class="finding-meta-item"><strong>CWE:</strong> {f.cwe_id or 'N/A'}</div>
                    <div class="finding-meta-item"><strong>OWASP:</strong> {f.owasp_category or 'N/A'}</div>
                    <div class="finding-meta-item"><strong>Confidence:</strong> {int(f.confidence * 100)}%</div>
                </div>
                <div class="finding-description">{html_lib.escape(f.description or '')}</div>
"""
                    # Add vulnerable code section
                    if code_snippet_escaped:
                        html += f"""
                <div class="section-label">Vulnerable Code</div>
                <div class="code-block vulnerable">{code_snippet_escaped}</div>
"""
                    # Add remediation section
                    if remediation or remediation_code_escaped:
                        html += f"""
                <div class="section-label">Solution / Remediation</div>
"""
                        if remediation:
                            html += f"""<div class="remediation-text">{html_lib.escape(remediation)}</div>"""
                        if remediation_code_escaped:
                            html += f"""<div class="code-block remediation">{remediation_code_escaped}</div>"""

                    html += """
            </div>
"""

        html += """
        </div>
        <footer>
            <p>Generated by PENTAS Security Analysis Agent</p>
        </footer>
    </div>
</body>
</html>
"""

        with open(filepath, "w") as f:
            f.write(html)

        return str(filepath)

    @staticmethod
    def _count_by_severity(findings_dict: List[Dict]) -> Dict[str, int]:
        """Count findings by severity."""
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings_dict:
            sev = f.get("severity", "LOW")
            if sev in counts:
                counts[sev] += 1
        return counts

    @staticmethod
    def _count_by_severity_objects(findings: List[Any]) -> Dict[str, int]:
        """Count finding objects by severity."""
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
            if sev in counts:
                counts[sev] += 1
        return counts
