"""
Gitleaks Secret Detection Scanner Integration.
Detects hardcoded secrets, API keys, and credentials.
"""
from typing import List
from .base_tool import BaseTool
from ..findings import Finding, Severity, FindingSource


class GitleaksScanner(BaseTool):
    name = "gitleaks"
    description = "Gitleaks — hardcoded secret and credential detection"

    def is_available(self) -> bool:
        return self._command_exists("gitleaks")

    def run(self, target_path: str) -> dict:
        import tempfile, os, json as json_mod
        report_file = os.path.join(tempfile.gettempdir(), "gitleaks_report.json")

        self._run_command([
            "gitleaks", "detect",
            "--source", target_path,
            "--report-format", "json",
            "--report-path", report_file,
            "--no-git",
        ], timeout=120)

        if os.path.exists(report_file):
            try:
                with open(report_file, 'r') as f:
                    data = json_mod.load(f)
                os.remove(report_file)
                return {"findings": data} if isinstance(data, list) else data
            except Exception:
                return {}
        return {}

    def parse_results(self, raw_results: dict) -> List[Finding]:
        findings = []
        for leak in raw_results.get("findings", []):
            findings.append(Finding(
                title=f"Secret Leaked: {leak.get('Description', 'Unknown Secret')}",
                description=f"Rule: {leak.get('RuleID', 'unknown')} — {leak.get('Description', '')}",
                severity=Severity.HIGH,
                source=FindingSource.TOOL_GITLEAKS,
                file_path=leak.get("File", ""),
                line_number=leak.get("StartLine", 0),
                end_line=leak.get("EndLine", 0),
                code_snippet=leak.get("Match", "")[:200],
                cwe_id="CWE-798",
                owasp_category="A07:2021 Auth Failures",
                confidence=0.92,
                remediation="Remove the hardcoded secret, rotate the exposed credential, and use environment variables or a secrets vault.",
            ))
        return findings
