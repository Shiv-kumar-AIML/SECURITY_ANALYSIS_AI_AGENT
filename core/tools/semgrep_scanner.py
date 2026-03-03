"""
Semgrep SAST Scanner Integration.
Runs Semgrep with auto-config and parses JSON findings.
"""
from typing import List
from .base_tool import BaseTool
from ..findings import Finding, Severity, FindingSource


class SemgrepScanner(BaseTool):
    name = "semgrep"
    description = "Semgrep SAST scanner — pattern-based static analysis"

    def is_available(self) -> bool:
        return self._command_exists("semgrep")

    def run(self, target_path: str) -> dict:
        result = self._run_json_command([
            "semgrep", "scan",
            "--config", "auto",
            "--json",
            "--quiet",
            "--timeout", "60",
            target_path
        ], timeout=300)
        return result or {}

    def parse_results(self, raw_results: dict) -> List[Finding]:
        findings = []
        for result in raw_results.get("results", []):
            severity_str = result.get("extra", {}).get("severity", "WARNING").upper()
            severity_map = {
                "ERROR": Severity.HIGH,
                "WARNING": Severity.MEDIUM,
                "INFO": Severity.LOW,
            }
            severity = severity_map.get(severity_str, Severity.MEDIUM)

            cwe_ids = result.get("extra", {}).get("metadata", {}).get("cwe", [])
            cwe_str = cwe_ids[0] if cwe_ids else ""
            owasp_cats = result.get("extra", {}).get("metadata", {}).get("owasp", [])
            owasp_str = owasp_cats[0] if owasp_cats else ""

            findings.append(Finding(
                title=result.get("check_id", "Unknown Rule").split(".")[-1].replace("-", " ").title(),
                description=result.get("extra", {}).get("message", "No description"),
                severity=severity,
                source=FindingSource.TOOL_SEMGREP,
                file_path=result.get("path", ""),
                line_number=result.get("start", {}).get("line", 0),
                end_line=result.get("end", {}).get("line", 0),
                code_snippet=result.get("extra", {}).get("lines", ""),
                cwe_id=cwe_str,
                owasp_category=owasp_str,
                confidence=0.85,
                references=[result.get("extra", {}).get("metadata", {}).get("source", "")],
            ))
        return findings
