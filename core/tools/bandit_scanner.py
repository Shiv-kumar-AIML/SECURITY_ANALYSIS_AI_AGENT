"""
Bandit Python SAST Scanner Integration.
Runs Bandit for Python-specific vulnerability detection.
"""
from typing import List
from .base_tool import BaseTool
from ..findings import Finding, Severity, FindingSource


class BanditScanner(BaseTool):
    name = "bandit"
    description = "Bandit scanner — Python-specific SAST"

    def is_available(self) -> bool:
        return self._command_exists("bandit")

    def run(self, target_path: str) -> dict:
        result = self._run_json_command([
            "bandit", "-r", target_path,
            "-f", "json",
            "--quiet",
        ], timeout=300)
        return result or {}

    def parse_results(self, raw_results: dict) -> List[Finding]:
        findings = []
        for result in raw_results.get("results", []):
            severity_map = {
                "HIGH": Severity.HIGH,
                "MEDIUM": Severity.MEDIUM,
                "LOW": Severity.LOW,
            }
            severity = severity_map.get(result.get("issue_severity", "").upper(), Severity.MEDIUM)

            confidence_map = {"HIGH": 0.9, "MEDIUM": 0.7, "LOW": 0.5}
            confidence = confidence_map.get(result.get("issue_confidence", "").upper(), 0.7)

            cwe_data = result.get("issue_cwe", {})
            cwe_str = f"CWE-{cwe_data.get('id', '')}" if cwe_data else ""

            findings.append(Finding(
                title=result.get("test_name", "Unknown Issue").replace("_", " ").title(),
                description=result.get("issue_text", "No description"),
                severity=severity,
                source=FindingSource.TOOL_BANDIT,
                file_path=result.get("filename", ""),
                line_number=result.get("line_number", 0),
                end_line=result.get("end_col_offset", result.get("line_number", 0)),
                code_snippet=result.get("code", ""),
                cwe_id=cwe_str,
                confidence=confidence,
                references=[f"https://bandit.readthedocs.io/en/latest/plugins/{result.get('test_id', '')}"],
            ))
        return findings
