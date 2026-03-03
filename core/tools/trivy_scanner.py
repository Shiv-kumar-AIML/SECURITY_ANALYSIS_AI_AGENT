"""
Trivy SCA/Container Scanner Integration.
Runs Trivy in filesystem mode for dependency and misconfiguration scanning.
"""
from typing import List
from .base_tool import BaseTool
from ..findings import Finding, Severity, FindingSource


class TrivyScanner(BaseTool):
    name = "trivy"
    description = "Trivy scanner — SCA, container, and IaC vulnerability detection"

    def is_available(self) -> bool:
        return self._command_exists("trivy")

    def run(self, target_path: str) -> dict:
        result = self._run_json_command([
            "trivy", "fs",
            "--format", "json",
            "--scanners", "vuln,secret,misconfig",
            "--quiet",
            target_path
        ], timeout=300)
        return result or {}

    def parse_results(self, raw_results: dict) -> List[Finding]:
        findings = []

        for result in raw_results.get("Results", []):
            target_file = result.get("Target", "")

            # Vulnerability findings
            for vuln in result.get("Vulnerabilities", []):
                severity_map = {
                    "CRITICAL": Severity.CRITICAL,
                    "HIGH": Severity.HIGH,
                    "MEDIUM": Severity.MEDIUM,
                    "LOW": Severity.LOW,
                    "UNKNOWN": Severity.INFO,
                }
                severity = severity_map.get(vuln.get("Severity", "").upper(), Severity.MEDIUM)

                cvss_score = 0.0
                cvss_data = vuln.get("CVSS", {})
                for source_cvss in cvss_data.values():
                    if "V3Score" in source_cvss:
                        cvss_score = source_cvss["V3Score"]
                        break

                pkg_name = vuln.get("PkgName", "unknown")
                installed_ver = vuln.get("InstalledVersion", "")
                fixed_ver = vuln.get("FixedVersion", "")

                remediation = f"Upgrade `{pkg_name}` from `{installed_ver}` to `{fixed_ver}`" if fixed_ver else f"No fix available yet for `{pkg_name}@{installed_ver}`"

                findings.append(Finding(
                    title=f"{vuln.get('VulnerabilityID', 'CVE-Unknown')} in {pkg_name}",
                    description=vuln.get("Description", vuln.get("Title", "No description")),
                    severity=severity,
                    source=FindingSource.TOOL_TRIVY,
                    file_path=target_file,
                    cwe_id=", ".join(vuln.get("CweIDs", [])),
                    owasp_category="A06:2021 Vulnerable Components",
                    cvss_score=cvss_score,
                    confidence=0.95,
                    remediation=remediation,
                    references=vuln.get("References", [])[:3],
                ))

            # Secret findings
            for secret in result.get("Secrets", []):
                findings.append(Finding(
                    title=f"Secret Detected: {secret.get('Category', 'Unknown')}",
                    description=f"Hardcoded secret found: {secret.get('Title', '')}",
                    severity=Severity.HIGH,
                    source=FindingSource.TOOL_TRIVY,
                    file_path=target_file,
                    line_number=secret.get("StartLine", 0),
                    end_line=secret.get("EndLine", 0),
                    code_snippet=secret.get("Match", ""),
                    cwe_id="CWE-798",
                    owasp_category="A07:2021 Auth Failures",
                    confidence=0.9,
                    remediation="Move this secret to environment variables or a secrets manager.",
                ))

        return findings
