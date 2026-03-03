"""
npm audit Integration.
Runs npm audit for Node.js dependency vulnerability scanning.
"""
import json as json_mod
from typing import List
from .base_tool import BaseTool
from ..findings import Finding, Severity, FindingSource


class NpmAuditScanner(BaseTool):
    name = "npm_audit"
    description = "npm audit — Node.js dependency vulnerability scanner"

    def is_available(self) -> bool:
        return self._command_exists("npm")

    def _has_package_json(self, target_path: str) -> bool:
        import os
        return os.path.exists(os.path.join(target_path, "package.json"))

    def run(self, target_path: str) -> dict:
        if not self._has_package_json(target_path):
            return {}

        output = self._run_command([
            "npm", "audit", "--json",
            "--prefix", target_path,
        ], timeout=120)

        if output:
            try:
                return json_mod.loads(output)
            except json_mod.JSONDecodeError:
                return {}
        return {}

    def parse_results(self, raw_results: dict) -> List[Finding]:
        findings = []
        vulnerabilities = raw_results.get("vulnerabilities", {})

        for pkg_name, vuln_data in vulnerabilities.items():
            severity_map = {
                "critical": Severity.CRITICAL,
                "high": Severity.HIGH,
                "moderate": Severity.MEDIUM,
                "low": Severity.LOW,
                "info": Severity.INFO,
            }
            severity = severity_map.get(vuln_data.get("severity", "").lower(), Severity.MEDIUM)

            fix_available = vuln_data.get("fixAvailable", False)
            remediation = f"Run `npm audit fix` to auto-fix" if fix_available else f"Manual upgrade required for `{pkg_name}`"

            via_list = vuln_data.get("via", [])
            description_parts = []
            cwe_ids = []
            refs = []
            for via in via_list:
                if isinstance(via, dict):
                    description_parts.append(via.get("title", ""))
                    refs.append(via.get("url", ""))
                    cwe_ids.extend(via.get("cwe", []))
                elif isinstance(via, str):
                    description_parts.append(f"Transitive via {via}")

            findings.append(Finding(
                title=f"Vulnerable Dependency: {pkg_name}@{vuln_data.get('range', '?')}",
                description=" | ".join(filter(None, description_parts)) or f"Vulnerability in {pkg_name}",
                severity=severity,
                source=FindingSource.TOOL_NPM_AUDIT,
                file_path="package.json",
                cwe_id=", ".join(cwe_ids[:2]),
                owasp_category="A06:2021 Vulnerable Components",
                confidence=0.95,
                remediation=remediation,
                references=[r for r in refs if r][:3],
            ))
        return findings
