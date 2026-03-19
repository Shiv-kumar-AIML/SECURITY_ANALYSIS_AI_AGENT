"""
Remediation Agent — generates fixes and remediation guidance.
Produces corrected code snippets, OWASP/CWE references, and step-by-step fix instructions.
"""
from typing import List
from .base_agent import BaseAgent
from ..findings import Finding, ScanResult, FindingSource
from ..constants import SKILLS_DIR, CWE_MAP


class RemediationAgent(BaseAgent):
    name = "remediation_agent"
    role = "Security Remediation Specialist Agent"
    description = (
        "You are a security remediation specialist. For each confirmed vulnerability, you generate: "
        "1) A corrected code snippet that fixes the issue, "
        "2) Step-by-step remediation instructions, "
        "3) References to OWASP, CWE, and security best practices. "
        "You ensure fixes don't introduce regressions and follow security best practices."
    )

    REMEDIATION_SYSTEM_PROMPT = """You are a security remediation specialist agent. Your job is to generate high-quality fixes for vulnerabilities.

## Rules
1. **Fix must be minimal** — only change what's necessary to fix the vulnerability
2. **Fix must be correct** — the fixed code must actually prevent the vulnerability
3. **Fix must be production-ready** — use proper error handling, no placeholders
4. **Explain the fix** — clearly explain WHY the fix works and what security principle it applies
5. **Reference standards** — cite CWE IDs, OWASP guidelines, and security frameworks

## Output Format
For each vulnerability, provide:

```
REMEDIATION:
- Vulnerability: [Title of the vulnerability being fixed]
- Fix Strategy: [Brief description of the fix approach]
- Security Principle: [What security principle this applies — e.g., parameterized queries, input validation, least privilege]
- Fixed Code:
```[language]
[The corrected code]
```
- Step-by-Step:
  1. [First step]
  2. [Second step]
  3. [Third step]
- References:
  - [CWE/OWASP/other reference]
```
"""

    def __init__(self, llm, memory, skills_dir=None):
        super().__init__(llm, memory, skills_dir or SKILLS_DIR)

    def _generate_remediations(self, findings: List[Finding], code_context: str) -> str:
        """Generate remediation guidance for all findings."""
        self.think(f"Generating remediation for {len(findings)} vulnerabilities...")

        vuln_summary = ""
        for i, f in enumerate(findings[:30], 1):  # Process up to 30 findings for remediation
            vuln_summary += (
                f"\n### Vulnerability #{i}\n"
                f"- **Title**: {f.title}\n"
                f"- **Severity**: {f.severity.value}\n"
                f"- **File**: {f.file_path}:{f.line_number}\n"
                f"- **CWE**: {f.cwe_id}\n"
                f"- **Description**: {f.description}\n"
                f"- **Code**: `{f.code_snippet[:300]}`\n"
            )

        prompt = (
            f"## Vulnerabilities to Remediate\n{vuln_summary}\n\n"
            f"## Source Code Context\n<CODE>\n{code_context[:10000]}\n</CODE>\n\n"
            f"## Previous Agent Analysis\n{self.get_peer_context()}\n\n"
            f"Generate production-ready remediation for each vulnerability. "
            f"Provide corrected code that can be directly applied."
        )

        return self.run_with_reasoning(prompt, system_prompt=self.REMEDIATION_SYSTEM_PROMPT)

    def _enrich_findings_with_remediation(self, findings: List[Finding], remediation_text: str):
        """Enrich existing findings with remediation details."""
        blocks = remediation_text.split("REMEDIATION:")

        for block in blocks[1:]:
            lines = block.strip().split("\n")
            vuln_title = ""
            fix_code = ""
            fix_strategy = ""
            steps = []
            refs = []

            in_code = False
            code_lines = []

            for line in lines:
                stripped = line.strip().lstrip("- ")

                if stripped.startswith("Vulnerability:"):
                    vuln_title = stripped.split(":", 1)[1].strip()
                elif stripped.startswith("Fix Strategy:"):
                    fix_strategy = stripped.split(":", 1)[1].strip()
                elif stripped.startswith("```") and not in_code:
                    in_code = True
                elif stripped.startswith("```") and in_code:
                    in_code = False
                    fix_code = "\n".join(code_lines)
                    code_lines = []
                elif in_code:
                    code_lines.append(line)

            # Match found remediation to existing findings
            for finding in findings:
                if vuln_title and (vuln_title.lower() in finding.title.lower() or
                                   finding.title.lower() in vuln_title.lower()):
                    if fix_code:
                        finding.remediation_code = fix_code
                    if fix_strategy:
                        finding.remediation = f"{fix_strategy}. {finding.remediation}" if finding.remediation else fix_strategy

    def execute(self, scan_result: ScanResult, code_context: str, console=None) -> dict:
        """
        Generate remediation for all confirmed vulnerabilities.
        """
        self.think("Starting remediation generation phase...")

        # Get all confirmed findings
        confirmed = scan_result.get_confirmed()
        if not confirmed:
            self.conclude("No confirmed findings to remediate.")
            return {"remediation_text": "No vulnerabilities found.", "findings_remediated": 0}

        # Generate remediations
        remediation_text = self._generate_remediations(confirmed, code_context)
        self.share_knowledge("remediation_output", remediation_text)

        # Enrich findings
        self._enrich_findings_with_remediation(confirmed, remediation_text)

        # Enrich CWE/OWASP mapping for findings missing it
        for finding in confirmed:
            if not finding.cwe_id:
                # Try to map from our CWE_MAP
                for key, cwe_data in CWE_MAP.items():
                    if key.replace("_", " ") in finding.title.lower():
                        finding.cwe_id = cwe_data["id"]
                        if not finding.owasp_category:
                            finding.owasp_category = cwe_data["owasp"]
                        break

        self.conclude(f"Remediation generated for {len(confirmed)} findings")
        self.send_to_agent("verifier_agent", f"Remediation complete for {len(confirmed)} findings.", "context")

        return {
            "remediation_text": remediation_text,
            "findings_remediated": len(confirmed),
        }
