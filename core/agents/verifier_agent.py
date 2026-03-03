"""
Verifier Agent — cross-validates findings and eliminates false positives.
Uses Layer 3 skills and independent reasoning to produce final confidence scores.
"""
from typing import List
from .base_agent import BaseAgent
from ..findings import Finding, ScanResult, Severity, FindingSource
from ..constants import SKILLS_DIR, LAYER_3_SKILLS


class VerifierAgent(BaseAgent):
    name = "verifier_agent"
    role = "Security Finding Verifier & False Positive Eliminator"
    description = (
        "You are the Verification Agent. Your job is to cross-validate ALL findings from both tools and AI agents. "
        "You eliminate false positives, validate exploitability, assign final confidence scores, "
        "and ensure only genuine vulnerabilities make it into the final report."
    )

    VERIFIER_SYSTEM_PROMPT = """You are a security verification expert. You receive vulnerability findings and must verify each one.

## Verification Process
For each finding, you must:

1. **Check Reachability**: Is the vulnerable code actually reachable from an entry point?
2. **Check Sanitization**: Is there sanitization/validation between source and sink that the original analysis missed?
3. **Check Context**: Is this in test code, example code, or dead code?
4. **Check Exploitability**: Can this actually be exploited in a real-world scenario?
5. **Assign Confidence**: Rate 0.0 (definitely false positive) to 1.0 (definitely vulnerable)

## Output Format
For each finding, output:
```
VERIFICATION:
- Finding: [Title of the finding]
- Verdict: [CONFIRMED / FALSE_POSITIVE / NEEDS_REVIEW]
- Confidence: [0.0 to 1.0]
- Reasoning: [Your verification reasoning]
- Adjusted Severity: [if different from original]
```

## False Positive Indicators
- Test files (.test.js, .spec.py, test_*.py)
- Example/demo code with placeholder values
- Dead code behind feature flags or unreachable conditions
- Properly sanitized inputs that were flagged by pattern matching
- Internal-only utilities not exposed to external input
"""

    def __init__(self, llm, memory, skills_dir=None):
        super().__init__(llm, memory, skills_dir or SKILLS_DIR)

    def _run_layer3_skills(self, code_context: str, console=None) -> dict:
        """Run Layer 3 (precision filtering) skills."""
        self.think("Running Layer 3 precision filtering skills...")
        results = {}
        peer_context = self.get_peer_context()

        for skill in LAYER_3_SKILLS:
            skill_display = skill.replace('.md', '').replace('-', ' ').title()
            if console:
                console.print(f"  [cyan]▸[/cyan] Verifying: [bold]{skill_display}[/bold]")

            response = self.run_skill(skill, code_context, extra_context=peer_context)
            results[skill] = response

            skill_key = skill.replace(".md", "").replace("-", "_")
            self.share_knowledge(skill_key, response)

        return results

    def _verify_findings(self, findings: List[Finding], code_context: str) -> str:
        """Cross-validate all findings with reasoning."""
        self.think(f"Cross-validating {len(findings)} findings...")

        findings_text = ""
        for i, f in enumerate(findings[:20], 1):
            findings_text += (
                f"\n### Finding #{i}\n"
                f"- **Title**: {f.title}\n"
                f"- **Severity**: {f.severity.value}\n"
                f"- **Source**: {f.source.value}\n"
                f"- **File**: {f.file_path}:{f.line_number}\n"
                f"- **CWE**: {f.cwe_id}\n"
                f"- **Description**: {f.description[:300]}\n"
                f"- **Reasoning**: {f.reasoning_chain[:300]}\n"
            )

        prompt = (
            f"## All Findings to Verify\n{findings_text}\n\n"
            f"## Peer Agent Context\n{self.get_peer_context()}\n\n"
            f"## Source Code\n<CODE>\n{code_context[:10000]}\n</CODE>\n\n"
            f"Verify EACH finding. For each, state whether it is CONFIRMED, FALSE_POSITIVE, or NEEDS_REVIEW. "
            f"Assign a confidence score from 0.0 to 1.0. Explain your reasoning."
        )

        return self.run_with_reasoning(prompt, system_prompt=self.VERIFIER_SYSTEM_PROMPT)

    def _apply_verification(self, findings: List[Finding], verification_text: str):
        """Apply verification results to findings."""
        blocks = verification_text.split("VERIFICATION:")

        for block in blocks[1:]:
            lines = block.strip().split("\n")
            title = ""
            verdict = ""
            confidence = 0.8
            reasoning = ""
            adjusted_severity = ""

            for line in lines:
                stripped = line.strip().lstrip("- ")
                if stripped.startswith("Finding:"):
                    title = stripped.split(":", 1)[1].strip()
                elif stripped.startswith("Verdict:"):
                    verdict = stripped.split(":", 1)[1].strip().upper()
                elif stripped.startswith("Confidence:"):
                    try:
                        confidence = float(stripped.split(":", 1)[1].strip())
                    except ValueError:
                        confidence = 0.8
                elif stripped.startswith("Reasoning:"):
                    reasoning = stripped.split(":", 1)[1].strip()
                elif stripped.startswith("Adjusted Severity:"):
                    adjusted_severity = stripped.split(":", 1)[1].strip().upper()

            # Match to actual findings
            for finding in findings:
                if title and (title.lower() in finding.title.lower() or
                              finding.title.lower() in title.lower()):
                    finding.confidence = min(max(confidence, 0.0), 1.0)

                    if "FALSE_POSITIVE" in verdict:
                        finding.is_false_positive = True
                        finding.false_positive_reason = reasoning

                    if reasoning and not finding.reasoning_chain:
                        finding.reasoning_chain = reasoning

                    if adjusted_severity:
                        severity_map = {
                            "CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
                            "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW, "INFO": Severity.INFO,
                        }
                        if adjusted_severity in severity_map:
                            finding.severity = severity_map[adjusted_severity]

    def execute(self, scan_result: ScanResult, code_context: str, console=None) -> dict:
        """
        Full verification pipeline:
        1. Run Layer 3 precision skills
        2. Cross-validate all findings
        3. Mark false positives, adjust confidence and severity
        """
        self.think("Starting verification and false positive filtering...")

        # 1. Run Layer 3 Skills
        layer3_results = self._run_layer3_skills(code_context, console=console)

        # 2. Cross-Validate
        all_findings = scan_result.findings
        if all_findings:
            verification_text = self._verify_findings(all_findings, code_context)
            self.share_knowledge("verification_output", verification_text)

            # 3. Apply Verification
            self._apply_verification(all_findings, verification_text)

        # Mark any findings without explicit confidence
        for f in all_findings:
            if f.confidence == 0.0:
                f.confidence = 0.7  # Default moderate confidence

        confirmed = scan_result.get_confirmed()
        false_positives = [f for f in all_findings if f.is_false_positive]

        self.conclude(f"Verification complete: {len(confirmed)} confirmed, {len(false_positives)} false positives eliminated")

        self.send_to_agent("all", f"Verification done: {len(confirmed)} confirmed findings, "
                           f"{len(false_positives)} false positives.", "status")

        return {
            "layer3_results": layer3_results,
            "confirmed_count": len(confirmed),
            "false_positive_count": len(false_positives),
        }
