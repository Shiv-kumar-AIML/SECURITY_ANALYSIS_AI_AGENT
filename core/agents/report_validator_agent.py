"""
Report Validator Agent — Final quality assurance agent.
Runs AFTER verification and BEFORE report generation.

Responsibilities:
1. DEDUP: Detect and remove semantically duplicate findings the dedup algorithm missed
2. VALIDATE: Check each finding's correctness via LLM reasoning
3. REMEDIATION: Verify remediation code matches the project's tech stack
4. SEVERITY: Confirm severity classification is accurate
5. CLEAN: Remove false positives the verifier missed (e.g. Prisma injection)

This agent sends findings to the LLM in batches and generates a structured
validation result for each finding: KEEP, REMOVE (duplicate/FP), or FIX (wrong remediation/severity).
"""
import re
from typing import List, Dict, Tuple
from .base_agent import BaseAgent, SharedMemory
from ..llm_provider import LLMProvider
from ..findings import Finding, ScanResult, Severity


VALIDATOR_SYSTEM_PROMPT = """You are the REPORT VALIDATOR agent — the final quality gate before a security report goes to production.
Your job is to review a batch of security findings and validate each one.

For EACH finding, you must output a structured verdict:

VALIDATION: [Finding Number]
- Finding: [exact title]
- Verdict: KEEP | REMOVE | FIX
- Reason: [1-2 sentence explanation]
- Duplicate Of: [number of the finding this duplicates, or "none"]
- Duplicate File: [the FILE PATH of the other finding this duplicates, or "none"]
- Corrected Severity: [CRITICAL|HIGH|MEDIUM|LOW|INFO|SAME]
- Remediation Issue: [describe what's wrong with the remediation, or "none"]
- Corrected Remediation: [if FIX, provide the correct remediation text, else "none"]

Rules for your validation:

🚨 NEVER REMOVE THESE (use FIX instead if something is wrong):
- Findings with Confidence >= 90% from tool scanners — these are deterministic regex/tool matches
- Findings with CRITICAL severity — these are the most important findings
- Findings about hardcoded OTP, passwords, secrets, authentication bypass
- Findings about missing authentication on admin endpoints
- Dependency CVEs from npm_audit/trivy — they are ALWAYS real
- If a finding has a problem (wrong severity, wrong remediation), use FIX, NOT REMOVE

DUPLICATES (STRICT RULES):
- Two findings are duplicates ONLY if they describe the SAME vulnerability in the SAME FILE
- You MUST specify the file path of the duplicate in "Duplicate File"
- DIFFERENT files are NEVER duplicates, even if they have the same vulnerability TYPE
- Example: hardcoded OTP in send-otp/route.ts AND verify-otp/route.ts = NOT duplicates (different files!)
- Example: path traversal in upload/route.ts (semgrep) AND upload/route.ts (agent) = DUPLICATE (same file)
- When removing a duplicate, keep the one with the better description/code snippet

FALSE POSITIVES (only these are safe to REMOVE):
- Prisma ORM queries (findUnique, findFirst, create, update) are ALWAYS parameterized — NOT injectable
- React/TSX component form validation (e.g., confirmPassword.length > 0) is NOT a security vulnerability
- Frontend-only validation in .tsx files is NOT a weak password policy — server-side validation IS

REMEDIATION CHECKS:
- If the project is Node.js/TypeScript/Next.js, remediation must use JavaScript/TypeScript, NOT Python/Django
- If you see Python-style remediation (cursor.execute, Django ORM) for a Node.js project, mark as FIX

SEVERITY (can only go DOWN, never UP):
- You may LOWER severity (e.g., HIGH -> MEDIUM) but NEVER raise it (e.g., MEDIUM -> CRITICAL)
- Use SAME if the current severity is correct
- Math.random() for IDs = MEDIUM, for OTP = HIGH
- User enumeration = MEDIUM
- Format string in console.log = LOW

IMPORTANT:
- Be EXTREMELY conservative with REMOVE — when in doubt, KEEP
- It is FAR WORSE to remove a real vulnerability than to keep a false positive
- Only REMOVE clear, obvious false positives and EXACT same-file duplicates
"""


class ReportValidatorAgent(BaseAgent):
    """
    Final quality assurance agent that validates findings before report generation.
    Uses LLM reasoning to detect duplicates, false positives, and incorrect remediations.
    """
    name = "report_validator"
    role = "Security Report Validator & Quality Assurance"
    description = (
        "You validate the final security report for correctness, remove duplicates, "
        "verify remediation quality, and ensure severity classifications are accurate."
    )

    def __init__(self, llm: LLMProvider, memory: SharedMemory, skills_dir=None):
        super().__init__(llm, memory, skills_dir)

    def _build_findings_summary(self, findings: List[Finding], start_idx: int = 1) -> str:
        """Build a concise summary of findings for LLM validation."""
        parts = []
        for i, f in enumerate(findings, start_idx):
            rel_path = f.file_path.split('cloned_repos/')[-1] if 'cloned_repos/' in (f.file_path or '') else (f.file_path or 'N/A')
            parts.append(f"""
FINDING #{i}:
  Title: {f.title}
  Severity: {f.severity.value}
  File: {rel_path}
  Line: {f.line_number}
  CWE: {f.cwe_id or 'N/A'}
  Confidence: {f.confidence}
  Source: {f.source.value}
  Description: {(f.description or '')[:300]}
  Code Snippet: {(f.code_snippet or '')[:300]}
  Remediation: {(f.remediation or '')[:200]}
  Remediation Code: {(f.remediation_code or '')[:300]}
""")
        return "\n".join(parts)

    def _validate_batch(self, findings: List[Finding], tech_stack: str,
                        code_context: str, start_idx: int = 1) -> str:
        """Send a batch of findings to LLM for validation."""
        findings_text = self._build_findings_summary(findings, start_idx)

        prompt = f"""Validate the following {len(findings)} security findings for a {tech_stack} project.

Check each finding for:
1. Is it a real vulnerability? (not a false positive)
2. Is it a duplicate of another finding in this batch?
3. Is the remediation code correct for {tech_stack}? (not Python/Django for a Node.js project)
4. Is the severity classification accurate?

{findings_text}

For each finding, output your validation using the exact format specified.
Remember: Be CONSERVATIVE with REMOVE. Only remove clear false positives and exact duplicates.
"""
        return self.run_with_reasoning(prompt, system_prompt=VALIDATOR_SYSTEM_PROMPT)

    def _parse_validations(self, validation_text: str) -> Dict[int, dict]:
        """Parse LLM validation output into structured results."""
        results = {}
        blocks = validation_text.split("VALIDATION:")

        for block in blocks[1:]:
            lines = block.strip().split("\n")
            finding_num = 0
            verdict = "KEEP"
            reason = ""
            duplicate_of = "none"
            corrected_severity = "SAME"
            remediation_issue = "none"
            corrected_remediation = "none"

            # Try to get finding number from the first line
            first_line = lines[0].strip() if lines else ""
            num_match = re.search(r'(\d+)', first_line)
            if num_match:
                finding_num = int(num_match.group(1))

            for line in lines:
                stripped = line.strip().lstrip("- ")
                if stripped.startswith("Finding:"):
                    pass  # Just the title echo
                elif stripped.startswith("Verdict:"):
                    verdict = stripped.split(":", 1)[1].strip().upper()
                elif stripped.startswith("Reason:"):
                    reason = stripped.split(":", 1)[1].strip()
                elif stripped.startswith("Duplicate Of:"):
                    duplicate_of = stripped.split(":", 1)[1].strip().lower()
                elif stripped.startswith("Corrected Severity:"):
                    corrected_severity = stripped.split(":", 1)[1].strip().upper()
                elif stripped.startswith("Remediation Issue:"):
                    remediation_issue = stripped.split(":", 1)[1].strip()
                elif stripped.startswith("Corrected Remediation:"):
                    corrected_remediation = stripped.split(":", 1)[1].strip()

            if finding_num > 0:
                results[finding_num] = {
                    "verdict": verdict,
                    "reason": reason,
                    "duplicate_of": duplicate_of,
                    "corrected_severity": corrected_severity,
                    "remediation_issue": remediation_issue,
                    "corrected_remediation": corrected_remediation,
                }

        return results

    def _is_protected(self, finding: Finding) -> bool:
        """Check if a finding is protected from removal.
        Protected findings can be FIXed but NEVER removed."""
        # High-confidence tool findings (deterministic pattern scanner, semgrep)
        if finding.confidence >= 0.90:
            return True
        # CRITICAL severity
        if finding.severity == Severity.CRITICAL:
            return True
        # Dependency CVEs
        if finding.source.value in ('trivy', 'npm_audit'):
            return True
        # Hardcoded secrets/OTP/auth bypass keywords in title
        protected_keywords = ['hardcoded', 'otp', 'bypass', 'missing auth', 'admin',
                              'stack trace', 'error.stack']
        title_lower = finding.title.lower()
        if any(kw in title_lower for kw in protected_keywords):
            return True
        return False

    def _validate_duplicate_claim(self, finding: Finding, validation: dict,
                                   all_findings: List[Finding], start_idx: int) -> bool:
        """Validate that a duplicate claim is legitimate (same file)."""
        dup_of = validation.get("duplicate_of", "none")
        if dup_of == "none" or not dup_of:
            return False  # No duplicate claim

        # Extract the duplicate finding number
        dup_match = re.search(r'(\d+)', str(dup_of))
        if not dup_match:
            return False

        dup_num = int(dup_match.group(1))
        dup_idx = dup_num - start_idx
        if dup_idx < 0 or dup_idx >= len(all_findings):
            return False  # Invalid reference

        other_finding = all_findings[dup_idx]

        # STRICT: Must be the SAME file to be a duplicate
        this_file = (finding.file_path or "").split('/')[-1].lower()
        other_file = (other_finding.file_path or "").split('/')[-1].lower()

        if this_file != other_file:
            self.think(
                f"REJECTED duplicate claim: '{finding.title}' in {this_file} "
                f"is NOT a duplicate of '{other_finding.title}' in {other_file} — different files"
            )
            return False  # Different files = NOT duplicates

        return True  # Same file, legitimate duplicate

    def _severity_order(self, severity: Severity) -> int:
        """Return numeric order: CRITICAL=4, HIGH=3, MEDIUM=2, LOW=1, INFO=0."""
        return {Severity.CRITICAL: 4, Severity.HIGH: 3, Severity.MEDIUM: 2,
                Severity.LOW: 1, Severity.INFO: 0}.get(severity, 0)

    def _apply_validations(self, findings: List[Finding], validations: Dict[int, dict],
                           start_idx: int = 1) -> Tuple[List[Finding], int, int, int]:
        """Apply validation results to findings. Returns (validated_findings, kept, removed, fixed)."""
        validated = []
        removed = 0
        fixed = 0

        severity_map = {
            "CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW, "INFO": Severity.INFO,
        }

        for i, finding in enumerate(findings, start_idx):
            validation = validations.get(i)
            if not validation:
                # No validation = keep by default
                validated.append(finding)
                continue

            verdict = validation["verdict"]
            is_protected = self._is_protected(finding)

            # ═══ REMOVE verdict ═══
            if "REMOVE" in verdict:
                # GUARD 1: Protected findings can NEVER be removed
                if is_protected:
                    self.think(
                        f"BLOCKED removal of #{i} '{finding.title}' — protected "
                        f"(confidence={finding.confidence}, severity={finding.severity.value}). "
                        f"LLM reason: {validation['reason']}"
                    )
                    validated.append(finding)
                    continue

                # GUARD 2: Duplicate claims must be same-file
                dup_of = validation.get("duplicate_of", "none")
                if dup_of and dup_of.lower() != "none":
                    if not self._validate_duplicate_claim(finding, validation, findings, start_idx):
                        # Duplicate claim rejected — keep the finding
                        validated.append(finding)
                        continue

                self.think(f"REMOVING #{i} '{finding.title}': {validation['reason']}")
                removed += 1
                continue

            # ═══ FIX verdict ═══
            if "FIX" in verdict:
                self.think(f"FIXING #{i} '{finding.title}': {validation['reason']}")
                fixed += 1

                # Apply corrected severity — ONLY if it goes DOWN, never UP
                sev = validation.get("corrected_severity", "SAME")
                if sev in severity_map:
                    new_severity = severity_map[sev]
                    if self._severity_order(new_severity) < self._severity_order(finding.severity):
                        finding.severity = new_severity  # Downgrade allowed
                    # Upgrades are silently ignored

                # Apply corrected remediation
                corrected = validation.get("corrected_remediation", "none")
                if corrected and corrected.lower() != "none":
                    finding.remediation = corrected

                # Fix remediation issue notes
                rem_issue = validation.get("remediation_issue", "none")
                if rem_issue and rem_issue.lower() != "none":
                    if any(kw in rem_issue.lower() for kw in ["python", "django", "wrong language", "wrong tech"]):
                        finding.remediation_code = ""

            # ═══ KEEP verdict — apply severity correction (only downward) ═══
            if "KEEP" in verdict:
                sev = validation.get("corrected_severity", "SAME")
                if sev in severity_map:
                    new_severity = severity_map[sev]
                    if self._severity_order(new_severity) < self._severity_order(finding.severity):
                        finding.severity = new_severity

            validated.append(finding)

        kept = len(validated)
        return validated, kept, removed, fixed

    def execute(self, scan_result: ScanResult, code_context: str, console=None) -> dict:
        """
        Execute the report validation pipeline:
        1. Collect all confirmed findings
        2. Send to LLM in batches for validation
        3. Apply corrections (remove duplicates/FPs, fix remediations, adjust severity)
        """
        self.think("Starting report validation — final quality gate before report generation")

        # Get tech stack
        tech_stack = ", ".join(scan_result.tech_stack) if scan_result.tech_stack else "Unknown"

        # Get confirmed findings (not false positives)
        confirmed = [f for f in scan_result.findings if not f.is_false_positive]
        if not confirmed:
            self.conclude("No findings to validate")
            return {"validated_count": 0, "removed_count": 0, "fixed_count": 0}

        self.think(f"Validating {len(confirmed)} confirmed findings for tech stack: {tech_stack}")

        # Process in batches of 8 findings (to keep LLM context manageable)
        batch_size = 8
        all_validated = []
        total_removed = 0
        total_fixed = 0

        for batch_start in range(0, len(confirmed), batch_size):
            batch = confirmed[batch_start:batch_start + batch_size]
            batch_idx = batch_start + 1
            batch_label = f"Batch {batch_start // batch_size + 1}"

            if console:
                console.print(f"  [cyan]▸[/cyan] Validating: [bold]{batch_label}[/bold] ({len(batch)} findings)")

            try:
                validation_text = self._validate_batch(
                    batch, tech_stack, code_context, start_idx=batch_idx
                )

                validations = self._parse_validations(validation_text)
                validated, kept, removed, fixed = self._apply_validations(
                    batch, validations, start_idx=batch_idx
                )

                all_validated.extend(validated)
                total_removed += removed
                total_fixed += fixed

            except Exception as e:
                self.think(f"Validation failed for {batch_label}: {e} — keeping all findings in batch")
                all_validated.extend(batch)

        # Update scan result — replace findings with validated ones
        # Mark removed findings as false positives
        validated_titles = {f.title for f in all_validated}
        for f in scan_result.findings:
            if not f.is_false_positive and f.title not in validated_titles:
                f.is_false_positive = True
                f.false_positive_reason = "Removed by report validator (duplicate or false positive)"

        self.conclude(
            f"Validation complete: {len(all_validated)} kept, "
            f"{total_removed} removed, {total_fixed} fixed"
        )

        # Share results with shared memory
        self.share_knowledge("validation_stats", {
            "validated": len(all_validated),
            "removed": total_removed,
            "fixed": total_fixed,
        })

        return {
            "validated_count": len(all_validated),
            "removed_count": total_removed,
            "fixed_count": total_fixed,
        }
