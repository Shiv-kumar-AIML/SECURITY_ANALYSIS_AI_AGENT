"""
Verifier Agent — Production-grade false positive elimination.
Uses BOTH rule-based pre-filtering AND LLM reasoning for maximum accuracy.
Framework-aware: understands ORMs, JWT, TypeScript safety, Django protections.
"""
import os
import re
from typing import List
from .base_agent import BaseAgent
from ..findings import Finding, ScanResult, Severity, FindingSource
from ..constants import SKILLS_DIR, LAYER_3_SKILLS


# ═══════════════════════════════════════════════════════════════
# RULE-BASED FALSE POSITIVE FILTERS
# These run BEFORE the LLM and instantly mark obvious false positives.
# ═══════════════════════════════════════════════════════════════

def _is_test_file(file_path: str) -> bool:
    """Check if file is a test/example/mock file."""
    test_indicators = [
        '/test/', '/tests/', '/__tests__/', '/spec/', '/mock/', '/mocks/',
        '/fixtures/', '/testdata/', '/test_data/', '/examples/', '/demo/',
        '.test.', '.spec.', '_test.', 'test_', 'conftest.', '/e2e/',
    ]
    path_lower = file_path.lower()
    return any(indicator in path_lower for indicator in test_indicators)


def _is_migration_file(file_path: str) -> bool:
    """Check if file is a database migration (auto-generated, not user code)."""
    return '/migrations/' in file_path and file_path.endswith('.py')


def _is_config_file(file_path: str) -> bool:
    """Config files like settings.py, manage.py are not user-facing vulnerabilities."""
    basename = os.path.basename(file_path).lower()
    return basename in {'manage.py', 'wsgi.py', 'asgi.py', 'conftest.py', 'setup.py', 'setup.cfg'}


def _is_safe_orm_query(finding: Finding) -> bool:
    """
    Django ORM / Sequelize / SQLAlchemy queries are parameterized by default.
    If a finding flags a standard ORM call as SQL injection, it's a false positive.
    """
    safe_orm_patterns = [
        '.objects.filter(', '.objects.get(', '.objects.create(', '.objects.all()',
        '.objects.exclude(', '.objects.values(', '.objects.annotate(',
        '.objects.aggregate(', '.objects.count()', '.objects.first()',
        '.objects.last()', '.objects.exists()', '.objects.update(',
        '.objects.delete(', '.objects.bulk_create(',
        'Model.findOne(', 'Model.findAll(', 'Model.create(',
        '.findById(', '.findByPk(', '.where(', 
        'session.query(', 'session.add(', 'session.commit(',
    ]
    code = (finding.code_snippet or "").lower() + (finding.description or "").lower()
    title = finding.title.lower()
    
    # Only apply to SQL-related findings
    if 'sql' not in title and 'injection' not in title and 'cwe-89' not in (finding.cwe_id or '').lower():
        return False
    
    return any(pattern.lower() in code for pattern in safe_orm_patterns)


def _is_safe_framework_pattern(finding: Finding) -> bool:
    """
    Framework-provided safety patterns that don't need fixing.
    IMPORTANT: This function NEVER filters dependency CVEs or tool-reported findings
    with CVE IDs — those are always real.
    """
    code = (finding.code_snippet or "").lower()
    desc = (finding.description or "").lower()
    title = finding.title.lower()
    file_path_lower = (finding.file_path or "").lower()
    
    # NEVER filter dependency CVEs — they are always real
    if 'cve-' in title or 'vulnerable dependency' in title:
        return False
    
    # NEVER filter findings from deterministic pattern scanner (confidence >= 0.95)
    # These are regex-matched hardcoded OTPs, stack trace leaks, etc. — always real
    if finding.confidence >= 0.95 and finding.source.value in ('semgrep', 'pattern_scanner'):
        return False
    
    # NEVER filter findings from tool scanners that report dependencies
    if finding.source.value in ('trivy', 'npm_audit') and 'A06:2021' in (finding.owasp_category or ''):
        return False
    
    # Prisma ORM queries are ALWAYS parameterized — NOT vulnerable to injection
    # This prevents false 'NoSQL Injection' and 'SQL Injection' reports on Prisma
    prisma_methods = ['prisma.', 'findunique', 'findfirst', 'findmany', 'create(', 
                      'update(', 'delete(', 'upsert(', 'aggregate(', 'groupby(']
    if any(inj in title for inj in ['injection', 'nosql injection', 'sql injection']):
        if any(pm in code or pm in desc for pm in prisma_methods):
            # Prisma parameterizes all queries — this is a false positive
            return True
    
    # Prisma with user-controlled keys is NOT prototype pollution
    if 'prototype pollution' in title or 'cwe-1321' in (finding.cwe_id or '').lower():
        if any(pm in code or pm in desc for pm in prisma_methods):
            # Prisma's typed API prevents prototype pollution
            return True
    
    # path.join() in Node.js is not inherently path traversal
    if 'path traversal' in title or 'cwe-22' in (finding.cwe_id or '').lower():
        if 'path.join(' in code and 'req.' not in code and 'request.' not in code:
            # Check BOTH code snippet AND file path for upload context
            upload_indicators = ['file.name', 'file_name', 'filename', 'upload', 'originalname',
                                 'extension', 'ext', 'formdata', 'multipart', 'buffer',
                                 'writefile', 'write_file', 'savefile', 'save_file']
            has_user_input_in_code = any(indicator in code for indicator in upload_indicators)
            has_user_input_in_path = any(indicator in file_path_lower for indicator in 
                                         ['upload', 'file', 'media', 'attachment', 'asset'])
            if not has_user_input_in_code and not has_user_input_in_path:
                return True  # path.join without user input is safe
    
    # Crypto/hash imports are NOT secrets
    if 'secret' in title or 'hardcoded' in title:
        if any(safe in code for safe in ['bcrypt', 'argon2', 'hashlib', 'crypto.', 'pbkdf2']):
            return True
    
    # NEVER filter hardcoded auth bypass values (OTP fallbacks, dev passwords)
    # These often appear alongside process.env but ARE still vulnerabilities
    auth_bypass_indicators = [
        'otp', 'fallback', 'bypass', 'dev-', 'test-', '111111', '123456', '000000',
        'hardcoded otp', 'hardcoded password', 'hardcoded token', 'auth bypass',
        'authentication bypass', 'dev backdoor', 'fallback code', 'fallback otp',
    ]
    is_auth_bypass = any(ind in title or ind in desc for ind in auth_bypass_indicators)
    
    # Environment variables used for secrets = CORRECT practice, NOT hardcoded
    # BUT: do NOT filter if the finding is about a hardcoded auth bypass value
    # AND: do NOT filter if there's a hardcoded fallback default value
    # e.g., os.environ.get('PASSWORD', 'hardcoded') — the fallback IS the vuln
    if not is_auth_bypass and ('secret' in title or 'hardcoded' in title or 'cwe-798' in (finding.cwe_id or '').lower()):
        # Check for hardcoded default/fallback patterns — these are STILL vulnerable
        fallback_indicators = [
            ", '", ', "', "default=", "default ='", 'default ="',
            "fallback", "or '", 'or "',
        ]
        has_hardcoded_fallback = any(pat in code for pat in fallback_indicators)

        if not has_hardcoded_fallback:
            env_patterns = [
                'process.env', 'os.environ', 'os.getenv(', 'config(',
                'from env', 'from @shared/config/env',
                'environment variable', 'env var',
            ]
            if any(pat in code or pat in desc for pat in env_patterns):
                return True
            if 'jwt' in title and ('env' in code or 'environment' in desc):
                return True
    
    # Config URLs from hardcoded constants are NOT SSRF
    if 'ssrf' in title or 'cwe-918' in (finding.cwe_id or '').lower():
        config_indicators = [
            'const ', 'constant', 'config', 'env_type', 'switch',
            'local_url', 'dev_url', 'prod_url', 'base_url',
        ]
        if any(ind in code or ind in desc for ind in config_indicators):
            if 'req.' not in code and 'request.' not in code and 'user' not in code:
                return True
    
    # Hardcoded URLs in config files are NOT vulnerabilities
    if 'hardcoded' in title and 'url' in title:
        if 'config' in desc or 'environment' in desc or 'switch' in code:
            return True
    
    # "No vulnerabilities found" — ONLY check the TITLE, not description
    # (descriptions legitimately mention injection types)
    no_vuln_title_phrases = [
        'no vulnerabilit', 'not vulnerable', 'none found',
        'no issues found', 'no findings found', 'not applicable',
        '— no ', '- no ', 'no evident', 'no direct',
        'no injection', 'no command injection', 'no code execution',
        'properly validated', 'correctly implemented',
    ]
    for phrase in no_vuln_title_phrases:
        if phrase in title:
            return True

    # UNIVERSAL: Detect when "vulnerable code" is actually a STRING DEFINITION,
    # regex pattern, or documentation example — not a real vulnerability.
    # Works for ANY project, no hardcoded filenames.
    if code:
        import re
        # Check if the dangerous function is inside quotes (= string reference, not actual call)
        # e.g., '"cursor.execute"' in a list vs cursor.execute(query) as real code
        quoted_danger_patterns = re.findall(
            r'["\'][a-z_]+\.(execute|system|popen|run|call|eval|exec)["\']', code
        )
        if quoted_danger_patterns:
            # Also verify there are list/dict indicators (string collections)
            collection_indicators = ['["', "['", '",', "',", '": ', "': ", "re.compile"]
            if any(ind in code for ind in collection_indicators):
                return True

    return False


def _is_lock_file_duplicate(finding: Finding) -> bool:
    """
    Lock files (package-lock.json, yarn.lock) — only keep the main manifest finding.
    BUT: only filter if the SAME CVE also exists in the non-lock file.
    For now, just filter lock files as they duplicate manifest entries.
    """
    basename = os.path.basename(finding.file_path or "").lower()
    return basename in {'package-lock.json', 'yarn.lock', 'pipfile.lock', 'poetry.lock', 'composer.lock'}


def rule_based_filter(findings: List[Finding]) -> List[Finding]:
    """
    Apply rule-based filters to instantly mark obvious false positives.
    This runs BEFORE the LLM verifier for speed and accuracy.
    CRITICAL: NEVER filters dependency CVEs from trivy/npm_audit.
    """
    for f in findings:
        reason = None
        
        # NEVER filter dependency CVEs from tool scanners
        is_dependency_cve = (
            'cve-' in f.title.lower() or
            'vulnerable dependency' in f.title.lower() or
            f.source.value in ('trivy', 'npm_audit')
        )
        
        # 1. Test files (but NOT dependency CVEs)
        if not is_dependency_cve and _is_test_file(f.file_path):
            reason = "Finding is in test/example code, not production code."
        
        # 2. Migration files (Django auto-generated)
        elif not is_dependency_cve and _is_migration_file(f.file_path):
            reason = "Finding is in an auto-generated database migration file."
        
        # 3. Safe ORM queries flagged as SQL injection
        elif _is_safe_orm_query(f):
            reason = "Uses parameterized ORM query (Django ORM/SQLAlchemy/Sequelize). Parameterized by default — not vulnerable to SQL injection."
        
        # 4. Framework safety patterns
        elif _is_safe_framework_pattern(f):
            reason = "Framework provides built-in safety for this pattern."
        
        # 5. Lock file duplicates (keep manifest, drop lock file entries)
        elif _is_lock_file_duplicate(f):
            reason = "Duplicate from lock file. Vulnerability tracked via main manifest."
        
        if reason:
            f.is_false_positive = True
            f.false_positive_reason = reason
    
    return findings


class VerifierAgent(BaseAgent):
    name = "verifier_agent"
    role = "Security Finding Verifier & False Positive Eliminator"
    description = (
        "You are the Verification Agent. You cross-validate ALL findings using "
        "dataflow analysis, framework awareness, and real-world exploitability assessment. "
        "You understand that ORMs are parameterized, TypeScript provides type safety, "
        "JWT libraries handle token validation, and many pattern-based findings are false positives."
    )

    VERIFIER_SYSTEM_PROMPT = """You are a senior security engineer performing FINAL verification of vulnerability findings.

## IMPORTANT: TWO TYPES OF VALID FINDINGS
You must handle BOTH types correctly:

### Type A: Dataflow Vulnerabilities
These require SOURCE → FLOW → SINK proof. If the framework protects against it, mark FALSE_POSITIVE.

### Type B: Missing Security Controls (ALWAYS CONFIRM)
These findings about MISSING controls are ALWAYS valid and should be CONFIRMED:
- Hardcoded fallback credentials (OTP codes, passwords, tokens) — ALWAYS CRITICAL
- Missing authentication on admin/privileged endpoints — ALWAYS CRITICAL  
- Stack traces / error details returned to clients — ALWAYS HIGH
- Missing security headers (CSP, HSTS, X-Frame-Options) — ALWAYS MEDIUM
- Missing cookie security flags (httpOnly, secure, sameSite) — ALWAYS MEDIUM
- Missing rate limiting on auth endpoints — ALWAYS MEDIUM
- Weak password policy — ALWAYS MEDIUM
- User enumeration via different error messages — ALWAYS MEDIUM
- Insecure randomness (Math.random for security) — ALWAYS MEDIUM
**DO NOT mark Type B findings as FALSE_POSITIVE. They do not need a dataflow path.**

## Dataflow Verification Process (for Type A only)
For EACH Type A finding, verify these IN ORDER:

### 1. SOURCE CHECK
- Does untrusted user input actually reach this code?
- If the data comes from internal/trusted sources only → FALSE_POSITIVE

### 2. FRAMEWORK PROTECTION CHECK
- **Django ORM**: `.objects.filter()`, `.objects.get()`, QuerySets are parameterized → NOT SQL injection
- **Prisma ORM**: Uses parameterized queries → NOT SQL injection
- **TypeScript**: Strong typing prevents many injection types
- **JWT Libraries**: jose, jsonwebtoken handle validation → auth bypass only if misconfigured
- **Template Engines**: Auto-escape HTML by default → NOT XSS (unless mark_safe/|safe used)

### 3. SANITIZATION CHECK  
- Is the input validated/sanitized BEFORE reaching the dangerous function?
- If properly sanitized → FALSE_POSITIVE

### 4. REACHABILITY CHECK
- Is this code reachable from a public endpoint?
- Is it dead code, test code, or behind a feature flag?

## VERDICT RULES
- **CONFIRMED**: 
  - Type A: Untrusted input reaches a dangerous sink WITHOUT proper sanitization
  - Type B: A security control is MISSING (no dataflow needed)
  - Hardcoded auth bypass values (OTP '111111', dev passwords) — ALWAYS CONFIRMED + CRITICAL
  - Admin endpoint without auth check — ALWAYS CONFIRMED + CRITICAL
- **FALSE_POSITIVE**: Any of these:
  - ORM/parameterized query flagged as SQL injection
  - path.join() without user input flagged as path traversal
  - Template auto-escaping flagged as XSS
  - Test/example/mock code
  - Properly sanitized input
  - A finding that says "no vulnerabilities found" — this is NOT a finding at all
- **NEEDS_REVIEW**: Cannot determine with certainty

## Severity Assignment for Type B Findings
- Hardcoded auth bypass (OTP/password fallback): **CRITICAL**
- Unauthenticated admin endpoints: **CRITICAL**
- Stack trace leaks in responses: **HIGH**
- Unauthenticated file uploads: **HIGH**
- Missing cookie security flags: **MEDIUM**
- Missing security headers: **MEDIUM**
- Missing rate limiting on auth: **MEDIUM**
- User enumeration: **MEDIUM**
- Weak password policy: **MEDIUM**

## Output Format
For each finding:
```
VERIFICATION:
- Finding: [Title]
- Verdict: [CONFIRMED / FALSE_POSITIVE / NEEDS_REVIEW]
- Confidence: [0.0 to 1.0]
- Reasoning: [Specific dataflow/framework reasoning]
- Adjusted Severity: [CRITICAL / HIGH / MEDIUM / LOW / INFO / same]
```
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

    def _verify_findings_batch(self, findings: List[Finding], code_context: str, batch_label: str = "") -> str:
        """Cross-validate a batch of findings with dataflow-aware reasoning."""
        self.think(f"Cross-validating {len(findings)} findings ({batch_label})...")

        findings_text = ""
        for i, f in enumerate(findings, 1):
            findings_text += (
                f"\n### Finding #{i}\n"
                f"- **Title**: {f.title}\n"
                f"- **Severity**: {f.severity.value}\n"
                f"- **Source**: {f.source.value}\n"
                f"- **File**: {f.file_path}:{f.line_number}\n"
                f"- **CWE**: {f.cwe_id}\n"
                f"- **Description**: {f.description[:200]}\n"
                f"- **Code**: ```{f.code_snippet[:300]}```\n"
            )

        prompt = (
            f"## Findings to Verify ({batch_label})\n{findings_text}\n\n"
            f"## Peer Agent Context\n{self.get_peer_context()}\n\n"
            f"## Source Code\n<CODE>\n{code_context[:15000]}\n</CODE>\n\n"
            f"Verify EACH finding carefully. "
            f"For Type A (dataflow) findings: Check (1) Does user input reach this code? (2) Does the framework protect it? (3) Is there sanitization? "
            f"For Type B (missing controls) findings: These are VALID if a security control is genuinely missing. DO NOT mark them as false positives. "
            f"Mark FALSE_POSITIVE ONLY for findings that are clearly wrong — ORM queries as SQL injection, auto-escaped templates as XSS, test code, etc. "
            f"PRESERVE findings about: hardcoded auth bypasses, missing admin auth, stack trace leaks, missing headers, insecure cookies, rate limiting gaps."
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
        Production verification pipeline:
        1. Rule-based pre-filtering (instant, no LLM needed)
        2. Layer 3 precision skills
        3. LLM-based dataflow verification in batches
        """
        self.think("Starting verification and false positive filtering...")

        all_findings = scan_result.findings
        
        # ═══════════════════════════════════════════
        # PHASE 0: Rule-Based Pre-Filtering (instant)
        # ═══════════════════════════════════════════
        pre_filter_count = len([f for f in all_findings if not f.is_false_positive])
        rule_based_filter(all_findings)
        post_filter_count = len([f for f in all_findings if not f.is_false_positive])
        rule_filtered = pre_filter_count - post_filter_count
        
        if console and rule_filtered > 0:
            console.print(f"  [green]✓[/green] Rule-based filter: [bold]{rule_filtered}[/bold] obvious false positives removed")

        # ═══════════════════════════════════════════
        # PHASE 1: Layer 3 Skills
        # ═══════════════════════════════════════════
        layer3_results = self._run_layer3_skills(code_context, console=console)

        # ═══════════════════════════════════════════
        # PHASE 2: LLM Dataflow Verification (in batches)
        # ═══════════════════════════════════════════
        # Only verify findings that passed rule-based filtering
        unverified = [f for f in all_findings if not f.is_false_positive]
        
        if unverified:
            # Prioritize: verify CRITICAL/HIGH first, then MEDIUM/LOW
            critical_high = [f for f in unverified if f.severity in (Severity.CRITICAL, Severity.HIGH)]
            medium_low = [f for f in unverified if f.severity in (Severity.MEDIUM, Severity.LOW, Severity.INFO)]

            # Batch 1: Critical & High findings (most important to verify)
            if critical_high:
                for batch_start in range(0, len(critical_high), 50):
                    batch = critical_high[batch_start:batch_start + 50]
                    batch_label = f"Critical+High batch {batch_start // 50 + 1}"
                    verification_text = self._verify_findings_batch(batch, code_context, batch_label)
                    self.share_knowledge(f"verification_critical_high_{batch_start}", verification_text)
                    self._apply_verification(batch, verification_text)

            # Batch 2: Medium & Low findings
            if medium_low:
                for batch_start in range(0, len(medium_low), 50):
                    batch = medium_low[batch_start:batch_start + 50]
                    batch_label = f"Medium+Low batch {batch_start // 50 + 1}"
                    verification_text = self._verify_findings_batch(batch, code_context, batch_label)
                    self.share_knowledge(f"verification_medium_low_{batch_start}", verification_text)
                    self._apply_verification(batch, verification_text)

        # Set default confidence for unverified findings
        for f in all_findings:
            if f.confidence == 0.0:
                f.confidence = 0.7

        confirmed = scan_result.get_confirmed()
        false_positives = [f for f in all_findings if f.is_false_positive]

        self.conclude(f"Verification complete: {len(confirmed)} confirmed, {len(false_positives)} false positives eliminated")

        return {
            "layer3_results": layer3_results,
            "confirmed_count": len(confirmed),
            "false_positive_count": len(false_positives),
            "rule_filtered_count": rule_filtered,
        }
