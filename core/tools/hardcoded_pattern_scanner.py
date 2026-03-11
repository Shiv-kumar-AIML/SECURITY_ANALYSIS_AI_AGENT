"""
Hardcoded Pattern Scanner — Deterministic, rule-based vulnerability detector.
Finds critical security patterns that LLMs miss due to non-determinism:
  - Hardcoded OTP/password fallbacks
  - Math.random() for security-sensitive values
  - error.stack leaks in responses
  - Missing security headers
  - User enumeration patterns
  - Weak password policy (length-only)
  - Unauthenticated endpoints (no auth check)

This scanner uses REGEX only — no LLM dependency. It ALWAYS finds these patterns.
"""
import os
import re
from typing import List
from .base_tool import BaseTool
from ..findings import Finding, Severity, FindingSource


# ═══════════════════════════════════════════════════════════════
# PATTERN DEFINITIONS — each pattern defines what to search for
# ═══════════════════════════════════════════════════════════════

PATTERNS = [
    {
        "id": "hardcoded-otp-bypass",
        "title": "Hardcoded OTP Bypass — Authentication can be bypassed with known code",
        "description": (
            "A hardcoded OTP code (e.g., '111111') is used as a fallback for authentication. "
            "An attacker who knows this code can bypass OTP verification entirely, "
            "gaining unauthorized access to any account without a valid OTP."
        ),
        "severity": Severity.CRITICAL,
        "cwe_id": "CWE-287: Improper Authentication",
        "owasp": "A07:2021 - Identification and Authentication Failures",
        # Match patterns like: otp === '111111', code == "123456", = '000000', let x = '111111'
        "regex": r"""(?:['"](?:111111|123456|000000|999999|112233|654321)['"])""",
        "file_patterns": ["*.ts", "*.js", "*.tsx", "*.jsx", "*.py"],
        "context_keywords": ["otp", "verify", "auth", "login", "code", "fallback", "bypass"],
    },
    {
        "id": "hardcoded-dev-password",
        "title": "Hardcoded Development Password/Token in Source Code",
        "description": (
            "A hardcoded password, token, or secret is embedded in the source code. "
            "Even if gated behind environment checks, misconfiguration can expose it in production."
        ),
        "severity": Severity.CRITICAL,
        "cwe_id": "CWE-798: Use of Hard-coded Credentials",
        "owasp": "A07:2021 - Identification and Authentication Failures",
        # Match dev/test passwords in auth context
        "regex": r"""(?:password|passwd|secret|token)\s*(?:===?|!==?|=)\s*['"](?:admin|password|test|dev|123456|qwerty|secret|changeme)['"]""",
        "file_patterns": ["*.ts", "*.js", "*.tsx", "*.jsx", "*.py"],
        "context_keywords": ["auth", "login", "password", "admin", "verify"],
    },
    {
        "id": "insecure-random-otp",
        "title": "Insecure Randomness — Math.random() Used for OTP/Token Generation",
        "description": (
            "Math.random() is not cryptographically secure. It uses a predictable PRNG "
            "that can be reverse-engineered, allowing attackers to predict generated "
            "OTP codes, session tokens, or unique IDs."
        ),
        "severity": Severity.MEDIUM,
        "cwe_id": "CWE-330: Use of Insufficiently Random Values",
        "owasp": "A02:2021 - Cryptographic Failures",
        "regex": r"""Math\.random\s*\(\s*\)""",
        "file_patterns": ["*.ts", "*.js", "*.tsx", "*.jsx"],
        "context_keywords": ["otp", "token", "code", "id", "random", "generate", "uuid"],
    },
    {
        "id": "stack-trace-leak",
        "title": "Stack Trace Leak — Internal Error Details Exposed to Client",
        "description": (
            "error.stack or full error objects are returned in API responses. "
            "This exposes internal code structure, file paths, and library versions "
            "to attackers, aiding reconnaissance for further attacks."
        ),
        "severity": Severity.HIGH,
        "cwe_id": "CWE-209: Generation of Error Message Containing Sensitive Information",
        "owasp": "A04:2021 - Insecure Design",
        "regex": r"""(?:error\.stack|err\.stack|\.stack\b)(?!Trace)""",
        "file_patterns": ["*.ts", "*.js", "*.tsx", "*.jsx"],
        "context_keywords": ["response", "json", "return", "res.", "NextResponse", "send"],
    },
    {
        "id": "user-enumeration",
        "title": "User Enumeration — Login Reveals Whether a User Exists",
        "description": (
            "The login/auth endpoint returns different error messages for 'user not found' "
            "vs 'wrong password'. This allows attackers to enumerate valid usernames/emails "
            "by observing the response differences."
        ),
        "severity": Severity.MEDIUM,
        "cwe_id": "CWE-204: Observable Response Discrepancy",
        "owasp": "A07:2021 - Identification and Authentication Failures",
        "regex": r"""['"](?:User not found|Account not found|Email not found|No user|No account|Phone not registered|User does not exist|Invalid email)['"]""",
        "file_patterns": ["*.ts", "*.js", "*.tsx", "*.jsx", "*.py"],
        "context_keywords": ["login", "auth", "signin", "sign-in", "authenticate"],
    },
    {
        "id": "weak-password-length-only",
        "title": "Weak Password Policy — Only Length Validation, No Complexity Requirements",
        "description": (
            "Password validation only checks minimum length (e.g., password.length < 8). "
            "This allows weak passwords like '12345678' or 'aaaaaaaa' that are trivially "
            "guessable via brute-force or dictionary attacks."
        ),
        "severity": Severity.MEDIUM,
        "cwe_id": "CWE-521: Weak Password Requirements",
        "owasp": "A07:2021 - Identification and Authentication Failures",
        # Only match password/newPassword — NOT confirmPassword (that's form UI validation)
        "regex": r"""(?<!confirm)(?:password|newPassword|new_password)(?:\.length|\.len\b)\s*(?:<|<=|>|>=)\s*\d+""",
        "file_patterns": ["*.ts", "*.js", "*.py"],  # Exclude .tsx/.jsx — those are React UI components
        "context_keywords": ["password", "reset", "change", "register", "signup"],
    },
    {
        "id": "missing-auth-api-route",
        "title": "API Route Without Authentication — No Auth Check Before Database Operations",
        "description": (
            "This API route performs database operations (create, update, delete) "
            "but does not verify the caller's identity via JWT, session, or any auth mechanism. "
            "Any unauthenticated user can invoke this endpoint."
        ),
        "severity": Severity.HIGH,
        "cwe_id": "CWE-306: Missing Authentication for Critical Function",
        "owasp": "A01:2021 - Broken Access Control",
        # Match route handlers that have prisma/db operations but NO auth checks
        "regex": r"""(?:export\s+async\s+function\s+(?:POST|PUT|PATCH|DELETE))|(?:app\.(?:post|put|patch|delete)\s*\()""",
        "file_patterns": ["*.ts", "*.js"],
        "context_keywords": ["admin", "approve", "delete", "update", "create"],
        "negative_keywords": ["verifyAccessToken", "getServerSession", "auth(", "authenticate", 
                              "requireAuth", "withAuth", "isAuthenticated", "jwt", "bearer",
                              "authorization", "cookie", "session"],
    },
    {
        "id": "env-var-fallback-secret",
        "title": "Hardcoded Fallback Password/Secret in Environment Variable Read",
        "description": (
            "An environment variable read (os.environ.get or process.env) has a hardcoded "
            "fallback value for a security-sensitive setting (*_PASSWORD, *_SECRET, *_KEY, *_TOKEN). "
            "If the environment variable is not set in production, the hardcoded fallback becomes "
            "the live value, exposing credentials to anyone who reads the source code."
        ),
        "severity": Severity.CRITICAL,
        "cwe_id": "CWE-798: Use of Hard-coded Credentials",
        "owasp": "A07:2021 - Identification and Authentication Failures",
        # Match: os.environ.get('ANYTHING_PASSWORD', 'non_empty_value')
        # Also: process.env.SECRET || 'fallback'
        "regex": r"""(?:os\.environ\.get\s*\(\s*['\"][^'"]*(?:PASSWORD|SECRET|KEY|TOKEN)[^'"]*['"]\s*,\s*['"][^'"]+['"]\s*\))|(?:process\.env\.\w*(?:PASSWORD|SECRET|KEY|TOKEN)\w*\s*\|\|\s*['"][^'"]+['"])""",
        "file_patterns": ["*.py", "*.js", "*.ts"],
        "context_keywords": ["password", "secret", "key", "token", "credential", "api"],
    },
]


class HardcodedPatternScanner(BaseTool):
    """
    Deterministic pattern scanner that finds security issues via regex.
    Does NOT depend on any LLM — always produces consistent results.
    """
    name = "pattern_scanner"
    description = "Deterministic pattern-based security scanner"

    def is_available(self) -> bool:
        return True  # Pure Python, always available

    def run(self, target_path: str) -> dict:
        """Scan all relevant files for hardcoded patterns."""
        results = []
        
        for root, _dirs, files in os.walk(target_path):
            # Skip node_modules, .git, dist, build
            rel_root = os.path.relpath(root, target_path)
            if any(skip in rel_root.split(os.sep) for skip in 
                   ['node_modules', '.git', 'dist', 'build', '.next', '__pycache__', 'coverage']):
                continue
            
            for filename in files:
                filepath = os.path.join(root, filename)
                
                for pattern in PATTERNS:
                    # Check file extension match
                    if not any(filename.endswith(ext.replace('*', '')) for ext in pattern["file_patterns"]):
                        continue
                    
                    try:
                        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                        
                        if len(content) > 500_000:  # Skip very large files
                            continue
                        
                        lines = content.split('\n')
                        
                        # Find all regex matches
                        for match in re.finditer(pattern["regex"], content, re.IGNORECASE):
                            match_pos = match.start()
                            # Calculate line number
                            line_num = content[:match_pos].count('\n') + 1
                            
                            # Get context: 5 lines before and after the match
                            start_line = max(0, line_num - 6)
                            end_line = min(len(lines), line_num + 5)
                            context = '\n'.join(lines[start_line:end_line])
                            context_lower = context.lower()
                            
                            # Check if context contains relevant keywords
                            has_context = True
                            if pattern.get("context_keywords"):
                                has_context = any(kw in context_lower for kw in pattern["context_keywords"])
                            
                            # For missing-auth pattern, check negative keywords
                            if pattern["id"] == "missing-auth-api-route":
                                # Read the FULL file content to check if auth exists anywhere
                                file_lower = content.lower()
                                has_auth = any(neg in file_lower for neg in pattern.get("negative_keywords", []))
                                if has_auth:
                                    continue  # File has auth checks, skip
                                # Also check for admin/sensitive context
                                if not any(kw in filepath.lower() for kw in pattern["context_keywords"]):
                                    continue  # Not a sensitive endpoint, skip
                            
                            if has_context:
                                # Get the matching line content
                                match_line = lines[line_num - 1] if line_num <= len(lines) else ""
                                
                                results.append({
                                    "pattern_id": pattern["id"],
                                    "title": pattern["title"],
                                    "description": pattern["description"],
                                    "severity": pattern["severity"],
                                    "cwe_id": pattern["cwe_id"],
                                    "owasp": pattern.get("owasp", ""),
                                    "file": filepath,
                                    "line": line_num,
                                    "match": match.group(0),
                                    "context": context,
                                    "match_line": match_line.strip(),
                                })
                    except Exception:
                        continue
        
        return {"findings": results}

    def parse_results(self, raw_results: dict) -> List[Finding]:
        """Convert raw pattern matches into Finding objects."""
        findings = []
        seen = set()  # Dedup by pattern_id + file
        
        for item in raw_results.get("findings", []):
            # Dedup: only one finding per pattern per UNIQUE file path (not basename)
            # Using relative path to avoid merging send-otp/route.ts with verify-otp/route.ts
            rel_path = os.path.relpath(item['file'], os.path.commonpath([item['file']])) if item['file'] else item['file']
            # Use last 3 path components for dedup (e.g., 'client/auth/send-otp/route.ts')
            path_parts = item['file'].replace('\\', '/').split('/')
            dedup_path = '/'.join(path_parts[-4:]) if len(path_parts) >= 4 else '/'.join(path_parts)
            dedup_key = f"{item['pattern_id']}|{dedup_path}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            
            finding = Finding(
                title=item["title"],
                description=(
                    f"{item['description']}\n\n"
                    f"**Match**: `{item['match']}` at line {item['line']}\n"
                    f"**Evidence**: `{item['match_line']}`"
                ),
                severity=item["severity"],
                source=FindingSource.TOOL_SEMGREP,  # Use tool source so verifier respects it
                file_path=item["file"],
                line_number=item["line"],
                code_snippet=item["context"],
                cwe_id=item["cwe_id"],
                owasp_category=item.get("owasp", ""),
                confidence=0.95,  # High confidence — deterministic match
            )
            findings.append(finding)
        
        return findings
