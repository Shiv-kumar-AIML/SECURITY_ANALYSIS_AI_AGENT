"""
Enhanced Report Generator.
Produces clean, structured reports with COMPLETE details for every finding:
  - Vulnerable Code (reads actual source files)
  - Why This Is Vulnerable (explanation)
  - Solution Code + Description (default templates for common vulns)
Ordered by: Critical → High → Medium → Low → Info
Deduplicates findings to remove redundant entries.
"""
import re
import time
import json
import os
from pathlib import Path
from .constants import REPORTS_DIR
from .findings import ScanResult, Severity, Finding


# ═══════════════════════════════════════════════════════════════
# DEFAULT REMEDIATION TEMPLATES for common vulnerability types.
# Used when the LLM/tool doesn't provide remediation.
# ═══════════════════════════════════════════════════════════════
DEFAULT_REMEDIATIONS = {
    "sql_injection": {
        "why": "User input is directly concatenated or interpolated into SQL queries without parameterization. An attacker can inject malicious SQL commands to read, modify, or delete database data.",
        "solution": "Use parameterized queries (prepared statements) instead of string concatenation. Never embed user input directly into SQL strings.",
        "code": """# VULNERABLE:
query = "SELECT * FROM users WHERE id = " + user_id

# FIXED (parameterized):
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

# OR with Django ORM (safe by default):
User.objects.filter(id=user_id)"""
    },
    "command_injection": {
        "why": "User-controlled input flows into OS command execution functions without sanitization. An attacker can inject shell metacharacters (;, |, &&, etc.) to execute arbitrary commands on the server.",
        "solution": "Avoid shell=True. Use subprocess with a list of arguments. Validate and sanitize all user inputs before passing to system commands.",
        "code": """# VULNERABLE:
os.system("ping " + user_input)
subprocess.call("ls " + path, shell=True)

# FIXED (use list args, no shell):
subprocess.run(["ping", "-c", "1", validated_host], shell=False)
subprocess.run(["ls", validated_path], shell=False)"""
    },
    "xss": {
        "why": "User-supplied data is rendered in HTML output without proper escaping. An attacker can inject JavaScript code that executes in other users' browsers, stealing cookies, credentials, or performing actions on their behalf.",
        "solution": "Always escape user input before rendering in HTML. Use framework-provided template engines. Avoid mark_safe(), HttpResponse with user data, and direct DOM manipulation.",
        "code": """# VULNERABLE (Node.js/Express):
res.send(`<p>${userInput}</p>`);

# FIXED (use a template engine like EJS with auto-escaping):
res.render('template', { data: userInput });

# FIXED (manual escape with DOMPurify):
import DOMPurify from 'dompurify';
const clean = DOMPurify.sanitize(userInput);"""
    },
    "open_redirect": {
        "why": "The application redirects users to a URL provided in the request without validating it. An attacker can craft a URL that redirects to a malicious site for phishing.",
        "solution": "Validate redirect URLs against an allowlist of domains. Only allow redirects to your own domain.",
        "code": """// VULNERABLE:
const next = req.query.next;
res.redirect(next);

// FIXED:
const allowedHosts = [process.env.APP_DOMAIN];
const url = new URL(req.query.next, `https://${process.env.APP_DOMAIN}`);
if (allowedHosts.includes(url.hostname)) {
  res.redirect(url.toString());
} else {
  res.redirect('/');
}"""
    },
    "csrf": {
        "why": "CSRF protection is missing or disabled. An attacker can trick authenticated users into submitting malicious requests.",
        "solution": "Enable CSRF protection. For Next.js API routes, validate the Origin/Referer header or use CSRF tokens.",
        "code": """// FIXED (Next.js — validate Origin header):
const origin = request.headers.get('origin');
const allowedOrigins = [process.env.NEXT_PUBLIC_APP_URL];
if (!allowedOrigins.includes(origin)) {
  return NextResponse.json({ error: 'Forbidden' }, { status: 403 });
}"""
    },
    "hardcoded_secret": {
        "why": "Sensitive credentials (API keys, passwords, tokens) are hardcoded in the source code. Anyone with access to the repository can extract and misuse them.",
        "solution": "Move all secrets to environment variables or a secrets manager. Never commit secrets to git.",
        "code": """// VULNERABLE:
const API_KEY = 'sk-1234567890abcdef';

// FIXED (use environment variables):
const API_KEY = process.env.API_KEY;
if (!API_KEY) throw new Error('API_KEY must be set');

// For Next.js, use .env.local (gitignored):
// API_KEY=sk-your-key-here"""
    },
    "unvalidated_password": {
        "why": "Password validation only checks length, allowing weak passwords (e.g., '12345678', 'password') that are vulnerable to brute-force and dictionary attacks.",
        "solution": "Enforce password complexity: minimum length, uppercase, lowercase, digits, and special characters.",
        "code": """// VULNERABLE:
if (password.length < 8) { return error; }

// FIXED (enforce complexity):
function validatePassword(password: string): string | null {
  if (password.length < 8) return 'Password must be at least 8 characters';
  if (!/[A-Z]/.test(password)) return 'Must contain an uppercase letter';
  if (!/[a-z]/.test(password)) return 'Must contain a lowercase letter';
  if (!/[0-9]/.test(password)) return 'Must contain a digit';
  if (!/[!@#$%^&*]/.test(password)) return 'Must contain a special character';
  return null;
}"""
    },
    "eval_usage": {
        "why": "eval() executes arbitrary code from a string. If any part of that string comes from user input, an attacker can execute arbitrary code on the server.",
        "solution": "Remove eval() entirely. Use JSON.parse() for JSON, or implement proper parsers.",
        "code": """// VULNERABLE:
const result = eval(userExpression);

// FIXED (for JSON):
const result = JSON.parse(userData);

// FIXED (for math): use a safe expression library like 'mathjs'"""
    },
    "vulnerable_dependency": {
        "why": "The project uses third-party packages with known security vulnerabilities (CVEs). Attackers can exploit these vulnerabilities if the affected package functionality is reachable from user input.",
        "solution": "Upgrade the vulnerable dependency to the patched version. Run dependency audits regularly.",
        "code": """# Check for vulnerable dependencies:
npm audit

# Auto-fix where possible:
npm audit fix

# Force fix (may include breaking changes):
npm audit fix --force

# Or manually update the specific package:
npm update <package-name>
npm install <package-name>@latest"""
    },
    # ─── Node.js / Express / Next.js specific templates ───
    "path_traversal": {
        "why": "User-controlled input (filenames, paths, extensions) is used in file system operations without sanitization. An attacker can traverse directories using '../' sequences to read or write arbitrary files.",
        "solution": "Sanitize filenames by stripping path separators and traversal sequences. Use path.basename() to extract only the filename. Validate the resolved path stays within the intended directory.",
        "code": """// VULNERABLE:
const filePath = path.join(uploadDir, file.name);
await writeFile(filePath, buffer);

// FIXED:
import path from 'path';

const safeName = path.basename(file.name).replace(/[^\\w.-]/g, '');
const safeExt = safeName.split('.').pop()?.replace(/[^a-zA-Z0-9]/g, '') || 'bin';
const filename = `${uuidv4()}.${safeExt}`;
const filePath = path.resolve(uploadDir, filename);

// Verify resolved path is within allowed directory
if (!filePath.startsWith(path.resolve(uploadDir) + path.sep)) {
  throw new Error('Path traversal detected');
}
await writeFile(filePath, buffer);"""
    },
    "jwt_vulnerability": {
        "why": "JWT tokens may be vulnerable to algorithm confusion attacks, weak secrets, or missing validation. If tokens are not properly verified, attackers can forge authentication tokens.",
        "solution": "Always explicitly specify the allowed algorithm when verifying. Use strong secrets (256+ bits). Set appropriate expiration times.",
        "code": """// FIXED (jose library — already handles algorithm enforcement):
import { jwtVerify } from 'jose';

const secret = new TextEncoder().encode(process.env.JWT_SECRET);
const { payload } = await jwtVerify(token, secret, {
  algorithms: ['HS256'],  // Explicitly restrict algorithm
  maxTokenAge: '1h',       // Limit token lifetime
});"""
    },
    "missing_security_headers": {
        "why": "The application does not set security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options), leaving it vulnerable to clickjacking, MIME sniffing, and cross-site attacks.",
        "solution": "Add security headers in next.config.js or middleware. For Express, use the helmet middleware.",
        "code": """// FIXED (next.config.js):
const nextConfig = {
  async headers() {
    return [{
      source: '/(.*)',
      headers: [
        { key: 'X-Frame-Options', value: 'DENY' },
        { key: 'X-Content-Type-Options', value: 'nosniff' },
        { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
        { key: 'Strict-Transport-Security', value: 'max-age=63072000; includeSubDomains' },
        { key: 'Content-Security-Policy', value: "default-src 'self'; script-src 'self'" },
      ],
    }];
  },
};

// FIXED (Express — use helmet):
import helmet from 'helmet';
app.use(helmet());"""
    },
    "insecure_cookie": {
        "why": "Authentication cookies are missing security flags, making them vulnerable to theft via XSS (missing httpOnly), network interception (missing secure), or CSRF (missing sameSite).",
        "solution": "Set all three security flags on authentication cookies: httpOnly, secure, and sameSite.",
        "code": """// VULNERABLE:
cookies.set('accessToken', token);

// FIXED:
cookies.set('accessToken', token, {
  httpOnly: true,                                // Prevents JavaScript access (XSS protection)
  secure: process.env.NODE_ENV === 'production', // HTTPS only in production
  sameSite: 'lax',                               // CSRF protection
  maxAge: 15 * 60,                               // 15 minutes
  path: '/',
});"""
    },
    "auth_bypass": {
        "why": "Hardcoded fallback credentials (OTP codes, passwords, tokens) allow authentication bypass. Even if gated behind environment checks, misconfiguration in production can activate the bypass.",
        "solution": "Remove all hardcoded fallback credentials. Use proper OTP validation against the database in all environments.",
        "code": """// VULNERABLE:
const isDevFallback = otp === '111111' && !process.env.TWILIO_ACCOUNT_SID;
if (!validOtp && !isDevFallback) { reject(); }

// FIXED (remove fallback entirely):
const validOtp = await prisma.otp.findFirst({
  where: { phone, code: otp, used: false, expiresAt: { gt: new Date() } }
});
if (!validOtp) {
  return NextResponse.json({ error: 'Invalid or expired OTP' }, { status: 400 });
}
await prisma.otp.update({ where: { id: validOtp.id }, data: { used: true } });"""
    },
    "stack_trace_leak": {
        "why": "Stack traces and internal error details are returned in API responses. This exposes internal code structure, file paths, and library versions to attackers, aiding reconnaissance.",
        "solution": "Never return error.stack or internal error details to clients. Log them server-side and return generic error messages.",
        "code": """// VULNERABLE:
return NextResponse.json({ error: error.message, stack: error.stack }, { status: 500 });

// FIXED:
console.error('Internal error:', error);  // Log full error server-side
return NextResponse.json(
  { success: false, message: 'Internal server error' },
  { status: 500 }
);"""
    },
    "insecure_randomness": {
        "why": "Math.random() is not cryptographically secure. It uses a predictable PRNG that can be reverse-engineered, allowing attackers to predict generated OTP codes, session IDs, or tokens.",
        "solution": "Use crypto.randomInt() or crypto.randomBytes() for security-sensitive random values.",
        "code": """// VULNERABLE:
const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
const serviceId = Math.random().toString(36).substring(2, 12);

// FIXED (Node.js crypto):
import crypto from 'crypto';
const otpCode = crypto.randomInt(100000, 999999).toString();
const serviceId = crypto.randomBytes(6).toString('hex');"""
    },
    "weak_password_policy": {
        "why": "Password validation only checks minimum length (e.g., 8 characters). This allows weak passwords like '12345678' or 'password' that are trivially guessable.",
        "solution": "Enforce password complexity requirements: minimum length, mixed case, digits, and special characters.",
        "code": """// VULNERABLE:
if (password.length < 8) { return 'Too short'; }

// FIXED:
function validatePassword(password: string): string | null {
  if (password.length < 8) return 'Password must be at least 8 characters';
  if (!/[A-Z]/.test(password)) return 'Must contain uppercase letter';
  if (!/[a-z]/.test(password)) return 'Must contain lowercase letter';
  if (!/[0-9]/.test(password)) return 'Must contain a digit';
  if (!/[!@#$%^&*()_+=-]/.test(password)) return 'Must contain special character';
  return null;
}"""
    },
    "mark_safe": {
        "why": "mark_safe() tells Django to NOT escape HTML content in templates. If the marked content contains any user-controlled data, it creates an XSS vulnerability.",
        "solution": "Replace mark_safe() with format_html() which safely escapes parameters while keeping the HTML structure.",
        "code": """# VULNERABLE:
from django.utils.safestring import mark_safe
html = mark_safe(f'<a href="{url}">{user_text}</a>')

# FIXED:
from django.utils.html import format_html
html = format_html('<a href="{}">{}</a>', url, user_text)"""
    },
    "query_set_extra": {
        "why": "QuerySet.extra() allows raw SQL to be injected into Django ORM queries. Django documentation itself warns against using extra().",
        "solution": "Replace .extra() with Django ORM methods like .annotate(), .filter(), .values().",
        "code": """# VULNERABLE:
qs.extra(where=["name = '%s'" % user_input])

# FIXED (use ORM):
qs.filter(name=user_input)"""
    },
    "http_response_direct": {
        "why": "Directly passing data to HttpResponse bypasses template engine XSS protections.",
        "solution": "Use render() with templates instead of HttpResponse with dynamic content.",
        "code": """# VULNERABLE:
return HttpResponse(f"Hello {user_name}")

# FIXED:
return render(request, 'greeting.html', {'name': user_name})"""
    },
    "blocktranslate_no_escape": {
        "why": "Translated strings in {% blocktranslate %} tags are not escaped by default.",
        "solution": "Apply the force_escape filter to translated variables.",
        "code": """<!-- VULNERABLE: -->
{% blocktranslate %}Welcome {{ username }}{% endblocktranslate %}

<!-- FIXED: -->
{% blocktranslate %}Welcome {{ username|force_escape }}{% endblocktranslate %}"""
    },
}


def _match_remediation_template(finding: Finding) -> dict:
    """Match a finding to a default remediation template based on title, CWE, or description."""
    title_lower = finding.title.lower()
    desc_lower = finding.description.lower()
    cwe = finding.cwe_id.lower() if finding.cwe_id else ""

    # Direct keyword matching
    # Direct keyword matching (ORDER MATTERS — more specific first)
    matches = {
        # Specific Node.js/Express/Next.js patterns first
        "auth_bypass": ["auth bypass", "hardcoded otp", "otp bypass", "fallback otp", "fallback code",
                        "cwe-287", "authentication bypass", "dev backdoor"],
        "stack_trace_leak": ["stack trace", "error.stack", "cwe-209", "stack leak"],
        "insecure_randomness": ["math.random", "insecure random", "cwe-330", "predictable"],
        "weak_password_policy": ["password policy", "password.length", "weak password"],
        "missing_security_headers": ["security header", "csp", "hsts", "x-frame-options", "missing header", "cwe-693"],
        "insecure_cookie": ["cookie flag", "httponly", "samesite", "insecure cookie", "cwe-614"],
        "path_traversal": ["path traversal", "cwe-22", "path.join", "path join", "directory traversal"],
        "jwt_vulnerability": ["jwt", "cwe-327", "cwe-347", "algorithm confusion", "jwtverify"],
        # Generic patterns after
        "sql_injection": ["sql injection", "cwe-89", "query set extra", "query-set-extra", "extends custom expression"],
        "command_injection": ["command injection", "cwe-78", "os.system", "subprocess"],
        "xss": ["cross-site scripting", "xss", "cwe-79", "direct use of httpresponse", "http_response"],
        "open_redirect": ["open redirect", "cwe-601"],
        "csrf": ["csrf", "cwe-352", "csrf_exempt", "no csrf"],
        "hardcoded_secret": ["hardcoded secret", "hardcoded credential", "cwe-798", "api key exposed"],
        "unvalidated_password": ["unvalidated password", "cwe-521", "password validation"],
        "eval_usage": ["eval(", "cwe-95"],
        "vulnerable_dependency": ["cve-", "vulnerable dependency", "cwe-1321", "prototype pollution"],
        "mark_safe": ["mark_safe", "avoid mark safe"],
        "query_set_extra": ["query set extra", "queryset.extra"],
        "http_response_direct": ["httpresponse", "direct use of http"],
        "blocktranslate_no_escape": ["blocktranslate", "block translate"],
    }

    for template_key, keywords in matches.items():
        for keyword in keywords:
            if keyword in title_lower or keyword in desc_lower or keyword in cwe:
                return DEFAULT_REMEDIATIONS.get(template_key, {})

    return {}


class ReportGenerator:
    def __init__(self, scan_result: ScanResult):
        self.result = scan_result
        if not REPORTS_DIR.exists():
            REPORTS_DIR.mkdir(parents=True)

    @staticmethod
    def _normalize_file_path(file_path: str) -> str:
        """Extract normalized filename for dedup (just the relative tail)."""
        # Strip cloned_repos/repo_name prefix and take only the app-relative path
        if 'cloned_repos/' in file_path:
            parts = file_path.split('cloned_repos/')
            if len(parts) > 1:
                repo_rest = parts[1]
                slash_idx = repo_rest.find('/')
                if slash_idx >= 0:
                    return repo_rest[slash_idx + 1:]
        return os.path.basename(file_path)

    @staticmethod
    def _extract_cwe_number(cwe_id: str) -> str:
        """Extract just the CWE number for dedup (e.g., 'CWE-22' from 'CWE-22: Path Traversal...')."""
        if not cwe_id:
            return ""
        match = re.search(r'CWE-\d+', cwe_id, re.IGNORECASE)
        return match.group(0).upper() if match else cwe_id.strip().upper()

    def _deduplicate(self, findings: list) -> list:
        """Remove duplicate findings using multiple matching strategies.
        
        Dedup keys (any match = duplicate):
        1. Exact: title + file + line_number
        2. CVE-based: CVE-ID + file
        3. CWE+file: CWE-22 + upload/route.ts (catches same-vuln-type same-file from different sources)
        4. Desc-prefix: title + file + desc[:100]
        
        When duplicates are found, keep the one with higher confidence or better remediation.
        """
        seen = {}
        unique = []

        for f in findings:
            rel_path = self._get_relative_path(f.file_path)
            norm_file = self._normalize_file_path(f.file_path)

            # Extract CVE ID from title if present
            cve_match = re.search(r'(CVE-\d{4}-\d+)', f.title)
            cve_id = cve_match.group(1) if cve_match else None

            # Extract normalized CWE number
            cwe_num = self._extract_cwe_number(f.cwe_id)

            keys = set()
            # Key 1: Exact match
            keys.add(f"{f.title}|{rel_path}|{f.line_number}")
            # Key 2: CVE-based (same CVE, same file)
            if cve_id:
                keys.add(f"{cve_id}|{rel_path}")
            # Key 3: CWE + FULL relative path — THIS catches cross-source duplicates
            # e.g., semgrep's "Path Join Resolve Traversal" and agent's "Path Traversal in Upload"
            # both have CWE-22 and point to the same file
            # IMPORTANT: Use FULL rel_path, not norm_file, to avoid merging different files
            # e.g., send-otp/route.ts and verify-otp/route.ts are DIFFERENT files
            if cwe_num and rel_path:
                keys.add(f"{cwe_num}|{rel_path}")
            # Key 4: Description-prefix match
            desc_prefix = f.description[:100].strip()
            keys.add(f"{f.title}|{rel_path}|{desc_prefix}")

            is_duplicate = False
            for key in keys:
                if key in seen:
                    existing = seen[key]
                    # Replace if new finding has better quality
                    if (f.confidence > existing.confidence or
                            (f.remediation and not existing.remediation) or
                            (f.remediation_code and not existing.remediation_code) or
                            (f.severity.score > existing.severity.score)):
                        try:
                            idx = unique.index(existing)
                            unique[idx] = f
                        except ValueError:
                            pass
                        for k in keys:
                            seen[k] = f
                    is_duplicate = True
                    break

            if not is_duplicate:
                unique.append(f)
                for key in keys:
                    seen[key] = f

        return unique

    def _get_relative_path(self, file_path: str) -> str:
        """Convert absolute path to relative path from the scanned repo."""
        target = self.result.target_path
        if target and file_path.startswith(target):
            return os.path.relpath(file_path, target)
        if "cloned_repos/" in file_path:
            parts = file_path.split("cloned_repos/")
            if len(parts) > 1:
                repo_and_rest = parts[1]
                slash_idx = repo_and_rest.find("/")
                if slash_idx >= 0:
                    return repo_and_rest[slash_idx + 1:]
        return file_path

    def _read_source_code(self, file_path: str, line_number: int, end_line: int = 0, context_lines: int = 5) -> str:
        """Read actual vulnerable code from the source file."""
        try:
            if not os.path.isfile(file_path):
                return ""

            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                all_lines = f.readlines()

            if not all_lines or line_number <= 0:
                return ""

            start = max(0, line_number - context_lines - 1)
            end = min(len(all_lines), (end_line or line_number) + context_lines)

            code_lines = []
            for i in range(start, end):
                marker = ">>>" if (line_number - 1) <= i <= (end_line or line_number) - 1 else "   "
                code_lines.append(f"{marker} {i + 1:4d} | {all_lines[i].rstrip()}")

            return "\n".join(code_lines)
        except Exception:
            return ""

    def _enrich_finding(self, finding: Finding) -> Finding:
        """Ensure every finding has: code snippet, why-vulnerable, remediation."""
        # 1. Ensure code snippet — read from source file if missing
        bad_snippets = {"", "requires login", "No code", "N/A"}
        if not finding.code_snippet or finding.code_snippet.strip() in bad_snippets:
            if finding.file_path and finding.line_number > 0:
                extracted = self._read_source_code(finding.file_path, finding.line_number, finding.end_line)
                if extracted:
                    finding.code_snippet = extracted

        # 2. Ensure remediation — use default template if missing
        template = _match_remediation_template(finding)
        if template:
            if not finding.reasoning_chain or finding.reasoning_chain.strip() == "":
                finding.reasoning_chain = template.get("why", "")
            if not finding.remediation or finding.remediation.strip() == "":
                finding.remediation = template.get("solution", "")
            if not finding.remediation_code or finding.remediation_code.strip() == "":
                finding.remediation_code = template.get("code", "")

        # 3. Fallback: use description as why-vulnerable if reasoning is still empty
        if not finding.reasoning_chain or finding.reasoning_chain.strip() == "":
            finding.reasoning_chain = finding.description

        # 4. Fallback remediation from CWE/OWASP
        if not finding.remediation or finding.remediation.strip() == "":
            if finding.cwe_id:
                finding.remediation = f"Address {finding.cwe_id} by following OWASP guidelines. Review and fix the code at the indicated location."
            else:
                finding.remediation = "Review and fix the code at the indicated location. Follow security best practices for the identified vulnerability type."

        return finding

    @staticmethod
    def _clean_code_block(text: str) -> str:
        """Strip nested markdown backticks and LLM commentary from code blocks."""
        if not text:
            return ""
        # Remove nested ```language ... ``` wrappers that LLM adds
        cleaned = re.sub(r'```\w*\s*\n?', '', text)
        # Remove trailing ``` closers
        cleaned = cleaned.rstrip('`').strip()
        
        # Phase 1: Remove known LLM commentary patterns
        commentary_patterns = [
            r'^Most automated findings.*$',
            r'^The main security concern.*$',
            r'^Overall[,.].*$',
            r'^The codebase (?:contains|demonstrates|shows|exhibits|generally).*$',
            r'^Some parameters.*$',
            r'^Minor issues.*$',
            r'^The code (?:appears|relies|does not|constructs|processes).*$',
            r'^The most critical (?:issue|issues|vulnerability).*$',
            r'^Additional concerns.*$',
            r'^The JWT-based.*$',
            r'^External API calls.*$',
            r'^Sanitize all.*$',
            r'^The primary concern.*$',
            r'^MEDIUM[,.].*$',
            r'^Always sanitize.*$',
            r'^Prefer server-generated.*$',
            r'^Use cryptographic.*$',
            r'^Avoid concatenating.*$',
            r'^While the code performs.*$',
            r'^Stripe API calls.*$',
            r'^Twilio SMS.*$',
            r'^This (?:OTP|vulnerability|issue|finding).*$',
            r'^These issues.*$',
            r'^Implement strict.*$',
            r'^Potential directory traversal.*$',
            r'^Insufficient validation.*$',
            r'^Lack of strict.*$',
            r'^Missing rate limiting.*$',
            r'^Embedding user data.*$',
            r'^Admin routes lack.*$',
            r'^Some endpoints.*$',
            r'^URL parameters.*$',
            r'^Sensitive data embedded.*$',
        ]
        
        # Phase 2: Prose detection — remove lines that are clearly English prose, not code
        # Code lines typically have: =, {, }, (, ), ;, //, /*, #, :, ->, =>, import, const, var, let, def, class, function, if, for, return, etc.
        code_indicators = re.compile(
            r'[{};=<>!&|]|^\s*(?:import|from|const|var|let|def|class|function|if|else|for|while|return|export|try|catch|throw|async|await|new|typeof|instanceof|switch|case|break|continue|do|in|of|//|/\*|\*|#|@|->|=>|\$\{|npm |pip )\b',
            re.IGNORECASE
        )
        
        lines = cleaned.split('\n')
        filtered = []
        for line in lines:
            stripped = line.strip()
            # Skip markdown horizontal rules in code
            if stripped in ('---', '***', '___', ''):
                continue
            
            # Phase 1: Known pattern removal
            is_commentary = False
            for pattern in commentary_patterns:
                if re.match(pattern, stripped, re.IGNORECASE):
                    is_commentary = True
                    break
            if is_commentary:
                continue
            
            # Phase 2: Prose detection heuristic
            # If line has NO code indicators and reads like a sentence (>40 chars, starts with capital, has spaces)
            if len(stripped) > 40 and not code_indicators.search(stripped):
                # Count words — prose has many words
                words = stripped.split()
                if len(words) >= 6:
                    # Looks like prose, not code — skip it
                    continue
            
            filtered.append(line)
        
        # Remove trailing empty lines
        while filtered and not filtered[-1].strip():
            filtered.pop()
        return '\n'.join(filtered).strip()

    def _detect_language(self) -> str:
        """Auto-detect code language from tech stack."""
        raw = self.result.tech_stack or ""
        tech = (", ".join(raw) if isinstance(raw, list) else str(raw)).lower()
        if any(t in tech for t in ['typescript', 'tsx', 'react']):
            return 'typescript'
        elif any(t in tech for t in ['javascript', 'node', 'express']):
            return 'javascript'
        elif 'python' in tech or 'django' in tech:
            return 'python'
        elif 'java' in tech:
            return 'java'
        elif 'go' in tech:
            return 'go'
        elif 'php' in tech:
            return 'php'
        return ''

    def _format_finding(self, finding: Finding, index: int) -> str:
        """Format a single finding with COMPLETE details."""
        # Enrich the finding first
        finding = self._enrich_finding(finding)

        rel_path = self._get_relative_path(finding.file_path)
        lang = self._detect_language()
        lines = []

        # Header
        lines.append(f"### {finding.severity.emoji} {index}. {finding.title}")
        lines.append("")

        # Tags
        tags = []
        if finding.cwe_id:
            tags.append(f"`{finding.cwe_id}`")
        if finding.owasp_category:
            tags.append(f"`{finding.owasp_category}`")
        if finding.confidence:
            tags.append(f"Confidence: `{finding.confidence:.0%}`")
        if tags:
            lines.append(f"**Tags**: {' | '.join(tags)}")
            lines.append("")

        # Description
        lines.append("**Description:**")
        lines.append(finding.description)
        lines.append("")

        # Vulnerable Code — ALWAYS show file + line
        lines.append("**Vulnerable Code:**")
        lines.append(f"- **File**: `{rel_path}`")
        if finding.line_number:
            line_info = f"Line {finding.line_number}"
            if finding.end_line and finding.end_line != finding.line_number:
                line_info += f" - {finding.end_line}"
            lines.append(f"- **Line**: {line_info}")
        lines.append("")

        # Code snippet — clean nested backticks from LLM output
        code_snippet = self._clean_code_block(finding.code_snippet or "")
        if code_snippet and code_snippet.strip() not in {"", "requires login", "No code", "N/A"}:
            lines.append(f"```{lang}")
            lines.append(code_snippet[:800])
            lines.append("```")
            lines.append("")

        # Why This Is Vulnerable — ALWAYS present, clean LLM commentary
        why_text = self._clean_code_block(finding.reasoning_chain or finding.description)
        lines.append("**Why This Is Vulnerable:**")
        lines.append(why_text or finding.description)
        lines.append("")

        # Solution / Remediation — ALWAYS present
        solution_text = self._clean_code_block(finding.remediation or "")
        lines.append("**Solution / Remediation:**")
        lines.append(solution_text or "Review the code and apply security best practices for this vulnerability type.")
        lines.append("")

        # Solution code — clean nested backticks, use correct language
        remedy_code = self._clean_code_block(finding.remediation_code or "")
        if remedy_code:
            lines.append(f"```{lang}")
            lines.append(remedy_code[:800])
            lines.append("```")
            lines.append("")

        # References
        if finding.references and any(r for r in finding.references if r):
            lines.append("**References:**")
            for ref in finding.references:
                if ref:
                    lines.append(f"- {ref}")
            lines.append("")

        lines.append("---")
        lines.append("")
        return "\n".join(lines)

    def to_markdown(self) -> Path:
        """Generate a clean Markdown report, ordered by severity, with COMPLETE details."""
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        report_file = REPORTS_DIR / f"security_report_{timestamp}.md"

        confirmed = self._deduplicate(self.result.get_confirmed())
        false_positives = [f for f in self.result.findings if f.is_false_positive]
        scan_duration = self.result.scan_end - self.result.scan_start if self.result.scan_end else 0

        md = []

        # Header
        md.append("# 🛡️ Security Vulnerability Report")
        md.append("")
        md.append(f"**Target**: `{self.result.target_path}`  ")
        md.append(f"**Date**: {time.strftime('%Y-%m-%d %H:%M:%S')}  ")
        md.append(f"**Scan Duration**: {scan_duration:.1f}s  ")
        md.append(f"**Files Scanned**: {self.result.files_scanned}  ")
        md.append(f"**Lines of Code**: {self.result.total_lines}  ")
        md.append(f"**Tech Stack**: {', '.join(self.result.tech_stack)}  ")
        md.append(f"**Risk Score**: {self.result.risk_score:.1f}/10")
        md.append("")

        # Summary Table
        md.append("## 📊 Summary")
        md.append("")
        md.append("| Severity | Count |")
        md.append("|----------|-------|")
        counts = {}
        for sev in Severity:
            c = len([f for f in confirmed if f.severity == sev])
            counts[sev] = c
            if c > 0:
                md.append(f"| {sev.emoji} **{sev.value}** | {c} |")
        md.append(f"| **Total Unique** | **{len(confirmed)}** |")
        if false_positives:
            md.append(f"| False Positives Filtered | {len(false_positives)} |")
        md.append("")

        # Executive Summary
        md.append("## 📋 Executive Summary")
        md.append("")
        if confirmed:
            critical_count = counts.get(Severity.CRITICAL, 0)
            high_count = counts.get(Severity.HIGH, 0)
            medium_count = counts.get(Severity.MEDIUM, 0)
            total = len(confirmed)

            # Generate risk assessment
            if critical_count > 0:
                risk_level = "**HIGH RISK** — Critical vulnerabilities require immediate attention before deployment."
            elif high_count > 0:
                risk_level = "**MODERATE RISK** — High severity findings should be addressed before production deployment."
            elif medium_count > 0:
                risk_level = "**LOW-MODERATE RISK** — Medium severity findings should be reviewed and planned for remediation."
            else:
                risk_level = "**LOW RISK** — Only low/informational findings detected."

            md.append(f"This scan identified **{total} confirmed vulnerabilities** "
                      f"({critical_count} critical, {high_count} high, {medium_count} medium). "
                      f"Risk assessment: {risk_level}")
            md.append("")

            # Highlight top critical issues
            critical_findings = [f for f in confirmed if f.severity == Severity.CRITICAL]
            high_findings = [f for f in confirmed if f.severity == Severity.HIGH]
            top_issues = critical_findings + high_findings
            if top_issues:
                md.append("**Priority fixes:**")
                for i, f in enumerate(top_issues[:5], 1):
                    md.append(f"{i}. {f.severity.emoji} **{f.title}** — `{self._get_relative_path(f.file_path)}`")
                md.append("")
        else:
            md.append("No confirmed vulnerabilities were detected in this scan. "
                      "The application appears to follow security best practices.")
            md.append("")

        # Findings by severity
        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        severity_headers = {
            Severity.CRITICAL: "## 🔴 Critical Severity Findings",
            Severity.HIGH: "## 🟠 High Severity Findings",
            Severity.MEDIUM: "## 🟡 Medium Severity Findings",
            Severity.LOW: "## 🔵 Low Severity Findings",
            Severity.INFO: "## ⚪ Informational Findings",
        }

        global_index = 1
        for severity in severity_order:
            severity_findings = [f for f in confirmed if f.severity == severity]
            if not severity_findings:
                continue

            md.append(severity_headers[severity])
            md.append("")

            for finding in severity_findings:
                md.append(self._format_finding(finding, global_index))
                global_index += 1

        if not confirmed:
            md.append("## ✅ No Vulnerabilities Found")
            md.append("")
            md.append("No confirmed vulnerabilities were detected in this scan.")
            md.append("")

        md.append("---")
        md.append(f"*Generated by Security Analysis Agent v2.0 • {time.strftime('%Y-%m-%d %H:%M:%S')}*")
        md.append("")

        with open(report_file, 'w', encoding='utf-8') as f:
            f.write("\n".join(md))

        return report_file

    def to_sarif(self) -> Path:
        """Generate SARIF 2.1.0 JSON report for CI/CD integration."""
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        report_file = REPORTS_DIR / f"security_report_{timestamp}.sarif.json"

        confirmed = self._deduplicate(self.result.get_confirmed())

        rules = []
        results = []
        rule_ids_seen = set()

        for f in confirmed:
            rule_id = f.cwe_id or f.finding_id
            if rule_id not in rule_ids_seen:
                rule_ids_seen.add(rule_id)
                rules.append({
                    "id": rule_id,
                    "shortDescription": {"text": f.title},
                    "fullDescription": {"text": f.description[:500]},
                    "defaultConfiguration": {
                        "level": {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}.get(f.severity.value, "warning")
                    },
                    "properties": {"security-severity": str(f.severity.score)}
                })

            results.append({
                "ruleId": rule_id,
                "message": {"text": f.description},
                "level": {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}.get(f.severity.value, "warning"),
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": self._get_relative_path(f.file_path)}, "region": {"startLine": max(f.line_number, 1), "endLine": max(f.end_line or f.line_number, 1)}}}],
                "properties": {"confidence": f.confidence, "source": f.source.value}
            })

        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "Security Analysis Agent", "version": "2.0.0", "rules": rules}}, "results": results}]
        }

        with open(report_file, 'w', encoding='utf-8') as file:
            json.dump(sarif, file, indent=2)

        return report_file

    def to_json(self) -> Path:
        """Generate structured JSON report with COMPLETE details for every finding."""
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        report_file = REPORTS_DIR / f"security_report_{timestamp}.json"

        confirmed = self._deduplicate(self.result.get_confirmed())
        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

        grouped = {}
        for sev_name in severity_order:
            sev_findings = [f for f in confirmed if f.severity.value == sev_name]
            if sev_findings:
                grouped[sev_name] = []
                for f in sev_findings:
                    f = self._enrich_finding(f)
                    snippet = f.code_snippet
                    if snippet and snippet.strip() in {"", "requires login", "No code", "N/A"}:
                        snippet = ""
                    grouped[sev_name].append({
                        "title": f.title,
                        "description": f.description,
                        "vulnerable_code": {
                            "file": self._get_relative_path(f.file_path),
                            "line": f.line_number,
                            "end_line": f.end_line or f.line_number,
                            "snippet": snippet,
                        },
                        "why_vulnerable": f.reasoning_chain or f.description,
                        "solution": {
                            "description": f.remediation,
                            "fixed_code": f.remediation_code,
                        },
                        "metadata": {
                            "cwe": f.cwe_id,
                            "owasp": f.owasp_category,
                            "confidence": f.confidence,
                            "source": f.source.value,
                            "references": [r for r in f.references if r],
                        }
                    })

        report = {
            "report_info": {
                "target": self.result.target_path,
                "date": time.strftime('%Y-%m-%d %H:%M:%S'),
                "files_scanned": self.result.files_scanned,
                "lines_of_code": self.result.total_lines,
                "tech_stack": self.result.tech_stack,
                "risk_score": round(self.result.risk_score, 1),
            },
            "summary": {s.value: len([f for f in confirmed if f.severity == s]) for s in Severity},
            "total_confirmed": len(confirmed),
            "false_positives_filtered": len([f for f in self.result.findings if f.is_false_positive]),
            "findings": grouped,
        }

        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        return report_file
