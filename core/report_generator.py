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
        "solution": "Always escape user input before rendering in HTML. Use framework-provided template engines (Django templates auto-escape by default). Avoid mark_safe(), HttpResponse with user data, and direct DOM manipulation.",
        "code": """# VULNERABLE:
return HttpResponse(user_input)
return mark_safe(user_data)

# FIXED (use template engine):
return render(request, 'template.html', {'data': user_data})

# FIXED (manual escape):
from django.utils.html import escape
return HttpResponse(escape(user_input))

# FIXED (use format_html instead of mark_safe):
from django.utils.html import format_html
return format_html('<p>{}</p>', user_data)"""
    },
    "open_redirect": {
        "why": "The application redirects users to a URL provided in the request (e.g., a 'next' parameter) without validating it. An attacker can craft a URL that redirects users to a malicious site for phishing.",
        "solution": "Validate redirect URLs using Django's url_has_allowed_host_and_scheme() (or is_safe_url in older versions). Only allow redirects to your own domain.",
        "code": """# VULNERABLE:
next_url = request.GET.get('next')
return redirect(next_url)

# FIXED:
from django.utils.http import url_has_allowed_host_and_scheme

next_url = request.GET.get('next', '/')
if url_has_allowed_host_and_scheme(next_url, allowed_hosts={request.get_host()}):
    return redirect(next_url)
else:
    return redirect('/')"""
    },
    "csrf": {
        "why": "The @csrf_exempt decorator disables Django's CSRF protection for this view. An attacker can trick authenticated users into submitting malicious requests without their knowledge.",
        "solution": "Remove @csrf_exempt and use Django's built-in CSRF protection. For AJAX requests, include the CSRF token in the request header.",
        "code": """# VULNERABLE:
@csrf_exempt
def payment_view(request):
    # processes payment without CSRF protection
    pass

# FIXED (remove csrf_exempt, use CSRF token):
def payment_view(request):
    # Django CSRF middleware automatically validates
    pass

# For AJAX, include CSRF token in JavaScript:
# headers: {'X-CSRFToken': getCookie('csrftoken')}"""
    },
    "hardcoded_secret": {
        "why": "Sensitive credentials (API keys, passwords, tokens) are hardcoded in the source code. Anyone with access to the repository can extract and misuse them. If the repo is public, the secrets are fully exposed.",
        "solution": "Move all secrets to environment variables or a secrets manager (AWS Secrets Manager, HashiCorp Vault, .env files excluded from git).",
        "code": """# VULNERABLE:
API_KEY = "sk-1234567890abcdef"
DB_PASSWORD = "super_secret_password"

# FIXED (use environment variables):
import os
API_KEY = os.environ.get('API_KEY')
DB_PASSWORD = os.environ.get('DB_PASSWORD')

# FIXED (use python-decouple):
from decouple import config
API_KEY = config('API_KEY')"""
    },
    "unvalidated_password": {
        "why": "Passwords are being set on user objects without running Django's password validators. This allows users to set weak passwords (e.g., '123', 'password'), making accounts vulnerable to brute-force attacks.",
        "solution": "Always validate passwords using Django's built-in password validation before setting them. Use validate_password() or Django forms with password validation.",
        "code": """# VULNERABLE:
user.set_password(raw_password)
user.save()

# FIXED:
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError

try:
    validate_password(raw_password, user)
    user.set_password(raw_password)
    user.save()
except ValidationError as e:
    # Handle invalid password — return errors to user
    return {'errors': e.messages}"""
    },
    "eval_usage": {
        "why": "eval() executes arbitrary Python code from a string. If any part of that string comes from user input, an attacker can execute arbitrary code on the server, leading to full system compromise.",
        "solution": "Remove eval() entirely. Use json.loads() for JSON parsing, ast.literal_eval() for safe literal evaluation, or implement proper parsers for structured input.",
        "code": """# VULNERABLE:
result = eval(user_expression)

# FIXED (for JSON):
import json
result = json.loads(user_data)

# FIXED (for safe literals like dicts/lists):
import ast
result = ast.literal_eval(user_data)

# FIXED (for math expressions):
# Use a safe expression parser library instead"""
    },
    "vulnerable_dependency": {
        "why": "The project uses third-party packages with known security vulnerabilities (CVEs). Attackers can exploit these vulnerabilities if the affected package functionality is reachable from user input.",
        "solution": "Upgrade the vulnerable dependency to the patched version. Run dependency audits regularly. Pin dependencies to specific safe versions.",
        "code": """# In package.json — update the version:
# "lodash": "^4.17.21"  (was: "^4.17.10")

# Run: npm audit fix
# Or: npm update <package-name>

# In requirements.txt:
# package>=safe_version

# Run: pip install --upgrade <package-name>"""
    },
    "mark_safe": {
        "why": "mark_safe() tells Django to NOT escape HTML content in templates. If the marked content contains any user-controlled data, it creates an XSS vulnerability where attackers can inject malicious scripts.",
        "solution": "Replace mark_safe() with format_html() which safely escapes parameters while keeping the HTML structure.",
        "code": """# VULNERABLE:
from django.utils.safestring import mark_safe
html = mark_safe(f'<a href="{url}">{user_text}</a>')

# FIXED:
from django.utils.html import format_html
html = format_html('<a href="{}">{}</a>', url, user_text)"""
    },
    "query_set_extra": {
        "why": "QuerySet.extra() allows raw SQL to be injected into Django ORM queries. If any user input reaches the extra() parameters, it can lead to SQL injection. Django documentation itself warns against using extra().",
        "solution": "Replace .extra() with Django ORM methods like .annotate(), .filter(), .values(), or use RawSQL with proper parameterization.",
        "code": """# VULNERABLE:
qs.extra(where=["name = '%s'" % user_input])

# FIXED (use ORM):
qs.filter(name=user_input)

# FIXED (if raw SQL needed, use params):
from django.db.models import Q
qs.filter(Q(name=user_input))"""
    },
    "http_response_direct": {
        "why": "Directly passing data to HttpResponse bypasses Django's template engine XSS protections. If the response content includes any user-supplied data, attackers can inject HTML/JavaScript.",
        "solution": "Use Django's render() with templates instead of HttpResponse with dynamic content. Templates auto-escape by default.",
        "code": """# VULNERABLE:
return HttpResponse(f"Hello {user_name}")

# FIXED (use template):
return render(request, 'greeting.html', {'name': user_name})

# FIXED (for JSON API responses):
from django.http import JsonResponse
return JsonResponse({'greeting': f'Hello {user_name}'})"""
    },
    "blocktranslate_no_escape": {
        "why": "Translated strings in {% blocktranslate %} tags are not escaped by default. If a translator adds malicious HTML/JavaScript in their translation, it will be rendered as-is in the template.",
        "solution": "Apply the force_escape filter to translated variables, or use the |escape filter on template variables inside blocktranslate.",
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
    matches = {
        "sql_injection": ["sql injection", "cwe-89", "query set extra", "query-set-extra", "extends custom expression"],
        "command_injection": ["command injection", "cwe-78", "os.system", "subprocess"],
        "xss": ["cross-site scripting", "xss", "cwe-79", "direct use of httpresponse", "http_response"],
        "open_redirect": ["open redirect", "cwe-601", "redirect"],
        "csrf": ["csrf", "cwe-352", "csrf_exempt", "no csrf"],
        "hardcoded_secret": ["secret", "hardcoded", "cwe-798", "api key", "password.*literal"],
        "unvalidated_password": ["unvalidated password", "cwe-521", "password validation"],
        "eval_usage": ["eval", "cwe-95", "eval()"],
        "vulnerable_dependency": ["cve-", "vulnerable", "cwe-1321", "prototype pollution", "dependency"],
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

    def _deduplicate(self, findings: list) -> list:
        """Remove duplicate findings using multiple matching strategies."""
        seen = {}
        unique = []

        for f in findings:
            rel_path = self._get_relative_path(f.file_path)

            # Extract CVE ID from title if present
            cve_match = re.search(r'(CVE-\d{4}-\d+)', f.title)
            cve_id = cve_match.group(1) if cve_match else None

            keys = set()
            keys.add(f"{f.title}|{rel_path}|{f.line_number}")
            if cve_id:
                keys.add(f"{cve_id}|{rel_path}")
            desc_prefix = f.description[:100].strip()
            keys.add(f"{f.title}|{rel_path}|{desc_prefix}")

            is_duplicate = False
            for key in keys:
                if key in seen:
                    existing = seen[key]
                    if (f.confidence > existing.confidence or
                            (f.remediation and not existing.remediation) or
                            (f.remediation_code and not existing.remediation_code)):
                        idx = unique.index(existing)
                        unique[idx] = f
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

    def _format_finding(self, finding: Finding, index: int) -> str:
        """Format a single finding with COMPLETE details."""
        # Enrich the finding first
        finding = self._enrich_finding(finding)

        rel_path = self._get_relative_path(finding.file_path)
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

        # Code snippet
        if finding.code_snippet and finding.code_snippet.strip() not in {"", "requires login", "No code", "N/A"}:
            lines.append("```")
            lines.append(finding.code_snippet.strip()[:800])
            lines.append("```")
            lines.append("")

        # Why This Is Vulnerable — ALWAYS present
        lines.append("**Why This Is Vulnerable:**")
        lines.append(finding.reasoning_chain or finding.description)
        lines.append("")

        # Solution / Remediation — ALWAYS present
        lines.append("**Solution / Remediation:**")
        lines.append(finding.remediation or "Review the code and apply security best practices for this vulnerability type.")
        lines.append("")

        if finding.remediation_code and finding.remediation_code.strip():
            lines.append("```python")
            lines.append(finding.remediation_code.strip()[:800])
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
