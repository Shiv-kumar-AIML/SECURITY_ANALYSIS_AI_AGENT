---
name: sast-web-misconfig-engine
description: Web Application Security Misconfiguration — methodology-based analysis
version: 5.0.0
---

# Web Application Security Misconfiguration Engine

## Your Mission
Find **security misconfigurations** in the web application setup — these are configuration-level issues that aren't about the logic of a single function but about how the entire application is configured and deployed.

## Step-by-Step Analysis

### Step 1: Analyze the Server/Application Entry Point
Read the main server file (app entry, server setup) and check:

**Cross-Origin Resource Sharing (CORS):**
- How is CORS configured? What origins are allowed?
- Is access overly permissive (any origin can interact with the API)?
- Are credentials allowed with permissive origins (especially dangerous)?

**Rate Limiting:**
- Are there any rate limiting mechanisms in place?
- Are authentication endpoints (login, register, forgot-password, OTP) protected against brute-force attacks?
- What rate limit thresholds are set? Are they reasonable?
- **Is there rate limiting on OTP verification?** (6-digit OTP = only 1M combinations, brute-forceable)

**Security Headers:**
- Are security header middleware (like helmet) configured?
- Are headers like Content-Security-Policy, X-Frame-Options, HSTS configured?
- **If NO security headers are configured at all, report as MEDIUM**

**Body/Upload Limits:**
- Are request body size limits set? Are they reasonable?
- Is there file upload size and type validation?

### Step 2: Check Static File and Upload Handling
- Are user-uploaded files served directly without authentication?
- Can an attacker access other users' uploaded files by guessing/enumerating filenames?
- Are uploaded files validated for type and scanned for malware?
- Are files served from the same origin (XSS risk if executable)?
- **Does the upload endpoint check MIME type AND file extension?**
- **Does the upload endpoint require authentication?**

### Step 3: Check API Response Content — CRITICAL
- Do any API responses expose sensitive information that should be private?
- Are password reset tokens/links returned in API responses instead of being sent via secure channels (email)?
- **Do error responses include `error.stack`, `traceback`, or internal file paths?** (CRITICAL)
- **Search for patterns like:** `{ error: error.message, stack: error.stack }` — this leaks internal code structure
- Are responses including more fields than necessary (password hashes, internal IDs)?

### Step 4: Check Transport Security and Cookie Flags
- Is HTTPS enforced in production?
- Are there any HTTP-only endpoints in production?
- **Are authentication cookies (accessToken, refreshToken, sessionId) set with ALL of these flags:**
  - `httpOnly: true` — prevents JavaScript access (XSS token theft protection)
  - `secure: true` — only sent over HTTPS
  - `sameSite: 'strict'` or `'lax'` — CSRF protection
- **If ANY auth cookie is missing ANY of these flags, report as MEDIUM**
- Is HSTS (Strict-Transport-Security) configured?

### Step 5: Check Logging and Debug Configuration
- Is debug mode or verbose logging active in production config?
- Are sensitive values (passwords, tokens, secrets) being logged?
- Are there console.log or print statements that output sensitive data?

### Step 6: Check for Hardcoded Infrastructure
- Are TLS certificate paths hardcoded in the server file?
- Are domain names or internal IPs hardcoded in configuration?
- Are database connection strings hardcoded instead of reading from env?

### Step 7: Assess Each Finding
For each misconfiguration found:
- What is the realistic attack scenario?
- What is the actual impact if exploited?
- Is it environment-dependent (dev vs production)?

## Key Principle
**Security misconfigurations are about what is MISSING or PERMISSIVE, not about code logic bugs.** Look for what SHOULD be there but ISN'T (rate limiting, security headers, cookie flags, auth on uploads) and what is TOO OPEN (CORS, body limits, static file access, stack traces in responses).

## What NOT to Report
- Development-only configurations clearly gated behind environment checks
- Intentionally public endpoints with permissive CORS (public APIs)
- Security headers when a reverse proxy (Nginx, Cloudflare) is handling them

## Output Format
Report EACH misconfiguration as a SEPARATE finding:
```
VULNERABILITY:
- Title: [Specific Misconfiguration Name]
- Severity: [CRITICAL/HIGH/MEDIUM/LOW]
- CWE: [CWE-xxx]
- OWASP: A05:2021 Security Misconfiguration
- File: [file path where the configuration exists or should exist]
- Line: [line number if applicable]
- Description: [what the misconfiguration is and its security impact]
- Code Evidence: [the actual configuration code or the absence that indicates the issue]
- Remediation: [exact fix — what to add, change, or configure]
- Fixed Code: [corrected configuration]
```

## Example (for reference only)
A server that allows any origin to make cross-origin requests by defaulting to wildcard when no CORS origin is configured is vulnerable to cross-site attacks where malicious websites can interact with the API on behalf of logged-in users. The fix is to explicitly whitelist allowed origins.

