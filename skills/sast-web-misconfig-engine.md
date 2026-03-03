---
name: sast-web-misconfig-engine
description: Web Application Security Misconfiguration — methodology-based analysis
version: 4.0.0
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

**Security Headers:**
- Are security header middleware (like helmet) configured?
- Are headers like Content-Security-Policy, X-Frame-Options, HSTS configured?

**Body/Upload Limits:**
- Are request body size limits set? Are they reasonable?
- Is there file upload size and type validation?

### Step 2: Check Static File and Upload Handling
- Are user-uploaded files served directly without authentication?
- Can an attacker access other users' uploaded files by guessing/enumerating filenames?
- Are uploaded files validated for type and scanned for malware?
- Are files served from the same origin (XSS risk if executable)?

### Step 3: Check API Response Content
- Do any API responses expose sensitive information that should be private?
- Are password reset tokens/links returned in API responses instead of being sent via secure channels (email)?
- Do error responses reveal internal details (stack traces, SQL queries, file paths)?
- Are responses including more fields than necessary (password hashes, internal IDs)?

### Step 4: Check Transport Security
- Is HTTPS enforced in production?
- Are there any HTTP-only endpoints in production?
- Are cookies set with Secure flag?

### Step 5: Check Logging and Debug Configuration
- Is debug mode or verbose logging active in production config?
- Are sensitive values (passwords, tokens, secrets) being logged?

### Step 6: Assess Each Finding
For each misconfiguration found:
- What is the realistic attack scenario?
- What is the actual impact if exploited?
- Is it environment-dependent (dev vs production)?

## Key Principle
**Security misconfigurations are about what is MISSING or PERMISSIVE, not about code logic bugs.** Look for what SHOULD be there but ISN'T (rate limiting, security headers, auth on uploads) and what is TOO OPEN (CORS, body limits, static file access).

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
