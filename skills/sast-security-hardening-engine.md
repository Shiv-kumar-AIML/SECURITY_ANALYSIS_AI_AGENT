---
name: sast-security-hardening-engine
description: Security Hardening & Missing Controls Detection — methodology-based analysis
version: 1.0.0
---

# Security Hardening & Missing Controls Engine

## Your Mission
Find **missing security controls** — these are NOT code logic bugs but security best practices that are ABSENT from the application. Missing controls leave the application vulnerable even if the code logic is correct.

## Step-by-Step Analysis

### Step 1: Check Security Headers Configuration
Examine the server config, framework config, and middleware setup:

**Required Headers (check if present):**
- `Content-Security-Policy` — prevents XSS and data injection
- `Strict-Transport-Security` (HSTS) — enforces HTTPS
- `X-Frame-Options` or CSP frame-ancestors — prevents clickjacking
- `X-Content-Type-Options: nosniff` — prevents MIME sniffing
- `Referrer-Policy` — controls referrer information
- `Permissions-Policy` — restricts browser features

**Where to check:**
- Next.js: `next.config.js/ts` → headers configuration
- Express: helmet middleware or custom headers middleware
- Django: SecurityMiddleware, SECURE_HSTS_SECONDS settings
- Server files (nginx.conf, server.js)

Report as MEDIUM if no security headers are configured at all.

### Step 2: Check Cookie Security Flags
For every place cookies are set (auth tokens, session cookies):

```
// VULNERABLE — missing security flags:
res.cookies.set('accessToken', token, { path: '/' })

// SECURE — all flags set:
res.cookies.set('accessToken', token, {
  path: '/',
  httpOnly: true,    // prevents JS access (XSS protection)
  secure: true,      // HTTPS only
  sameSite: 'strict' // CSRF protection
})
```

Check ALL cookie-setting code including login, token refresh, and logout handlers.

### Step 3: Check Error Response Content
Search for error handlers/catch blocks and examine what they return:

**VULNERABLE patterns:**
```
// Returns stack trace to client — information leakage
catch (error) {
  return Response({ error: error.message, stack: error.stack })
}

// Returns internal error details
return { error: message, detail: error.toString() }
```

**SAFE pattern:**
```
// Generic error to client, detailed log server-side
catch (error) {
  console.error('Internal error:', error)
  return Response({ error: 'Internal server error' })
}
```

### Step 4: Check Password Policy
Find password validation code (signup, change-password, reset-password):

**Weak policy (VULNERABLE):**
```
if (password.length < 8) return 'Password too short'
```

**Strong policy (SAFE):**
```
// Checks: minimum length, uppercase, lowercase, number, special char
// Optionally: checks against breached password database
```

Report as MEDIUM if only length is checked without complexity requirements.

### Step 5: Check User Enumeration
Compare error responses for different auth failure cases:

**VULNERABLE — reveals whether user exists:**
```
if (!user) return { message: 'User not found', status: 404 }
if (!validPassword) return { message: 'Invalid password', status: 401 }
```

**SAFE — same response regardless:**
```
return { message: 'Invalid credentials', status: 401 }
```

Check login, forgot-password, and registration endpoints.

### Step 6: Check Insecure Randomness
Find all uses of random number generation for security purposes:

**VULNERABLE:**
```
Math.random()                    // Predictable
Math.random().toString(36)       // Predictable IDs
Math.floor(Math.random() * 999)  // Predictable OTP
```

**SAFE:**
```
crypto.randomBytes(32)           // Cryptographically secure
crypto.randomUUID()              // Secure UUID
require('uuid').v4()             // Secure UUID
```

### Step 7: Check File Upload Security
For each upload endpoint, verify:
1. **Authentication** — is the uploader authenticated?
2. **File type validation** — is MIME type AND extension checked?
3. **File size limit** — is there a reasonable max size?
4. **Filename sanitization** — are special chars and path traversal sequences removed?
5. **Storage isolation** — are uploads stored outside the web root or on a separate domain?

### Step 8: Check for Hardcoded Infrastructure
Look for:
- Hardcoded TLS certificate file paths
- Hardcoded domain names in server config
- Hardcoded internal IP addresses
- Database connection strings in code (not from env)

## Key Principle
**Security hardening issues are about what SHOULD be there but ISN'T. Even if no dataflow vulnerability exists, a missing security control (like HSTS or cookie flags) can enable entire classes of attacks.**

## What NOT to Report
- Headers handled by a reverse proxy (clearly documented nginx/cloudflare setup)
- Development-only servers with explicit environment gates
- Cookies for non-sensitive purposes (analytics, preferences)

## Output Format
```
VULNERABILITY:
- Title: Missing Security Control — [specific control]
- Severity: [CRITICAL/HIGH/MEDIUM/LOW]
- CWE: [CWE-xxx]
- OWASP: [OWASP category]
- File: [file path where control should exist]
- Line: [line number if applicable]
- Description: [what control is missing and its security impact]
- Dataflow: MISSING CONTROL: [describe what should be present but isn't]
- Code Evidence: [the code that shows the missing control]
- Exploit Scenario: [how an attacker exploits the gap]
- Remediation: [exact fix]
- Fixed Code: [corrected version with the control added]
```
