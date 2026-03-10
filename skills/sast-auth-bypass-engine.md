---
name: sast-auth-bypass-engine
description: Authentication Bypass & Dev Backdoor Detection — methodology-based analysis
version: 1.0.0
---

# Authentication Bypass & Dev Backdoor Detection Engine

## Your Mission
Find **authentication bypass vulnerabilities** — hardcoded fallback credentials, dev backdoors left in production code, environment-gated bypasses that could leak, and endpoints that skip authentication entirely.

## Step-by-Step Analysis

### Step 1: Find Hardcoded Authentication Fallbacks
Search the ENTIRE codebase for patterns where authentication can be bypassed via hardcoded values:

**OTP/Code Fallbacks:**
- Any hardcoded OTP like `'111111'`, `'123456'`, `'000000'`
- Fallback codes assigned before real generation: `let code = '111111'`
- Dev-mode bypass: `if (otp === 'test-otp' && process.env.NODE_ENV === 'development')`
- Conditions using `!process.env.SOME_VAR` that fall through to a hardcoded value

**Token/Password Fallbacks:**
- Hardcoded test tokens: `if (token === 'dev-token')`, `if (apiKey === 'test-key')`
- Master passwords in code: `if (password === 'admin123')`
- Fallback authentication: `if (!authProviderAvailable) { grant_access() }`

**Why these are CRITICAL:** If the environment variable is not set in production (common misconfiguration), the hardcoded bypass becomes active for ALL users.

### Step 2: Check Environment-Gated Bypasses
Look for auth bypasses gated behind environment checks that COULD leak to production:

```
// DANGEROUS: If TWILIO_ACCOUNT_SID is not set, bypass is active
const isDevFallback = code === '111111' && (!process.env.TWILIO_ACCOUNT_SID || process.env.NODE_ENV === 'development')

// DANGEROUS: Missing env var = bypass
if (!apiKey) { return defaultAuth() }
```

For each such bypass, ask:
- What happens if the environment variable is NOT set in production?
- Does it fail OPEN (grants access) or fail CLOSED (denies access)?
- Failing open = CRITICAL vulnerability

### Step 3: Find Unauthenticated Sensitive Endpoints
Go through EVERY API route/endpoint handler and check:
- Does it have ANY form of authentication check? (middleware, token verification, session check)
- If it's in an `admin/`, `management/`, `internal/` path — is it protected?
- Does it perform privileged operations (CRUD on other users, approve/reject, financial operations)?

**An admin endpoint with no auth check is ALWAYS CRITICAL.**

### Step 4: Check OTP/Token Security
- Is the OTP long enough (6+ digits)?
- Is it generated with cryptographically secure randomness? (`crypto.randomBytes`, NOT `Math.random`)
- Are there attempt limits on verification? (brute-force protection)
- Are used OTPs properly invalidated?
- What is the OTP expiry time? (should be ≤ 10 minutes)

### Step 5: Check for Missing Brute-Force Protection
For each authentication endpoint:
- **Login**: Is there rate limiting? Account lockout after N failures?
- **OTP Verification**: Can an attacker try unlimited OTP codes?
- **Password Reset**: Can an attacker spam reset requests?
- **API Key Validation**: Is there rate limiting on key verification?

## Key Principle
**ANY way to authenticate without presenting valid credentials is an authentication bypass. Even if it's "only for dev mode" — if the condition can be true in production, it's exploitable.**

## What NOT to Report
- Test files with mock authentication
- Clearly labeled example/demo code
- Auth bypass in development-only servers that are never deployed to production
- Feature flags with proper secure defaults

## Output Format
```
VULNERABILITY:
- Title: Authentication Bypass — [specific issue]
- Severity: [CRITICAL/HIGH/MEDIUM/LOW]
- CWE: [CWE-287/798/307/306 as applicable]
- OWASP: A07:2021 Identification and Authentication Failures
- File: [file path]
- Line: [line number]
- Description: [explanation of how auth can be bypassed]
- Dataflow: SOURCE: [hardcoded value or missing check] → FLOW: [how bypass occurs] → SINK: [unauthorized access granted]
- Code Evidence: [the vulnerable code]
- Exploit Scenario: [concrete attack steps]
- Remediation: [how to fix]
- Fixed Code: [corrected version]
```
