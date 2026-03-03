---
name: sast-jwt-oidc-engine
description: JWT & Session Security — methodology-based analysis
version: 4.0.0
---

# JWT & Session Security Engine

## Your Mission
Find authentication and session management vulnerabilities — weak token configuration, missing verification, insecure transmission, and session handling flaws.

## Step-by-Step Analysis

### Step 1: Find Token Creation & Configuration
Locate where tokens (JWT, session IDs, API keys) are created and configured:
- Where are tokens generated? What library/function is used?
- What algorithm is used for signing?
- What secret/key is used? Is it from a secure source (env var, secrets manager) or hardcoded?
- What is the token expiry time? Is it appropriate for the token's purpose?

### Step 2: Analyze Token Verification
Check how tokens are verified before trusting their contents:
- Is the token signature actually verified, or is it just decoded without verification?
- Is the algorithm explicitly specified during verification (to prevent algorithm confusion)?
- Is the token's expiry actually checked?
- Are the token claims validated (issuer, audience, etc.)?

### Step 3: Check Token Lifecycle Management
- **Revocation**: Can tokens be invalidated? Is there a blacklist, database check, or token versioning?
- **Refresh**: Are there separate access and refresh tokens? Are refresh tokens rotated?
- **Logout**: Does logout actually invalidate the token, or does it just delete it from client-side?
- **Expiry**: Are access tokens short-lived (minutes/hours)? Are refresh tokens properly managed?

### Step 4: Check Token Transmission Security
- Are tokens transmitted over secure channels (HTTPS)?
- Are cookies marked with `Secure`, `HttpOnly`, and `SameSite` flags?
- Are tokens ever placed in URLs (query parameters, path)?
- Are tokens logged or exposed in error messages?

### Step 5: Assess Configuration Values
- Is the token expiry appropriate? (Access tokens > 24h hours is a risk)
- Is there a fallback/default expiry that is too long?
- Is the signing secret strong enough? (Short or predictable secrets can be brute-forced)

## Key Principle
**Trust nothing about a token until it's cryptographically verified.** Check the full lifecycle: creation → transmission → verification → revocation.

## What NOT to Report
- JWT secrets properly stored in environment variables (this is correct practice)
- Short-lived tokens with proper verification
- Tokens in Authorization headers over HTTPS

## Output Format
```
VULNERABILITY:
- Title: JWT/Session Security — [specific issue]
- Severity: [CRITICAL/HIGH/MEDIUM/LOW]
- CWE: [CWE-287/327/613/598/319 as applicable]
- OWASP: A07:2021 Authentication Failures
- File: [file path]
- Line: [line number]
- Description: [explanation]
- Dataflow: SOURCE: [token config/creation] → FLOW: [how token is used] → SINK: [security impact]
- Code Evidence: [the vulnerable code]
- Remediation: [specific fix]
- Fixed Code: [corrected version]
```

## Example (for reference only)
An application that sets a default JWT expiry of 1 year (`'1y'`) for access tokens is vulnerable because if a token is leaked or stolen, the attacker has a full year to use it. The fix is to use short-lived access tokens (15-30 minutes) with a refresh token mechanism for longer sessions.
