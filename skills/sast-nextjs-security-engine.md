---
name: sast-nextjs-security-engine
description: Next.js Framework Security Analysis — API routes, middleware, and SSR audit
version: 1.0.0
---

# Next.js Security Engine

## Your Mission
Perform a comprehensive Next.js-specific security audit. Next.js has unique patterns around API routes, middleware, server actions, and SSR that create specific security risks.

## Step-by-Step Analysis

### Step 1: Check API Route Authentication
- API routes in `app/api/` without auth checks → **HIGH** for state-changing routes
- **CRITICAL**: Check if middleware.ts ONLY protects page routes, not /api/ routes
- Each POST/PUT/PATCH/DELETE API route should verify the session/JWT before operations

### Step 2: Check Security Headers
Look in `next.config.js` or `next.config.ts`:
- No `headers()` configuration → **MEDIUM** (missing security headers)
- Should have: X-Frame-Options, X-Content-Type-Options, Referrer-Policy, CSP, HSTS

### Step 3: Check Environment Variable Exposure
- `NEXT_PUBLIC_*` env vars are exposed to the browser
- `NEXT_PUBLIC_API_KEY = 'sk-...'` → **CRITICAL** (secret exposed to client)
- `NEXT_PUBLIC_DATABASE_URL` → **CRITICAL**
- Only non-sensitive values should use NEXT_PUBLIC_ prefix

### Step 4: Check for XSS via dangerouslySetInnerHTML
- `dangerouslySetInnerHTML={{ __html: userInput }}` → **HIGH**
- `dangerouslySetInnerHTML={{ __html: sanitize(input) }}` → check sanitizer quality
- React auto-escapes JSX by default — only flag dangerouslySetInnerHTML

### Step 5: Check Server Actions Security
- Server actions without auth checks → **HIGH**
- `"use server"` functions that modify data without validating user identity
- Missing input validation in server actions → **MEDIUM**

### Step 6: Check Middleware Coverage
- `matcher` in middleware.ts — does it cover all sensitive routes?
- `/api/*` routes excluded from auth middleware → **HIGH**
- Static file paths (`_next/static`) correctly excluded → **SAFE**

### Step 7: Check Cookie Security
- Cookies set without `httpOnly`, `secure`, `sameSite` → **MEDIUM**
- JWT stored in localStorage → **HIGH** (accessible via XSS)
- Cookies in `cookies().set()` without security flags → **MEDIUM**

### Step 8: Check Redirect Security
- `redirect(req.query.next)` → **HIGH** (open redirect)
- `redirect(url)` without validating url is on same domain → **HIGH**

### Step 9: Check Image/File Handling
- `next.config.js` `images.remotePatterns` too broad → **LOW**
- File upload API without type/size validation → **MEDIUM**

### Step 10: Check Secret Management
- Hardcoded secrets in `next.config.js` → **CRITICAL**
- `.env.local` patterns committed to git → **CRITICAL**
- Server-side env vars (without NEXT_PUBLIC_) → **SAFE**

## What NOT to Report
- React JSX expressions — auto-escaped by default
- Next.js Image component — handles optimization safely
- Server Components — run server-side only
- TypeScript type checking — improves safety

## Output Format
```
VULNERABILITY:
- Title: [Next.js-specific title]
- Severity: [CRITICAL/HIGH/MEDIUM/LOW]
- CWE: [CWE-xxx]
- OWASP: [relevant category]
- File: [file path]
- Line: [line number]
- Description: [what's wrong]
- Code Evidence: [the vulnerable code/config]
- Remediation: [exact fix]
- Fixed Code: [corrected code]
```
