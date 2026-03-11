---
name: sast-secret-detection-engine
description: Hardcoded Secret & Credential Detection — methodology-based analysis
version: 5.0.0
---

# Secret Detection Engine

## Your Mission
Find **hardcoded secrets, credentials, sensitive tokens, and authentication bypass values** embedded directly in source code. Distinguish between genuinely hardcoded secrets and properly externalized secret management.

## Step-by-Step Analysis

### Step 1: Find All Secret-Like Values
Scan for variables, constants, and configuration values that represent sensitive data:
- API keys, tokens, passwords, database credentials
- Cloud provider credentials, webhook URLs with tokens
- Encryption keys, signing secrets
- Connection strings with embedded credentials

### Step 2: Find Hardcoded Authentication Bypass Values
**This is equally important as finding secrets:**
- Hardcoded OTP fallback codes: `let otp = '111111'`, `fallbackCode = '123456'`
- Hardcoded test passwords: `if (password === 'admin')`, `masterPassword = 'test123'`
- Hardcoded dev tokens: `if (token === 'dev-bypass')`, `testApiKey = 'sk-test-xxx'`
- Any literal value that, if matched, grants authentication or authorization

**Why these matter:** Even if gated behind `process.env.NODE_ENV === 'development'` or `!process.env.SOME_VAR`, if the condition can be true in production (env var not set), the bypass is active.

### Step 2.5: Find Hardcoded DEFAULT VALUES in Environment Variable Reads
**THIS IS CRITICALLY IMPORTANT AND OFTEN MISSED:**

These patterns look "safe" because they use environment variables, but they have **hardcoded fallback defaults** that become the actual value if the env var is missing:

```python
# Python — VULNERABLE (has hardcoded fallback):
SECRET_KEY = os.environ.get('SECRET_KEY', 'my-weak-secret')
PASSWORD = os.environ.get('DB_PASSWORD', 'admin123')
PAYMENT_SECRET = os.environ.get('PAYMENT_SECRET', 'default_secret_123')

# Node.js — VULNERABLE (has hardcoded fallback):
const secret = process.env.JWT_SECRET || 'dev-secret-key'
const apiKey = process.env.API_KEY ?? 'default-key'
```

**Why this is dangerous:** If the environment variable is NOT set in production (misconfiguration, new deployment), the hardcoded fallback becomes the live value. Attackers who read the source code know the secret.

**SAFE patterns (no fallback or empty fallback):**
```python
SECRET_KEY = os.environ['SECRET_KEY']           # Crashes if missing — SAFE
SECRET_KEY = os.environ.get('SECRET_KEY')        # None if missing — SAFE
PASSWORD = os.environ.get('DB_PASSWORD', '')     # Empty fallback — SAFE
```

Report hardcoded defaults as **CRITICAL** for passwords/keys, **HIGH** for other config.

### Step 3: Check the Source of the Value
For each potential secret, ask: **Is the value hardcoded in the source code, or is it loaded from an external secure source?**

Hardcoded (VULNERABLE):
- Literal string assigned directly in code
- Configuration file committed to the repository with real values
- Fallback values that grant auth: `const code = process.env.OTP || '111111'`

Externalized (SAFE — do NOT report):
- Environment variables
- Secrets management services
- Config files that are in `.gitignore`
- Placeholder/example values in `.env.example` files

### Step 4: Evaluate Context
- Is this in a test file with intentionally fake credentials?
- Is this a hash value (bcrypt hash, SHA checksum) rather than a secret?
- Is this a placeholder like "your-key-here" or "changeme"?
- Is this an import of a secret from a config module (which itself reads from env)?

### Step 5: Assess Severity
- **CRITICAL**: Production credentials, cloud provider keys, database passwords, auth bypass values that could work in production
- **HIGH**: API keys with broad permissions, payment processing keys, OTP fallbacks gated behind unreliable env checks
- **MEDIUM**: Development/staging credentials, internal service tokens
- **LOW**: Test credentials that don't access real systems

## Key Principle
**A literal secret value in source code that could grant access to systems or data = vulnerability.**
**A hardcoded fallback value that bypasses authentication = vulnerability (even if gated behind env checks).**
**Reading secrets from environment variables or secrets managers = correct practice and NOT a vulnerability.**

## What NOT to Report
- Environment variable reads — these are the correct, secure approach
- Imports from config modules that themselves read from env
- Hash values (bcrypt, argon2, SHA) — these are derived values, not secrets
- Test fixtures with fake data
- Example/template files with placeholder values
- Cryptographic library imports

## Output Format
```
VULNERABILITY:
- Title: Hardcoded Secret — [type of secret]
- Severity: [CRITICAL/HIGH/MEDIUM/LOW]
- CWE: CWE-798
- OWASP: A07:2021 Authentication Failures
- File: [file path]
- Line: [line number]
- Description: [what secret was found and what it provides access to]
- Code Evidence: [the hardcoded value, partially redacted for safety]
- Remediation: [move to environment variable or secrets manager]
- Fixed Code: [externalized version]
```

## Example (for reference only)
A database connection string `"postgresql://admin:P@ssw0rd123@prod-db.internal:5432/myapp"` hardcoded in a config file committed to the repository is a critical vulnerability because anyone with repo access can connect to the production database. The fix is to read the connection string from an environment variable.

A hardcoded OTP fallback `let otpCode = '111111'` that is used when Twilio credentials are not set is critical because if the Twilio env vars are missing in production, any user can authenticate with OTP `111111`.

