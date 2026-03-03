---
name: sast-secret-detection-engine
description: Hardcoded Secret Detection — methodology-based analysis
version: 4.0.0
---

# Secret Detection Engine

## Your Mission
Find **hardcoded secrets, credentials, and sensitive tokens** embedded directly in source code. Distinguish between genuinely hardcoded secrets and properly externalized secret management.

## Step-by-Step Analysis

### Step 1: Find All Secret-Like Values
Scan for variables, constants, and configuration values that represent sensitive data:
- API keys, tokens, passwords, database credentials
- Cloud provider credentials, webhook URLs with tokens
- Encryption keys, signing secrets
- Connection strings with embedded credentials

### Step 2: Check the Source of the Value
For each potential secret, ask: **Is the value hardcoded in the source code, or is it loaded from an external secure source?**

Hardcoded (VULNERABLE):
- Literal string assigned directly in code
- Configuration file committed to the repository with real values

Externalized (SAFE — do NOT report):
- Environment variables
- Secrets management services
- Config files that are in `.gitignore`
- Placeholder/example values in `.env.example` files

### Step 3: Evaluate Context
- Is this in a test file with intentionally fake credentials?
- Is this a hash value (bcrypt hash, SHA checksum) rather than a secret?
- Is this a placeholder like "your-key-here" or "changeme"?
- Is this an import of a secret from a config module (which itself reads from env)?

### Step 4: Assess Severity
- **CRITICAL**: Production credentials, cloud provider keys, database passwords
- **HIGH**: API keys with broad permissions, payment processing keys
- **MEDIUM**: Development/staging credentials, internal service tokens
- **LOW**: Test credentials that don't access real systems

## Key Principle
**A literal secret value in source code that could grant access to systems or data = vulnerability.**
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
