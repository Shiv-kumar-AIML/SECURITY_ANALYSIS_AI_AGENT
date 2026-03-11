---
name: sast-universal-credential-engine
description: Universal Credential & Secret Detection — all languages, all patterns
version: 1.0.0
---

# Universal Credential & Secret Detection Engine

## Your Mission
Find ALL hardcoded credentials, secrets, API keys, and sensitive data in the codebase — regardless of language or framework. This skill covers Python, JavaScript/TypeScript, Java, Go, PHP, Ruby, C#, and configuration files.

## Step 1: Hardcoded Passwords & Secrets
Search for directly assigned credentials in ANY language:

```python
# Python
PASSWORD = 'secret123'
DB_PASSWORD = "admin"
SECRET_KEY = 'weak-key'
```
```javascript
// JavaScript / TypeScript
const password = 'secret123';
let dbPassword = "admin";
const SECRET = 'weak-key';
```
```java
// Java
String password = "secret123";
private static final String API_KEY = "sk-xxxx";
```
```go
// Go
password := "secret123"
var apiKey = "sk-xxxx"
```
```php
// PHP
$password = 'secret123';
define('API_KEY', 'sk-xxxx');
```

**Variable name patterns to check:** Any variable containing: `PASSWORD`, `SECRET`, `KEY`, `TOKEN`, `CREDENTIAL`, `API_KEY`, `AUTH`, `PRIVATE`, `SIGNING`

**CRITICAL** if value is a non-empty literal string (not loaded from env/config).

## Step 2: Environment Variable Reads with Hardcoded Fallbacks
THIS IS THE MOST COMMONLY MISSED PATTERN — developers think it's "safe" because they use env vars, but the hardcoded fallback IS the vulnerability:

```python
# Python — VULNERABLE:
SECRET_KEY = os.environ.get('SECRET_KEY', 'my-weak-secret')     # ← fallback!
PASSWORD = os.environ.get('DB_PASSWORD', 'admin123')             # ← fallback!
API_TOKEN = os.environ.get('API_TOKEN', 'tok_default_value')     # ← fallback!

# Python — SAFE:
SECRET_KEY = os.environ['SECRET_KEY']                            # crashes if missing
SECRET_KEY = os.environ.get('SECRET_KEY')                        # returns None
SECRET_KEY = os.environ.get('SECRET_KEY', '')                    # empty = will fail
```

```javascript
// JavaScript/Node.js — VULNERABLE:
const secret = process.env.JWT_SECRET || 'dev-secret-key';       // ← fallback!
const apiKey = process.env.API_KEY ?? 'default-key';             // ← fallback!
const dbUrl = process.env.DATABASE_URL || 'postgres://user:pass@localhost/db';

// JavaScript — SAFE:
const secret = process.env.JWT_SECRET;                           // undefined if missing
if (!secret) throw new Error('JWT_SECRET required');
```

```java
// Java — VULNERABLE:
String secret = System.getProperty("secret", "default_secret");  // ← fallback!
String key = System.getenv("API_KEY") != null ? System.getenv("API_KEY") : "fallback";

// Go — VULNERABLE:
secret := os.Getenv("SECRET")
if secret == "" { secret = "default_secret" }                    // ← fallback!
```

**CRITICAL if:** The fallback value looks like a real credential (non-empty, non-placeholder).

## Step 3: API Keys & Service Credentials
Look for leaked API keys from common services — these are ALWAYS CRITICAL:

| Service | Pattern Example |
|---|---|
| **AWS** | `AKIA[0-9A-Z]{16}`, `aws_secret_access_key = '...'` |
| **SendGrid** | `SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}` |
| **Stripe** | `sk_live_[a-zA-Z0-9]{24,}`, `sk_test_...` |
| **Google/Firebase** | `AIza[0-9A-Za-z_-]{35}` |
| **Twilio** | `SK[a-f0-9]{32}` |
| **GitHub** | `ghp_[a-zA-Z0-9]{36}`, `gho_`, `ghu_`, `ghs_`, `ghr_` |
| **Slack** | `xoxb-`, `xoxp-`, `xapp-` |
| **JWT secrets** | Short or guessable signing keys like `'secret'`, `'key123'` |
| **Private keys** | `-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----` |

## Step 4: Database Connection Strings with Embedded Passwords
```python
# VULNERABLE — password embedded in URL:
DATABASE_URL = 'postgres://admin:password123@db.example.com:5432/mydb'
MONGO_URI = 'mongodb://root:secret@mongo:27017/admin'
REDIS_URL = 'redis://:mypassword@redis:6379/0'

# SAFE — loaded from env:
DATABASE_URL = os.environ.get('DATABASE_URL')
```

Check ALL of these formats:
- `postgres://user:PASSWORD@host`
- `mysql://user:PASSWORD@host`
- `mongodb://user:PASSWORD@host`
- `redis://:PASSWORD@host`
- `amqp://user:PASSWORD@host` (RabbitMQ)

## Step 5: Configuration Files
Check these non-code files for hardcoded secrets:

| File | What to check |
|---|---|
| `.env` / `.env.example` | Real values instead of placeholders |
| `docker-compose.yml` | `POSTGRES_PASSWORD: real_value` |
| `Dockerfile` | `ENV SECRET_KEY=hardcoded` |
| `config.yaml` / `config.json` | Any password/key/token fields |
| `application.properties` (Java) | `spring.datasource.password=xxx` |
| `appsettings.json` (.NET) | `ConnectionStrings` with passwords |
| `wp-config.php` (WordPress) | `DB_PASSWORD`, `AUTH_KEY`, etc. |

## Step 6: Encryption & Signing Keys
```python
# VULNERABLE — weak/hardcoded signing:
jwt.encode(payload, 'secret', algorithm='HS256')      # weak key
hmac.new(b'hardcoded-key', msg, hashlib.sha256)       # hardcoded HMAC key
Fernet(b'hardcoded-32-byte-key-here!!!!!')            # hardcoded encryption key

# Node.js:
jwt.sign(payload, 'my-secret');                        # weak JWT key
crypto.createHmac('sha256', 'hardcoded-key');          # hardcoded HMAC
```

**CRITICAL** if the key is short (<32 chars), guessable, or hardcoded.

## Step 7: Credentials in Comments or Disabled Code
Don't skip commented-out code — real credentials often hide there:
```python
# Old production credentials (TODO: remove)
# DB_PASSWORD = 'real_production_password_123'
# API_KEY = 'sk_live_actual_key_here'
```

## What NOT to Report
- Environment variables read WITHOUT fallbacks → SAFE
- Placeholder values like `'your-api-key-here'`, `'CHANGE_ME'`, `'xxx'` → SAFE
- Test/mock values in test files (`test_*.py`, `*.test.js`, `*.spec.ts`) → LOW at most
- Auto-generated Django `SECRET_KEY` in fresh projects (django-insecure-) → already covered
- Empty string fallbacks → SAFE (will fail at startup)

## Output Format
```
VULNERABILITY:
- Title: [Descriptive title with variable name and file]
- Severity: CRITICAL
- CWE: CWE-798
- OWASP: A07:2021 - Identification and Authentication Failures
- File: [file path]
- Line: [line number]
- Description: [what credential is exposed and the risk]
- Code Evidence: [the exact line with the hardcoded value]
- Remediation: [how to fix — env var, secrets manager, etc.]
- Fixed Code: [corrected code snippet]
```
