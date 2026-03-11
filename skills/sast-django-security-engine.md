---
name: sast-django-security-engine
description: Django Framework Security Analysis — comprehensive configuration and code audit
version: 1.0.0
---

# Django Security Engine

## Your Mission
Perform a comprehensive Django-specific security audit. Django has many built-in security features, but they must be **correctly configured**. Your job is to check each one systematically.

## Step-by-Step Analysis

### Step 1: Check SECRET_KEY
Find `SECRET_KEY` in all settings files (base.py, local.py, production.py, staging.py):

**CRITICAL if:**
- `SECRET_KEY = 'short_string'` — hardcoded weak/guessable value
- `SECRET_KEY = 'django-insecure-...'` — still using the default insecure key
- Same SECRET_KEY in production and development settings

**SAFE if:**
- `SECRET_KEY = os.environ.get('SECRET_KEY')` — loaded from env (no fallback)
- `SECRET_KEY = os.environ['DJANGO_SECRET_KEY']` — env var, will crash if missing

**STILL VULNERABLE if:**
- `SECRET_KEY = os.environ.get('SECRET_KEY', 'weak_fallback')` — has a hardcoded fallback!

### Step 2: Check DEBUG Setting
- `DEBUG = True` in production settings → **HIGH** (exposes stack traces, SQL queries, template variables)
- `DEBUG = os.environ.get('DEBUG', True)` → **HIGH** (defaults to True if env var missing)

### Step 3: Check ALLOWED_HOSTS
- `ALLOWED_HOSTS = ['*']` → **HIGH** (HTTP Host header injection, cache poisoning, password reset hijacking)
- `ALLOWED_HOSTS = []` in production → **MEDIUM** (Django returns 400 but useful for DoS)
- Should be explicit hostnames: `ALLOWED_HOSTS = ['example.com', 'www.example.com']`

### Step 4: Check CSRF Protection
Search for `csrf_exempt` decorator usage across ALL views:
- `@csrf_exempt` on state-changing endpoints (POST/PUT/DELETE) → **HIGH**
- Especially dangerous on: checkout, payment, cart, wishlist, user profile endpoints
- `@method_decorator(csrf_exempt, name='dispatch')` on class-based views → same risk
- Count all csrf_exempt usages and report the total — excessive use indicates systemic CSRF weakness

### Step 5: Check Security Middleware & Headers
Look for these settings — report as **MEDIUM** if ANY are missing:

```python
# All of these MUST be present in production settings:
SECURE_SSL_REDIRECT = True                    # Force HTTPS
SECURE_HSTS_SECONDS = 31536000               # HSTS for 1 year
SECURE_HSTS_INCLUDE_SUBDOMAINS = True         # HSTS on subdomains
SECURE_HSTS_PRELOAD = True                    # HSTS preload list
SESSION_COOKIE_SECURE = True                  # Session cookie HTTPS only
CSRF_COOKIE_SECURE = True                     # CSRF cookie HTTPS only
SECURE_BROWSER_XSS_FILTER = True             # X-XSS-Protection header
SECURE_CONTENT_TYPE_NOSNIFF = True           # X-Content-Type-Options
X_FRAME_OPTIONS = 'DENY'                     # Clickjacking protection
```

If NONE of these are set at all, report as **HIGH** — the entire application lacks basic HTTP security.
**IMPORTANT**: Report EACH setting that is missing as a separate VULNERABILITY. Do NOT combine into one finding. Check ALL settings files (base, local, production, staging) — if ANY production-related file is missing these settings, report it.

### Step 6: Check Hardcoded Fallback Passwords (os.environ.get with default)
This is a commonly MISSED vulnerability — look for this pattern EVERYWHERE:

```python
# VULNERABLE — hardcoded fallback value exposes secret even when env var is set!
PASSWORD = os.environ.get('SOME_PASSWORD', 'hardcoded_value')  # ← fallback is the vulnerability!
BENEFIT_PASSWORD = os.environ.get('BENEFIT_PASSWORD', '100156638')  # ← CRITICAL!
SECRET = os.environ.get('SECRET', 'default_secret')  # ← CRITICAL fallback!
```

**CRITICAL if:**
- `os.environ.get('ANY_KEY', 'non-empty-string')` where the fallback is NOT empty and contains a real credential/password
- Especially: `*_PASSWORD`, `*_SECRET`, `*_KEY`, `*_TOKEN` variable names with non-empty fallbacks

**SAFE if:**
- `os.environ.get('KEY', '')` — empty string fallback (will fail at runtime)
- `os.environ.get('KEY')` — returns None (no fallback)
- `os.environ['KEY']` — raises KeyError if missing

Search ALL settings/*.py files for the regex pattern: `os\.environ\.get\(.*,\s*['"]\w+` — this catches any env var with a non-empty fallback.

### Step 7: Check Database Passwords
Look for hardcoded DATABASE credentials in settings:
- `'PASSWORD': 'hardcoded_value'` → **CRITICAL**
- `'PASSWORD': os.environ.get('DB_PASSWORD', 'default_pass')` → **CRITICAL** (fallback!)
- `'PASSWORD': os.environ.get('DB_PASSWORD', '')` → **SAFE** (empty fallback will fail)

### Step 8: Check for Pickle Deserialization
- `CELERY_ACCEPT_CONTENT = ['json', 'pickle']` → **HIGH** (RCE via message broker)
- `serializer='pickle'` in celery task decorators → **HIGH**
- `pickle.loads()` with untrusted data → **CRITICAL**
- Celery should ONLY accept JSON: `CELERY_ACCEPT_CONTENT = ['json']`

### Step 9: Check XSS via mark_safe
Search for `mark_safe()` usage:
- `mark_safe(user_data)` or `mark_safe(model_field)` → **MEDIUM** (stored XSS if field contains user input)
- `mark_safe(render_to_string(...))` → depends on template escaping
- Use `format_html()` instead of `mark_safe()` for any data that could contain user input

### Step 10: Check Raw SQL
- `cursor.execute("SELECT ... " + user_input)` → **CRITICAL** (SQL injection)
- `cursor.execute("SELECT ... %s", (param,))` → **SAFE** (parameterized)
- `.objects.raw("SELECT ...")` with string formatting → **HIGH**
- `.objects.extra(where=["..."])` with user input → **HIGH**
- `.objects.raw("SELECT ... %s", [param])` → **SAFE** (parameterized)

### Step 11: Check Email/API Credentials
Look for hardcoded API keys, email passwords, payment gateway credentials:
- `EMAIL_HOST_PASSWORD = 'SG.xxxx'` → **CRITICAL** (SendGrid API key exposed)
- `STRIPE_SECRET_KEY = 'sk_live_...'` → **CRITICAL**
- `AWS_SECRET_ACCESS_KEY = '...'` → **CRITICAL**
- Any `*_PASSWORD`, `*_SECRET`, `*_KEY`, `*_TOKEN` with hardcoded literal values

### Step 12: Check Password Validators
In production settings, verify `AUTH_PASSWORD_VALIDATORS` is configured:
- Missing entirely → **MEDIUM** (no password strength requirements)
- Only `MinimumLengthValidator` → **MEDIUM** (length only, no complexity)
- Should have: `UserAttributeSimilarityValidator`, `MinimumLengthValidator`, `CommonPasswordValidator`, `NumericPasswordValidator`

### Step 13: Check for Admin URL Disclosure
- Default `admin/` URL path → **LOW** (makes admin panel easily discoverable)
- Should use a non-obvious path like `secret-admin-panel-xyz/`

## Key Principle
**Django is secure by default, but only if properly configured.** The most common Django vulnerabilities come from MISSING or INCORRECT configuration, not from code bugs. Check settings systematically, not randomly.

## What NOT to Report
- Django ORM queries (.objects.filter, .get, .create) — parameterized by default
- Template variables without |safe — auto-escaped by default
- Django password hashing — bcrypt/PBKDF2 is secure
- csrf_exempt on webhook/callback endpoints that receive external POST (legitimate use)

## Output Format
```
VULNERABILITY:
- Title: [Django-specific title]
- Severity: [CRITICAL/HIGH/MEDIUM/LOW]
- CWE: [CWE-xxx]
- OWASP: [relevant OWASP category]
- File: [settings file or view file]
- Line: [line number]
- Description: [what's wrong and security impact]
- Code Evidence: [the vulnerable setting or code]
- Remediation: [exact fix]
- Fixed Code: [corrected setting]
```
