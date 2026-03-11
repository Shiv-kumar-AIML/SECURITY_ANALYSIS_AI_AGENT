---
name: sast-flask-security-engine
description: Flask Framework Security Analysis — configuration and code audit
version: 1.0.0
---

# Flask Security Engine

## Your Mission
Perform a comprehensive Flask-specific security audit. Flask is a micro-framework with minimal built-in security — most protections must be explicitly added.

## Step-by-Step Analysis

### Step 1: Check Secret Key
- `app.secret_key = 'hardcoded'` → **CRITICAL**
- `app.config['SECRET_KEY'] = 'dev'` → **CRITICAL**
- `SECRET_KEY = os.environ.get('SECRET_KEY', 'fallback')` → **CRITICAL** (fallback!)

### Step 2: Check Debug Mode
- `app.run(debug=True)` in production → **HIGH**
- `DEBUG = True` in production config → **HIGH**
- `FLASK_DEBUG=1` in .env committed to repo → **HIGH**

### Step 3: Check CORS Configuration
- `CORS(app)` with no origin restrictions → **HIGH** (any origin can access API)
- `CORS(app, resources={r"/*": {"origins": "*"}})` → **HIGH**
- Should restrict to specific origins: `origins=["https://example.com"]`

### Step 4: Check Session Cookie Security
- Missing `SESSION_COOKIE_SECURE = True` → **MEDIUM**
- Missing `SESSION_COOKIE_HTTPONLY = True` → **MEDIUM**
- Missing `SESSION_COOKIE_SAMESITE = 'Lax'` → **MEDIUM**

### Step 5: Check Template Security
- `Markup(user_data)` → **HIGH** (XSS — marks as safe HTML)
- `render_template_string(user_input)` → **CRITICAL** (SSTI — server-side template injection)
- `|safe` filter with user data in Jinja templates → **HIGH**
- Default Jinja auto-escaping is safe — don't report normal template usage

### Step 6: Check File Upload Security
- `file.save(os.path.join(upload_dir, file.filename))` → **HIGH** (no filename sanitization)
- Use `secure_filename()` from werkzeug.utils
- Check for missing file type validation and size limits

### Step 7: Check SQL Usage
- `db.engine.execute("SELECT ... " + user_input)` → **CRITICAL**
- `db.session.execute(text(...))` with string formatting → **HIGH**
- SQLAlchemy ORM queries (.filter, .query) → **SAFE**

### Step 8: Check for Dangerous Functions
- `os.system()`, `subprocess.call(shell=True)` → **HIGH** if user input flows in
- `eval()`, `exec()` → **CRITICAL** if user input flows in
- `pickle.loads(untrusted_data)` → **CRITICAL** (RCE)
- `yaml.load()` without `Loader=SafeLoader` → **HIGH**

### Step 9: Check Authentication
- No `@login_required` on sensitive routes → **HIGH**
- Missing rate limiting on login endpoints → **MEDIUM**
- Passwords stored without hashing → **CRITICAL**

### Step 10: Check Error Handling
- `traceback.format_exc()` returned in API response → **HIGH**
- `app.config['PROPAGATE_EXCEPTIONS'] = True` in production → **MEDIUM**

## What NOT to Report
- SQLAlchemy ORM queries — parameterized by default
- Jinja2 template variables without |safe — auto-escaped
- Flask-Login decorated routes — properly authenticated
- Werkzeug password hashing — secure

## Output Format
```
VULNERABILITY:
- Title: [Flask-specific title]
- Severity: [CRITICAL/HIGH/MEDIUM/LOW]
- CWE: [CWE-xxx]
- OWASP: [relevant category]
- File: [file path]
- Line: [line number]
- Description: [what's wrong]
- Code Evidence: [the vulnerable code]
- Remediation: [exact fix]
- Fixed Code: [corrected code]
```
