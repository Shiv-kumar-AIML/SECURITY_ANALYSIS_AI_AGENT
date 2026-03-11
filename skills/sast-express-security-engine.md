---
name: sast-express-security-engine
description: Express.js Framework Security Analysis — configuration and middleware audit
version: 1.0.0
---

# Express.js Security Engine

## Your Mission
Perform a comprehensive Express.js-specific security audit. Express is minimal by default — security must be explicitly added via middleware.

## Step-by-Step Analysis

### Step 1: Check for Helmet (Security Headers)
- No `helmet` middleware → **MEDIUM** (missing all security headers)
- `app.use(helmet())` → **SAFE**
- Custom headers without CSP, HSTS, X-Frame-Options → **MEDIUM**

### Step 2: Check CORS Configuration
- `app.use(cors())` with no options → **HIGH** (allows ALL origins)
- `cors({ origin: '*' })` → **HIGH**
- `cors({ origin: true, credentials: true })` → **CRITICAL** (any origin + cookies)
- Should use: `cors({ origin: ['https://example.com'] })`

### Step 3: Check Rate Limiting
- No rate limiting middleware on auth routes → **MEDIUM**
- `express-rate-limit` configured but too permissive (>100 req/min on login) → **LOW**

### Step 4: Check Session Security
- `app.use(session({ secret: 'hardcoded' }))` → **CRITICAL**
- Session without `secure: true` in production → **MEDIUM**
- Missing `httpOnly: true`, `sameSite: 'strict'` → **MEDIUM**
- `resave: true` + `saveUninitialized: true` → **LOW**

### Step 5: Check Body Parser Limits
- No request body size limit → **MEDIUM** (DoS via large payloads)
- `app.use(express.json({ limit: '100mb' }))` → **LOW** (excessive limit)
- Recommended: `limit: '1mb'` for JSON, `limit: '10mb'` for file uploads

### Step 6: Check Error Handling
- `app.use((err, req, res, next) => { res.json({ stack: err.stack }) })` → **HIGH**
- `NODE_ENV !== 'production'` check for verbose errors → **SAFE**
- No global error handler → **MEDIUM** (Express default leaks stack in dev)

### Step 7: Check SQL/NoSQL Usage
- `db.query("SELECT ... " + req.body.id)` → **CRITICAL**
- MongoDB: `{ $where: req.body.query }` → **CRITICAL** (NoSQL injection)
- ORM queries (Sequelize, Mongoose) → **SAFE** (parameterized)

### Step 8: Check File Upload Security
- `multer` without file type filter → **MEDIUM**
- `multer({ dest: 'public/uploads' })` → **HIGH** (uploads in web root)
- `file.originalname` used directly → **HIGH** (path traversal)

### Step 9: Check Authentication
- Sensitive routes without `passport.authenticate()` or similar → **HIGH**
- JWT verification without algorithm restriction → **HIGH**
- `jwt.verify(token, secret)` without `algorithms` option → **MEDIUM**

### Step 10: Check Server Configuration
- `app.listen(PORT)` on `0.0.0.0` without reverse proxy → **LOW**
- `trust proxy` not set behind load balancer → **LOW** (rate limiting bypass)
- `x-powered-by` header not disabled → **LOW** (information disclosure)

## What NOT to Report
- Sequelize/Mongoose ORM queries — parameterized by default
- EJS/Pug template variables — auto-escaped by default
- Passport.js authenticated routes — properly protected
- bcrypt password hashing — secure

## Output Format
```
VULNERABILITY:
- Title: [Express-specific title]
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
