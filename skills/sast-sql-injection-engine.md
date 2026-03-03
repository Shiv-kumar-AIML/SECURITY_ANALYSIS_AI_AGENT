---
name: sast-sql-injection-engine
description: SQL Injection Vulnerability Detection — methodology-based analysis
version: 4.0.0
---

# SQL Injection Detection Engine

## Your Mission
Find code where **untrusted user input** reaches a **SQL execution function** without proper **parameterization or sanitization**.

## Step-by-Step Analysis

### Step 1: Find All Database Query Points
Scan the codebase for any function that executes SQL or database queries. This includes:
- Raw SQL execution functions (query, execute, raw, etc.)
- ORM methods that accept raw/unparameterized input
- Database driver methods
- Any function that builds SQL strings

### Step 2: For Each Query Point, Trace Backwards
Ask: **Where does the data in this query come from?**
- Trace each variable in the query back to its origin
- Is it from user input (HTTP request, form, URL params, headers)?
- Is it from a trusted internal source (config, constants, other DB results)?
- Is it hardcoded?

### Step 3: Check the Data Path for Sanitization
Between the source and the query, check:
- Is the input parameterized? (placeholders like `?`, `$1`, `:param`)
- Is the input passed through an ORM query builder that auto-parameterizes?
- Is the input validated/type-cast before reaching the query?
- Is string concatenation or interpolation used to build the query?

### Step 4: Assess Exploitability
- Can an attacker control the input? (is it exposed via API/URL/form?)
- Is authentication required to reach this code path?
- What data could be extracted (user data, credentials, admin access)?

### Step 5: Determine Severity
- **CRITICAL**: Unauthenticated SQL injection exposing sensitive data
- **HIGH**: Authenticated SQL injection with data extraction potential
- **MEDIUM**: SQL injection with limited impact (e.g., read-only, restricted data)
- **LOW**: Theoretical injection with significant mitigations in place

## Key Principle
**String concatenation or interpolation into SQL = vulnerable** (if the data comes from user input).
**Parameterized queries / ORM query builders = safe** (the database driver handles escaping).

## What NOT to Report
- ORM query builder methods that parameterize automatically
- Queries where all variables are from trusted/internal sources
- Queries in test files or migration scripts
- String concatenation with hardcoded constants only

## Output Format
```
VULNERABILITY:
- Title: SQL Injection — [specific description of where and how]
- Severity: [CRITICAL/HIGH/MEDIUM/LOW]
- CWE: CWE-89
- OWASP: A03:2021 Injection
- File: [exact file path]
- Line: [line number]
- Description: [clear explanation of the vulnerability]
- Dataflow: SOURCE: [where user input enters] → FLOW: [how it reaches the query] → SINK: [the query execution function]
- Code Evidence: [the vulnerable code showing the unsafe query construction]
- Remediation: [how to fix — use parameterized queries]
- Fixed Code: [corrected version using parameterization appropriate to the framework in use]
```

## Example (for reference only — do not limit your analysis to this pattern)
A function that takes a user-provided email and builds a query like `"SELECT * FROM users WHERE email = '" + email + "'"` is vulnerable because an attacker could provide `' OR 1=1 --` as the email to extract all users. The fix is to use parameterized queries: `query("SELECT * FROM users WHERE email = $1", [email])`.
