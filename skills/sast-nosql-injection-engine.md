---
name: sast-nosql-injection-engine
description: NoSQL Injection Detection — methodology-based analysis
version: 4.0.0
---

# NoSQL Injection Detection Engine

## Your Mission
Find code where **untrusted user input** is used to construct **NoSQL queries** (MongoDB, DynamoDB, CouchDB, etc.) in a way that allows an attacker to manipulate the query logic.

## Step-by-Step Analysis

### Step 1: Find All NoSQL Query Points
Scan for database query operations — `find()`, `findOne()`, `aggregate()`, `updateOne()`, `deleteMany()`, or any method that queries a NoSQL database.

### Step 2: Check How Query Objects Are Built
Ask: **Is the query object constructed using unvalidated user input?**
- If `req.body` is passed directly as a query filter, an attacker can inject query operators (like `$gt`, `$ne`, `$regex`) to manipulate the query logic.
- If `JSON.parse()` is used on user input to build queries, the user controls the entire query structure.

### Step 3: Check for Operator Injection
The core NoSQL injection attack is: sending `{ "$ne": null }` where a string value is expected. This turns an equality check into a "not null" check, bypassing authentication or filters.

### Step 4: Check for Type Enforcement
- Is the input type-cast to a string/number before use?
- Is schema validation (Zod, Joi, Mongoose schema) enforcing scalar types?
- Does the code destructure only known fields from user input?

### Step 5: Assess Impact
- Authentication bypass (login without password)
- Data exfiltration (querying records you shouldn't access)
- Data manipulation (updating/deleting records via operator injection)

## Key Principle
**User input used directly as a query object or part of a query object without type enforcement = vulnerable.**
**Type-cast/validated input used in queries = safe.**

## What NOT to Report
- Queries where input is type-cast (e.g., `String(input)`, `Number(input)`)
- Queries behind strict schema validation that enforces input types
- Queries where only specific fields are destructured from input

## Output Format
```
VULNERABILITY:
- Title: NoSQL Injection — [specific description]
- Severity: [CRITICAL/HIGH/MEDIUM/LOW]
- CWE: CWE-943
- OWASP: A03:2021 Injection
- File: [file path]
- Line: [line number]
- Description: [explanation]
- Dataflow: SOURCE: [user input] → FLOW: [query construction] → SINK: [database operation]
- Code Evidence: [the vulnerable code]
- Remediation: [enforce type validation, sanitize operators]
- Fixed Code: [corrected version]
```

## Example (for reference only)
A login function that does `User.findOne({ email: req.body.email, password: req.body.password })` is vulnerable if `req.body.password` can be `{ "$ne": null }`, which would match any non-null password, bypassing authentication. The fix is to enforce `String(req.body.password)` or validate with a schema.
