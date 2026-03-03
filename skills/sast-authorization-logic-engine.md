---
name: sast-authorization-logic-engine
description: Broken Access Control & Authorization Logic — methodology-based analysis
version: 4.0.0
---

# Authorization & Access Control Engine

## Your Mission
Find broken access control vulnerabilities — missing authentication on endpoints, missing authorization checks, insecure direct object references (IDOR), privilege escalation, and sensitive data exposure.

## Step-by-Step Analysis

### Step 1: Map All Routes and Their Protection
Go through every route definition in the application:
- List all endpoints (GET, POST, PUT, DELETE)
- For each, identify what middleware/guards are applied (auth, role checks, etc.)
- Flag any state-changing endpoint (POST, PUT, DELETE) that has NO authentication middleware
- Flag endpoints that handle sensitive data without proper auth

### Step 2: Check Authorization Depth
Authentication (who are you?) is not the same as authorization (what can you do?):
- Does the endpoint check if the authenticated user has the right ROLE for this action?
- Does the endpoint verify OWNERSHIP — can user A access user B's data?
- Are admin-only operations restricted to admin roles?
- Is role information trusted from the token, or verified from the database?

### Step 3: Check Direct Object References
For any endpoint that accesses resources by ID:
- Does the code verify that the requesting user owns or has permission to access that resource?
- Can a user change the ID in the URL/body to access another user's data?
- Are there any filters applied to restrict results to the current user?

### Step 4: Check Data Exposure in Responses
- Does the API return more data than the client needs?
- Are sensitive fields (password hashes, internal IDs, tokens, secrets) included in responses?
- Are error messages revealing internal information (stack traces, DB queries)?

### Step 5: Check for Mass Assignment
- Can users set fields they shouldn't (role, isAdmin, balance, verified) by including extra fields in the request body?
- Does the code whitelist allowed fields, or does it accept everything from the request?

### Step 6: Check for Privilege Escalation Paths
- Can a regular user access admin endpoints?
- Can a user modify their own role/permissions?
- Are there hidden/undocumented endpoints without auth?

## Key Principle
**Every endpoint that accesses user-specific data MUST verify ownership. Every state-changing endpoint MUST verify permission.**

## What NOT to Report
- Public endpoints that are intentionally unauthenticated (login, register, public pages)
- Endpoints with proper auth middleware AND ownership checks in the controller

## Output Format
```
VULNERABILITY:
- Title: Broken Access Control — [specific issue]
- Severity: [CRITICAL/HIGH/MEDIUM/LOW]
- CWE: [CWE-284/285/306/639/862/863 as applicable]
- OWASP: A01:2021 Broken Access Control
- File: [file path]
- Line: [line number]
- Description: [explanation]
- Dataflow: SOURCE: [request] → FLOW: [missing/weak check] → SINK: [unauthorized access to resource]
- Code Evidence: [the vulnerable code]
- Remediation: [add auth/authorization check]
- Fixed Code: [corrected version]
```

## Example (for reference only)
A route that accepts a user ID from URL parameters and returns that user's data without verifying that the requesting user is the same user or an admin is an IDOR vulnerability. An attacker can change the ID to access any user's data. The fix is to verify `requestingUser.id === targetUser.id` or check for admin role before returning data.
