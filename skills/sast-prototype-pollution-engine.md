---
name: sast-prototype-pollution-engine
description: Prototype Pollution Detection — methodology-based analysis
version: 4.0.0
---

# Prototype Pollution Detection Engine

## Your Mission
Find code where **untrusted user input** can modify the **prototype chain** of JavaScript objects, allowing attackers to inject properties that affect all objects in the application.

## Step-by-Step Analysis

### Step 1: Find Object Modification Points
Locate code that dynamically modifies objects using user-controlled keys or values:
- Deep merge/extend functions that recursively merge objects
- Property assignment using bracket notation with dynamic keys
- Functions that copy properties from one object to another

### Step 2: Trace the Key/Value Sources
For each modification point, ask:
- Where does the KEY come from? Can the user control which property is set?
- Where does the VALUE come from? Can the user set arbitrary values?
- Is the entire object provided by the user (e.g., from request body)?

### Step 3: Check for Prototype Guards
- Does the code check for dangerous keys (`__proto__`, `constructor`, `prototype`) before assignment?
- Is the target object created with `Object.create(null)` (no prototype chain)?
- Does the merge function skip inherited properties?
- Are object keys whitelisted (only known, specific fields accepted)?

### Step 4: Assess Impact
- Can the attacker set `isAdmin: true` on all objects?
- Can they modify `toString`, `valueOf`, or other built-in methods?
- Can they cause denial of service by polluting critical properties?
- Does the pollution cross request boundaries (affecting all users)?

## Key Principle
**User-controlled property keys set on shared/global objects without key validation = vulnerable.**
**Destructuring known fields from user input = safe.**

## What NOT to Report
- Spread operators with known fields only
- Object destructuring that extracts only specific properties
- Libraries that have prototype pollution protection built in
- Property access on objects created with `Object.create(null)`

## Output Format
```
VULNERABILITY:
- Title: Prototype Pollution — [description]
- Severity: [CRITICAL/HIGH/MEDIUM]
- CWE: CWE-1321
- OWASP: A03:2021 Injection
- File: [file path]
- Line: [line number]
- Description: [explanation]
- Dataflow: SOURCE: [user input] → FLOW: [merge/assign operation] → SINK: [Object.prototype modification]
- Code Evidence: [the vulnerable code]
- Remediation: [validate keys, block proto, use Object.create(null)]
- Fixed Code: [corrected version]
```

## Example (for reference only)
A deep merge function that recursively assigns all properties from user input to a config object is vulnerable because the user can send `{"__proto__": {"isAdmin": true}}`, which modifies `Object.prototype.isAdmin`, making every object in the application believe the user is an admin. The fix is to filter out `__proto__`, `constructor`, and `prototype` keys before merging.
