---
name: sca-dependency-engine
description: Software Composition Analysis — methodology-based dependency vulnerability assessment
version: 4.0.0
---

# SCA Dependency Engine

## Your Mission
Validate and enrich dependency vulnerability findings from automated tools. Assess the real-world impact of each CVE based on whether the vulnerable functionality is actually used.

## Step-by-Step Analysis

### Step 1: Review Tool Findings
Accept findings from trivy, npm audit, pip audit, and similar tools. These tools report known CVEs for installed packages.

### Step 2: Verify Package Presence
For each CVE finding, confirm:
- Is the package in the project's dependency manifest (package.json, requirements.txt, etc.)?
- Is it a direct dependency or a transitive (indirect) dependency?
- Is it in production dependencies or development-only dependencies?

### Step 3: Assess Reachability
- Is the vulnerable function/module from this package actually imported and used in the codebase?
- Is it reachable from user-controlled input?
- If it's a transitive dependency, is the parent package using the vulnerable functionality?

### Step 4: Evaluate Severity in Context
- A critical CVE in a dev-only dependency has lower real-world risk
- A moderate CVE in a heavily-used production dependency may have higher risk
- Consider whether the vulnerable code path is actually exercisable

### Step 5: Check for Available Fixes
- Is there a patched version available?
- Would upgrading introduce breaking changes?
- Are there alternative packages without the vulnerability?

## Key Principle
**All CVEs in production dependencies should be reported.** Dev-only dependency CVEs can be downgraded in severity. The goal is to ensure the user knows what's vulnerable and how to fix it.

## What NOT to Report
- Duplicate CVEs from multiple tools for the same package
- Lock file entries that duplicate manifest findings
- CVEs that have been disputed or withdrawn

## Output Format
```
VULNERABILITY:
- Title: Vulnerable Dependency: [package]@[version]
- Severity: [based on CVE severity adjusted by reachability]
- CWE: [from CVE]
- OWASP: A06:2021 Vulnerable Components
- File: [manifest file path]
- Line: 0
- Description: [CVE description, package purpose, impact]
- Remediation: [update to fixed version, alternative package]
- Fixed Code: [update command]
- References: [CVE/advisory links]
```
