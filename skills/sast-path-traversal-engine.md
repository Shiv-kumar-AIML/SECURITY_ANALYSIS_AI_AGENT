---
name: sast-path-traversal-engine
description: Path Traversal Detection — methodology-based analysis
version: 4.0.0
---

# Path Traversal Detection Engine

## Your Mission
Find code where **untrusted user input** is used to construct **file system paths**, allowing an attacker to access files outside the intended directory.

## Step-by-Step Analysis

### Step 1: Find All File System Operations
Scan for any function that reads, writes, deletes, or serves files. This includes file reads, writes, directory listings, static file serving, and file downloads.

### Step 2: Trace the File Path Construction
For each file operation, ask:
- Where does the file path or filename come from?
- Is any part of the path derived from user input (URL params, query params, form data, uploaded filenames)?
- Is the path built using string concatenation, path joining, or template interpolation?

### Step 3: Check for Path Validation
Between user input and the file operation, check:
- Is the resolved path validated to stay within the intended base directory?
- Is the input checked for traversal sequences (`../`, `..\\`, encoded variants)?
- Is the filename validated against an allowlist or pattern?
- Does the code resolve the absolute path and verify it starts with the expected base?

### Step 4: Check Static File Serving
Examine how static/uploaded files are served:
- Is a static file directory configured? What directory does it serve?
- Can an attacker access sensitive files by manipulating the URL path?
- Are uploaded files served from the same origin as the application?

### Step 5: Assess Impact
- Can the attacker read sensitive system files (config, credentials, source code)?
- Can the attacker write/overwrite files (code execution, config manipulation)?
- Can the attacker list directory contents?

## Key Principle
**User input in file path without path resolution and containment check = vulnerable.**
**Hardcoded paths or paths validated to stay within a base directory = safe.**

## What NOT to Report
- File operations with entirely hardcoded paths
- Static file serving from a hardcoded directory with no user-controlled subpath
- Paths constructed from database values that don't originate from direct user input

## Output Format
```
VULNERABILITY:
- Title: Path Traversal — [description]
- Severity: [HIGH/MEDIUM]
- CWE: CWE-22
- OWASP: A01:2021 Broken Access Control
- File: [file path]
- Line: [line number]
- Description: [explanation]
- Dataflow: SOURCE: [user input] → FLOW: [path construction] → SINK: [file operation]
- Code Evidence: [the vulnerable code]
- Remediation: [resolve path, verify it stays within base directory]
- Fixed Code: [corrected version]
```

## Example (for reference only)
A file download endpoint that constructs the path as `/uploads/ + req.params.filename` is vulnerable because an attacker can send `filename=../../etc/passwd` to read system files. The fix is to resolve the full path and verify it starts with the uploads directory before serving.
