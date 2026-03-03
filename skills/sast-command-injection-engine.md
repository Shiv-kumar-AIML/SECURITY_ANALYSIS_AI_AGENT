---
name: sast-command-injection-engine
description: OS Command Injection Detection — methodology-based analysis
version: 4.0.0
---

# Command Injection Detection Engine

## Your Mission
Find code where **untrusted user input** reaches an **OS command execution function** without proper sanitization, allowing an attacker to execute arbitrary system commands.

## Step-by-Step Analysis

### Step 1: Find All Command Execution Points
Scan for any function that executes system commands — shell commands, process spawning, system calls. Look for any function in the codebase that can run OS-level commands.

### Step 2: Trace Data into Commands
For each command execution point, ask:
- Is any part of the command string constructed from user input?
- Is string concatenation or interpolation used to build command arguments?
- Is the command executed through a shell (shell=True, `/bin/sh -c`)?

### Step 3: Check for Shell Interpretation
Shell interpretation is the key risk. When a command runs through a shell, metacharacters like `;`, `|`, `&&`, `$(...)`, and backticks can inject additional commands. Ask:
- Does the execution function invoke a shell?
- Are arguments passed as a single string (shell) or an array (no shell)?

### Step 4: Check for Input Sanitization
- Is user input validated against a whitelist of allowed values?
- Is user input escaped for shell metacharacters?
- Are command arguments passed as an array (which avoids shell interpretation)?

### Step 5: Assess Impact
Command injection is almost always **CRITICAL** because it gives the attacker full OS-level access — reading files, installing malware, pivoting to other systems.

## Key Principle
**User input concatenated into a command string executed via shell = CRITICAL vulnerability.**
**Commands with array arguments and no shell = safe** (even with user input in arguments).

## What NOT to Report
- Commands where all arguments are hardcoded constants
- Process spawning with array arguments and `shell: false`
- Commands that are entirely internal (no user input reaches them)

## Output Format
```
VULNERABILITY:
- Title: Command Injection — [description]
- Severity: CRITICAL
- CWE: CWE-78
- OWASP: A03:2021 Injection
- File: [file path]
- Line: [line number]
- Description: [explanation]
- Dataflow: SOURCE: [user input] → FLOW: [command construction] → SINK: [execution function]
- Code Evidence: [the vulnerable code]
- Remediation: [use array arguments, avoid shell, validate input]
- Fixed Code: [corrected version]
```

## Example (for reference only)
A function that runs `exec("ping " + req.query.host)` is critically vulnerable because an attacker can send `host=127.0.0.1; cat /etc/passwd` to execute arbitrary commands. The fix is to use `execFile("ping", ["-c", "1", validatedHost])` which passes arguments as an array without shell interpretation.
