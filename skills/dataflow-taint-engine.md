---
name: dataflow-taint-engine
description: Dataflow Taint Analysis — methodology-based source-to-sink tracing
version: 4.0.0
---

# Dataflow Taint Analysis Engine

## Your Mission
Trace the flow of **untrusted data** from where it enters the application (sources) through its transformations (flow) to where it reaches potentially dangerous operations (sinks). This is the foundation of all injection vulnerability detection.

## Step-by-Step Analysis

### Step 1: Identify All Data Entry Points (Sources)
Find every point where external, untrusted data enters the application:
- HTTP request components (body, query parameters, URL parameters, headers, cookies)
- File uploads and their contents
- WebSocket/real-time messages
- External API responses (if user-controlled upstream)
- Database values that originated from user input
- Environment variables (generally trusted, but verify)

### Step 2: Trace Data Flow Through the Application
For each source, follow the data as it moves:
- Variable assignments and reassignments
- Function call arguments and return values
- Object property access and destructuring
- String concatenation, interpolation, and template literals
- Data transformation (encoding, serialization, parsing)

### Step 3: Identify Sanitization Points (Taint Breaks)
Check if the data is sanitized, validated, or transformed into a safe form at any point:
- Input validation (schema validation, type checking, format verification)
- Type casting (converting to number, boolean, etc.)
- Encoding/escaping (HTML encoding, URL encoding, SQL parameterization)
- Allow-listing (checking against a set of known-safe values)
- ORM query builders (which parameterize automatically)

### Step 4: Identify Dangerous Operations (Sinks)
Find where data reaches operations that can be exploited:
- Database queries (SQL, NoSQL)
- System command execution
- File system operations
- HTML rendering/template output
- URL construction and redirects
- Code evaluation
- Network requests
- Serialization/deserialization

### Step 5: Connect the Chain
For each path from source to sink:
- Is there an unbroken chain of tainted data flow?
- Does the data pass through any sanitizer that neutralizes the threat?
- Is the sanitizer appropriate for the sink type? (SQL escaping doesn't protect against XSS)

## Key Principle
**A vulnerability exists only when untrusted data flows from a source to a dangerous sink WITHOUT appropriate sanitization for that specific sink type.** Each sink type has its own required sanitization.

## Classification
- **Source → (no sanitizer) → Sink**: VULNERABLE — report it
- **Source → (appropriate sanitizer) → Sink**: SAFE — don't report
- **Source → (wrong sanitizer) → Sink**: VULNERABLE — the sanitizer doesn't protect against this sink type
- **Trusted source → Sink**: SAFE — no untrusted data involved

## Output: Report only confirmed source-to-sink paths where no appropriate sanitizer exists
