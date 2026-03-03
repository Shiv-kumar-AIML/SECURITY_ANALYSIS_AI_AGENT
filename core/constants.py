import os
from pathlib import Path

# Paths
BASE_DIR = Path(__file__).resolve().parent.parent
SKILLS_DIR = BASE_DIR / "skills"
REPORTS_DIR = BASE_DIR / "reports"
CLONED_REPOS_DIR = BASE_DIR / "cloned_repos"

# Default LLM configs
DEFAULT_OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
DEFAULT_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5-coder:latest")

# Skills Layer Definitions
LAYER_1_SKILLS = [
    "core-ast-engine.md",
    "control-flow-engine.md",
    "dataflow-taint-engine.md",
    "async-flow-modeling.md",
    "module-callgraph-engine.md"
]

LAYER_2_SKILLS = [
    "sast-sql-injection-engine.md",
    "sast-nosql-injection-engine.md",
    "sast-command-injection-engine.md",
    "sast-path-traversal-engine.md",
    "sast-jwt-oidc-engine.md",
    "sast-authorization-logic-engine.md",
    "sast-prototype-pollution-engine.md",
    "sast-secret-detection-engine.md",
    "sast-web-misconfig-engine.md",
    "sca-dependency-engine.md"
]

LAYER_3_SKILLS = [
    "sanitizer-recognition-engine.md",
    "false-positive-reduction-engine.md",
    "business-logic-anomaly-engine.md",
    "architecture-trust-boundary-engine.md",
    "cross-service-token-acceptance-engine.md"
]

# Supported file extensions for SAST
SUPPORTED_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go",
    ".rb", ".php", ".cs", ".json", ".yaml", ".yml",
    ".xml", ".sql", ".sh", ".bash", ".dockerfile",
    ".tf", ".hcl",  # Terraform/IaC
}

# Dependency manifest files (for SCA)
MANIFEST_FILES = {
    "package.json", "package-lock.json", "yarn.lock",
    "requirements.txt", "Pipfile", "Pipfile.lock", "pyproject.toml",
    "go.mod", "go.sum",
    "Gemfile", "Gemfile.lock",
    "pom.xml", "build.gradle",
    "composer.json", "composer.lock",
    "Cargo.toml", "Cargo.lock",
}

# Directories to skip during scanning
SKIP_DIRECTORIES = {
    ".git", "node_modules", "venv", ".venv", "env",
    "__pycache__", ".tox", ".mypy_cache", ".pytest_cache",
    "dist", "build", ".eggs", ".next", ".nuxt",
    "vendor", "third_party",
}

# CWE Reference Mapping
CWE_MAP = {
    "sql_injection": {"id": "CWE-89", "name": "SQL Injection", "owasp": "A03:2021 Injection"},
    "nosql_injection": {"id": "CWE-943", "name": "NoSQL Injection", "owasp": "A03:2021 Injection"},
    "command_injection": {"id": "CWE-78", "name": "OS Command Injection", "owasp": "A03:2021 Injection"},
    "path_traversal": {"id": "CWE-22", "name": "Path Traversal", "owasp": "A01:2021 Broken Access Control"},
    "xss": {"id": "CWE-79", "name": "Cross-site Scripting", "owasp": "A03:2021 Injection"},
    "ssrf": {"id": "CWE-918", "name": "Server-Side Request Forgery", "owasp": "A10:2021 SSRF"},
    "hardcoded_secret": {"id": "CWE-798", "name": "Hardcoded Credentials", "owasp": "A07:2021 Auth Failures"},
    "broken_auth": {"id": "CWE-287", "name": "Improper Authentication", "owasp": "A07:2021 Auth Failures"},
    "broken_access": {"id": "CWE-284", "name": "Improper Access Control", "owasp": "A01:2021 Broken Access Control"},
    "prototype_pollution": {"id": "CWE-1321", "name": "Prototype Pollution", "owasp": "A03:2021 Injection"},
    "jwt_weak": {"id": "CWE-347", "name": "JWT Verification Failure", "owasp": "A02:2021 Crypto Failures"},
    "insecure_deserialization": {"id": "CWE-502", "name": "Insecure Deserialization", "owasp": "A08:2021 Software Integrity"},
    "vulnerable_dependency": {"id": "CWE-1395", "name": "Vulnerable Dependency", "owasp": "A06:2021 Vulnerable Components"},
    "crypto_failure": {"id": "CWE-327", "name": "Broken Cryptography", "owasp": "A02:2021 Crypto Failures"},
    "open_redirect": {"id": "CWE-601", "name": "Open Redirect", "owasp": "A01:2021 Broken Access Control"},
    "xxe": {"id": "CWE-611", "name": "XML External Entity", "owasp": "A05:2021 Security Misconfig"},
    "idor": {"id": "CWE-639", "name": "Insecure Direct Object Reference", "owasp": "A01:2021 Broken Access Control"},
    "race_condition": {"id": "CWE-362", "name": "Race Condition", "owasp": "A04:2021 Insecure Design"},
}

# Severity thresholds
SEVERITY_THRESHOLDS = {
    "CRITICAL": {"min_cvss": 9.0, "color": "bright_red"},
    "HIGH": {"min_cvss": 7.0, "color": "red"},
    "MEDIUM": {"min_cvss": 4.0, "color": "yellow"},
    "LOW": {"min_cvss": 0.1, "color": "blue"},
    "INFO": {"min_cvss": 0.0, "color": "dim"},
}
