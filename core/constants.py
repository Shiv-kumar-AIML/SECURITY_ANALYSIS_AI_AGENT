import os
from pathlib import Path

# Paths
BASE_DIR = Path(__file__).resolve().parent.parent
SKILLS_DIR = BASE_DIR / "skills"
REPORTS_DIR = BASE_DIR / "reports"

# Default configs
DEFAULT_OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
DEFAULT_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5-coder:latest") # Use coding models like qwen2.5-coder or deepseek-coder

# Skills Layer Definitions
LAYER_1_SKILLS = [
    "dataflow-taint-engine.md"
]

LAYER_2_SKILLS = [
    "sast-sql-injection-engine.md",
    "sast-nosql-injection-engine.md",
    "sast-command-injection-engine.md",
    "sast-path-traversal-engine.md",
    "sast-jwt-oidc-engine.md",
    "sast-authorization-logic-engine.md",
    "sast-secret-detection-engine.md",
    "sca-dependency-engine.md"
]

LAYER_3_SKILLS = []

LAYER_4_SKILLS = [
    "report-validation-engine.md"
]

# Supported file extensions for SAST
SUPPORTED_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".php", ".cs", ".json"
}
