"""
Structured Finding model for security vulnerabilities.
Used across all agents and tools for consistent output format.
"""
import json
import uuid
import time
from dataclasses import dataclass, field, asdict
from typing import Optional, List
from enum import Enum


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def color(self):
        return {
            "CRITICAL": "bright_red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "blue",
            "INFO": "dim",
        }.get(self.value, "white")

    @property
    def emoji(self):
        return {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "LOW": "🔵",
            "INFO": "⚪",
        }.get(self.value, "⚪")

    @property
    def score(self):
        return {
            "CRITICAL": 10,
            "HIGH": 8,
            "MEDIUM": 5,
            "LOW": 3,
            "INFO": 1,
        }.get(self.value, 0)


class FindingSource(Enum):
    TOOL_SEMGREP = "semgrep"
    TOOL_BANDIT = "bandit"
    TOOL_TRIVY = "trivy"
    TOOL_GITLEAKS = "gitleaks"
    TOOL_NPM_AUDIT = "npm_audit"
    AGENT_RECON = "recon_agent"
    AGENT_VULNERABILITY = "vulnerability_agent"
    AGENT_REMEDIATION = "remediation_agent"
    AGENT_VERIFIER = "verifier_agent"
    SKILL_LAYER_1 = "skill_layer_1"
    SKILL_LAYER_2 = "skill_layer_2"
    SKILL_LAYER_3 = "skill_layer_3"


@dataclass
class Finding:
    """A single security finding from any source (tool or agent)."""
    title: str
    description: str
    severity: Severity
    source: FindingSource
    file_path: str = ""
    line_number: int = 0
    end_line: int = 0
    code_snippet: str = ""
    cwe_id: str = ""
    owasp_category: str = ""
    cvss_score: float = 0.0
    confidence: float = 0.0  # 0.0 to 1.0
    remediation: str = ""
    remediation_code: str = ""
    reasoning_chain: str = ""  # Chain-of-thought reasoning
    is_false_positive: bool = False
    false_positive_reason: str = ""
    references: List[str] = field(default_factory=list)
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp: float = field(default_factory=time.time)

    def to_dict(self):
        d = asdict(self)
        d["severity"] = self.severity.value
        d["source"] = self.source.value
        return d

    def to_json(self):
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, data: dict) -> "Finding":
        data["severity"] = Severity(data.get("severity", "INFO"))
        data["source"] = FindingSource(data.get("source", "skill_layer_2"))
        data.pop("finding_id", None)
        data.pop("timestamp", None)
        return cls(**data)

    def severity_badge(self) -> str:
        return f"{self.severity.emoji} {self.severity.value}"


@dataclass
class ScanResult:
    """Aggregated results from a complete security scan."""
    target_path: str
    scan_start: float = field(default_factory=time.time)
    scan_end: float = 0.0
    findings: List[Finding] = field(default_factory=list)
    tool_findings: List[Finding] = field(default_factory=list)
    agent_findings: List[Finding] = field(default_factory=list)
    recon_context: dict = field(default_factory=dict)
    agent_reasoning: dict = field(default_factory=dict)
    tech_stack: List[str] = field(default_factory=list)
    files_scanned: int = 0
    total_lines: int = 0

    def add_finding(self, finding: Finding):
        self.findings.append(finding)
        if finding.source.value.startswith("tool_"):
            self.tool_findings.append(finding)
        else:
            self.agent_findings.append(finding)

    def get_by_severity(self, severity: Severity) -> List[Finding]:
        return [f for f in self.findings if f.severity == severity and not f.is_false_positive]

    def get_confirmed(self) -> List[Finding]:
        return [f for f in self.findings if not f.is_false_positive]

    @property
    def severity_counts(self) -> dict:
        confirmed = self.get_confirmed()
        return {
            s.value: len([f for f in confirmed if f.severity == s])
            for s in Severity
        }

    @property
    def risk_score(self) -> float:
        confirmed = self.get_confirmed()
        if not confirmed:
            return 0.0
        return sum(f.severity.score * f.confidence for f in confirmed) / len(confirmed)

    def to_dict(self):
        return {
            "target_path": self.target_path,
            "scan_start": self.scan_start,
            "scan_end": self.scan_end,
            "files_scanned": self.files_scanned,
            "total_lines": self.total_lines,
            "tech_stack": self.tech_stack,
            "severity_counts": self.severity_counts,
            "risk_score": self.risk_score,
            "findings": [f.to_dict() for f in self.get_confirmed()],
            "false_positives": [f.to_dict() for f in self.findings if f.is_false_positive],
        }

    def to_json(self):
        return json.dumps(self.to_dict(), indent=2)
