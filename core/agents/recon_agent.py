"""
Reconnaissance Agent — the first agent in the pipeline.
Maps the codebase, identifies tech stack, runs tool scanners,
builds initial threat model and shares context with downstream agents.
"""
import os
from pathlib import Path
from typing import List, Dict
from .base_agent import BaseAgent
from ..findings import Finding, ScanResult, Severity, FindingSource
from ..tools.tool_registry import ToolRegistry
from ..constants import (
    SKILLS_DIR, MANIFEST_FILES,
    SKIP_DIRECTORIES, SUPPORTED_EXTENSIONS
)


class ReconAgent(BaseAgent):
    name = "recon_agent"
    role = "Security Reconnaissance Agent"
    description = (
        "You are the Reconnaissance Agent. Your job is to deeply understand the codebase architecture, "
        "identify the technology stack, map entry points, data flows, and build a comprehensive threat model. "
        "You share your findings with downstream vulnerability analysis agents."
    )

    def __init__(self, llm, memory, skills_dir=None):
        super().__init__(llm, memory, skills_dir or SKILLS_DIR)
        self.tool_registry = ToolRegistry()

    def _detect_tech_stack(self, target_path: str) -> Dict:
        """Detect the technology stack by examining files."""
        self.think("Scanning directory structure to identify technology stack...")

        tech = {
            "languages": set(),
            "frameworks": [],
            "databases": [],
            "manifests": [],
            "entry_points": [],
            "config_files": [],
            "total_files": 0,
            "total_lines": 0,
        }

        lang_map = {
            ".py": "Python", ".js": "JavaScript", ".ts": "TypeScript",
            ".jsx": "React/JSX", ".tsx": "React/TSX", ".java": "Java",
            ".go": "Go", ".rb": "Ruby", ".php": "PHP", ".cs": "C#",
        }

        framework_indicators = {
            "express": ("express", "JavaScript"), "django": ("django", "Python"),
            "flask": ("flask", "Python"), "fastapi": ("fastapi", "Python"),
            "spring": ("spring", "Java"), "rails": ("rails", "Ruby"),
            "laravel": ("laravel", "PHP"), "nextjs": ("next", "JavaScript"),
            "react": ("react", "JavaScript"), "angular": ("angular", "TypeScript"),
        }

        for root, dirs, files in os.walk(target_path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRECTORIES]

            for file in files:
                filepath = os.path.join(root, file)
                ext = Path(file).suffix

                if ext in SUPPORTED_EXTENSIONS:
                    tech["total_files"] += 1
                    if ext in lang_map:
                        tech["languages"].add(lang_map[ext])

                    try:
                        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            tech["total_lines"] += content.count('\n')

                            for fw_name, (indicator, lang) in framework_indicators.items():
                                if indicator in content.lower():
                                    if fw_name not in tech["frameworks"]:
                                        tech["frameworks"].append(fw_name)
                    except Exception:
                        pass

                if file in MANIFEST_FILES:
                    tech["manifests"].append(os.path.relpath(filepath, target_path))

                if file in {"main.py", "app.py", "index.js", "server.js", "main.go", "Main.java", "app.rb"}:
                    tech["entry_points"].append(os.path.relpath(filepath, target_path))

                if file in {"Dockerfile", "docker-compose.yml", ".env", ".env.example", "nginx.conf", "config.yaml"}:
                    tech["config_files"].append(os.path.relpath(filepath, target_path))

        tech["languages"] = list(tech["languages"])
        return tech

    def _run_tools(self, target_path: str, console=None) -> List[Finding]:
        """Run all available external scanning tools."""
        self.think("Running external security scanning tools...")
        available = self.tool_registry.get_available_tools()
        unavailable = self.tool_registry.get_unavailable_tools()

        if available:
            self.think(f"Available tools: {[t.name for t in available]}")
        if unavailable:
            self.think(f"Unavailable tools (not installed): {[t.name for t in unavailable]}")

        findings = self.tool_registry.scan_all(target_path, console=console)
        self.conclude(f"Tool scanning complete: {len(findings)} findings from {len(available)} tools")
        return findings

    # NOTE: Layer 1 skills (AST, control flow, dataflow, async, callgraph) have been
    # merged into the unified analysis skills run by VulnerabilityAgent.
    # This eliminates 5 separate LLM calls without accuracy loss.

    def _build_threat_model(self, tech_stack: Dict, code_context: str) -> str:
        """Use LLM reasoning to build an initial threat model."""
        self.think("Building initial threat model with reasoning...")

        prompt = (
            f"## Technology Stack Analysis\n"
            f"- Languages: {', '.join(tech_stack.get('languages', []))}\n"
            f"- Frameworks: {', '.join(tech_stack.get('frameworks', []))}\n"
            f"- Entry Points: {', '.join(tech_stack.get('entry_points', []))}\n"
            f"- Manifest Files: {', '.join(tech_stack.get('manifests', []))}\n"
            f"- Config Files: {', '.join(tech_stack.get('config_files', []))}\n"
            f"- Total Files: {tech_stack.get('total_files', 0)}\n"
            f"- Total Lines: {tech_stack.get('total_lines', 0)}\n\n"
            f"## Source Code\n<CODE>\n{code_context[:15000]}\n</CODE>\n\n"
            "Based on the technology stack and code, build a **Threat Model** that covers:\n"
            "1. **Attack Surface**: What entry points are exposed (HTTP endpoints, CLI args, file uploads)?\n"
            "2. **Data Flow**: How does user input flow through the application? What validation exists?\n"
            "3. **Trust Boundaries**: Where does trusted/untrusted data cross boundaries?\n"
            "4. **High-Risk Areas**: Which files/functions are most likely to contain vulnerabilities?\n"
            "5. **Dependency Risks**: Which dependencies are known to have security issues?\n"
        )

        response = self.run_with_reasoning(prompt)
        self.share_knowledge("threat_model", response)
        return response

    def execute(self, scan_result: ScanResult, code_context: str, console=None) -> dict:
        """
        Reconnaissance execution (optimized — Layer 1 skills merged into unified analysis):
        1. Detect tech stack
        2. Run external tools
        3. Build threat model
        """
        self.think("Starting reconnaissance phase...")

        # 1. Tech Stack Detection
        tech_stack = self._detect_tech_stack(scan_result.target_path)
        # Include both languages AND frameworks in tech_stack for display
        languages = tech_stack.get("languages", [])
        frameworks = tech_stack.get("frameworks", [])
        # Capitalize framework names for display
        framework_display = {
            'django': 'Django', 'flask': 'Flask', 'fastapi': 'FastAPI',
            'express': 'Express.js', 'nextjs': 'Next.js', 'react': 'React',
            'angular': 'Angular', 'spring': 'Spring', 'rails': 'Rails',
            'laravel': 'Laravel',
        }
        display_frameworks = [framework_display.get(fw, fw.title()) for fw in frameworks]
        scan_result.tech_stack = languages + display_frameworks
        scan_result.files_scanned = tech_stack.get("total_files", 0)
        scan_result.total_lines = tech_stack.get("total_lines", 0)
        self.share_knowledge("tech_stack", tech_stack)
        self.conclude(f"Tech stack: {tech_stack['languages']}, {tech_stack['total_files']} files, {tech_stack['total_lines']} lines")

        # 2. Run External Tools
        tool_findings = self._run_tools(scan_result.target_path, console=console)
        for f in tool_findings:
            scan_result.add_finding(f)
        self.share_knowledge("tool_findings_count", len(tool_findings))
        tool_summary = "\n".join([f"- [{f.severity.value}] {f.title} in {f.file_path}:{f.line_number}" for f in tool_findings[:20]])
        self.share_knowledge("tool_findings_summary", tool_summary or "No tool findings.")

        # 3. Build Threat Model (single LLM call)
        threat_model = self._build_threat_model(tech_stack, code_context)

        # Send high-level context to downstream agents
        self.send_to_agent("vulnerability_agent", f"Tech stack: {tech_stack['languages']}. "
                           f"Tool findings: {len(tool_findings)}. Threat model built.", "context")
        self.send_to_agent("all", f"Recon complete. {tech_stack['total_files']} files analyzed. "
                           f"{len(tool_findings)} tool findings. Threat model ready.", "status")

        return {
            "tech_stack": tech_stack,
            "tool_findings": tool_findings,
            "threat_model": threat_model,
        }
