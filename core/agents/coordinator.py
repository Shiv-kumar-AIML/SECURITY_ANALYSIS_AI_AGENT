"""
Coordinator Agent — orchestrates the entire multi-agent scan pipeline.
Plans strategy, delegates to specialized agents, and compiles final results.
"""
import time
from .base_agent import BaseAgent, SharedMemory
from .recon_agent import ReconAgent
from .vulnerability_agent import VulnerabilityAgent
from .remediation_agent import RemediationAgent
from .verifier_agent import VerifierAgent
from .report_validator_agent import ReportValidatorAgent
from ..llm_provider import LLMProvider
from ..findings import ScanResult
from ..constants import SKILLS_DIR


class CoordinatorAgent(BaseAgent):
    name = "coordinator"
    role = "Security Scan Coordinator"
    description = (
        "You are the coordinator agent that orchestrates the entire security scan. "
        "You delegate work to specialized agents, manage the pipeline, and compile final results."
    )

    def __init__(self, llm: LLMProvider, target_path: str, skills_dir=None):
        self.shared_memory = SharedMemory()
        super().__init__(llm, self.shared_memory, skills_dir or SKILLS_DIR)
        self.target_path = target_path
        self.scan_result = ScanResult(target_path=target_path)

        # Initialize all agents with shared memory
        self.recon = ReconAgent(llm, self.shared_memory, self.skills_dir)
        self.vuln_analyst = VulnerabilityAgent(llm, self.shared_memory, self.skills_dir)
        self.remediator = RemediationAgent(llm, self.shared_memory, self.skills_dir)
        self.verifier = VerifierAgent(llm, self.shared_memory, self.skills_dir)
        self.validator = ReportValidatorAgent(llm, self.shared_memory, self.skills_dir)

    def execute_full_scan(self, code_context: str, console=None):
        """
        Execute the full 6-phase multi-agent scan pipeline:
        Phase 1: Reconnaissance (tech stack + tools + code mapping)
        Phase 2: Deep Vulnerability Analysis (skills + reasoning)
        Phase 3: Correlation (merge all findings)
        Phase 4: Remediation (generate fixes)
        Phase 5: Verification (false positive filtering)
        Phase 6: Report Validation (final quality gate)
        """
        self.think("Initializing multi-agent security scan pipeline...")

        # ═══════════════════════════════════════════
        # PHASE 1: RECONNAISSANCE
        # ═══════════════════════════════════════════
        if console:
            console.rule("[bold bright_cyan]Phase 1: Reconnaissance & Code Intelligence[/bold bright_cyan]")

        recon_results = self.recon.execute(self.scan_result, code_context, console=console)

        if console:
            tech = recon_results["tech_stack"]
            console.print(f"\n  [green]✓[/green] Tech Stack: [bold]{', '.join(tech.get('languages', []))}[/bold]")
            console.print(f"  [green]✓[/green] Files Scanned: [bold]{tech.get('total_files', 0)}[/bold]")
            console.print(f"  [green]✓[/green] Tool Findings: [bold]{len(recon_results.get('tool_findings', []))}[/bold]")
            console.print(f"  [green]✓[/green] Threat Model: [bold]Built[/bold]\n")

        # ═══════════════════════════════════════════
        # PHASE 2: DEEP VULNERABILITY ANALYSIS
        # ═══════════════════════════════════════════
        if console:
            console.rule("[bold bright_yellow]Phase 2: Deep Vulnerability Analysis (Reasoning)[/bold bright_yellow]")

        vuln_results = self.vuln_analyst.execute(self.scan_result, code_context, console=console)

        if console:
            console.print(f"\n  [green]✓[/green] Agent Findings: [bold]{len(vuln_results.get('findings', []))}[/bold]")
            console.print(f"  [green]✓[/green] Deep Analysis: [bold]Complete[/bold]\n")

        # ═══════════════════════════════════════════
        # PHASE 3: REMEDIATION
        # ═══════════════════════════════════════════
        if console:
            console.rule("[bold bright_magenta]Phase 3: Remediation & Fix Generation[/bold bright_magenta]")

        remediation_results = self.remediator.execute(self.scan_result, code_context, console=console)

        if console:
            console.print(f"\n  [green]✓[/green] Fixes Generated: [bold]{remediation_results.get('findings_remediated', 0)}[/bold]\n")

        # ═══════════════════════════════════════════
        # PHASE 4: VERIFICATION & FALSE POSITIVE FILTERING
        # ═══════════════════════════════════════════
        if console:
            console.rule("[bold bright_green]Phase 4: Verification & False Positive Filtering[/bold bright_green]")

        verify_results = self.verifier.execute(self.scan_result, code_context, console=console)

        if console:
            console.print(f"\n  [green]✓[/green] Confirmed: [bold]{verify_results.get('confirmed_count', 0)}[/bold]")
            console.print(f"  [green]✓[/green] False Positives Eliminated: [bold]{verify_results.get('false_positive_count', 0)}[/bold]\n")

        # ═══════════════════════════════════════════
        # PHASE 5: REPORT VALIDATION (Final Quality Gate)
        # ═══════════════════════════════════════════
        if console:
            console.rule("[bold bright_white]Phase 5: Report Validation & Quality Assurance[/bold bright_white]")

        validation_results = self.validator.execute(self.scan_result, code_context, console=console)

        if console:
            console.print(f"\n  [green]✓[/green] Validated: [bold]{validation_results.get('validated_count', 0)}[/bold]")
            removed = validation_results.get('removed_count', 0)
            fixed = validation_results.get('fixed_count', 0)
            if removed > 0:
                console.print(f"  [yellow]✗[/yellow] Removed (duplicates/FP): [bold]{removed}[/bold]")
            if fixed > 0:
                console.print(f"  [cyan]✎[/cyan] Fixed (remediation/severity): [bold]{fixed}[/bold]")
            console.print()

        # Finalize
        self.scan_result.scan_end = time.time()

        # Store agent reasoning in results
        self.scan_result.agent_reasoning = {
            "recon": self.recon.get_reasoning_log(),
            "vulnerability": self.vuln_analyst.get_reasoning_log(),
            "remediation": self.remediator.get_reasoning_log(),
            "verifier": self.verifier.get_reasoning_log(),
            "validator": self.validator.get_reasoning_log(),
            "coordinator": self.get_reasoning_log(),
        }

        self.scan_result.recon_context = {
            "shared_memory": str(self.shared_memory.read_all()),
        }

        return self.scan_result

    def execute_tools_only(self, console=None):
        """Execute only tool scanning without LLM analysis."""
        self.think("Running tools-only scan (no LLM)...")

        if console:
            console.rule("[bold bright_cyan]Tools-Only Scan[/bold bright_cyan]")

        recon_results = self.recon._detect_tech_stack(self.target_path)
        self.scan_result.tech_stack = recon_results.get("languages", [])
        self.scan_result.files_scanned = recon_results.get("total_files", 0)
        self.scan_result.total_lines = recon_results.get("total_lines", 0)

        tool_findings = self.recon._run_tools(self.target_path, console=console)
        for f in tool_findings:
            self.scan_result.add_finding(f)

        self.scan_result.scan_end = time.time()
        return self.scan_result
