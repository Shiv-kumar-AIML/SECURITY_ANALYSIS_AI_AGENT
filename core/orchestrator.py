"""
SASTOrchestrator — backward-compatible orchestrator that now uses the multi-agent system.
This wraps the CoordinatorAgent for seamless integration.
"""
from pathlib import Path
from .agents.coordinator import CoordinatorAgent
from .llm_provider import LLMProvider
from .findings import ScanResult


class SASTOrchestrator:
    """
    Multi-agent SAST orchestrator.
    Coordinates: Recon → Vulnerability Analysis → Remediation → Verification
    """

    def __init__(self, target_code: str, target_path: str = "",
                 model_name: str = None, gemini_key: str = None,
                 openai_key: str = None, openai_base_url: str = None):
        self.target_code = target_code
        self.target_path = target_path

        self.provider = LLMProvider(
            model=model_name or None,
            gemini_key=gemini_key,
            openai_key=openai_key,
            openai_base_url=openai_base_url,
        )

        self.coordinator = CoordinatorAgent(
            llm=self.provider,
            target_path=target_path,
        )

    def analyze(self, console=None) -> ScanResult:
        """Run the full multi-agent analysis pipeline."""
        return self.coordinator.execute_full_scan(self.target_code, console=console)

    def analyze_tools_only(self, console=None) -> ScanResult:
        """Run only tool scanning without LLM analysis."""
        return self.coordinator.execute_tools_only(console=console)
