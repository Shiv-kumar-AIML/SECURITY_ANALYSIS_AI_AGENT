"""
Abstract base class for all security scanning tools.
Each tool must implement: is_available(), run(), parse_results()
"""
import subprocess
import shutil
import json
from abc import ABC, abstractmethod
from typing import List, Optional
from ..findings import Finding


class BaseTool(ABC):
    """Base class for all external security scanning tools."""

    name: str = "base_tool"
    description: str = "Base scanning tool"

    @abstractmethod
    def is_available(self) -> bool:
        """Check if the tool is installed and accessible."""
        pass

    @abstractmethod
    def run(self, target_path: str) -> dict:
        """Run the tool against the target and return raw results."""
        pass

    @abstractmethod
    def parse_results(self, raw_results: dict) -> List[Finding]:
        """Parse raw tool output into structured Finding objects."""
        pass

    def _command_exists(self, cmd: str) -> bool:
        """Check if a command is available in PATH."""
        return shutil.which(cmd) is not None

    def _run_command(self, args: list, timeout: int = 300) -> Optional[str]:
        """Run a subprocess command safely and return stdout."""
        try:
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.stdout
        except subprocess.TimeoutExpired:
            return None
        except FileNotFoundError:
            return None
        except Exception:
            return None

    def _run_json_command(self, args: list, timeout: int = 300) -> Optional[dict]:
        """Run a subprocess command and parse JSON output."""
        output = self._run_command(args, timeout)
        if output:
            try:
                return json.loads(output)
            except json.JSONDecodeError:
                return None
        return None

    def scan(self, target_path: str) -> List[Finding]:
        """Full scan pipeline: run tool → parse results."""
        if not self.is_available():
            return []
        raw = self.run(target_path)
        if raw is None:
            return []
        return self.parse_results(raw)
