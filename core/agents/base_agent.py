"""
Base Agent class for the multi-agent security analysis system.
All specialized agents inherit from this class.
Each agent has: reasoning capability, tool access, shared memory, and structured output.
"""
import threading
from typing import Optional, List, Dict
from ..llm_provider import LLMProvider
from ..findings import Finding, ScanResult


class SharedMemory:
    """
    Shared knowledge base between agents.
    Agents write their findings and context here so other agents can read them.
    This enables inter-agent knowledge sharing and collaborative reasoning.
    """

    def __init__(self, max_messages: int = 1000):
        self._store: Dict[str, dict] = {}
        self._messages: List[dict] = []
        self._lock = threading.RLock()  # Reentrant lock for thread safety
        self._max_messages = max_messages

    def write(self, agent_name: str, key: str, value):
        """Write a piece of knowledge to shared memory."""
        with self._lock:
            if agent_name not in self._store:
                self._store[agent_name] = {}
            self._store[agent_name][key] = value

    def read(self, agent_name: str, key: str = None):
        """Read knowledge from a specific agent's memory."""
        with self._lock:
            if key:
                return self._store.get(agent_name, {}).get(key)
            return self._store.get(agent_name, {})

    def read_all(self) -> Dict[str, dict]:
        """Read all shared knowledge."""
        with self._lock:
            return self._store.copy()  # Return copy to prevent external modification

    def send_message(self, from_agent: str, to_agent: str, content: str, msg_type: str = "info"):
        """Send an inter-agent message."""
        with self._lock:
            self._messages.append({
                "from": from_agent,
                "to": to_agent,
                "type": msg_type,
                "content": content,
            })
            # Prevent memory leak by limiting message history
            if len(self._messages) > self._max_messages:
                # Keep only the most recent messages
                self._messages = self._messages[-self._max_messages:]

    def get_messages(self, agent_name: str) -> List[dict]:
        """Get all messages addressed to a specific agent."""
        with self._lock:
            return [m for m in self._messages if m["to"] == agent_name or m["to"] == "all"]

    def get_context_summary(self, exclude_agent: str = "") -> str:
        """Generate a context summary from all agents' shared knowledge."""
        with self._lock:
            parts = []
            for agent_name, data in self._store.items():
                if agent_name == exclude_agent:
                    continue
                parts.append(f"\n### Knowledge from [{agent_name}]:")
                for key, value in data.items():
                    if isinstance(value, str):
                        parts.append(f"**{key}**: {value[:2000]}")
                    elif isinstance(value, list):
                        parts.append(f"**{key}**: {len(value)} items")
                        for item in value[:5]:
                            parts.append(f"  - {str(item)[:200]}")
                    elif isinstance(value, dict):
                        parts.append(f"**{key}**: {str(value)[:500]}")
            return "\n".join(parts)


class BaseAgent:
    """
    Base class for all security analysis agents.
    Provides: LLM access, reasoning chains, shared memory, skill loading.
    """

    name: str = "base_agent"
    role: str = "Base Security Agent"
    description: str = "A generic security analysis agent"

    def __init__(self, llm: LLMProvider, memory: SharedMemory, skills_dir=None):
        self.llm = llm
        self.memory = memory
        self.skills_dir = skills_dir
        self.reasoning_log: List[str] = []

    def think(self, thought: str):
        """Log an internal reasoning step."""
        self.reasoning_log.append(f"[{self.name}] 💭 {thought}")

    def conclude(self, conclusion: str):
        """Log a conclusion."""
        self.reasoning_log.append(f"[{self.name}] ✅ {conclusion}")

    def share_knowledge(self, key: str, value):
        """Share a piece of knowledge with other agents via shared memory."""
        self.memory.write(self.name, key, value)

    def read_peer_knowledge(self, peer_name: str = None, key: str = None):
        """Read knowledge from peer agents."""
        if peer_name:
            return self.memory.read(peer_name, key)
        return self.memory.read_all()

    def get_peer_context(self) -> str:
        """Get summarized context from all peer agents."""
        return self.memory.get_context_summary(exclude_agent=self.name)

    def send_to_agent(self, to_agent: str, message: str, msg_type: str = "info"):
        """Send a message to another agent."""
        self.memory.send_message(self.name, to_agent, message, msg_type)

    def get_my_messages(self) -> List[dict]:
        """Read messages from other agents."""
        return self.memory.get_messages(self.name)

    def load_skill(self, skill_filename: str) -> str:
        """Load a skill prompt from the skills directory."""
        if not self.skills_dir:
            return ""
        skill_path = self.skills_dir / skill_filename
        if not skill_path.exists():
            return ""
        with open(skill_path, 'r', encoding='utf-8') as f:
            return f.read()

    def run_with_reasoning(self, prompt: str, system_prompt: str = None) -> str:
        """Run LLM with chain-of-thought reasoning and log the process."""
        self.think(f"Analyzing with prompt ({len(prompt)} chars)")
        sys_prompt = system_prompt or f"You are {self.role}. {self.description}"
        response = self.llm.reason(prompt, system=sys_prompt)
        self.conclude(f"Analysis complete ({len(response)} chars response)")
        return response

    def run_skill(self, skill_filename: str, code_context: str, extra_context: str = "") -> str:
        """Run a specific skill against code with optional extra context."""
        skill_prompt = self.load_skill(skill_filename)
        if not skill_prompt:
            return f"Skill '{skill_filename}' not found."

        prompt = f"Target Codebase:\n<CODE>\n{code_context}\n</CODE>\n\n"
        if extra_context:
            prompt += f"Previous Knowledge & Context:\n<CONTEXT>\n{extra_context}\n</CONTEXT>\n\n"
        prompt += """Execute your specific analysis skill on the target codebase. Think step-by-step.

IMPORTANT: Pay special attention to the SECURITY-RELEVANT CONFIGURATION FILES section at the top of the code — check for hardcoded secrets, weak settings, missing security controls, and dangerous defaults.

For EACH vulnerability you find, you MUST output it using EXACTLY this format:

VULNERABILITY:
- Title: [specific descriptive title]
- Severity: [CRITICAL/HIGH/MEDIUM/LOW]
- CWE: [CWE-xxx]
- OWASP: [relevant category]
- File: [exact file path from the code]
- Line: [line number]
- Description: [what is wrong and the security impact]
- Code Evidence: [the vulnerable code/setting]
- Remediation: [how to fix it]
- Fixed Code: [corrected code]

If you find NO vulnerabilities, say: "No vulnerabilities found for this skill."
Do NOT use any other format. Do NOT use markdown headers or numbered lists for findings."""

        return self.llm.reason(prompt, system=skill_prompt)

    def execute(self, scan_result: ScanResult, code_context: str) -> dict:
        """Main execution method — must be implemented by subclasses."""
        raise NotImplementedError("Subclasses must implement execute()")

    def get_reasoning_log(self) -> str:
        """Return the full reasoning log."""
        return "\n".join(self.reasoning_log)
