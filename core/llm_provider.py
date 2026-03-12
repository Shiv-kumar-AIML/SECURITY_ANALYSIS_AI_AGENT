"""
Enhanced LLM Provider with multi-backend support.
Supports: Ollama (local), Google Gemini (cloud), OpenAI-compatible (cloud)
Features: retry logic, structured JSON output, streaming, context management.
"""
import json
import time
import urllib.request
import urllib.error
from typing import Optional
from .constants import DEFAULT_OLLAMA_HOST, DEFAULT_MODEL


class LLMProvider:
    """Multi-backend LLM provider with reasoning support."""

    def __init__(self, host=DEFAULT_OLLAMA_HOST, model=DEFAULT_MODEL,
                 gemini_key=None, openai_key=None, openai_base_url=None, llm_provider=None):
        self.host = host
        self.model = model
        self.gemini_key = gemini_key
        self.openai_key = openai_key
        self.openai_base_url = openai_base_url or "https://api.openai.com/v1"
        self.api_url = f"{self.host}/api/generate"
        self.total_tokens = 0
        self.total_calls = 0

        # Determine llm_provider
        if llm_provider:
            self.llm_provider = llm_provider.lower()
            if self.llm_provider == "gemini":
                import google.generativeai as genai
                genai.configure(api_key=self.gemini_key)
                if "gemini" not in self.model.lower():
                    self.model = "gemini-2.5-flash"
        elif self.openai_key:
            self.llm_provider = "openai"
        elif self.gemini_key:
            self.llm_provider = "gemini"
            import google.generativeai as genai
            genai.configure(api_key=self.gemini_key)
            if "gemini" not in self.model.lower():
                self.model = "gemini-2.5-flash"
        else:
            self.llm_provider = "ollama"

    def generate(self, prompt: str,
                 system: str = "You are an enterprise-grade security analysis agent.",
                 temperature: float = 0.1,
                 json_mode: bool = False,
                 max_retries: int = 3) -> str:
        """Generate a response with automatic retry and backend routing."""
        last_error = None

        for attempt in range(max_retries):
            try:
                if self.llm_provider == "openai":
                    result = self._generate_openai(prompt, system, temperature, json_mode)
                elif self.llm_provider == "gemini":
                    result = self._generate_gemini(prompt, system, temperature)
                else:
                    result = self._generate_ollama(prompt, system, temperature, json_mode)

                self.total_calls += 1
                return result

            except Exception as e:
                last_error = e
                if attempt < max_retries - 1:
                    wait_time = (2 ** attempt) + 1
                    time.sleep(wait_time)

        return f"Error after {max_retries} attempts: {last_error}"

    def reason(self, prompt: str,
               system: str = "You are an enterprise-grade security analysis agent.",
               temperature: float = 0.1) -> str:
        """Generate with chain-of-thought reasoning instruction prepended."""
        reasoning_wrapper = (
            "Think through this step-by-step using the following reasoning framework:\n\n"
            "## REASONING CHAIN\n"
            "1. **OBSERVE**: What code patterns, data flows, and structures do you see?\n"
            "2. **HYPOTHESIZE**: What potential security issues could exist here?\n"
            "3. **TRACE**: Trace the data flow from source to sink. Is user input sanitized?\n"
            "4. **VALIDATE**: Can this actually be exploited? What are the preconditions?\n"
            "5. **CLASSIFY**: What is the severity (CRITICAL/HIGH/MEDIUM/LOW/INFO)?\n"
            "6. **CONCLUDE**: State your final findings with evidence.\n\n"
            "---\n\n"
            f"{prompt}"
        )
        return self.generate(reasoning_wrapper, system=system, temperature=temperature)

    def _generate_openai(self, prompt: str, system: str, temperature: float, json_mode: bool) -> str:
        """OpenAI-compatible API backend."""
        try:
            from openai import OpenAI
            client = OpenAI(api_key=self.openai_key, base_url=self.openai_base_url)

            kwargs = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": prompt}
                ],
                "temperature": temperature,
                "max_tokens": 16384,
            }
            if json_mode:
                kwargs["response_format"] = {"type": "json_object"}

            response = client.chat.completions.create(**kwargs)
            return response.choices[0].message.content or ""

        except Exception as e:
            raise RuntimeError(f"OpenAI API error: {e}")

    def _generate_gemini(self, prompt: str, system: str, temperature: float) -> str:
        """Google Gemini API backend."""
        try:
            import google.generativeai as genai
            model = genai.GenerativeModel(self.model, system_instruction=system)
            response = model.generate_content(
                prompt,
                generation_config=genai.types.GenerationConfig(temperature=temperature)
            )
            return response.text
        except Exception as e:
            raise RuntimeError(f"Gemini API error: {e}")

    def _generate_ollama(self, prompt: str, system: str, temperature: float, json_mode: bool) -> str:
        """Local Ollama API backend."""
        data = {
            "model": self.model,
            "prompt": prompt,
            "system": system,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_ctx": 32768
            }
        }
        if json_mode:
            data["format"] = "json"

        req = urllib.request.Request(
            self.api_url,
            data=json.dumps(data).encode('utf-8'),
            headers={'Content-Type': 'application/json'}
        )

        try:
            with urllib.request.urlopen(req, timeout=300) as response:
                result = json.loads(response.read().decode('utf-8'))
                return result.get("response", "")
        except Exception as e:
            raise RuntimeError(f"Ollama error at {self.host}: {e}. Ensure Ollama is running and model '{self.model}' is pulled.")

    @property
    def llm_provider_display(self) -> str:
        names = {
            "openai": "OpenAI API",
            "gemini": "Google Gemini",
            "ollama": "Local Ollama",
        }
        return names.get(self.llm_provider, self.llm_provider)
