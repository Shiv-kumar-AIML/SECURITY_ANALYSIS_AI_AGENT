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
from .constants import DEFAULT_OLLAMA_HOST, DEFAULT_OLLAMA_MODEL, DEFAULT_OPENAI_MODEL, DEFAULT_GEMINI_MODEL


class LLMProvider:
    """Multi-backend LLM provider with reasoning support."""

    def __init__(self, host=DEFAULT_OLLAMA_HOST, model=None,
                 gemini_key=None, openai_key=None, openai_base_url=None, llm_provider=None):
        self.host = host
        self.gemini_key = gemini_key
        self.openai_key = openai_key
        self.openai_base_url = openai_base_url or "https://api.openai.com/v1"
        self.api_url = f"{self.host}/api/generate"
        self.total_tokens = 0
        self.total_calls = 0

        # Determine llm_provider
        if llm_provider:
            self.llm_provider = llm_provider.lower()
        elif self.openai_key:
            self.llm_provider = "openai"
        elif self.gemini_key:
            self.llm_provider = "gemini"
        else:
            self.llm_provider = "ollama"

        # Determine model
        self.model = model
        if not self.model:
            if self.llm_provider == "openai":
                self.model = DEFAULT_OPENAI_MODEL
            elif self.llm_provider == "gemini":
                self.model = DEFAULT_GEMINI_MODEL
            else:
                self.model = DEFAULT_OLLAMA_MODEL

        # Configure Google Gemini if needed
        if self.llm_provider == "gemini":
            import google.generativeai as genai
            genai.configure(api_key=self.gemini_key)
            if "gemini" not in self.model.lower():
                self.model = DEFAULT_GEMINI_MODEL

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
                "max_tokens": 32768,  # Increased for unified skills which produce longer analysis
            }
            if json_mode:
                kwargs["response_format"] = {"type": "json_object"}

            response = client.chat.completions.create(**kwargs)

            # Track token usage
            if hasattr(response, 'usage') and response.usage:
                self.total_tokens += response.usage.total_tokens
            self.total_calls += 1

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

            # Track token usage (approximate)
            if hasattr(response, 'usage_metadata') and response.usage_metadata:
                # Gemini provides input/output token counts
                input_tokens = getattr(response.usage_metadata, 'prompt_token_count', 0)
                output_tokens = getattr(response.usage_metadata, 'candidates_token_count', 0)
                self.total_tokens += input_tokens + output_tokens
            self.total_calls += 1

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
                "num_ctx": 65536  # Increased for unified skills which use larger system prompts
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

                # Track token usage with better estimation
                output_tokens = result.get("eval_count", 0)
                
                # Estimate input tokens (rough approximation: ~4 chars per token)
                input_text = system + "\n\n" + prompt if system else prompt
                estimated_input_tokens = len(input_text) // 4
                
                # Total tokens = input + output
                total_tokens = estimated_input_tokens + output_tokens
                self.total_tokens += total_tokens
                
                self.total_calls += 1

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

    def get_token_stats(self) -> dict:
        """Get token usage statistics."""
        return {
            "total_tokens": self.total_tokens,
            "total_calls": self.total_calls,
            "provider": self.llm_provider
        }
