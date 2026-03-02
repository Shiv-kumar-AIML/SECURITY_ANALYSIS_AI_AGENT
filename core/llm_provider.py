import json
import urllib.request
import urllib.error
import google.generativeai as genai
import openai
from .constants import DEFAULT_OLLAMA_HOST, DEFAULT_MODEL

class LLMProvider:
    def __init__(self, host=DEFAULT_OLLAMA_HOST, model=DEFAULT_MODEL, gemini_key=None, openai_key=None):
        self.host = host
        self.model = model
        self.gemini_key = gemini_key
        self.openai_key = openai_key
        self.api_url = f"{self.host}/api/generate"
        
        if self.gemini_key:
            genai.configure(api_key=self.gemini_key)
            # Default to gemini-2.5-flash if user requests gemini but didn't specify a precise gemini model
            if "gemini" not in self.model.lower():
                self.model = "gemini-2.5-flash"
                
        if self.openai_key:
            self.openai_client = openai.OpenAI(api_key=self.openai_key)
            if "gpt" not in self.model.lower() and "o1" not in self.model.lower() and "o3" not in self.model.lower():
                self.model = "gpt-4o-mini"

    def generate(self, prompt, system="You are an enterprise-grade SAST analysis agent.", temperature=0.1):
        if self.openai_key:
            return self._generate_openai(prompt, system, temperature)
        elif self.gemini_key:
            return self._generate_gemini(prompt, system, temperature)
        else:
            return self._generate_ollama(prompt, system, temperature)
            
    def _generate_gemini(self, prompt, system, temperature):
        try:
            model = genai.GenerativeModel(self.model, system_instruction=system)
            response = model.generate_content(
                prompt,
                generation_config=genai.types.GenerationConfig(temperature=temperature)
            )
            return response.text
        except Exception as e:
            error_msg = f"Error connecting to Gemini API: {e}."
            print(f"[-] {error_msg}")
            return f"Error: {e}"

    def _generate_openai(self, prompt, system, temperature):
        try:
            response = self.openai_client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": prompt}
                ],
                temperature=temperature
            )
            return response.choices[0].message.content
        except Exception as e:
            error_msg = f"Error connecting to OpenAI API: {e}."
            print(f"[-] {error_msg}")
            return f"Error: {e}"

    def _generate_ollama(self, prompt, system, temperature):
        data = {
            "model": self.model,
            "prompt": prompt,
            "system": system,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_ctx": 32768 # Large context window for deep code analysis, dependent on model support
            }
        }
        req = urllib.request.Request(self.api_url, data=json.dumps(data).encode('utf-8'),
                                     headers={'Content-Type': 'application/json'})
        
        try:
            with urllib.request.urlopen(req) as response:
                result = json.loads(response.read().decode('utf-8'))
                return result.get("response", "")
        except urllib.error.URLError as e:
            error_msg = f"Error connecting to Ollama at {self.host}: {e}. Ensure Ollama is running and model '{self.model}' is pulled."
            print(f"[-] {error_msg}")
            return f"Error: {e}"
