import os
from pathlib import Path
from .constants import SKILLS_DIR, LAYER_1_SKILLS, LAYER_2_SKILLS, LAYER_3_SKILLS, LAYER_4_SKILLS
from .llm_provider import LLMProvider

class SASTOrchestrator:
    def __init__(self, target_code: str, model_name: str = None, gemini_key: str = None, openai_key: str = None):
        self.target_code = target_code
        self.provider = LLMProvider(model=model_name, gemini_key=gemini_key, openai_key=openai_key) if model_name else LLMProvider(gemini_key=gemini_key, openai_key=openai_key)

    def _load_skill(self, skill_filename: str) -> str:
        skill_path = SKILLS_DIR / skill_filename
        if not skill_path.exists():
            return f"Skill module '{skill_filename}' not found."
        with open(skill_path, 'r', encoding='utf-8') as f:
            return f.read()
    def _chunk_target_code(self, target_code: str, max_chars: int = 150000) -> list:
        chunks = []
        current_chunk = ""
        # Assuming parser separates files by "--- "
        parts = target_code.split("--- ")
        for part in parts:
            if not part.strip(): continue
            block = "--- " + part
            if len(current_chunk) + len(block) > max_chars and current_chunk:
                chunks.append(current_chunk)
                current_chunk = block
            else:
                current_chunk += block
        if current_chunk:
            chunks.append(current_chunk)
        return chunks if chunks else [target_code]

    def run_layer(self, layer_skills: list, additional_context: str = ""):
        import time
        results = {}
        chunks = self._chunk_target_code(self.target_code)
        
        for skill in layer_skills:
            print(f"[*] Executing Agent Skill: {skill} (across {len(chunks)} chunks)...")
            system_prompt = self._load_skill(skill)
            
            if "not found" in system_prompt:
                print(f"[-] Skipping missing skill: {skill}")
                results[skill] = "Skill module not implemented."
                continue
            
            skill_findings = []
            for idx, chunk in enumerate(chunks):
                if len(chunks) > 1:
                    print(f"    -> Processing chunk {idx+1}/{len(chunks)}")
                    
                prompt = f"Target Codebase Sector ({idx+1}/{len(chunks)}):\n<CODE>\n{chunk}\n</CODE>\n\n"
                if additional_context:
                    prompt += f"Previous Findings (Context):\n<PREVIOUS_FINDINGS>\n{additional_context}\n</PREVIOUS_FINDINGS>\n\n"
                    
                prompt += (
                    "Execute your specific analysis skill on this portion of the codebase. "
                    "Return ONLY the list of vulnerabilities found using bullet points. "
                    "DO NOT include any main titles, headers (like '# Security Findings Summary' or '# Report'), "
                    "introductions, or conversational text. Just the findings. "
                    "If you find nothing relevant, explicitly state exactly 'NO VULNERABILITIES FOUND' to save tokens."
                )
                
                response = self.provider.generate(prompt=prompt, system=system_prompt)
                
                # Simple heuristic to drop useless responses and save token aggregation size
                if "NO VULNERABILITIES" not in response.upper() and "NO FINDINGS" not in response.upper() and len(response.strip()) > 30:
                    skill_findings.append(response.strip())
                
                time.sleep(1) # Rate limit protection
                
            results[skill] = "\n\n".join(skill_findings) if skill_findings else "No critical findings in this layer."
            time.sleep(2) # Cooldown between skills
            
        return results

    def analyze(self):
        print(f"\n{'='*50}\n[Phase 1] Core Engine Recognition Layer\n{'='*50}")
        layer_1_results = self.run_layer(LAYER_1_SKILLS)
        
        # Summarize Layer 1 context for Layer 2
        l1_context = "\n".join([f"[{k}]: {v}" for k, v in layer_1_results.items()])
        
        print(f"\n{'='*50}\n[Phase 2] Security Domain Vulnerability Detection\n{'='*50}")
        layer_2_results = self.run_layer(LAYER_2_SKILLS, additional_context=l1_context)
        
        # Summarize Layer 2 findings for Layer 3 (Precision filtering)
        l2_context = "\n".join([f"[{k}]: {v}" for k, v in layer_2_results.items() if "Skill module not implemented" not in v])
        
        print(f"\n{'='*50}\n[Phase 3] Advanced Precision & False Positive Filtering\n{'='*50}")
        layer_3_results = self.run_layer(LAYER_3_SKILLS, additional_context=l2_context)
            
        # Summarize Layer 3 findings for Layer 4 (Validation)
        l3_context = "\n".join([f"[{k}]: {v}" for k, v in layer_3_results.items() if "Skill module not implemented" not in v])
        
        print(f"\n{'='*50}\n[Phase 4] Report Auditor & Final Validation\n{'='*50}")
        layer_4_results = {}
        for skill in LAYER_4_SKILLS:
            print(f"[*] Executing Agent Skill: {skill}...")
            system_prompt = self._load_skill(skill)
            if "not found" in system_prompt:
                print(f"[-] Skipping missing skill: {skill}")
                layer_4_results[skill] = "Skill module not implemented."
                continue
            
            prompt = f"Previous Findings (Context):\n<PREVIOUS_FINDINGS>\n{l3_context}\n</PREVIOUS_FINDINGS>\n\n"
            prompt += (
                "Execute your report formatting skill based on the above findings. "
                "Return ONLY the ordered list of vulnerabilities with their details. "
                "DO NOT include any main titles, headers (like '# Security Findings Summary' or '# Report'), "
                "introductions, or conversational text. Just the list of findings."
            )
            
            response = self.provider.generate(prompt=prompt, system=system_prompt)
            layer_4_results[skill] = response
            
        return {
            "layer_1": layer_1_results,
            "layer_2": layer_2_results,
            "layer_3": layer_3_results,
            "layer_4": layer_4_results
        }
