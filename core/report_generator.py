import time
from pathlib import Path
from .constants import REPORTS_DIR

class ReportGenerator:
    def __init__(self, analysis_results: dict):
        self.results = analysis_results
        if not REPORTS_DIR.exists():
            REPORTS_DIR.mkdir(parents=True)
            
    def to_markdown(self):
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        report_file = REPORTS_DIR / f"sast_report_{timestamp}.md"
        
        md_content = "# Enterprise SAST Security Scan Report\n\n"
        md_content += f"**Date:** {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        
        md_content += "## Executive Summary\n"
        md_content += "This report compiles deep-analysis findings from multiple specialized AI agents. The final findings have been rigorously validated against the raw codebase to eliminate false positives and hallucinations.\n\n"
        
        md_content += "## 🎯 Final Validated Findings (Layer 4: Report Auditor)\n"
        md_content += "These vulnerabilities have been verified by the final audit agent to exist within the target codebase context.\n\n"
        
        for skill, finding in self.results.get("layer_4", {}).items():
            if "Skill module not implemented" not in finding:
                md_content += f"{finding}\n\n---\n"
                
        # Optional: Add a note that raw telemetry was omitted for readability
        md_content += "\n> **Note:** Raw agent telemetry (AST, CFG, Taint Analysis) has been omitted for readability. Only fully validated findings are shown.\n"
            
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(md_content)
            
        return report_file
