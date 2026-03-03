<div align="center">
  <img src="https://img.shields.io/badge/Status-Active-success?style=for-the-badge&logoColor=white" />
  <img src="https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/Engine-LLM_Reasoning-purple?style=for-the-badge&logo=openai&logoColor=white" />
  <img src="https://img.shields.io/badge/License-Apache_2.0-red?style=for-the-badge&logoColor=white" />
  <img src="https://img.shields.io/badge/Contributions-Welcome-brightgreen?style=for-the-badge&logoColor=white" />
  
  <h1>🛡️ Pentas-Agent</h1>
  <p><strong>Enterprise-Grade, Multi-Agent AI Security Vulnerability Detection Engine</strong></p>
  
  <p>
    An intelligent SAST/SCA scanner that doesn't just pattern-match, it <strong>reasons</strong>. 
    By combining traditional security tools with specialized AI methodology engines, Pentas-Agent 
    traces dataflows, verifies exploitability, and dynamically eliminates false positives.
  </p>
</div>

---

## 📸 See it in Action (Agent Workflow)

Pentas-Agent provides a rich, color-coded CLI interface that guides you through every step of the deep security analysis.

<details>
<summary><b>🔍 Phase 1: Scan Configuration & Codebase Parsing</b></summary>

<br>
The agent begins by extracting abstract syntax trees (ASTs) and structuring the scan configuration.
<div align="center">
  <img src="./assets/scan_cli.png" alt="Scan Configuration CLI Menu" width="800" />
</div>

</details>

<details>
<summary><b>🛠️ Phase 1 (Cont.): Reconnaissance & External Tools Execution</b></summary>

<br>
It runs standard tools like `semgrep`, `bandit`, `trivy`, and `npm_audit` in the background, building a threat model from the output.
<div align="center">
  <img src="./assets/phase_1.png" alt="Reconnaissance and Tools Phase" width="800" />
</div>

</details>

<details>
<summary><b>🧠 Phase 2: Deep Vulnerability Analysis (Methodology Reasoning)</b></summary>

<br>
The Vulnerability Agent iterates through 12+ specialized methodology engines (SQLi, Auth Logic, Prototype Pollution, etc.) to perform reasoning-based security checks.
<div align="center">
  <img src="./assets/phase_2.png" alt="Deep Analysis Phase" width="800" />
</div>

</details>

<details>
<summary><b>🧹 Phase 3 & 4: Remediation and False Positive Filtering</b></summary>

<br>
The agent generates context-aware fixes and then aggressively filters out test files, safe constants, and unexploitable code paths to leave only **genuine** findings.
<div align="center">
  <img src="./assets/phase_3.png" alt="Verification and FP Filtering Phase" width="800" />
</div>

</details>

<details>
<summary><b>📊 Phase 5: Scan Complete (Summary & Dashboard)</b></summary>

<br>
A clear color-coded summary of CRITICAL, HIGH, MEDIUM, and LOW vulnerabilities.
<div align="center">
  <img src="./assets/summary.png" alt="Findings Summary" width="800" />
</div>

</details>

<details>
<summary><b>📄 Phase 6: Automated Report Generation</b></summary>

<br>
The tool automatically generates Markdown, JSON, and SARIF reports directly into the `/reports` folder.
<div align="center">
  <img src="./assets/reports.png" alt="Generated Reports" width="800" />
</div>

</details>

---

## 🌟 Why Pentas-Agent?

Traditional scanners (like standard Semgrep or Checkmarx) produce thousands of false positives because they rely on static grep-like patterns. **Pentas-Agent is different.**

- 🧠 **Methodology-Based Skills**: Instead of looking for `eval(...)`, the agent traces the dataflow: *Did this input come from an HTTP request? Was it sanitized by Zod? Did it reach the eval sink?*
- 🎭 **Multi-Agent Architecture**: Dedicated AI agents for Reconnaissance, Deep Analysis, Verification (False Positive Reduction), and Remediation.
- 🛡️ **Framework-Aware**: Automatically recognizes safety mechanisms in Drizzle ORM, Django ORM, Express auto-escaping, Fastify schemas, etc.
- 🧹 **Aggressive False Positive Filtering**: Dramatically reduces alert fatigue by eliminating test files, trusted constants, and dead code endpoints.

---

## 🏗️ How It Works (The Multi-Agent Flow)

Pentas-Agent operates in a highly orchestrated 6-phase pipeline. Here is the architecture flow from raw code to verified security report:

```mermaid
graph TD
    classDef agent fill:#1e3a8a,stroke:#3b82f6,stroke-width:2px,color:#fff;
    classDef tool fill:#047857,stroke:#10b981,stroke-width:2px,color:#fff;
    classDef phase fill:#374151,stroke:#6b7280,stroke-width:2px,color:#fff,font-weight:bold;
    classDef report fill:#9d174d,stroke:#f43f5e,stroke-width:2px,color:#fff;
    classDef subg fill:none,stroke:#4b5563,stroke-width:2px,stroke-dasharray: 5 5;

    A["Raw Source Code"] --> B{"Phase 1: Recon & Tools"}:::phase
    
    subgraph P1["Data Collection"]
        direction TB
        B --> C["Recon Agent: AST & Threat Model"]:::agent
        B --> D["Traditional Tools: Semgrep, Trivy, npm audit"]:::tool
    end
    class P1 subg

    C & D --> E{"Phase 2: Deep Analysis"}:::phase
    
    subgraph P2["Vulnerability Reasoning"]
        direction TB
        E --> F["Vulnerability Agent"]:::agent
        F --> G[("12+ Methodology Skills")]:::tool
        G -.->|"Dataflow Taint"| F
        G -.->|"Auth Logic Check"| F
        G -.->|"SQLi Tracing"| F
    end
    class P2 subg

    F --> H{"Phase 3: Remediation"}:::phase
    H --> I["Remediation Agent: Context-Aware Fixes"]:::agent

    I --> J{"Phase 4: Verification"}:::phase

    subgraph P4["False Positive Filtering"]
        direction TB
        J --> K["Verifier Agent"]:::agent
        K --> L["Rule-Based Filters"]
        K --> M["LLM FP Reduction Engine"]
    end
    class P4 subg

    K --> N{"Phase 5: Reporting"}:::phase
    
    subgraph P5["Outputs"]
        N --> O["Markdown (.md)"]:::report
        N --> P["JSON Format"]:::report
        N --> Q["SARIF Format"]:::report
    end
    class P5 subg
```

---

## 🧠 The "Brain" of the Agent (Methodology Engine)

The core intelligence lives in the `skills/` directory. These are not regex rules; they are **Step-by-Step Methodologies** taught to the LLM. 

| Skill Category | Description of Analysis |
|----------------|-------------------------|
| **Dataflow Taint** | Identifies `SOURCES` (user input) -> traces `FLOW` -> verifies absence of `SANITIZERS` -> confirms reaching dangerous `SINKS`. |
| **Auth Logic** | Maps all routes, checks authorization depth, hunts for IDORs, and finds mass-assignment paths. |
| **Web Misconfig** | Enforces checks on CORS origin handling, Rate Limiting presence, Security Headers, and Static File exposure. |
| **Secret Detection** | Differentiates between securely externalized `process.env` keys and dangerously hardcoded production secrets. |
| **Dependency SCA** | Analyzes whether a vulnerable dependency is *actually reachable* and loaded in production (vs. dev-only). |

---

## 🚀 Installation & Usage

### 1. Prerequisites
- Python 3.10+
- `semgrep`, `trivy`, and `npm` installed in your system PATH.

### 2. Setup
```bash
# Clone the repository
git clone https://github.com/Shiv-kumar-AIML/SECURITY_ANALYSIS_AI_AGENT.git
cd SECURITY_ANALYSIS_AI_AGENT

# Install Python dependencies
pip install -r requirements.txt
```

### 3. Running Scans

To start a full multi-agent scan, run the CLI. You can target local directories or remote Git repositories.

**Scan a Local Project:**
```bash
python main.py /path/to/local/project --openai-key sk-xxxx --model gpt-4.1-mini
```

**Scan a GitHub Repository (with authentication for private repos):**
```bash
python main.py https://ghp_YourAccessTokenHere@github.com/organization/private-repo.git \
  --openai-key sk-xxxx \
  --model gpt-4.1-nano
```

---

## 🤝 Contributing to Pentas-Agent (For Developers & Engineers)

We heavily encourage contributions from the open-source community! Whether you want to add new methodologies, integrate new static analysis tools, or improve the LLM reasoning pipeline, your help is appreciated.

### 🛠️ Development Environment Setup

1. **Fork & Clone**: Fork the repo and clone it locally.
2. **Virtual Environment**: Ensure you are using Python 3.10+. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate
   ```
3. **Install Requirements**: 
   ```bash
   pip install -r requirements.txt
   ```
4. **Tool Installations**: Ensure global binary tools are accessible in your environment path:
   - `semgrep`: Required for static code analysis.
   - `trivy`: Required for container, IaC, and dependency scans.
   - `npm`: Required for running `npm audit` on target Node.js projects.

### 🧠 Creating New AI Security Skills
Pentas-Agent separates security logic from core Python code. You don't need to write Python strings or complex AST parsers to add a brand-new security check!

1. Open the `skills/` directory.
2. Create a new markdown file mimicking `sast-path-traversal-engine.md`.
3. **Focus on Methodology**: Do not provide strict regex patterns. Instead, explain step-by-step *how* a human auditor would trace the vulnerability. Provide instructions on identifying sources, sinks, and sanitizers.
4. Add your new skill file name to the appropriate array (e.g., `LAYER_2_SKILLS`) in `core/constants.py`.

### 🔄 Pull Request Process
1. Create a feature branch (`git checkout -b feature/amazing-skill`).
2. Test your changes locally on purposefully vulnerable target repositories (like `test_repo/vuln.js` or OWASP Juice Shop).
3. If editing core Python agents (`core/agents/*.py`), ensure you don't break the existing multi-agent `orchestrator.py` flow.
4. Open a PR with a clear description of the vulnerability your new skill addresses or the system bug you fixed.

---

## 📄 Output Reports

After the scan sequence is complete, the results are natively stored in the `reports/` folder:
- **Markdown (`.md`)**: Beautiful, human-readable formatting with actual code blocks and step-by-step remediation snippets.
- **JSON (`.json`)**: Raw structured data representing exact coordinates of the vulnerability.
- **SARIF (`.sarif.json`)**: Industry standard file format for direct integrations into GitHub Advanced Security (GHAS) or GitLab CI.

---

<div align="center">
  <p>Built for precision. Designed for production. 🛡️</p>
</div>
