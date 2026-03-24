"""
FastAPI webhook server for GitHub App integration.
Receives PR events and runs security analysis.
"""
import os
import json
import logging
import shutil
import tempfile
import subprocess
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Request, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse
from pydantic_settings import BaseSettings
from pydantic import Field

from backend.github_service import GitHubService

# ──────────────────────────────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────────────────────────────


class Settings(BaseSettings):
    """Application settings from environment variables."""

    github_app_id: str = Field(default="", alias="GITHUB_APP_ID")
    github_private_key_path: str = Field(
        default="backend/private-key.pem", alias="GITHUB_PRIVATE_KEY_PATH"
    )
    github_webhook_secret: str = Field(default="", alias="GITHUB_WEBHOOK_SECRET")

    # Optional: LLM settings for security scanning
    llm_provider: Optional[str] = Field(default=None, alias="LLM_PROVIDER")
    openai_api_key: Optional[str] = Field(default=None, alias="OPENAI_API_KEY")
    gemini_api_key: Optional[str] = Field(default=None, alias="GEMINI_API_KEY")
    openai_base_url: Optional[str] = Field(default=None, alias="OPENAI_BASE_URL")
    ollama_host: Optional[str] = Field(default="http://localhost:11434", alias="OLLAMA_HOST")
    openai_model: Optional[str] = Field(default="gpt-4o", alias="OPENAI_MODEL")
    gemini_model: Optional[str] = Field(default="gemini-2.5-pro", alias="GEMINI_MODEL")
    ollama_model: Optional[str] = Field(default="qwen2.5-coder:latest", alias="OLLAMA_MODEL")

    # Server
    debug: bool = Field(default=False, alias="DEBUG")

    class Config:
        env_file = ".env"
        case_sensitive = False
        extra = "ignore"  # Ignore any extra fields not defined


# ──────────────────────────────────────────────────────────────────────
# Setup
# ──────────────────────────────────────────────────────────────────────

settings = Settings()

# Configure logging
logging.basicConfig(level=logging.DEBUG if settings.debug else logging.INFO)
logger = logging.getLogger(__name__)

# Initialize GitHub service
try:
    github_service = GitHubService(
        app_id=settings.github_app_id,
        private_key_path=settings.github_private_key_path,
        webhook_secret=settings.github_webhook_secret,
    )
except Exception as e:
    logger.error(f"Failed to initialize GitHub service: {e}")
    github_service = None

# Create FastAPI app
app = FastAPI(
    title="Security Analysis Agent",
    description="GitHub App for automated security scanning on PRs",
    version="1.0.0",
)


# ──────────────────────────────────────────────────────────────────────
# Routes
# ──────────────────────────────────────────────────────────────────────


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "ok",
        "github_app_configured": github_service is not None,
    }


@app.get("/_stcore/health")
async def streamlit_health():
    """Streamlit health check (suppress 404 errors)."""
    return {"status": "ok"}


@app.get("/_stcore/host-config")
async def streamlit_host_config():
    """Streamlit host config (suppress 404 errors)."""
    return {}


@app.post("/github/webhook")
async def handle_webhook(request: Request, background_tasks: BackgroundTasks):
    """
    GitHub webhook endpoint.
    Receives PR events and triggers security analysis.
    """
    # Check if GitHub service is configured
    if github_service is None:
        logger.error("GitHub service not configured. Check GITHUB_APP_ID and private key path.")
        raise HTTPException(status_code=503, detail="GitHub service not configured")

    # Get raw body for signature verification
    raw_body = await request.body()
    signature = request.headers.get("X-Hub-Signature-256", "")
    event_type = request.headers.get("X-GitHub-Event", "")

    # Verify webhook signature
    if not github_service.verify_webhook_signature(raw_body, signature):
        logger.warning("Invalid webhook signature")
        raise HTTPException(status_code=401, detail="Invalid signature")

    # Parse payload
    try:
        payload = json.loads(raw_body)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    logger.info(f"Received webhook event: {event_type}")

    # Handle pull_request events
    if event_type == "pull_request":
        action = payload.get("action")

        # Trigger analysis on these actions
        if action in ("opened", "synchronize", "reopened"):
            logger.info(f"PR action: {action} — scheduling analysis")

            # Run analysis in background
            background_tasks.add_task(
                analyze_pr,
                payload,
            )

            return {"status": "analysis scheduled"}

    return {"status": "ignored"}


async def analyze_pr(payload: dict):
    """
    Analyze PR for security vulnerabilities.
    Background task.
    """
    try:
        # Extract PR details
        pr = payload["pull_request"]
        repo = payload["repository"]

        owner = repo["owner"]["login"]
        repo_name = repo["name"]
        pull_number = pr["number"]
        installation_id = payload["installation"]["id"]

        logger.info(f"\n{'='*80}")
        logger.info(f"🔍 FULL SECURITY ANALYSIS: {owner}/{repo_name} PR #{pull_number}")
        logger.info(f"{'='*80}")

        # Get installation token
        token = github_service.get_installation_token(installation_id)

        # Clone the repo with authentication
        clone_url = repo["clone_url"]
        # Insert token for authenticated clone (works for private repos)
        if clone_url.startswith("https://"):
            auth_clone_url = clone_url.replace("https://", f"https://x-access-token:{token}@")
        else:
            auth_clone_url = clone_url

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)

            # Clone at PR's head with authentication
            head_ref = pr["head"]["ref"]
            logger.info(f"Cloning {clone_url} (branch: {head_ref})")  # Log without token

            # Shallow clone directly to the PR branch (most efficient)
            result = subprocess.run(
                ["git", "clone", "--depth=1", "--branch", head_ref, auth_clone_url, str(tmpdir)],
                capture_output=True,
                timeout=120,
            )

            # If direct branch clone fails (branch doesn't exist on remote yet or other issues),
            # fall back to cloning default branch and then fetching the PR ref
            if result.returncode != 0:
                logger.info(f"Direct branch clone failed, falling back to fetch method...")

                # Clean up any partial clone before retrying
                if tmpdir.exists():
                    shutil.rmtree(tmpdir, ignore_errors=True)
                    tmpdir.mkdir(parents=True, exist_ok=True)

                # Clone default branch
                subprocess.run(
                    ["git", "clone", "--depth=1", auth_clone_url, str(tmpdir)],
                    check=True,
                    capture_output=True,
                    timeout=120,
                )

                # Fetch the PR branch and create a local branch from FETCH_HEAD
                subprocess.run(
                    ["git", "-C", str(tmpdir), "fetch", "origin", head_ref, "--depth=1"],
                    capture_output=True,
                    timeout=60,
                )

                # Checkout using FETCH_HEAD (the fetched ref) and create local branch
                subprocess.run(
                    ["git", "-C", str(tmpdir), "checkout", "-b", head_ref, "FETCH_HEAD"],
                    check=True,
                    capture_output=True,
                    timeout=60,
                )
            else:
                logger.info(f"Successfully cloned branch: {head_ref}")

            # Get changed files
            files = github_service.get_pr_files(
                owner, repo_name, pull_number, token
            )

            logger.info(f"Found {len(files)} changed files")

            # Filter to supported file types
            source_files = [
                f for f in files
                if f["status"] != "removed"
                and f["filename"].endswith((
                    ".py", ".js", ".ts", ".tsx", ".java", ".go", ".rb",
                    ".php", ".cs", ".cpp", ".c", ".h", ".yaml", ".yml",
                    ".json", ".xml", ".dockerfile"
                ))
            ]

            if not source_files:
                logger.info("No supported source files changed")

                # Post review (APPROVE since no code to scan)
                comment_body = "✅ No supported source files changed in this PR."
                head_commit = pr["head"]["sha"]
                github_service.post_pr_review(
                    owner, repo_name, pull_number, comment_body, "APPROVE", token, head_commit
                )
                return

            logger.info(f"🔧 Analyzing {len(source_files)} source files\n")

            # Run FULL security scan (with LLM, remediation, etc)
            try:
                scan_result = run_security_scan(str(tmpdir))

                if scan_result is None:
                    logger.info("No code to analyze")
                    comment_body = "✅ **No supported source code to analyze.**"
                    head_commit = pr["head"]["sha"]
                    github_service.post_pr_review(
                        owner, repo_name, pull_number, comment_body, "APPROVE", token, head_commit
                    )
                    return

                # Get confirmed findings
                confirmed = scan_result.get_confirmed()
                confirmed_count = len(confirmed)

                logger.info(f"\n{'='*80}")
                logger.info(f"✅ SCAN COMPLETE: {confirmed_count} findings detected")
                logger.info(f"{'='*80}\n")

                # Generate detailed reports using CORE ReportGenerator
                from core.report_generator import ReportGenerator as CoreReportGenerator

                report_paths = {}

                if confirmed_count > 0:
                    logger.info("📄 Generating detailed reports...")
                    report_gen = CoreReportGenerator(scan_result)

                    # Generate all report formats (methods return Path objects)
                    report_paths["markdown"] = str(report_gen.to_markdown())
                    report_paths["json"] = str(report_gen.to_json())
                    report_paths["sarif"] = str(report_gen.to_sarif())

                    logger.info(f"✅ Generated reports:")
                    for fmt, path in report_paths.items():
                        logger.info(f"   • {fmt.upper()}: {path}")

                # Post findings as PR review (shows prominently at top)
                comment_body = format_scan_results_from_scanresult(scan_result, len(source_files), report_paths)
                logger.info(f"\n💬 Posting security analysis review to PR...")

                # Determine review event based on severity
                severity_counts = scan_result.severity_counts
                if severity_counts.get("CRITICAL", 0) > 0 or severity_counts.get("HIGH", 0) > 0:
                    review_event = "REQUEST_CHANGES"
                else:
                    review_event = "COMMENT"

                # Get PR head commit for review
                head_commit = pr["head"]["sha"]

                response = github_service.post_pr_review(
                    owner, repo_name, pull_number, comment_body, review_event, token, head_commit
                )

                logger.info(f"✅ Review posted successfully ({review_event})!")
                logger.info(f"{'='*80}\n")

            except Exception as e:
                logger.error(f"\n❌ Scan failed: {e}", exc_info=True)

                # Post error as review comment
                error_comment = (
                    "⚠️ **Security analysis encountered an error:**\n\n"
                    f"```\n{str(e)}\n```\n\n"
                    "Please check server logs for details."
                )
                head_commit = pr["head"]["sha"]
                github_service.post_pr_review(
                    owner, repo_name, pull_number, error_comment, "COMMENT", token, head_commit
                )
                logger.info(f"{'='*80}\n")

    except Exception as e:
        logger.error(f"Failed to analyze PR: {e}", exc_info=True)


def run_security_scan(target_path: str):
    """
    Run security scan on target code using FULL AGENT mode.

    Args:
        target_path: Path to code directory

    Returns:
        ScanResult object with all analysis
    """
    from core.parser import CodeParser
    from core.orchestrator import SASTOrchestrator

    logger.info(f"Running FULL AGENT analysis on {target_path}")

    # Parse code with context extraction
    parser = CodeParser(target_path)
    parsed_data = parser.extract_smart_context()
    target_code = parsed_data.get("context", "")

    if not target_code:
        logger.warning("No code to analyze")
        return None

    logger.info(f"Code parsed: {len(target_code)} chars, {len(parsed_data)} metadata")

    # Run FULL AGENT analysis (not tools-only!)
    orchestrator = SASTOrchestrator(
        target_code=target_code,
        target_path=target_path,
        model_name=settings.openai_model or "gpt-4o-mini",
        openai_key=settings.openai_api_key,
        llm_provider=settings.llm_provider or "openai",
    )

    logger.info("Starting multi-phase analysis...")

    # FULL AGENT ANALYSIS (with LLM, remediation, verification)
    scan_result = orchestrator.analyze()

    # Get confirmed findings
    confirmed = scan_result.get_confirmed()

    logger.info(f"Analysis complete: {len(confirmed)} confirmed findings")

    return scan_result


def format_scan_results_from_scanresult(scan_result, files_changed: int, report_paths: dict = None) -> str:
    """
    Format ScanResult as GitHub comment with FULL INLINE DETAILS.

    Args:
        scan_result: ScanResult object from orchestrator
        files_changed: Number of changed files
        report_paths: Dict of report file paths (json, markdown, sarif)

    Returns:
        Formatted comment body with complete finding details
    """
    if report_paths is None:
        report_paths = {}

    confirmed = scan_result.get_confirmed()
    confirmed_count = len(confirmed)

    if confirmed_count == 0:
        return (
            f"✅ **Security Analysis Complete**\n\n"
            f"Scanned {files_changed} file(s) — "
            f"**0 findings** detected."
        )

    # Build findings summary grouped by severity
    by_severity = {}
    for finding in confirmed:
        sev = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)
        if sev not in by_severity:
            by_severity[sev] = []
        by_severity[sev].append(finding)

    # Start with summary header
    comment = (
        f"🔍 **Security Analysis Results**\n\n"
        f"Scanned {files_changed} file(s) — **{confirmed_count} finding(s)** detected\n\n"
    )

    # Summary counts by severity
    comment += "## Summary\n\n"
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    for severity in severity_order:
        if severity in by_severity:
            count = len(by_severity[severity])
            emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(severity, "")
            comment += f"- {emoji} **{severity}**: {count}\n"

    comment += "\n---\n\n"
    comment += "## Detailed Findings\n\n"

    # Show FULL details for findings (limit to prevent GitHub comment size issues)
    MAX_DETAILED_FINDINGS = 15  # Show max 15 detailed findings
    total_shown = 0

    for severity in severity_order:
        if severity not in by_severity or total_shown >= MAX_DETAILED_FINDINGS:
            continue

        findings_list = by_severity[severity]
        emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(severity, "")
        comment += f"### {emoji} {severity} Severity\n\n"

        for idx, finding in enumerate(findings_list, 1):
            if total_shown >= MAX_DETAILED_FINDINGS:
                remaining = confirmed_count - total_shown
                comment += f"\n... and {remaining} more finding(s). Check local reports for full details.\n"
                break

            # Finding header
            comment += f"#### {idx}. {finding.title}\n\n"
            comment += f"**Location:** `{finding.file_path}:{finding.line_number}`  \n"
            comment += f"**Severity:** {severity}\n\n"

            # Description
            if finding.description:
                comment += f"**Description:**  \n{finding.description}\n\n"

            # Vulnerable code snippet
            if finding.code_snippet:
                comment += "**Vulnerable Code:**\n```python\n"
                # Limit code snippet to 15 lines to keep comment readable
                code_lines = finding.code_snippet.strip().split('\n')[:15]
                comment += '\n'.join(code_lines)
                if len(finding.code_snippet.strip().split('\n')) > 15:
                    comment += "\n... (truncated)"
                comment += "\n```\n\n"

            # Additional context (CWE, OWASP, confidence)
            metadata = []
            if finding.cwe_id:
                metadata.append(f"CWE: {finding.cwe_id}")
            if finding.owasp_category:
                metadata.append(f"OWASP: {finding.owasp_category}")
            if finding.confidence > 0:
                metadata.append(f"Confidence: {finding.confidence:.0%}")

            if metadata:
                comment += f"**Details:** {' | '.join(metadata)}\n\n"

            # Remediation
            if finding.remediation or finding.remediation_code:
                comment += "**Remediation:**\n"
                if finding.remediation:
                    comment += f"{finding.remediation}\n\n"
                if finding.remediation_code:
                    comment += "**Fixed Code:**\n```python\n"
                    code_lines = finding.remediation_code.strip().split('\n')[:15]
                    comment += '\n'.join(code_lines)
                    if len(finding.remediation_code.strip().split('\n')) > 15:
                        comment += "\n... (truncated)"
                    comment += "\n```\n\n"

            comment += "---\n\n"
            total_shown += 1

    # Footer with local report paths (for developer reference)
    if report_paths:
        comment += "\n## 📋 Local Reports Generated\n\n"
        comment += "_These files are available on your local machine:_\n\n"
        if report_paths.get("markdown"):
            comment += f"- 📝 Markdown: `{report_paths['markdown']}`\n"
        if report_paths.get("json"):
            comment += f"- 📊 JSON: `{report_paths['json']}`\n"
        if report_paths.get("sarif"):
            comment += f"- 🔧 SARIF: `{report_paths['sarif']}`\n"

    return comment


def format_scan_results(scan_result: dict, files_changed: int, report_paths: dict = None) -> str:
    """
    Format scan results as GitHub comment.

    Args:
        scan_result: Scan results from analyze_pr
        files_changed: Number of changed files
        report_paths: Dict of report file paths (json, markdown, html)

    Returns:
        Formatted comment body
    """
    if report_paths is None:
        report_paths = {}

    status = scan_result.get("status", "unknown")

    if status == "no_code":
        return "✅ **No supported source code to analyze.**"

    confirmed = scan_result.get("confirmed", 0)
    findings = scan_result.get("findings", [])

    if confirmed == 0:
        return (
            f"✅ **Security Analysis Complete**\n\n"
            f"Scanned {files_changed} file(s) — "
            f"**0 findings** detected."
        )

    # Build findings summary grouped by severity
    by_severity = {}
    for finding in findings:
        sev = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)
        if sev not in by_severity:
            by_severity[sev] = []
        by_severity[sev].append(finding)

    comment = (
        f"🔍 **Security Analysis Results**\n\n"
        f"Scanned {files_changed} file(s) — **{confirmed} finding(s)** detected:\n\n"
    )

    # Show findings by severity level
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    for severity in severity_order:
        if severity in by_severity:
            findings_list = by_severity[severity]
            count = len(findings_list)
            comment += f"### {severity} ({count})\n"

            # Show first 3 of each severity, then "and X more"
            for f in findings_list[:3]:
                comment += (
                    f"- **{f.title}** "
                    f"(`{f.file_path}:{f.line_number}`)\n"
                )

            if count > 3:
                comment += f"- ... and {count - 3} more **{severity}** finding(s)\n"

            comment += "\n"

    # Add report links
    comment += "📋 **Full Reports**:\n"
    if report_paths.get("json"):
        comment += f"- [📊 JSON Report]({report_paths['json']})\n"
    if report_paths.get("markdown"):
        comment += f"- [📝 Markdown Report]({report_paths['markdown']})\n"
    if report_paths.get("html"):
        comment += f"- [🌐 HTML Report]({report_paths['html']})\n"

    return comment


# ──────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "webhook_server:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.debug,
        log_level="debug" if settings.debug else "info",
    )
