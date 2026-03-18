"""Streamlit UI for GitHub-login based repo scanning with incremental/full modes.

Flow:
1) Login with GitHub (OAuth device flow)
2) Show user repos on home screen
3) Clone/update selected repo
4) Run incremental scan by default (full mode from env-supported toggle)
5) Generate markdown report and convert it to PDF
"""

from __future__ import annotations

import base64
import hashlib
import os
import secrets
import sqlite3
import subprocess
import textwrap
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Callable
import re

import streamlit as st

from core.constants import BASE_DIR, DEFAULT_OPENAI_MODEL, WORKSPACE_DIR
from core.findings import ScanResult
from core.orchestrator import SASTOrchestrator
from core.parser import CodeParser
from core.report_generator import ReportGenerator
from core.scan_cache import ScanCache


APP_DB_PATH = BASE_DIR / ".app_users.db"


def _strip_rich_markup(text: str) -> str:
    """Convert rich-marked text to plain terminal-style text."""
    cleaned = re.sub(r"\[[^\]]+\]", "", text)
    return cleaned.replace("\u2192", "->").strip()


class StreamlitScanConsole:
    """Minimal console adapter to show coordinator logs in Streamlit."""

    def __init__(self, emit_line: Callable[[str], None]):
        self.emit_line = emit_line

    def print(self, *args, **kwargs) -> None:
        if not args:
            self.emit_line("")
            return

        text = " ".join(str(a) for a in args)
        lines = text.splitlines() or [""]
        for line in lines:
            self.emit_line(_strip_rich_markup(line))

    def rule(self, text: str = "") -> None:
        header = _strip_rich_markup(text)
        bar = "=" * 72
        self.emit_line(bar)
        if header:
            self.emit_line(header)
        self.emit_line(bar)


def init_app_db() -> None:
    """Create app auth database if missing."""
    with sqlite3.connect(APP_DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS app_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                github_login TEXT DEFAULT '',
                github_token TEXT DEFAULT '',
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS app_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            )
            """
        )
        conn.commit()


def _hash_password(password: str, salt: str) -> str:
    return hashlib.sha256(f"{salt}:{password}".encode("utf-8")).hexdigest()


def create_app_user(username: str, password: str) -> tuple[bool, str]:
    """Create a local platform user."""
    username = username.strip().lower()
    if len(username) < 3:
        return False, "Username minimum 3 characters hona chahiye."
    if len(password) < 8:
        return False, "Password minimum 8 characters hona chahiye."

    salt = secrets.token_hex(16)
    pwd_hash = _hash_password(password, salt)
    now = int(time.time())

    try:
        with sqlite3.connect(APP_DB_PATH) as conn:
            conn.execute(
                """
                INSERT INTO app_users (username, password_hash, password_salt, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (username, pwd_hash, salt, now, now),
            )
            conn.commit()
        return True, "Signup successful. Ab login karein."
    except sqlite3.IntegrityError:
        return False, "Ye username already exists."


def authenticate_app_user(username: str, password: str) -> tuple[bool, str]:
    """Validate local platform user credentials."""
    username = username.strip().lower()
    with sqlite3.connect(APP_DB_PATH) as conn:
        row = conn.execute(
            "SELECT password_hash, password_salt FROM app_users WHERE username = ?",
            (username,),
        ).fetchone()

    if not row:
        return False, "User not found."

    expected_hash, salt = row
    if _hash_password(password, salt) != expected_hash:
        return False, "Invalid password."

    return True, "Login successful."


def load_user_github_auth(username: str) -> tuple[str, str]:
    """Return persisted GitHub (login, token) for a local app user."""
    with sqlite3.connect(APP_DB_PATH) as conn:
        row = conn.execute(
            "SELECT github_login, github_token FROM app_users WHERE username = ?",
            (username.strip().lower(),),
        ).fetchone()

    if not row:
        return "", ""
    return str(row[0] or ""), str(row[1] or "")


def save_user_github_auth(username: str, github_login: str, github_token: str) -> None:
    """Persist GitHub token once so user does not need repeated OAuth login."""
    now = int(time.time())
    with sqlite3.connect(APP_DB_PATH) as conn:
        conn.execute(
            """
            UPDATE app_users
            SET github_login = ?, github_token = ?, updated_at = ?
            WHERE username = ?
            """,
            (github_login, github_token, now, username.strip().lower()),
        )
        conn.commit()


def clear_user_github_auth(username: str) -> None:
    """Clear persisted GitHub auth when token becomes invalid or user disconnects."""
    now = int(time.time())
    with sqlite3.connect(APP_DB_PATH) as conn:
        conn.execute(
            """
            UPDATE app_users
            SET github_login = '', github_token = '', updated_at = ?
            WHERE username = ?
            """,
            (now, username.strip().lower()),
        )
        conn.commit()


def get_app_setting(key: str, default: str = "") -> str:
    """Read a global app setting from SQLite."""
    with sqlite3.connect(APP_DB_PATH) as conn:
        row = conn.execute("SELECT value FROM app_settings WHERE key = ?", (key,)).fetchone()
    if not row:
        return default
    return str(row[0] or default)


def set_app_setting(key: str, value: str) -> None:
    """Upsert a global app setting into SQLite."""
    now = int(time.time())
    with sqlite3.connect(APP_DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO app_settings (key, value, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET
                value = excluded.value,
                updated_at = excluded.updated_at
            """,
            (key, value, now),
        )
        conn.commit()


def _github_get(token: str, endpoint: str, params: dict | None = None) -> dict | list:
    """Call GitHub REST API with bearer token authentication."""
    query = ""
    if params:
        query = "?" + urllib.parse.urlencode(params)

    req = urllib.request.Request(
        url=f"https://api.github.com{endpoint}{query}",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "security-analysis-streamlit-ui",
        },
    )

    with urllib.request.urlopen(req, timeout=30) as response:
        payload = response.read().decode("utf-8")
        import json

        return json.loads(payload)


def get_authenticated_user(token: str) -> dict:
    data = _github_get(token, "/user")
    if not isinstance(data, dict):
        raise ValueError("Invalid GitHub user payload.")
    return data


def list_user_repos(token: str) -> list[dict]:
    """Fetch all repos visible to the authenticated user (paginated)."""
    repos: list[dict] = []
    page = 1

    while True:
        batch = _github_get(
            token,
            "/user/repos",
            params={
                "per_page": 100,
                "page": page,
                "sort": "updated",
                "direction": "desc",
                "affiliation": "owner,collaborator,organization_member",
            },
        )

        if not isinstance(batch, list):
            raise ValueError("Invalid GitHub repository payload.")

        repos.extend(batch)
        if len(batch) < 100:
            break
        page += 1

    return repos


def _github_post_form(url: str, data: dict) -> dict:
    """Send x-www-form-urlencoded POST and parse JSON response."""
    encoded = urllib.parse.urlencode(data).encode("utf-8")
    req = urllib.request.Request(
        url=url,
        data=encoded,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "security-analysis-streamlit-ui",
        },
        method="POST",
    )

    with urllib.request.urlopen(req, timeout=30) as response:
        import json

        return json.loads(response.read().decode("utf-8"))


def start_github_device_login(client_id: str, scope: str = "repo read:user") -> dict:
    """Start GitHub OAuth device flow and return device metadata."""
    return _github_post_form(
        "https://github.com/login/device/code",
        {
            "client_id": client_id,
            "scope": scope,
        },
    )


def poll_github_device_token(client_id: str, device_code: str, interval_seconds: int, max_wait_seconds: int = 180) -> str:
    """Poll GitHub OAuth token endpoint until user finishes login."""
    deadline = time.time() + max_wait_seconds
    interval = max(2, int(interval_seconds or 5))

    while time.time() < deadline:
        payload = _github_post_form(
            "https://github.com/login/oauth/access_token",
            {
                "client_id": client_id,
                "device_code": device_code,
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            },
        )

        if "access_token" in payload:
            return str(payload["access_token"])

        err = str(payload.get("error", ""))
        if err == "authorization_pending":
            time.sleep(interval)
            continue
        if err == "slow_down":
            interval += 2
            time.sleep(interval)
            continue
        if err == "expired_token":
            raise RuntimeError("Login session expired. Please start GitHub login again.")
        if err == "access_denied":
            raise RuntimeError("GitHub login denied by user.")

        raise RuntimeError(f"GitHub login failed: {err or 'unknown_error'}")

    raise RuntimeError("Timed out waiting for GitHub login confirmation.")


def _git_auth_prefix(token: str | None) -> list[str]:
    """Return git auth args without writing token to repository remotes."""
    if not token:
        return ["git"]
    # Git over HTTPS expects basic auth; use x-access-token:<token>.
    basic = base64.b64encode(f"x-access-token:{token}".encode("utf-8")).decode("ascii")
    return ["git", "-c", f"http.extraheader=AUTHORIZATION: basic {basic}"]


def clone_or_update_repo(repo: dict, token: str | None, incremental: bool) -> Path:
    """Clone first time; update existing clone before scan."""
    owner_repo = repo.get("full_name", "repo")
    repo_slug = owner_repo.replace("/", "__")
    local_path = WORKSPACE_DIR / repo_slug
    clone_url = str(repo.get("clone_url", ""))

    WORKSPACE_DIR.mkdir(parents=True, exist_ok=True)

    if local_path.exists():
        git_prefix = _git_auth_prefix(token)
        # Keep local mirror fresh for both scan modes.
        fetch_result = subprocess.run(git_prefix + ["-C", str(local_path), "fetch", "origin"], check=False, capture_output=True, text=True)
        pull_cmd = git_prefix + ["-C", str(local_path), "pull", "--ff-only"]
        pull_result = subprocess.run(pull_cmd, check=False, capture_output=True, text=True)

        # If token auth fails for public repo, retry without auth.
        if (fetch_result.returncode != 0 or pull_result.returncode != 0) and not repo.get("private"):
            subprocess.run(["git", "-C", str(local_path), "fetch", "origin"], check=False, capture_output=True)
            pull_result = subprocess.run(["git", "-C", str(local_path), "pull", "--ff-only"], check=False, capture_output=True, text=True)

        # In full mode, if ff-only fails, still scan local code.
        # In incremental mode, try to sync with remote head if diverged.
        if incremental and pull_result.returncode != 0:
            subprocess.run(["git", "-C", str(local_path), "reset", "--hard", "origin/HEAD"], check=False, capture_output=True)

        return local_path

    clone_cmd = _git_auth_prefix(token) + ["clone", clone_url, str(local_path)]
    result = subprocess.run(clone_cmd, check=False, capture_output=True, text=True)
    if result.returncode != 0 and not repo.get("private"):
        # Public repo fallback: retry clone without auth header.
        result = subprocess.run(["git", "clone", clone_url, str(local_path)], check=False, capture_output=True, text=True)

    if result.returncode != 0:
        stderr = (result.stderr or "").strip()
        raise RuntimeError(f"Git clone failed: {stderr[:400]}")

    return local_path


def _run_scan_pipeline(
    target_path: str,
    incremental: bool,
    model_name: str,
    openai_key: str,
    openai_base_url: str | None,
    progress: Callable[[str], None],
    console: StreamlitScanConsole | None = None,
) -> tuple[Path, Path | None, ScanResult]:
    """Run scan and return (markdown_report, pdf_report, scan_result)."""
    code_parser = CodeParser(target_path)
    scan_cache = ScanCache(target_path)

    cached_findings = []
    files_to_rescan = None

    if incremental:
        if scan_cache.is_warm():
            changed, added, deleted = scan_cache.compute_diff()

            if not changed and not added and not deleted:
                progress("No changed files detected. Reusing cached findings.")
                if console:
                    console.print("[+] Incremental mode: no changed files, using cached findings")
                scan_result = ScanResult(target_path=target_path)
                for finding in scan_cache.get_cached_findings([]):
                    scan_result.add_finding(finding)
                scan_result.scan_end = scan_result.scan_start

                md_path = ReportGenerator(scan_result).to_markdown()
                pdf_path: Path | None = None
                try:
                    pdf_path = markdown_to_pdf(md_path)
                except ModuleNotFoundError:
                    if console:
                        console.print("[!] PDF skipped: reportlab is not installed")
                if console:
                    console.print(f"[+] Report generated: {md_path}")
                    if pdf_path:
                        console.print(f"[+] PDF generated: {pdf_path}")
                return md_path, pdf_path, scan_result

            files_to_rescan = changed + added
            cached_findings = scan_cache.get_cached_findings(files_to_rescan + deleted)
            progress(f"Incremental scan: rescanning {len(files_to_rescan)} changed files.")
            if console:
                console.print(f"[*] Incremental diff -> changed/add: {len(files_to_rescan)}, deleted: {len(deleted)}")
        else:
            progress("No scan cache found. Running baseline full scan once.")
            if console:
                console.print("[*] Incremental requested but cache not found, running baseline full scan")

    if console:
        console.rule("Parsing Target Codebase")
    if files_to_rescan is not None:
        target_code = code_parser.extract_context_for_files(files_to_rescan)
        if console:
            console.print(f"[+] Context built from changed files: {len(files_to_rescan)}")
    else:
        smart_context = code_parser.extract_smart_context()
        target_code = smart_context["context"]
        if console:
            meta = smart_context.get("metadata", {})
            if meta.get("used_fallback"):
                console.print(f"[!] Smart context fallback: {meta.get('fallback_reason', 'unknown')}")
            else:
                console.print(f"[+] Smart context functions: {meta.get('functions_selected', 0)}/{meta.get('functions_total', 0)}")

    if not target_code:
        raise RuntimeError("No supported source files found in selected repository.")

    progress("Running AI vulnerability analysis...")
    orchestrator = SASTOrchestrator(
        target_code=target_code,
        target_path=target_path,
        model_name=model_name,
        openai_key=openai_key,
        openai_base_url=openai_base_url,
        llm_provider="openai",
    )
    scan_result = orchestrator.analyze(console=console)

    if cached_findings:
        for finding in cached_findings:
            scan_result.add_finding(finding)
        if console:
            console.print(f"[+] Merged cached findings: {len(cached_findings)}")

    if incremental or not scan_cache.is_warm():
        scan_cache.save(scan_result.get_confirmed())
        if console:
            console.print("[+] Scan cache updated")

    progress("Generating markdown report...")
    md_path = ReportGenerator(scan_result).to_markdown()
    if console:
        console.print(f"[+] Markdown report: {md_path}")

    progress("Converting markdown report to PDF...")
    pdf_path: Path | None = None
    try:
        pdf_path = markdown_to_pdf(md_path)
    except ModuleNotFoundError:
        if console:
            console.print("[!] PDF skipped: reportlab is not installed")
    if console:
        if pdf_path:
            console.print(f"[+] PDF report: {pdf_path}")
        console.rule("Scan Complete")
    return md_path, pdf_path, scan_result


def markdown_to_pdf(markdown_path: Path) -> Path:
    """Convert markdown report into a readable text-based PDF."""
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas

    pdf_path = markdown_path.with_suffix(".pdf")
    markdown = markdown_path.read_text(encoding="utf-8", errors="ignore")

    _, page_height = A4
    left_margin = 40
    top_margin = 50
    bottom_margin = 50

    c = canvas.Canvas(str(pdf_path), pagesize=A4)
    y = page_height - top_margin

    def ensure_space(lines_needed: int, line_height: int) -> None:
        nonlocal y
        if y - (lines_needed * line_height) < bottom_margin:
            c.showPage()
            y = page_height - top_margin

    in_code_block = False

    for raw_line in markdown.splitlines():
        line = raw_line.rstrip("\n")

        if line.strip().startswith("```"):
            in_code_block = not in_code_block
            continue

        if in_code_block:
            c.setFont("Courier", 8)
            wrapped = textwrap.wrap(line, width=105) or [""]
            ensure_space(len(wrapped), 10)
            for part in wrapped:
                c.drawString(left_margin + 8, y, part)
                y -= 10
            continue

        if line.startswith("# "):
            c.setFont("Helvetica-Bold", 16)
            content = line[2:].strip()
            wrapped = textwrap.wrap(content, width=75) or [""]
            ensure_space(len(wrapped), 20)
            for part in wrapped:
                c.drawString(left_margin, y, part)
                y -= 20
            y -= 4
            continue

        if line.startswith("## "):
            c.setFont("Helvetica-Bold", 13)
            content = line[3:].strip()
            wrapped = textwrap.wrap(content, width=90) or [""]
            ensure_space(len(wrapped), 16)
            for part in wrapped:
                c.drawString(left_margin, y, part)
                y -= 16
            y -= 2
            continue

        if line.startswith("### "):
            c.setFont("Helvetica-Bold", 11)
            content = line[4:].strip()
            wrapped = textwrap.wrap(content, width=95) or [""]
            ensure_space(len(wrapped), 14)
            for part in wrapped:
                c.drawString(left_margin, y, part)
                y -= 14
            continue

        c.setFont("Helvetica", 9)
        prefix = ""
        content = line
        if line.startswith("- "):
            prefix = "- "
            content = line[2:]

        wrapped = textwrap.wrap(content, width=108) or [""]
        ensure_space(len(wrapped), 12)
        for i, part in enumerate(wrapped):
            draw_text = f"{prefix}{part}" if i == 0 else part
            c.drawString(left_margin, y, draw_text)
            y -= 12

        if not content.strip():
            y -= 4

    c.save()
    return pdf_path


def _env_default_scan_mode() -> str:
    """Pick default scan mode from env; fallback to incremental."""
    mode = os.getenv("SCAN_MODE", "incremental").strip().lower()
    if mode in {"full", "incremental"}:
        return mode

    # Support boolean-style env for convenience.
    force_full = os.getenv("FULL_SCAN", "false").strip().lower()
    if force_full in {"1", "true", "yes", "on"}:
        return "full"

    return "incremental"


def main() -> None:
    st.set_page_config(
        page_title="Security Analysis UI",
        page_icon="SAST",
        layout="wide",
        initial_sidebar_state="collapsed",
    )
    init_app_db()

    st.title("Security Analysis Agent")
    st.caption("Create platform account once, connect GitHub once, and start scans without repeated OAuth prompts.")

    if "app_authenticated" not in st.session_state:
        st.session_state.app_authenticated = False
    if "app_username" not in st.session_state:
        st.session_state.app_username = ""
    if "repos" not in st.session_state:
        st.session_state.repos = []
    if "user_login" not in st.session_state:
        st.session_state.user_login = ""
    if "github_token" not in st.session_state:
        st.session_state.github_token = ""
    if "selected_repo_full_name" not in st.session_state:
        st.session_state.selected_repo_full_name = ""
    if "device_flow" not in st.session_state:
        st.session_state.device_flow = {}
    if "github_oauth_client_id" not in st.session_state:
        st.session_state.github_oauth_client_id = ""

    env_client_id = os.getenv("GITHUB_OAUTH_CLIENT_ID", "").strip()
    stored_client_id = get_app_setting("github_oauth_client_id", "")
    if not st.session_state.github_oauth_client_id:
        if env_client_id:
            st.session_state.github_oauth_client_id = env_client_id
        elif stored_client_id:
            st.session_state.github_oauth_client_id = stored_client_id

    openai_key = os.getenv("OPENAI_API_KEY", "").strip()
    openai_base_url = os.getenv("OPENAI_BASE_URL", "").strip() or None

    def load_repos_with_token(token: str) -> None:
        user = get_authenticated_user(token)
        repos = list_user_repos(token)
        st.session_state.github_token = token
        st.session_state.user_login = user.get("login", "")
        st.session_state.repos = repos

    def logout_app() -> None:
        st.session_state.app_authenticated = False
        st.session_state.app_username = ""
        st.session_state.github_token = ""
        st.session_state.user_login = ""
        st.session_state.repos = []
        st.session_state.selected_repo_full_name = ""
        st.session_state.device_flow = {}

    if not st.session_state.app_authenticated:
        st.subheader("Step 1: Create account or login")
        tab_signup, tab_login = st.tabs(["Sign up", "Login"])

        with tab_signup:
            with st.form("signup_form", clear_on_submit=False):
                su_username = st.text_input("Username")
                su_password = st.text_input("Password", type="password")
                su_submit = st.form_submit_button("Create account", use_container_width=True)
                if su_submit:
                    ok, msg = create_app_user(su_username, su_password)
                    if ok:
                        st.success(msg)
                    else:
                        st.error(msg)

        with tab_login:
            with st.form("login_form", clear_on_submit=False):
                li_username = st.text_input("Username", key="login_username")
                li_password = st.text_input("Password", type="password", key="login_password")
                li_submit = st.form_submit_button("Login", use_container_width=True)
                if li_submit:
                    ok, msg = authenticate_app_user(li_username, li_password)
                    if ok:
                        uname = li_username.strip().lower()
                        st.session_state.app_authenticated = True
                        st.session_state.app_username = uname

                        saved_login, saved_token = load_user_github_auth(uname)
                        if saved_token:
                            try:
                                load_repos_with_token(saved_token)
                                st.session_state.user_login = saved_login or st.session_state.user_login
                            except Exception:
                                clear_user_github_auth(uname)
                                st.session_state.github_token = ""
                                st.session_state.repos = []

                        st.success(msg)
                        st.rerun()
                    else:
                        st.error(msg)
        return

    top1, top2 = st.columns([4, 1])
    top1.success(f"App user: {st.session_state.app_username}")
    if top2.button("Logout", use_container_width=True):
        logout_app()
        st.rerun()

    if not st.session_state.github_token:
        st.subheader("Step 2: Connect GitHub")
        entered_client_id = st.text_input(
            "GitHub OAuth Client ID",
            value=st.session_state.github_oauth_client_id,
            help="GitHub OAuth app ka client id daalein.",
        ).strip()
        if entered_client_id != st.session_state.github_oauth_client_id:
            st.session_state.github_oauth_client_id = entered_client_id

        # Persist once so user does not need to enter it again.
        if st.session_state.github_oauth_client_id:
            set_app_setting("github_oauth_client_id", st.session_state.github_oauth_client_id)

        client_id = st.session_state.github_oauth_client_id
        if not client_id:
            st.warning("OAuth Client ID required hai.")
            st.info("Client ID ko env me bhi set kar sakte hain: GITHUB_OAUTH_CLIENT_ID")
            return

        if st.button("Login with GitHub", type="primary", use_container_width=True):
            try:
                flow = start_github_device_login(client_id)
                verify_uri = str(flow.get("verification_uri", "https://github.com/login/device"))
                user_code = str(flow.get("user_code", ""))
                st.info(f"GitHub Code: {user_code}")
                st.link_button("Open GitHub Login Page", verify_uri, use_container_width=True)

                with st.spinner("Waiting for GitHub authorization..."):
                    token = poll_github_device_token(
                        client_id=client_id,
                        device_code=str(flow.get("device_code", "")),
                        interval_seconds=int(flow.get("interval", 5) or 5),
                        max_wait_seconds=int(flow.get("expires_in", 900) or 900),
                    )

                load_repos_with_token(token)
                save_user_github_auth(
                    st.session_state.app_username,
                    st.session_state.user_login,
                    token,
                )
                st.success("GitHub connected. Next login se dubara OAuth nahi maangega.")
                st.rerun()
            except Exception as exc:
                st.error(f"GitHub login failed: {exc}")
        return

    repos: list[dict] = st.session_state.repos
    if not repos:
        try:
            load_repos_with_token(st.session_state.github_token)
            repos = st.session_state.repos
        except Exception:
            clear_user_github_auth(st.session_state.app_username)
            st.session_state.github_token = ""
            st.warning("Saved GitHub session expired. Please connect GitHub again.")
            st.rerun()

    row1, row2, row3 = st.columns([3, 1, 1])
    row1.info(f"GitHub connected as: {st.session_state.user_login}")
    if row2.button("Refresh Repos", use_container_width=True):
        try:
            load_repos_with_token(st.session_state.github_token)
            save_user_github_auth(st.session_state.app_username, st.session_state.user_login, st.session_state.github_token)
            st.success("Repository list refreshed.")
            st.rerun()
        except Exception as exc:
            st.error(f"Refresh failed: {exc}")
    if row3.button("Disconnect GitHub", use_container_width=True):
        clear_user_github_auth(st.session_state.app_username)
        st.session_state.github_token = ""
        st.session_state.user_login = ""
        st.session_state.repos = []
        st.session_state.selected_repo_full_name = ""
        st.rerun()

    selected_name = st.session_state.selected_repo_full_name
    if not selected_name:
        st.subheader("Choose repository")
        repo_search = st.text_input("Search repository", value="")
        filtered = repos
        if repo_search.strip():
            needle = repo_search.strip().lower()
            filtered = [r for r in repos if needle in str(r.get("full_name", "")).lower()]

        st.caption("Repository par click karein. Fir scan options screen open hogi.")
        cols = st.columns(3)
        for idx, repo in enumerate(filtered):
            with cols[idx % 3]:
                full_name = str(repo.get("full_name", ""))
                private_tag = "Private" if repo.get("private") else "Public"
                st.markdown(f"**{full_name}**")
                st.caption(f"{private_tag} | Updated: {repo.get('updated_at', 'n/a')}")
                if st.button("Open", key=f"open_repo_{full_name}", use_container_width=True):
                    st.session_state.selected_repo_full_name = full_name
                    st.rerun()
        if not filtered:
            st.warning("No repositories match your search.")
        return

    selected_repo = next((r for r in repos if r.get("full_name") == selected_name), None)
    if not selected_repo:
        st.session_state.selected_repo_full_name = ""
        st.rerun()

    st.subheader(f"Step 3: Scan options - {selected_name}")
    openai_model = st.text_input("Model", value=os.getenv("OPENAI_MODEL", DEFAULT_OPENAI_MODEL))
    default_mode = _env_default_scan_mode()
    scan_mode = st.radio(
        "Scan mode",
        options=["incremental", "full"],
        index=0 if default_mode == "incremental" else 1,
        horizontal=True,
    )

    back_col, scan_col = st.columns(2)
    if back_col.button("Back to Repositories", use_container_width=True):
        st.session_state.selected_repo_full_name = ""
        st.rerun()
    run_scan = scan_col.button("Start Scan", type="primary", use_container_width=True)

    if not run_scan:
        return

    if not openai_key:
        st.error("OPENAI_API_KEY server env me set hona chahiye. UI me key input disabled hai.")
        return

    incremental = scan_mode == "incremental"
    progress_placeholder = st.empty()
    st.markdown("### Live Scan Logs")
    logs_box = st.empty()
    scan_logs: list[str] = []

    def emit_log(line: str) -> None:
        ts = time.strftime("%H:%M:%S")
        safe_line = line if line else " "
        scan_logs.append(f"[{ts}] {safe_line}")
        logs_box.code("\n".join(scan_logs[-350:]), language="bash")

    console = StreamlitScanConsole(emit_log)

    def progress_update(message: str) -> None:
        progress_placeholder.info(message)
        emit_log(f"[*] {message}")

    try:
        emit_log("[+] Scan initiated")
        emit_log(f"[+] Target repository: {selected_name}")
        emit_log(f"[+] Scan mode: {'incremental' if incremental else 'full'}")

        with st.spinner("Preparing repository..."):
            local_repo = clone_or_update_repo(selected_repo, st.session_state.github_token, incremental=incremental)
            emit_log(f"[+] Repository ready: {local_repo}")

        with st.spinner("Running security scan..."):
            md_path, pdf_path, scan_result = _run_scan_pipeline(
                target_path=str(local_repo),
                incremental=incremental,
                model_name=openai_model,
                openai_key=openai_key,
                openai_base_url=openai_base_url,
                progress=progress_update,
                console=console,
            )

        progress_placeholder.success("Scan complete.")
        emit_log("[+] Scan complete")
        confirmed = scan_result.get_confirmed()
        st.success(f"Scan finished: {len(confirmed)} confirmed findings.")
        st.write(f"Markdown report: `{md_path}`")
        if pdf_path:
            st.write(f"PDF report: `{pdf_path}`")
        else:
            st.warning("PDF generation skipped because `reportlab` is not installed.")

        md_bytes = md_path.read_bytes()
        pdf_bytes = pdf_path.read_bytes() if pdf_path else b""
        d1, d2 = st.columns(2)
        d1.download_button(
            "Download Markdown",
            data=md_bytes,
            file_name=md_path.name,
            mime="text/markdown",
            use_container_width=True,
        )
        if pdf_path:
            d2.download_button(
                "Download PDF",
                data=pdf_bytes,
                file_name=pdf_path.name,
                mime="application/pdf",
                use_container_width=True,
            )

        with st.expander("Preview markdown report"):
            st.markdown(md_path.read_text(encoding="utf-8", errors="ignore"))
    except Exception as exc:
        progress_placeholder.error("Scan failed.")
        st.exception(exc)


if __name__ == "__main__":
    main()
