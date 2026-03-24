import os
import shutil
import time
from pathlib import Path
from typing import Optional, Tuple
from urllib.parse import urlparse

# ── Git clone resilience settings ──────────────────────────────────────
_MAX_RETRIES = 3
_BACKOFF_SECONDS = 2  # multiplied by attempt number

def is_git_url(value: str) -> bool:
    """Check whether the input looks like a git remote URL."""
    return any(
        value.startswith(prefix)
        for prefix in ("http://", "https://", "git@", "ssh://")
    ) and any(value.endswith(suffix) for suffix in (".git", ""))

def _git_env() -> dict:
    """Build an env dict that forces HTTP/1.1 and a large POST buffer."""
    env = os.environ.copy()
    env.update({
        "GIT_HTTP_VERSION": "HTTP/1.1",
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "http.postBuffer",
        "GIT_CONFIG_VALUE_0": "524288000",  # 500 MB
        "GIT_TERMINAL_PROMPT": "0",         # Disable terminal prompts for passwords
    })
    return env

def sanitize_url(url: str) -> str:
    """Removes sensitive credentials from the URL for safe logging."""
    parsed = urlparse(url)
    
    # Remove username and password from netloc
    if parsed.username or parsed.password:
        netloc = parsed.hostname
        if parsed.port:
            netloc += f":{parsed.port}"
        parsed = parsed._replace(netloc=netloc)
    
    # Remove sensitive query parameters
    if parsed.query:
        from urllib.parse import parse_qs, urlencode
        query_params = parse_qs(parsed.query, keep_blank_values=True)
        
        # Remove common sensitive parameter names
        sensitive_params = {
            'token', 'access_token', 'auth_token', 'api_key', 'apikey', 
            'password', 'passwd', 'secret', 'key', 'auth', 'credential',
            'private_token', 'access_token', 'refresh_token'
        }
        
        # Case-insensitive removal
        filtered_params = {}
        for param, values in query_params.items():
            if param.lower() not in sensitive_params:
                filtered_params[param] = values
        
        if filtered_params != query_params:  # Only update if we removed something
            parsed = parsed._replace(query=urlencode(filtered_params, doseq=True))
    
    # Remove fragment (often contains tokens)
    if parsed.fragment:
        parsed = parsed._replace(fragment='')
    
    return parsed.geturl()

def clone_repo(url: str, dest: Optional[str] = None, force_fresh: bool = False) -> str:
    """
    Clone a git repository to a local directory with production-level safety.
    Hides credentials, shallow clones for speed, and retries on failure.

    Args:
        url: Git repository URL
        dest: Destination directory (optional, uses cache if None)
        force_fresh: If True, delete existing cache and clone fresh
    """
    try:
        import git
    except ImportError:
        raise RuntimeError("gitpython is required. Install with: pip install gitpython")

    safe_url = sanitize_url(url)

    if dest is None:
        # Use project-local hidden cache dir
        local_cache = Path(__file__).resolve().parent.parent / ".scan_cache" / "clones"
        local_cache.mkdir(parents=True, exist_ok=True)

        parsed = urlparse(safe_url)
        repo_name = os.path.basename(parsed.path).replace(".git", "") or "repo"
        dest_path = local_cache / repo_name

        if dest_path.exists() and any(dest_path.iterdir()):
            if force_fresh:
                # Force fresh clone - delete cached repo
                print(f"[*] Force fresh: removing cached repo {repo_name} ...")
                shutil.rmtree(dest_path, ignore_errors=True)
            else:
                # Update existing cached repo with git pull
                print(f"[*] Updating cached repository: {repo_name} ...")
                try:
                    import subprocess
                    # Fetch and reset to origin/HEAD to handle force pushes
                    subprocess.run(
                        ["git", "-C", str(dest_path), "fetch", "--depth=1", "origin"],
                        capture_output=True, timeout=60, env=_git_env()
                    )
                    # Get default branch name
                    result = subprocess.run(
                        ["git", "-C", str(dest_path), "remote", "show", "origin"],
                        capture_output=True, text=True, timeout=30, env=_git_env()
                    )
                    default_branch = "main"
                    for line in result.stdout.splitlines():
                        if "HEAD branch:" in line:
                            default_branch = line.split(":")[-1].strip()
                            break

                    # Reset to origin's default branch
                    subprocess.run(
                        ["git", "-C", str(dest_path), "reset", "--hard", f"origin/{default_branch}"],
                        capture_output=True, timeout=30, env=_git_env()
                    )
                    print(f"[+] Repository updated to latest {default_branch}.")
                    return str(dest_path.resolve())
                except Exception as e:
                    print(f"[!] Failed to update cached repo: {e}. Re-cloning fresh...")
                    shutil.rmtree(dest_path, ignore_errors=True)
    else:
        dest_path = Path(dest)

    env = _git_env()
    last_error = None

    for attempt in range(1, _MAX_RETRIES + 1):
        if attempt == 1:
            print(f"[*] Safely acquiring target repository: {safe_url} ...")
        else:
            print(f"[*] Re-attempting repository acquisition ({attempt}/{_MAX_RETRIES}) ...")
            
        try:
            # Shallow clone depth=1 to optimize speed and hide git history
            git.Repo.clone_from(url, str(dest_path), depth=1, env=env)
            print("[+] Repository acquired successfully.")
            return str(dest_path.resolve())
        except git.GitCommandError as exc:
            last_error = exc
            if attempt < _MAX_RETRIES:
                wait = _BACKOFF_SECONDS * attempt
                time.sleep(wait)
                if dest_path.exists():
                    shutil.rmtree(dest_path, ignore_errors=True)
        except Exception as e:
            last_error = e
            break

    print(f"[-] Failed to acquire repository. Check remote URL and/or access tokens.")
    import sys
    sys.exit(1)


# ── Incremental scan helpers ────────────────────────────────────────────

def is_git_repo(path: str) -> bool:
    """Return True if *path* is inside a git working tree."""
    import subprocess
    try:
        result = subprocess.run(
            ["git", "-C", path, "rev-parse", "--is-inside-work-tree"],
            capture_output=True, text=True, timeout=5,
        )
        return result.returncode == 0 and result.stdout.strip() == "true"
    except Exception:
        return False


def get_current_commit(path: str) -> Optional[str]:
    """Return the current HEAD commit SHA (full) or None if unavailable."""
    import subprocess
    try:
        result = subprocess.run(
            ["git", "-C", path, "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return None


def get_changed_files_since_commit(path: str, since_commit: str) -> Tuple[list, list, list]:
    """
    Return three lists — (modified, added, deleted) — of repo-relative file
    paths that changed between *since_commit* and HEAD.

    Uses ``git diff --name-status`` so we get the change type for free.
    Returns ([], [], []) when the diff cannot be computed (e.g. first run,
    force-push, or non-git repo).
    """
    import subprocess
    try:
        result = subprocess.run(
            ["git", "-C", path, "diff", "--name-status", since_commit, "HEAD"],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode != 0:
            return [], [], []

        modified, added, deleted = [], [], []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split("\t", 1)
            if len(parts) < 2:
                continue
            status, filepath = parts[0][0], parts[1]  # first char handles 'M','A','D','R','C'
            if status in ("M", "R", "C"):
                modified.append(filepath)
            elif status == "A":
                added.append(filepath)
            elif status == "D":
                deleted.append(filepath)

        return modified, added, deleted
    except Exception:
        return [], [], []


def get_untracked_files(path: str) -> list:
    """Return untracked (new, unstaged) files in the working tree."""
    import subprocess
    try:
        result = subprocess.run(
            ["git", "-C", path, "ls-files", "--others", "--exclude-standard"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            return [f.strip() for f in result.stdout.splitlines() if f.strip()]
    except Exception:
        pass
    return []
