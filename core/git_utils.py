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
    if parsed.username or parsed.password:
        netloc = parsed.hostname
        if parsed.port:
            netloc += f":{parsed.port}"
        return parsed._replace(netloc=netloc).geturl()
    return url

def clone_repo(url: str, dest: Optional[str] = None) -> str:
    """
    Clone a git repository to a local directory with production-level safety.
    Hides credentials, shallow clones for speed, and retries on failure.
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
        repo_name = os.path.basename(parsed.path).replace(".git", "") or "cloned_repo"
        dest_path = local_cache / repo_name
        
        if dest_path.exists() and any(dest_path.iterdir()):
            print(f"[*] Using existing cached codebase: {repo_name} ...")
            return str(dest_path.resolve())
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
