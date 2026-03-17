"""
Incremental Scan Cache — Git-Aware Differential Scanning.

Strategy
--------
On the **first** run (no cache) the full codebase is scanned and every
finding is stored alongside the git commit hash (or a SHA-256 of each file
as a fallback when the target is not a git repo).

On **subsequent** runs with ``--incremental``:
  1. Ask git (or compare file hashes) which files changed.
  2. Keep the cached findings for *unchanged* files — no re-scan needed.
  3. Only build the code context for changed / added files and pass that
     smaller context to the agent pipeline.
  4. Re-merge: drop old findings that came from deleted files, merge new
     findings, and persist the updated cache.

Cache location:  <project-root>/.scan_cache/<target-slug>/state.json
"""

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .constants import SCAN_CACHE_DIR, SUPPORTED_EXTENSIONS, SKIP_DIRECTORIES
from .findings import Finding
from .git_utils import (
    is_git_repo,
    get_current_commit,
    get_changed_files_since_commit,
    get_untracked_files,
)


def _slug(target_path: str) -> str:
    """Deterministic folder name for a given target path."""
    return hashlib.sha1(str(Path(target_path).resolve()).encode()).hexdigest()[:12]


def _file_sha256(filepath: str) -> str:
    """Content hash used as a fallback when git is not available."""
    h = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
    except OSError:
        return ""
    return h.hexdigest()


class ScanCache:
    """Persistent cache of per-file findings for incremental scanning."""

    VERSION = 2  # bump when the cache schema changes

    def __init__(self, target_path: str):
        self.target_path = str(Path(target_path).resolve())
        self._cache_dir = SCAN_CACHE_DIR / _slug(self.target_path)
        self._state_file = self._cache_dir / "state.json"

        # Runtime state (loaded from disk or defaults)
        self._last_commit: Optional[str] = None
        self._file_hashes: Dict[str, str] = {}   # rel_path → sha256
        self._findings_by_file: Dict[str, List[dict]] = {}  # rel_path → [finding dicts]
        self._scan_time: float = 0.0
        self._git_available: bool = False

        self._load()

    # ── persistence ─────────────────────────────────────────────────────

    def _load(self):
        if not self._state_file.exists():
            return  # first run — empty cache is fine

        try:
            with open(self._state_file, "r", encoding="utf-8") as f:
                state = json.load(f)

            if state.get("version") != self.VERSION:
                return  # schema changed — treat as cold start

            self._last_commit = state.get("last_commit")
            self._file_hashes = state.get("file_hashes", {})
            self._findings_by_file = state.get("findings_by_file", {})
            self._scan_time = state.get("scan_time", 0.0)
        except Exception:
            # Corrupt cache — silent cold start
            self._last_commit = None
            self._file_hashes = {}
            self._findings_by_file = {}

    def save(self, all_findings: List[Finding]):
        """Persist the full set of current findings to disk."""
        try:
            self._cache_dir.mkdir(parents=True, exist_ok=True)

            # Re-index by relative file path
            self._findings_by_file = {}
            for f in all_findings:
                rel = _rel(f.file_path, self.target_path)
                self._findings_by_file.setdefault(rel, []).append(f.to_dict())

            # Refresh file hashes for all supported files
            self._file_hashes = _compute_file_hashes(self.target_path)

            # Record current git commit (if available)
            if is_git_repo(self.target_path):
                self._last_commit = get_current_commit(self.target_path)

            state = {
                "version": self.VERSION,
                "target_path": self.target_path,
                "last_commit": self._last_commit,
                "scan_time": time.time(),
                "file_hashes": self._file_hashes,
                "findings_by_file": self._findings_by_file,
            }

            # Write to temporary file first, then atomically rename
            temp_file = self._state_file.with_suffix('.tmp')
            with open(temp_file, "w", encoding="utf-8") as f:
                json.dump(state, f, indent=2)
            
            # Atomic rename to prevent corruption
            temp_file.replace(self._state_file)
            
        except Exception as e:
            # Log the error but don't crash the scan
            import sys
            print(f"Warning: Failed to save scan cache: {e}", file=sys.stderr)
            # Try to clean up temp file if it exists
            try:
                if temp_file.exists():
                    temp_file.unlink()
            except:
                pass

    # ── incremental logic ────────────────────────────────────────────────

    def is_warm(self) -> bool:
        """True if we have a valid previous scan to diff against."""
        return bool(self._findings_by_file or self._file_hashes)

    def compute_diff(self) -> Tuple[List[str], List[str], List[str]]:
        """
        Return (changed, added, deleted) as repo-relative paths.

        Prefers ``git diff`` when available; falls back to SHA-256 comparison
        for plain directories.
        """
        if not self.is_warm():
            return [], [], []  # cold start — caller should do a full scan

        # ── git-based diff ───────────────────────────────────────────────
        if is_git_repo(self.target_path) and self._last_commit:
            mod, added, deleted = get_changed_files_since_commit(
                self.target_path, self._last_commit
            )
            # Also pick up untracked files (new files not yet committed)
            untracked = get_untracked_files(self.target_path)
            # Filter untracked to only supported extensions
            untracked = [
                p for p in untracked
                if Path(p).suffix in SUPPORTED_EXTENSIONS
            ]
            added = list(set(added + untracked))
            return mod, added, deleted

        # ── hash-based diff (non-git fallback) ──────────────────────────
        current_hashes = _compute_file_hashes(self.target_path)

        changed, added, deleted = [], [], []
        all_old = set(self._file_hashes)
        all_new = set(current_hashes)

        for rel in all_new - all_old:
            added.append(rel)
        for rel in all_old - all_new:
            deleted.append(rel)
        for rel in all_old & all_new:
            if current_hashes[rel] != self._file_hashes[rel]:
                changed.append(rel)

        return changed, added, deleted

    def get_cached_findings(self, exclude_files: List[str]) -> List[Finding]:
        """
        Re-hydrate and return all cached findings whose source file is NOT
        in *exclude_files* (changed / deleted files that need a fresh scan).
        """
        exclude_set = set(exclude_files)
        findings = []
        for rel_path, finding_dicts in self._findings_by_file.items():
            if rel_path in exclude_set:
                continue
            for d in finding_dicts:
                try:
                    findings.append(Finding.from_dict(dict(d)))
                except Exception:
                    pass
        return findings

    def summary(self, changed: List[str], added: List[str], deleted: List[str]) -> dict:
        """Human-readable diff summary used by the CLI."""
        return {
            "warm": self.is_warm(),
            "last_commit": self._last_commit or "N/A",
            "changed": changed,
            "added": added,
            "deleted": deleted,
            "total_changed": len(changed) + len(added),
            "total_deleted": len(deleted),
            "cached_files": len(self._findings_by_file),
        }


# ── helpers ──────────────────────────────────────────────────────────────

def _rel(file_path: str, base: str) -> str:
    """Normalise an absolute path to a base-relative posix string."""
    try:
        return str(Path(file_path).relative_to(base))
    except ValueError:
        return file_path


def _compute_file_hashes(target_path: str) -> Dict[str, str]:
    """Walk *target_path* and return {rel_path: sha256} for every supported file."""
    hashes: Dict[str, str] = {}
    base = Path(target_path).resolve()

    for root, dirs, files in os.walk(base):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRECTORIES]
        for fname in files:
            fp = Path(root) / fname
            if fp.suffix not in SUPPORTED_EXTENSIONS:
                continue
            rel = str(fp.relative_to(base))
            hashes[rel] = _file_sha256(str(fp))

    return hashes
