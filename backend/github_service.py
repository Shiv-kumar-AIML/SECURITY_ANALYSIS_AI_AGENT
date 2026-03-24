"""
GitHub API integration for Security Analysis Agent.
Handles JWT authentication, PR diffs, and commenting.
"""
import json
import hmac
import hashlib
import time
import httpx
import jwt
from typing import Optional, Dict, Any, List
from pathlib import Path


class GitHubService:
    """Service for interacting with GitHub API."""

    def __init__(
        self,
        app_id: str,
        private_key_path: str,
        webhook_secret: str,
    ):
        """
        Initialize GitHub service.

        Args:
            app_id: GitHub App ID
            private_key_path: Path to private key PEM file
            webhook_secret: Webhook signature secret
        """
        self.app_id = app_id
        self.webhook_secret = webhook_secret
        self.private_key_path = private_key_path

        # Load private key
        with open(private_key_path, "r") as f:
            self.private_key = f.read()

    def verify_webhook_signature(self, payload: bytes, signature: str) -> bool:
        """
        Verify GitHub webhook signature.

        Args:
            payload: Raw request body
            signature: X-Hub-Signature-256 header value

        Returns:
            True if signature is valid
        """
        if not signature.startswith("sha256="):
            return False

        expected_signature = hmac.new(
            self.webhook_secret.encode(),
            payload,
            hashlib.sha256
        ).hexdigest()

        provided_signature = signature.split("=", 1)[1]

        return hmac.compare_digest(expected_signature, provided_signature)

    def get_installation_token(self, installation_id: int) -> str:
        """
        Get GitHub App installation token.

        Args:
            installation_id: GitHub App installation ID

        Returns:
            Access token for API calls
        """
        # Create JWT
        now = int(time.time())
        payload = {
            "iss": self.app_id,
            "iat": now,
            "exp": now + 300,  # 5 minutes
        }

        jwt_token = jwt.encode(payload, self.private_key, algorithm="RS256")

        # Exchange JWT for installation token
        response = httpx.post(
            f"https://api.github.com/app/installations/{installation_id}/access_tokens",
            headers={
                "Authorization": f"Bearer {jwt_token}",
                "Accept": "application/vnd.github.v3+json",
                "User-Agent": "pentas-agent",
            },
            json={},
        )

        response.raise_for_status()
        data = response.json()
        return data["token"]

    def get_pr_diff(
        self,
        owner: str,
        repo: str,
        pull_number: int,
        installation_token: str,
    ) -> str:
        """
        Get PR diff/changes.

        Args:
            owner: Repository owner
            repo: Repository name
            pull_number: Pull request number
            installation_token: GitHub App installation token

        Returns:
            Unified diff format
        """
        response = httpx.get(
            f"https://api.github.com/repos/{owner}/{repo}/pulls/{pull_number}",
            headers={
                "Authorization": f"token {installation_token}",
                "Accept": "application/vnd.github.v3.diff",
                "User-Agent": "pentas-agent",
            },
        )

        response.raise_for_status()
        return response.text

    def get_pr_files(
        self,
        owner: str,
        repo: str,
        pull_number: int,
        installation_token: str,
    ) -> List[Dict[str, Any]]:
        """
        Get list of changed files in PR.

        Args:
            owner: Repository owner
            repo: Repository name
            pull_number: Pull request number
            installation_token: GitHub App installation token

        Returns:
            List of file change objects
        """
        files = []
        page = 1
        per_page = 100

        while True:
            response = httpx.get(
                f"https://api.github.com/repos/{owner}/{repo}/pulls/{pull_number}/files",
                headers={
                    "Authorization": f"token {installation_token}",
                    "Accept": "application/vnd.github.v3+json",
                    "User-Agent": "pentas-agent",
                },
                params={"page": page, "per_page": per_page},
            )

            response.raise_for_status()
            data = response.json()

            if not data:
                break

            files.extend(data)
            page += 1

        return files

    def post_pr_review_comment(
        self,
        owner: str,
        repo: str,
        pull_number: int,
        commit_id: str,
        path: str,
        line: int,
        body: str,
        installation_token: str,
    ) -> Dict[str, Any]:
        """
        Post comment on specific line of PR.

        Args:
            owner: Repository owner
            repo: Repository name
            pull_number: Pull request number
            commit_id: Commit SHA
            path: File path
            line: Line number
            body: Comment body
            installation_token: GitHub App installation token

        Returns:
            Response from GitHub API
        """
        response = httpx.post(
            f"https://api.github.com/repos/{owner}/{repo}/pulls/{pull_number}/comments",
            headers={
                "Authorization": f"token {installation_token}",
                "Accept": "application/vnd.github.v3+json",
                "User-Agent": "pentas-agent",
            },
            json={
                "commit_id": commit_id,
                "path": path,
                "line": line,
                "body": body,
            },
        )

        response.raise_for_status()
        return response.json()

    def post_pr_comment(
        self,
        owner: str,
        repo: str,
        pull_number: int,
        body: str,
        installation_token: str,
    ) -> Dict[str, Any]:
        """
        Post general comment on PR.

        Args:
            owner: Repository owner
            repo: Repository name
            pull_number: Pull request number
            body: Comment body
            installation_token: GitHub App installation token

        Returns:
            Response from GitHub API
        """
        response = httpx.post(
            f"https://api.github.com/repos/{owner}/{repo}/issues/{pull_number}/comments",
            headers={
                "Authorization": f"token {installation_token}",
                "Accept": "application/vnd.github.v3+json",
                "User-Agent": "pentas-agent",
            },
            json={"body": body},
        )

        response.raise_for_status()
        return response.json()

    def post_pr_review(
        self,
        owner: str,
        repo: str,
        pull_number: int,
        body: str,
        event: str,
        installation_token: str,
        commit_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Post a PR review (appears prominently at top).

        Args:
            owner: Repository owner
            repo: Repository name
            pull_number: Pull request number
            body: Review body
            event: Review event - "COMMENT", "APPROVE", or "REQUEST_CHANGES"
            installation_token: GitHub App installation token
            commit_id: Optional specific commit SHA to review

        Returns:
            Response from GitHub API
        """
        payload = {
            "body": body,
            "event": event,
        }

        if commit_id:
            payload["commit_id"] = commit_id

        response = httpx.post(
            f"https://api.github.com/repos/{owner}/{repo}/pulls/{pull_number}/reviews",
            headers={
                "Authorization": f"token {installation_token}",
                "Accept": "application/vnd.github.v3+json",
                "User-Agent": "pentas-agent",
            },
            json=payload,
        )

        response.raise_for_status()
        return response.json()

    def get_pr_base_and_head(
        self,
        owner: str,
        repo: str,
        pull_number: int,
        installation_token: str,
    ) -> tuple[str, str]:
        """
        Get base and head commit SHAs for a PR.

        Args:
            owner: Repository owner
            repo: Repository name
            pull_number: Pull request number
            installation_token: GitHub App installation token

        Returns:
            Tuple of (base_commit, head_commit)
        """
        response = httpx.get(
            f"https://api.github.com/repos/{owner}/{repo}/pulls/{pull_number}",
            headers={
                "Authorization": f"token {installation_token}",
                "Accept": "application/vnd.github.v3+json",
                "User-Agent": "pentas-agent",
            },
        )

        response.raise_for_status()
        data = response.json()

        return data["base"]["sha"], data["head"]["sha"]
