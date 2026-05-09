"""
GitHub OAuth authentication module for CascadeGuard.
Handles sign-in flow and token management for accessing both public and private repositories.
"""

import os
import json
import base64
import requests
from datetime import datetime, timedelta
from typing import Optional
from urllib.parse import urlencode, parse_qs
from dotenv import load_dotenv

load_dotenv()

# OAuth configuration
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
# Use OAUTH_REDIRECT_URI from .env if available, otherwise default to localhost
REDIRECT_URI = os.getenv("OAUTH_REDIRECT_URI", "http://localhost:8501")
GITHUB_AUTH_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_API_URL = "https://api.github.com"


class GitHubOAuthHandler:
    """Handles GitHub OAuth authentication flow."""

    @staticmethod
    def get_auth_url(scope: str = "repo") -> str:
        """
        Generate the GitHub authorization URL.
        
        Scopes:
        - repo: Full control of private repositories (includes public)
        - public_repo: Access to public repositories only
        """
        if not CLIENT_ID or not CLIENT_SECRET:
            raise ValueError("CLIENT_ID and CLIENT_SECRET must be set in .env")
        
        params = {
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "scope": scope,
            "state": "cascadeguard",  # Simple state for CSRF protection
        }
        url = f"{GITHUB_AUTH_URL}?{urlencode(params)}"
        print(f"[OAuth] Auth URL: {url}")
        return url

    @staticmethod
    def exchange_code_for_token(code: str) -> Optional[dict]:
        """
        Exchange authorization code for access token.
        
        Returns:
            dict with access_token, token_type, scope on success
            None on failure
        """
        if not CLIENT_ID or not CLIENT_SECRET:
            print("[OAuth] ERROR: CLIENT_ID and CLIENT_SECRET not configured")
            return None
        
        try:
            print(f"[OAuth] Exchanging code for token...")
            response = requests.post(
                GITHUB_TOKEN_URL,
                data={
                    "client_id": CLIENT_ID,
                    "client_secret": CLIENT_SECRET,
                    "code": code,
                    "redirect_uri": REDIRECT_URI,
                },
                headers={"Accept": "application/json"},
                timeout=10
            )
            response.raise_for_status()
            data = response.json()
            
            if "error" in data:
                print(f"[OAuth] ERROR: {data.get('error_description', 'Unknown error')}")
                return None
            
            print(f"[OAuth] ✅ Token obtained successfully")
            return data
        except Exception as e:
            print(f"[OAuth] ERROR exchanging code: {e}")
            return None

    @staticmethod
    def get_user_info(access_token: str) -> Optional[dict]:
        """
        Fetch authenticated user's information.
        
        Returns:
            dict with user info (login, name, avatar_url, etc.)
        """
        try:
            headers = {
                "Authorization": f"token {access_token}",
                "Accept": "application/vnd.github.v3+json"
            }
            response = requests.get(f"{GITHUB_API_URL}/user", headers=headers, timeout=10)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"Failed to fetch user info: {e}")
            return None

    @staticmethod
    def list_repositories(access_token: str, affiliation: str = "owner,collaborator") -> list:
        """
        Fetch list of repositories accessible to the authenticated user.
        
        Args:
            access_token: GitHub OAuth access token
            affiliation: Filter by user/repo relationship (owner, collaborator, organization_member)
        
        Returns:
            list of repos sorted by pushed_at (most recent first)
        """
        try:
            headers = {
                "Authorization": f"token {access_token}",
                "Accept": "application/vnd.github.v3+json"
            }
            
            repos = []
            page = 1
            per_page = 100
            
            while True:
                response = requests.get(
                    f"{GITHUB_API_URL}/user/repos",
                    headers=headers,
                    params={
                        "affiliation": affiliation,
                        "sort": "pushed",
                        "order": "desc",
                        "per_page": per_page,
                        "page": page,
                        "type": "all"  # Include public, private, and forks
                    },
                    timeout=10
                )
                response.raise_for_status()
                page_repos = response.json()
                
                if not page_repos:
                    break
                
                repos.extend(page_repos)
                page += 1
                
                # Stop if we got fewer than per_page (indicates last page)
                if len(page_repos) < per_page:
                    break
            
            # Format repository data
            formatted_repos = []
            for repo in repos:
                formatted_repos.append({
                    "name": repo["name"],
                    "full_name": repo["full_name"],
                    "html_url": repo["html_url"],
                    "description": repo.get("description", ""),
                    "private": repo["private"],
                    "language": repo.get("language"),
                    "pushed_at": repo.get("pushed_at"),
                    "url": repo["clone_url"],
                })
            
            return formatted_repos
        except Exception as e:
            print(f"Failed to list repositories: {e}")
            return []

    @staticmethod
    def get_repository_details(access_token: str, owner: str, repo: str) -> Optional[dict]:
        """
        Fetch details about a specific repository.
        """
        try:
            headers = {
                "Authorization": f"token {access_token}",
                "Accept": "application/vnd.github.v3+json"
            }
            response = requests.get(
                f"{GITHUB_API_URL}/repos/{owner}/{repo}",
                headers=headers,
                timeout=10
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"Failed to fetch repository details: {e}")
            return None


class TokenStore:
    """Simple in-memory token storage (can be upgraded to encrypted DB later)."""
    
    @staticmethod
    def store_token(token: str, expires_in: Optional[int] = None) -> dict:
        """
        Store token with metadata.
        
        Returns:
            Token metadata dict with expiration info
        """
        metadata = {
            "token": token,
            "stored_at": datetime.utcnow().isoformat(),
            "expires_in": expires_in,
        }
        if expires_in:
            metadata["expires_at"] = (datetime.utcnow() + timedelta(seconds=expires_in)).isoformat()
        return metadata
    
    @staticmethod
    def is_token_expired(token_metadata: dict) -> bool:
        """Check if token has expired."""
        if "expires_at" not in token_metadata:
            return False
        
        expires_at = datetime.fromisoformat(token_metadata["expires_at"])
        return datetime.utcnow() > expires_at
    
    @staticmethod
    def get_valid_token(token_metadata: Optional[dict]) -> Optional[str]:
        """Get token if valid and not expired."""
        if not token_metadata:
            return None
        
        if TokenStore.is_token_expired(token_metadata):
            return None
        
        return token_metadata.get("token")
