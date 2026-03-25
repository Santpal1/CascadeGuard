import os
import base64
import requests
from dotenv import load_dotenv

load_dotenv()

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
BASE_URL = "https://api.github.com"

HEADERS = {
    "Authorization": f"token {GITHUB_TOKEN}",
    "Accept": "application/vnd.github.v3+json"
}

TARGET_FILES = [
    "requirements.txt",
    "pyproject.toml",
    "package-lock.json",
    "package.json",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts"
]

# Folders that always contain noise — never real project deps
EXCLUDED_FOLDERS = {
    "node_modules",
    "vendor",
    ".git",
    "__pycache__",
    ".tox",
    "venv",
    ".venv",
    "env",
    "dist",
    "build",
    "target",        # Maven build output
    ".gradle",       # Gradle cache
    "examples",
    "example",
    "samples",
    "sample",
    "demo",
    "demos",
    "test",
    "tests",
    "fixtures",
    "docs",
    "doc",
    ".github",
    "site",
    "benchmark",
    "benchmarks",
}


def parse_github_url(url: str) -> tuple:
    url = url.rstrip("/")
    parts = url.replace("https://github.com/", "").split("/")
    if len(parts) < 2:
        raise ValueError(f"Invalid GitHub URL: {url}")
    return parts[0], parts[1]


def get_file_tree(owner: str, repo: str) -> list:
    url = f"{BASE_URL}/repos/{owner}/{repo}/git/trees/HEAD?recursive=1"
    response = requests.get(url, headers=HEADERS)

    if response.status_code == 404:
        raise ValueError(f"Repository not found: {owner}/{repo}")
    if response.status_code == 401:
        raise ValueError("GitHub token is invalid or missing.")
    response.raise_for_status()

    data = response.json()

    # GitHub truncates trees over 100k files — warn if so
    if data.get("truncated"):
        print("[github_client] WARNING: repo file tree was truncated by GitHub. "
              "Some dependency files in deep paths may be missed.")

    tree = data.get("tree", [])
    return [item["path"] for item in tree if item["type"] == "blob"]


def find_dependency_files(file_paths: list) -> list:
    """
    Finds all dependency files in the repo, excluding noise folders.
    Returns them sorted so root-level files come first.
    """
    found = []

    for path in file_paths:
        filename = path.split("/")[-1]

        if filename not in TARGET_FILES:
            continue

        # Check every segment of the path against the exclusion list
        parts = path.split("/")
        path_parts = parts[:-1]  # all folders, not the filename itself

        if any(part.lower() in EXCLUDED_FOLDERS for part in path_parts):
            print(f"[github_client] Skipping {path} (excluded folder)")
            continue

        found.append(path)

    # Sort: root files first (fewer slashes = higher up), then alphabetical
    found.sort(key=lambda p: (p.count("/"), p))
    return found


def get_file_content(owner: str, repo: str, path: str) -> str:
    url = f"{BASE_URL}/repos/{owner}/{repo}/contents/{path}"
    response = requests.get(url, headers=HEADERS)
    response.raise_for_status()

    content_b64 = response.json().get("content", "")
    decoded = base64.b64decode(content_b64.replace("\n", "")).decode("utf-8")
    return decoded