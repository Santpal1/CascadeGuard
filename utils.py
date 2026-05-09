"""
Utility functions for CascadeGuard.
Version parsing, error handling, and common validations.
"""

import re
from typing import Optional, List, Tuple
import logging

logger = logging.getLogger(__name__)


def parse_version(version_str: str) -> Optional[List[int]]:
    """
    Parses a version string into a list of integers.
    Examples:
        "1.2.3" -> [1, 2, 3]
        "v2.1.0-alpha" -> [2, 1, 0]
        "invalid" -> None
    """
    if not version_str or version_str in ("unspecified", "inherited-from-parent"):
        return None
    
    # Strip non-numeric prefix
    clean = re.sub(r'^[^0-9]*', '', str(version_str))
    # Take only the first version if there's a range like ">=1.0,<2.0"
    clean = clean.split(",")[0].strip()
    
    # Extract numeric parts
    parts = re.findall(r'\d+', clean)
    try:
        return [int(p) for p in parts] if parts else None
    except ValueError:
        return None


def compare_versions(v1: str, v2: str) -> int:
    """
    Compares two version strings.
    Returns:
        -1 if v1 < v2
         0 if v1 == v2
         1 if v1 > v2
    """
    parts1 = parse_version(v1) or []
    parts2 = parse_version(v2) or []
    
    if not parts1 or not parts2:
        return 0
    
    for p1, p2 in zip(parts1, parts2):
        if p1 < p2:
            return -1
        if p1 > p2:
            return 1
    
    # Handle cases where one version has more parts
    if len(parts1) < len(parts2):
        return -1
    if len(parts1) > len(parts2):
        return 1
    
    return 0


def normalize_package_name(name: str) -> str:
    """
    Normalizes package name for consistent lookups.
    - lowercase
    - replace underscores/hyphens
    """
    return re.sub(r'[-_]+', '-', name.lower())


def extract_version_spec(spec: str) -> Tuple[str, str]:
    """
    Extracts operator and version from a specifier.
    "(>=1.0,<2.0)" -> (">=", "1.0"), ("< ", "2.0")
    """
    operators = [">= ", "<=", "==", "~=", "!=", ">", "<", "~"]
    for op in operators:
        if op in spec:
            parts = spec.split(op, 1)
            if len(parts) == 2:
                return (op.strip(), parts[1].strip())
    return ("", spec.strip())


def is_valid_node_id(node_id: str) -> bool:
    """Validates node ID format: 'ecosystem:package'"""
    if not isinstance(node_id, str):
        return False
    if ":" not in node_id:
        return False
    ecosystem, package = node_id.split(":", 1)
    return bool(ecosystem and package)


def validate_github_url(url: str) -> bool:
    """Validates GitHub URL format"""
    if not url:
        return False
    return url.startswith("https://github.com/") or url.startswith("git@github.com:")


def extract_github_repo(url: str) -> Optional[Tuple[str, str]]:
    """
    Extracts owner and repo from GitHub URL.
    Returns (owner, repo) or None if invalid.
    """
    try:
        if "github.com/" not in url:
            return None
        
        parts = url.rstrip("/").split("github.com/")[1].split("/")
        if len(parts) >= 2:
            return (parts[0], parts[1])
    except (IndexError, AttributeError):
        pass
    
    return None
