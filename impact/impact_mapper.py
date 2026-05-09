"""
Impact Mapper - Cross-references vulnerabilities with source code analysis.

Maps vulnerable packages to affected files and estimates the scope of impact.
"""

import logging
import networkx as nx
from typing import Dict, List, Optional
from .feature_inferrer import infer_features, infer_features_from_imports

logger = logging.getLogger(__name__)


def map_impact(enriched_graph: nx.DiGraph, scan_results: Dict) -> Dict:
    """
    Maps vulnerable packages in the graph to affected files in scan results.
    Handles both direct imports and transitive dependencies.
    
    Args:
        enriched_graph: From risk/enricher.py with vulnerability data
        scan_results: From ast_scanner.scan_repository()
    
    Returns:
        {
            "ecosystem:package": {
                "affected_files": ["payments/api.py", "auth/client.py"],
                "entry_points": ["app.py", "server.js"],
                "features": ["payment flow", "authentication"],
                "exposure_scope": "HIGH/MEDIUM/LOW"
            }
        }
    """
    impact_map = {}
    
    # Step 1: Build a map of which files import which packages
    # This maps import names to files that use them
    import_to_files = {}
    for filepath, file_data in scan_results.items():
        for import_name in file_data.get("imports", []):
            if import_name not in import_to_files:
                import_to_files[import_name] = []
            import_to_files[import_name].append(filepath)
    
    # Step 2: For each vulnerable package in the graph
    for node, data in enriched_graph.nodes(data=True):
        if data.get("ecosystem") == "root":
            continue
        
        # Only process vulnerable nodes
        if data.get("risk_score", 0) == 0 or data.get("vuln_count", 0) == 0:
            continue
        
        # Extract package name from node ID (format: "ecosystem:name")
        if ":" in node:
            ecosystem, package_name = node.split(":", 1)
        else:
            package_name = node
        
        # Use node ID directly as key
        package_id = node
        
        # Find affected files in two ways:
        # A) Direct imports: files that directly import this package
        direct_files = _find_affected_files_direct(package_name, import_to_files)
        
        # B) Transitive dependencies: files that import packages that depend on this one
        transitive_files = _find_affected_files_transitive(
            node, enriched_graph, import_to_files
        )
        
        # Combine both
        affected_files = sorted(list(set(direct_files + transitive_files)))
        affected_entry_points = _find_entry_points(affected_files, scan_results)
        
        # Infer features from affected files and their imports
        estimated_features = _infer_affected_features(
            affected_files, scan_results, affected_entry_points
        )
        
        # Calculate exposure scope
        exposure_scope = _calculate_exposure_scope(
            affected_entry_points,
            len(affected_files),
            len(scan_results)
        )
        
        impact_map[package_id] = {
            "affected_files": affected_files,
            "entry_points": affected_entry_points,
            "features": estimated_features,
            "exposure_scope": exposure_scope
        }
    
    return impact_map


def _find_affected_files_direct(package_name: str, import_to_files: Dict[str, List[str]]) -> List[str]:
    """
    Finds all files that directly import a given package.
    Handles package name normalization.
    """
    affected = []
    normalized_pkg = _normalize_package_name(package_name)
    
    for import_name, files in import_to_files.items():
        if _packages_match(import_name, normalized_pkg):
            affected.extend(files)
    
    return sorted(list(set(affected)))


def _find_affected_files_transitive(
    package_node: str,
    graph: nx.DiGraph, 
    import_to_files: Dict[str, List[str]]
) -> List[str]:
    """
    Finds files affected by transitive dependencies.
    
    For a vulnerable package, finds which files import packages that depend on it
    (i.e., packages that have this package as a transitive dependency).
    
    Example:
      - main.py imports googleapiclient (google-api-python-client)
      - google-api-python-client depends on httplib2
      - If httplib2 is vulnerable, main.py is affected (through the chain)
    """
    affected_files = []
    
    # Find all packages that eventually depend on this vulnerable package
    # i.e., find all predecessors (including transitive) of this package
    try:
        predecessors = nx.ancestors(graph, package_node)
    except:
        predecessors = set()
    
    # For each predecessor (package that depends on the vulnerable one)
    for pred_node in predecessors:
        if pred_node == "Santpal1/Email-Cleaner":  # Skip root node
            continue
        
        # Get the package name from node ID
        if ":" in pred_node:
            ecosystem, pred_pkg_name = pred_node.split(":", 1)
        else:
            pred_pkg_name = pred_node
        
        # Find files that import this predecessor package
        normalized_pred = _normalize_package_name(pred_pkg_name)
        
        for import_name, files in import_to_files.items():
            if _packages_match(import_name, normalized_pred):
                affected_files.extend(files)
    
    return sorted(list(set(affected_files)))


def _find_affected_files(package_name: str, scan_results: Dict) -> List[str]:
    """
    Finds all files that import a given package.
    Handles package name normalization.
    """
    affected = []
    normalized_pkg = _normalize_package_name(package_name)
    
    for filepath, file_data in scan_results.items():
        file_imports = file_data.get("imports", [])
        
        for import_name in file_imports:
            if _packages_match(import_name, normalized_pkg):
                affected.append(filepath)
                break
    
    return sorted(affected)


def _find_entry_points(affected_files: List[str], scan_results: Dict) -> List[str]:
    """
    Filters affected files to find entry points.
    """
    entry_points = []
    
    for filepath in affected_files:
        file_data = scan_results.get(filepath, {})
        if file_data.get("is_entry_point", False):
            entry_points.append(filepath)
    
    return sorted(entry_points)


def _infer_affected_features(
    affected_files: List[str],
    scan_results: Dict,
    entry_points: List[str]
) -> List[str]:
    """
    Infers user-facing features affected by vulnerabilities.
    Prioritizes entry points and their imports.
    """
    features = set()
    
    # Prioritize entry points
    if entry_points:
        for ep in entry_points:
            features.update(infer_features(ep))
            
            # Also check imports from entry points
            ep_imports = scan_results.get(ep, {}).get("imports", [])
            features.update(infer_features_from_imports(ep_imports))
    
    # Then scan other affected files
    for filepath in affected_files:
        features.update(infer_features(filepath))
        
        file_imports = scan_results.get(filepath, {}).get("imports", [])
        features.update(infer_features_from_imports(file_imports))
    
    return sorted(list(features))


def _calculate_exposure_scope(
    affected_entry_points: List[str],
    num_affected_files: int,
    total_files: int
) -> str:
    """
    Determines exposure scope based on entry point and file coverage.
    """
    if not affected_entry_points:
        # No entry points affected, but some files affected
        if total_files > 0:
            coverage = num_affected_files / total_files
            if coverage > 0.3:
                return "MEDIUM"  # Utility files but broadly used
            return "LOW"
        return "LOW"
    
    # Entry points are affected
    return "HIGH"


def _normalize_package_name(name: str) -> Dict[str, str]:
    """
    Normalizes a package name for matching.
    Handles special cases like PIL=Pillow, sklearn=scikit-learn, etc.
    
    Returns a dict with different normalized forms for flexible matching.
    """
    name = name.lower().strip()
    
    # Special equivalences: PyPI package names that differ from import names
    # Format: "pypi_package_name": {"import_name1", "import_name2", ...}
    equivalences = {
        # PIL
        "pil": {"pillow", "pil"},
        "pillow": {"pillow", "pil"},
        # scikit
        "sklearn": {"scikit-learn", "sklearn", "scikit_learn"},
        "scikit-learn": {"scikit-learn", "sklearn", "scikit_learn"},
        # PyYAML
        "yaml": {"pyyaml", "yaml"},
        "pyyaml": {"pyyaml", "yaml"},
        # Google packages
        "google-api-python-client": {"google-api-python-client", "googleapiclient", "google", "google_apis"},
        "google-auth": {"google-auth", "google_auth", "google"},
        "google-auth-oauthlib": {"google-auth-oauthlib", "google_auth_oauthlib", "oauth", "oauthlib"},
        "google-auth-httplib2": {"google-auth-httplib2", "google_auth_httplib2"},
        "google-api-core": {"google-api-core", "google_api_core", "google"},
        # Other common packages
        "beautifulsoup4": {"beautifulsoup4", "bs4"},
        "pillow": {"pillow", "pil", "image"},
        "pyyaml": {"pyyaml", "yaml"},
        "markdownify": {"markdownify", "markdown"},
        "cryptography": {"cryptography", "crypto"},
        "requests-oauthlib": {"requests-oauthlib", "requests_oauthlib"},
        "pyopenssl": {"pyopenssl", "openssl"},
        "pyjwt": {"pyjwt", "jwt"},
        "python-dateutil": {"python-dateutil", "dateutil"},
    }
    
    # Check if this package has known equivalences
    if name in equivalences:
        return equivalences[name]
    
    # For scoped packages (@scope/name), store multiple forms
    if name.startswith("@"):
        parts = name.split("/")
        if len(parts) == 2:
            scope, pkg = parts
            return {name, pkg, name.replace("@", ""), name.replace("/", "-")}
    
    # Standard normalization: handle hyphen/underscore equivalence
    normalized = {
        name,
        name.replace("-", "_"),
        name.replace("_", "-"),
        name.replace("-", ""),  # Also try removing hyphens entirely
        name.replace("_", ""),  # Also try removing underscores entirely
    }
    
    return normalized


def _packages_match(import_name: str, normalized_pkg: Dict[str, str]) -> bool:
    """
    Checks if an import matches a normalized package name.
    Handles case-insensitivity and special cases.
    """
    import_lower = import_name.lower().strip()
    
    # Check all normalized forms
    for form in normalized_pkg:
        form_lower = form.lower().strip()
        
        # Exact match
        if import_lower == form_lower:
            return True
        
        # Handle scoped package matching (@scope/package matches package)
        if import_lower.startswith("@") and "/" in import_lower:
            parts = import_lower.split("/")
            if len(parts) == 2:
                scope, pkg = parts
                if pkg == form_lower or form_lower == import_lower:
                    return True
    
    return False
