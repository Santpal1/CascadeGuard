"""
Narrative Generator - Produces unified risk narratives combining attack classification
and module impact analysis.

Generates comprehensive narratives for CRITICAL and HIGH risk nodes.
"""

import logging
from typing import Dict, Optional, List
from risk.attack_classifier import classify_attack, extract_cwe_ids, get_attack_narrative

logger = logging.getLogger(__name__)


def generate_full_narrative(
    node_id: str,
    node_data: Dict,
    impact_map: Dict,
    risk_score: float,
    risk_class: str
) -> Dict:
    """
    Generates a comprehensive risk narrative combining all factors.
    
    Args:
        node_id: Package identifier (e.g., "npm:axios" or "axios")
        node_data: Node data from enriched graph
        impact_map: Result from impact_mapper.map_impact()
        risk_score: Numeric risk score (0-100)
        risk_class: "CRITICAL" / "HIGH" / "MEDIUM" / "LOW"
    
    Returns:
        {
            "package": "axios",
            "version": "0.21.1",
            "risk_score": 8.7,
            "risk_class": "CRITICAL",
            "attack_type": "Remote Code Execution",
            "attacker_capability": "Full server takeover via malicious response",
            "affected_files": ["payments/api.py", "auth/client.js"],
            "affected_features": ["Payment Processing", "Authentication"],
            "exposure_scope": "HIGH",
            "fix_recommendation": "Upgrade to axios@1.6.8 (no breaking changes)",
            "narrative": "..."
        }
    """
    # Extract package name from node ID (remove ecosystem prefix if present)
    if ":" in node_id:
        ecosystem, package_name = node_id.split(":", 1)
    else:
        package_name = node_id
    
    version = node_data.get("version", "unknown")
    package_full = f"{package_name}@{version}"
    
    # Extract vulnerabilities and CWE information
    vulns = node_data.get("vulnerabilities", [])
    
    # Extract CWE IDs from vulnerabilities
    cwe_ids = []
    for vuln in vulns:
        refs = vuln.get("references", [])
        for ref in refs:
            url = ref.get("url", "")
            if "cwe.mitre.org" in url:
                # Extract CWE ID
                parts = url.split("/")
                for i, p in enumerate(parts):
                    if p == "definitions" and i + 1 < len(parts):
                        cwe_num = parts[i + 1].replace(".html", "")
                        if cwe_num.isdigit():
                            cwe_ids.append(f"CWE-{cwe_num}")
    
    # Classify attack
    attack_classification = classify_attack(cwe_ids)
    
    # Get impact data using node_id (which has ecosystem prefix)
    impact_data = impact_map.get(node_id, {})
    affected_files = impact_data.get("affected_files", [])[:3]  # Top 3
    affected_entry_points = impact_data.get("entry_points", [])
    estimated_features = impact_data.get("features", [])
    exposure_scope = impact_data.get("exposure_scope", "UNKNOWN")
    
    # Generate fix recommendation
    fix_rec = _generate_fix_recommendation(
        package_name,
        version,
        vulns,
        node_data.get("fix_available", False)
    )
    
    # Generate narrative
    narrative = _build_narrative(
        package_full,
        attack_classification,
        affected_files,
        affected_entry_points,
        estimated_features,
        exposure_scope,
        vulns
    )
    
    return {
        "package": package_full,
        "risk_score": round(risk_score, 1),
        "risk_class": risk_class,
        "attack_type": attack_classification["primary_attack"],
        "attacker_capability": attack_classification["attacker_capability"],
        "affected_files": affected_files,
        "affected_features": estimated_features,
        "exposure_scope": exposure_scope,
        "fix_recommendation": fix_rec,
        "narrative": narrative
    }


def _generate_fix_recommendation(
    package_name: str,
    current_version: str,
    vulns: List[Dict],
    fix_available: bool
) -> str:
    """
    Generates a fix recommendation based on available patches.
    """
    if not vulns:
        return f"No automatic recommendation available for {package_name}@{current_version}"
    
    if not fix_available:
        return (f"No known fix available for {package_name}@{current_version}. "
               f"Consider removing this dependency or implementing additional mitigations.")
    
    # Try to find a recommended fixed version
    fixed_versions = [v.get("fixed_in") for v in vulns if v.get("fixed_in")]
    
    if fixed_versions:
        # Get the highest version number (simplified - doesn't handle semantic versioning perfectly)
        fixed_versions = list(set(fixed_versions))
        recommended_version = max(fixed_versions, key=lambda v: _version_sort_key(v))
        
        return (f"Upgrade to {package_name}@{recommended_version} "
               f"(addresses all known vulnerabilities)")
    
    return f"Updates available for {package_name}. Check release notes for breaking changes."


def _version_sort_key(version: str) -> tuple:
    """
    Converts a version string to a sortable tuple.
    Simple implementation: "1.2.3" -> (1, 2, 3)
    """
    if not version:
        return (0, 0, 0)
    
    parts = version.split(".")
    try:
        return tuple(int(p.split("-")[0]) for p in parts[:3])
    except (ValueError, IndexError):
        return (0, 0, 0)


def _build_narrative(
    package_full: str,
    attack_classification: Dict,
    affected_files: List[str],
    affected_entry_points: List[str],
    estimated_features: List[str],
    exposure_scope: str,
    vulns: List[Dict]
) -> str:
    """
    Builds a comprehensive narrative string.
    """
    parts = []
    
    # Start with package and primary attack
    primary_attack = attack_classification["primary_attack"]
    attack_types_str = ", ".join(attack_classification["attack_types"])
    
    parts.append(
        f"{package_full} contains a {primary_attack} vulnerability "
        f"({attack_types_str})."
    )
    
    # Add attacker capability
    capability = attack_classification["attacker_capability"]
    parts.append(f"An attacker could {capability}.")
    
    # Add module impact
    if affected_files or affected_entry_points:
        files_str = ", ".join(affected_files) if affected_files else "multiple files"
        parts.append(f"This vulnerability affects {files_str}.")
    
    if estimated_features:
        features_str = ", ".join(estimated_features)
        parts.append(f"User-facing features impacted: {features_str}.")
    
    if exposure_scope == "HIGH":
        parts.append("The exposure scope is HIGH due to entry point involvement.")
    elif exposure_scope == "MEDIUM":
        parts.append("The exposure scope is MEDIUM, affecting utility/shared code.")
    else:
        parts.append("The exposure scope is LOW, currently only indirect impact.")
    
    # Add severity context
    if vulns:
        cvss_scores = [v.get("cvss_score", 0) for v in vulns if v.get("cvss_score")]
        if cvss_scores:
            max_cvss = max(cvss_scores)
            parts.append(f"CVSS Score: {max_cvss:.1f}")
    
    return " ".join(parts)


def generate_rapid_narrative(package_name: str, attack_classification: Dict) -> str:
    """
    Quick narrative generation for the risk report output.
    Simpler than generate_full_narrative, suitable for summaries.
    """
    return get_attack_narrative(package_name, attack_classification)
