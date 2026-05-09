"""
Attack Type Classification - Maps CWE IDs to human-readable attack categories.

Extracts CWE IDs from vulnerability data and classifies them into
attack types with narrative descriptions.

Strategy (Option C):
    1. Check curated CWE_ATTACK_MAP first — rich, hand-crafted entries
    2. Fall back to local cwe_db.json (parsed from cwec_v4.20.xml) for anything else
       Run parse_cwe_xml.py once to generate output/cwe_db.json
"""

import logging
import json
import os
import re
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)

# ─── Local CWE DB (parsed from cwec_v4.20.xml by parse_cwe_xml.py) ──────────

_CWE_DB_PATH = os.path.join(os.path.dirname(__file__), "..", "output", "cwe_db.json")
_cwe_db: dict = {}
_cwe_db_loaded: bool = False


def _load_cwe_db():
    global _cwe_db, _cwe_db_loaded
    if _cwe_db_loaded:
        return
    try:
        if os.path.exists(_CWE_DB_PATH):
            with open(_CWE_DB_PATH, "r") as f:
                _cwe_db = json.load(f)
            logger.debug(f"[cwe_db] Loaded {len(_cwe_db)} entries from {_CWE_DB_PATH}")
        else:
            logger.warning(
                f"[cwe_db] {_CWE_DB_PATH} not found. "
                f"Run parse_cwe_xml.py to generate it."
            )
    except Exception as e:
        logger.warning(f"[cwe_db] Failed to load cwe_db.json: {e}")
    _cwe_db_loaded = True


# ─── Curated CWE map (checked first, cwe_db.json used as fallback) ───────────

CWE_ATTACK_MAP = {
    # Injection Attacks
    "CWE-78": {
        "category": "Command Injection",
        "attack_type": "Remote Code Execution",
        "attacker_capability": "Execute arbitrary system commands",
        "impact": "Full system compromise",
        "severity": "CRITICAL"
    },
    "CWE-89": {
        "category": "SQL Injection",
        "attack_type": "Data Manipulation / Theft",
        "attacker_capability": "Read/modify/delete database records",
        "impact": "Database compromise, data theft",
        "severity": "CRITICAL"
    },
    "CWE-94": {
        "category": "Code Injection",
        "attack_type": "Remote Code Execution",
        "attacker_capability": "Execute arbitrary code in application context",
        "impact": "Full application compromise",
        "severity": "CRITICAL"
    },

    # Web-based Injection
    "CWE-79": {
        "category": "Cross-Site Scripting (XSS)",
        "attack_type": "Session Hijacking / Malware Delivery",
        "attacker_capability": "Execute arbitrary JavaScript in user's browser",
        "impact": "Session theft, credential theft, malware injection",
        "severity": "HIGH"
    },
    "CWE-611": {
        "category": "XML External Entity (XXE)",
        "attack_type": "Remote Code Execution / Data Theft",
        "attacker_capability": "Read sensitive files, SSRF attacks, RCE",
        "impact": "File disclosure, remote code execution",
        "severity": "CRITICAL"
    },
    "CWE-601": {
        "category": "Open Redirect",
        "attack_type": "Phishing / Social Engineering",
        "attacker_capability": "Redirect users to attacker-controlled sites",
        "impact": "Phishing, credential theft, malware delivery",
        "severity": "MEDIUM"
    },

    # Path / File
    "CWE-22": {
        "category": "Path Traversal",
        "attack_type": "Arbitrary File Read / Write",
        "attacker_capability": "Access or overwrite files outside intended directory",
        "impact": "Sensitive file disclosure, config/source code exposure",
        "severity": "HIGH"
    },
    "CWE-73": {
        "category": "External Control of File Name or Path",
        "attack_type": "Arbitrary File Access",
        "attacker_capability": "Control file paths used by the application",
        "impact": "File disclosure, potential code execution",
        "severity": "HIGH"
    },

    # Memory & Type Safety
    "CWE-119": {
        "category": "Buffer Overflow",
        "attack_type": "Remote Code Execution / Denial of Service",
        "attacker_capability": "Corrupt memory, execute arbitrary code, crash application",
        "impact": "System takeover, denial of service",
        "severity": "CRITICAL"
    },
    "CWE-772": {
        "category": "Memory Leak",
        "attack_type": "Information Disclosure / Denial of Service",
        "attacker_capability": "Exhaust system memory, trigger crashes",
        "impact": "Server crash, DoS, potential information leakage",
        "severity": "MEDIUM"
    },

    # ReDoS / Resource
    "CWE-1333": {
        "category": "Inefficient Regular Expression (ReDoS)",
        "attack_type": "Denial of Service",
        "attacker_capability": "Trigger catastrophic backtracking via crafted input",
        "impact": "Application hang, event-loop block in Node.js",
        "severity": "HIGH"
    },
    "CWE-400": {
        "category": "Uncontrolled Resource Consumption (DoS)",
        "attack_type": "Denial of Service",
        "attacker_capability": "Exhaust system resources (CPU, memory, disk)",
        "impact": "Service unavailability, system crash",
        "severity": "HIGH"
    },
    "CWE-770": {
        "category": "Allocation of Resources Without Limits",
        "attack_type": "Denial of Service",
        "attacker_capability": "Force unbounded memory or CPU allocation",
        "impact": "Service crash, resource exhaustion",
        "severity": "MEDIUM"
    },

    # Information & Authentication
    "CWE-200": {
        "category": "Information Disclosure",
        "attack_type": "Sensitive Data Exposure",
        "attacker_capability": "Read sensitive information (keys, tokens, PII)",
        "impact": "Exposure of credentials, API keys, user data",
        "severity": "HIGH"
    },
    "CWE-287": {
        "category": "Authentication Bypass",
        "attack_type": "Unauthorized Access",
        "attacker_capability": "Gain access without valid credentials",
        "impact": "Unauthorized access to accounts and features",
        "severity": "CRITICAL"
    },
    "CWE-306": {
        "category": "Missing Authentication for Critical Function",
        "attack_type": "Unauthorized Access",
        "attacker_capability": "Invoke privileged functions without authentication",
        "impact": "Full account/admin takeover",
        "severity": "CRITICAL"
    },
    "CWE-352": {
        "category": "Cross-Site Request Forgery (CSRF)",
        "attack_type": "Unauthorized Action Execution",
        "attacker_capability": "Perform actions on behalf of authenticated users",
        "impact": "Unauthorized modifications, fund transfers, account takeover",
        "severity": "HIGH"
    },

    # Prototype Pollution (very common in npm)
    "CWE-1321": {
        "category": "Prototype Pollution",
        "attack_type": "Remote Code Execution / Denial of Service",
        "attacker_capability": "Pollute Object.prototype to alter application behaviour",
        "impact": "Property injection, RCE in some frameworks, DoS",
        "severity": "HIGH"
    },

    # Cryptographic & Security
    "CWE-310": {
        "category": "Cryptographic Issues",
        "attack_type": "Data Compromise",
        "attacker_capability": "Decrypt sensitive information or forge signatures",
        "impact": "Data decryption, authentication bypass",
        "severity": "HIGH"
    },
    "CWE-327": {
        "category": "Use of Broken/Risky Cryptographic Algorithm",
        "attack_type": "Data Compromise",
        "attacker_capability": "Break encryption and forge or read protected data",
        "impact": "Credential exposure, signature forgery",
        "severity": "HIGH"
    },

    # Upload & File Handling
    "CWE-434": {
        "category": "Unrestricted File Upload",
        "attack_type": "Remote Code Execution / Malware Injection",
        "attacker_capability": "Upload and execute arbitrary files",
        "impact": "Remote code execution, malware injection",
        "severity": "CRITICAL"
    },

    # Deserialization
    "CWE-502": {
        "category": "Insecure Deserialization",
        "attack_type": "Remote Code Execution",
        "attacker_capability": "Instantiate arbitrary objects, execute code",
        "impact": "Remote code execution, application takeover",
        "severity": "CRITICAL"
    },

    # SSRF
    "CWE-918": {
        "category": "Server-Side Request Forgery (SSRF)",
        "attack_type": "Internal Network Access / Data Theft",
        "attacker_capability": "Make requests to internal services, access cloud metadata",
        "impact": "Access to internal services, cloud credential theft",
        "severity": "HIGH"
    },

    # Open / Misc
    "CWE-20": {
        "category": "Improper Input Validation",
        "attack_type": "Varies by Context",
        "attacker_capability": "Submit malformed input to trigger unintended behaviour",
        "impact": "Depends on usage — DoS, injection, bypass",
        "severity": "MEDIUM"
    },
    "CWE-noinfo": {
        "category": "Insufficient Information",
        "attack_type": "Unknown Attack Type",
        "attacker_capability": "Insufficient data to determine attacker capability",
        "impact": "Unknown",
        "severity": "UNKNOWN"
    },
}

# Severity hierarchy for determining primary attack
SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH":     1,
    "MEDIUM":   2,
    "LOW":      3,
    "UNKNOWN":  4,
}


def _lookup_cwe(cwe_id: str) -> Optional[Dict]:
    """
    Looks up a CWE ID.
    1. Curated CWE_ATTACK_MAP  — rich hand-crafted entries, checked first.
    2. Local cwe_db.json       — full MITRE dataset (~1000 entries), no network.
    """
    if cwe_id in CWE_ATTACK_MAP:
        return CWE_ATTACK_MAP[cwe_id]

    _load_cwe_db()
    entry = _cwe_db.get(cwe_id)
    if entry:
        logger.debug(f"[cwe_db] Resolved {cwe_id} from local DB: {entry['category']}")
    else:
        logger.debug(f"[cwe_db] {cwe_id} not found in curated map or local DB")
    return entry


def classify_attack(cwe_ids: List[str]) -> Dict:
    """
    Classifies a list of CWE IDs into attack types and capabilities.
    Unknown CWEs are resolved from local cwe_db.json (no network calls).

    Args:
        cwe_ids: List of CWE IDs (e.g., ["CWE-78", "CWE-79"])

    Returns:
        {
            "attack_types":        [...],   # matched attack category names
            "primary_attack":      "...",   # highest severity match
            "attacker_capability": "...",   # what attacker can DO
            "cwe_ids":             [...],   # normalized CWE IDs
            "has_cwe_match":       bool     # whether CWEs were resolved
        }
    """
    # Normalize CWE IDs
    normalized_cwe_ids = []
    if cwe_ids:
        for cwe_id in cwe_ids:
            cwe_id = cwe_id.strip().upper()
            if not cwe_id.startswith("CWE-"):
                cwe_id = f"CWE-{cwe_id}"
            if cwe_id not in normalized_cwe_ids:
                normalized_cwe_ids.append(cwe_id)

    matched_attacks = []
    capabilities    = set()

    for cwe_id in normalized_cwe_ids:
        attack_info = _lookup_cwe(cwe_id)
        if attack_info:
            matched_attacks.append(attack_info)
            capabilities.add(attack_info["attacker_capability"])

    # Sort by severity to find primary
    matched_attacks.sort(
        key=lambda x: SEVERITY_ORDER.get(x.get("severity", "UNKNOWN"), 999)
    )

    primary_attack = matched_attacks[0]["attack_type"] if matched_attacks else "Unknown Attack Type"
    attack_types   = sorted(set(a["category"] for a in matched_attacks))
    attacker_capability = (
        " + ".join(sorted(capabilities))
        if capabilities
        else "Malicious activity enabled by vulnerability"
    )

    return {
        "attack_types":        attack_types,
        "primary_attack":      primary_attack,
        "attacker_capability": attacker_capability,
        "cwe_ids":             normalized_cwe_ids,
        "has_cwe_match":       len(matched_attacks) > 0,
    }


def extract_cwe_ids(vulnerabilities: List[Dict]) -> List[str]:
    """
    Extracts CWE IDs from vulnerability objects returned by osv_client.
    Checks all locations OSV may store CWE data.

    Args:
        vulnerabilities: List of vulnerability dicts from OSV

    Returns:
        Deduplicated list of CWE IDs
    """
    cwe_ids     = []
    cwe_regex   = re.compile(r'CWE-\d+', re.IGNORECASE)
    cwe_url_pat = "cwe.mitre.org"

    def _add(cwe_str: str):
        val = cwe_str.strip().upper()
        if not val.startswith("CWE-"):
            val = f"CWE-{val}"
        if re.match(r'CWE-\d+', val) and val not in cwe_ids:
            cwe_ids.append(val)

    for vuln in vulnerabilities:
        # ── Method 0: aliases (e.g. ["CWE-400", "CVE-2023-1234"]) ─────────────
        for alias in vuln.get("aliases", []):
            if re.match(r'(?i)CWE-\d+', alias):
                _add(alias)

        # ── Method 1: references — CWE URLs and inline CWE mentions ───────────
        for ref in vuln.get("references", []):
            url = ref.get("url", "") if isinstance(ref, dict) else ref
            if not url:
                continue

            if cwe_url_pat in url:
                # https://cwe.mitre.org/data/definitions/78.html
                parts = url.split("/")
                for i, part in enumerate(parts):
                    if part == "definitions" and i + 1 < len(parts):
                        cwe_num = parts[i + 1].replace(".html", "").split("?")[0]
                        if cwe_num.isdigit():
                            _add(f"CWE-{cwe_num}")
                        break

            for match in cwe_regex.findall(url):
                _add(match)

        # ── Method 2: database_specific.cwe_ids / .cwe / .CWE ────────────────
        db = vuln.get("database_specific", {})
        if isinstance(db, dict):
            for key in ("cwe_ids", "cwe", "CWE"):
                val = db.get(key)
                if not val:
                    continue
                items = val if isinstance(val, list) else [val]
                for item in items:
                    _add(str(item))

        # ── Method 3: summary / details text ──────────────────────────────────
        for field in ("summary", "details"):
            text = vuln.get(field, "")
            if text:
                for match in cwe_regex.findall(text):
                    _add(match)

    return cwe_ids


def get_attack_narrative(
    package_name: str,
    attack_classification: Dict,
    severity: str = "UNKNOWN"
) -> str:
    """
    Generates a human-readable narrative sentence describing the attack.
    """
    primary_attack = attack_classification.get("primary_attack", "Unknown")
    attack_types   = attack_classification.get("attack_types", [])
    cwe_list       = attack_classification.get("cwe_ids", [])

    cwe_str     = ", ".join(cwe_list) if cwe_list else "Unspecified vulnerability"
    attack_desc = ", ".join(attack_types).lower() if attack_types else "a vulnerability"

    if primary_attack == "Remote Code Execution":
        return (f"{package_name} enables Remote Code Execution through {attack_desc}. "
                f"Attackers can execute arbitrary code with the application's privileges ({cwe_str})")

    if primary_attack == "Data Manipulation / Theft":
        return (f"{package_name} allows data theft and manipulation via {attack_desc}. "
                f"Sensitive data in databases or files may be exposed, modified, or deleted ({cwe_str})")

    if "Authentication" in primary_attack or "Unauthorized Access" in primary_attack:
        return (f"{package_name} allows unauthorized access through {attack_desc}. "
                f"Attackers can bypass authentication and access protected resources ({cwe_str})")

    if "Denial of Service" in primary_attack:
        return (f"{package_name} can be exploited for Denial of Service via {attack_desc}. "
                f"The application may become unavailable or unresponsive ({cwe_str})")

    if primary_attack == "Session Hijacking / Malware Delivery":
        return (f"{package_name} enables session hijacking and malware delivery via {attack_desc}. "
                f"User sessions can be compromised and malicious code injected ({cwe_str})")

    if primary_attack == "Phishing / Social Engineering":
        return (f"{package_name} can be used for phishing and social engineering via {attack_desc}. "
                f"Users may be redirected to attacker-controlled sites ({cwe_str})")

    if primary_attack == "Sensitive Data Exposure":
        return (f"{package_name} exposes sensitive data through {attack_desc}. "
                f"Credentials, API keys, and personal information may be revealed ({cwe_str})")

    if primary_attack == "Internal Network Access / Data Theft":
        return (f"{package_name} enables access to internal services via {attack_desc}. "
                f"Attackers can reach internal networks and cloud metadata services ({cwe_str})")

    if primary_attack == "Arbitrary File Read / Write":
        return (f"{package_name} allows path traversal via {attack_desc}. "
                f"Attackers can read or overwrite files outside the intended directory ({cwe_str})")

    if primary_attack == "Varies by Context":
        return (f"{package_name} has an input validation weakness ({attack_desc}). "
                f"Impact depends on context — potential DoS, injection, or bypass ({cwe_str})")

    if primary_attack == "Data Manipulation":
        return (f"{package_name} allows data manipulation via {attack_desc}. "
                f"Attackers may modify, corrupt, or delete application data ({cwe_str})")

    if primary_attack == "Security Bypass":
        return (f"{package_name} enables security control bypass via {attack_desc}. "
                f"Attackers can circumvent intended protections ({cwe_str})")

    if primary_attack == "Defense Evasion":
        return (f"{package_name} may allow attackers to hide malicious activity via {attack_desc}. "
                f"Attack traces may be obscured or logs tampered with ({cwe_str})")

    if primary_attack == "Security Weakness":
        return (f"{package_name} contains a security weakness ({attack_desc}). "
                f"This may be exploitable depending on application context ({cwe_str})")

    # Severity-based fallback
    if severity in ("CRITICAL", "HIGH"):
        return (f"{package_name} contains a {severity.lower()} security vulnerability. "
                f"This may enable {attack_desc} leading to system compromise or data exposure ({cwe_str})")

    # Generic fallback
    if attack_types:
        return (f"{package_name} has a known security issue ({attack_types[0]}). "
                f"Attackers may exploit {attack_desc} to compromise the application ({cwe_str})")

    return (f"{package_name} has a known security issue. "
            f"This vulnerability may enable attackers to compromise the application ({cwe_str})")