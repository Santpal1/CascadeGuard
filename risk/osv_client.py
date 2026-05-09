import requests
import time

OSV_API_URL = "https://api.osv.dev/v1/query"

# Ecosystem name mapping — OSV uses specific casing
ECOSYSTEM_MAP = {
    "pypi":  "PyPI",
    "npm":   "npm",
    "maven": "Maven",
}

# In-memory cache — avoids re-querying the same package
_cache = {}


def query_vulnerabilities(name: str, version: str, ecosystem: str) -> list:
    """
    Queries the OSV database for known vulnerabilities affecting
    a specific package and version.

    Returns a list of vulnerability dicts, each containing:
        - vuln_id:     CVE or GHSA identifier
        - summary:     short description
        - severity:    CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN
        - cvss_score:  float 0.0–10.0
        - fixed_in:    version where the fix was released (or None)
        - detail_url:  link to full vulnerability details
    """
    cache_key = f"{ecosystem}:{name}:{version}"
    if cache_key in _cache:
        return _cache[cache_key]

    osv_ecosystem = ECOSYSTEM_MAP.get(ecosystem.lower())
    if not osv_ecosystem:
        return []

    payload = {
        "package": {
            "name": name,
            "ecosystem": osv_ecosystem
        }
    }

    # If we have a real version, include it for precise matching
    if version and version not in ("unspecified", "inherited-from-parent"):
        payload["version"] = _clean_version(version)

    try:
        response = requests.post(OSV_API_URL, json=payload, timeout=10)
        if not response.ok:
            print(f"[osv] WARNING: OSV returned {response.status_code} "
                  f"for {ecosystem}:{name}")
            return []

        data = response.json()
        vulns = data.get("vulns", [])
        result = [_parse_vulnerability(v) for v in vulns]

        _cache[cache_key] = result

        # Be respectful to the API — small delay between calls
        time.sleep(0.1)
        return result

    except requests.exceptions.Timeout:
        print(f"[osv] TIMEOUT querying {ecosystem}:{name}")
        return []
    except Exception as e:
        print(f"[osv] ERROR querying {ecosystem}:{name} — {e}")
        return []


def _parse_vulnerability(vuln: dict) -> dict:
    """
    Extracts the fields we care about from a raw OSV vulnerability object.
    OSV severity data is nested and inconsistent — this normalizes it.
    """
    vuln_id  = vuln.get("id", "UNKNOWN")
    summary  = vuln.get("summary", "No summary available")
    aliases  = vuln.get("aliases", [])  # often contains the CVE ID
    
    # IMPORTANT: Preserve references for CWE extraction
    references = vuln.get("references", [])

    # Prefer CVE alias over GHSA id for recognizability
    display_id = next(
        (a for a in aliases if a.startswith("CVE-")),
        vuln_id
    )

    # Extract CVSS score — OSV stores severity in multiple places
    cvss_score, severity = _extract_severity(vuln)

    # Find the fixed version from affected ranges
    fixed_in = _extract_fixed_version(vuln)

    detail_url = f"https://osv.dev/vulnerability/{vuln_id}"

    return {
    "vuln_id":           vuln_id,
    "display_id":        display_id,
    "summary":           summary,
    "severity":          severity,
    "cvss_score":        cvss_score,
    "fixed_in":          fixed_in,
    "detail_url":        detail_url,
    "references":        references,
    "database_specific": vuln.get("database_specific", {}),  # needed for CWE extraction
    "aliases":           aliases,                             # needed for CWE extraction
}


def _extract_severity(vuln: dict) -> tuple:
    """
    Extracts the best available CVSS score from an OSV vulnerability.

    OSV stores severity in three locations with inconsistent formats:
    1. severity[].score  — can be a float string OR a CVSS vector string
    2. database_specific.severity — a plain label like "HIGH" (most reliable)
    3. affected[].ecosystem_specific.severity — label, rarely present

    Strategy:
    - Try to extract a numeric score from the vector string first
    - Fall back to the label in database_specific (always present for GitHub vulns)
    - Final fallback: ecosystem_specific label
    """
    scores = []
    label_fallback = None

    # --- Location 1: severity array ---
    for sev in vuln.get("severity", []):
        score_str = sev.get("score", "")
        score_type = sev.get("type", "")

        if score_type == "CVSS_V4":
            # CVSS v4.0 vectors don't embed a numeric score.
            # Extract it from the vector metrics manually.
            score = _parse_cvss_v4_vector(score_str)
            if score is not None:
                scores.append(score)

        elif score_type in ("CVSS_V3", "CVSS_V2"):
            # CVSS v3/v2 vectors also don't have the number inline
            # but the database_specific label is more reliable here too
            score = _cvss_string_to_float(score_str)
            if score is not None:
                scores.append(score)

    # --- Location 2: database_specific.severity (most reliable label) ---
    db_specific = vuln.get("database_specific", {})
    db_label = db_specific.get("severity", "").upper()
    if db_label:
        label_fallback = db_label
        # If we have no numeric score yet, convert label to number
        score = _label_to_cvss(db_label)
        if score is not None and not scores:
            scores.append(score)

    # --- Location 3: affected[].ecosystem_specific ---
    for affected in vuln.get("affected", []):
        eco = affected.get("ecosystem_specific") or {}
        eco_label = eco.get("severity", "").upper()
        if eco_label and not scores and not label_fallback:
            score = _label_to_cvss(eco_label)
            if score is not None:
                scores.append(score)

    if not scores:
        return 0.0, "UNKNOWN"

    best_score = max(scores)
    # Use the database label if available — more precise than reverse-mapping
    final_label = label_fallback if label_fallback else _cvss_to_label(best_score)
    return round(best_score, 1), final_label


def _parse_cvss_v4_vector(vector: str) -> float | None:
    """
    CVSS v4.0 vectors look like:
    CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:H

    The numeric base score is NOT embedded in the vector string itself.
    We approximate it from the impact metrics using CVSS v4 severity mapping.

    Key metrics used:
        VC/VI/VA = Vulnerable system Confidentiality/Integrity/Availability
        SC/SI/SA = Subsequent system impact
        AV       = Attack Vector (N=Network is worst)
        AC       = Attack Complexity (L=Low is worst)
    """
    if not vector or "CVSS:4.0" not in vector:
        return None

    import re
    metrics = dict(re.findall(r'([A-Z]+):([A-Z]+)', vector))

    # Score the impact metrics
    impact_map = {"H": 2, "L": 1, "N": 0}
    vc = impact_map.get(metrics.get("VC", "N"), 0)
    vi = impact_map.get(metrics.get("VI", "N"), 0)
    va = impact_map.get(metrics.get("VA", "N"), 0)
    sc = impact_map.get(metrics.get("SC", "N"), 0)
    si = impact_map.get(metrics.get("SI", "N"), 0)
    sa = impact_map.get(metrics.get("SA", "N"), 0)

    total_impact = vc + vi + va + sc + si + sa  # max = 12

    # Score exploitability
    av_score = {"N": 1.0, "A": 0.8, "L": 0.6, "P": 0.3}.get(
        metrics.get("AV", "N"), 0.5
    )
    ac_score = {"L": 1.0, "H": 0.5}.get(metrics.get("AC", "L"), 0.75)

    # Combine: impact drives the score, exploitability scales it
    raw = (total_impact / 12) * 10 * av_score * ac_score

    return round(min(raw, 10.0), 1)


def _extract_fixed_version(vuln: dict) -> str | None:
    """
    Finds the version in which the vulnerability was fixed,
    from the affected ranges in the OSV record.
    """
    for affected in vuln.get("affected", []):
        for r in affected.get("ranges", []):
            for event in r.get("events", []):
                if "fixed" in event:
                    return event["fixed"]
    return None


def _cvss_string_to_float(score_str: str) -> float | None:
    """
    CVSS scores in OSV can be bare numbers ('7.5') or
    full vector strings ('CVSS:3.1/AV:N/AC:L/...').
    Extracts the numeric base score from either format.
    """
    if not score_str:
        return None
    import re
    # Match a float like 7.5 or 10.0 anywhere in the string
    match = re.search(r'\b(\d+\.\d+)\b', str(score_str))
    if match:
        return float(match.group(1))
    return None


def _label_to_cvss(label: str) -> float | None:
    """Maps severity labels to representative CVSS scores."""
    return {
        "CRITICAL": 9.5,
        "HIGH":     8.0,  # was 7.5 — HIGH typically clusters around 8
        "MEDIUM":   5.5,  # was 5.0
        "LOW":      2.0,
    }.get(label)

def _cvss_to_label(score: float) -> str:
    """Converts a numeric CVSS score to a severity label."""
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    if score > 0.0:  return "LOW"
    return "UNKNOWN"


def _clean_version(version: str) -> str:
    """
    Resolves version specifiers to a usable version string.

    Handles:
        '>=2.0.0'     -> '2.0.0'  (use minimum compatible)
        '^4.18.2'     -> '4.18.2' (caret = compatible with)
        '~=3.1.2'     -> '3.1.2'  (compatible release)
        '2.0.0,<3.0'  -> '2.0.0'  (range, take lower bound)
        'unspecified' -> ''        (let registry return latest)
    """
    import re

    if not version or version in ("unspecified", "inherited-from-parent"):
        return ""

    # Strip leading operators and spaces
    cleaned = re.sub(r'^[\^~=><! ]+', '', version.strip())

    # If range like '>=1.0.0,<2.0.0' take the first (lower) bound
    cleaned = cleaned.split(",")[0].strip()

    # Strip anything after whitespace (e.g. '2.0.0 ; python_requires')
    cleaned = cleaned.split()[0] if cleaned else ""

    # Validate it looks like a version
    if not re.match(r'^\d+', cleaned):
        return ""

    return cleaned