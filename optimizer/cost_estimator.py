import networkx as nx


ECOSYSTEM_COMPLEXITY = {
    "pypi":  1.0,   # pip install -U is usually straightforward
    "npm":   1.2,   # node_modules can have cascading breaks
    "maven": 1.5,   # Java dependency upgrades often need code changes
    "root":  0.0,
}


def estimate_fix_cost(
    node: str,
    data: dict,
    G: nx.DiGraph
) -> float:
    """
    Estimates the engineering hours required to fix a vulnerable package.

    Formula:
        cost = base_hours
             × ecosystem_factor
             × dependent_factor
             × version_lag_factor

    All factors are >= 1.0 so cost only grows from the base.

    Args:
        node:  node id (e.g. 'pypi:werkzeug')
        data:  node attribute dict from the graph
        G:     the full dependency graph

    Returns:
        Estimated fix cost in hours (float, minimum 1.0)
    """
    base_hours = 2.0
    ecosystem  = data.get("ecosystem", "pypi")

    # Factor 1: ecosystem complexity
    eco_factor = ECOSYSTEM_COMPLEXITY.get(ecosystem, 1.0)

    # Factor 2: number of packages that depend on this one
    # More dependents = more things that could break when you upgrade
    in_degree = data.get("in_degree", 0)
    if in_degree == 0:
        dependent_factor = 1.0
    elif in_degree <= 2:
        dependent_factor = 1.3
    elif in_degree <= 5:
        dependent_factor = 1.7
    else:
        dependent_factor = 2.2

    # Factor 3: version lag
    # How outdated is the current version vs the fixed version?
    # More outdated = more likely to have breaking changes
    version_lag_factor = _estimate_version_lag(
        data.get("version", "unspecified"),
        _get_fixed_version(data)
    )

    cost = base_hours * eco_factor * dependent_factor * version_lag_factor
    return round(max(cost, 1.0), 2)


def estimate_fix_benefit(node: str, data: dict) -> float:
    """
    Estimates the risk reduction value from fixing a vulnerable package.

    Combines:
        - risk_score:      base vulnerability × centrality (from Module 3)
        - exposure_score:  simulation blast radius impact (from Module 4)
        - blast_radius:    average packages protected if this is fixed
        - fix_penalty:     heavy penalty if no fix is available

    Returns:
        Benefit score (float, higher = more valuable to fix)
    """
    risk_score    = data.get("risk_score", 0.0)
    exposure      = data.get("exposure_score", 0.0)
    mean_br       = data.get("mean_blast_radius", 1.0)
    fix_available = data.get("fix_available", False)
    cvss          = data.get("cvss_score", 0.0)

    # Core benefit combines static risk with dynamic simulation results
    benefit = (
        risk_score    * 0.40 +   # static centrality-weighted risk
        exposure      * 0.35 +   # simulation-derived exposure
        mean_br       * 3.0  +   # each protected package = 3 benefit points
        cvss          * 1.5      # raw severity still matters
    )

    # Heavy penalty if no fix exists — can't actually resolve it
    if not fix_available:
        benefit *= 0.15

    return round(max(benefit, 0.1), 2)


def _get_fixed_version(data: dict) -> str | None:
    """Extracts the fixed version from the first vulnerability record."""
    vulns = data.get("vulnerabilities", [])
    for v in vulns:
        if v.get("fixed_in"):
            return v["fixed_in"]
    return None


def _estimate_version_lag(current: str, fixed: str | None) -> float:
    """
    Estimates how hard an upgrade will be based on version distance.
    Uses semantic versioning major/minor/patch components.

    Major version bump (1.x → 2.x) = likely breaking changes = high cost
    Minor version bump (1.2 → 1.5) = moderate effort
    Patch version bump (1.2.3 → 1.2.9) = usually safe = low cost
    Unknown versions = assume moderate effort
    """
    if not fixed or current in ("unspecified", "inherited-from-parent"):
        return 1.3  # unknown lag — assume moderate

    try:
        cur_parts   = _parse_version(current)
        fixed_parts = _parse_version(fixed)

        if not cur_parts or not fixed_parts:
            return 1.3

        # Major version difference
        if fixed_parts[0] > cur_parts[0]:
            return 2.0  # likely breaking changes

        # Minor version difference
        if len(fixed_parts) > 1 and len(cur_parts) > 1:
            if fixed_parts[1] > cur_parts[1] + 2:
                return 1.5  # several minor versions behind

        # Patch only
        return 1.1

    except Exception:
        return 1.3


def _parse_version(version_str: str) -> list | None:
    """Parses a version string into a list of integers."""
    import re
    # Strip non-numeric prefix (e.g. 'v2.1.0' -> '2.1.0')
    clean = re.sub(r'^[^0-9]*', '', str(version_str))
    parts = clean.split(".")
    try:
        return [int(re.sub(r'[^0-9]', '', p)) for p in parts if p]
    except Exception:
        return None