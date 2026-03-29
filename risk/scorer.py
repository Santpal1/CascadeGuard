import math

def compute_risk_score(
    cvss_score: float,
    pagerank: float,
    in_degree: int,
    mean_blast_radius: float = 0.0,
    critical_hit_rate: float = 0.0,
    exposure_score: float = 0.0,
    max_pagerank: float = 1.0
) -> float:
    """
    Composite risk score (0-100).

    Components:
        CVSS score         — raw exploitability        (40%)
        Normalized pagerank — structural importance    (25%)
        Blast radius        — simulation mean impact   (20%)
        Critical hit rate   — worst case probability   (15%)

    in_degree removed as standalone factor — already captured by pagerank.
    Simulation results integrated directly so score is dynamic, not static.
    """
    if cvss_score == 0.0:
        return 0.0

    # Normalize each input to 0-1
    cvss_norm     = cvss_score / 10.0
    pagerank_norm = pagerank / max_pagerank if max_pagerank > 0 else 0.0
    br_norm       = min(mean_blast_radius / 50.0, 1.0)  # cap at 50 nodes
    crit_norm     = critical_hit_rate  # already 0-1

    # Weighted combination — no multiplication chains
    raw = (
        cvss_norm     * 0.40 +
        pagerank_norm * 0.25 +
        br_norm       * 0.20 +
        crit_norm     * 0.15
    )

    return round(min(raw * 100, 100.0), 2)


def classify_risk(score: float) -> str:
    if score >= 35: return "CRITICAL"
    if score >= 20: return "HIGH"
    if score >= 10: return "MEDIUM"
    if score > 0:   return "LOW"
    return "CLEAN"