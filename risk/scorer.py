import math


def compute_risk_score(
    cvss_score: float,
    pagerank: float,
    in_degree: int,
    max_pagerank: float = 1.0
) -> float:
    """
    Computes a composite risk score (0–100) for a dependency node.

    Formula:
        risk = CVSS × (1 + normalized_pagerank) × (1 + log(in_degree + 1))

    Rationale:
        - CVSS:               raw exploitability of the vulnerability
        - pagerank multiplier: structural importance in the full graph
                               (accounts for transitive influence)
        - in_degree multiplier: number of packages directly depending on this
                                one — log-scaled to prevent outliers dominating
        - Normalized to 0–100 for readability

    Args:
        cvss_score:    float 0.0–10.0 from OSV
        pagerank:      float from networkx, pre-computed in Module 2
        in_degree:     int, number of direct dependents
        max_pagerank:  float, highest pagerank in the graph (for normalization)

    Returns:
        float 0.0–100.0
    """
    if cvss_score == 0.0:
        return 0.0

    # Normalize pagerank to 0–1 range relative to the graph
    norm_pagerank = pagerank / max_pagerank if max_pagerank > 0 else 0

    # Log-scale in_degree so highly connected nodes don't explode the score
    log_indegree = math.log(in_degree + 1)

    raw = cvss_score * (1 + norm_pagerank) * (1 + log_indegree)

    # CVSS max is 10, norm_pagerank max is 1, log(in_degree+1) grows slowly
    # Theoretical max ≈ 10 × 2 × ~4 = 80 for extreme cases
    # We cap and normalize to 100
    normalized = min((raw / 80) * 100, 100.0)

    return round(normalized, 2)


def classify_risk(score: float) -> str:
    if score >= 35: return "CRITICAL"
    if score >= 20: return "HIGH"
    if score >= 10: return "MEDIUM"
    if score > 0:   return "LOW"
    return "CLEAN"