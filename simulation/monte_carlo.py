import random
from collections import defaultdict
import networkx as nx
from simulation.propagation import run_single_simulation


def run_monte_carlo(
    G: nx.DiGraph,
    origin_node: str,
    n_simulations: int = 1000
) -> dict:
    """
    Runs n_simulations attack simulations from a single origin node
    and aggregates the results into a statistical summary.

    Returns:
        {
            "origin":                 node id,
            "n_simulations":          int,
            "mean_blast_radius":      float,
            "max_blast_radius":       int,
            "min_blast_radius":       int,
            "std_blast_radius":       float,
            "p50_blast_radius":       float  (median),
            "p95_blast_radius":       float  (worst case),
            "critical_hit_rate":      float  (0-1),
            "node_infection_prob":    dict   {node_id: probability},
            "exposure_score":         float  (0-100, overall danger rating)
        }
    """
    blast_radii    = []
    critical_hits  = 0
    node_hit_count = defaultdict(int)

    for i in range(n_simulations):
        result = run_single_simulation(G, origin_node, seed=None)

        blast_radii.append(result["blast_radius"])
        if result["critical_hit"]:
            critical_hits += 1
        for node in result["compromised"]:
            node_hit_count[node] += 1

    # ── Statistics ────────────────────────────────────────────────────
    n = len(blast_radii)
    mean_br  = sum(blast_radii) / n
    max_br   = max(blast_radii)
    min_br   = min(blast_radii)

    # Standard deviation
    variance = sum((x - mean_br) ** 2 for x in blast_radii) / n
    std_br   = variance ** 0.5

    # Percentiles — sort and index
    sorted_br = sorted(blast_radii)
    p50 = sorted_br[int(n * 0.50)]
    p95 = sorted_br[int(n * 0.95)]

    # Node infection probabilities
    node_infection_prob = {
        node: round(count / n, 4)
        for node, count in node_hit_count.items()
    }

    # ── Exposure Score (0-100) ─────────────────────────────────────────
    # Combines:
    #   - mean blast radius relative to total graph size
    #   - critical hit rate
    #   - p95 worst case relative to graph size
    total_nodes = G.number_of_nodes()
    origin_cvss = G.nodes[origin_node].get("cvss_score", 0.0)

    br_factor       = (mean_br / total_nodes) * 100
    critical_factor = (critical_hits / n) * 100
    p95_factor      = (p95 / total_nodes) * 100
    cvss_factor     = (origin_cvss / 10.0) * 100

    exposure_score = (
        br_factor       * 0.35 +
        critical_factor * 0.25 +
        p95_factor      * 0.25 +
        cvss_factor     * 0.15
    )

    return {
        "origin":              origin_node,
        "n_simulations":       n_simulations,
        "mean_blast_radius":   round(mean_br, 2),
        "max_blast_radius":    max_br,
        "min_blast_radius":    min_br,
        "std_blast_radius":    round(std_br, 2),
        "p50_blast_radius":    p50,
        "p95_blast_radius":    p95,
        "critical_hit_rate":   round(critical_hits / n, 4),
        "node_infection_prob": node_infection_prob,
        "exposure_score":      round(min(exposure_score, 100.0), 2)
    }