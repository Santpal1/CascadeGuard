import random
import networkx as nx


def compute_propagation_probability(
    source_cvss: float,
    target_risk_score: float
) -> float:
    """
    Computes the probability that an attack spreads from a compromised
    node to a dependent node.

    Formula:
        P = base_p × cvss_factor × (1 - target_resistance)

    Where:
        base_p           = 0.5 (baseline 50% chance any edge is exploited)
        cvss_factor      = CVSS/10 (higher severity = more likely to spread)
        target_resistance = target's own risk score normalized 0-1
                           (a well-patched, low-risk node resists better)

    This means:
        - CVSS 10.0 vulnerability has base 50% × 100% = 50% spread chance
        - CVSS 4.0 vulnerability has base 50% × 40%  = 20% spread chance
        - A high-risk target node is EASIER to infect (less resistance)
        - A clean target node is harder to infect
    """
    base_p = 0.5
    cvss_factor = source_cvss / 10.0

    # Target resistance: higher risk_score = already vulnerable = less resistance
    # Normalize target risk_score from 0-100 to 0-1
    target_resistance = 1.0 - (min(target_risk_score, 100) / 100.0)
    # Clamp resistance between 0.1 and 0.9 — never impossible, never certain
    target_resistance = max(0.1, min(0.9, target_resistance))

    probability = base_p * cvss_factor * (1.0 - target_resistance * 0.5)
    return round(min(probability, 0.95), 4)  # cap at 95%


def run_single_simulation(
    G: nx.DiGraph,
    origin_node: str,
    seed: int = None
) -> dict:
    """
    Simulates one attack propagation starting from origin_node.

    Uses a probabilistic BFS — at each step, the attack tries to
    spread from every currently compromised node to its dependents.
    Each spread attempt is a random coin flip weighted by propagation
    probability.

    Args:
        G:           enriched dependency graph
        origin_node: node where the attack originates
        seed:        random seed for reproducibility

    Returns:
        {
            "origin":           node id,
            "compromised":      set of compromised node ids,
            "blast_radius":     count of compromised nodes,
            "critical_hit":     whether any CRITICAL node was compromised,
            "propagation_path": ordered list showing spread sequence,
            "depth_reached":    how many hops from origin
        }
    """
    if seed is not None:
        random.seed(seed)

    origin_data = G.nodes.get(origin_node, {})
    origin_cvss = origin_data.get("cvss_score", 0.0)

    compromised = {origin_node}
    propagation_path = [origin_node]
    frontier = {origin_node}  # nodes to spread from in this step
    depth = 0
    critical_hit = origin_data.get("risk_class") == "CRITICAL"

    while frontier:
        next_frontier = set()
        depth += 1

        for node in frontier:
            node_data = G.nodes.get(node, {})
            node_cvss = node_data.get("cvss_score", origin_cvss)

            # Get all nodes that depend on this one (predecessors in DiGraph)
            # These are the packages that IMPORT this package —
            # if this package is compromised, they are at risk
            dependents = list(G.predecessors(node))

            for dependent in dependents:
                if dependent in compromised:
                    continue  # already compromised

                dep_data = G.nodes.get(dependent, {})
                dep_risk = dep_data.get("risk_score", 0.0)

                prob = compute_propagation_probability(node_cvss, dep_risk)

                if random.random() < prob:
                    compromised.add(dependent)
                    next_frontier.add(dependent)
                    propagation_path.append(dependent)

                    if dep_data.get("risk_class") == "CRITICAL":
                        critical_hit = True

        frontier = next_frontier

    return {
        "origin":           origin_node,
        "compromised":      compromised,
        "blast_radius":     len(compromised),
        "critical_hit":     critical_hit,
        "propagation_path": propagation_path,
        "depth_reached":    depth
    }