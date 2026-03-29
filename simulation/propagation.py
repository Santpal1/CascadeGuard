import random
import networkx as nx


def compute_propagation_probability(
    source_cvss: float,
    target_risk_score: float,
    source_depth: int = 1,
    max_depth: int = 3
) -> float:
    """
    Probability of attack spreading from compromised node to dependent.

    Grounded factors:
        cvss_factor:    higher severity = spreads more easily
        depth_factor:   closer to root = higher impact (shallower = worse)
        resistance:     target's own risk score (higher risk = less resistant)

    Capped between 0.05 and 0.90 — never impossible, never certain.
    """
    # Factor 1: CVSS drives base probability
    cvss_factor = source_cvss / 10.0  # 0.0 to 1.0

    # Factor 2: depth — attacks closer to root spread more reliably
    # depth 1 = direct dep = factor 1.0
    # depth 3 = transitive  = factor 0.6
    depth_factor = 1.0 - (source_depth - 1) * (0.2 / max(max_depth - 1, 1))
    depth_factor = max(0.4, depth_factor)

    # Factor 3: target resistance — high risk targets are easier to infect
    resistance = 1.0 - (min(target_risk_score, 100) / 100.0)
    resistance = max(0.2, min(0.8, resistance))  # clamp 0.2-0.8

    probability = 0.5 * cvss_factor * depth_factor * (1.0 - resistance * 0.4)

    # Hard clamp — never impossible, never certain
    return round(max(0.05, min(0.90, probability)), 4)


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

                # In run_single_simulation, replace the prob line with:
                source_depth = G.nodes[node].get("depth", 1)
                prob = compute_propagation_probability(
                    node_cvss, dep_risk,
                    source_depth=source_depth,
                    max_depth=3
                )

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