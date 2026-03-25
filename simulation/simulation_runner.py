import json
import os
import networkx as nx
from simulation.monte_carlo import run_monte_carlo


def run_full_simulation(
    G: nx.DiGraph,
    n_simulations: int = 1000,
    output_path: str = "output/simulation_results.json"
) -> dict:
    """
    Runs Monte Carlo simulations for every vulnerable node in the graph
    and compiles a full simulation report.

    Only simulates from nodes with cvss_score > 0 — clean nodes
    can't be attack origins.

    Returns a dict of {node_id: simulation_results} plus
    a global summary.
    """

    # Find all vulnerable origin candidates
    vulnerable_nodes = [
        (node, data) for node, data in G.nodes(data=True)
        if data.get("cvss_score", 0.0) > 0
        and data.get("ecosystem") != "root"
    ]

    if not vulnerable_nodes:
        print("[simulation] No vulnerable nodes found. Nothing to simulate.")
        return {}

    print(f"\n[simulation] Starting Monte Carlo simulation")
    print(f"[simulation] Origin nodes:   {len(vulnerable_nodes)}")
    print(f"[simulation] Runs per node:  {n_simulations}")
    print(f"[simulation] Total runs:     {len(vulnerable_nodes) * n_simulations}\n")

    all_results = {}

    for i, (node, data) in enumerate(vulnerable_nodes):
        print(f"[simulation] ({i+1}/{len(vulnerable_nodes)}) "
              f"Simulating from: {node} "
              f"(CVSS {data.get('cvss_score', 0)}, "
              f"{data.get('risk_class', 'UNKNOWN')})")

        result = run_monte_carlo(G, node, n_simulations)
        all_results[node] = result

        # Attach simulation results back to the graph node
        G.nodes[node]["exposure_score"]    = result["exposure_score"]
        G.nodes[node]["mean_blast_radius"] = result["mean_blast_radius"]
        G.nodes[node]["p95_blast_radius"]  = result["p95_blast_radius"]
        G.nodes[node]["critical_hit_rate"] = result["critical_hit_rate"]

    # ── Global Summary ────────────────────────────────────────────────
    summary = _build_summary(all_results, G)
    all_results["__summary__"] = summary

    # Save to disk
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    # node_infection_prob contains sets — convert for JSON serialization
    serializable = _make_serializable(all_results)
    with open(output_path, "w") as f:
        json.dump(serializable, f, indent=2)

    print(f"\n[simulation] Results saved to {output_path}")
    _print_simulation_report(all_results, G)

    return all_results


def _build_summary(all_results: dict, G: nx.DiGraph) -> dict:
    """Builds a global summary across all simulations."""
    results = {k: v for k, v in all_results.items() if k != "__summary__"}

    if not results:
        return {}

    # Highest exposure node
    top_node = max(results, key=lambda n: results[n]["exposure_score"])

    # Average blast radius across all origins
    avg_blast = sum(r["mean_blast_radius"] for r in results.values()) / len(results)

    # Nodes that appear in >50% of ANY simulation — systemic risk nodes
    systemic_nodes = set()
    for result in results.values():
        for node, prob in result["node_infection_prob"].items():
            if prob >= 0.5:
                systemic_nodes.add(node)

    return {
        "total_vulnerable_origins": len(results),
        "average_blast_radius":     round(avg_blast, 2),
        "highest_exposure_node":    top_node,
        "highest_exposure_score":   results[top_node]["exposure_score"],
        "systemic_risk_nodes":      list(systemic_nodes),
        "systemic_risk_count":      len(systemic_nodes),
    }


def _print_simulation_report(all_results: dict, G: nx.DiGraph):
    """Prints a ranked summary table of simulation results."""
    results = {k: v for k, v in all_results.items() if k != "__summary__"}

    ranked = sorted(
        results.items(),
        key=lambda x: x[1]["exposure_score"],
        reverse=True
    )

    summary = all_results.get("__summary__", {})

    print("\n[simulation] ── Simulation Report ─────────────────────────────")
    print(f"  {'Package':<40} {'Exposure':>8} {'Mean BR':>7} "
          f"{'P95 BR':>6} {'Crit%':>6}")
    print(f"  {'─'*40} {'─'*8} {'─'*7} {'─'*6} {'─'*6}")

    for node, result in ranked:
        print(
            f"  {node:<40} "
            f"{result['exposure_score']:>8.1f} "
            f"{result['mean_blast_radius']:>7.1f} "
            f"{result['p95_blast_radius']:>6} "
            f"{result['critical_hit_rate']*100:>5.1f}%"
        )

    print(f"  {'─'*72}")
    print(f"\n  Systemic risk nodes (infected in >50% of simulations): "
          f"{summary.get('systemic_risk_count', 0)}")
    for node in summary.get('systemic_risk_nodes', []):
        print(f"    → {node}")
    print()


def _make_serializable(obj):
    """Recursively converts sets to lists for JSON serialization."""
    if isinstance(obj, set):
        return list(obj)
    if isinstance(obj, dict):
        return {k: _make_serializable(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_make_serializable(v) for v in obj]
    return obj