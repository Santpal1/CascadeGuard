import networkx as nx
from networkx.readwrite import json_graph
import json
import os

from risk.osv_client import query_vulnerabilities
from risk.scorer import compute_risk_score, classify_risk

def _aggregate_cvss(vulns: list) -> float:
    """
    Aggregates CVSS scores across all vulnerabilities.
    Uses max score but boosts for multiple highs and critical presence.

    Better than raw max because:
        - 1 critical + 5 highs is worse than just 1 critical
        - Volume of vulnerabilities indicates systemic neglect
    """
    if not vulns:
        return 0.0

    scores = [v["cvss_score"] for v in vulns if v["cvss_score"] > 0]
    if not scores:
        return 0.0

    max_score    = max(scores)
    has_critical = any(v["severity"] == "CRITICAL" for v in vulns)
    vuln_count   = len(scores)

    # Volume bonus: many vulns = slightly higher effective score
    volume_bonus = min(vuln_count * 0.05, 0.5)

    # Critical presence bonus
    critical_bonus = 0.3 if has_critical else 0.0

    aggregated = min(max_score + volume_bonus + critical_bonus, 10.0)
    return round(aggregated, 2)

def _build_explanation(node: str, data: dict, sim: dict) -> str:
    """
    Generates a human-readable explanation of why a node is risky.
    Stored as node attribute, used by dashboard and reports.
    """
    reasons = []

    cvss = data.get("cvss_score", 0)
    if cvss >= 9.0:
        reasons.append(f"Critical CVSS {cvss}")
    elif cvss >= 7.0:
        reasons.append(f"High CVSS {cvss}")
    elif cvss > 0:
        reasons.append(f"CVSS {cvss}")

    pagerank = data.get("pagerank", 0)
    if pagerank > 0.05:
        reasons.append("high graph centrality")

    in_deg = data.get("in_degree", 0)
    if in_deg >= 3:
        reasons.append(f"{in_deg} packages depend on it")

    br = sim.get("mean_blast_radius", 0)
    if br >= 3:
        reasons.append(f"blast radius {br:.1f} nodes on average")

    crit_rate = sim.get("critical_hit_rate", 0)
    if crit_rate >= 0.5:
        reasons.append(f"{crit_rate*100:.0f}% chance of critical cascade")

    vuln_count = data.get("vuln_count", 0)
    if vuln_count >= 5:
        reasons.append(f"{vuln_count} known vulnerabilities")

    if not reasons:
        return "Low severity vulnerability with minimal graph impact"

    return " + ".join(reasons)

def enrich_graph(G: nx.DiGraph, simulation_results: dict = None) -> nx.DiGraph:
    """
    Main entry point for Module 3.

    Takes an annotated dependency graph from Module 2,
    queries OSV for every non-root node, attaches vulnerability
    data, and computes a risk score for each node.

    New node attributes added:
        vulnerabilities: list of vuln dicts from OSV
        vuln_count:      total number of known vulnerabilities
        cvss_score:      highest CVSS score across all vulns (0.0–10.0)
        severity:        CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN / CLEAN
        risk_score:      composite score 0–100
        risk_class:      CRITICAL / HIGH / MEDIUM / LOW / CLEAN
        fix_available:   True if at least one vuln has a known fix

    Returns:
        The same graph with enriched node attributes.
    """
    nodes = [
        (node, data) for node, data in G.nodes(data=True)
        if data.get("ecosystem") != "root"
    ]

    print(f"\n[enricher] Enriching {len(nodes)} nodes...")

    # Pre-compute max pagerank for normalization in scorer
    all_pageranks = [
        d.get("pagerank", 0) for _, d in G.nodes(data=True)
        if d.get("ecosystem") != "root"
    ]
    max_pagerank = max(all_pageranks) if all_pageranks else 1.0

    # Track summary stats
    total_vulns    = 0
    vulnerable_nodes = 0
    critical_nodes = 0

    for i, (node, data) in enumerate(nodes):
        name      = data.get("id", node).split(":")[-1] if ":" in node else node
        version   = data.get("version", "unspecified")
        ecosystem = data.get("ecosystem", "")

        print(f"[enricher] ({i+1}/{len(nodes)}) Querying: {node}")

        vulns = query_vulnerabilities(name, version, ecosystem)

        # Pick the worst CVSS score across all vulnerabilities
        cvss_score = _aggregate_cvss(vulns)

        fix_available = any(v["fixed_in"] is not None for v in vulns)

        risk_score = compute_risk_score(
            cvss_score=cvss_score,
            pagerank=data.get("pagerank", 0),
            in_degree=data.get("in_degree", 0),
            max_pagerank=max_pagerank
        )
        risk_class = classify_risk(risk_score)

        # Store everything back on the node
        G.nodes[node]["vulnerabilities"] = vulns
        G.nodes[node]["vuln_count"]      = len(vulns)
        G.nodes[node]["cvss_score"]      = cvss_score
        G.nodes[node]["severity"]        = vulns[0]["severity"] if vulns else "CLEAN"
        G.nodes[node]["risk_score"]      = risk_score
        G.nodes[node]["risk_class"]      = risk_class
        G.nodes[node]["fix_available"]   = fix_available

        if vulns:
            vulnerable_nodes += 1
            total_vulns += len(vulns)
            if risk_class == "CRITICAL":
                critical_nodes += 1
    sim = simulation_results.get(node, {}) if simulation_results else {}
    G.nodes[node]["explanation"] = _build_explanation(node, G.nodes[node], sim)

    print(f"\n[enricher] ── Enrichment Summary ─────────────────────")
    print(f"[enricher] Nodes scanned:      {len(nodes)}")
    print(f"[enricher] Vulnerable nodes:   {vulnerable_nodes}")
    print(f"[enricher] Total vulns found:  {total_vulns}")
    print(f"[enricher] Critical nodes:     {critical_nodes}")
    print(f"[enricher] ────────────────────────────────────────────\n")

    return G

def rescore_after_simulation(G: nx.DiGraph, simulation_results: dict) -> nx.DiGraph:
    """
    Re-computes risk scores after simulation results are available.
    Called after run_full_simulation() in main.py.
    Updates each node's risk_score and risk_class with simulation data.
    """
    from risk.scorer import compute_risk_score, classify_risk

    all_pageranks = [
        d.get("pagerank", 0) for _, d in G.nodes(data=True)
        if d.get("ecosystem") != "root"
    ]
    max_pagerank = max(all_pageranks) if all_pageranks else 1.0

    print("\n[enricher] Re-scoring nodes with simulation data...")

    for node, data in G.nodes(data=True):
        if data.get("ecosystem") == "root":
            continue

        sim = simulation_results.get(node, {})

        new_score = compute_risk_score(
            cvss_score         = data.get("cvss_score", 0.0),
            pagerank           = data.get("pagerank", 0.0),
            in_degree          = data.get("in_degree", 0),
            mean_blast_radius  = sim.get("mean_blast_radius", 0.0),
            critical_hit_rate  = sim.get("critical_hit_rate", 0.0),
            exposure_score     = sim.get("exposure_score", 0.0),
            max_pagerank       = max_pagerank
        )

        G.nodes[node]["risk_score"]  = new_score
        G.nodes[node]["risk_class"]  = classify_risk(new_score)

    print("[enricher] Re-scoring complete.")
    return G

def export_enriched_graph(G: nx.DiGraph, path: str = "output/enriched_graph.json"):
    """Saves the enriched graph to JSON for Ayan's simulation module."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    data = json_graph.node_link_data(G)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[enricher] Enriched graph saved to {path}")


def load_enriched_graph(path: str = "output/enriched_graph.json") -> nx.DiGraph:
    """Ayan loads this instead of re-running enrichment."""
    with open(path, "r") as f:
        data = json.load(f)
    return json_graph.node_link_graph(data, directed=True)


def print_risk_report(G: nx.DiGraph):
    """
    Prints a ranked list of all vulnerable nodes.
    This is also the basis for Geetanjali's report view.
    """
    vulnerable = [
        (node, data) for node, data in G.nodes(data=True)
        if data.get("risk_score", 0) > 0
    ]
    vulnerable.sort(key=lambda x: x[1]["risk_score"], reverse=True)

    print("\n[enricher] ── Risk Report (ranked by risk score) ──────")
    print(f"  {'Package':<40} {'CVSS':>6} {'Risk':>6} {'Class':<10} {'Fix?'}")
    print(f"  {'─'*40} {'─'*6} {'─'*6} {'─'*10} {'─'*5}")

    for node, data in vulnerable:
        print(
            f"  {node:<40} "
            f"{data['cvss_score']:>6.1f} "
            f"{data['risk_score']:>6.1f} "
            f"{data['risk_class']:<10} "
            f"{'YES' if data['fix_available'] else 'NO'}"
        )

    if not vulnerable:
        print("  No vulnerabilities found.")

    print(f"  {'─'*72}\n")