import networkx as nx
from networkx.readwrite import json_graph
import json
import os

from risk.osv_client import query_vulnerabilities
from risk.scorer import compute_risk_score, classify_risk


def enrich_graph(G: nx.DiGraph) -> nx.DiGraph:
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
        cvss_score = max(
            (v["cvss_score"] for v in vulns),
            default=0.0
        )

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

    print(f"\n[enricher] ── Enrichment Summary ─────────────────────")
    print(f"[enricher] Nodes scanned:      {len(nodes)}")
    print(f"[enricher] Vulnerable nodes:   {vulnerable_nodes}")
    print(f"[enricher] Total vulns found:  {total_vulns}")
    print(f"[enricher] Critical nodes:     {critical_nodes}")
    print(f"[enricher] ────────────────────────────────────────────\n")

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