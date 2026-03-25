import json
import os
import networkx as nx
from networkx.readwrite import json_graph


def export_graph(G: nx.DiGraph, path: str = "output/graph.json"):
    """
    Exports the graph to a JSON file using networkx's node-link format.
    Any teammate can reload it with load_graph().
    """
    os.makedirs(os.path.dirname(path), exist_ok=True)

    data = json_graph.node_link_data(G)

    with open(path, "w") as f:
        json.dump(data, f, indent=2)

    print(f"[exporter] Graph exported to {path}")
    print(f"[exporter] {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")
    _print_summary(G)


def load_graph(path: str = "output/graph.json") -> nx.DiGraph:
    """
    Reloads a previously exported graph from JSON.
    Piyush and Ayan will use this instead of re-running ingestion.
    """
    with open(path, "r") as f:
        data = json.load(f)
    G = json_graph.node_link_graph(data, directed=True)
    print(f"[exporter] Graph loaded from {path}: "
          f"{G.number_of_nodes()} nodes, {G.number_of_edges()} edges")
    return G


def _print_summary(G: nx.DiGraph):
    """
    Prints a human-readable summary of the graph — useful during dev
    and also feeds into Geetanjali's report module later.
    """
    print("\n[exporter] ── Graph Summary ──────────────────────")

    # Top 5 nodes by in_degree (most depended-upon)
    by_in_degree = sorted(
        [(n, d["in_degree"]) for n, d in G.nodes(data=True)
         if d.get("ecosystem") != "root"],
        key=lambda x: x[1],
        reverse=True
    )[:5]

    print("[exporter] Top 5 most depended-upon packages (in-degree):")
    for name, score in by_in_degree:
        print(f"           {name}  ←  {score} dependents")

    # Top 5 by pagerank
    by_pagerank = sorted(
        [(n, d["pagerank"]) for n, d in G.nodes(data=True)
         if d.get("ecosystem") != "root"],
        key=lambda x: x[1],
        reverse=True
    )[:5]

    print("[exporter] Top 5 by PageRank (systemic importance):")
    for name, score in by_pagerank:
        print(f"           {name}  →  {score}")

    print("[exporter] ────────────────────────────────────────\n")