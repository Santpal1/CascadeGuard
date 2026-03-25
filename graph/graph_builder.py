import networkx as nx
from graph.registry_client import get_dependencies


def build_graph(packages: list, repo_name: str = "root", max_depth: int = 3) -> nx.DiGraph:
    """
    Builds a directed dependency graph from a flat list of packages.

    Nodes represent packages. A directed edge A → B means "A depends on B".
    The root node represents the repository itself.

    Args:
        packages:  list of {name, version, ecosystem} dicts from Module 1
        repo_name: name of the root node (usually owner/repo)
        max_depth: how many levels of transitive deps to resolve (default 3)

    Returns:
        nx.DiGraph with node attributes:
            - version, ecosystem, depth, direct (bool)
            - in_degree, out_degree, pagerank (computed after build)
    """
    G = nx.DiGraph()

    # Add root node
    G.add_node(repo_name, version="root", ecosystem="root", depth=0, direct=False)

    visited = {}  # tracks node_key -> depth at which it was first visited

    print(f"\n[graph] Building graph for '{repo_name}'")
    print(f"[graph] Seed packages: {len(packages)}, max depth: {max_depth}")

    # Add all direct dependencies first (depth 1)
    for pkg in packages:
        node_id = _node_id(pkg)
        G.add_node(node_id,
                   version=pkg["version"],
                   ecosystem=pkg["ecosystem"],
                   depth=1,
                   direct=True)
        G.add_edge(repo_name, node_id)
        visited[node_id] = 1

    # Now resolve transitive deps recursively
    _resolve_transitive(G, packages, visited, current_depth=1, max_depth=max_depth)

    # Compute graph metrics — needed by Piyush for risk scoring
    _annotate_metrics(G)

    print(f"[graph] Graph built: {G.number_of_nodes()} nodes, "
          f"{G.number_of_edges()} edges")

    return G


def _resolve_transitive(
    G: nx.DiGraph,
    packages: list,
    visited: dict,
    current_depth: int,
    max_depth: int
):
    """
    Recursively fetches and adds transitive dependencies up to max_depth.
    """
    if current_depth >= max_depth:
        return

    next_level = []

    for pkg in packages:
        node_id = _node_id(pkg)
        print(f"[graph] Resolving depth {current_depth+1}: {node_id}")

        transitive = get_dependencies(
            pkg["name"], pkg["version"], pkg["ecosystem"]
        )

        for dep in transitive:
            dep_id = _node_id(dep)

            # If already in graph at a shallower depth, just add the edge
            # Don't re-resolve — avoid exponential blowup
            if dep_id in visited:
                if not G.has_edge(node_id, dep_id):
                    G.add_edge(node_id, dep_id)
                continue

            # New node — add it
            G.add_node(dep_id,
                       version=dep["version"],
                       ecosystem=dep["ecosystem"],
                       depth=current_depth + 1,
                       direct=False)
            G.add_edge(node_id, dep_id)
            visited[dep_id] = current_depth + 1
            next_level.append(dep)

    # Recurse one level deeper
    if next_level:
        _resolve_transitive(G, next_level, visited, current_depth + 1, max_depth)


def _annotate_metrics(G: nx.DiGraph):
    """
    Computes graph-theoretic metrics on every node and stores them
    as node attributes. These are consumed by Piyush's risk scorer.

    in_degree:   how many packages depend on this one
                 (higher = more dangerous if compromised)
    out_degree:  how many packages this one depends on
                 (higher = larger attack surface)
    pagerank:    importance score accounting for the full graph structure
                 (best single metric for systemic risk)
    descendants: how many nodes are reachable downstream
                 (= blast radius if this node is compromised)
    """
    print("[graph] Computing graph metrics...")

    in_deg  = dict(G.in_degree())
    out_deg = dict(G.out_degree())

    # PageRank needs at least one edge
    if G.number_of_edges() > 0:
        pagerank = nx.pagerank(G, alpha=0.85)
    else:
        pagerank = {n: 1.0 / G.number_of_nodes() for n in G.nodes()}

    for node in G.nodes():
        # Count reachable descendants = potential blast radius
        try:
            desc_count = len(nx.descendants(G, node))
        except Exception:
            desc_count = 0

        G.nodes[node]["in_degree"]    = in_deg.get(node, 0)
        G.nodes[node]["out_degree"]   = out_deg.get(node, 0)
        G.nodes[node]["pagerank"]     = round(pagerank.get(node, 0.0), 6)
        G.nodes[node]["descendants"]  = desc_count


def _node_id(pkg: dict) -> str:
    """
    Creates a unique, consistent node identifier for a package.
    Format: 'ecosystem:name' — we intentionally exclude version
    because the same package at different versions is still the
    same node in the graph (version is stored as an attribute).
    """
    return f"{pkg['ecosystem']}:{pkg['name']}"