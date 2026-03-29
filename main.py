from ingestion.ingestion_runner import ingest
from graph.graph_builder import build_graph
from graph.graph_exporter import export_graph
from risk.enricher import enrich_graph, export_enriched_graph, print_risk_report, rescore_after_simulation
from simulation.simulation_runner import run_full_simulation
from optimizer.optimizer_runner import run_optimization

url = "https://github.com/pallets/flask"

# Module 1 + 2
packages = ingest(url)
G        = build_graph(packages, repo_name="pallets/flask", max_depth=3)

# Module 3 — initial scoring without simulation data
G        = enrich_graph(G)

# Module 4 — simulation
results  = run_full_simulation(G, n_simulations=1000)

# Re-score now that simulation data is available
G        = rescore_after_simulation(G, results)

# Re-enrich with explainability using simulation data
for node, data in G.nodes(data=True):
    if data.get("ecosystem") != "root":
        from risk.enricher import _build_explanation
        sim = results.get(node, {})
        G.nodes[node]["explanation"] = _build_explanation(node, data, sim)

export_enriched_graph(G)
print_risk_report(G)

# Module 5 — optimization
plan = run_optimization(G, results)