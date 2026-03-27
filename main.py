from ingestion.ingestion_runner import ingest
from graph.graph_builder import build_graph
from graph.graph_exporter import export_graph
from risk.enricher import enrich_graph, export_enriched_graph, print_risk_report
from risk.enricher import load_enriched_graph
from simulation.simulation_runner import run_full_simulation
from optimizer.optimizer_runner import run_optimization

url = "https://github.com/pallets/flask"

# Run full pipeline
packages = ingest(url)
G        = build_graph(packages, repo_name="pallets/flask", max_depth=3)
G        = enrich_graph(G)
export_enriched_graph(G)
print_risk_report(G)

results  = run_full_simulation(G, n_simulations=1000)
plan     = run_optimization(G, results)