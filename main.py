from ingestion.ingestion_runner import ingest
from graph.graph_builder import build_graph
from graph.graph_exporter import export_graph, load_graph
from risk.enricher import enrich_graph, export_enriched_graph, print_risk_report

url = "https://github.com/Santpal1/AgriSense_Prototype"

# Module 1
packages = ingest(url)

# Module 2
G = build_graph(packages, repo_name="pallets/flask", max_depth=3)
export_graph(G)

# Module 3
G = enrich_graph(G)
export_enriched_graph(G)
print_risk_report(G)