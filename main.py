from ingestion.ingestion_runner import ingest
from graph.graph_builder import build_graph
from graph.graph_exporter import export_graph, load_graph

# Use Flask — small enough to run fast, deep enough to show real results
url = "https://github.com/Santpal1/AgriSense_Prototype"

# Module 1
packages = ingest(url)
print(f"\nModule 1 done: {len(packages)} direct packages")

# Module 2
G = build_graph(packages, repo_name="pallets/flask", max_depth=3)
export_graph(G)