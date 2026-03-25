from risk.enricher import load_enriched_graph
from simulation.simulation_runner import run_full_simulation

G = load_enriched_graph("output/enriched_graph.json")
results = run_full_simulation(G, n_simulations=1000)