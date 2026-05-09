"""
CascadeGuard main entry point - runs the full pipeline.
"""

import sys
import os
import json
from typing import Tuple

from logging_config import setup_logging, get_logger
from config import validate_config, get_config
from models import validate_packages_list

# Initialize logging
setup_logging()
logger = get_logger(__name__)

try:
    validate_config()
    logger.info("Configuration validated ✓")
except ValueError as e:
    logger.error(f"Configuration error: {e}")
    sys.exit(1)

# Module 1 + 2
from ingestion.ingestion_runner import ingest
from ingestion.github_client import parse_github_url, get_file_tree, get_file_content
from graph.graph_builder import build_graph
from risk.enricher import (
    enrich_graph, export_enriched_graph, print_risk_report,
    rescore_after_simulation, _build_explanation, print_enhanced_risk_report
)
from simulation.simulation_runner import run_full_simulation
from optimizer.optimizer_runner import run_optimization

# New feature imports
from impact.ast_scanner import scan_repository
from impact.impact_mapper import map_impact
from risk.narrative_generator import generate_full_narrative


def _fetch_source_files(owner: str, repo: str, extensions: set = None) -> dict:
    """
    Fetches all source files from the GitHub repository.
    
    Args:
        owner: GitHub username
        repo: Repository name
        extensions: File extensions to fetch (default: .py, .js, .ts, .jsx, .tsx)
    
    Returns:
        Dict of {filename: file_content}
    """
    if extensions is None:
        extensions = {".py", ".js", ".ts", ".jsx", ".tsx"}
    
    logger.info("[main] Fetching source files from GitHub...")
    
    try:
        file_tree = get_file_tree(owner, repo)
    except Exception as e:
        logger.warning(f"[main] Failed to fetch file tree: {e}")
        return {}
    
    # Filter for relevant files
    excluded_dirs = {
        "node_modules", "vendor", ".git", "__pycache__", ".tox",
        "venv", ".venv", "env", "dist", "build", "target", ".gradle",
        "examples", "example", "samples", "sample", "demo", "demos",
        "test", "tests", "fixtures", "docs", "doc", ".github", "site",
        "benchmark", "benchmarks", ".pytest_cache", ".venv"
    }
    
    source_files = {}
    for path in file_tree:
        # Check file extension
        has_target_ext = any(path.endswith(ext) for ext in extensions)
        if not has_target_ext:
            continue
        
        # Check if in excluded directories
        path_parts = path.split("/")
        if any(part in excluded_dirs for part in path_parts[:-1]):
            logger.debug(f"[main] Skipping excluded path: {path}")
            continue
        
        try:
            content = get_file_content(owner, repo, path)
            source_files[path] = content
            logger.debug(f"[main] Fetched {path}")
        except Exception as e:
            logger.warning(f"[main] Failed to fetch {path}: {e}")
            continue
    
    logger.info(f"[main] Fetched {len(source_files)} source files")
    return source_files


def _save_impact_report(impact_report: list, path: str = "output/impact_report.json"):
    """Saves full impact report with narratives."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    
    # Convert narrative objects to JSON-serializable dicts
    serializable_report = []
    for item in impact_report:
        # Create a copy and ensure all values are JSON-serializable
        report_item = dict(item)
        serializable_report.append(report_item)
    
    with open(path, "w") as f:
        json.dump(serializable_report, f, indent=2)
    logger.info(f"[main] Impact report saved to {path}")


def main() -> int:
    """Main entry point for CascadeGuard"""
    url = "https://github.com/pallets/flask"
    
    try:
        logger.info(f"Starting analysis for: {url}")
        
        # Stage 1: Ingestion
        packages = ingest(url)
        if not packages:
            logger.error("No packages found")
            return 1
        
        # Stage 2: Graph Construction
        G = build_graph(packages, repo_name="pallets/flask", max_depth=3)
        
        # Stage 3: Risk Enrichment with Attack Classification
        G = enrich_graph(G)
        
        # Stage 4: Simulation
        results = run_full_simulation(G, n_simulations=1000)
        G = rescore_after_simulation(G, results)
        
        # Stage 5: Explanation generation
        for node, data in G.nodes(data=True):
            if data.get("ecosystem") != "root":
                sim = results.get(node, {})
                G.nodes[node]["explanation"] = _build_explanation(node, data, sim)
        
        export_enriched_graph(G)
        print_risk_report(G)
        
        # NEW: Stage 6 - Module Impact Analysis
        logger.info("[main] Starting module-level impact analysis...")
        
        # Fetch source files
        owner, repo = parse_github_url(url)
        source_files = _fetch_source_files(owner, repo)
        
        # Scan repository
        if source_files:
            scan_results = scan_repository(source_files)
            logger.info(f"[main] Scanned {len(scan_results)} source files")
        else:
            scan_results = {}
            logger.warning("[main] No source files found, skipping impact analysis")
        
        # Map impact
        impact_map = map_impact(G, scan_results)
        logger.info(f"[main] Mapped impact for {len(impact_map)} vulnerable packages")
        
        # Generate narratives for CRITICAL and HIGH risk nodes
        impact_report = []
        for node, data in G.nodes(data=True):
            if data.get("ecosystem") == "root":
                continue
            
            risk_class = data.get("risk_class", "")
            if risk_class not in ["CRITICAL", "HIGH"]:
                continue
            
            narrative = generate_full_narrative(
                node,
                data,
                impact_map,
                data.get("risk_score", 0),
                risk_class
            )
            
            impact_report.append(narrative)
        
        # Save impact report
        if impact_report:
            _save_impact_report(impact_report)
            logger.info(f"[main] Generated narratives for {len(impact_report)} high-risk packages")
        
        # Print enhanced report
        print_enhanced_risk_report(G, impact_map)
        
        # Stage 7: Optimization
        plan = run_optimization(G, results)
        logger.info("Pipeline complete ✓")
        return 0
    
    except Exception as e:
        logger.exception(f"Fatal error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())