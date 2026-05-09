"""
Configuration management for CascadeGuard.
Centralizes all constants, tunable parameters, and configuration options.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional
import os
from dotenv import load_dotenv

load_dotenv()


@dataclass
class GraphConfig:
    """Graph building configuration"""
    max_depth: int = 3
    max_nodes: int = 500
    registry_cache_ttl: int = 3600


@dataclass
class SimulationConfig:
    """Monte Carlo simulation configuration"""
    n_simulations: int = 1000
    random_seed: Optional[int] = None


@dataclass
class OptimizerConfig:
    """Optimization engine configuration"""
    default_budgets: List[int] = field(default_factory=lambda: [8, 16, 24, 40])
    base_fix_hours: float = 2.0


@dataclass
class ScoringConfig:
    """Risk scoring configuration"""
    cvss_weight: float = 0.40
    pagerank_weight: float = 0.25
    blast_radius_weight: float = 0.20
    critical_hit_weight: float = 0.15
    
    # Risk classification thresholds
    critical_threshold: float = 35.0
    high_threshold: float = 20.0
    medium_threshold: float = 10.0


@dataclass
class PropagationConfig:
    """Attack propagation simulation configuration"""
    base_propagation_factor: float = 0.5
    depth_decay_rate: float = 0.2
    min_propagation_prob: float = 0.05
    max_propagation_prob: float = 0.90


@dataclass
class IngestionConfig:
    """Dependency ingestion configuration"""
    target_files: List[str] = field(default_factory=lambda: [
        "requirements.txt",
        "pyproject.toml",
        "package-lock.json",
        "package.json",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts"
    ])
    
    excluded_folders: List[str] = field(default_factory=lambda: [
        "node_modules", "vendor", ".git", "__pycache__", ".tox",
        "venv", ".venv", "env", "dist", "build", "target",
        ".gradle", "examples", "example", "samples", "sample",
        "demo", "demos", "test", "tests", "fixtures", "docs",
        "doc", ".github", "site", "benchmark", "benchmarks"
    ])


@dataclass
class CascadeGuardConfig:
    """Master configuration combining all modules"""
    graph: GraphConfig = field(default_factory=GraphConfig)
    simulation: SimulationConfig = field(default_factory=SimulationConfig)
    optimizer: OptimizerConfig = field(default_factory=OptimizerConfig)
    scoring: ScoringConfig = field(default_factory=ScoringConfig)
    propagation: PropagationConfig = field(default_factory=PropagationConfig)
    ingestion: IngestionConfig = field(default_factory=IngestionConfig)
    
    github_token: str = field(default_factory=lambda: os.getenv("GITHUB_TOKEN", ""))
    log_level: str = "INFO"
    output_dir: str = "output"
    debug: bool = False


# Global config instance
CONFIG = CascadeGuardConfig()


def get_config() -> CascadeGuardConfig:
    """Returns the global configuration instance"""
    return CONFIG


def validate_config() -> bool:
    """Validates that configuration is valid"""
    if not CONFIG.github_token:
        raise ValueError("GITHUB_TOKEN environment variable is not set")
    
    if CONFIG.graph.max_depth < 1:
        raise ValueError("max_depth must be >= 1")
    
    if CONFIG.graph.max_nodes < 10:
        raise ValueError("max_nodes must be >= 10")
    
    if CONFIG.simulation.n_simulations < 1:
        raise ValueError("n_simulations must be >= 1")
    
    # Check scoring weights sum to 1.0
    weights_sum = (
        CONFIG.scoring.cvss_weight +
        CONFIG.scoring.pagerank_weight +
        CONFIG.scoring.blast_radius_weight +
        CONFIG.scoring.critical_hit_weight
    )
    if abs(weights_sum - 1.0) > 0.01:
        raise ValueError(f"Scoring weights must sum to 1.0, got {weights_sum}")
    
    return True
