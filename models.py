"""
Data validation schemas for CascadeGuard using Pydantic.
Ensures all intermediate outputs conform to expected formats.
"""

from pydantic import BaseModel, Field, validator
from typing import List, Dict, Optional, Any
from enum import Enum


# ─────────────────────────────────────────────────────────────────────────────
# Ingestion Models
# ─────────────────────────────────────────────────────────────────────────────

class Package(BaseModel):
    """Direct dependency from ingestion module"""
    name: str = Field(..., description="Package name")
    version: str = Field(default="unspecified", description="Package version")
    ecosystem: str = Field(..., description="Package ecosystem (pypi, npm, maven)")
    
    class Config:
        validate_assignment = True


# ─────────────────────────────────────────────────────────────────────────────
# Graph Models
# ─────────────────────────────────────────────────────────────────────────────

class GraphNode(BaseModel):
    """Node attributes in the dependency graph"""
    version: str
    ecosystem: str
    depth: int = Field(ge=0, description="Distance from root")
    direct: bool = Field(default=False, description="Is direct dependency?")
    in_degree: int = Field(default=0, ge=0)
    out_degree: int = Field(default=0, ge=0)
    pagerank: float = Field(default=0.0, ge=0.0, le=1.0)
    descendants: int = Field(default=0, ge=0)


# ─────────────────────────────────────────────────────────────────────────────
# Vulnerability Models
# ─────────────────────────────────────────────────────────────────────────────

class SeverityEnum(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class Vulnerability(BaseModel):
    """Vulnerability from OSV database"""
    vuln_id: str = Field(..., description="CVE or GHSA identifier")
    display_id: str = Field(..., description="Human-readable ID (prefer CVE)")
    summary: str = Field(..., description="Short description")
    severity: SeverityEnum = Field(..., description="CVSS severity rating")
    cvss_score: float = Field(default=0.0, ge=0.0, le=10.0)
    fixed_in: Optional[str] = Field(None, description="Version with fix")
    detail_url: str = Field(..., description="Link to vulnerability details")


# ─────────────────────────────────────────────────────────────────────────────
# Risk Scoring Models
# ─────────────────────────────────────────────────────────────────────────────

class RiskClassEnum(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    CLEAN = "CLEAN"
    UNKNOWN = "UNKNOWN"


class EnrichedGraphNode(GraphNode):
    """Node with vulnerability and risk data"""
    vulnerabilities: List[Vulnerability] = Field(default_factory=list)
    vuln_count: int = Field(default=0, ge=0)
    cvss_score: float = Field(default=0.0, ge=0.0, le=10.0)
    severity: SeverityEnum = Field(default=SeverityEnum.UNKNOWN)
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    risk_class: RiskClassEnum = Field(default=RiskClassEnum.CLEAN)
    fix_available: bool = Field(default=False)
    explanation: str = Field(default="")


# ─────────────────────────────────────────────────────────────────────────────
# Simulation Models
# ─────────────────────────────────────────────────────────────────────────────

class SimulationResult(BaseModel):
    """Result from single Monte Carlo simulation"""
    origin: str
    n_simulations: int
    mean_blast_radius: float = Field(ge=0.0)
    max_blast_radius: int = Field(ge=0)
    min_blast_radius: int = Field(ge=0)
    std_blast_radius: float = Field(ge=0.0)
    p50_blast_radius: int = Field(ge=0)
    p95_blast_radius: int = Field(ge=0)
    critical_hit_rate: float = Field(ge=0.0, le=1.0)
    node_infection_prob: Dict[str, float]
    exposure_score: float = Field(ge=0.0, le=100.0)


class PropagationEvent(BaseModel):
    """Result from single attack propagation simulation"""
    origin: str
    compromised: List[str]
    blast_radius: int
    critical_hit: bool
    propagation_path: List[str]
    depth_reached: int


# ─────────────────────────────────────────────────────────────────────────────
# Attack Classification Models
# ─────────────────────────────────────────────────────────────────────────────

class AttackClassification(BaseModel):
    """Classification of attack types from CWE IDs"""
    attack_types: List[str] = Field(description="Matched attack category names")
    primary_attack: str = Field(description="Highest severity attack type")
    attacker_capability: str = Field(description="What an attacker can do")
    cwe_ids: List[str] = Field(description="Raw CWE IDs from vulnerabilities")


# ─────────────────────────────────────────────────────────────────────────────
# Module Impact Models
# ─────────────────────────────────────────────────────────────────────────────

class ScanResult(BaseModel):
    """Result of scanning a single source file"""
    imports: List[str] = Field(default_factory=list, description="Imported packages")
    functions: List[str] = Field(default_factory=list, description="Top-level function names")
    is_entry_point: bool = Field(default=False, description="Is this an entry point?")


class ModuleImpact(BaseModel):
    """Impact of a vulnerable package on source code"""
    affected_files: List[str] = Field(description="Files that import the vulnerable package")
    affected_entry_points: List[str] = Field(description="Entry point files affected")
    estimated_user_features: List[str] = Field(description="User-facing features affected")
    exposure_scope: str = Field(description="HIGH / MEDIUM / LOW")


# ─────────────────────────────────────────────────────────────────────────────
# Risk Narrative Models
# ─────────────────────────────────────────────────────────────────────────────

class RiskNarrative(BaseModel):
    """Unified risk narrative combining attack and impact analysis"""
    package: str = Field(description="Package name with version (e.g., axios@0.21.1)")
    risk_score: float = Field(ge=0.0, le=100.0, description="Numeric risk score")
    risk_class: RiskClassEnum = Field(description="CRITICAL / HIGH / MEDIUM / LOW")
    attack_type: str = Field(description="Primary attack type from classification")
    attacker_capability: str = Field(description="What attacker can do")
    affected_files: List[str] = Field(description="Top 3 affected files")
    affected_features: List[str] = Field(description="User-facing features affected")
    exposure_scope: str = Field(description="HIGH / MEDIUM / LOW")
    fix_recommendation: str = Field(description="Recommended mitigation")
    narrative: str = Field(description="Full narrative paragraph")


# ─────────────────────────────────────────────────────────────────────────────
# Optimization Models
# ─────────────────────────────────────────────────────────────────────────────

class MitigationAction(BaseModel):
    """Single mitigation action (e.g., upgrade a package)"""
    node: str
    cost_hours: float = Field(ge=0.1)
    benefit: float = Field(ge=0.0)
    cvss_score: float = Field(ge=0.0, le=10.0)
    risk_score: float = Field(ge=0.0, le=100.0)
    risk_class: RiskClassEnum
    exposure_score: float = Field(ge=0.0, le=100.0)
    mean_blast_radius: float = Field(ge=0.0)
    fix_available: bool
    ecosystem: str
    version: str
    vuln_count: int = Field(ge=0)
    fixed_in: Optional[str] = None


class OptimizationResult(BaseModel):
    """Result from knapsack optimization for a budget"""
    selected_fixes: List[MitigationAction]
    total_cost: float = Field(ge=0.0)
    total_benefit: float = Field(ge=0.0)
    remaining_budget: float = Field(ge=0.0)
    risk_reduction_pct: float = Field(ge=0.0, le=100.0)
    unaddressed_fixes: List[MitigationAction]


class MitigationPlan(BaseModel):
    """Complete mitigation plan with multiple budget scenarios"""
    total_vulnerable_packages: int = Field(ge=0)
    all_items_ranked: List[MitigationAction]
    budget_scenarios: Dict[float, OptimizationResult]


# ─────────────────────────────────────────────────────────────────────────────
# Assessment Models
# ─────────────────────────────────────────────────────────────────────────────

class AssessmentStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"


class Assessment(BaseModel):
    """Complete assessment result"""
    repo_url: str
    graph_data: Dict[str, Any] = Field(description="Serialized NetworkX graph")
    simulation_results: Dict[str, SimulationResult]
    mitigation_plan: MitigationPlan
    status: AssessmentStatus = AssessmentStatus.COMPLETE
    timestamp: str = Field(description="ISO format timestamp")


# ─────────────────────────────────────────────────────────────────────────────
# Validation Helpers
# ─────────────────────────────────────────────────────────────────────────────

def validate_package(pkg: dict) -> Package:
    """Validates and returns a Package object"""
    return Package(**pkg)


def validate_packages_list(packages: list) -> List[Package]:
    """Validates a list of packages"""
    return [Package(**pkg) for pkg in packages]


def validate_mitigation_action(action: dict) -> MitigationAction:
    """Validates and returns a MitigationAction object"""
    return MitigationAction(**action)
