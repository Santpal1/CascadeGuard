# 🛡️ **CascadeGuard: Comprehensive Dependency Risk Propagation System**

---

## **Table of Contents**

1. [Project Overview](#project-overview)
2. [Architecture & Pipeline](#architecture--pipeline)
3. [Module Documentation](#module-documentation)
4. [Complete Workflow](#complete-workflow)
5. [Setup & Installation](#setup--installation)
6. [Usage](#usage)
7. [Output Files](#output-files)
8. [Key Concepts](#key-concepts)

---

## **Project Overview**

**CascadeGuard** is a sophisticated **dependency vulnerability risk analysis and simulation system** designed to assess open-source repositories across multiple programming ecosystems (Python/PyPI, JavaScript/npm, Java/Maven).

### **What It Does**

CascadeGuard answers critical security questions:

- 🔍 **Which vulnerable packages pose the greatest systemic risk?**
- 📊 **How do vulnerabilities propagate through the dependency chain?**
- 💥 **What is the "blast radius" if a critical dependency is compromised?**
- 🎯 **Which packages should be prioritized for security upgrades?**
- 🏗️ **How do vulnerabilities impact user-facing features?**

### **Key Features**

✅ **Multi-Ecosystem Support** – Python, Node.js, Java/Maven  
✅ **Comprehensive Vulnerability Data** – OSV database integration  
✅ **Attack Type Classification** – CWE-based threat categorization  
✅ **Monte Carlo Simulation** – Probability-based propagation analysis  
✅ **Graph Analytics** – Centrality metrics for dependency ranking  
✅ **Impact Mapping** – Affected features and entry points  
✅ **Optimization** – Knapsack-based fix prioritization  
✅ **Interactive Dashboard** – Real-time visualization of risk landscape  

---

## **Architecture & Pipeline**

CascadeGuard operates as a **6-stage pipeline**, where each module is independent and produces output that feeds into subsequent stages:

```
┌─────────────────────────────────────────────────────────────────┐
│                      CASCADEGUARD PIPELINE                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  MODULE 1: INGESTION                                            │
│  └─> Extract dependencies from GitHub repo (all ecosystems)    │
│      Output: packages.json                                     │
│                                                                 │
│  MODULE 2: GRAPH BUILDING                                       │
│  └─> Build directed dependency graph + centrality metrics      │
│      Output: graph.json                                        │
│                                                                 │
│  MODULE 3: ENRICHMENT + ATTACK CLASSIFICATION                   │
│  └─> Query OSV database + classify attack types + score risk  │
│      Output: enriched_graph.json                               │
│                                                                 │
│  MODULE 4: SIMULATION                                           │
│  └─> Monte Carlo propagation analysis (10K scenarios)         │
│      Output: simulation_results.json                           │
│                                                                 │
│  MODULE 5: OPTIMIZATION                                         │
│  └─> Knapsack problem for fix prioritization (budget scenarios) │
│      Output: mitigation_plan.json                              │
│                                                                 │
│  MODULE 6: IMPACT ANALYSIS                                      │
│  └─> AST scanning + feature impact mapping                     │
│      Output: impact_report.json                                │
│                                                                 │
│  DASHBOARD                                                      │
│  └─> Real-time visualization of risk landscape                 │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Each module can re-run independently** – no need to re-execute upstream stages if output files exist.

---

## **Module Documentation**

### **Module 1: Ingestion** (`ingestion/`)

**Purpose:** Extract direct dependencies from a GitHub repository across all supported ecosystems.

#### **Key Components**

**`github_client.py`**
- `parse_github_url()` – Parse GitHub URLs into owner/repo
- `get_file_tree()` – Fetch complete file tree from GitHub API
- `find_dependency_files()` – Identify dependency manifests (exclude noise)
- `get_file_content()` – Fetch raw file content

**`ingestion_runner.py`**
- Main orchestrator that:
  1. Fetches file tree from GitHub
  2. Identifies supported dependency files
  3. Routes each to appropriate parser
  4. Deduplicates by (name, ecosystem)

**Supported Formats:**

| File | Ecosystem | Parser |
|------|-----------|--------|
| `requirements.txt` | PyPI | regex-based |
| `pyproject.toml` | PyPI | TOML parsing |
| `package-lock.json` | npm | JSON parsing (v1/v2/v3) |
| `package.json` | npm | JSON parsing |
| `pom.xml` | Maven | XML + property substitution |
| `build.gradle` | Gradle | DSL parsing |
| `build.gradle.kts` | Gradle | Kotlin DSL parsing |

#### **Output Format**

```json
{
  "packages": [
    {"name": "flask", "version": "2.1.0", "ecosystem": "pypi"},
    {"name": "axios", "version": "0.21.1", "ecosystem": "npm"}
  ]
}
```

---

### **Module 2: Graph Building** (`graph/`)

**Purpose:** Construct a directed dependency graph with advanced graph metrics.

#### **Key Components**

**`graph_builder.py`**
- `build_graph()` – Recursively fetch transitive dependencies
- Computes:
  - **In-degree/Out-degree** – Number of dependents/dependencies
  - **Pagerank** – Graph centrality (importance in ecosystem)
  - **Descendants** – Total count of transitive dependents
  - **Depth** – Distance from root package

**`graph_exporter.py`**
- Export to NetworkX JSON format
- Generate HTML visualization (vis.js)

#### **Graph Statistics**

For each node:
```json
{
  "id": "axios:0.21.1",
  "version": "0.21.1",
  "ecosystem": "npm",
  "in_degree": 142,           // 142 packages depend on this
  "out_degree": 8,            // depends on 8 packages
  "pagerank": 0.0234,         // centrality metric (0-1)
  "descendants": 3456,        // total transitive dependents
  "depth": 2,                 // distance from root
  "direct": false             // not a direct dependency
}
```

**Why it matters:**
- High in-degree + high pagerank = **super-critical node**
- If compromised, affects hundreds of downstream packages

---

### **Module 3: Enrichment & Attack Classification** (`risk/`)

**Purpose:** Query OSV database, classify attack types, and compute risk scores.

#### **Key Components**

**`osv_client.py`**
- Queries OSV API for vulnerabilities
- Handles ecosystem-specific queries
- Caches results (avoid API hammering)
- Returns:
  - Vulnerability ID (CVE or GHSA)
  - CVSS score (aggregated across v2/v3/v4)
  - Severity classification
  - Fixed version (if available)
  - References (including CWE URLs)

**`attack_classifier.py`** ⭐ **(Recently Fixed)**

Extracts and classifies attack types from vulnerabilities:

**Process:**
1. **Extract CWE IDs** from OSV vulnerability references
   - Handles multiple reference formats
   - Fallback to database_specific fields
   - Regex matching on summary text
   
2. **Classify Attacks** – Maps CWE IDs to attack categories:
   - **Remote Code Execution** (CWE-78, CWE-94, CWE-502, etc.)
   - **SQL Injection** (CWE-89)
   - **Cross-Site Scripting** (CWE-79)
   - **Authentication Bypass** (CWE-287)
   - **Data Exposure** (CWE-200)
   - And 12+ more categories

3. **Generate Narratives** – Human-readable attack descriptions:
   ```
   "axios@0.21.1 enables Remote Code Execution through code injection. 
    Attackers can execute arbitrary code with the application's privileges (CWE-94)"
   ```

**Output for each node:**
```json
{
  "attack_classification": {
    "attack_types": ["Code Injection", "Remote Code Execution"],
    "primary_attack": "Remote Code Execution",
    "attacker_capability": "Execute arbitrary code in application context",
    "cwe_ids": ["CWE-94"],
    "has_cwe_match": true,
    "narrative": "axios enables Remote Code Execution...",
    "severity": "CRITICAL"
  }
}
```

**`scorer.py`**
Computes risk scores (0-100) combining:
- **CVSS Score** (0-10) – Vulnerability severity
- **Pagerank** (0-1) – Graph centrality
- **In-degree** – Number of dependents
- **Mean blast radius** – From simulation
- **Critical hit rate** – Probability of severe cascade

Risk classifications:
- **CRITICAL** – Risk score ≥ 80
- **HIGH** – Risk score ≥ 60
- **MEDIUM** – Risk score ≥ 40
- **LOW** – Risk score < 40
- **CLEAN** – No vulnerabilities

**`enricher.py`**
Main orchestrator that enriches each node with:
- Vulnerability list from OSV
- Aggregated CVSS score
- Attack classification + narrative
- Risk score + risk class
- Explanation (human-readable reason for risk)

#### **Node Enrichment Output**

```json
{
  "id": "axios:0.21.1",
  "vulnerabilities": [
    {
      "vuln_id": "GHSA-1234-5678-90ab",
      "display_id": "CVE-2021-41103",
      "summary": "...",
      "severity": "CRITICAL",
      "cvss_score": 9.1,
      "fixed_in": "0.21.4",
      "detail_url": "https://osv.dev/...",
      "references": [...]
    }
  ],
  "vuln_count": 1,
  "cvss_score": 9.1,
  "severity": "CRITICAL",
  "risk_score": 87.3,
  "risk_class": "CRITICAL",
  "fix_available": true,
  "attack_classification": {
    "attack_types": ["Code Injection"],
    "primary_attack": "Remote Code Execution",
    "attacker_capability": "Execute arbitrary code...",
    "narrative": "axios enables Remote Code Execution...",
    "has_cwe_match": true
  },
  "explanation": "Critical CVSS 9.1 + high graph centrality + 142 dependents"
}
```

---

### **Module 4: Simulation** (`simulation/`)

**Purpose:** Monte Carlo simulation to quantify propagation risk and "blast radius."

#### **Key Components**

**`propagation.py`**
Simulates attack propagation from a compromise point:
- For each neighbor, probabilistically compromise based on vulnerability severity
- Tracks: compromised nodes, propagation path, depth reached
- Tracks whether "critical hit" occurred (widespread compromise)

**`monte_carlo.py`**
Runs 10,000 propagation scenarios from each node:
- Aggregates results:
  - Mean/min/max blast radius
  - P50/P95 blast radius (percentiles)
  - Critical hit rate (frequency of widespread compromise)
  - Node infection probabilities

**Output:**
```json
{
  "origin": "axios",
  "n_simulations": 10000,
  "mean_blast_radius": 85.3,
  "max_blast_radius": 856,
  "min_blast_radius": 2,
  "std_blast_radius": 127.4,
  "p50_blast_radius": 42,
  "p95_blast_radius": 412,
  "critical_hit_rate": 0.34,
  "exposure_score": 62.1,
  "node_infection_prob": {
    "lodash": 0.78,
    "express": 0.65
  }
}
```

**Interpretation:**
- **Mean blast radius 85.3** – On average, compromising axios would affect 85 downstream packages
- **Critical hit rate 34%** – In 34% of scenarios, compromise spreads extensively

---

### **Module 5: Optimization** (`optimizer/`)

**Purpose:** Determine which packages to upgrade for maximum risk reduction within budget.

#### **Key Components**

**`knapsack.py`**
Solves weighted knapsack problem:
- **Items** – Vulnerable packages with cost, benefit, priority
- **Capacity** – Budget in hours (e.g., 40 hours/sprint)
- **Objective** – Maximize risk reduction within budget

**`cost_estimator.py`**
Estimates upgrade cost based on:
- Ecosystem (npm < java < python)
- Transitive dependency count
- Breaking change risk
- Test coverage

#### **Output**

```json
{
  "total_vulnerable_packages": 47,
  "all_items_ranked": [
    {
      "node": "axios",
      "cost_hours": 2.5,
      "benefit": 18.5,
      "risk_score": 87.3,
      "ecosystem": "npm"
    }
  ],
  "budget_scenarios": {
    "20": {
      "selected_fixes": [...],
      "total_cost": 19.5,
      "total_benefit": 45.2,
      "risk_reduction_pct": 62.1
    },
    "40": {...},
    "80": {...}
  }
}
```

---

### **Module 6: Impact Analysis** (`impact/`)

**Purpose:** Determine which user-facing features are affected by vulnerable packages.

#### **Key Components**

**`ast_scanner.py`**
Scans source code (Python, JavaScript, TypeScript):
- **Import analysis** – Which packages does each file import?
- **Entry point detection** – Identifies main handlers/endpoints
- **Function extraction** – Top-level function names

**`feature_inferrer.py`**
Infers user-facing features from code:
- Maps entry points to features
- Correlates vulnerable imports to feature usage
- Determines exposure scope (HIGH/MEDIUM/LOW)

**`impact_mapper.py`**
Main orchestrator:
- For each vulnerable package:
  - Find importing source files
  - Identify affected entry points
  - Infer user features at risk

#### **Output**

```json
{
  "package": "axios",
  "risk_class": "CRITICAL",
  "affected_files": [
    "src/api/client.js",
    "src/services/paymentHandler.js"
  ],
  "affected_entry_points": [
    "GET /api/users",
    "POST /api/payments"
  ],
  "estimated_user_features": [
    "User profile retrieval",
    "Payment processing"
  ],
  "exposure_scope": "HIGH",
  "attack_narrative": "axios enables Remote Code Execution..."
}
```

---

## **Complete Workflow**

### **Step-by-Step Execution**

```python
# 1. INGEST dependencies
packages = ingest("https://github.com/user/repo")

# 2. BUILD dependency graph
G = build_graph(packages)
# Recursively fetches transitive dependencies
# Computes: in_degree, out_degree, pagerank, descendants

# 3. ENRICH with vulnerability data
G = enrich_graph(G)
# Queries OSV for each node
# Classifies attack types
# Computes risk scores

# 4. SIMULATE propagation
sim_results = run_full_simulation(G)
# 10K simulations from each node
# Computes: mean_blast_radius, critical_hit_rate, exposure_score

# 5. RE-SCORE after simulation
G = rescore_after_simulation(G, sim_results)

# 6. OPTIMIZE fixes
mitigation_plan = run_optimization(G, budget=40)
# Solves knapsack problem
# Returns ranked list of packages to upgrade

# 7. ANALYZE impact
impact_report = map_impact(G, repo_path)
# Scans source code
# Maps vulnerabilities to features

# 8. VISUALIZE results
# Dashboard renders: graph_vis.html
```

---

## **Setup & Installation**

### **Requirements**

- Python 3.9+
- Git
- GitHub token (for API access)

### **Installation**

```bash
# Clone repository
git clone https://github.com/Santpal1/CascadeGuard.git
cd CascadeGuard

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set environment variables
export GITHUB_TOKEN="your_github_token"
# Or create .env file:
# GITHUB_TOKEN=your_token
```

### **Configuration**

Edit `config.py`:
```python
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
OUTPUT_DIR = "output"
CACHE_DIR = "cache"
MAX_TRANSITIVE_DEPTH = 10
SIMULATION_ITERATIONS = 10000
```

---

## **Usage**

### **Run Full Pipeline**

```bash
python main.py
```

Prompts for:
1. GitHub repository URL
2. Budget for fix prioritization (hours)

### **Run Individual Modules**

```python
# Just ingestion
from ingestion.ingestion_runner import ingest
packages = ingest("https://github.com/user/repo")

# Just graph building
from graph.graph_builder import build_graph
G = build_graph(packages)

# Just enrichment
from risk.enricher import enrich_graph, export_enriched_graph
G = enrich_graph(G)
export_enriched_graph(G)

# Just simulation
from simulation.simulation_runner import run_full_simulation
results = run_full_simulation(G)
```

---

## **Output Files**

### **Generated Outputs** (in `output/` directory)

| File | Purpose | Format |
|------|---------|--------|
| `enriched_graph.json` | Full graph with vulnerability data | NetworkX JSON |
| `graph_vis.html` | Interactive visualization | HTML (vis.js) |
| `graph.json` | Base dependency graph | JSON |
| `simulation_results.json` | Propagation analysis | JSON |
| `mitigation_plan.json` | Fix prioritization | JSON |
| `impact_report.json` | Feature impact analysis | JSON |

---

## **Key Concepts**

### **Pagerank (Graph Centrality)**

Measures how "important" a package is in the ecosystem:
- **High pagerank** – Many packages depend on it
- **Critical for risk assessment** – If compromised, affects large portion of ecosystem

### **Blast Radius**

Number of packages that could be compromised if a vulnerability is exploited:
- **Mean blast radius** – Average from 10K simulations
- **P95 blast radius** – 95th percentile (worst-case scenario)

### **Critical Hit Rate**

Probability that a compromise leads to widespread propagation:
- **0.34 (34%)** – High risk of cascade effect
- **0.05 (5%)** – Low risk, compromise likely contained

### **Risk Score (0-100)**

Composite score combining:
- **CVSS** – Vulnerability severity
- **Centrality** – How important the package is
- **Propagation** – How far compromise can spread

### **Exposure Scope**

Determines breadth of impact:
- **HIGH** – Affects major user features
- **MEDIUM** – Affects supporting features
- **LOW** – Affects non-critical features

---

## **Project Structure**

```
CascadeGuard/
├── ingestion/          # Module 1: Extract dependencies
│   ├── github_client.py
│   ├── ingestion_runner.py
│   └── parsers/
├── graph/              # Module 2: Build dependency graph
│   ├── graph_builder.py
│   ├── graph_exporter.py
│   └── registry_client.py
├── risk/               # Module 3: Enrichment & Classification
│   ├── attack_classifier.py
│   ├── enricher.py
│   ├── osv_client.py
│   ├── scorer.py
│   └── narrative_generator.py
├── simulation/         # Module 4: Propagation analysis
│   ├── monte_carlo.py
│   ├── propagation.py
│   └── simulation_runner.py
├── optimizer/          # Module 5: Fix prioritization
│   ├── cost_estimator.py
│   ├── knapsack.py
│   └── optimizer_runner.py
├── impact/             # Module 6: Feature impact analysis
│   ├── ast_scanner.py
│   ├── feature_inferrer.py
│   └── impact_mapper.py
├── dashboard/          # Interactive visualization
│   └── app.py
├── main.py             # Entry point / orchestration
├── models.py           # Pydantic validation schemas
├── config.py           # Configuration
├── requirements.txt    # Python dependencies
└── output/             # Generated outputs
```

---

## **License**

MIT License – See LICENSE file for details.

## **Contributing**

Contributions welcome! Please:
1. Fork the repository
2. Create feature branch (`git checkout -b feature/improvement`)
3. Commit changes (`git commit -am 'Add improvement'`)
4. Push to branch (`git push origin feature/improvement`)
5. Create Pull Request

---

**Last Updated:** April 2026  
**Version:** 2.0.0  
**Status:** Production Ready ✅
