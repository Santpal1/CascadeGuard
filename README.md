## **🔍 CascadeGuard: Comprehensive Project Documentation**

---

### **Project Overview**

**CascadeGuard** is a sophisticated **dependency vulnerability risk propagation and simulation system** for analyzing open-source repositories. It:

1. **Ingests** dependency files from GitHub repositories (supporting Python, Node.js, and Java/Maven ecosystems)
2. **Builds** a directed dependency graph representing relationships between packages
3. **Enriches** nodes with vulnerability data from the OSV database
4. **Scores** risk based on CVSS, graph centrality, and dependency structure
5. **Simulates** attack propagation via Monte Carlo methods to quantify exposure

The ultimate goal: **Identify which vulnerable packages pose the greatest systemic risk** through cascading compromise scenarios.

---

### **Architecture Overview**

The project is organized as a **4-stage pipeline**:

```
Module 1: INGESTION → Module 2: GRAPH BUILDING → Module 3: ENRICHMENT → Module 4: SIMULATION
```

Each module is independent and generates output that feeds into the next stage. Output files allow re-running downstream modules without re-ingesting.

---

## **Module 1: Ingestion** (ingestion)

**Purpose:** Extract direct dependencies from a GitHub repository across multiple ecosystems.

### Key Components

#### **github_client.py**

- **`parse_github_url()`** – Parses GitHub URLs into owner/repo components
- **`get_file_tree(owner, repo)`** – Fetches complete file tree from GitHub API using recursive tree endpoint
- **`find_dependency_files(file_paths)`** – Filters files by target names (requirements.txt, pom.xml, package.json, etc.) and excludes noise folders (node_modules, .git, test, etc.)
- **`get_file_content()`** – Fetches raw file content from GitHub

**Exclusion Strategy:** Avoids build outputs (`target/`, `node_modules/`, `dist/`), test directories, and documentation to focus on real project dependencies.

#### **ingestion_runner.py**

- **`ingest(github_url)`** – Main orchestrator that:
  1. Fetches file tree from GitHub
  2. Identifies supported dependency files
  3. Routes each file to the appropriate parser
  4. Deduplicates packages by (name, ecosystem)
  5. Returns `list[{name, version, ecosystem}]`

**Parser Map:**

```python
PARSER_MAP = {
    "requirements.txt":  parse_requirements_txt,      # Python
    "pyproject.toml":    parse_pyproject_toml,        # Python (modern)
    "package-lock.json": parse_package_lock,          # Node.js
    "package.json":      parse_package_json,          # Node.js
    "pom.xml":           parse_pom_xml,               # Java/Maven
    "build.gradle":      parse_gradle,                # Java/Gradle
    "build.gradle.kts":  parse_gradle,                # Java/Gradle (Kotlin DSL)
}
```

#### **parsers**

Each parser extracts packages from its respective format:

- **python_parser.py** – Parses `requirements.txt` using regex to extract name and version specifiers (`==`, `>=`, `<=`, etc.)
- **node_parser.py** – Parses `package-lock.json` (v1, v2, v3); handles nested `node_modules/` paths
- **node_package_parser.py** – Parses `package.json` dependencies
- **toml_parser.py** – Parses `pyproject.toml` (modern Python)
- **java_parser.py** – Parses `pom.xml` with:
  - Property resolution (`${maven.version}` substitution)
  - Scope filtering (skips `test`, `provided`, `system` dependencies)
  - Maven artifact notation (`groupId:artifactId`)
- **gradle_parser.py** – Parses Gradle `build.gradle` and `build.gradle.kts`

**Output Format:**

```python
packages = [
    {"name": "flask", "version": "2.1.0", "ecosystem": "pypi"},
    {"name": "werkzeug", "version": "2.0.0", "ecosystem": "pypi"},
    ...
]
```

---

## **Module 2: Graph Building** (graph)

**Purpose:** Construct a directed dependency graph and compute centrality metrics.

### Key Components

#### **graph_builder.py**

**`build_graph(packages, repo_name, max_depth=3) → nx.DiGraph`**

Creates a directed graph where:

- **Nodes** = packages + root repository node
- **Edges** = A → B means "A depends on B"
- **Direction:** Package dependencies flow downstream

**Process:**

1. Add root node with metadata: `{version: "root", ecosystem: "root", depth: 0, direct: False}`
2. Add all direct dependencies at depth 1 from ingestion output
3. Recursively resolve transitive dependencies up to `max_depth` using registry clients
4. Compute graph metrics (PageRank, in-degree, out-degree)

**Node Attributes:**

```python
{
    "version": str,          # Package version
    "ecosystem": str,        # "pypi", "npm", "maven"
    "depth": int,           # Distance from root (1 = direct)
    "direct": bool,         # Was this a direct dependency?
    "in_degree": int,       # Number of packages depending on this
    "out_degree": int,      # Number of packages this depends on
    "pagerank": float,      # Networkx PageRank (systemic importance)
}
```

**`_resolve_transitive()`** – Recursive function that:

- For each package, queries the registry (PyPI, npm, Maven Central) for its dependencies
- Avoids exponential blowup by:
  - Only traversing up to `max_depth`
  - Reusing nodes already visited at shallower depths
- Uses caching to prevent duplicate API calls

#### **registry_client.py**

Queries package registries for transitive dependencies. Implements:

- **`_pypi_deps(name, version)`** – Queries PyPI JSON API; parses `requires_dist` metadata
- **`_npm_deps(name, version)`** – Queries npm registry; extracts `dependencies` object
- **`_maven_deps(name, version)`** – Queries Maven Central for POM files
- **`_maven_latest_version()`** – Resolves unspecified versions to latest release

**Caching:** In-memory `_cache` dict prevents re-fetching the same package across recursive calls.

#### **graph_exporter.py**

- **`export_graph(G, path)`** – Serializes graph to JSON using networkx's node-link format
- **`load_graph(path)`** – Reloads graph from JSON (allows downstream modules to skip ingestion)
- **`_print_summary(G)`** – Prints human-readable summary:
  - Top 5 most depended-upon packages (highest in-degree)
  - Top 5 by PageRank (systemic importance)

---

## **Module 3: Enrichment** (risk)

**Purpose:** Query vulnerability databases, compute risk scores, and classify severity.

### Key Components

#### **osv_client.py**

**`query_vulnerabilities(name, version, ecosystem) → list[dict]`**

Queries the **Open Source Vulnerabilities (OSV) database** at `https://api.osv.dev/v1/query`.

**For each vulnerability found, extracts:**

```python
{
    "vuln_id": str,        # CVE or GHSA identifier
    "summary": str,        # Short description
    "severity": str,       # CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN
    "cvss_score": float,   # 0.0–10.0 scale
    "fixed_in": str|None,  # Version where fix was released (if known)
    "detail_url": str,     # Link to full details
}
```

**Features:**

- In-memory caching to prevent duplicate queries
- Respects rate limiting with 0.1s delays between requests
- Maps ecosystem names to OSV format (e.g., `pypi` → `PyPI`)
- Handles missing/unspecified versions gracefully

#### **scorer.py**

**`compute_risk_score(cvss_score, pagerank, in_degree, max_pagerank) → float (0–100)`**

Computes a **composite risk score** accounting for:

1. **CVSS Score (0–10)** – Raw exploitability
2. **PageRank (normalized 0–1)** – Structural importance in dependency graph
   - Packages that many others depend on are more critical
3. **In-degree (log-scaled)** – Number of direct dependents
   - Each additional dependent increases risk, but with diminishing returns (log scale)

**Formula:**

```
risk = CVSS × (1 + normalized_pagerank) × (1 + log(in_degree + 1))
normalized_risk = min((risk / 80) * 100, 100)  # Cap at 100
```

**Rationale:**

- A high-CVSS vulnerability affecting a critical node (high PageRank + in-degree) amplifies risk multiplicatively
- Theoretical max ≈ 10 × 2 × 4 = 80 for extreme cases, normalized to 100

**`classify_risk(score) → str`**

Maps score to severity class:

```
score >= 35  → CRITICAL
score >= 20  → HIGH
score >= 10  → MEDIUM
score > 0    → LOW
score == 0   → CLEAN
```

#### **[risk/enricher.py](risk/enricher.py)**

**`enrich_graph(G) → nx.DiGraph`**

Main orchestrator that:

1. For each non-root node, queries OSV for vulnerabilities
2. Extracts highest CVSS score across all vulnerabilities
3. Computes risk score using graph metrics
4. Classifies risk into severity bins
5. Attaches to node as new attributes

**Node Enrichment Attributes:**

```python
{
    "vulnerabilities": list[dict],  # Full vuln objects from OSV
    "vuln_count": int,             # Total count
    "cvss_score": float,           # Highest CVSS (0–10)
    "severity": str,               # Worst severity from all vulns
    "risk_score": float,           # Composite 0–100
    "risk_class": str,             # CRITICAL/HIGH/MEDIUM/LOW/CLEAN
    "fix_available": bool,         # At least one vuln has a known fix
}
```

Prints enrichment summary showing counts of vulnerable/critical nodes.

---

## **Module 4: Simulation** (simulation)

**Purpose:** Monte Carlo simulation of attack propagation through the dependency graph.

### Key Components

#### **propagation.py**

**`compute_propagation_probability(source_cvss, target_risk_score) → float (0–0.95)`**

Probabilistic model for attack spread between nodes:

- **Base probability:** 50% (baseline exploit success per edge)
- **CVSS factor:** source_cvss / 10 (more severe = more likely to propagate)
- **Target resistance:** Based on target node's risk profile
  - **High-risk targets** (already vulnerable) have lower resistance → easier to infect
  - **Clean targets** (no vulns) have higher resistance → harder to infect

**Formula:**

```
P = 0.5 × (source_CVSS / 10) × (1 - target_resistance × 0.5)
```

**Example scenarios:**

- CVSS 10.0 against clean target: ~40% spread chance
- CVSS 4.0 against vulnerable target: ~25% spread chance

**`run_single_simulation(G, origin_node, seed) → dict`**

Simulates one attack propagation:

1. Start with `origin_node` as compromised
2. Maintain a **frontier** (nodes to spread from this step)
3. For each node in frontier:
   - Iterate all nodes that depend on it (predecessors in DiGraph)
   - Roll dice for each edge using propagation probability
   - Add successful spreads to frontier for next iteration
4. Return:

   ```python
   {
       "origin": str,                    # Attack origin
       "compromised": set[str],          # All compromised nodes
       "blast_radius": int,              # Count of compromised nodes
       "critical_hit": bool,             # Was any CRITICAL node hit?
       "propagation_path": list[str],    # Ordered spread sequence
       "depth_reached": int,             # Maximum hops from origin
   }
   ```

#### **monte_carlo.py**

**`run_monte_carlo(G, origin_node, n_simulations) → dict`**

Runs `n_simulations` attack propagations and aggregates statistics:

1. Execute `n_simulations` calls to `run_single_simulation()`
2. Collect results: blast_radius, critical_hit, node infection counts
3. Compute aggregates:

```python
{
    "origin": str,                           # Attack origin
    "n_simulations": int,                    # Runs performed
    "mean_blast_radius": float,              # Average compromised count
    "max_blast_radius": int,                 # Worst case
    "min_blast_radius": int,                 # Best case
    "std_blast_radius": float,               # Standard deviation
    "p50_blast_radius": float,               # Median
    "p95_blast_radius": float,               # 95th percentile (tail risk)
    "critical_hit_rate": float,              # Fraction of runs hitting CRITICAL
    "node_infection_prob": dict,             # {node_id: probability}
    "exposure_score": float,                 # Overall danger (0–100)
}
```

**Exposure Score Formula:**

- Blend of mean blast radius, critical hit rate, worst-case (p95), and source CVSS
- Weights: blast_factor (35%) + critical_factor (25%) + p95_factor (25%) + cvss_factor (15%)

#### **simulation_runner.py**

**`run_full_simulation(G, n_simulations) → dict`**

Main orchestrator that:

1. Identifies all vulnerable nodes (cvss_score > 0)
2. For each vulnerable node, runs Monte Carlo simulations
3. Compiles results into global report
4. Saves to simulation_results.json

---

## **Entry Point & Workflow** (main.py)

```python
from ingestion.ingestion_runner import ingest
from graph.graph_builder import build_graph
from risk.enricher import enrich_graph, export_enriched_graph, print_risk_report
from simulation.simulation_runner import run_full_simulation

url = "https://github.com/pallets/flask"

# Module 1: Download dependencies
packages = ingest(url)

# Module 2: Build dependency graph
G = build_graph(packages, repo_name="pallets/flask", max_depth=3)

# Module 3: Enrich with vulnerabilities
G = enrich_graph(G)
export_enriched_graph(G)
print_risk_report(G)

# Module 4: Simulate attacks
results = run_full_simulation(G, n_simulations=1000)
```

---

## **Data Flow Summary**

```
GitHub Repo URL
    ↓
[Module 1] Ingest dependencies → packages list
    ↓
[Module 2] Build graph → enriched DiGraph with PageRank, centrality
    ↓
[Module 3] Query OSV → add CVSS, risk scores, classifications
    ↓
[Module 4] Simulate propagation → statistics on blast radius, exposure
    ↓
Output: Risk reports, threat profiles, cascading attack scenarios
```

---

## **Output Files** (output)

- **`graph.json`** – Raw dependency graph (nodes + edges)
- **`enriched_graph.json`** – Graph with vulnerability annotations
- **`simulation_results.json`** – Monte Carlo results for each vulnerable node

---

## **Key Design Patterns**

1. **Caching:** Both registry_client.py and osv_client.py cache results to avoid redundant API calls
2. **Modular Output:** Each module can save intermediate results; downstream stages can reload
3. **Depth-Limited Traversal:** Graph builder stops at configurable depth to prevent exponential expansion
4. **Probabilistic Simulation:** Attack propagation uses realistic probability models rather than deterministic traversal
5. **Composite Risk Scoring:** Combines vulnerability severity, graph centrality, and dependency structure

---

## **Key Insights**

- **CascadeGuard is not just a vulnerability scanner**—it's a **risk propagation engine** that identifies which vulnerabilities pose the greatest threat based on dependency structure and cascading compromise scenarios
- **A low-CVSS vulnerability affecting a central package** can be riskier than **a high-CVSS vulnerability in an obscure package**
- The **simulation module** quantifies this by running thousands of attack scenarios and measuring how far each compromise spreads

---

## **Module 5: Optimization** (optimizer)

**Purpose:** Recommend which vulnerable packages to fix first, given a limited engineering budget, to maximize risk reduction.

### Key Components

#### **cost_estimator.py**

**`estimate_fix_cost(node, data, G) → float`**

Estimates the engineering hours required to fix a vulnerable package using a multi-factor model:

**Formula:**
```
cost = base_hours 
     × ecosystem_complexity_factor
     × dependent_complexity_factor
     × version_lag_factor
```

**Factors:**

1. **Base Hours** – 2.0 hours baseline
2. **Ecosystem Complexity:**
   - PyPI: 1.0× (straightforward pip upgrade)
   - npm: 1.2× (node_modules cascading breaks)
   - Maven: 1.5× (often requires code changes)
3. **Dependent Complexity** – Based on in-degree (how many packages depend on this):
   - 0 dependents: 1.0×
   - 1–2 dependents: 1.3×
   - 3–5 dependents: 1.7×
   - 6+ dependents: 2.2×
4. **Version Lag Factor** – Historical gap between current and fixed version (1.0–2.0×)

**Example:** A Maven package with 5 dependents and version lag 2.0 = 2.0 × 1.5 × 1.7 × 1.5 ≈ 7.65 hours

**`estimate_fix_benefit(node, data) → float`**

Estimates the risk reduction value from fixing a vulnerable package:

**Combines:**
- **Risk Score** – Vulnerability severity × centrality (from Module 3)
- **Exposure Score** – Blast radius impact from simulations (from Module 4)
- **Mean Blast Radius** – Average packages protected if this is fixed
- **Fix Penalty** – Large penalty if no fix is available

**Rationale:** Higher benefit = more valuable to fix, prioritizing packages that are both vulnerable AND central to the dependency graph

#### **knapsack.py**

**`knapsack_optimize(items, budget_hours) → dict`**

Solves the **0/1 Knapsack Problem** for optimal fix selection:

- **Items** = vulnerable packages (each with cost and benefit)
- **Capacity** = total engineering budget in hours
- **Goal** = maximize total benefit while staying within budget

**Algorithm:**
1. Build DP table where `dp[i][w]` = max benefit using first i items with capacity w
2. Backtrack through DP table to identify which items were selected
3. Return selected fixes, total cost, total benefit, and risk reduction %

**Output:**
```python
{
    "selected_fixes":     list[dict],    # Packages to fix
    "total_cost":         float,         # Hours used
    "total_benefit":      float,         # Risk reduction value
    "remaining_budget":   float,         # Leftover hours
    "risk_reduction_pct": float,         # % of total risk covered
    "unaddressed_fixes":  list[dict],    # Packages not selected
}
```

**Example:** With 40 hours budget, optimizer selects 12 critical packages covering 78% of overall risk

#### **optimizer_runner.py**

**`run_optimization(G, simulation_results, budgets=[8,16,24,40], output_path) → dict`**

Main orchestrator that:

1. Builds cost/benefit profile for every vulnerable non-root node
2. Runs knapsack optimizer for multiple budget scenarios (default: 8, 16, 24, 40 hours)
3. For each budget level, outputs:
   - Packages to fix (prioritized by benefit/cost ratio)
   - Total hours required
   - Risk reduction percentage
   - Unaddressed vulns (insufficient budget or no fix available)
4. Saves full mitigation plan to `output/mitigation_plan.json`

**Output Structure:**
```python
{
    "total_vulnerable_packages": int,
    "all_items_ranked": list[dict],     # All vulns ranked by benefit/cost
    "budget_scenarios": {
        8: { ... },      # Plan for 8-hour budget
        16: { ... },     # Plan for 16-hour budget
        24: { ... },     # Plan for 24-hour budget
        40: { ... },     # Plan for 40-hour budget (recommended)
    }
}
```

**Example Output:**
```
[optimizer] Budget  40h → fixes 12 packages, uses  35.2h, covers 78.3% of risk
[optimizer] Budget  24h → fixes  8 packages, uses  23.9h, covers 65.1% of risk
[optimizer] Budget  16h → fixes  5 packages, uses  15.8h, covers 48.2% of risk
[optimizer] Budget   8h → fixes  2 packages, uses   7.5h, covers 25.0% of risk
```

---

## **Module 6: Interactive Dashboard** (dashboard)

**Purpose:** Visualize the entire CascadeGuard analysis pipeline in an interactive Streamlit web application.

### Overview

The **Streamlit Dashboard** (`dashboard/app.py`) provides a comprehensive interface for analyzing, visualizing, and acting on supply chain risk:

- **Real-time GitHub ingestion** – Paste any GitHub URL and run live analysis
- **Cached results** – Load previous analyses without re-running the full pipeline
- **Interactive visualization** – Explore dependency graphs and vulnerability heat maps
- **Risk scoring & simulation** – View Monte Carlo blast radius statistics
- **Mitigation planning** – Access knapsack-optimized fix recommendations

### Features

#### **Landing Page**

When first loaded, displays:
- Project description: "Zero-Trust Software Supply Chain Risk Intelligence"
- Three info cards:
  - 🕸️ **Graph Analysis** – Full dependency graph up to 3 levels deep (PyPI, npm, Maven)
  - 🎲 **Monte Carlo Simulation** – 1000 attack propagation simulations per vulnerable node
  - ⚡ **Smart Prioritization** – Knapsack optimization for budget-constrained fixes

#### **Sidebar Controls**

- **GitHub URL Input** – Paste repository URL (e.g., https://github.com/pallets/flask)
- **Run Live Analysis** – Executes the full 5-module pipeline with progress tracking
- **Load Cached Results** – Retrieves previous analysis from `output/` directory
- **Settings:**
  - Dependency depth slider (1–5, default 3)
  - Simulation runs selector (100, 500, 1000, 5000; default 1000)
- **Data sources** – Lists GitHub, OSV, PyPI, npm, Maven Central
- **Analysis methods** – Monte Carlo, Knapsack, PageRank

#### **Tab 1: Overview Dashboard**

**Key Performance Indicators (KPIs):**
- Total Dependencies
- Vulnerable Packages
- Critical Risk nodes
- High Risk nodes
- Total CVEs found
- Fixable packages

**Visualizations:**

1. **Risk Distribution (Donut Chart)**
   - Breakdown by severity: CRITICAL, HIGH, MEDIUM, LOW, CLEAN
   - Center circle shows total vulnerable count

2. **Top 10 Riskiest Packages (Horizontal Bar Chart)**
   - Color-coded by risk class
   - Risk scores displayed on each bar
   - Hover for package details

3. **Ecosystem Breakdown (Cards)**
   - 🐍 Python (PyPI) – package count + vulnerable count
   - 📦 Node.js (npm) – package count + vulnerable count
   - ☕ Java (Maven) – package count + vulnerable count

#### **Tab 2: Interactive Dependency Graph**

Features:
- **Force-directed network visualization** using Vis.js library
- **Node styling:**
  - Size = PageRank (importance/centrality)
  - Color = Risk class (CRITICAL red, HIGH orange, etc.)
  - Root node = highlighted entry point
- **Interactive controls:**
  - Zoom, pan, drag to explore
  - Click nodes for details popup
  - Hover for package info
- **Filters:**
  - Show all / vulnerable only / critical only
  - Depth range slider
  - Search by package name

#### **Tab 3: Simulation Results & Blast Radius**

Displays Monte Carlo attack propagation analysis:

- **Attack origin selector** – Choose which vulnerable package to trace from
- **Simulation statistics:**
  - Mean blast radius – Average packages compromised
  - P95 blast radius – Worst-case scenario (95th percentile)
  - Critical hit rate – % of runs reaching a CRITICAL node
  - Exposure score – Overall danger metric (0–100)
- **Node infection probabilities** – For each package, probability of compromise
- **Visualization:**
  - Histogram of blast radius distribution
  - Heatmap of node infection probabilities
  - Timeline of propagation (step-by-step spread)

#### **Tab 4: Mitigation Plan & Optimization**

Displays knapsack-optimized fix recommendations:

- **Budget scenario selector** – Choose 8h, 16h, 24h, or 40h budget
- **Selected fixes table:**
  - Package name
  - Risk class (with color badge)
  - CVSS score
  - Estimated fix cost (hours)
  - Benefit score
  - Fixed-in version
  - Ecosystem

- **Summary statistics:**
  - Packages to fix (count)
  - Total hours required
  - Hours remaining
  - Risk reduction % (of total vulnerability risk)

- **Unaddressed vulnerabilities:**
  - List of packages below the cut-off
  - Reason: insufficient budget or no fix available

#### **Tab 5: Package Details**

Full data table with sortable/filterable columns:
- Package name & version
- Ecosystem (PyPI / npm / Maven)
- Dependency depth
- Direct vs transitive
- CVSS score
- Risk score & class
- Vulnerability count
- Fix availability
- In-degree (how many depend on this)
- PageRank (centrality)
- Mean blast radius
- Exposure score
- AI-generated explanation

**Features:**
- Sort by any column
- Search/filter by package name
- Expandable rows for vulnerability details
- Export to CSV

#### **Styling & UX**

- **Dark theme** matching GitHub's dark UI (Primer colors)
- **Risk-based color coding:**
  - 🔴 CRITICAL – #ff7b72 (bright red)
  - 🟠 HIGH – #f0883e (orange)
  - 🟡 MEDIUM – #e3b341 (yellow)
  - 🔵 LOW – #58a6ff (blue)
  - 🟢 CLEAN – #3fb950 (green)
- **Responsive layout** – Adapts to desktop, tablet, mobile
- **Streamlit components:**
  - Progress bars for pipeline execution
  - Spinners for long-running operations
  - Info/error/success messages
  - Expandable sections for detail

### Running the Dashboard

```bash
streamlit run dashboard/app.py
```

Dashboard opens at `http://localhost:8501`

---

## **Updated Data Flow Summary**

```
GitHub Repo URL
    ↓
[Module 1] Ingest dependencies → packages list
    ↓
[Module 2] Build graph → enriched DiGraph with PageRank, centrality
    ↓
[Module 3] Query OSV → add CVSS, risk scores, classifications
    ↓
[Module 4] Simulate propagation → statistics on blast radius, exposure
    ↓
[Module 5] Optimize fixes → knapsack-selected mitigation plan
    ↓
[Module 6] Interactive Dashboard → visualizations + export
    ↓
Output: Risk reports, threat profiles, cascading attack scenarios, fix priorities
```

---

## **Complete End-to-End Workflow**

### Using the Command-Line Pipeline (main.py)

```python
from ingestion.ingestion_runner import ingest
from graph.graph_builder import build_graph
from risk.enricher import enrich_graph, export_enriched_graph, print_risk_report
from simulation.simulation_runner import run_full_simulation
from optimizer.optimizer_runner import run_optimization

url = "https://github.com/pallets/flask"

# Module 1: Download dependencies
packages = ingest(url)

# Module 2: Build dependency graph
G = build_graph(packages, repo_name="pallets/flask", max_depth=3)

# Module 3: Enrich with vulnerabilities
G = enrich_graph(G)
export_enriched_graph(G)
print_risk_report(G)

# Module 4: Simulate attacks
results = run_full_simulation(G, n_simulations=1000)

# Module 5: Optimize mitigation
mitigation = run_optimization(G, results, budgets=[8, 16, 24, 40])
```

### Using the Interactive Dashboard

1. **Start the dashboard:**
   ```bash
   streamlit run dashboard/app.py
   ```

2. **In the sidebar:**
   - Paste GitHub URL (e.g., `https://github.com/pallets/flask`)
   - Click "🚀 Run Live Analysis"

3. **Monitor progress:**
   - Dashboard shows 5 steps: Ingestion → Graph → Enrichment → Simulation → Optimization

4. **Explore results in tabs:**
   - Overview: KPIs and risk distribution
   - Dependency Graph: Interactive visualization
   - Simulation: Blast radius analysis
   - Mitigation Plan: Knapsack recommendations
   - Package Details: Full vulnerability data

5. **Export or cache:**
   - Results saved to `output/` directory
   - Next time: Click "📂 Load Cached Results" to skip pipeline
