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
