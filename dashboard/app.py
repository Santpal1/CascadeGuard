import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import streamlit as st
import networkx as nx
from networkx.readwrite import json_graph
import json
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from collections import defaultdict

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="CascadeGuard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ── Custom CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
    /* Base */
    [data-testid="stAppViewContainer"] {
        background: #0d1117;
        color: #e6edf3;
    }
    [data-testid="stSidebar"] {
        background: #161b22;
        border-right: 1px solid #30363d;
    }
    [data-testid="stHeader"] { background: transparent; }

    /* Metric cards */
    [data-testid="stMetric"] {
        background: #161b22;
        border: 1px solid #30363d;
        border-radius: 12px;
        padding: 16px 20px;
    }
    [data-testid="stMetricLabel"] { color: #8b949e; font-size: 13px; }
    [data-testid="stMetricValue"] { color: #e6edf3; font-size: 28px; }

    /* Tabs */
    .stTabs [data-baseweb="tab-list"] {
        background: #161b22;
        border-radius: 8px;
        padding: 4px;
        border: 1px solid #30363d;
    }
    .stTabs [data-baseweb="tab"] {
        color: #8b949e;
        border-radius: 6px;
        font-weight: 500;
    }
    .stTabs [aria-selected="true"] {
        background: #21262d !important;
        color: #e6edf3 !important;
    }

    /* Buttons */
    .stButton > button {
        background: #238636;
        color: white;
        border: none;
        border-radius: 8px;
        font-weight: 600;
        padding: 10px 24px;
        width: 100%;
    }
    .stButton > button:hover { background: #2ea043; }

    /* Text input */
    .stTextInput > div > div > input {
        background: #21262d;
        border: 1px solid #30363d;
        border-radius: 8px;
        color: #e6edf3;
        font-size: 14px;
    }

    /* Section headers */
    .section-header {
        font-size: 18px;
        font-weight: 600;
        color: #e6edf3;
        padding: 8px 0 16px 0;
        border-bottom: 1px solid #30363d;
        margin-bottom: 20px;
    }

    /* Risk badges */
    .badge-critical {
        background: #ff000033;
        color: #ff7b72;
        border: 1px solid #ff7b7255;
        padding: 2px 10px;
        border-radius: 20px;
        font-size: 12px;
        font-weight: 600;
    }
    .badge-high {
        background: #fd7e1433;
        color: #f0883e;
        border: 1px solid #f0883e55;
        padding: 2px 10px;
        border-radius: 20px;
        font-size: 12px;
        font-weight: 600;
    }
    .badge-medium {
        background: #e3b34133;
        color: #e3b341;
        border: 1px solid #e3b34155;
        padding: 2px 10px;
        border-radius: 20px;
        font-size: 12px;
        font-weight: 600;
    }
    .badge-low {
        background: #1f6feb33;
        color: #58a6ff;
        border: 1px solid #58a6ff55;
        padding: 2px 10px;
        border-radius: 20px;
        font-size: 12px;
        font-weight: 600;
    }
    .badge-clean {
        background: #23863633;
        color: #3fb950;
        border: 1px solid #3fb95055;
        padding: 2px 10px;
        border-radius: 20px;
        font-size: 12px;
        font-weight: 600;
    }

    /* Info card */
    .info-card {
        background: #161b22;
        border: 1px solid #30363d;
        border-radius: 12px;
        padding: 20px;
        margin-bottom: 16px;
    }

    /* Expander */
    .streamlit-expanderHeader {
        background: #161b22 !important;
        border: 1px solid #30363d !important;
        border-radius: 8px !important;
        color: #e6edf3 !important;
    }

    /* Explanation box */
    .explanation-box {
        background: #1c2128;
        border-left: 3px solid #58a6ff;
        padding: 10px 16px;
        border-radius: 0 8px 8px 0;
        font-size: 13px;
        color: #8b949e;
        margin-top: 8px;
    }

    /* Dataframe */
    [data-testid="stDataFrame"] { border-radius: 8px; }

    /* Divider */
    hr { border-color: #30363d; }

    /* Slider */
    .stSlider > div > div > div { background: #238636; }
</style>
""", unsafe_allow_html=True)


# ── Helpers ───────────────────────────────────────────────────────────────────

RISK_COLORS = {
    "CRITICAL": "#ff7b72",
    "HIGH":     "#f0883e",
    "MEDIUM":   "#e3b341",
    "LOW":      "#58a6ff",
    "CLEAN":    "#3fb950",
    "UNKNOWN":  "#8b949e",
}

def badge(risk_class: str) -> str:
    cls = risk_class.lower() if risk_class else "clean"
    return f'<span class="badge-{cls}">{risk_class}</span>'

def load_graph_from_file(path: str) -> nx.DiGraph | None:
    if not os.path.exists(path):
        return None
    with open(path) as f:
        data = json.load(f)
    return json_graph.node_link_graph(data, directed=True, edges="links")

def load_json(path: str) -> dict | None:
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)

def run_pipeline(github_url: str, progress_bar, status_text) -> nx.DiGraph:
    """Runs the full CascadeGuard pipeline and returns the enriched graph."""
    from ingestion.ingestion_runner import ingest
    from graph.graph_builder import build_graph
    from risk.enricher import enrich_graph, export_enriched_graph
    from risk.enricher import rescore_after_simulation
    from simulation.simulation_runner import run_full_simulation
    from optimizer.optimizer_runner import run_optimization

    repo_name = github_url.rstrip("/").split("github.com/")[-1]

    status_text.text("📦 Step 1/5 — Fetching repository & parsing dependencies...")
    progress_bar.progress(10)
    packages = ingest(github_url)

    status_text.text("🕸️ Step 2/5 — Building dependency graph...")
    progress_bar.progress(30)
    G = build_graph(packages, repo_name=repo_name, max_depth=3)

    status_text.text("🔍 Step 3/5 — Querying vulnerability databases...")
    progress_bar.progress(50)
    G = enrich_graph(G)

    status_text.text("🎲 Step 4/5 — Running Monte Carlo simulations...")
    progress_bar.progress(70)
    results = run_full_simulation(G, n_simulations=1000)
    G = rescore_after_simulation(G, results)

    for node, data in G.nodes(data=True):
        if data.get("ecosystem") != "root":
            from risk.enricher import _build_explanation
            sim = results.get(node, {})
            G.nodes[node]["explanation"] = _build_explanation(node, data, sim)

    status_text.text("⚡ Step 5/5 — Optimizing mitigation plan...")
    progress_bar.progress(90)
    export_enriched_graph(G)
    run_optimization(G, results)

    progress_bar.progress(100)
    status_text.text("✅ Analysis complete.")

    return G, results

def get_node_df(G: nx.DiGraph) -> pd.DataFrame:
    """Converts graph nodes to a clean DataFrame for display."""
    rows = []
    for node, data in G.nodes(data=True):
        if data.get("ecosystem") == "root":
            continue
        rows.append({
            "package":       node,
            "version":       data.get("version", "—"),
            "ecosystem":     data.get("ecosystem", "—"),
            "depth":         data.get("depth", 0),
            "direct":        data.get("direct", False),
            "cvss_score":    data.get("cvss_score", 0.0),
            "risk_score":    data.get("risk_score", 0.0),
            "risk_class":    data.get("risk_class", "CLEAN"),
            "vuln_count":    data.get("vuln_count", 0),
            "fix_available": data.get("fix_available", False),
            "in_degree":     data.get("in_degree", 0),
            "pagerank":      round(data.get("pagerank", 0.0), 5),
            "mean_blast_radius": data.get("mean_blast_radius", 0.0),
            "exposure_score":    data.get("exposure_score", 0.0),
            "explanation":   data.get("explanation", ""),
        })
    return pd.DataFrame(rows).sort_values("risk_score", ascending=False)


# ── Sidebar ───────────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown("""
    <div style="padding: 8px 0 24px 0;">
        <div style="font-size:24px; font-weight:700; color:#e6edf3;">
            🛡️ CascadeGuard
        </div>
        <div style="font-size:12px; color:#8b949e; margin-top:4px;">
            Supply Chain Risk Intelligence
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("#### Analyze Repository")
    github_url = st.text_input(
        "GitHub URL",
        placeholder="https://github.com/owner/repo",
        label_visibility="collapsed"
    )

    run_live  = st.button("🚀 Run Live Analysis")
    load_cached = st.button("📂 Load Cached Results")

    st.markdown("---")
    st.markdown("#### Settings")
    max_depth = st.slider("Dependency depth", 1, 5, 3)
    n_sims    = st.select_slider(
        "Simulation runs",
        options=[100, 500, 1000, 5000],
        value=1000
    )

    st.markdown("---")
    st.markdown("""
    <div style="font-size:11px; color:#8b949e; line-height:1.6;">
        <b style="color:#e6edf3">Data sources</b><br>
        GitHub REST API<br>
        OSV Vulnerability DB<br>
        PyPI · npm · Maven Central<br><br>
        <b style="color:#e6edf3">Analysis</b><br>
        Monte Carlo Simulation<br>
        0/1 Knapsack Optimization<br>
        PageRank Centrality
    </div>
    """, unsafe_allow_html=True)


# ── Session state ─────────────────────────────────────────────────────────────

if "G" not in st.session_state:
    st.session_state.G = None
if "sim_results" not in st.session_state:
    st.session_state.sim_results = None
if "repo_name" not in st.session_state:
    st.session_state.repo_name = None


# ── Pipeline trigger ──────────────────────────────────────────────────────────

if run_live and github_url:
    with st.spinner(""):
        progress_bar = st.progress(0)
        status_text  = st.empty()
        G, results   = run_pipeline(github_url, progress_bar, status_text)
        st.session_state.G           = G
        st.session_state.sim_results = results
        st.session_state.repo_name   = github_url.split("github.com/")[-1].rstrip("/")
        st.rerun()

elif load_cached:
    G = load_graph_from_file("output/enriched_graph.json")
    results = load_json("output/simulation_results.json")
    if G and results:
        st.session_state.G           = G
        st.session_state.sim_results = {
            k: v for k, v in results.items() if k != "__summary__"
        }
        st.session_state.repo_name   = "cached results"
        st.success("Loaded cached results.")
    else:
        st.error("No cached results found. Run a live analysis first.")


# ── Landing screen ────────────────────────────────────────────────────────────

if st.session_state.G is None:
    st.markdown("""
    <div style="text-align:center; padding: 80px 0 40px 0;">
        <div style="font-size:64px;">🛡️</div>
        <div style="font-size:36px; font-weight:700; color:#e6edf3; margin-top:16px;">
            CascadeGuard
        </div>
        <div style="font-size:18px; color:#8b949e; margin-top:8px;">
            Zero-Trust Software Supply Chain Risk Intelligence
        </div>
        <div style="font-size:14px; color:#8b949e; margin-top:24px; max-width:560px;
                    margin-left:auto; margin-right:auto; line-height:1.8;">
            Enter a GitHub repository URL in the sidebar to analyze its full
            dependency graph, detect vulnerabilities, simulate attack propagation,
            and generate an optimized mitigation plan.
        </div>
    </div>
    """, unsafe_allow_html=True)

    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown("""
        <div class="info-card">
            <div style="font-size:28px;">🕸️</div>
            <div style="font-weight:600; color:#e6edf3; margin-top:8px;">
                Graph Analysis
            </div>
            <div style="font-size:13px; color:#8b949e; margin-top:6px;">
                Builds a full dependency graph up to 3 levels deep across
                PyPI, npm, and Maven ecosystems.
            </div>
        </div>
        """, unsafe_allow_html=True)
    with c2:
        st.markdown("""
        <div class="info-card">
            <div style="font-size:28px;">🎲</div>
            <div style="font-weight:600; color:#e6edf3; margin-top:8px;">
                Monte Carlo Simulation
            </div>
            <div style="font-size:13px; color:#8b949e; margin-top:6px;">
                Runs 1000 attack propagation simulations per vulnerable node
                to estimate real-world blast radius probabilities.
            </div>
        </div>
        """, unsafe_allow_html=True)
    with c3:
        st.markdown("""
        <div class="info-card">
            <div style="font-size:28px;">⚡</div>
            <div style="font-weight:600; color:#e6edf3; margin-top:8px;">
                Smart Prioritization
            </div>
            <div style="font-size:13px; color:#8b949e; margin-top:6px;">
                Knapsack optimization selects the highest-value fixes within
                your engineering budget — not just highest CVSS.
            </div>
        </div>
        """, unsafe_allow_html=True)
    st.stop()


# ── Main dashboard ────────────────────────────────────────────────────────────

G       = st.session_state.G
results = st.session_state.sim_results or {}
df      = get_node_df(G)

# Header
st.markdown(f"""
<div style="display:flex; align-items:center; justify-content:space-between;
            padding:0 0 20px 0; border-bottom:1px solid #30363d; margin-bottom:24px;">
    <div>
        <div style="font-size:22px; font-weight:700; color:#e6edf3;">
            🛡️ CascadeGuard
        </div>
        <div style="font-size:13px; color:#8b949e; margin-top:2px;">
            {st.session_state.repo_name}
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

# ── KPI row ───────────────────────────────────────────────────────────────────
total_nodes    = len(df)
vulnerable     = len(df[df["cvss_score"] > 0])
critical_nodes = len(df[df["risk_class"] == "CRITICAL"])
high_nodes     = len(df[df["risk_class"] == "HIGH"])
total_vulns    = int(df["vuln_count"].sum())
fixable        = len(df[(df["cvss_score"] > 0) & (df["fix_available"] == True)])

k1, k2, k3, k4, k5, k6 = st.columns(6)
k1.metric("Total Dependencies", total_nodes)
k2.metric("Vulnerable Packages", vulnerable)
k3.metric("Critical Risk",       critical_nodes, delta=None)
k4.metric("High Risk",           high_nodes)
k5.metric("Total CVEs",          total_vulns)
k6.metric("Fixable Now",         fixable)

st.markdown("<br>", unsafe_allow_html=True)

# ── Tabs ──────────────────────────────────────────────────────────────────────
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "📊  Overview",
    "🕸️  Dependency Graph",
    "🎲  Simulation",
    "⚡  Mitigation Plan",
    "🔍  Package Details",
])


# ══════════════════════════════════════════════════════════════════════════════
# TAB 1 — OVERVIEW
# ══════════════════════════════════════════════════════════════════════════════
with tab1:
    col_left, col_right = st.columns([1, 1], gap="large")

    with col_left:
        st.markdown('<div class="section-header">Risk Distribution</div>',
                    unsafe_allow_html=True)

        class_counts = df["risk_class"].value_counts().reset_index()
        class_counts.columns = ["class", "count"]

        order  = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "CLEAN"]
        colors = [RISK_COLORS.get(c, "#8b949e") for c in order]
        counts = [
            int(class_counts[class_counts["class"] == c]["count"].values[0])
            if c in class_counts["class"].values else 0
            for c in order
        ]

        fig_donut = go.Figure(go.Pie(
            labels=order,
            values=counts,
            hole=0.65,
            marker_colors=colors,
            textinfo="label+value",
            textfont=dict(color="#e6edf3", size=13),
            hovertemplate="<b>%{label}</b><br>%{value} packages<extra></extra>"
        ))
        fig_donut.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor ="rgba(0,0,0,0)",
            showlegend=False,
            margin=dict(t=20, b=20, l=20, r=20),
            height=280,
            annotations=[dict(
                text=f"<b>{vulnerable}</b><br>vulnerable",
                x=0.5, y=0.5,
                font=dict(color="#e6edf3", size=16),
                showarrow=False
            )]
        )
        st.plotly_chart(fig_donut, use_container_width=True)

    with col_right:
        st.markdown('<div class="section-header">Top 10 Riskiest Packages</div>',
                    unsafe_allow_html=True)

        top10 = df[df["risk_score"] > 0].head(10)
        if not top10.empty:
            fig_bar = go.Figure(go.Bar(
                x=top10["risk_score"],
                y=top10["package"].str.split(":").str[-1],
                orientation="h",
                marker=dict(
                    color=top10["risk_class"].map(RISK_COLORS),
                    line=dict(width=0)
                ),
                text=top10["risk_score"].round(1),
                textposition="outside",
                textfont=dict(color="#e6edf3", size=11),
                hovertemplate=(
                    "<b>%{y}</b><br>"
                    "Risk Score: %{x:.1f}<br>"
                    "<extra></extra>"
                )
            ))
            fig_bar.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor ="rgba(0,0,0,0)",
                xaxis=dict(
                    showgrid=True,
                    gridcolor="#30363d",
                    color="#8b949e",
                    range=[0, top10["risk_score"].max() * 1.2]
                ),
                yaxis=dict(
                    color="#e6edf3",
                    autorange="reversed"
                ),
                margin=dict(t=10, b=10, l=10, r=60),
                height=300,
            )
            st.plotly_chart(fig_bar, use_container_width=True)

    # Ecosystem breakdown
    st.markdown('<div class="section-header">Ecosystem Breakdown</div>',
                unsafe_allow_html=True)
    eco_cols = st.columns(3)
    for i, eco in enumerate(["pypi", "npm", "maven"]):
        eco_df = df[df["ecosystem"] == eco]
        vuln_eco = len(eco_df[eco_df["cvss_score"] > 0])
        with eco_cols[i]:
            label = {"pypi": "🐍 Python (PyPI)",
                     "npm":  "📦 Node.js (npm)",
                     "maven":"☕ Java (Maven)"}[eco]
            st.markdown(f"""
            <div class="info-card">
                <div style="font-size:15px; font-weight:600;
                            color:#e6edf3;">{label}</div>
                <div style="margin-top:12px; display:flex;
                            justify-content:space-between;">
                    <div>
                        <div style="font-size:24px; font-weight:700;
                                    color:#e6edf3;">{len(eco_df)}</div>
                        <div style="font-size:12px;
                                    color:#8b949e;">packages</div>
                    </div>
                    <div>
                        <div style="font-size:24px; font-weight:700;
                                    color:#ff7b72;">{vuln_eco}</div>
                        <div style="font-size:12px;
                                    color:#8b949e;">vulnerable</div>
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
# TAB 2 — DEPENDENCY GRAPH
# ══════════════════════════════════════════════════════════════════════════════
with tab2:
    st.markdown('<div class="section-header">Interactive Dependency Graph</div>',
                unsafe_allow_html=True)

    try:
        from pyvis.network import Network
        import streamlit.components.v1 as components

        net = Network(
            height="600px", width="100%",
            bgcolor="#0d1117", font_color="#e6edf3",
            directed=True
        )
        net.barnes_hut(
            gravity=-8000,
            central_gravity=0.3,
            spring_length=120,
            spring_strength=0.05
        )

        for node, data in G.nodes(data=True):
            eco      = data.get("ecosystem", "root")
            rc       = data.get("risk_class", "CLEAN")
            rs       = data.get("risk_score", 0.0)
            label    = node.split(":")[-1] if ":" in node else node
            color    = RISK_COLORS.get(rc, "#8b949e")
            size     = 10 + data.get("pagerank", 0) * 800
            size     = max(8, min(size, 40))
            title    = (
                f"<b>{node}</b><br>"
                f"Version: {data.get('version','—')}<br>"
                f"Risk: {rc} ({rs:.1f})<br>"
                f"CVSS: {data.get('cvss_score',0)}<br>"
                f"Vulns: {data.get('vuln_count',0)}<br>"
                f"{data.get('explanation','')}"
            )
            if eco == "root":
                color = "#58a6ff"
                size  = 30
            net.add_node(
                node, label=label,
                color=color, size=size,
                title=title, font={"size": 11}
            )

        for src, tgt in G.edges():
            net.add_edge(src, tgt, color="#30363d", arrows="to", width=0.8)

        os.makedirs("output", exist_ok=True)
        net.save_graph("output/graph_vis.html")
        with open("output/graph_vis.html") as f:
            html = f.read()
        components.html(html, height=620, scrolling=False)

    except ImportError:
        st.warning("Install pyvis for interactive graph: `pip install pyvis`")
        # Fallback: static plotly graph
        pos = nx.spring_layout(G, seed=42)
        edge_x, edge_y = [], []
        for src, tgt in G.edges():
            x0,y0 = pos[src]; x1,y1 = pos[tgt]
            edge_x += [x0,x1,None]; edge_y += [y0,y1,None]

        node_x = [pos[n][0] for n in G.nodes()]
        node_y = [pos[n][1] for n in G.nodes()]
        node_colors = [
            RISK_COLORS.get(G.nodes[n].get("risk_class","CLEAN"), "#8b949e")
            for n in G.nodes()
        ]
        fig_g = go.Figure()
        fig_g.add_trace(go.Scatter(
            x=edge_x, y=edge_y, mode="lines",
            line=dict(color="#30363d", width=0.8), hoverinfo="none"
        ))
        fig_g.add_trace(go.Scatter(
            x=node_x, y=node_y, mode="markers+text",
            marker=dict(color=node_colors, size=10),
            text=[n.split(":")[-1] for n in G.nodes()],
            textfont=dict(color="#e6edf3", size=9),
            textposition="top center"
        ))
        fig_g.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="#0d1117",
            showlegend=False, height=500,
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        )
        st.plotly_chart(fig_g, use_container_width=True)

    # Legend
    st.markdown("""
    <div style="display:flex; gap:16px; flex-wrap:wrap; margin-top:12px;">
        <span class="badge-critical">● CRITICAL</span>
        <span class="badge-high">● HIGH</span>
        <span class="badge-medium">● MEDIUM</span>
        <span class="badge-low">● LOW / ROOT</span>
        <span class="badge-clean">● CLEAN</span>
    </div>
    """, unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
# TAB 3 — SIMULATION
# ══════════════════════════════════════════════════════════════════════════════
with tab3:
    st.markdown('<div class="section-header">Attack Propagation Simulation</div>',
                unsafe_allow_html=True)

    sim_data = [
        {
            "package":         node,
            "exposure_score":  data["exposure_score"],
            "mean_blast_radius": data["mean_blast_radius"],
            "p95_blast_radius":  data["p95_blast_radius"],
            "critical_hit_rate": data["critical_hit_rate"] * 100,
            "cvss_score":      G.nodes[node].get("cvss_score", 0),
            "risk_class":      G.nodes[node].get("risk_class", "CLEAN"),
        }
        for node, data in results.items()
        if isinstance(data, dict) and "exposure_score" in data
    ]

    if not sim_data:
        st.info("No simulation data available.")
    else:
        sim_df = pd.DataFrame(sim_data).sort_values(
            "exposure_score", ascending=False
        )

        c1, c2 = st.columns(2, gap="large")

        with c1:
            st.markdown("**Exposure Score by Package**")
            fig_exp = go.Figure(go.Bar(
                x=sim_df["exposure_score"],
                y=sim_df["package"].str.split(":").str[-1],
                orientation="h",
                marker=dict(
                    color=sim_df["risk_class"].map(RISK_COLORS),
                    line=dict(width=0)
                ),
                text=sim_df["exposure_score"].round(1),
                textposition="outside",
                textfont=dict(color="#e6edf3", size=11),
                hovertemplate=(
                    "<b>%{y}</b><br>Exposure: %{x:.1f}<extra></extra>"
                )
            ))
            fig_exp.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor ="rgba(0,0,0,0)",
                xaxis=dict(showgrid=True, gridcolor="#30363d",
                           color="#8b949e"),
                yaxis=dict(color="#e6edf3", autorange="reversed"),
                margin=dict(t=10, b=10, l=10, r=60),
                height=350,
            )
            st.plotly_chart(fig_exp, use_container_width=True)

        with c2:
            st.markdown("**Blast Radius Distribution**")
            fig_br = go.Figure()
            fig_br.add_trace(go.Bar(
                name="Mean",
                x=sim_df["package"].str.split(":").str[-1],
                y=sim_df["mean_blast_radius"],
                marker_color="#58a6ff",
                opacity=0.85
            ))
            fig_br.add_trace(go.Bar(
                name="P95 (worst case)",
                x=sim_df["package"].str.split(":").str[-1],
                y=sim_df["p95_blast_radius"],
                marker_color="#ff7b72",
                opacity=0.65
            ))
            fig_br.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor ="rgba(0,0,0,0)",
                barmode="group",
                xaxis=dict(showgrid=False, color="#8b949e",
                           tickangle=-30),
                yaxis=dict(showgrid=True, gridcolor="#30363d",
                           color="#8b949e", title="Nodes affected"),
                legend=dict(font=dict(color="#e6edf3")),
                margin=dict(t=10, b=60, l=10, r=10),
                height=350,
            )
            st.plotly_chart(fig_br, use_container_width=True)

        # Critical hit rate scatter
        st.markdown("**Critical Hit Rate vs Exposure Score**")
        fig_scatter = px.scatter(
            sim_df,
            x="exposure_score",
            y="critical_hit_rate",
            color="risk_class",
            size="mean_blast_radius",
            hover_name="package",
            color_discrete_map=RISK_COLORS,
            labels={
                "exposure_score":    "Exposure Score",
                "critical_hit_rate": "Critical Hit Rate (%)",
                "risk_class":        "Risk Class"
            },
            size_max=30,
        )
        fig_scatter.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor ="#161b22",
            xaxis=dict(showgrid=True, gridcolor="#30363d", color="#8b949e"),
            yaxis=dict(showgrid=True, gridcolor="#30363d", color="#8b949e"),
            legend=dict(font=dict(color="#e6edf3"),
                        bgcolor="rgba(0,0,0,0)"),
            height=350,
        )
        st.plotly_chart(fig_scatter, use_container_width=True)

        # Systemic risk nodes
        sim_all = load_json("output/simulation_results.json") or {}
        summary = sim_all.get("__summary__", {})
        systemic = summary.get("systemic_risk_nodes", [])
        if systemic:
            st.markdown("**Systemic Risk Nodes** *(infected in >50% of all simulations)*")
            cols = st.columns(min(len(systemic), 4))
            for i, node in enumerate(systemic[:8]):
                rc = G.nodes[node].get("risk_class", "CLEAN") if node in G.nodes else "UNKNOWN"
                with cols[i % 4]:
                    st.markdown(
                        f'<div class="info-card" style="text-align:center;">'
                        f'<div style="font-size:12px; color:#e6edf3; '
                        f'font-weight:600;">{node.split(":")[-1]}</div>'
                        f'<div style="margin-top:8px;">{badge(rc)}</div>'
                        f'</div>',
                        unsafe_allow_html=True
                    )


# ══════════════════════════════════════════════════════════════════════════════
# TAB 4 — MITIGATION PLAN
# ══════════════════════════════════════════════════════════════════════════════
with tab4:
    st.markdown('<div class="section-header">Budget-Optimized Mitigation Plan</div>',
                unsafe_allow_html=True)

    plan_data = load_json("output/mitigation_plan.json")

    if not plan_data:
        st.info("Run the analysis to generate a mitigation plan.")
    else:
        budget = st.slider(
            "Engineering Budget (hours)",
            min_value=4, max_value=80, value=40, step=4,
            help="Adjust budget to see which fixes fit"
        )

        # Re-run knapsack for selected budget on the fly
        from optimizer.knapsack import knapsack_optimize
        all_items = plan_data.get("all_items_ranked", [])
        result    = knapsack_optimize(all_items, budget)
        selected  = result["selected_fixes"]
        unaddressed = result["unaddressed_fixes"]

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Fixes Selected",    len(selected))
        m2.metric("Hours Used",        f"{result['total_cost']}h")
        m3.metric("Hours Remaining",   f"{result['remaining_budget']}h")
        m4.metric("Risk Reduction",    f"{result['risk_reduction_pct']}%")

        st.markdown("<br>", unsafe_allow_html=True)

        if selected:
            st.markdown("**Selected Fixes — Prioritized Order**")
            for i, item in enumerate(selected, 1):
                rc       = item.get("risk_class", "UNKNOWN")
                fix_ver  = item.get("fixed_in") or "—"
                node     = item.get("node", "")
                pkg_name = node.split(":")[-1] if ":" in node else node
                exp      = G.nodes[node].get("explanation", "") \
                           if node in G.nodes else ""

                st.markdown(f"""
                <div class="info-card" style="margin-bottom:10px;">
                    <div style="display:flex; justify-content:space-between;
                                align-items:center;">
                        <div style="display:flex; align-items:center; gap:12px;">
                            <div style="font-size:18px; font-weight:700;
                                        color:#8b949e; min-width:28px;">
                                #{i}
                            </div>
                            <div>
                                <div style="font-weight:600; color:#e6edf3;">
                                    {pkg_name}
                                </div>
                                <div style="font-size:12px; color:#8b949e;">
                                    {node} · v{item.get('version','—')}
                                </div>
                            </div>
                        </div>
                        <div style="display:flex; gap:12px; align-items:center;">
                            {badge(rc)}
                            <div style="text-align:right;">
                                <div style="font-size:12px; color:#8b949e;">
                                    CVSS</div>
                                <div style="font-weight:600;
                                            color:{RISK_COLORS.get(rc,'#8b949e')};">
                                    {item.get('cvss_score',0):.1f}
                                </div>
                            </div>
                            <div style="text-align:right;">
                                <div style="font-size:12px; color:#8b949e;">
                                    Cost</div>
                                <div style="font-weight:600; color:#e6edf3;">
                                    {item.get('cost_hours',0):.1f}h
                                </div>
                            </div>
                            <div style="text-align:right;">
                                <div style="font-size:12px;
                                            color:#8b949e;">Fix version</div>
                                <div style="font-weight:600; color:#3fb950;">
                                    {fix_ver}
                                </div>
                            </div>
                        </div>
                    </div>
                    {f'<div class="explanation-box">{exp}</div>' if exp else ''}
                </div>
                """, unsafe_allow_html=True)

        if unaddressed:
            with st.expander(
                f"⚠️ {len(unaddressed)} packages not addressed "
                f"(increase budget or no fix available)"
            ):
                for item in unaddressed:
                    tag = "🔒 no fix" if not item.get("fix_available") else ""
                    st.markdown(
                        f"- `{item['node']}` — "
                        f"CVSS {item.get('cvss_score',0):.1f} "
                        f"· {item.get('risk_class','—')} {tag}"
                    )

        # Risk reduction efficiency chart
        st.markdown("<br>**Budget Efficiency — Risk Reduction per Scenario**")
        budgets_list = [4, 8, 12, 16, 20, 24, 32, 40, 56, 80]
        reductions   = []
        for b in budgets_list:
            r = knapsack_optimize(all_items, b)
            reductions.append(r["risk_reduction_pct"])

        fig_eff = go.Figure(go.Scatter(
            x=budgets_list, y=reductions,
            mode="lines+markers",
            line=dict(color="#238636", width=2),
            marker=dict(color="#3fb950", size=8),
            fill="tozeroy",
            fillcolor="rgba(35,134,54,0.15)",
            hovertemplate="Budget: %{x}h → %{y:.1f}% risk reduction<extra></extra>"
        ))
        # Mark current budget
        current_pct = knapsack_optimize(all_items, budget)["risk_reduction_pct"]
        fig_eff.add_vline(
            x=budget,
            line_dash="dash",
            line_color="#58a6ff",
            annotation_text=f"  {budget}h → {current_pct:.1f}%",
            annotation_font_color="#58a6ff"
        )
        fig_eff.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="#161b22",
            xaxis=dict(
                title="Budget (hours)",
                showgrid=True, gridcolor="#30363d",
                color="#8b949e"
            ),
            yaxis=dict(
                title="Risk Reduction (%)",
                showgrid=True, gridcolor="#30363d",
                color="#8b949e", range=[0, 105]
            ),
            height=300,
            margin=dict(t=10, b=40, l=10, r=10),
        )
        st.plotly_chart(fig_eff, use_container_width=True)


# ══════════════════════════════════════════════════════════════════════════════
# TAB 5 — PACKAGE DETAILS
# ══════════════════════════════════════════════════════════════════════════════
with tab5:
    st.markdown('<div class="section-header">Package Vulnerability Details</div>',
                unsafe_allow_html=True)

    # Filter controls
    fc1, fc2, fc3 = st.columns(3)
    with fc1:
        filter_class = st.multiselect(
            "Risk Class",
            ["CRITICAL", "HIGH", "MEDIUM", "LOW", "CLEAN"],
            default=["CRITICAL", "HIGH", "MEDIUM"]
        )
    with fc2:
        filter_eco = st.multiselect(
            "Ecosystem",
            ["pypi", "npm", "maven"],
            default=["pypi", "npm", "maven"]
        )
    with fc3:
        filter_fix = st.selectbox(
            "Fix Available",
            ["All", "Fix available", "No fix yet"]
        )

    fdf = df[df["risk_class"].isin(filter_class) &
             df["ecosystem"].isin(filter_eco)]
    if filter_fix == "Fix available":
        fdf = fdf[fdf["fix_available"] == True]
    elif filter_fix == "No fix yet":
        fdf = fdf[fdf["fix_available"] == False]

    st.markdown(f"*Showing {len(fdf)} packages*")

    for _, row in fdf.iterrows():
        node = row["package"]
        data = G.nodes.get(node, {})
        vulns = data.get("vulnerabilities", [])

        with st.expander(
            f"{node.split(':')[-1]}  |  "
            f"CVSS {row['cvss_score']:.1f}  |  "
            f"Risk {row['risk_score']:.1f}  |  "
            f"{row['risk_class']}"
        ):
            d1, d2, d3, d4 = st.columns(4)
            d1.metric("Risk Score",  f"{row['risk_score']:.1f}")
            d2.metric("CVSS",        f"{row['cvss_score']:.1f}")
            d3.metric("CVE Count",   row["vuln_count"])
            d4.metric("Dependents",  row["in_degree"])

            if row["explanation"]:
                st.markdown(
                    f'<div class="explanation-box">💡 {row["explanation"]}</div>',
                    unsafe_allow_html=True
                )

            if vulns:
                st.markdown("**Known Vulnerabilities**")
                for v in vulns:
                    color = RISK_COLORS.get(v.get("severity", ""), "#8b949e")
                    fix   = v.get("fixed_in") or "No fix available"
                    st.markdown(f"""
                    <div style="background:#1c2128; border:1px solid #30363d;
                                border-radius:8px; padding:12px 16px;
                                margin-bottom:8px;">
                        <div style="display:flex; justify-content:space-between;
                                    align-items:center;">
                            <div>
                                <span style="font-weight:600;
                                             color:{color};">
                                    {v.get('display_id','—')}
                                </span>
                                <span style="font-size:12px; color:#8b949e;
                                             margin-left:10px;">
                                    CVSS {v.get('cvss_score',0):.1f}
                                </span>
                            </div>
                            <div style="font-size:12px;">
                                <span style="color:#3fb950;">
                                    Fix: {fix}
                                </span>
                                <a href="{v.get('detail_url','#')}"
                                   target="_blank"
                                   style="color:#58a6ff; margin-left:12px;
                                          text-decoration:none;">
                                    View ↗
                                </a>
                            </div>
                        </div>
                        <div style="font-size:13px; color:#8b949e; margin-top:6px;">
                            {v.get('summary','—')}
                        </div>
                    </div>
                    """, unsafe_allow_html=True)
            else:
                st.markdown(
                    '<div style="color:#3fb950; font-size:13px;">'
                    '✅ No known vulnerabilities</div>',
                    unsafe_allow_html=True
                )