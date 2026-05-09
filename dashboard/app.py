"""
CascadeGuard Dashboard - Interactive web UI for risk visualization and mitigation planning.
Built with Streamlit.
"""

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
import logging

from logging_config import setup_logging, get_logger
from config import get_config

# Setup logging
setup_logging()
logger = get_logger(__name__)

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="CascadeGuard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ── Theme configuration ────────────────────────────────────────────────────────
def get_theme_css(is_light: bool) -> str:
    """Generate CSS based on theme preference."""
    if is_light:
        return """
        <style>
            /* Light Mode - Professional */
            [data-testid="stAppViewContainer"] {
                background: linear-gradient(135deg, #f8f9fa 0%, #f5f7fb 100%);
                color: #1a1f3a;
            }
            [data-testid="stSidebar"] {
                background: linear-gradient(135deg, #ffffff 0%, #f9fafc 100%);
                border-right: 1px solid #e0e3e8;
            }
            [data-testid="stHeader"] { background: transparent; }
            [data-testid="stToolbar"] { right: 2rem; }

            /* Metric cards */
            [data-testid="stMetric"] {
                background: white;
                border: 1px solid #e0e3e8;
                border-radius: 16px;
                padding: 20px;
                box-shadow: 0 2px 8px rgba(26, 31, 58, 0.05);
                transition: all 0.3s ease;
            }
            [data-testid="stMetric"]:hover {
                box-shadow: 0 4px 16px rgba(26, 31, 58, 0.1);
                border-color: #d0d4db;
            }
            [data-testid="stMetricLabel"] { color: #6b7280; font-size: 12px; font-weight: 500; letter-spacing: 0.5px; }
            [data-testid="stMetricValue"] { color: #1a1f3a; font-size: 32px; font-weight: 700; }

            /* Tabs */
            .stTabs [data-baseweb="tab-list"] {
                background: transparent;
                border-radius: 12px;
                padding: 0;
                border-bottom: 2px solid #e0e3e8;
            }
            .stTabs [data-baseweb="tab"] {
                color: #6b7280;
                border-radius: 8px 8px 0 0;
                font-weight: 600;
                padding: 12px 20px !important;
                transition: all 0.3s ease;
            }
            .stTabs [data-baseweb="tab"]:hover {
                color: #1a1f3a;
                background: #f0f3f8;
            }
            .stTabs [aria-selected="true"] {
                background: transparent !important;
                color: #0066cc !important;
                border-bottom: 3px solid #0066cc !important;
            }

            /* Buttons */
            .stButton > button {
                background: linear-gradient(135deg, #0066cc 0%, #0052a3 100%);
                color: white;
                border: none;
                border-radius: 10px;
                font-weight: 600;
                padding: 12px 24px;
                width: 100%;
                box-shadow: 0 4px 12px rgba(0, 102, 204, 0.25);
                transition: all 0.3s ease;
            }
            .stButton > button:hover {
                background: linear-gradient(135deg, #0052a3 0%, #003d7a 100%);
                box-shadow: 0 6px 16px rgba(0, 102, 204, 0.35);
                transform: translateY(-2px);
            }

            /* Text input */
            .stTextInput > div > div > input {
                background: white;
                border: 1.5px solid #e0e3e8;
                border-radius: 10px;
                color: #1a1f3a;
                font-size: 14px;
                padding: 10px 14px;
                transition: all 0.3s ease;
            }
            .stTextInput > div > div > input:focus {
                border-color: #0066cc;
                box-shadow: 0 0 0 3px rgba(0, 102, 204, 0.1);
            }

            /* Section headers */
            .section-header {
                font-size: 20px;
                font-weight: 700;
                color: #1a1f3a;
                padding: 8px 0 20px 0;
                border-bottom: 2px solid #e0e3e8;
                margin-bottom: 24px;
                background: linear-gradient(90deg, #1a1f3a 0%, #0066cc 100%);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
            }

            /* Risk badges - Light mode */
            .badge-critical {
                background: #fee2e2;
                color: #dc2626;
                border: 1px solid #fecaca;
                padding: 4px 12px;
                border-radius: 20px;
                font-size: 12px;
                font-weight: 600;
            }
            .badge-high {
                background: #fed7aa;
                color: #d97706;
                border: 1px solid #fdba74;
                padding: 4px 12px;
                border-radius: 20px;
                font-size: 12px;
                font-weight: 600;
            }
            .badge-medium {
                background: #fef3c7;
                color: #d97706;
                border: 1px solid #fde68a;
                padding: 4px 12px;
                border-radius: 20px;
                font-size: 12px;
                font-weight: 600;
            }
            .badge-low {
                background: #dbeafe;
                color: #2563eb;
                border: 1px solid #bfdbfe;
                padding: 4px 12px;
                border-radius: 20px;
                font-size: 12px;
                font-weight: 600;
            }
            .badge-clean {
                background: #dcfce7;
                color: #16a34a;
                border: 1px solid #bbf7d0;
                padding: 4px 12px;
                border-radius: 20px;
                font-size: 12px;
                font-weight: 600;
            }

            /* Info card */
            .info-card {
                background: white;
                border: 1px solid #e0e3e8;
                border-radius: 16px;
                padding: 24px;
                margin-bottom: 20px;
                box-shadow: 0 2px 8px rgba(26, 31, 58, 0.05);
                transition: all 0.3s ease;
            }
            .info-card:hover {
                box-shadow: 0 4px 16px rgba(26, 31, 58, 0.1);
                border-color: #d0d4db;
                transform: translateY(-2px);
            }

            /* Expander */
            .streamlit-expanderHeader {
                background: white !important;
                border: 1px solid #e0e3e8 !important;
                border-radius: 10px !important;
                color: #1a1f3a !important;
                font-weight: 600 !important;
            }
            .streamlit-expanderHeader:hover {
                background: #f9fafc !important;
            }

            /* Explanation box */
            .explanation-box {
                background: #f0f6ff;
                border-left: 4px solid #0066cc;
                padding: 12px 16px;
                border-radius: 0 8px 8px 0;
                font-size: 13px;
                color: #1a1f3a;
                margin-top: 12px;
            }

            /* Dataframe */
            [data-testid="stDataFrame"] {
                border-radius: 12px;
                border: 1px solid #e0e3e8;
                box-shadow: 0 2px 8px rgba(26, 31, 58, 0.05);
            }

            /* Divider */
            hr { border-color: #e0e3e8; }

            /* Slider */
            .stSlider > div > div > div { background: #0066cc; }
            
            /* Multi-select */
            .stMultiSelect > div > div {
                background: white;
                border: 1.5px solid #e0e3e8;
                border-radius: 10px;
            }
            
            /* Select box */
            .stSelectbox > div > div {
                background: white;
                border: 1.5px solid #e0e3e8;
                border-radius: 10px;
            }
        </style>
        """
    else:
        # Dark Mode
        return """
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
                box-shadow: 0 2px 8px rgba(0, 0, 0, 0.3);
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
                box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
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
        """

# ── Theme state initialization ────────────────────────────────────────────────
if "theme" not in st.session_state:
    st.session_state.theme = "light"  # Default to light mode

# ── Custom CSS ────────────────────────────────────────────────────────────────
st.markdown(get_theme_css(st.session_state.theme == "light"), unsafe_allow_html=True)


# ── Helpers ───────────────────────────────────────────────────────────────────

def get_risk_colors(is_light: bool) -> dict:
    """Return risk colors based on theme."""
    if is_light:
        return {
            "CRITICAL": "#dc2626",
            "HIGH":     "#d97706",
            "MEDIUM":   "#f59e0b",
            "LOW":      "#2563eb",
            "CLEAN":    "#16a34a",
            "UNKNOWN":  "#6b7280",
        }
    else:
        return {
            "CRITICAL": "#ff7b72",
            "HIGH":     "#f0883e",
            "MEDIUM":   "#e3b341",
            "LOW":      "#58a6ff",
            "CLEAN":    "#3fb950",
            "UNKNOWN":  "#8b949e",
        }

RISK_COLORS = get_risk_colors(st.session_state.theme == "light")

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

def run_pipeline(github_url: str, progress_bar, status_text):
    """Runs the full CascadeGuard pipeline including new attack classification and impact analysis."""
    from ingestion.ingestion_runner import ingest
    from ingestion.github_client import parse_github_url, get_file_tree, get_file_content
    from graph.graph_builder import build_graph
    from risk.enricher import enrich_graph, export_enriched_graph, rescore_after_simulation, _build_explanation
    from simulation.simulation_runner import run_full_simulation
    from optimizer.optimizer_runner import run_optimization
    from impact.ast_scanner import scan_repository
    from impact.impact_mapper import map_impact
    from risk.narrative_generator import generate_full_narrative

    repo_name = github_url.rstrip("/").split("github.com/")[-1]

    status_text.text("📦 Step 1/8 — Fetching repository & parsing dependencies...")
    progress_bar.progress(10)
    packages = ingest(github_url)

    status_text.text("🕸️ Step 2/8 — Building dependency graph...")
    progress_bar.progress(15)
    G = build_graph(packages, repo_name=repo_name, max_depth=3)

    status_text.text("🔍 Step 3/8 — Querying vulnerability databases...")
    progress_bar.progress(30)
    G = enrich_graph(G)

    status_text.text("🎲 Step 4/8 — Running Monte Carlo simulations...")
    progress_bar.progress(50)
    results = run_full_simulation(G, n_simulations=1000)
    G = rescore_after_simulation(G, results)

    for node, data in G.nodes(data=True):
        if data.get("ecosystem") != "root":
            sim = results.get(node, {})
            G.nodes[node]["explanation"] = _build_explanation(node, data, sim)

    status_text.text("📂 Step 5/8 — Fetching source files from repository...")
    progress_bar.progress(60)
    try:
        owner, repo = parse_github_url(github_url)
        file_tree = get_file_tree(owner, repo)
        
        # Filter for source files
        extensions = {".py", ".js", ".ts", ".jsx", ".tsx"}
        excluded_dirs = {"node_modules", "vendor", ".git", "__pycache__", ".tox", "venv", ".venv",
                        "env", "dist", "build", "target", ".gradle", "examples", "test", "tests",
                        "fixtures", "docs", "doc", ".github", "site", "benchmark", "benchmarks"}
        
        source_files = {}
        for path in file_tree:
            if not any(path.endswith(ext) for ext in extensions):
                continue
            if any(part in excluded_dirs for part in path.split("/")[:-1]):
                continue
            try:
                content = get_file_content(owner, repo, path)
                source_files[path] = content
            except Exception as e:
                logger.warning(f"Failed to fetch {path}: {e}")
    except Exception as e:
        logger.warning(f"Could not fetch source files: {e}")
        source_files = {}

    status_text.text("🔎 Step 6/8 — Scanning source code for imports...")
    progress_bar.progress(70)
    if source_files:
        scan_results = scan_repository(source_files)
    else:
        scan_results = {}

    status_text.text("🎯 Step 7/8 — Mapping vulnerability impact to source files...")
    progress_bar.progress(80)
    impact_map = map_impact(G, scan_results)
    
    # Attach impact data to nodes (keys in impact_map are node IDs matching graph nodes)
    for impact_node_id, impact_data in impact_map.items():
        if impact_node_id in G.nodes():
            G.nodes[impact_node_id]["impact_data"] = impact_data

    status_text.text("📝 Step 8/8 — Generating risk narratives...")
    progress_bar.progress(90)
    narratives = []
    for node, data in G.nodes(data=True):
        if data.get("ecosystem") != "root" and data.get("risk_class") in ["CRITICAL", "HIGH"]:
            try:
                narrative = generate_full_narrative(node, data, impact_map, 
                                                   data.get("risk_score", 0), 
                                                   data.get("risk_class", ""))
                narratives.append(narrative)
                G.nodes[node]["narrative"] = narrative
            except Exception as e:
                logger.warning(f"Failed to generate narrative for {node}: {e}")

    status_text.text("⚡ Optimizing mitigation plan...")
    progress_bar.progress(95)
    export_enriched_graph(G)
    run_optimization(G, results)

    progress_bar.progress(100)
    status_text.text("✅ Analysis complete.")

    return G, results, impact_map, narratives, scan_results

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
    # Theme toggle
    col1, col2 = st.columns(2)
    with col1:
        if st.button("☀️  Light", key="light_btn", use_container_width=True):
            st.session_state.theme = "light"
            st.rerun()
    with col2:
        if st.button("🌙 Dark", key="dark_btn", use_container_width=True):
            st.session_state.theme = "dark"
            st.rerun()
    
    st.markdown("---")
    
    st.markdown("""
    <div style="padding: 8px 0 24px 0;">
        <div style="font-size:24px; font-weight:700; {% if is_light %}color:#1a1f3a;{% else %}color:#e6edf3;{% endif %}">
            🛡️ CascadeGuard
        </div>
        <div style="font-size:12px; {% if is_light %}color:#6b7280;{% else %}color:#8b949e;{% endif %} margin-top:4px;">
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
    <div style="font-size:11px; {% if is_light %}color:#6b7280;{% else %}color:#8b949e;{% endif %} line-height:1.6;">
        <b style="{% if is_light %}color:#1a1f3a;{% else %}color:#e6edf3;{% endif %}">Data sources</b><br>
        GitHub REST API<br>
        OSV Vulnerability DB<br>
        PyPI · npm · Maven Central<br><br>
        <b style="{% if is_light %}color:#1a1f3a;{% else %}color:#e6edf3;{% endif %}">Analysis</b><br>
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
if "impact_map" not in st.session_state:
    st.session_state.impact_map = {}
if "narratives" not in st.session_state:
    st.session_state.narratives = []
if "scan_results" not in st.session_state:
    st.session_state.scan_results = {}


# ── Pipeline trigger ──────────────────────────────────────────────────────────

if run_live and github_url:
    with st.spinner(""):
        progress_bar = st.progress(0)
        status_text  = st.empty()
        G, results, impact_map, narratives, scan_results = run_pipeline(github_url, progress_bar, status_text)
        st.session_state.G              = G
        st.session_state.sim_results    = results
        st.session_state.repo_name      = github_url.split("github.com/")[-1].rstrip("/")
        st.session_state.impact_map     = impact_map
        st.session_state.narratives     = narratives
        st.session_state.scan_results   = scan_results
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
        
        # Reconstruct impact_map from graph nodes
        impact_map = {}
        for node, data in G.nodes(data=True):
            if data.get("impact_data"):
                impact_map[node] = data.get("impact_data")
        st.session_state.impact_map = impact_map
        
        # Reconstruct narratives from graph nodes
        narratives = []
        for node, data in G.nodes(data=True):
            if data.get("narrative") and data.get("risk_class") in ["CRITICAL", "HIGH"]:
                narratives.append(data.get("narrative"))
        st.session_state.narratives = narratives
        
        st.success("Loaded cached results.")
    else:
        st.error("No cached results found. Run a live analysis first.")


# ── Landing screen ────────────────────────────────────────────────────────────

if st.session_state.G is None:
    is_light = st.session_state.theme == "light"
    RISK_COLORS = get_risk_colors(is_light)
    
    st.markdown(f"""
    <div style="text-align:center; padding: 80px 0 40px 0;">
        <div style="font-size:64px;">🛡️</div>
        <div style="font-size:36px; font-weight:700; color:{'#1a1f3a' if is_light else '#e6edf3'}; margin-top:16px;">
            CascadeGuard
        </div>
        <div style="font-size:18px; color:{'#6b7280' if is_light else '#8b949e'}; margin-top:8px;">
            Zero-Trust Software Supply Chain Risk Intelligence
        </div>
        <div style="font-size:14px; color:{'#6b7280' if is_light else '#8b949e'}; margin-top:24px; max-width:560px;
                    margin-left:auto; margin-right:auto; line-height:1.8;">
            Enter a GitHub repository URL in the sidebar to analyze its full
            dependency graph, detect vulnerabilities, simulate attack propagation,
            and generate an optimized mitigation plan.
        </div>
    </div>
    """, unsafe_allow_html=True)

    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown(f"""
        <div class="info-card">
            <div style="font-size:28px;">🕸️</div>
            <div style="font-weight:600; color:{'#1a1f3a' if is_light else '#e6edf3'}; margin-top:8px;">
                Graph Analysis
            </div>
            <div style="font-size:13px; color:{'#6b7280' if is_light else '#8b949e'}; margin-top:6px;">
                Builds a full dependency graph up to 3 levels deep across
                PyPI, npm, and Maven ecosystems.
            </div>
        </div>
        """, unsafe_allow_html=True)
    with c2:
        st.markdown(f"""
        <div class="info-card">
            <div style="font-size:28px;">🎲</div>
            <div style="font-weight:600; color:{'#1a1f3a' if is_light else '#e6edf3'}; margin-top:8px;">
                Monte Carlo Simulation
            </div>
            <div style="font-size:13px; color:{'#6b7280' if is_light else '#8b949e'}; margin-top:6px;">
                Runs 1000 attack propagation simulations per vulnerable node
                to estimate real-world blast radius probabilities.
            </div>
        </div>
        """, unsafe_allow_html=True)
    with c3:
        st.markdown(f"""
        <div class="info-card">
            <div style="font-size:28px;">⚡</div>
            <div style="font-weight:600; color:{'#1a1f3a' if is_light else '#e6edf3'}; margin-top:8px;">
                Smart Prioritization
            </div>
            <div style="font-size:13px; color:{'#6b7280' if is_light else '#8b949e'}; margin-top:6px;">
                Knapsack optimization selects the highest-value fixes within
                your engineering budget — not just highest CVSS.
            </div>
        </div>
        """, unsafe_allow_html=True)
    st.stop()


# ── Main dashboard ────────────────────────────────────────────────────────────

# Update risk colors based on current theme
is_light = st.session_state.theme == "light"
RISK_COLORS = get_risk_colors(is_light)

G       = st.session_state.G
results = st.session_state.sim_results or {}
df      = get_node_df(G)

# Header
st.markdown(f"""
<div style="display:flex; align-items:center; justify-content:space-between;
            padding:0 0 20px 0; border-bottom:{'2px solid #e0e3e8' if is_light else '1px solid #30363d'}; margin-bottom:24px;">
    <div>
        <div style="font-size:22px; font-weight:700; color:{'#1a1f3a' if is_light else '#e6edf3'};">
            🛡️ CascadeGuard
        </div>
        <div style="font-size:13px; color:{'#6b7280' if is_light else '#8b949e'}; margin-top:2px;">
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
tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs([
    "📊  Overview",
    "🕸️  Dependency Graph",
    "🎲  Simulation",
    "⚡  Mitigation Plan",
    "🔍  Package Details",
    "🛡️  Attack Classification",
    "💥  Module Impact",
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
            textfont=dict(color='#1a1f3a' if is_light else '#e6edf3', size=13),
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
                font=dict(color='#1a1f3a' if is_light else '#e6edf3', size=16),
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
                textfont=dict(color='#1a1f3a' if is_light else '#e6edf3', size=11),
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
                    gridcolor='#e0e3e8' if is_light else '#30363d',
                    color='#6b7280' if is_light else '#8b949e',
                    range=[0, top10["risk_score"].max() * 1.2]
                ),
                yaxis=dict(
                    color='#1a1f3a' if is_light else '#e6edf3',
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
                            color:{'#1a1f3a' if is_light else '#e6edf3'};">{label}</div>
                <div style="margin-top:12px; display:flex;
                            justify-content:space-between;">
                    <div>
                        <div style="font-size:24px; font-weight:700;
                                    color:{'#1a1f3a' if is_light else '#e6edf3'};">{len(eco_df)}</div>
                        <div style="font-size:12px;
                                    color:{'#6b7280' if is_light else '#8b949e'};">packages</div>
                    </div>
                    <div>
                        <div style="font-size:24px; font-weight:700;
                                    color:{'#dc2626' if is_light else '#ff7b72'};">{vuln_eco}</div>
                        <div style="font-size:12px;
                                    color:{'#6b7280' if is_light else '#8b949e'};">vulnerable</div>
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
            bgcolor='#f8f9fa' if is_light else '#0d1117', 
            font_color='#1a1f3a' if is_light else '#e6edf3',
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
            title = (
                f"Package: {node}\n"
                f"Version: {data.get('version','—')}\n"
                f"Risk: {rc} ({rs:.1f})\n"
                f"CVSS: {data.get('cvss_score',0)}\n"
                f"Vulns: {data.get('vuln_count',0)}\n"
                f"{'⚠ ' + data.get('explanation','') if data.get('explanation') else ''}"
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
            net.add_edge(src, tgt, color='#e0e3e8' if is_light else '#30363d', arrows="to", width=0.8)

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
            line=dict(color='#e0e3e8' if is_light else '#30363d', width=0.8), hoverinfo="none"
        ))
        fig_g.add_trace(go.Scatter(
            x=node_x, y=node_y, mode="markers+text",
            marker=dict(color=node_colors, size=10),
            text=[n.split(":")[-1] for n in G.nodes()],
            textfont=dict(color='#1a1f3a' if is_light else '#e6edf3', size=9),
            textposition="top center"
        ))
        fig_g.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor='#f8f9fa' if is_light else '#0d1117',
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
            "package":           node,
            "exposure_score":    data["exposure_score"],
            "mean_blast_radius": data["mean_blast_radius"],
            "p95_blast_radius":  data["p95_blast_radius"],
            "critical_hit_rate": data["critical_hit_rate"] * 100,
            "cvss_score":        G.nodes[node].get("cvss_score", 0),
            "risk_class":        G.nodes[node].get("risk_class", "CLEAN"),
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

        # ── Origin node selector ──────────────────────────────────────────
        st.markdown("### 🎯 Blast Radius Animator")
        st.markdown(
            f"<div style='color:{'#1a1f3a' if is_light else '#8b949e'}; font-size:13px; margin-bottom:16px;'>"
            "Select an attack origin to animate how compromise spreads "
            "through the dependency graph in real time."
            "</div>",
            unsafe_allow_html=True
        )

        origin_options = sim_df["package"].tolist()
        selected_origin = st.selectbox(
            "Attack origin node",
            origin_options,
            format_func=lambda x: f"{x.split(':')[-1]} "
                                  f"(CVSS {G.nodes[x].get('cvss_score',0):.1f}, "
                                  f"{G.nodes[x].get('risk_class','—')})"
        )

        # ── Build animated graph ──────────────────────────────────────────
        if selected_origin:
            from simulation.propagation import run_single_simulation

            sim_result = run_single_simulation(G, selected_origin, seed=42)
            path       = sim_result["propagation_path"]

            # ── KEY CHANGE: only show relevant subgraph ───────────────────
            # Include: origin + all nodes reachable from origin (descendants)
            # + direct predecessors of origin (what depends on it)
            # + nodes in propagation path
            # This keeps the graph focused and readable

            relevant_nodes = set(path)

            # Add 2-hop neighborhood of origin
            for neighbor in list(G.predecessors(selected_origin)):
                relevant_nodes.add(neighbor)
                for n2 in G.predecessors(neighbor):
                    relevant_nodes.add(n2)

            for neighbor in list(G.successors(selected_origin)):
                relevant_nodes.add(neighbor)
                for n2 in G.successors(neighbor):
                    relevant_nodes.add(n2)

            # Always include root node
            for node, data in G.nodes(data=True):
                if data.get("ecosystem") == "root":
                    relevant_nodes.add(node)

            # Cap at 60 nodes for readability
            if len(relevant_nodes) > 60:
                # Prioritize: path nodes first, then by risk score
                path_set  = set(path)
                others    = sorted(
                    relevant_nodes - path_set,
                    key=lambda n: G.nodes[n].get("risk_score", 0),
                    reverse=True
                )
                relevant_nodes = path_set | set(others[:60 - len(path_set)])

            sub_G      = G.subgraph(relevant_nodes).copy()
            sub_nodes  = list(sub_G.nodes())
            pos        = nx.spring_layout(sub_G, seed=42, k=3.0)

            node_x = [pos[n][0] for n in sub_nodes]
            node_y = [pos[n][1] for n in sub_nodes]

            def get_node_color(n, revealed_set, origin):
                if n == origin:         return "#ff4444"
                if n in revealed_set:
                    rc = G.nodes[n].get("risk_class", "CLEAN")
                    return RISK_COLORS.get(rc, "#ff7b72")
                eco = G.nodes[n].get("ecosystem", "")
                if eco == "root":       return "#58a6ff"
                return "#b0b8c1" if is_light else "#21262d"

            def get_node_size(n, revealed_set):
                base = 12 + G.nodes[n].get("pagerank", 0) * 800
                if n in revealed_set:   return min(base * 1.8, 45)
                return max(base, 10)

            # Static edges
            edge_x, edge_y = [], []
            for src, tgt in sub_G.edges():
                x0, y0 = pos[src]
                x1, y1 = pos[tgt]
                edge_x += [x0, x1, None]
                edge_y += [y0, y1, None]

            # Highlight edges IN the propagation path
            attack_edge_x, attack_edge_y = [], []
            for i in range(len(path) - 1):
                if path[i] in pos and path[i+1] in pos:
                    x0, y0 = pos[path[i]]
                    x1, y1 = pos[path[i+1]]
                    attack_edge_x += [x0, x1, None]
                    attack_edge_y += [y0, y1, None]

            edge_trace = go.Scatter(
                x=edge_x, y=edge_y, mode="lines",
                line=dict(color="#4b5563" if is_light else "#30363d", width=0.8),
                hoverinfo="none", showlegend=False
            )

            # Build frames
            frames  = []
            revealed = set()

            for step_idx, node_at_step in enumerate(path):
                if node_at_step not in sub_nodes:
                    continue
                revealed.add(node_at_step)

                # Attack edge up to this step
                atk_x, atk_y = [], []
                for i in range(min(step_idx, len(path) - 1)):
                    if path[i] in pos and path[i+1] in pos:
                        x0,y0 = pos[path[i]]
                        x1,y1 = pos[path[i+1]]
                        atk_x += [x0, x1, None]
                        atk_y += [y0, y1, None]

                atk_edge_trace = go.Scatter(
                    x=atk_x, y=atk_y, mode="lines",
                    line=dict(color="#ff4444", width=2.5,
                              dash="dot"),
                    hoverinfo="none", showlegend=False
                )

                colors    = [get_node_color(n, revealed, selected_origin)
                             for n in sub_nodes]
                sizes     = [get_node_size(n, revealed) for n in sub_nodes]
                opacities = [1.0 if n in revealed else 0.3
                             for n in sub_nodes]
                labels    = [n.split(":")[-1] if ":" in n else n
                             for n in sub_nodes]
                hover_texts = [
                    f"{n}\nRisk: {G.nodes[n].get('risk_class','—')}"
                    f"\nCVSS: {G.nodes[n].get('cvss_score',0):.1f}"
                    f"\n{G.nodes[n].get('explanation','')}"
                    for n in sub_nodes
                ]

                node_trace = go.Scatter(
                    x=node_x, y=node_y,
                    mode="markers+text",
                    marker=dict(
                        color=colors, size=sizes,
                        opacity=opacities,
                        line=dict(
                            color=["#ff4444" if n == selected_origin
                                   else "#ff7b72" if n in revealed
                                   else "#30363d"
                                   for n in sub_nodes],
                            width=[3 if n in revealed else 0.5
                                   for n in sub_nodes]
                        )
                    ),
                    text=labels,
                    textposition="top center",
                    textfont=dict(
                        color=["#ff7b72" if n in revealed
                               else "#555" for n in sub_nodes],
                        size=[11 if n in revealed else 9
                              for n in sub_nodes]
                    ),
                    hovertext=hover_texts,
                    hoverinfo="text",
                    showlegend=False
                )

                frames.append(go.Frame(
                    data=[edge_trace, atk_edge_trace, node_trace],
                    name=str(step_idx),
                    layout=go.Layout(annotations=[dict(
                        x=0.01, y=0.99,
                        xref="paper", yref="paper",
                        text=(
                            f"<b>Step {step_idx + 1}/{len(path)}</b>  "
                            f"Compromised: {len(revealed)} node(s)  "
                            f"Latest: {node_at_step.split(':')[-1]}"
                        ),
                        showarrow=False,
                        bgcolor="#161b22",
                        bordercolor="#ff4444",
                        borderwidth=1,
                        borderpad=10,
                        font=dict(color="#e6edf3", size=13),
                        align="left",
                        xanchor="left", yanchor="top"
                    )])
                ))

            if not frames:
                st.info("This node had no propagation in the seed simulation. "
                        "Try a different origin or check simulation results.")
            else:
                # Initial state
                init_colors = [get_node_color(n, {selected_origin},
                                              selected_origin)
                               for n in sub_nodes]
                init_sizes  = [get_node_size(n, {selected_origin})
                               for n in sub_nodes]
                init_node   = go.Scatter(
                    x=node_x, y=node_y,
                    mode="markers+text",
                    marker=dict(
                        color=init_colors, size=init_sizes,
                        opacity=[1.0 if n == selected_origin
                                 else 0.3 for n in sub_nodes],
                        line=dict(
                            color=["#ff4444" if n == selected_origin
                                   else "#30363d" for n in sub_nodes],
                            width=[3 if n == selected_origin
                                   else 0.5 for n in sub_nodes]
                        )
                    ),
                    text=[n.split(":")[-1] if ":" in n else n
                          for n in sub_nodes],
                    textposition="top center",
                    textfont=dict(color="#8b949e", size=9),
                    hoverinfo="none", showlegend=False
                )

                empty_atk = go.Scatter(
                    x=[], y=[], mode="lines",
                    line=dict(color="#ff4444", width=2.5, dash="dot"),
                    hoverinfo="none", showlegend=False
                )

                fig_anim = go.Figure(
                    data=[edge_trace, empty_atk, init_node],
                    frames=frames,
                    layout=go.Layout(
                        paper_bgcolor="rgba(0,0,0,0)",
                        plot_bgcolor="#0d1117",
                        xaxis=dict(showgrid=False, zeroline=False,
                                   showticklabels=False),
                        yaxis=dict(showgrid=False, zeroline=False,
                                   showticklabels=False),
                        height=580,
                        margin=dict(t=30, b=80, l=20, r=20),
                        updatemenus=[dict(
                            type="buttons",
                            showactive=False,
                            y=0.02, x=0.5,
                            xanchor="center", yanchor="bottom",
                            bgcolor="#161b22",
                            bordercolor="#30363d",
                            font=dict(color="#e6edf3", size=13),
                            buttons=[
                                dict(
                                    label="▶  Play Attack",
                                    method="animate",
                                    args=[None, dict(
                                        frame=dict(duration=700,
                                                   redraw=True),
                                        fromcurrent=True,
                                        transition=dict(
                                            duration=400,
                                            easing="cubic-in-out"
                                        )
                                    )]
                                ),
                                dict(
                                    label="⏸  Pause",
                                    method="animate",
                                    args=[[None], dict(
                                        frame=dict(duration=0,
                                                   redraw=False),
                                        mode="immediate",
                                        transition=dict(duration=0)
                                    )]
                                ),
                                dict(
                                    label="↺  Reset",
                                    method="animate",
                                    args=[["0"], dict(
                                        mode="immediate",
                                        frame=dict(duration=0,
                                                   redraw=True),
                                        transition=dict(duration=0)
                                    )]
                                )
                            ]
                        )],
                        sliders=[dict(
                            active=0,
                            currentvalue=dict(
                                prefix="Step: ",
                                font=dict(color="#8b949e", size=12)
                            ),
                            pad=dict(t=50, b=10),
                            bgcolor="#161b22",
                            bordercolor="#30363d",
                            tickcolor="#30363d",
                            font=dict(color="#8b949e"),
                            steps=[
                                dict(
                                    method="animate",
                                    args=[[str(k)], dict(
                                        mode="immediate",
                                        frame=dict(duration=300,
                                                   redraw=True),
                                        transition=dict(duration=150)
                                    )],
                                    label=str(k + 1)
                                )
                                for k in range(len(frames))
                            ]
                        )]
                    )
                )

                st.plotly_chart(fig_anim, use_container_width=True)

                # Insight callout below animation
                br = sim_result["blast_radius"]
                sim_node = results.get(selected_origin, {})
                mean_br  = sim_node.get("mean_blast_radius", 0)
                p95_br   = sim_node.get("p95_blast_radius", 0)
                crit_rate = sim_node.get("critical_hit_rate", 0)

                if br <= 2:
                    insight = (
                        f"This package has a **contained blast radius** "
                        f"in this simulation run ({br} node(s) affected). "
                        f"Across 1000 simulations the mean is "
                        f"**{mean_br:.1f} nodes** with a worst-case of "
                        f"**{p95_br} nodes**. "
                        f"{'⚠️ Critical cascade probability: '  + str(round(crit_rate*100,1)) + '%' if crit_rate > 0 else ''}"
                    )
                else:
                    insight = (
                        f"This attack propagated to **{br} nodes** "
                        f"in this simulation run. "
                        f"Across 1000 simulations the mean blast radius is "
                        f"**{mean_br:.1f} nodes** with a worst-case P95 of "
                        f"**{p95_br} nodes**."
                    )
                st.info(insight)

                s1, s2, s3, s4 = st.columns(4)
                s1.metric("This Run — Blast Radius", br)
                s2.metric("Mean (1000 runs)",
                          f"{mean_br:.1f}")
                s3.metric("P95 Worst Case", p95_br)
                s4.metric("Critical Hit Rate",
                          f"{crit_rate*100:.1f}%")

        # ── Aggregate charts ──────────────────────────────────────────────
        st.markdown("### 📊 Simulation Aggregate Results")
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
                textfont=dict(color='#1a1f3a' if is_light else '#e6edf3', size=11),
                hovertemplate=(
                    "<b>%{y}</b><br>Exposure: %{x:.1f}<extra></extra>"
                )
            ))
            fig_exp.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor ="rgba(0,0,0,0)",
                xaxis=dict(showgrid=True, gridcolor='#e0e3e8' if is_light else '#30363d',
                           color='#6b7280' if is_light else '#8b949e'),
                yaxis=dict(color='#1a1f3a' if is_light else '#e6edf3', autorange="reversed"),
                margin=dict(t=10, b=10, l=10, r=60),
                height=350,
            )
            st.plotly_chart(fig_exp, use_container_width=True)

        with c2:
            st.markdown("**Blast Radius — Mean vs P95 Worst Case**")
            fig_br = go.Figure()
            fig_br.add_trace(go.Bar(
                name="Mean",
                x=sim_df["package"].str.split(":").str[-1],
                y=sim_df["mean_blast_radius"],
                marker_color="#58a6ff",
                opacity=0.85
            ))
            fig_br.add_trace(go.Bar(
                name="P95 worst case",
                x=sim_df["package"].str.split(":").str[-1],
                y=sim_df["p95_blast_radius"],
                marker_color="#ff7b72",
                opacity=0.65
            ))
            fig_br.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor ="rgba(0,0,0,0)",
                barmode="group",
                xaxis=dict(showgrid=False, color='#6b7280' if is_light else '#8b949e',
                           tickangle=-30),
                yaxis=dict(showgrid=True, gridcolor='#e0e3e8' if is_light else '#30363d',
                           color='#6b7280' if is_light else '#8b949e',
                           title="Nodes affected"),
                legend=dict(font=dict(color='#1a1f3a' if is_light else '#e6edf3')),
                margin=dict(t=10, b=60, l=10, r=10),
                height=350,
            )
            st.plotly_chart(fig_br, use_container_width=True)

        # Scatter
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
            plot_bgcolor='#f8f9fa' if is_light else '#161b22',
            xaxis=dict(showgrid=True, gridcolor='#e0e3e8' if is_light else '#30363d',
                       color='#6b7280' if is_light else '#8b949e'),
            yaxis=dict(showgrid=True, gridcolor='#e0e3e8' if is_light else '#30363d',
                       color='#6b7280' if is_light else '#8b949e'),
            legend=dict(font=dict(color='#1a1f3a' if is_light else '#e6edf3'),
                        bgcolor="rgba(0,0,0,0)"),
            height=350,
        )
        st.plotly_chart(fig_scatter, use_container_width=True)

        # Systemic risk nodes
        sim_all = load_json("output/simulation_results.json") or {}
        summary = sim_all.get("__summary__", {})
        systemic = summary.get("systemic_risk_nodes", [])
        if systemic:
            st.markdown(
                "**Systemic Risk Nodes** "
                "*(infected in >50% of all simulations)*"
            )
            cols = st.columns(min(len(systemic), 4))
            for i, node in enumerate(systemic[:8]):
                rc = G.nodes[node].get("risk_class", "CLEAN") \
                     if node in G.nodes else "UNKNOWN"
                with cols[i % 4]:
                    st.markdown(
                        f'<div class="info-card" style="text-align:center;">'
                        f'<div style="font-size:12px; color:#e6edf3; '
                        f'font-weight:600;">'
                        f'{node.split(":")[-1]}</div>'
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
                                        color:{'#6b7280' if is_light else '#8b949e'}; min-width:28px;">
                                #{i}
                            </div>
                            <div>
                                <div style="font-weight:600; color:{'#1a1f3a' if is_light else '#e6edf3'};">
                                    {pkg_name}
                                </div>
                                <div style="font-size:12px; color:{'#6b7280' if is_light else '#8b949e'};">
                                    {node} · v{item.get('version','—')}
                                </div>
                            </div>
                        </div>
                        <div style="display:flex; gap:12px; align-items:center;">
                            {badge(rc)}
                            <div style="text-align:right;">
                                <div style="font-size:12px; color:{'#6b7280' if is_light else '#8b949e'};">
                                    CVSS</div>
                                <div style="font-weight:600;
                                            color:{RISK_COLORS.get(rc,'#6b7280' if is_light else '#8b949e')};">
                                    {item.get('cvss_score',0):.1f}
                                </div>
                            </div>
                            <div style="text-align:right;">
                                <div style="font-size:12px; color:{'#6b7280' if is_light else '#8b949e'};">
                                    Cost</div>
                                <div style="font-weight:600; color:{'#1a1f3a' if is_light else '#e6edf3'};">
                                    {item.get('cost_hours',0):.1f}h
                                </div>
                            </div>
                            <div style="text-align:right;">
                                <div style="font-size:12px;
                                            color:{'#6b7280' if is_light else '#8b949e'};">Fix version</div>
                                <div style="font-weight:600; color:{'#059669' if is_light else '#3fb950'};">
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
            plot_bgcolor='#f8f9fa' if is_light else '#161b22',
            xaxis=dict(
                title="Budget (hours)",
                showgrid=True, gridcolor='#e0e3e8' if is_light else '#30363d',
                color='#6b7280' if is_light else '#8b949e'
            ),
            yaxis=dict(
                title="Risk Reduction (%)",
                showgrid=True, gridcolor='#e0e3e8' if is_light else '#30363d',
                color='#6b7280' if is_light else '#8b949e', range=[0, 105]
            ),
            height=300,
            margin=dict(t=10, b=40, l=10, r=10),
            font=dict(color='#1a1f3a' if is_light else '#e6edf3')
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
                    
                    bg_color = "#f3f4f6" if is_light else "#1c2128"
                    border_color = "#d1d5db" if is_light else "#30363d"
                    text_gray = "#6b7280" if is_light else "#8b949e"
                    fix_color = "#059669" if is_light else "#3fb950"
                    link_color = "#2563eb" if is_light else "#58a6ff"
                    
                    st.markdown(f"""
                    <div style="background:{bg_color}; border:1px solid {border_color};
                                border-radius:8px; padding:12px 16px;
                                margin-bottom:8px;">
                        <div style="display:flex; justify-content:space-between;
                                    align-items:center;">
                            <div>
                                <span style="font-weight:600;
                                             color:{color};">
                                    {v.get('display_id','—')}
                                </span>
                                <span style="font-size:12px; color:{text_gray};
                                             margin-left:10px;">
                                    CVSS {v.get('cvss_score',0):.1f}
                                </span>
                            </div>
                            <div style="font-size:12px;">
                                <span style="color:{fix_color};">
                                    Fix: {fix}
                                </span>
                                <a href="{v.get('detail_url','#')}"
                                   target="_blank"
                                   style="color:{link_color}; margin-left:12px;
                                          text-decoration:none;">
                                    View ↗
                                </a>
                            </div>
                        </div>
                        <div style="font-size:13px; color:{text_gray}; margin-top:6px;">
                            {v.get('summary','—')}
                        </div>
                    </div>
                    """, unsafe_allow_html=True)
            else:
                clean_color = "#059669" if is_light else "#3fb950"
                st.markdown(
                    f'<div style="color:{clean_color}; font-size:13px;">'
                    '✅ No known vulnerabilities</div>',
                    unsafe_allow_html=True
                )

with tab6:
    st.markdown('<div class="section-header">🛡️ Attack Classification</div>',
                unsafe_allow_html=True)

    if st.session_state.G is None:
        st.info("⚠️ Run the pipeline first to analyze attack patterns.")
    else:
        # Get unique packages with attack classifications
        attack_packages = []
        for node in st.session_state.G.nodes():
            if st.session_state.G.nodes[node].get("attack_classification"):
                package_name = node.split(":")[1] if ":" in node else node
                attack_packages.append({
                    "node": node,
                    "package": package_name,
                    "display_name": f"{package_name} ({node.split(':')[0].upper()})" if ":" in node else package_name,
                    "attack_info": st.session_state.G.nodes[node]["attack_classification"]
                })

        if not attack_packages:
            st.info("No attack classifications available.")
        else:
            # Package selector - show both package name and ecosystem
            package_options = [p["package"] for p in attack_packages]
            display_names = [p["display_name"] for p in attack_packages]
            
            selected_pkg_idx = st.selectbox(
                "Select a package to view attack details:",
                options=range(len(attack_packages)),
                format_func=lambda i: display_names[i]
            )

            if 0 <= selected_pkg_idx < len(attack_packages):
                p = attack_packages[selected_pkg_idx]
                pkg_node = p["node"]
                attack_info = p["attack_info"]

                if pkg_node and attack_info:
                    # Display attack information
                    ac1, ac2, ac3 = st.columns(3)
                    with ac1:
                        primary_attack = attack_info.get("primary_attack_type", attack_info.get("primary_attack", "Unknown"))
                        st.markdown(f"""
                        <div class="metric-card">
                            <div style="font-size:12px; color:#8b949e; font-weight:600;">
                                PRIMARY ATTACK TYPE
                            </div>
                            <div style="font-size:18px; font-weight:700; color:#f85149; margin-top:8px;">
                                {primary_attack if primary_attack != "Unknown Attack Type" else "No CWE Match"}
                            </div>
                        </div>
                        """, unsafe_allow_html=True)

                    with ac2:
                        attacker_cap = attack_info.get("attacker_capability", "Unknown")
                        st.markdown(f"""
                        <div class="metric-card">
                            <div style="font-size:12px; color:#8b949e; font-weight:600;">
                                ATTACKER CAPABILITY
                            </div>
                            <div style="font-size:14px; font-weight:700; margin-top:8px; word-wrap:break-word;">
                                {attacker_cap}
                            </div>
                        </div>
                        """, unsafe_allow_html=True)

                    with ac3:
                        num_cwes = len(attack_info.get("cwe_ids", []))
                        st.markdown(f"""
                        <div class="metric-card">
                            <div style="font-size:12px; color:#8b949e; font-weight:600;">
                                RELATED CWEs
                            </div>
                            <div style="font-size:20px; font-weight:700; color:#79c0ff; margin-top:8px;">
                                {num_cwes}
                            </div>
                        </div>
                        """, unsafe_allow_html=True)

                    st.markdown("---")

                    # Display CWE details
                    if attack_info.get("cwe_ids"):
                        st.markdown("**Related CWE Vulnerabilities**")
                        cwe_descriptions = attack_info.get("cwe_descriptions", {})
                        for cwe_id in attack_info.get("cwe_ids", []):
                            cwe_description = cwe_descriptions.get(cwe_id, "No description")
                            st.markdown(f"""
                            <div style="background:#0d1117; border:1px solid #30363d; border-radius:6px;
                                        padding:12px; margin-bottom:8px;">
                                <span style="font-weight:600; color:#79c0ff;">{cwe_id}</span>
                                <div style="font-size:13px; color:#8b949e; margin-top:4px;">
                                    {cwe_description}
                                </div>
                            </div>
                            """, unsafe_allow_html=True)
                        st.markdown("---")

                    # Display narrative
                    st.markdown("**Attack Narrative**")
                    narrative_text = attack_info.get("narrative", "No narrative available")
                    st.markdown(f"""
                    <div style="background:#161b22; border-left:4px solid #f85149; padding:12px;
                                border-radius:4px; margin-top:8px;">
                        <div style="font-size:14px; line-height:1.6; color:#e6edf3;">
                            {narrative_text}
                        </div>
                    </div>
                    """, unsafe_allow_html=True)

with tab7:
    st.markdown('<div class="section-header">💥 Module Impact Analysis</div>',
                unsafe_allow_html=True)

    impact_map = st.session_state.get("impact_map", {})

    if not impact_map:
        st.info("⚠️ Run the pipeline first to analyze module impact.")
    else:
        # Get unique packages with impact data
        impact_packages = []
        for node_id, impact_data in impact_map.items():
            package_name = node_id.split(":")[1] if ":" in node_id else node_id
            impact_packages.append({
                "node_id": node_id,
                "package": package_name,
                "display_name": f"{package_name} ({node_id.split(':')[0].upper()})" if ":" in node_id else package_name,
                "impact_data": impact_data
            })

        if not impact_packages:
            st.info("No module impact data available.")
        else:
            # Package selector - show both package name and ecosystem
            display_names = [p["display_name"] for p in impact_packages]
            
            selected_impact_idx = st.selectbox(
                "Select a vulnerable package to view impact:",
                options=range(len(impact_packages)),
                format_func=lambda i: display_names[i]
            )

            if 0 <= selected_impact_idx < len(impact_packages):
                p = impact_packages[selected_impact_idx]
                selected_impact_pkg = p["node_id"]
                impact_data = p["impact_data"]

                if selected_impact_pkg in impact_map:
                    # Overview metrics
                    im1, im2, im3, im4 = st.columns(4)
                    with im1:
                        affected_files = len(impact_data.get("affected_files", []))
                        st.markdown(f"""
                        <div class="metric-card">
                            <div style="font-size:12px; color:#8b949e; font-weight:600;">
                                AFFECTED FILES
                            </div>
                            <div style="font-size:20px; font-weight:700; color:#79c0ff; margin-top:8px;">
                                {affected_files}
                            </div>
                        </div>
                        """, unsafe_allow_html=True)

                    with im2:
                        entry_points = len(impact_data.get("entry_points", []))
                        st.markdown(f"""
                        <div class="metric-card">
                            <div style="font-size:12px; color:#8b949e; font-weight:600;">
                                ENTRY POINTS
                            </div>
                            <div style="font-size:20px; font-weight:700; color:#f85149; margin-top:8px;">
                                {entry_points}
                            </div>
                        </div>
                        """, unsafe_allow_html=True)

                    with im3:
                        features = len(impact_data.get("features", []))
                        st.markdown(f"""
                        <div class="metric-card">
                            <div style="font-size:12px; color:#8b949e; font-weight:600;">
                                FEATURES AT RISK
                            </div>
                            <div style="font-size:20px; font-weight:700; color:#d29922; margin-top:8px;">
                                {features}
                            </div>
                        </div>
                        """, unsafe_allow_html=True)

                    with im4:
                        exposure = impact_data.get("exposure_scope", "MEDIUM")
                        exposure_color = {"HIGH": "#f85149", "MEDIUM": "#d29922", "LOW": "#3fb950"}.get(exposure, "#8b949e")
                        st.markdown(f"""
                        <div class="metric-card">
                            <div style="font-size:12px; color:#8b949e; font-weight:600;">
                                EXPOSURE SCOPE
                            </div>
                            <div style="font-size:18px; font-weight:700; color:{exposure_color}; margin-top:8px;">
                                {exposure}
                            </div>
                        </div>
                        """, unsafe_allow_html=True)

                    st.markdown("---")

                    # Display affected files
                    if impact_data.get("affected_files"):
                        st.markdown("**Affected Source Files**")
                        file_list = impact_data.get("affected_files", [])
                        
                        # Categorize files
                        for file_path in file_list:
                            is_entry = "⚡" if file_path in impact_data.get("entry_points", []) else "📄"
                            st.markdown(f"{is_entry} `{file_path}`")

                    st.markdown("---")

                    # Display entry points
                    if impact_data.get("entry_points"):
                        st.markdown("**Entry Points (Direct API surface)**")
                        for ep in impact_data.get("entry_points", []):
                            st.markdown(f"""
                            <div style="background:#16213e; border:1px solid #30363d; border-radius:6px;
                                        padding:10px; margin-bottom:6px;">
                                <span style="font-weight:600; color:#79c0ff;">⚡</span>
                                <code style="margin-left:6px; color:#e6edf3;">{ep}</code>
                            </div>
                            """, unsafe_allow_html=True)

                    st.markdown("---")

                    # Display features
                    if impact_data.get("features"):
                        st.markdown("**Inferred Features at Risk**")
                        features_list = impact_data.get("features", [])
                        
                        # Create feature badges
                        feature_cols = st.columns(3)
                        for idx, feature in enumerate(features_list):
                            with feature_cols[idx % 3]:
                                feature_icons = {
                                    "Authentication": "🔐",
                                    "Payment": "💳",
                                    "File Upload": "📤",
                                    "API Gateway": "🌐",
                                    "Admin Panel": "⚙️",
                                    "Email": "📧",
                                    "Search": "🔍",
                                    "User Management": "👥",
                                    "Job Queue": "📋",
                                    "Reporting": "📊"
                                }
                                icon = feature_icons.get(feature, "🏷️")
                                st.markdown(f"""
                                <div style="background:#0d1117; border:1px solid #30363d;
                                            border-radius:6px; padding:12px; text-align:center;
                                            margin-bottom:8px;">
                                    <div style="font-size:24px;">{icon}</div>
                                    <div style="font-size:12px; font-weight:600; color:#e6edf3;
                                                margin-top:6px;">{feature}</div>
                                </div>
                                """, unsafe_allow_html=True)