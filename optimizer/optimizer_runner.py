import json
import os
import networkx as nx
from optimizer.cost_estimator import estimate_fix_cost, estimate_fix_benefit
from optimizer.knapsack import knapsack_optimize


# Default budgets to evaluate — gives judges multiple scenarios
DEFAULT_BUDGETS = [8, 16, 24, 40]  # hours


def run_optimization(
    G: nx.DiGraph,
    simulation_results: dict,
    budgets: list = None,
    output_path: str = "output/mitigation_plan.json"
) -> dict:
    """
    Main entry point for Module 5.

    Builds a cost/benefit profile for every vulnerable package,
    then runs the knapsack optimizer across multiple budget scenarios.

    Args:
        G:                  enriched + simulated graph
        simulation_results: output from Module 4
        budgets:            list of hour budgets to evaluate
        output_path:        where to save the mitigation plan

    Returns:
        Full mitigation plan dict
    """
    if budgets is None:
        budgets = DEFAULT_BUDGETS

    print(f"\n[optimizer] Building cost/benefit profiles...")

    # Build item list from all vulnerable nodes
    items = []
    for node, data in G.nodes(data=True):
        if data.get("cvss_score", 0.0) == 0:
            continue
        if data.get("ecosystem") == "root":
            continue

        cost    = estimate_fix_cost(node, data, G)
        benefit = estimate_fix_benefit(node, data)

        # Pull in simulation results if available
        sim = simulation_results.get(node, {})

        items.append({
            "node":           node,
            "cost_hours":     cost,
            "benefit":        benefit,
            "cvss_score":     data.get("cvss_score", 0.0),
            "risk_score":     data.get("risk_score", 0.0),
            "risk_class":     data.get("risk_class", "UNKNOWN"),
            "exposure_score": data.get("exposure_score",
                              sim.get("exposure_score", 0.0)),
            "mean_blast_radius": data.get("mean_blast_radius",
                                 sim.get("mean_blast_radius", 0.0)),
            "fix_available":  data.get("fix_available", False),
            "ecosystem":      data.get("ecosystem", ""),
            "version":        data.get("version", "unspecified"),
            "vuln_count":     data.get("vuln_count", 0),
            "fixed_in":       _get_fixed_version(data),
        })

    # Sort by benefit/cost ratio for display purposes
    items.sort(key=lambda x: x["benefit"] / max(x["cost_hours"], 0.1),
               reverse=True)

    print(f"[optimizer] {len(items)} vulnerable packages to optimize")
    print(f"[optimizer] Running knapsack for budgets: {budgets} hours\n")

    # Run optimizer for each budget scenario
    budget_plans = {}
    for budget in budgets:
        result = knapsack_optimize(items, budget)
        budget_plans[budget] = result
        print(f"[optimizer] Budget {budget:>3}h → "
              f"fixes {len(result['selected_fixes']):>2} packages, "
              f"uses {result['total_cost']:>5.1f}h, "
              f"covers {result['risk_reduction_pct']:>5.1f}% of risk")

    # Build full plan
    plan = {
        "total_vulnerable_packages": len(items),
        "all_items_ranked":          items,
        "budget_scenarios":          budget_plans,
    }

    # Save
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(plan, f, indent=2)
    print(f"\n[optimizer] Mitigation plan saved to {output_path}")

    # Print the most useful scenario — 40h budget
    _print_mitigation_report(budget_plans, items, recommended_budget=40)

    return plan


def _print_mitigation_report(
    budget_plans: dict,
    all_items: list,
    recommended_budget: int = 40
):
    """Prints a human-readable mitigation plan for the recommended budget."""
    plan = budget_plans.get(recommended_budget, list(budget_plans.values())[-1])
    selected = plan["selected_fixes"]

    print(f"\n[optimizer] ── Mitigation Plan ({recommended_budget}h budget) ──────────────")
    print(f"  Packages to fix:    {len(selected)}")
    print(f"  Hours required:     {plan['total_cost']}h")
    print(f"  Hours remaining:    {plan['remaining_budget']}h")
    print(f"  Risk reduction:     {plan['risk_reduction_pct']}%")
    print()
    print(f"  {'#':<3} {'Package':<38} {'Class':<10} {'CVSS':>5} "
          f"{'Cost':>5} {'Benefit':>8} {'Fix Version'}")
    print(f"  {'─'*3} {'─'*38} {'─'*10} {'─'*5} {'─'*5} {'─'*8} {'─'*15}")

    for i, item in enumerate(selected, 1):
        fix_ver = item.get("fixed_in") or "unknown"
        print(
            f"  {i:<3} "
            f"{item['node']:<38} "
            f"{item['risk_class']:<10} "
            f"{item['cvss_score']:>5.1f} "
            f"{item['cost_hours']:>5.1f}h "
            f"{item['benefit']:>8.1f} "
            f"{fix_ver}"
        )

    print(f"\n  Unaddressed ({len(plan['unaddressed_fixes'])}) — "
          f"insufficient budget or no fix available:")
    for item in plan["unaddressed_fixes"][:5]:
        tag = "(no fix)" if not item["fix_available"] else ""
        print(f"    → {item['node']} {tag}")
    if len(plan["unaddressed_fixes"]) > 5:
        print(f"    → ... and {len(plan['unaddressed_fixes']) - 5} more")
    print()


def _get_fixed_version(data: dict) -> str | None:
    """Gets the fixed version from vulnerability records."""
    for v in data.get("vulnerabilities", []):
        if v.get("fixed_in"):
            return v["fixed_in"]
    return None