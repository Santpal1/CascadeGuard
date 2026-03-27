def knapsack_optimize(items: list, budget_hours: float) -> dict:
    """
    Solves the 0/1 Knapsack problem to find the optimal set of fixes
    within a given engineering budget.

    Args:
        items: list of dicts, each with:
               {node, cost_hours, benefit, risk_score, cvss_score,
                risk_class, fix_available, ecosystem, version}
        budget_hours: total engineering hours available

    Returns:
        {
            "selected_fixes":      list of selected item dicts,
            "total_cost":          float (hours used),
            "total_benefit":       float (risk reduction achieved),
            "remaining_budget":    float (hours left over),
            "risk_reduction_pct":  float (% of total risk addressed),
            "unaddressed_fixes":   list of items not selected
        }
    """
    if not items or budget_hours <= 0:
        return _empty_result(items)

    # Convert hours to integer units (multiply by 10 for 0.1h precision)
    scale     = 10
    W         = int(budget_hours * scale)
    n         = len(items)
    weights   = [max(1, int(round(item["cost_hours"] * scale))) for item in items]
    values    = [item["benefit"] for item in items]

    # ── Dynamic Programming Table ──────────────────────────────────────
    # dp[i][w] = max benefit using first i items with weight capacity w
    # We use a 1D rolling array to save memory
    dp = [0.0] * (W + 1)

    for i in range(n):
        w_i = weights[i]
        v_i = values[i]
        # Traverse backwards to prevent using same item twice (0/1 knapsack)
        for w in range(W, w_i - 1, -1):
            dp[w] = max(dp[w], dp[w - w_i] + v_i)

    # ── Backtrack to find selected items ──────────────────────────────
    selected_indices = []
    w = W
    for i in range(n - 1, -1, -1):
        w_i = weights[i]
        v_i = values[i]
        if w >= w_i and abs(dp[w] - dp[w - w_i] - v_i) < 1e-6:
            selected_indices.append(i)
            w -= w_i

    selected_indices.reverse()  # restore original order

    selected = [items[i] for i in selected_indices]
    unselected = [items[i] for i in range(n) if i not in set(selected_indices)]

    total_cost    = sum(item["cost_hours"] for item in selected)
    total_benefit = sum(item["benefit"] for item in selected)
    total_all     = sum(item["benefit"] for item in items)

    risk_reduction_pct = (
        (total_benefit / total_all * 100) if total_all > 0 else 0.0
    )

    return {
        "selected_fixes":     selected,
        "total_cost":         round(total_cost, 2),
        "total_benefit":      round(total_benefit, 2),
        "remaining_budget":   round(budget_hours - total_cost, 2),
        "risk_reduction_pct": round(risk_reduction_pct, 1),
        "unaddressed_fixes":  unselected,
    }


def _empty_result(items: list) -> dict:
    return {
        "selected_fixes":     [],
        "total_cost":         0.0,
        "total_benefit":      0.0,
        "remaining_budget":   0.0,
        "risk_reduction_pct": 0.0,
        "unaddressed_fixes":  items,
    }