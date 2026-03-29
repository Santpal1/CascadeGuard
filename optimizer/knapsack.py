def knapsack_optimize(items: list, budget_hours: float) -> dict:
    """
    Solves 0/1 Knapsack for optimal fix selection within budget.
    Uses integer scaling (×10) for precision with float hour values.
    """
    if not items or budget_hours <= 0:
        return _empty_result(items)

    scale   = 10
    W       = int(round(budget_hours * scale))
    n       = len(items)
    weights = [max(1, int(round(item["cost_hours"] * scale))) for item in items]
    values  = [item["benefit"] for item in items]

    # Debug — uncomment if budget issues recur
    # print(f"[knapsack] W={W}, weights={weights}, budget={budget_hours}")

    # ── DP table (2D for reliable backtracking) ────────────────────────
    # dp[i][w] = max benefit using first i items with capacity w
    dp = [[0.0] * (W + 1) for _ in range(n + 1)]

    for i in range(1, n + 1):
        w_i = weights[i - 1]
        v_i = values[i - 1]
        for w in range(W + 1):
            # Don't take item i
            dp[i][w] = dp[i - 1][w]
            # Take item i if it fits
            if w >= w_i:
                dp[i][w] = max(dp[i][w], dp[i - 1][w - w_i] + v_i)

    # ── Backtrack to find which items were selected ────────────────────
    selected_indices = []
    w = W
    for i in range(n, 0, -1):
        # If value changed from row above, item i was selected
        if dp[i][w] != dp[i - 1][w]:
            selected_indices.append(i - 1)  # convert to 0-indexed
            w -= weights[i - 1]
            if w <= 0:
                break

    selected_indices.reverse()

    selected   = [items[i] for i in selected_indices]
    unselected = [items[i] for i in range(n)
                  if i not in set(selected_indices)]

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