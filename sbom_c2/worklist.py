"""
The fix worklist  (Capstone 2, Objective 4).

This replaces the NDCG ranking-quality evaluation. That measurement answered a
question a research reviewer asks -- is this ordering statistically better than
that ordering -- and a developer deciding what to fix on a Monday morning does
not ask it. Presenting two competing scores and a rank-correlation statistic
obscures the decision rather than supporting it.

What a developer actually needs is a short list, in order, with a reason for
each position stated in business terms: this one first, because it sits on the
payment service, which is in PCI-DSS scope, and no fix exists yet.

So the worklist orders by business consequence and explains each position in
one sentence. The technical score is retained on the record and shown as
supporting detail, not as a competing ranking.
"""

import logging

log = logging.getLogger("sbom_c2.worklist")

DEFAULT_SIZE = 10

# What makes one finding more urgent than another, in the order a developer
# would reason about it. Confirmed exploitation first because it removes the
# question; then whether a fix exists, because that decides whether this is an
# upgrade or a mitigation; then business consequence.
REASON_TEMPLATES = {
    "exploited": "Confirmed exploited in the wild. Fix this before anything "
                 "else on the list.",
    "revenue_unpatchable": "Sits on {process}, a revenue-critical process, and "
                           "has no available fix. Needs compensating controls "
                           "today, not a patch.",
    "regulated_unpatchable": "Sits on {process}, which is in {regimes} scope, "
                             "and cannot be patched yet. Needs a recorded "
                             "decision.",
    "revenue": "Sits on {process}, a revenue-critical process. A fix exists, "
               "so upgrade.",
    "regulated": "Sits on {process}, in {regimes} scope. A fix exists, so "
                 "upgrade.",
    "customer_facing": "Sits on {process}, which is customer-facing.",
    "unpatchable": "No fix is available yet, so this needs mitigation rather "
                   "than an upgrade.",
    "internal": "Supports {process}, an internal process with no revenue or "
                "regulatory exposure. Schedule it.",
    "unmapped": "This repository is not mapped to any business process, so its "
                "consequence is unknown rather than low. Map it to rank it "
                "properly.",
}


def _classify(processes, patch_available, exploited):
    """Pick the single reason that best explains this finding's position."""
    if exploited:
        return "exploited", {}

    if not processes:
        return "unmapped", {}

    revenue = [p for p in processes if p.get("revenue_dependency") == "direct"]
    regulated = [p for p in processes if p.get("regulatory_scope")]
    customer = [p for p in processes if p.get("customer_facing")]

    if revenue and not patch_available:
        return "revenue_unpatchable", {"process": revenue[0]["name"]}
    if regulated and not patch_available:
        return "regulated_unpatchable", {
            "process": regulated[0]["name"],
            "regimes": regulated[0].get("regulatory_scope", "regulatory")}
    if revenue:
        return "revenue", {"process": revenue[0]["name"]}
    if regulated:
        return "regulated", {
            "process": regulated[0]["name"],
            "regimes": regulated[0].get("regulatory_scope", "regulatory")}
    if customer:
        return "customer_facing", {"process": customer[0]["name"]}
    if not patch_available:
        return "unpatchable", {}
    return "internal", {"process": processes[0]["name"]}


# Rank weight per reason. Deliberately coarse: a developer needs a defensible
# order, not a score to three decimal places, and fine-grained weights invite
# arguments about the third decimal instead of about the decision.
REASON_RANK = {
    "exploited": 0,
    "revenue_unpatchable": 1,
    "regulated_unpatchable": 2,
    "revenue": 3,
    "regulated": 4,
    "customer_facing": 5,
    "unpatchable": 6,
    "unmapped": 7,
    "internal": 8,
}


def build(items, size=DEFAULT_SIZE):
    """
    Order findings into a fix worklist.

    `items` are dicts carrying at least: repository, component, version,
    identifier, processes (list of process attribute dicts), patch_available,
    exploited, and optionally score and upgrade_target.

    Returns the ordered list, each entry carrying `position`, `reason` and
    `reason_code`, plus a short summary for the panel header.
    """
    ranked = []
    for item in items:
        processes = item.get("processes") or []
        code, fields = _classify(processes, item.get("patch_available"),
                                 item.get("exploited"))
        ranked.append(dict(
            item,
            reason_code=code,
            reason=REASON_TEMPLATES[code].format(**fields) if fields
            else REASON_TEMPLATES[code],
            _rank=REASON_RANK[code],
        ))

    # Reason first, then technical score as the tie-break within a reason --
    # so two findings on the same payment service are separated by severity,
    # but severity never lifts an internal utility above a payment service.
    ranked.sort(key=lambda r: (r["_rank"], -(r.get("score") or 0.0)))

    out = []
    for position, row in enumerate(ranked[:size], 1):
        row.pop("_rank", None)
        row["position"] = position
        out.append(row)

    return out, _summary(ranked, out)


def _summary(all_ranked, shown):
    unpatchable = sum(1 for r in all_ranked if not r.get("patch_available"))
    exploited = sum(1 for r in all_ranked if r.get("exploited"))
    unmapped = sum(1 for r in all_ranked if r.get("reason_code") == "unmapped")
    return {
        "total_candidates": len(all_ranked),
        "shown": len(shown),
        "exploited": exploited,
        "unpatchable": unpatchable,
        "unmapped_repositories": unmapped,
        "how_to_read": "Ordered by business consequence, not by CVSS. Work "
                       "down the list: each position states why it sits where "
                       "it does. The technical score is shown as supporting "
                       "detail only.",
    }
