"""
Ranking-quality evaluation (Capstone 2 - Phase 6 / Objective 4).

Compares the business-aware ranking against the Capstone 1 technical-only
ranking, scored on a business-annotated ground-truth ordering using Normalised
Discounted Cumulative Gain.

NDCG is the right measure here because the claim is specifically about *order*:
both systems surface the same findings, so precision and recall cannot separate
them. What differs is which findings land at the top of the queue, and NDCG
rewards exactly that, discounting gain logarithmically by position.
"""

import math


def dcg(relevances):
    """Discounted cumulative gain, using the 2^rel - 1 gain formulation."""
    return sum(
        (2 ** rel - 1) / math.log2(i + 2) for i, rel in enumerate(relevances)
    )


def ndcg(ranked_ids, relevance, k=None):
    """
    ranked_ids: finding ids in the order the system presents them
    relevance:  {finding_id: graded relevance} from the ground truth,
                typically 0-3 (0 = ignore, 3 = fix first)
    k:          cut-off; None scores the whole list

    Returns a float in [0, 1]. 1.0 means the system ordered the queue exactly
    as the business-annotated ground truth would.
    """
    if not ranked_ids:
        return 0.0
    cut = len(ranked_ids) if k is None else min(k, len(ranked_ids))

    actual = [relevance.get(fid, 0) for fid in ranked_ids[:cut]]
    ideal = sorted(relevance.values(), reverse=True)[:cut]

    ideal_dcg = dcg(ideal)
    if ideal_dcg == 0:
        return 0.0
    return round(dcg(actual) / ideal_dcg, 4)


def rank_by(findings, score_key):
    """Order findings by a score field, highest first, id as tie-breaker."""
    return [
        f["id"]
        for f in sorted(
            findings, key=lambda f: (-(f.get(score_key) or 0), str(f.get("id")))
        )
    ]


def compare_rankings(findings, relevance, k=None):
    """
    Score both rankings and report the delta.

    `findings` must carry: id, business_score, baseline_score.
    `relevance` is the business-annotated ground truth.
    """
    business = rank_by(findings, "business_score")
    baseline = rank_by(findings, "baseline_score")

    business_ndcg = ndcg(business, relevance, k)
    baseline_ndcg = ndcg(baseline, relevance, k)
    delta = round(business_ndcg - baseline_ndcg, 4)
    improvement = (
        round((delta / baseline_ndcg) * 100, 2) if baseline_ndcg else None
    )

    return {
        "k": k or len(findings),
        "n_findings": len(findings),
        "ndcg_business_aware": business_ndcg,
        "ndcg_technical_only": baseline_ndcg,
        "delta": delta,
        "relative_improvement_pct": improvement,
        "business_ranking": business,
        "baseline_ranking": baseline,
    }


def precision_at_k(ranked_ids, relevance, k, threshold=2):
    """
    Share of the top k that the business considers genuinely worth fixing.

    A blunter companion to NDCG, and easier to state in a viva: "of the ten
    findings the system puts in front of you, how many actually mattered".
    """
    if k <= 0 or not ranked_ids:
        return 0.0
    top = ranked_ids[:k]
    hits = sum(1 for fid in top if relevance.get(fid, 0) >= threshold)
    return round(hits / len(top), 4)
