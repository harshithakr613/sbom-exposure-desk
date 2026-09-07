#!/usr/bin/env python3
"""
Ranking evaluation for Capstone 2, Objective 4.

Compares the business-aware ordering against the Capstone 1 technical-only
ordering, using Normalised Discounted Cumulative Gain against a ground truth
graded by hand, and reports a sensitivity analysis over the criticality weight.

    python scripts/evaluate_ranking.py --worksheet
        Writes ground_truth_worksheet.csv. Grade the relevance column, then:

    python scripts/evaluate_ranking.py --import ground_truth_worksheet.csv
        Reads the grades into ground_truth.json.

    python scripts/evaluate_ranking.py --run
        Computes NDCG, precision at k and the sensitivity analysis, and prints
        the figures needed for the report.

WHY THE WORKSHEET IS POOLED
---------------------------
There are far more findings than anyone can grade by hand, and grading only the
business-aware top twenty would bias the result in its own favour. The worksheet
therefore contains the UNION of the top k from each ranking, which is the
standard pooling method in information retrieval evaluation. It is sound because
findings outside the pool appear in neither ranking's top k and so cannot affect
the comparison at that cut-off.

WHY THE WORKSHEET HIDES THE SCORES
----------------------------------
If the grader can see what the model decided, the grading stops being
independent and the evaluation becomes an exercise in agreeing with yourself.
The worksheet shows the repository, the business process, the component and the
advisory, and nothing else. Grade it before running --run.
"""

import argparse
import csv
import json
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sbom_c2 import bia, evaluate, pipeline                  # noqa: E402
from sbom_c2.db import SessionLocal, init_db                 # noqa: E402
from sbom_c2.models import Exposure, Repository              # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORKSHEET = os.path.join(ROOT, "ground_truth_worksheet.csv")
TRUTH = os.path.join(ROOT, "ground_truth.json")

POOL_DEPTH = 20
RULE = "=" * 78


def heading(text):
    print("\n" + RULE)
    print(text)
    print(RULE)


def open_findings(session):
    rows = (session.query(Exposure)
            .filter(Exposure.state == "open")
            .filter(Exposure.business_score.isnot(None))
            .filter(Exposure.baseline_score.isnot(None)).all())
    # One finding per (repository, component, version, advisory identity), so a
    # CVE published under two advisory ids is graded once rather than twice.
    seen, unique = set(), []
    for e in rows:
        key = (e.repository_id, (e.component_name or "").lower(),
               e.component_version, e.cve_id or e.advisory_id)
        if key in seen:
            continue
        seen.add(key)
        unique.append(e)
    return unique


def build_pool(findings, depth=POOL_DEPTH):
    """Union of the top `depth` from each ranking."""
    by_business = sorted(findings, key=lambda e: -(e.business_score or 0))[:depth]
    by_technical = sorted(findings, key=lambda e: -(e.baseline_score or 0))[:depth]
    pool, seen = [], set()
    for e in by_business + by_technical:
        if e.id not in seen:
            seen.add(e.id)
            pool.append(e)
    return pool, by_business, by_technical


# ---------------------------------------------------------------------------
# Worksheet
# ---------------------------------------------------------------------------

def export(depth):
    init_db()
    session = SessionLocal()
    findings = open_findings(session)
    if not findings:
        sys.exit("No scored open findings. Run a scan and seed business context "
                 "first.")

    pool, by_business, by_technical = build_pool(findings, depth)

    # Shuffled, so the order of the worksheet carries no signal about either
    # ranking. A grader working down a list already sorted by the model would be
    # anchored by it.
    random.seed(20260912)
    random.shuffle(pool)

    context = {}
    for e in pool:
        repo = session.get(Repository, e.repository_id)
        processes, regimes = pipeline.repository_business_context(session, repo)
        context[e.id] = (repo, processes, regimes)

    with open(WORKSHEET, "w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["id", "repository", "business_process",
                         "regulatory_scope", "component", "version", "advisory",
                         "dependency", "relevance"])
        for e in pool:
            repo, processes, regimes = context[e.id]
            writer.writerow([
                e.id,
                repo.full_name if repo else "",
                "; ".join(p.name for p in processes) or "NOT MAPPED",
                ",".join(regimes),
                e.component_name,
                e.component_version or "unresolved",
                e.cve_id or e.advisory_id,
                "direct" if e.direct else "transitive",
                "",
            ])

    print("Wrote %s" % WORKSHEET)
    print("  %d findings in the pool" % len(pool))
    print("     top %d by business-aware score" % len(by_business))
    print("     top %d by technical score" % len(by_technical))
    print("     %d appear in both" % (len(by_business) + len(by_technical)
                                      - len(pool)))
    print("\nGrade the 'relevance' column 0-3:")
    print("  3  fix first  \u2014 severe, and the affected service matters")
    print("  2  fix soon   \u2014 important service, or high technical severity")
    print("  1  scheduled  \u2014 limited business consequence")
    print("  0  ignore     \u2014 no meaningful business consequence")
    print("\nGrade on what the finding would COST if left unfixed. The scores are")
    print("deliberately absent so your judgement is independent of the model's.")
    print("\nThen:  python scripts/evaluate_ranking.py --import %s"
          % os.path.basename(WORKSHEET))
    session.close()


def import_grades(path):
    truth, blank = {}, 0
    with open(path, newline="") as handle:
        for row in csv.DictReader(handle):
            value = (row.get("relevance") or "").strip()
            if value == "":
                blank += 1
                continue
            try:
                grade = int(value)
            except ValueError:
                sys.exit("Row %s has relevance '%s', which is not 0-3."
                         % (row.get("id"), value))
            if grade not in (0, 1, 2, 3):
                sys.exit("Row %s has relevance %d; the scale is 0-3."
                         % (row.get("id"), grade))
            truth[str(row["id"])] = grade

    if not truth:
        sys.exit("No graded rows found. Fill in the relevance column first.")
    if blank:
        print("WARNING: %d rows are still blank and will be excluded. Ungraded "
              "findings are treated as outside the pool, not as zero." % blank)

    spread = sorted(set(truth.values()))
    if len(spread) == 1:
        print("WARNING: every finding was graded %d. NDCG cannot distinguish "
              "two rankings when the ground truth is uniform." % spread[0])

    with open(TRUTH, "w") as handle:
        json.dump(truth, handle, indent=2)
    print("Wrote %s with %d graded findings (grades used: %s)"
          % (TRUTH, len(truth), ", ".join(str(g) for g in spread)))
    print("Now:  python scripts/evaluate_ranking.py --run")


# ---------------------------------------------------------------------------
# Sensitivity analysis
# ---------------------------------------------------------------------------

def factors(exposure):
    """
    Recover the normalised factor values from the stored contributions.

    Exact rather than approximate: a contribution is the factor multiplied by
    its weight and scaled to ten, so dividing back out returns the original
    value. This is what allows the weights to be varied without re-fetching any
    advisory data.
    """
    detail = json.loads(exposure.score_explanation or "{}")
    c = detail.get("contributions", {})
    return {
        "cvss": (c.get("cvss", 0) or 0) / (bia.SCORE_WEIGHTS["cvss"] * 10),
        "epss": (c.get("epss", 0) or 0) / (bia.SCORE_WEIGHTS["epss"] * 10),
        "criticality": (c.get("criticality", 0) or 0)
                       / (bia.SCORE_WEIGHTS["criticality"] * 10),
        "compliance": exposure.compliance_factor or 1.0,
    }


def score_with(f, w_cvss, w_epss, w_crit):
    base = (f["cvss"] * w_cvss + f["epss"] * w_epss
            + f["criticality"] * w_crit)
    return min(base * f["compliance"], 1.0) * 10


def sensitivity(findings, truth, k):
    """
    Vary the criticality weight and re-measure.

    If the business-aware ordering only beats the baseline at one particular
    weighting, the result is an artefact of that choice. This varies the
    criticality weight from 0.05 to 0.40, renormalising CVSS and EPSS in their
    published 5:3 proportion, and reports NDCG at each point.
    """
    cached = {e.id: factors(e) for e in findings}
    rows = []
    for w_crit in [0.05, 0.10, 0.15, 0.20, 0.25, 0.30, 0.35, 0.40]:
        remaining = 1.0 - w_crit
        w_cvss = remaining * (0.5 / 0.8)
        w_epss = remaining * (0.3 / 0.8)
        scored = [{"id": e.id,
                   "business_score": score_with(cached[e.id], w_cvss, w_epss,
                                                w_crit),
                   "baseline_score": e.baseline_score}
                  for e in findings]
        result = evaluate.compare_rankings(scored, truth, k)
        rows.append((w_crit, w_cvss, w_epss,
                     result["ndcg_business_aware"],
                     result["ndcg_technical_only"],
                     result["delta"]))
    return rows


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

def run(k):
    if not os.path.exists(TRUTH):
        sys.exit("ground_truth.json not found. Run --worksheet, grade it, then "
                 "--import.")
    init_db()
    session = SessionLocal()

    truth = {int(key): int(value)
             for key, value in json.load(open(TRUTH)).items()}
    findings = [e for e in open_findings(session) if e.id in truth]
    if not findings:
        sys.exit("None of the graded findings are still present. Re-run the "
                 "worksheet after any rescan.")

    k = k or min(POOL_DEPTH, len(findings))
    rows = [{"id": e.id, "business_score": e.business_score,
             "baseline_score": e.baseline_score} for e in findings]
    result = evaluate.compare_rankings(rows, truth, k)

    heading("CAPSTONE 2 \u2014 OBJECTIVE 4: RANKING EVALUATION")
    print("  Findings graded             %d" % len(truth))
    print("  Findings evaluated          %d" % len(findings))
    print("  Cut-off (k)                 %d" % k)
    grades = {}
    for value in truth.values():
        grades[value] = grades.get(value, 0) + 1
    print("  Grade distribution          %s"
          % ", ".join("%d\u2192%d" % (g, n) for g, n in sorted(grades.items())))

    heading("1. RANKING QUALITY")
    print("  NDCG@%-2d business-aware      %.4f" % (k, result["ndcg_business_aware"]))
    print("  NDCG@%-2d technical-only      %.4f" % (k, result["ndcg_technical_only"]))
    print("  Difference                  %+.4f" % result["delta"])
    if result["relative_improvement_pct"] is not None:
        print("  Relative improvement        %+.2f%%"
              % result["relative_improvement_pct"])
    verdict = ("business-aware ranking is better"
               if result["delta"] > 0 else
               "no improvement measured" if result["delta"] == 0 else
               "technical-only ranking scored higher")
    print("  Verdict                     %s" % verdict)

    heading("2. PRECISION AT K")
    print("  %-4s %-16s %-16s" % ("k", "business-aware", "technical-only"))
    for cut in (3, 5, 10, k):
        if cut > len(findings):
            continue
        pb = evaluate.precision_at_k(result["business_ranking"], truth, cut)
        pt = evaluate.precision_at_k(result["baseline_ranking"], truth, cut)
        print("  %-4d %-16.2f %-16.2f" % (cut, pb, pt))
    print("\n  Precision here is the share of the top k graded 2 or 3 \u2014 of "
          "the findings\n  the system puts in front of you, how many actually "
          "mattered.")

    heading("3. SENSITIVITY TO THE CRITICALITY WEIGHT")
    print("  Is the improvement robust, or an artefact of weighting "
          "criticality at 0.20?\n")
    print("  %-11s %-8s %-8s %-14s %-14s %s"
          % ("criticality", "cvss", "epss", "NDCG business", "NDCG technical",
             "delta"))
    rows_s = sensitivity(findings, truth, k)
    better = 0
    for w_crit, w_cvss, w_epss, nb, nt, delta in rows_s:
        marker = "  <- published model" if abs(w_crit - 0.20) < 1e-9 else ""
        if delta > 0:
            better += 1
        print("  %-11.2f %-8.2f %-8.2f %-14.4f %-14.4f %+.4f%s"
              % (w_crit, w_cvss, w_epss, nb, nt, delta, marker))
    print("\n  Business-aware ranking scored higher at %d of %d weightings."
          % (better, len(rows_s)))
    if better == len(rows_s):
        print("  The improvement holds across the whole range, so it is not an")
        print("  artefact of the particular weighting chosen.")
    elif better == 0:
        print("  The improvement does not hold at any weighting. Report this")
        print("  plainly \u2014 a negative result honestly reported is a result.")
    else:
        print("  The improvement holds at some weightings and not others. State")
        print("  the range over which it holds rather than the single figure.")

    heading("4. TOP TEN UNDER EACH RANKING")
    lookup = {e.id: e for e in findings}
    print("  %-4s %-34s %-34s" % ("", "business-aware", "technical-only"))
    for i in range(min(10, len(findings))):
        b = lookup[result["business_ranking"][i]]
        t = lookup[result["baseline_ranking"][i]]
        label = lambda e: "%s / %s (%d)" % (
            (e.repository.full_name.split("/")[-1] if e.repository else "?"),
            (e.component_name or "")[:16], truth.get(e.id, 0))
        print("  %-4d %-34s %-34s" % (i + 1, label(b)[:34], label(t)[:34]))
    print("\n  The number in brackets is the ground-truth grade. A good ranking")
    print("  puts the 3s at the top.")

    heading("SUMMARY FOR REPORT CHAPTER 10")
    print("  NDCG@%d business-aware  %.4f" % (k, result["ndcg_business_aware"]))
    print("  NDCG@%d technical-only  %.4f" % (k, result["ndcg_technical_only"]))
    print("  Improvement            %+.2f%%"
          % (result["relative_improvement_pct"] or 0))
    print("  Robust across weights  %d of %d" % (better, len(rows_s)))
    print("  Findings graded        %d" % len(truth))
    print()
    session.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worksheet", action="store_true",
                        help="write the pooled annotation worksheet")
    parser.add_argument("--depth", type=int, default=POOL_DEPTH,
                        help="pool depth per ranking (default 20)")
    parser.add_argument("--import", dest="path", help="import a graded worksheet")
    parser.add_argument("--run", action="store_true", help="compute the evaluation")
    parser.add_argument("-k", type=int, help="NDCG cut-off (default: pool size)")
    args = parser.parse_args()

    if args.worksheet:
        export(args.depth)
    elif args.path:
        import_grades(args.path)
    elif args.run:
        run(args.k)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
