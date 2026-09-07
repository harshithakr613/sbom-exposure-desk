#!/usr/bin/env python3
"""
Capstone 1, Objective 4 — Validation and Evaluation.

Measures the detection accuracy the proposal commits to: matching precision,
recall, false-positive rate, and end-to-end latency, plus explicit verification
of the three real-world CVE scenarios.

    python scripts/validate.py                # full validation run
    python scripts/validate.py --latency      # time a full sync as well
    python scripts/validate.py --csv results.csv

METHODOLOGY, AND WHY IT IS NOT CIRCULAR
---------------------------------------
The demonstration organisation is built from forks of real projects, so its
dependency trees contain genuine vulnerabilities beyond the versions pinned
deliberately. That makes a naive "anything unexpected is a false positive"
calculation wrong: most unexpected findings are real.

So the two measures are computed against different ground truths.

  RECALL is measured against the PLANTED set. Every pinned vulnerable version
  in data/demo_org.json is a CVE that must be found. Recall = found / planted.
  This is a true known-answer test: the answer was decided before the run.

  PRECISION is measured by INDEPENDENT RE-VERIFICATION. For each reported
  finding, the component is checked to exist in that repository's stored
  inventory at the stated version, and the version is re-evaluated against the
  advisory's affected range using a separate code path from the correlator.
  A finding that fails either check is a false positive.

Reporting a single number for both would be easier and less honest.
"""

import argparse
import csv
import json
import os
import sys
import time
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sbom_c2 import config, feeds, matching            # noqa: E402
from sbom_c2.db import SessionLocal, init_db           # noqa: E402
from sbom_c2.models import (                           # noqa: E402
    Component, Exposure, Repository, Vulnerability)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPEC = os.path.join(ROOT, "data", "demo_org.json")

# The three scenarios named in the Capstone 1 proposal.
SCENARIOS = {
    "Log4Shell": {
        "cve": "CVE-2021-44228",
        "package": "org.apache.logging.log4j:log4j-core",
        "affected": "2.0 through 2.14.1",
    },
    "Spring4Shell": {
        "cve": "CVE-2022-22965",
        "package": "org.springframework:spring-core",
        "affected": "< 5.3.18",
    },
    "XZ Utils backdoor": {
        "cve": "CVE-2024-3094",
        "package": "xz-utils",
        "affected": "5.6.0, 5.6.1",
        # A compromise of a Linux system library distributed through OS package
        # managers, not an application dependency declared in package.json,
        # requirements.txt or pom.xml. It lies outside the scope of SBOM-based
        # application dependency analysis, so it is reported as a scope
        # limitation rather than counted as a detection failure.
        "out_of_scope": True,
        "scope_note": ("system-level package, not an application dependency; "
                       "outside the scope of manifest-derived SBOM analysis"),
    },
}

RULE = "=" * 78


def heading(text):
    print("\n" + RULE)
    print(text)
    print(RULE)


# ---------------------------------------------------------------------------
# Recall: did we find every vulnerability we deliberately planted?
# ---------------------------------------------------------------------------

def measure_recall(session, org):
    spec = json.load(open(SPEC))

    planted = []
    for repo in spec["repositories"]:
        for cve in repo.get("known_cves", []):
            planted.append((repo["name"], cve))

    found, missed = [], []
    for repo_name, cve in planted:
        full_name = "%s/%s" % (org, repo_name)
        repository = (session.query(Repository)
                      .filter_by(full_name=full_name).one_or_none())
        if repository is None:
            missed.append((repo_name, cve, "repository not ingested"))
            continue

        hit = (session.query(Exposure)
               .filter_by(repository_id=repository.id, cve_id=cve)
               .first())
        if hit:
            found.append((repo_name, cve, hit.match_type))
        else:
            # Distinguish "we missed it" from "the component is not there",
            # which is a demo-environment problem rather than a detection one.
            component = (session.query(Component)
                         .filter_by(repository_id=repository.id).all())
            names = {(c.name or "").lower() for c in component}
            pins = spec_pins_for(spec, repo_name)
            reason = "component absent from SBOM" if not (
                pins & names) else "component present, advisory not matched"
            missed.append((repo_name, cve, reason))

    total = len(planted)
    recall = round(len(found) / total, 4) if total else 0.0
    return {"planted": total, "found": found, "missed": missed,
            "recall": recall}


def spec_pins_for(spec, repo_name):
    for repo in spec["repositories"]:
        if repo["name"] == repo_name:
            return {p.split(":")[-1].lower() for p in repo["pins"]}
    return set()


# ---------------------------------------------------------------------------
# Precision: is every reported finding independently verifiable?
# ---------------------------------------------------------------------------

def measure_precision(session, sample_limit=None):
    exposures = session.query(Exposure).all()
    if sample_limit:
        exposures = exposures[:sample_limit]

    inventory = defaultdict(dict)
    for component in session.query(Component).all():
        key = (component.repository_id, (component.name or "").lower())
        inventory[key][str(component.version)] = component

    advisories = {}
    true_positive, false_positive, unverifiable = [], [], []

    for exposure in exposures:
        key = (exposure.repository_id, (exposure.component_name or "").lower())
        versions = inventory.get(key)

        # Check 1 -- the component must actually be in the inventory.
        if not versions:
            false_positive.append((exposure, "component not in repository SBOM"))
            continue

        if exposure.component_version and \
                str(exposure.component_version) not in versions:
            false_positive.append((exposure, "version not present in SBOM"))
            continue

        # Check 2 -- re-evaluate the version range from the advisory itself,
        # via a fetch and comparison independent of the stored correlation.
        advisory = advisories.get(exposure.advisory_id)
        if advisory is None:
            advisory = feeds.fetch_osv_advisory(exposure.advisory_id)
            advisories[exposure.advisory_id] = advisory or {}
            advisory = advisories[exposure.advisory_id]

        if not advisory:
            unverifiable.append((exposure, "advisory could not be re-fetched"))
            continue

        if not exposure.component_version:
            unverifiable.append((exposure, "component carries no version"))
            continue

        component = {
            "name": exposure.component_name,
            "version": exposure.component_version,
            "ecosystem": exposure.ecosystem,
        }
        affected, _match_type = matching.advisory_affects(component, advisory)
        if affected:
            true_positive.append(exposure)
        else:
            false_positive.append((exposure, "version outside affected range"))

    verified = len(true_positive) + len(false_positive)
    precision = round(len(true_positive) / verified, 4) if verified else 0.0
    fp_rate = round(len(false_positive) / verified, 4) if verified else 0.0

    return {
        "examined": len(exposures),
        "verifiable": verified,
        "true_positive": len(true_positive),
        "false_positive": false_positive,
        "unverifiable": unverifiable,
        "precision": precision,
        "false_positive_rate": fp_rate,
    }


# ---------------------------------------------------------------------------
# Named scenarios
# ---------------------------------------------------------------------------

def check_scenarios(session):
    results = {}
    for name, scenario in SCENARIOS.items():
        hits = (session.query(Exposure)
                .filter_by(cve_id=scenario["cve"]).all())
        repos = sorted({session.get(Repository, h.repository_id).full_name
                        for h in hits if h.repository_id})

        # Present in the estate at all? Distinguishes a detection failure from
        # a component that simply is not there.
        present = (session.query(Component)
                   .filter(Component.name.ilike(
                       "%%%s%%" % scenario["package"].split(":")[-1]))
                   .all())

        results[name] = {
            "cve": scenario["cve"],
            "package": scenario["package"],
            "out_of_scope": scenario.get("out_of_scope", False),
            "scope_note": scenario.get("scope_note"),
            "detected": bool(hits),
            "finding_count": len(hits),
            "repositories": repos,
            "component_present_in_estate": bool(present),
            "versions_present": sorted({str(c.version) for c in present
                                        if c.version})[:6],
        }
    return results


# ---------------------------------------------------------------------------
# Coverage statistics for the report
# ---------------------------------------------------------------------------

def coverage(session):
    repositories = session.query(Repository).count()
    components = session.query(Component).count()
    exposures = session.query(Exposure).count()
    advisories = session.query(Vulnerability).count()

    by_match = defaultdict(int)
    transitive = direct = 0
    for exposure in session.query(Exposure).all():
        by_match[exposure.match_type or "UNKNOWN"] += 1
        if exposure.direct:
            direct += 1
        else:
            transitive += 1

    by_tier = defaultdict(int)
    for exposure in session.query(Exposure).all():
        by_tier[exposure.tier or "UNSCORED"] += 1

    ecosystems = defaultdict(int)
    for component in session.query(Component).all():
        ecosystems[component.ecosystem or "unknown"] += 1

    return {
        "repositories": repositories,
        "components": components,
        "exposures": exposures,
        "advisories": advisories,
        "by_match_type": dict(by_match),
        "direct": direct,
        "transitive": transitive,
        "by_tier": dict(by_tier),
        "ecosystems": dict(sorted(ecosystems.items(),
                                  key=lambda kv: -kv[1])[:8]),
    }


def measure_latency():
    """Time a full organisation sync, end to end."""
    from sbom_c2.github_client import GitHubClient
    from sbom_c2 import pipeline

    token, org = config.require_github()
    session = SessionLocal()
    try:
        start = time.time()
        summary = pipeline.run_full_pipeline(session, GitHubClient(token, org))
        elapsed = time.time() - start
        per_repo = elapsed / max(summary.get("repositories", 1), 1)
        return {"seconds": round(elapsed, 1),
                "per_repository_seconds": round(per_repo, 2),
                "summary": summary}
    finally:
        session.close()


# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--latency", action="store_true",
                        help="also time a full sync (slow)")
    parser.add_argument("--csv", help="write the findings table to CSV")
    parser.add_argument("--sample", type=int,
                        help="limit precision checking to N findings")
    args = parser.parse_args()

    init_db()
    session = SessionLocal()
    _token, org = config.require_github()

    heading("CAPSTONE 1 — OBJECTIVE 4: VALIDATION AND EVALUATION")
    print("Organisation: %s" % org)

    cov = coverage(session)
    heading("1. COVERAGE")
    print("  Repositories ingested      %d" % cov["repositories"])
    print("  Components inventoried     %d" % cov["components"])
    print("  Advisories in knowledge base %d" % cov["advisories"])
    print("  Exposures detected         %d" % cov["exposures"])
    print("  Direct / transitive        %d / %d"
          % (cov["direct"], cov["transitive"]))
    print("\n  By match type:")
    for name, count in sorted(cov["by_match_type"].items(),
                              key=lambda kv: -kv[1]):
        print("    %-14s %5d" % (name, count))
    print("\n  By priority tier:")
    for name, count in sorted(cov["by_tier"].items(), key=lambda kv: -kv[1]):
        print("    %-14s %5d" % (name, count))
    print("\n  Components by ecosystem:")
    for name, count in cov["ecosystems"].items():
        print("    %-14s %5d" % (name, count))

    heading("2. RECALL  (against deliberately planted vulnerabilities)")
    rec = measure_recall(session, org)
    print("  Planted vulnerabilities    %d" % rec["planted"])
    print("  Detected                   %d" % len(rec["found"]))
    print("  Missed                     %d" % len(rec["missed"]))
    print("  RECALL                     %.1f%%   (target > 85%%)  %s"
          % (rec["recall"] * 100, "PASS" if rec["recall"] > 0.85 else "BELOW TARGET"))
    if rec["missed"]:
        print("\n  Not detected:")
        for repo, cve, reason in rec["missed"]:
            print("    %-24s %-18s %s" % (repo, cve, reason))

    heading("3. PRECISION  (independent re-verification of each finding)")
    print("  Re-fetching advisories and re-evaluating version ranges...")
    prec = measure_precision(session, args.sample)
    print("  Findings examined          %d" % prec["examined"])
    print("  Independently verifiable   %d" % prec["verifiable"])
    print("  True positives             %d" % prec["true_positive"])
    print("  False positives            %d" % len(prec["false_positive"]))
    print("  Unverifiable (no version)  %d" % len(prec["unverifiable"]))
    print("  PRECISION                  %.1f%%   (target > 90%%)  %s"
          % (prec["precision"] * 100,
             "PASS" if prec["precision"] > 0.90 else "BELOW TARGET"))
    print("  FALSE-POSITIVE RATE        %.1f%%   (target < 10%%)  %s"
          % (prec["false_positive_rate"] * 100,
             "PASS" if prec["false_positive_rate"] < 0.10 else "ABOVE TARGET"))
    if prec["false_positive"][:10]:
        print("\n  Sample false positives:")
        for exposure, reason in prec["false_positive"][:10]:
            print("    %-28s %-16s %s"
                  % (str(exposure.component_name)[:28],
                     str(exposure.component_version)[:16], reason))

    heading("4. REAL-WORLD CVE SCENARIOS")
    scen = check_scenarios(session)
    for name, result in scen.items():
        if result["out_of_scope"]:
            status = "OUT OF SCOPE"
        else:
            status = "DETECTED" if result["detected"] else "not detected"
        print("\n  %s  (%s)" % (name, result["cve"]))
        print("    Status                   %s" % status)
        print("    Findings                 %d" % result["finding_count"])
        if result["repositories"]:
            print("    Repositories             %s"
                  % ", ".join(r.split("/")[-1] for r in result["repositories"]))
        if result["out_of_scope"]:
            print("    Note                     %s" % result["scope_note"])
        elif not result["detected"]:
            print("    Component in estate      %s"
                  % ("yes" if result["component_present_in_estate"] else "no"))
            if result["versions_present"]:
                print("    Versions present         %s"
                      % ", ".join(result["versions_present"]))

    if args.latency:
        heading("5. END-TO-END LATENCY")
        print("  Running a full sync, this takes several minutes...")
        lat = measure_latency()
        print("  Full portfolio sync        %.1f s" % lat["seconds"])
        print("  Per repository             %.2f s" % lat["per_repository_seconds"])
        print("  Repositories               %d" % lat["summary"]["repositories"])

    if args.csv:
        with open(args.csv, "w", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["metric", "value", "target", "result"])
            writer.writerow(["repositories", cov["repositories"], "", ""])
            writer.writerow(["components", cov["components"], "", ""])
            writer.writerow(["exposures", cov["exposures"], "", ""])
            writer.writerow(["recall", "%.4f" % rec["recall"], "> 0.85",
                             "PASS" if rec["recall"] > 0.85 else "BELOW"])
            writer.writerow(["precision", "%.4f" % prec["precision"], "> 0.90",
                             "PASS" if prec["precision"] > 0.90 else "BELOW"])
            writer.writerow(["false_positive_rate",
                             "%.4f" % prec["false_positive_rate"], "< 0.10",
                             "PASS" if prec["false_positive_rate"] < 0.10
                             else "ABOVE"])
            for name, result in scen.items():
                writer.writerow([
                    "scenario:%s" % name, result["cve"],
                    "out of scope" if result["out_of_scope"] else "detected",
                    "N/A" if result["out_of_scope"]
                    else ("PASS" if result["detected"] else "NOT FOUND")])
        print("\nWrote %s" % args.csv)

    heading("SUMMARY FOR REPORT CHAPTER 9")
    print("  Recall              %.1f%%" % (rec["recall"] * 100))
    print("  Precision           %.1f%%" % (prec["precision"] * 100))
    print("  False-positive rate %.1f%%" % (prec["false_positive_rate"] * 100))
    in_scope = {n: r for n, r in scen.items() if not r["out_of_scope"]}
    print("  Scenarios detected  %d of %d in scope  (%d excluded by scope)"
          % (sum(1 for r in in_scope.values() if r["detected"]),
             len(in_scope), len(scen) - len(in_scope)))
    print()

    session.close()


if __name__ == "__main__":
    main()
