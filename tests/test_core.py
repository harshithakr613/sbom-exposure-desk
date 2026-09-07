"""
Unit tests for the pure-logic core: BIA scoring, correlation, NDCG.

Run with:  python3 -m unittest discover -s tests -v
No third-party test framework and no network needed.
"""

import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sbom_c2 import bia, matching, evaluate  # noqa: E402


PAYMENTS = {
    "name": "Payment Processing",
    "revenue_dependency": "direct",
    "customer_facing": True,
    "availability_requirement": "critical",
    "data_sensitivity": "regulated",
}
LOGGING = {
    "name": "Internal Logging",
    "revenue_dependency": "none",
    "customer_facing": False,
    "availability_requirement": "low",
    "data_sensitivity": "internal",
}


class TestBIA(unittest.TestCase):
    def test_criticality_bounds(self):
        self.assertEqual(bia.process_criticality(PAYMENTS)[0], 1.0)
        low, _ = bia.process_criticality(LOGGING)
        self.assertTrue(0.0 < low < 0.2)

    def test_repository_takes_max_not_mean(self):
        score, detail = bia.repository_criticality([LOGGING, PAYMENTS])
        self.assertEqual(score, 1.0)
        self.assertEqual(detail["driving_process"], "Payment Processing")
        self.assertEqual(detail["process_count"], 2)

    def test_no_processes_is_unknown_not_zero(self):
        score, detail = bia.repository_criticality([])
        self.assertEqual(score, bia.UNMAPPED_CRITICALITY)
        self.assertIsNone(detail["driving_process"])

    def test_unknown_attribute_rejected(self):
        with self.assertRaises(bia.BusinessContextError):
            bia.process_criticality({"revenue_dependency": "somewhat"})

    def test_identical_cve_separates_by_business_context(self):
        """The core claim of the project, asserted as a test."""
        crit_pay, _ = bia.repository_criticality([PAYMENTS])
        crit_log, _ = bia.repository_criticality([LOGGING])
        pay = bia.composite_score(7.5, 0.42, crit_pay, ["PCI-DSS", "GDPR"])
        log = bia.composite_score(7.5, 0.42, crit_log, [])

        self.assertGreater(pay["score"], log["score"])
        self.assertEqual(pay["tier"], "CRITICAL")
        self.assertEqual(bia.baseline_score(7.5, 0.42, "high"),
                         bia.baseline_score(7.5, 0.42, "high"))

    def test_compliance_uplift_capped(self):
        factor, regimes = bia.compliance_factor(
            ["PCI-DSS", "GDPR", "HIPAA", "SOX", "DORA"])
        self.assertEqual(factor, 1.25)
        self.assertEqual(len(regimes), 5)

    def test_compliance_dedupes_and_normalises(self):
        factor, regimes = bia.compliance_factor(["pci-dss", "PCI-DSS", " gdpr "])
        self.assertEqual(regimes, ["GDPR", "PCI-DSS"])
        self.assertEqual(factor, 1.2)

    def test_score_never_exceeds_ten(self):
        result = bia.composite_score(10.0, 1.0, 1.0, ["PCI-DSS", "GDPR", "HIPAA"])
        self.assertLessEqual(result["score"], 10.0)


class TestPurl(unittest.TestCase):
    def test_simple_purl(self):
        p = matching.parse_purl("pkg:npm/lodash@4.17.19")
        self.assertEqual(p["name"], "lodash")
        self.assertEqual(p["ecosystem"], "npm")
        self.assertEqual(p["version"], "4.17.19")

    def test_scoped_npm_purl(self):
        p = matching.parse_purl("pkg:npm/%40babel/traverse@7.23.0")
        self.assertEqual(p["ecosystem"], "npm")
        self.assertTrue(p["name"].endswith("traverse"))

    def test_maven_group_artifact_joined(self):
        p = matching.parse_purl("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1")
        self.assertEqual(p["name"], "org.apache.logging.log4j:log4j-core")
        self.assertEqual(p["ecosystem"], "Maven")

    def test_pypi_ecosystem_mapped(self):
        p = matching.parse_purl("pkg:pypi/django@3.2.4")
        self.assertEqual(p["ecosystem"], "PyPI")

    def test_non_purl_returns_none(self):
        self.assertIsNone(matching.parse_purl("lodash-4.17.19"))
        self.assertIsNone(matching.parse_purl(None))


class TestVersionRanges(unittest.TestCase):
    RANGE = {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}

    def test_vulnerable_version_in_range(self):
        self.assertTrue(matching.version_in_range("4.17.19", self.RANGE))

    def test_fixed_version_excluded(self):
        self.assertFalse(matching.version_in_range("4.17.21", self.RANGE))
        self.assertFalse(matching.version_in_range("5.0.0", self.RANGE))

    def test_introduced_boundary_respected(self):
        rng = {"events": [{"introduced": "2.0.0"}, {"fixed": "2.15.0"}]}
        self.assertFalse(matching.version_in_range("1.9.0", rng))
        self.assertTrue(matching.version_in_range("2.14.1", rng))

    def test_last_affected_form(self):
        rng = {"events": [{"introduced": "0"}, {"last_affected": "1.2.5"}]}
        self.assertTrue(matching.version_in_range("1.2.5", rng))
        self.assertFalse(matching.version_in_range("1.2.6", rng))


LODASH_ADVISORY = {
    "id": "GHSA-35jh-r3h4-6jhm",
    "aliases": ["CVE-2021-23337"],
    "summary": "Command injection in lodash",
    "affected": [
        {
            "package": {"ecosystem": "npm", "name": "lodash"},
            "ranges": [{"type": "SEMVER",
                        "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}],
        }
    ],
}
LOG4J_ADVISORY = {
    "id": "GHSA-jfh8-c2jp-5v3q",
    "aliases": ["CVE-2021-44228"],
    "summary": "Remote code execution in Log4j",
    "affected": [
        {
            "package": {"ecosystem": "Maven",
                        "name": "org.apache.logging.log4j:log4j-core"},
            "ranges": [{"type": "ECOSYSTEM",
                        "events": [{"introduced": "2.0"}, {"fixed": "2.15.0"}]}],
        }
    ],
}


class TestCorrelation(unittest.TestCase):
    def setUp(self):
        self.index = matching.advisory_index([LODASH_ADVISORY, LOG4J_ADVISORY])

    def test_detects_vulnerable_transitive_component(self):
        components = [{
            "name": "lodash", "ecosystem": "npm", "version": "4.17.19",
            "purl": "pkg:npm/lodash@4.17.19", "direct": False,
            "path": "app > webpack > lodash",
        }]
        found = matching.correlate(components, self.index)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["cve_id"], "CVE-2021-23337")
        self.assertFalse(found[0]["direct"])
        self.assertEqual(found[0]["path"], "app > webpack > lodash")

    def test_patched_version_produces_no_finding(self):
        components = [{"name": "lodash", "ecosystem": "npm", "version": "4.17.21",
                       "purl": "pkg:npm/lodash@4.17.21"}]
        self.assertEqual(matching.correlate(components, self.index), [])

    def test_log4shell_detected(self):
        components = [{
            "name": "org.apache.logging.log4j:log4j-core",
            "ecosystem": "Maven", "version": "2.14.1",
        }]
        found = matching.correlate(components, self.index)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["cve_id"], "CVE-2021-44228")

    def test_no_duplicate_findings_per_advisory(self):
        components = [{"name": "lodash", "ecosystem": "npm", "version": "4.17.19"}]
        found = matching.correlate(components, self.index)
        self.assertEqual(len(found), 1)

    def test_wrong_ecosystem_not_matched(self):
        components = [{"name": "lodash", "ecosystem": "PyPI", "version": "4.17.19"}]
        self.assertEqual(matching.correlate(components, self.index), [])


class TestNDCG(unittest.TestCase):
    FINDINGS = [
        {"id": "f1", "business_score": 8.4, "baseline_score": 6.5},   # payments
        {"id": "f2", "business_score": 5.2, "baseline_score": 6.5},   # logging
        {"id": "f3", "business_score": 7.1, "baseline_score": 7.0},   # auth
        {"id": "f4", "business_score": 3.0, "baseline_score": 7.2},   # internal tool
    ]
    # Ground truth: payments and auth matter, the internal tool does not.
    TRUTH = {"f1": 3, "f3": 2, "f2": 1, "f4": 0}

    def test_perfect_ranking_scores_one(self):
        self.assertEqual(evaluate.ndcg(["f1", "f3", "f2", "f4"], self.TRUTH), 1.0)

    def test_reversed_ranking_scores_low(self):
        self.assertLess(evaluate.ndcg(["f4", "f2", "f3", "f1"], self.TRUTH), 0.7)

    def test_business_ranking_beats_baseline(self):
        result = evaluate.compare_rankings(self.FINDINGS, self.TRUTH)
        self.assertGreater(result["ndcg_business_aware"],
                           result["ndcg_technical_only"])
        self.assertEqual(result["business_ranking"][0], "f1")
        self.assertGreater(result["delta"], 0)

    def test_empty_ranking_is_zero(self):
        self.assertEqual(evaluate.ndcg([], self.TRUTH), 0.0)

    def test_precision_at_k(self):
        ranked = evaluate.rank_by(self.FINDINGS, "business_score")
        self.assertEqual(evaluate.precision_at_k(ranked, self.TRUTH, 2), 1.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestUnmappedRepositories(unittest.TestCase):
    """An unmapped repository is unknown risk, not low risk."""

    def test_unmapped_scores_at_median_not_zero(self):
        score, detail = bia.repository_criticality([])
        self.assertEqual(score, bia.UNMAPPED_CRITICALITY)
        self.assertTrue(detail["unmapped"])

    def test_unmapped_outranks_a_genuinely_trivial_process(self):
        trivial, _ = bia.repository_criticality([LOGGING])
        unknown, _ = bia.repository_criticality([])
        self.assertGreater(unknown, trivial)

    def test_mapped_repository_is_not_flagged(self):
        _, detail = bia.repository_criticality([PAYMENTS])
        self.assertFalse(detail["unmapped"])


class TestFixEffort(unittest.TestCase):
    def test_patch_bump_is_cheapest(self):
        e = bia.fix_effort("1.2.5", "1.2.6")
        self.assertEqual(e["band"], "PATCH")
        self.assertEqual(e["multiplier"], 1.0)

    def test_minor_bump(self):
        self.assertEqual(bia.fix_effort("2.14.1", "2.15.0")["band"], "MINOR")

    def test_single_major_bump(self):
        self.assertEqual(bia.fix_effort("0.21.0", "1.0.0")["band"], "MAJOR")

    def test_multiple_major_versions(self):
        self.assertEqual(bia.fix_effort("2.11.2", "5.0.0")["band"], "MAJOR_MULTI")

    def test_no_patch_is_highest_effort_not_lowest(self):
        """No available fix must not read as an easy win."""
        e = bia.fix_effort("1.0.0", None)
        self.assertEqual(e["band"], "NO_FIX")
        self.assertEqual(e["effort"], 1.0)
        self.assertEqual(bia.quick_win_score(9.9, e), 0.0)

    def test_unparseable_versions_fall_back(self):
        self.assertEqual(bia.fix_effort("weird", "1.0")["band"], "UNKNOWN")

    def test_short_versions_are_padded(self):
        self.assertEqual(bia.fix_effort("2.14", "2.14.1")["band"], "PATCH")

    def test_effort_breaks_ties_but_does_not_overturn_importance(self):
        """A critical finding needing a major upgrade still beats a trivial one."""
        critical_hard = bia.quick_win_score(9.0, bia.fix_effort("1.0.0", "2.0.0"))
        trivial_easy = bia.quick_win_score(3.0, bia.fix_effort("1.2.5", "1.2.6"))
        self.assertGreater(critical_hard, trivial_easy)

    def test_effort_reorders_comparable_findings(self):
        easy = bia.quick_win_score(7.0, bia.fix_effort("1.2.5", "1.2.6"))
        hard = bia.quick_win_score(7.4, bia.fix_effort("1.0.0", "4.0.0"))
        self.assertGreater(easy, hard)

    def test_risk_score_is_unaffected_by_effort(self):
        """Effort is a separate axis; composite_score must not see it."""
        crit, _ = bia.repository_criticality([PAYMENTS])
        before = bia.composite_score(9.8, 0.006, crit, ["PCI-DSS"])["score"]
        bia.fix_effort("1.0.0", "9.0.0")
        after = bia.composite_score(9.8, 0.006, crit, ["PCI-DSS"])["score"]
        self.assertEqual(before, after)


# GHSA-67hx-6x53-jw92 lists two packages with similar names and different fix
# states. This is the shape that produced false positives before exact matches
# were given precedence over fuzzy ones.
MULTI_PACKAGE_ADVISORY = {
    "id": "GHSA-67hx-6x53-jw92",
    "aliases": ["CVE-2023-45133"],
    "affected": [
        {"package": {"ecosystem": "npm", "name": "@babel/traverse"},
         "ranges": [{"type": "SEMVER",
                     "events": [{"introduced": "0"}, {"fixed": "7.23.2"}]}]},
        {"package": {"ecosystem": "npm", "name": "babel-traverse"},
         "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]},
    ],
}


class TestExactMatchPrecedence(unittest.TestCase):
    """An exact name match must never be overridden by a similar-looking one."""

    def setUp(self):
        self.index = matching.advisory_index([MULTI_PACKAGE_ADVISORY])

    def _check(self, name, version):
        return matching.correlate(
            [{"name": name, "ecosystem": "npm", "version": version}], self.index)

    def test_vulnerable_version_still_detected(self):
        found = self._check("@babel/traverse", "7.14.2")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["match_type"], "PURL_EXACT")

    def test_patched_version_not_matched_via_sibling_package(self):
        """The regression: 7.23.9 is patched and must not match babel-traverse."""
        self.assertEqual(self._check("@babel/traverse", "7.23.9"), [])
        self.assertEqual(self._check("@babel/traverse", "7.27.0"), [])

    def test_legacy_package_still_detected(self):
        found = self._check("babel-traverse", "6.26.0")
        self.assertEqual(len(found), 1)

    def test_patched_lodash_not_flagged(self):
        advisory = {
            "id": "GHSA-35jh-r3h4-6jhm", "aliases": ["CVE-2021-23337"],
            "affected": [{"package": {"ecosystem": "npm", "name": "lodash"},
                          "ranges": [{"type": "SEMVER",
                                      "events": [{"introduced": "0"},
                                                 {"fixed": "4.17.21"}]}]}]}
        index = matching.advisory_index([advisory])
        vulnerable = matching.correlate(
            [{"name": "lodash", "ecosystem": "npm", "version": "4.17.19"}], index)
        patched = matching.correlate(
            [{"name": "lodash", "ecosystem": "npm", "version": "4.17.21"}], index)
        self.assertEqual(len(vulnerable), 1)
        self.assertEqual(patched, [])


class TestVersionConstraints(unittest.TestCase):
    """Manifest constraints are not resolved versions and must not be treated so."""

    def test_recognises_constraints(self):
        for value in ("^1.15.1", ">= 8.0.0", "~2.4", "*", "latest"):
            self.assertTrue(matching.is_constraint(value), value)

    def test_concrete_versions_are_not_constraints(self):
        for value in ("1.2.5", "4.17.19", "2.14.1", None):
            self.assertFalse(matching.is_constraint(value), value)

    def test_constraint_is_reported_as_unresolved_not_evaluated(self):
        advisory = {
            "id": "X", "aliases": ["CVE-1"],
            "affected": [{"package": {"ecosystem": "npm", "name": "axios"},
                          "ranges": [{"type": "SEMVER",
                                      "events": [{"introduced": "0"},
                                                 {"fixed": "1.0.0"}]}]}]}
        index = matching.advisory_index([advisory])
        found = matching.correlate(
            [{"name": "axios", "ecosystem": "npm", "version": "^1.15.1"}], index)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["match_type"], "NO_VERSION")

    def test_resolved_patched_version_still_clean(self):
        advisory = {
            "id": "X", "aliases": ["CVE-1"],
            "affected": [{"package": {"ecosystem": "npm", "name": "axios"},
                          "ranges": [{"type": "SEMVER",
                                      "events": [{"introduced": "0"},
                                                 {"fixed": "1.0.0"}]}]}]}
        index = matching.advisory_index([advisory])
        self.assertEqual(matching.correlate(
            [{"name": "axios", "ecosystem": "npm", "version": "2.0.0"}], index), [])
