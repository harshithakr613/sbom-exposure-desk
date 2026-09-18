"""
Tests for the pre-disclosure ("zero-day") layer:
feed normalisation, the four correlation tiers, and degraded-mode scoring.

No network, no database, no third-party test framework. Every feed payload
below is a fixture shaped like the real response, so the parsers are exercised
without depending on a live endpoint -- which also means these tests still pass
when ENISA is down or the CVD ledger has rotated.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sbom_c2 import zeroday_feeds as zf          # noqa: E402
from sbom_c2 import zeroday_match as zm          # noqa: E402
from sbom_c2 import zeroday_score as zs          # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

CVD_SEALED = {
    "hash": "a3f9" + "0" * 60,
    "committed_at": "2026-07-14T00:00:00Z",
    "reveal_tier": 2,
    "revealed": False,
    "ant_id": None,
    "project": None,
    "claude_severity": "high",
    "status": "in_disclosure",
    "cve_ids": [],
    "ghsa_ids": [],
}

CVD_REVEALED = {
    "hash": "b7c2" + "0" * 60,
    "committed_at": "2026-04-02T00:00:00Z",
    "revealed": True,
    "revealed_at": "2026-07-01T00:00:00Z",
    "ant_id": "ANT-2026-00412",
    "project": "libexpat",
    "bug_class": "out-of-bounds read",
    "claude_severity": "high",
    "vendor_severity": "medium",
    "maintainer_severity": "critical",
    "cve_ids": [],
    "ghsa_ids": [],
    "patched": False,
    "status": "disclosed",
}

CVD_PATCHED = dict(CVD_REVEALED, ant_id="ANT-2026-00088", project="jinja2",
                   cve_ids=["CVE-2026-11111"], patched=True,
                   patched_at="2026-08-01T00:00:00Z")

OSSFUZZ_RECORD = {
    "id": "OSV-2026-76",
    "summary": "Security exception in HTMLTagBalancer.endElement",
    "published": "2026-01-18T00:02:11Z",
    "affected": [{
        "package": {"name": "htmlunit", "ecosystem": "OSS-Fuzz",
                    "purl": "pkg:generic/htmlunit"},
        "ranges": [{
            "type": "GIT",
            "repo": "https://github.com/HtmlUnit/htmlunit.git",
            "events": [{"introduced": "69f12908fca8b940fa6cd114b0266b909fca0c1a"},
                       {"fixed": "b750ca63a80698eddef3fc3457911bc21a825b58"}],
        }],
        "ecosystem_specific": {"severity": "LOW"},
    }],
}

GHSA_ROW = {
    "ghsa_id": "GHSA-abcd-1234-wxyz",
    "cve_id": None,                       # issued before the CVE lands in NVD
    "summary": "Prototype pollution in lodash",
    "severity": "high",
    "published_at": "2026-08-20T10:00:00Z",
    "html_url": "https://github.com/advisories/GHSA-abcd-1234-wxyz",
    "vulnerabilities": [{
        "package": {"name": "lodash", "ecosystem": "npm"},
        "vulnerable_version_range": "< 4.17.21",
        "first_patched_version": None,
    }],
}

DEBIAN_JSON = {
    "libexpat": {
        "TEMP-0000000-269968": {
            "description": "heap overflow in doProlog",
            "releases": {"bookworm": {"status": "open", "urgency": "high"}},
        },
        "CVE-2024-45491": {"releases": {"bookworm": {"status": "resolved"}}},
    },
}

COMPONENTS = [
    {"name": "lodash", "version": "4.17.19", "ecosystem": "npm",
     "purl": "pkg:npm/lodash@4.17.19"},
    {"name": "libexpat", "version": "2.5.0", "ecosystem": "Debian",
     "purl": "pkg:deb/debian/libexpat@2.5.0"},
    {"name": "htmlunit", "version": "4.20.0", "ecosystem": "Maven",
     "purl": "pkg:maven/org.htmlunit/htmlunit@4.20.0",
     "repo_url": "https://github.com/HtmlUnit/htmlunit"},
    {"name": "flask", "version": "3.0.0", "ecosystem": "PyPI",
     "purl": "pkg:pypi/flask@3.0.0"},
]


def parse_cvd(rows):
    """Drive the CVD parser off a fixture instead of the network."""
    import unittest.mock as mock
    with mock.patch.object(zf, "_get_json", return_value=rows):
        return zf.fetch_cvd_ledger()


# ---------------------------------------------------------------------------

class TestCVDLedger(unittest.TestCase):

    def test_sealed_commitment_has_no_project_and_no_tier(self):
        [finding] = parse_cvd([CVD_SEALED])
        self.assertEqual(finding["stage"], zf.STAGE_COMMITMENT)
        self.assertEqual(finding["stage_label"], "T0")
        self.assertIsNone(finding["project"])
        # No evidence tier: there is nothing to correlate against, and the
        # system must not invent one.
        self.assertIsNone(finding["evidence_tier"])

    def test_revealed_finding_is_project_tier(self):
        [finding] = parse_cvd([CVD_REVEALED])
        self.assertEqual(finding["stage"], zf.STAGE_REVEALED)
        self.assertEqual(finding["evidence_tier"], zm.TIER_PROJECT)
        self.assertEqual(finding["project"], "libexpat")
        self.assertEqual(finding["cve_ids"], [])

    def test_maintainer_severity_wins_over_model_and_vendor(self):
        [finding] = parse_cvd([CVD_REVEALED])
        self.assertEqual(finding["severity_band"], "critical")
        self.assertEqual(finding["severities"]["model"], "high")
        self.assertEqual(finding["severities"]["vendor"], "medium")

    def test_stage_advances_to_patched(self):
        [finding] = parse_cvd([CVD_PATCHED])
        self.assertEqual(finding["stage"], zf.STAGE_PATCHED)
        self.assertTrue(finding["patched"])

    def test_revealed_findings_survive_the_record_cap(self):
        # The ledger is ordered newest-commitment-first and the newest entries
        # are all still sealed, so a naive head-slice returns nothing usable.
        # One revealed finding buried under many commitments must still come
        # back -- and come back first.
        sealed = [dict(CVD_SEALED, hash="%064x" % n) for n in range(50)]
        rows = sealed + [CVD_REVEALED]
        import unittest.mock as mock
        with mock.patch.object(zf, "_get_json", return_value=rows):
            findings = zf.fetch_cvd_ledger(limit=10)
        self.assertEqual(len(findings), 10)
        self.assertEqual(findings[0]["stage"], zf.STAGE_REVEALED)
        self.assertEqual(findings[0]["project"], "libexpat")

    def test_ledger_may_be_wrapped_in_a_key(self):
        findings = parse_cvd({"entries": [CVD_REVEALED]})
        self.assertEqual(len(findings), 1)


class TestOssFuzzNormalisation(unittest.TestCase):

    def setUp(self):
        self.finding = zf._from_osv(OSSFUZZ_RECORD, source="ossfuzz")

    def test_generic_purl_does_not_qualify_as_purl_tier(self):
        # pkg:generic/<project> carries no ecosystem or version range, so it
        # must not be treated as a PURL match.
        self.assertEqual(self.finding["evidence_tier"], zm.TIER_COMMIT)

    def test_git_commit_range_is_captured(self):
        [rng] = self.finding["commit_ranges"]
        self.assertTrue(rng["introduced"].startswith("69f129"))
        self.assertTrue(rng["fixed"].startswith("b750ca"))

    def test_no_cve_means_still_pre_identifier(self):
        self.assertEqual(self.finding["cve_ids"], [])
        # A fixed commit exists, so the finding has reached the patch stage.
        self.assertEqual(self.finding["stage"], zf.STAGE_PATCHED)


class TestGhsaAndDebian(unittest.TestCase):

    def test_ghsa_without_cve_is_pre_identifier(self):
        import unittest.mock as mock
        with mock.patch.object(zf, "_get_json", return_value=[GHSA_ROW]):
            [finding] = zf.fetch_github_advisories()
        self.assertEqual(finding["stage"], zf.STAGE_REVEALED)
        self.assertEqual(finding["ecosystem"], "npm")
        self.assertEqual(finding["severity_band"], "high")

    def test_debian_keeps_only_cve_less_temp_entries(self):
        import unittest.mock as mock
        with mock.patch.object(zf, "_get_json", return_value=DEBIAN_JSON):
            findings = zf.fetch_debian_temp()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["source_id"], "TEMP-0000000-269968")
        self.assertEqual(findings[0]["project"], "libexpat")


class TestGithubVersionRanges(unittest.TestCase):

    def test_range_strings_become_osv_events(self):
        self.assertEqual(zf.parse_github_version_range("< 4.17.21"),
                         [{"introduced": "0"}, {"fixed": "4.17.21"}])
        self.assertEqual(zf.parse_github_version_range(">= 1.0.0, < 1.2.3"),
                         [{"introduced": "1.0.0"}, {"fixed": "1.2.3"}])
        self.assertEqual(zf.parse_github_version_range("<= 2.0.0"),
                         [{"introduced": "0"}, {"last_affected": "2.0.0"}])

    def test_unparseable_range_stays_unbounded(self):
        # Never invent a bound: an unbounded advisory must stay unbounded so
        # the matcher discounts it rather than asserting a range.
        self.assertEqual(zf.parse_github_version_range(""), [])
        self.assertEqual(zf.parse_github_version_range(None), [])

    def test_patched_version_is_not_reported_as_affected(self):
        # Observed against the live feed: js-yaml 3.14.0, 3.14.1, 4.1.0 and
        # 4.3.1 all matched one advisory because the range was never parsed,
        # so already-fixed versions were reported as exposed.
        import unittest.mock as mock
        with mock.patch.object(zf, "_get_json", return_value=[GHSA_ROW]):
            [finding] = zf.fetch_github_advisories()

        vulnerable = {"name": "lodash", "version": "4.17.19",
                      "ecosystem": "npm", "purl": "pkg:npm/lodash@4.17.19"}
        patched = {"name": "lodash", "version": "4.17.21",
                   "ecosystem": "npm", "purl": "pkg:npm/lodash@4.17.21"}

        matched, confidence, reason = zm.match_purl(finding, vulnerable)
        self.assertTrue(matched)
        self.assertIn("inside affected range", reason)
        self.assertEqual(confidence, zm.TIER_CONFIDENCE[zm.TIER_PURL])

        matched, _c, _r = zm.match_purl(finding, patched)
        self.assertFalse(matched)

    def test_unbounded_match_is_not_marked_verified(self):
        unbounded = zf.PreDisclosureFinding.make(
            source="ghsa", source_id="GHSA-none", stage=zf.STAGE_REVEALED,
            evidence_tier=zm.TIER_PURL,
            affected_ranges=[{"package": {"name": "lodash",
                                          "ecosystem": "npm"}}])
        [hit] = zm.correlate_finding(unbounded, [COMPONENTS[0]])
        self.assertIn("no version bound", hit["reason"])
        self.assertFalse(hit["verified"])


class TestNormalisation(unittest.TestCase):

    def test_packaging_prefixes_are_stripped(self):
        self.assertEqual(zm.normalise_project("python-requests"), "requests")
        self.assertEqual(zm.normalise_project("ruby-httparty"), "httparty")

    def test_lib_prefix_is_preserved(self):
        # libxml2 is the real upstream name; folding it to xml2 would invent
        # an equivalence and T0 already matches on similarity alone.
        self.assertEqual(zm.normalise_project("libxml2-dev"), "libxml2")
        self.assertEqual(zm.normalise_project("libpng"), "libpng")

    def test_coordinates_reduce_to_the_project(self):
        self.assertEqual(
            zm.normalise_project("org.apache.logging.log4j:log4j-core"),
            "log4j-core")
        # The npm scope is retained: it is part of the identity, not a path.
        self.assertEqual(zm.normalise_project("@babel/traverse"),
                         "babel-traverse")

    def test_repo_urls_compare_equal_across_forms(self):
        expected = "github.com/htmlunit/htmlunit"
        for url in ("https://github.com/HtmlUnit/htmlunit.git",
                    "git@github.com:HtmlUnit/htmlunit.git",
                    "github.com/htmlunit/htmlunit/"):
            self.assertEqual(zm.normalise_repo_url(url), expected)


class TestCorrelationTiers(unittest.TestCase):

    def test_t0_matches_project_name_only(self):
        [finding] = parse_cvd([CVD_REVEALED])
        hits = zm.correlate_finding(finding, COMPONENTS)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["component"]["name"], "libexpat")
        self.assertEqual(hits[0]["tier"], zm.TIER_PROJECT)
        # Over-inclusive by design, so it is never reported as verified.
        self.assertFalse(hits[0]["verified"])

    def test_t1_matches_repository_for_a_commit_range_finding(self):
        finding = zf._from_osv(OSSFUZZ_RECORD, source="ossfuzz")
        hits = zm.correlate_finding(finding, COMPONENTS)
        self.assertEqual([h["tier"] for h in hits], [zm.TIER_COMMIT])
        self.assertEqual(hits[0]["component"]["name"], "htmlunit")
        # No commit recorded in the SBOM, so confidence is reduced and the
        # reason says why rather than asserting a match it cannot prove.
        self.assertIn("no commit", hits[0]["reason"])
        self.assertLess(hits[0]["confidence"],
                        zm.TIER_CONFIDENCE[zm.TIER_COMMIT])

    def test_t1_confirms_when_the_sbom_records_the_introducing_commit(self):
        finding = zf._from_osv(OSSFUZZ_RECORD, source="ossfuzz")
        pinned = dict(COMPONENTS[2],
                      commit="69f12908fca8b940fa6cd114b0266b909fca0c1a")
        matched, confidence, reason = zm.match_commit(finding, pinned)
        self.assertTrue(matched)
        self.assertEqual(confidence, zm.TIER_CONFIDENCE[zm.TIER_COMMIT])
        self.assertIn("introducing commit", reason)

    def test_t1_clears_a_component_pinned_at_the_fix(self):
        finding = zf._from_osv(OSSFUZZ_RECORD, source="ossfuzz")
        fixed = dict(COMPONENTS[2],
                     commit="b750ca63a80698eddef3fc3457911bc21a825b58")
        matched, _confidence, _reason = zm.match_commit(finding, fixed)
        self.assertFalse(matched)

    def test_t3_evaluates_the_version_range(self):
        finding = zf.PreDisclosureFinding.make(
            source="ghsa", source_id="GHSA-x", stage=zf.STAGE_REVEALED,
            evidence_tier=zm.TIER_PURL,
            affected_ranges=[{
                "package": {"name": "lodash", "ecosystem": "npm"},
                "ranges": [{"type": "ECOSYSTEM",
                            "events": [{"introduced": "0"},
                                       {"fixed": "4.17.21"}]}],
            }])
        matched, confidence, _reason = zm.match_purl(finding, COMPONENTS[0])
        self.assertTrue(matched)
        self.assertEqual(confidence, zm.TIER_CONFIDENCE[zm.TIER_PURL])

        patched = dict(COMPONENTS[0], version="4.17.21",
                       purl="pkg:npm/lodash@4.17.21")
        matched, _c, _r = zm.match_purl(finding, patched)
        self.assertFalse(matched)

    def test_component_version_beats_a_stale_purl_version(self):
        finding = zf.PreDisclosureFinding.make(
            source="ghsa", source_id="GHSA-w", stage=zf.STAGE_REVEALED,
            evidence_tier=zm.TIER_PURL,
            affected_ranges=[{
                "package": {"name": "lodash", "ecosystem": "npm"},
                "ranges": [{"type": "ECOSYSTEM",
                            "events": [{"introduced": "0"},
                                       {"fixed": "4.17.21"}]}],
            }])
        # PURL still says 4.17.19; the resolved version has moved past the fix.
        upgraded = dict(COMPONENTS[0], version="4.17.21")
        matched, _c, _r = zm.match_purl(finding, upgraded)
        self.assertFalse(matched)

    def test_t3_does_not_assert_a_range_against_a_constraint(self):
        finding = zf.PreDisclosureFinding.make(
            source="ghsa", source_id="GHSA-y", stage=zf.STAGE_REVEALED,
            evidence_tier=zm.TIER_PURL,
            affected_ranges=[{
                "package": {"name": "lodash", "ecosystem": "npm"},
                "ranges": [{"type": "ECOSYSTEM",
                            "events": [{"introduced": "0"},
                                       {"fixed": "4.17.21"}]}],
            }])
        constrained = dict(COMPONENTS[0], version="^4.17.19", purl=None)
        matched, confidence, reason = zm.match_purl(finding, constrained)
        self.assertTrue(matched)
        self.assertIn("constraint", reason)
        self.assertLess(confidence, zm.TIER_CONFIDENCE[zm.TIER_PURL])

    def test_scoped_npm_packages_do_not_collapse_together(self):
        # Observed against the live GHSA feed: one advisory for @tiptap/core
        # matched @babel/core, @eslint/core, @vueuse/core and four others at
        # 1.00, because the scope was being discarded before comparison.
        names = ["@tiptap/core", "@babel/core", "@vueuse/core", "@eslint/core"]
        normalised = [zm.normalise_project(n) for n in names]
        self.assertEqual(len(set(normalised)), len(names))

    def test_precise_findings_do_not_fall_back_to_fuzzy_matching(self):
        # A GHSA advisory names its package exactly. If that package is not in
        # the inventory the answer is "not affected" -- never a name match
        # against a different package that happens to look similar.
        finding = zf.PreDisclosureFinding.make(
            source="ghsa", source_id="GHSA-j95f-988m-3j2f",
            stage=zf.STAGE_REVEALED, evidence_tier=zm.TIER_PURL,
            project="@tiptap/core", package_name="@tiptap/core",
            ecosystem="npm", purl="pkg:npm/@tiptap/core",
            affected_ranges=[{
                "package": {"name": "@tiptap/core", "ecosystem": "npm"},
                "ranges": [{"type": "ECOSYSTEM",
                            "events": [{"introduced": "0"},
                                       {"fixed": "3.0.0"}]}],
            }])
        unrelated = {"name": "@vueuse/core", "version": "12.8.2",
                     "ecosystem": "npm", "purl": "pkg:npm/@vueuse/core@12.8.2"}
        self.assertEqual(zm.correlate_finding(finding, [unrelated]), [])

    def test_product_matching_respects_ecosystem(self):
        # A Packagist advisory cannot affect a PyPI package.
        finding = zf.PreDisclosureFinding.make(
            source="euvd", source_id="EUVD-1", stage=zf.STAGE_IDENTIFIED,
            evidence_tier=zm.TIER_PRODUCT, project="predis/predis",
            ecosystem="Packagist")
        redis = {"name": "redis", "version": "4.5.4", "ecosystem": "PyPI"}
        matched, _c, _r = zm.match_product(finding, redis)
        self.assertFalse(matched)

    def test_trailing_digit_names_are_not_the_same_package(self):
        # httpx2 vs httpx scores 0.91. That is how a typosquat is built.
        finding = zf.PreDisclosureFinding.make(
            source="euvd", source_id="EUVD-2", stage=zf.STAGE_IDENTIFIED,
            evidence_tier=zm.TIER_PRODUCT, project="httpx2")
        httpx = {"name": "httpx", "version": "0.28.1", "ecosystem": "PyPI"}
        matched, _c, _r = zm.match_product(finding, httpx)
        self.assertFalse(matched)

    def test_sealed_commitments_are_never_correlated(self):
        findings = parse_cvd([CVD_SEALED])
        results = zm.correlate(findings, {"org/app": COMPONENTS})
        self.assertEqual(results, [])

    def test_short_near_miss_names_do_not_match(self):
        # Observed against the real ledger: htslib (C bioinformatics) scored
        # 0.91 against tslib (TypeScript runtime helper) and produced two false
        # positives. Short near-misses are typosquat territory, not evidence.
        finding = zf.PreDisclosureFinding.make(
            source="cvd", source_id="ANT-2026-H4RM2RMD",
            stage=zf.STAGE_REVEALED, evidence_tier=zm.TIER_PROJECT,
            project="htslib")
        tslib = {"name": "tslib", "version": "2.8.1", "ecosystem": "npm",
                 "purl": "pkg:npm/tslib@2.8.1"}
        matched, _c, _r = zm.match_project(finding, tslib)
        self.assertFalse(matched)

    def test_long_names_may_still_match_fuzzily(self):
        finding = zf.PreDisclosureFinding.make(
            source="cvd", source_id="ANT-x", stage=zf.STAGE_REVEALED,
            evidence_tier=zm.TIER_PROJECT, project="apache-commons-compress")
        component = {"name": "apache-commons-compres", "ecosystem": "Maven"}
        matched, _c, _r = zm.match_project(finding, component)
        self.assertTrue(matched)

    def test_t0_stands_down_once_an_identifier_exists(self):
        # The published OSV path matches this precisely on PURL and version,
        # so a name match adds noise rather than coverage.
        finding = zf.PreDisclosureFinding.make(
            source="cvd", source_id="ANT-y", stage=zf.STAGE_PATCHED,
            evidence_tier=zm.TIER_PROJECT, project="libexpat",
            cve_ids=["CVE-2026-62257"])
        matched, _c, _r = zm.match_project(finding, COMPONENTS[1])
        self.assertFalse(matched)

    def test_short_project_names_do_not_fire_at_t0(self):
        finding = zf.PreDisclosureFinding.make(
            source="cvd", source_id="ANT-x", stage=zf.STAGE_REVEALED,
            evidence_tier=zm.TIER_PROJECT, project="go")
        self.assertEqual(zm.correlate_finding(finding, COMPONENTS), [])


class TestDegradedScoring(unittest.TestCase):

    def test_consensus_prefers_maintainer(self):
        [finding] = parse_cvd([CVD_REVEALED])
        score, band, basis = zs.consensus_severity(finding)
        self.assertEqual(band, "critical")
        self.assertEqual(score, zs.SEVERITY_TO_CVSS["critical"])
        self.assertIn("maintainer", basis)
        self.assertIn("differed", basis)

    def test_missing_severity_assumes_medium_not_zero(self):
        finding = zf.PreDisclosureFinding.make(
            source="cvd", source_id="ANT-z", stage=zf.STAGE_REVEALED,
            evidence_tier=zm.TIER_PROJECT)
        score, band, basis = zs.consensus_severity(finding)
        self.assertEqual(band, "medium")
        self.assertGreater(score, 0)
        self.assertIn("assumed", basis)

    def test_revealed_and_unpatched_is_the_worst_prior(self):
        revealed = zf.PreDisclosureFinding.make(
            source="cvd", source_id="a", stage=zf.STAGE_REVEALED,
            evidence_tier=zm.TIER_PROJECT, patched=False)
        patched = zf.PreDisclosureFinding.make(
            source="cvd", source_id="b", stage=zf.STAGE_PATCHED,
            evidence_tier=zm.TIER_PROJECT, patched=True)
        self.assertGreater(zs.disclosure_prior(revealed)[0],
                           zs.disclosure_prior(patched)[0])

    def test_kev_overrides_the_stage_prior(self):
        finding = zf.PreDisclosureFinding.make(
            source="cvd", source_id="c", stage=zf.STAGE_PATCHED,
            evidence_tier=zm.TIER_PROJECT, patched=True, exploited=True)
        prior, basis = zs.disclosure_prior(finding)
        self.assertEqual(prior, zs.KEV_PRIOR)
        self.assertIn("exploited", basis)

    def test_substitutions_are_recorded(self):
        [finding] = parse_cvd([CVD_REVEALED])
        scored = zs.score_exposure(finding, criticality=0.8,
                                   tier=zm.TIER_PROJECT)
        self.assertTrue(scored["degraded"])
        self.assertEqual(scored["substitutions"]["cvss"]["substituted_with"],
                         "Consensus Severity Proxy")
        self.assertEqual(scored["substitutions"]["epss"]["substituted_with"],
                         "Disclosure-Stage Prior")
        self.assertIn("proxied by", zs.explain(scored))

    def test_published_values_are_used_when_available(self):
        [finding] = parse_cvd([CVD_PATCHED])
        scored = zs.score_exposure(finding, criticality=0.8,
                                   tier=zm.TIER_PURL, cvss=9.8, epss=0.7)
        self.assertFalse(scored["degraded"])
        self.assertEqual(scored["substitutions"], {})

    def test_weak_evidence_is_discounted_below_strong_evidence(self):
        [finding] = parse_cvd([CVD_REVEALED])
        strong = zs.score_exposure(finding, 0.8, tier=zm.TIER_PURL)
        weak = zs.score_exposure(finding, 0.8, tier=zm.TIER_PROJECT)
        self.assertGreater(strong["score"], weak["score"])
        self.assertEqual(strong["undiscounted_score"],
                         weak["undiscounted_score"])

    def test_exploited_findings_rank_first_regardless_of_score(self):
        rows = [
            {"score": 9.5, "exploited": False, "evidence_tier": zm.TIER_PURL},
            {"score": 2.0, "exploited": True, "evidence_tier": zm.TIER_PROJECT},
        ]
        self.assertTrue(zs.rank(rows)[0]["exploited"])


class TestTierBreakdown(unittest.TestCase):

    def test_counts_are_reported_per_tier(self):
        findings = parse_cvd([CVD_REVEALED]) + \
            [zf._from_osv(OSSFUZZ_RECORD, source="ossfuzz")]
        results = zm.correlate(findings, {"org/app": COMPONENTS})
        breakdown = zm.tier_breakdown(results)
        self.assertEqual(breakdown[zm.TIER_PROJECT], 1)
        self.assertEqual(breakdown[zm.TIER_COMMIT], 1)
        self.assertEqual(breakdown[zm.TIER_PURL], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
