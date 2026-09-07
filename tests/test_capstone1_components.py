"""
Tests for the Capstone 1 architecture components:
SBOM quality gate, CPE fuzzy matching, dependency graph traversal,
and multi-format SBOM parsing.

No network, no database, no third-party test framework.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sbom_c2 import cpe, cvss, depgraph, quality, sbom_formats  # noqa: E402


GOOD = [
    {"name": "lodash", "version": "4.17.19", "ecosystem": "npm",
     "purl": "pkg:npm/lodash@4.17.19"},
    {"name": "axios", "version": "0.21.0", "ecosystem": "npm",
     "purl": "pkg:npm/axios@0.21.0"},
]
BAD = [
    {"name": "mystery", "version": None, "ecosystem": None},
    {"name": "unknown", "version": None, "ecosystem": None},
]


class TestQualityGate(unittest.TestCase):
    def test_complete_sbom_passes(self):
        result = quality.assess(GOOD)
        self.assertTrue(result.passed)
        self.assertEqual(result.dimensions["identifier_coverage"], 1.0)
        self.assertEqual(result.rejected, [])

    def test_sbom_without_identifiers_fails(self):
        result = quality.assess(BAD)
        self.assertFalse(result.passed)
        self.assertEqual(result.dimensions["identifier_coverage"], 0.0)
        self.assertTrue(any("PURL or CPE" in i for i in result.issues))

    def test_empty_sbom_fails_cleanly(self):
        result = quality.assess([])
        self.assertFalse(result.passed)
        self.assertEqual(result.score, 0.0)

    def test_cpe_alone_is_sufficient(self):
        result = quality.assess([
            {"name": "log4j", "version": "2.14.1", "ecosystem": "Maven",
             "cpe": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"}])
        self.assertTrue(result.passed)

    def test_admissible_splits_without_discarding(self):
        admitted, rejected = quality.admissible(GOOD + BAD)
        self.assertEqual(len(admitted), 2)
        self.assertEqual(len(rejected), 2)
        self.assertEqual(len(admitted) + len(rejected), 4)


class TestCPE(unittest.TestCase):
    def test_parse_cpe23(self):
        f = cpe.parse_cpe("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*")
        self.assertEqual(f["vendor"], "apache")
        self.assertEqual(f["product"], "log4j")
        self.assertEqual(f["version"], "2.14.1")
        self.assertEqual(f["part_name"], "application")

    def test_wildcards_become_none(self):
        f = cpe.parse_cpe("cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*")
        self.assertIsNone(f["version"])

    def test_legacy_cpe22(self):
        f = cpe.parse_cpe("cpe:/a:apache:log4j:2.14.1")
        self.assertEqual(f["product"], "log4j")

    def test_non_cpe_returns_none(self):
        self.assertIsNone(cpe.parse_cpe("pkg:npm/lodash@4.17.19"))
        self.assertIsNone(cpe.parse_cpe(None))

    def test_matches_qualified_maven_name(self):
        matched, score, _ = cpe.match(
            "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
            {"name": "org.apache.logging.log4j:log4j-core", "ecosystem": "Maven"})
        self.assertTrue(matched)
        self.assertGreater(score, 0.9)

    def test_rejects_unrelated_product(self):
        matched, score, _ = cpe.match(
            "cpe:2.3:a:redhat:openssl:1.0:*:*:*:*:*:*:*",
            {"name": "org.apache.logging.log4j:log4j-core", "ecosystem": "Maven"})
        self.assertFalse(matched)
        self.assertLess(score, 0.5)

    def test_best_match_picks_highest(self):
        best, score = cpe.best_match(
            ["cpe:2.3:a:redhat:openssl:1.0:*:*:*:*:*:*:*",
             "cpe:2.3:a:lodash:lodash:4.17.19:*:*:*:*:*:*:*"],
            {"name": "lodash", "ecosystem": "npm"})
        self.assertIn("lodash", best)
        self.assertGreater(score, 0.9)


class TestReverseGraph(unittest.TestCase):
    def setUp(self):
        self.graph = depgraph.ReverseDependencyGraph.build({
            "payments-api": [
                {"name": "lodash", "ecosystem": "npm", "version": "4.17.19"},
                {"name": "axios", "ecosystem": "npm", "version": "0.21.0"}],
            "marketing-site": [
                {"name": "lodash", "ecosystem": "npm", "version": "4.17.19"}],
            "analytics-batch": [
                {"name": "PyYAML", "ecosystem": "PyPI", "version": "5.3.1"}],
        })

    def test_finds_all_repositories_containing_component(self):
        repos = self.graph.repositories_containing("npm", "lodash")
        self.assertEqual(repos, ["marketing-site", "payments-api"])

    def test_blast_radius_counts_repositories(self):
        blast = self.graph.blast_radius("npm", "lodash")
        self.assertEqual(blast["repository_count"], 2)
        self.assertEqual(blast["versions_present"], ["4.17.19"])

    def test_unknown_component_is_empty_not_error(self):
        self.assertEqual(self.graph.repositories_containing("npm", "nope"), [])

    def test_shared_components_excludes_singletons(self):
        shared = self.graph.shared_components(minimum=2)
        self.assertEqual(len(shared), 1)
        self.assertEqual(shared[0]["repository_count"], 2)

    def test_matching_is_case_insensitive(self):
        self.assertEqual(
            self.graph.repositories_containing("NPM", "LODASH"),
            ["marketing-site", "payments-api"])


SPDX_WITH_CHAINS = {
    "spdxVersion": "SPDX-2.3",
    "documentDescribes": ["SPDXRef-app"],
    "packages": [
        {"SPDXID": "SPDXRef-app", "name": "payments-api"},
        {"SPDXID": "SPDXRef-webpack", "name": "webpack"},
        {"SPDXID": "SPDXRef-lodash", "name": "lodash"},
    ],
    "relationships": [
        {"spdxElementId": "SPDXRef-app", "relatedSpdxElement": "SPDXRef-webpack",
         "relationshipType": "DEPENDS_ON"},
        {"spdxElementId": "SPDXRef-webpack", "relatedSpdxElement": "SPDXRef-lodash",
         "relationshipType": "DEPENDS_ON"},
    ],
}


class TestDependencyChains(unittest.TestCase):
    def test_reconstructs_transitive_chain(self):
        graph = depgraph.DependencyChainGraph.from_spdx(SPDX_WITH_CHAINS)
        self.assertTrue(graph.has_relationships)
        self.assertEqual(graph.chain_to("lodash"),
                         ["payments-api", "webpack", "lodash"])

    def test_depth_and_directness(self):
        graph = depgraph.DependencyChainGraph.from_spdx(SPDX_WITH_CHAINS)
        self.assertEqual(graph.depth_of("lodash"), 2)
        self.assertFalse(graph.is_direct("lodash"))
        self.assertTrue(graph.is_direct("webpack"))

    def test_flat_sbom_returns_none_not_a_fabricated_chain(self):
        graph = depgraph.DependencyChainGraph.from_spdx(
            {"packages": [{"SPDXID": "a", "name": "lodash"}]})
        self.assertFalse(graph.has_relationships)
        self.assertIsNone(graph.chain_to("lodash"))
        self.assertIsNone(graph.depth_of("lodash"))

    def test_unknown_component_has_no_chain(self):
        graph = depgraph.DependencyChainGraph.from_spdx(SPDX_WITH_CHAINS)
        self.assertIsNone(graph.chain_to("not-present"))


class TestSBOMFormats(unittest.TestCase):
    CYCLONEDX = {
        "bomFormat": "CycloneDX", "specVersion": "1.4",
        "metadata": {"tools": [{"name": "syft", "version": "1.0"}],
                     "component": {"name": "payments-api"}},
        "components": [
            {"name": "lodash", "version": "4.17.19",
             "purl": "pkg:npm/lodash@4.17.19",
             "cpe": "cpe:2.3:a:lodash:lodash:4.17.19:*:*:*:*:*:*:*"}],
    }

    def test_detects_cyclonedx(self):
        self.assertEqual(sbom_formats.detect_format(self.CYCLONEDX), "cyclonedx")

    def test_detects_spdx(self):
        self.assertEqual(sbom_formats.detect_format(SPDX_WITH_CHAINS), "spdx")

    def test_rejects_unknown_format(self):
        with self.assertRaises(sbom_formats.UnsupportedSBOM):
            sbom_formats.detect_format({"something": "else"})

    def test_cyclonedx_parses_purl_and_cpe(self):
        components, meta = sbom_formats.parse(self.CYCLONEDX)
        self.assertEqual(meta["format"], "CycloneDX")
        self.assertEqual(components[0]["ecosystem"], "npm")
        self.assertTrue(components[0]["cpe"])

    def test_spdx_skips_repository_root_package(self):
        doc = {"spdxVersion": "SPDX-2.3", "packages": [
            {"SPDXID": "a", "name": "com.github.org/payments-api"},
            {"SPDXID": "b", "name": "npm:lodash", "versionInfo": "4.17.19",
             "externalRefs": [{"referenceType": "purl",
                               "referenceLocator": "pkg:npm/lodash@4.17.19"}]}]}
        components, _ = sbom_formats.parse(doc)
        self.assertEqual(len(components), 1)
        self.assertEqual(components[0]["name"], "lodash")

    def test_spdx_extracts_cpe_external_ref(self):
        doc = {"spdxVersion": "SPDX-2.3", "packages": [
            {"SPDXID": "b", "name": "log4j-core", "versionInfo": "2.14.1",
             "externalRefs": [{"referenceType": "cpe23Type",
                               "referenceLocator":
                                   "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"}]}]}
        components, _ = sbom_formats.parse(doc)
        self.assertTrue(components[0]["cpe"])


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestCVSS(unittest.TestCase):
    """Base scores must match the published NVD values, not approximate them."""

    PUBLISHED = [
        ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", 7.2),   # CVE-2021-23337
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),  # Log4Shell
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),   # minimist
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 8.8),   # babel traverse
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5),   # qs ReDoS
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N", 5.9),   # lodash pollution
        ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", 6.4),   # scope changed
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),   # no impact
    ]

    def test_matches_published_scores(self):
        for vector, expected in self.PUBLISHED:
            self.assertAlmostEqual(cvss.base_score(vector), expected, places=1,
                                   msg=vector)

    def test_scope_changed_uses_different_privilege_weights(self):
        """Scope Changed must score higher than the identical Unchanged vector."""
        changed = cvss.base_score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H")
        unchanged = cvss.base_score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H")
        self.assertGreater(changed, unchanged)

    def test_attack_complexity_lowers_score(self):
        easy = cvss.base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        hard = cvss.base_score("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H")
        self.assertGreater(easy, hard)

    def test_vector_without_prefix_accepted(self):
        self.assertAlmostEqual(
            cvss.base_score("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8, places=1)

    def test_incomplete_vector_rejected(self):
        with self.assertRaises(cvss.InvalidVector):
            cvss.base_score("CVSS:3.1/AV:N/AC:L")

    def test_severity_bands(self):
        self.assertEqual(cvss.severity(9.8), "CRITICAL")
        self.assertEqual(cvss.severity(7.2), "HIGH")
        self.assertEqual(cvss.severity(5.5), "MEDIUM")
        self.assertEqual(cvss.severity(2.0), "LOW")

    def test_advisory_records_how_score_was_obtained(self):
        """A computed score and an estimated one must be distinguishable."""
        computed = cvss.score_from_advisory({"severity": [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]})
        self.assertEqual(computed[2], "vector")
        estimated = cvss.score_from_advisory(
            {"database_specific": {"severity": "MODERATE"}})
        self.assertEqual(estimated[2], "qualitative")
        self.assertEqual(cvss.score_from_advisory({})[2], None)
