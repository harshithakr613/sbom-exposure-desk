"""
Tests for the Capstone 2 remediation ladder and fix worklist.

Written deliberately against the awkward shapes rather than the happy path,
because those are what the demonstration database actually contains: findings
with no patch, no identifier and no bug class; repositories mapped to no
business process at all; and processes that span several repositories.

No network, no database, no third-party test framework.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sbom_c2 import worklist                            # noqa: E402
from sbom_c2 import zeroday_feeds as zf                 # noqa: E402
from sbom_c2 import zeroday_remediation as zr           # noqa: E402


PAYMENTS = {"name": "Payment Processing", "owner": "Priya N",
            "revenue_dependency": "direct", "customer_facing": True,
            "availability_requirement": "critical",
            "data_sensitivity": "regulated", "regulatory_scope": "PCI-DSS,GDPR"}
PATIENTS = {"name": "Patient Records Access", "owner": "Arjun M",
            "revenue_dependency": "indirect", "customer_facing": False,
            "availability_requirement": "high",
            "data_sensitivity": "regulated", "regulatory_scope": "HIPAA,GDPR"}
LOGGING = {"name": "Internal Logging", "owner": "Ops",
           "revenue_dependency": "none", "customer_facing": False,
           "availability_requirement": "low",
           "data_sensitivity": "internal", "regulatory_scope": ""}


def finding(stage=zf.STAGE_REVEALED, **kw):
    base = dict(source="cvd", source_id="ANT-2026-TEST", stage=stage,
                evidence_tier="T0_PROJECT", project="libexpat",
                package_name="libexpat", bug_class="path-traversal")
    base.update(kw)
    return zf.PreDisclosureFinding.make(**base)


class TestLadderStages(unittest.TestCase):

    def test_revealed_with_no_patch_is_flagged_as_the_gap(self):
        plan = zr.remediation_plan(finding(), repository="org/payments",
                                   processes=[PAYMENTS])
        self.assertEqual(plan["stage_label"], "T1")
        self.assertTrue(plan["is_the_gap"])
        self.assertFalse(plan["patch_available"])

    def test_the_gap_states_what_is_blocked_and_why(self):
        plan = zr.remediation_plan(finding(), repository="org/payments",
                                   processes=[PAYMENTS])
        blocked = " ".join(plan["blocked"]).lower()
        self.assertIn("no fixed version", blocked)
        self.assertIn("dependabot cannot act", blocked)
        self.assertIn("no cve or ghsa", blocked)

    def test_commitment_stage_offers_no_asset_level_action(self):
        plan = zr.remediation_plan(finding(stage=zf.STAGE_COMMITMENT,
                                           project=None))
        self.assertEqual(plan["stage_label"], "T0")
        self.assertEqual(plan["urgency"], "watch")
        self.assertIn("No project is published", " ".join(plan["blocked"]))

    def test_a_published_fix_leads_the_plan(self):
        plan = zr.remediation_plan(
            finding(stage=zf.STAGE_PATCHED, fixed_version="2.6.1"),
            repository="org/payments", processes=[PAYMENTS])
        self.assertEqual(plan["stage_label"], "T3")
        self.assertTrue(plan["patch_available"])
        self.assertIn("Upgrade to 2.6.1", plan["actions"][0]["action"])
        self.assertEqual(plan["blocked"], [])

    def test_identifier_enables_the_native_handoff(self):
        plan = zr.remediation_plan(
            finding(stage=zf.STAGE_IDENTIFIED, cve_ids=["CVE-2026-1"]),
            repository="org/payments", processes=[PAYMENTS])
        actions = " ".join(a["action"] for a in plan["actions"])
        self.assertIn("Link the native security alert", actions)


class TestCompensatingControls(unittest.TestCase):

    def test_advice_is_specific_to_the_bug_class(self):
        controls = zr.compensating_controls("path-traversal")
        self.assertTrue(any("path separators" in c for c in controls))

    def test_memory_safety_classes_share_a_response(self):
        for cls in ("heap-buffer-overflow", "use-after-free", "oob-read"):
            controls = zr.compensating_controls(cls)
            self.assertTrue(any("untrusted input" in c for c in controls), cls)

    def test_unknown_or_missing_bug_class_still_yields_advice(self):
        # The ledger sometimes publishes no bug class at all. Returning nothing
        # would leave the one stage that needs guidance with none.
        for value in (None, "", "something-nobody-has-seen"):
            self.assertTrue(zr.compensating_controls(value))


class TestUrgency(unittest.TestCase):

    def test_confirmed_exploitation_overrides_business_context(self):
        plan = zr.remediation_plan(finding(exploited=True),
                                   repository="org/logs", processes=[LOGGING])
        self.assertEqual(plan["urgency"], "immediate")
        self.assertIn("KEV", plan["urgency_reason"])

    def test_revenue_critical_and_unpatchable_is_immediate(self):
        plan = zr.remediation_plan(finding(), repository="org/payments",
                                   processes=[PAYMENTS])
        self.assertEqual(plan["urgency"], "immediate")
        self.assertIn("Payment Processing", plan["urgency_reason"])

    def test_regulated_and_unpatchable_is_high(self):
        plan = zr.remediation_plan(finding(), repository="org/patients",
                                   processes=[PATIENTS])
        self.assertEqual(plan["urgency"], "high")

    def test_internal_process_is_not_urgent(self):
        plan = zr.remediation_plan(finding(fixed_version="1.2.3"),
                                   repository="org/logs", processes=[LOGGING])
        self.assertEqual(plan["urgency"], "planned")

    def test_unmapped_repository_does_not_crash(self):
        # Every repository in the demonstration organisation starts unmapped.
        plan = zr.remediation_plan(finding(), repository="org/unknown",
                                   processes=[])
        self.assertIn(plan["urgency"], zr.URGENCY_ORDER)


class TestAlerts(unittest.TestCase):

    def test_only_actionable_findings_raise_an_alert(self):
        quiet = zr.remediation_plan(finding(fixed_version="1.0.1"),
                                    repository="org/logs", processes=[LOGGING])
        self.assertIsNone(zr.alert_for(quiet, finding()))

        loud = zr.remediation_plan(finding(), repository="org/payments",
                                   processes=[PAYMENTS])
        alert = zr.alert_for(loud, finding(), exposure_id=7)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["exposure_id"], 7)

    def test_headline_names_the_package_and_the_absence_of_a_patch(self):
        plan = zr.remediation_plan(finding(), repository="org/payments",
                                   processes=[PAYMENTS])
        alert = zr.alert_for(plan, finding())
        self.assertIn("libexpat", alert["headline"])
        self.assertIn("no patch available", alert["headline"])

    def test_summary_counts_the_unpatchable_population(self):
        plans = [zr.remediation_plan(finding(), repository="r",
                                     processes=[PAYMENTS]),
                 zr.remediation_plan(finding(stage=zf.STAGE_PATCHED,
                                             fixed_version="2.0"),
                                     repository="r", processes=[LOGGING])]
        s = zr.summarise(plans)
        self.assertEqual(s["total"], 2)
        self.assertEqual(s["unpatchable"], 1)


class TestWorklist(unittest.TestCase):

    def items(self):
        return [
            {"repository": "org/logs", "component": "lodash",
             "patch_available": True, "exploited": False, "score": 9.1,
             "processes": [LOGGING]},
            {"repository": "org/payments", "component": "libexpat",
             "patch_available": False, "exploited": False, "score": 4.2,
             "processes": [PAYMENTS]},
            {"repository": "org/patients", "component": "joi",
             "patch_available": False, "exploited": False, "score": 5.0,
             "processes": [PATIENTS]},
            {"repository": "org/orphan", "component": "svgo",
             "patch_available": True, "exploited": False, "score": 8.0,
             "processes": []},
        ]

    def test_business_consequence_outranks_technical_score(self):
        rows, _ = worklist.build(self.items())
        # The payments finding scores 4.2 against 9.1 for the internal utility,
        # and must still come first.
        self.assertEqual(rows[0]["repository"], "org/payments")
        self.assertEqual(rows[-1]["repository"], "org/logs")

    def test_every_position_states_its_reason(self):
        rows, _ = worklist.build(self.items())
        for row in rows:
            self.assertTrue(row["reason"])
            self.assertIn(row["reason_code"], worklist.REASON_RANK)

    def test_exploitation_takes_the_top_slot(self):
        items = self.items()
        items[0]["exploited"] = True          # the internal utility
        rows, _ = worklist.build(items)
        self.assertEqual(rows[0]["repository"], "org/logs")
        self.assertIn("exploited", rows[0]["reason"].lower())

    def test_unmapped_is_reported_as_unknown_not_low(self):
        rows, summary = worklist.build(self.items())
        orphan = [r for r in rows if r["repository"] == "org/orphan"][0]
        self.assertEqual(orphan["reason_code"], "unmapped")
        self.assertIn("unknown rather than low", orphan["reason"])
        self.assertEqual(summary["unmapped_repositories"], 1)

    def test_score_breaks_ties_within_the_same_reason(self):
        a = dict(self.items()[1], component="a", score=3.0)
        b = dict(self.items()[1], component="b", score=7.0)
        rows, _ = worklist.build([a, b])
        self.assertEqual(rows[0]["component"], "b")

    def test_list_is_capped_and_positions_are_sequential(self):
        rows, summary = worklist.build(self.items() * 5, size=6)
        self.assertEqual(len(rows), 6)
        self.assertEqual([r["position"] for r in rows], [1, 2, 3, 4, 5, 6])
        self.assertEqual(summary["total_candidates"], 20)

    def test_empty_input_is_handled(self):
        rows, summary = worklist.build([])
        self.assertEqual(rows, [])
        self.assertEqual(summary["total_candidates"], 0)


class TestManyToManyContext(unittest.TestCase):

    def test_a_repository_supporting_several_processes_takes_the_worst(self):
        # A shared library under both payments and internal logging is a
        # payments risk; averaging would dilute exactly that signal.
        plan = zr.remediation_plan(finding(), repository="org/shared",
                                   processes=[LOGGING, PAYMENTS])
        self.assertEqual(plan["urgency"], "immediate")
        self.assertIn("Payment Processing", plan["urgency_reason"])

    def test_all_supported_processes_are_reported(self):
        plan = zr.remediation_plan(finding(), repository="org/shared",
                                   processes=[LOGGING, PAYMENTS])
        self.assertEqual(set(plan["processes"]),
                         {"Internal Logging", "Payment Processing"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
