"""
Tests for the impact-measurement arithmetic.

Uses lightweight stand-ins rather than the ORM, so these run without a database
or SQLAlchemy installed -- the arithmetic is what can be wrong, not the storage.
"""

import datetime as dt
import os
import sys
import types
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sbom_c2 import impact  # noqa: E402


def exposure(state, detected_hours_ago=None, resolved_hours_ago=None, score=5.0):
    now = dt.datetime.now(dt.timezone.utc)
    return types.SimpleNamespace(
        state=state,
        business_score=score,
        detected_at=(now - dt.timedelta(hours=detected_hours_ago)
                     if detected_hours_ago is not None else None),
        resolved_at=(now - dt.timedelta(hours=resolved_hours_ago)
                     if resolved_hours_ago is not None else None),
    )


class TestMTTR(unittest.TestCase):
    def test_single_resolved_finding(self):
        mttr, n = impact.mean_time_to_remediate(
            [exposure("resolved", detected_hours_ago=10, resolved_hours_ago=4)])
        self.assertEqual(n, 1)
        self.assertAlmostEqual(mttr, 6.0, places=1)

    def test_mean_across_findings(self):
        mttr, n = impact.mean_time_to_remediate([
            exposure("resolved", 10, 4),   # 6h
            exposure("resolved", 20, 8),   # 12h
        ])
        self.assertEqual(n, 2)
        self.assertAlmostEqual(mttr, 9.0, places=1)

    def test_open_findings_excluded(self):
        mttr, n = impact.mean_time_to_remediate([
            exposure("open", 10, None),
            exposure("resolved", 10, 4),
        ])
        self.assertEqual(n, 1)

    def test_no_resolved_findings_reports_none(self):
        mttr, n = impact.mean_time_to_remediate([exposure("open", 5)])
        self.assertIsNone(mttr)
        self.assertEqual(n, 0)

    def test_impossible_ordering_ignored(self):
        """Resolved before detected would poison the mean; drop it instead."""
        mttr, n = impact.mean_time_to_remediate(
            [exposure("resolved", detected_hours_ago=2, resolved_hours_ago=9)])
        self.assertEqual(n, 0)

    def test_naive_datetimes_do_not_crash(self):
        """SQLite returns naive datetimes; subtraction must still work."""
        naive = types.SimpleNamespace(
            state="resolved", business_score=5.0,
            detected_at=dt.datetime(2026, 9, 1, 10, 0),
            resolved_at=dt.datetime(2026, 9, 1, 16, 0))
        mttr, n = impact.mean_time_to_remediate([naive])
        self.assertEqual(n, 1)
        self.assertAlmostEqual(mttr, 6.0, places=1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
