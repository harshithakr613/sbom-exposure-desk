"""
Risk-reduction impact measurement (Objective 4).

Turns remediation events into the two audiences' numbers:
  * operations  -- open vs resolved, fix rate, Mean Time to Remediate
  * executive   -- business risk eliminated, processes protected,
                   compliance exposure reduced

"Business risk" here is the sum of business-aware scores. Summing scores is a
deliberate simplification and should be described as an index rather than a
quantity: it is monotonic in the thing we care about (high-scoring findings on
critical processes contribute most) without pretending to be a currency value.
"""

import datetime as dt

# The ORM models are imported lazily inside the functions that touch the
# database, so the arithmetic in this module stays importable -- and testable --
# without SQLAlchemy present.


def _now():
    return dt.datetime.now(dt.timezone.utc)


def _aware(value):
    """SQLite hands back naive datetimes; normalise before subtracting."""
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=dt.timezone.utc)
    return value


def mean_time_to_remediate(exposures):
    """
    Mean hours between detection and resolution, over resolved findings only.

    Returns (mttr_hours, sample_size). A small sample is reported honestly
    rather than hidden, because on a demonstration organisation it will be
    small and the viva will ask.
    """
    durations = []
    for exposure in exposures:
        if exposure.state != "resolved":
            continue
        detected = _aware(exposure.detected_at)
        resolved = _aware(exposure.resolved_at)
        if not detected or not resolved or resolved < detected:
            continue
        durations.append((resolved - detected).total_seconds() / 3600.0)

    if not durations:
        return None, 0
    return round(sum(durations) / len(durations), 2), len(durations)


def compute_impact(session):
    """Compute the full impact picture from current state."""
    from .models import Exposure

    exposures = session.query(Exposure).all()

    open_ones = [e for e in exposures if e.state != "resolved"]
    resolved = [e for e in exposures if e.state == "resolved"]

    total = len(exposures)
    fix_rate = round(len(resolved) / total, 4) if total else 0.0
    mttr, sample = mean_time_to_remediate(exposures)

    risk_open = round(sum(e.business_score or 0.0 for e in open_ones), 2)
    risk_eliminated = round(sum(e.business_score or 0.0 for e in resolved), 2)

    # Business processes that no longer carry any open finding.
    protected, at_risk = _process_protection(session, open_ones)

    compliance_open = len({
        e.repository_id for e in open_ones
        if (e.compliance_factor or 1.0) > 1.0
    })

    by_tier = {}
    for exposure in open_ones:
        by_tier[exposure.tier or "UNSCORED"] = by_tier.get(exposure.tier or "UNSCORED", 0) + 1

    return {
        "generated_at": _now().isoformat(),
        "operations": {
            "total_findings": total,
            "open": len(open_ones),
            "resolved": len(resolved),
            "fix_rate": fix_rate,
            "mttr_hours": mttr,
            "mttr_sample_size": sample,
            "open_by_tier": by_tier,
        },
        "business": {
            "business_risk_open": risk_open,
            "business_risk_eliminated": risk_eliminated,
            "risk_reduction_pct": (
                round(risk_eliminated / (risk_open + risk_eliminated) * 100, 2)
                if (risk_open + risk_eliminated) else 0.0
            ),
            "processes_protected": len(protected),
            "processes_at_risk": len(at_risk),
            "protected_process_names": sorted(protected),
            "at_risk_process_names": sorted(at_risk),
            "repositories_in_regulatory_scope_with_open_findings": compliance_open,
        },
    }


def _process_protection(session, open_exposures):
    """Split business processes into those clean and those still exposed."""
    from .models import ProcessRepositoryLink

    repos_with_open = {e.repository_id for e in open_exposures}

    protected, at_risk = set(), set()
    for link in session.query(ProcessRepositoryLink).all():
        process = link.process
        if process is None:
            continue
        if link.repository_id in repos_with_open:
            at_risk.add(process.name)
        else:
            protected.add(process.name)
    # A process is only protected if none of its repositories is exposed.
    return protected - at_risk, at_risk


def capture_snapshot(session):
    """Persist the current metrics so the dashboard can plot a trend."""
    from .models import ImpactSnapshot

    impact = compute_impact(session)
    ops, biz = impact["operations"], impact["business"]

    snapshot = ImpactSnapshot(
        open_count=ops["open"],
        resolved_count=ops["resolved"],
        fix_rate=ops["fix_rate"],
        mttr_hours=ops["mttr_hours"],
        business_risk_open=biz["business_risk_open"],
        business_risk_eliminated=biz["business_risk_eliminated"],
        processes_protected=biz["processes_protected"],
        compliance_exposure_open=biz[
            "repositories_in_regulatory_scope_with_open_findings"],
    )
    session.add(snapshot)
    session.commit()
    return impact


def snapshot_history(session, limit=50):
    from .models import ImpactSnapshot

    rows = (session.query(ImpactSnapshot)
            .order_by(ImpactSnapshot.captured_at.desc()).limit(limit).all())
    return [
        {
            "captured_at": r.captured_at.isoformat() if r.captured_at else None,
            "open": r.open_count,
            "resolved": r.resolved_count,
            "fix_rate": r.fix_rate,
            "mttr_hours": r.mttr_hours,
            "business_risk_open": r.business_risk_open,
            "business_risk_eliminated": r.business_risk_eliminated,
        }
        for r in reversed(rows)
    ]
