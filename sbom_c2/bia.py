"""
Business Impact Analysis engine  (Capstone 2 - Objectives 1 & 2)

Pure logic: no I/O, no third-party imports. That keeps it unit-testable and
independent of the database or the GitHub API.

Capstone 1 scored an exposure as:
    composite = (CVSS/10 * 0.5) + (EPSS * 0.3) + (manual_tier * 0.2)

The criticality term there was a human-assigned tier. Capstone 2 keeps the same
three terms and the same weights, but *derives* criticality from a formal
business-context model and applies a compliance uplift for repositories in
regulatory scope.
"""

# --- attribute -> normalised value maps -------------------------------------
# These are the BIA impact scales. Every value lands in [0, 1] so the weighted
# sum is also in [0, 1] and stays comparable with CVSS/10 and EPSS.

REVENUE_DEPENDENCY = {"none": 0.0, "indirect": 0.5, "direct": 1.0}
AVAILABILITY_REQUIREMENT = {"low": 0.25, "medium": 0.5, "high": 0.75, "critical": 1.0}
DATA_SENSITIVITY = {"public": 0.0, "internal": 0.34, "confidential": 0.67, "regulated": 1.0}

# Weights for the business-criticality roll-up. Sum to 1.0.
CRITICALITY_WEIGHTS = {
    "revenue_dependency": 0.35,
    "customer_facing": 0.25,
    "availability_requirement": 0.25,
    "data_sensitivity": 0.15,
}

# Capstone 1 composite weights, retained unchanged.
SCORE_WEIGHTS = {"cvss": 0.5, "epss": 0.3, "criticality": 0.2}

COMPLIANCE_UPLIFT_PER_REGIME = 0.10
MAX_COMPLIANCE_UPLIFT = 0.25

TIER_THRESHOLDS = [(8.0, "CRITICAL"), (6.0, "HIGH"), (4.0, "MEDIUM")]

MANUAL_TIER_VALUES = {"critical": 1.0, "high": 0.75, "medium": 0.5, "low": 0.25}

# A repository with no business process mapped carries UNKNOWN risk, not LOW
# risk. Scoring it zero would sink it to the bottom of the queue and hide it --
# the precise failure this project exists to prevent. It is scored at the median
# instead and flagged, so it surfaces for mapping rather than disappearing.
UNMAPPED_CRITICALITY = 0.5


class BusinessContextError(ValueError):
    """Raised when a business process carries an attribute value we cannot score."""


def _lookup(table, value, field):
    key = str(value).strip().lower()
    if key not in table:
        raise BusinessContextError(
            "unknown %s value %r (expected one of %s)"
            % (field, value, ", ".join(sorted(table)))
        )
    return table[key]


def process_criticality(process):
    """
    Derive a criticality value in [0, 1] for one business process.

    `process` is a mapping with keys revenue_dependency, customer_facing,
    availability_requirement and data_sensitivity.

    Returns (score, contributions); contributions explains how the score arose.
    """
    values = {
        "revenue_dependency": _lookup(
            REVENUE_DEPENDENCY,
            process.get("revenue_dependency", "none"),
            "revenue_dependency",
        ),
        "customer_facing": 1.0 if process.get("customer_facing") else 0.0,
        "availability_requirement": _lookup(
            AVAILABILITY_REQUIREMENT,
            process.get("availability_requirement", "low"),
            "availability_requirement",
        ),
        "data_sensitivity": _lookup(
            DATA_SENSITIVITY,
            process.get("data_sensitivity", "public"),
            "data_sensitivity",
        ),
    }
    contributions = {k: round(v * CRITICALITY_WEIGHTS[k], 4) for k, v in values.items()}
    return round(sum(contributions.values()), 4), contributions


def repository_criticality(processes):
    """
    Derive a repository's business criticality from the processes it supports.

    A repository is as critical as the most critical process it underpins. We
    take the maximum rather than the mean, because a shared library supporting
    both payments and an internal cron job is a payments risk, and averaging
    would dilute exactly the signal we are trying to surface.

    Returns (score, detail). `detail` names the driving process so the dashboard
    can explain why a repository ranks where it does.
    """
    if not processes:
        return UNMAPPED_CRITICALITY, {
            "driving_process": None,
            "contributions": {},
            "process_count": 0,
            "unmapped": True,
            "note": ("No business process mapped. Scored at the median as "
                     "unknown risk, not low risk. Map this repository to "
                     "obtain a derived criticality."),
        }

    scored = []
    for p in processes:
        score, contributions = process_criticality(p)
        scored.append((score, p, contributions))
    scored.sort(key=lambda t: t[0], reverse=True)

    top_score, top_process, top_contributions = scored[0]
    return top_score, {
        "driving_process": top_process.get("name"),
        "contributions": top_contributions,
        "process_count": len(processes),
        "unmapped": False,
    }


def compliance_factor(regimes):
    """
    Multiplicative uplift for repositories in regulatory scope.

    Each distinct regime adds 10%, capped at 25%, so compliance sharpens the
    ordering without swamping severity. Returns (factor >= 1.0, distinct list).
    """
    distinct = {str(r).strip().upper() for r in (regimes or []) if str(r).strip()}
    uplift = min(len(distinct) * COMPLIANCE_UPLIFT_PER_REGIME, MAX_COMPLIANCE_UPLIFT)
    return round(1.0 + uplift, 4), sorted(distinct)


def composite_score(cvss, epss, criticality, regimes=None):
    """
    Business-aware composite score on a 0-10 scale.

    cvss:        CVSS v3.1 base score, 0-10
    epss:        EPSS probability, 0-1
    criticality: derived business criticality, 0-1 (see repository_criticality)
    regimes:     regulatory regimes in scope for the repository

    Returns a dict with the score, the tier, and the per-factor contributions --
    the explainability the proposal commits to in Objective 2.
    """
    cvss_n = max(0.0, min(float(cvss or 0.0), 10.0)) / 10.0
    epss_n = max(0.0, min(float(epss or 0.0), 1.0))
    crit_n = max(0.0, min(float(criticality or 0.0), 1.0))

    parts = {
        "cvss": round(cvss_n * SCORE_WEIGHTS["cvss"], 4),
        "epss": round(epss_n * SCORE_WEIGHTS["epss"], 4),
        "criticality": round(crit_n * SCORE_WEIGHTS["criticality"], 4),
    }
    base = sum(parts.values())
    factor, distinct = compliance_factor(regimes)
    final = min(base * factor, 1.0)

    return {
        "score": round(final * 10.0, 2),
        "tier": tier_for(final * 10.0),
        "base_score": round(base * 10.0, 2),
        "compliance_factor": factor,
        "regimes": distinct,
        "contributions": {k: round(v * 10.0, 2) for k, v in parts.items()},
    }


def baseline_score(cvss, epss, manual_tier):
    """
    The Capstone 1 score, kept so Phase 6 measures improvement against a real
    baseline rather than against an assertion.
    """
    crit = MANUAL_TIER_VALUES.get(str(manual_tier or "low").lower(), 0.25)
    value = (
        (max(0.0, min(float(cvss or 0.0), 10.0)) / 10.0) * SCORE_WEIGHTS["cvss"]
        + max(0.0, min(float(epss or 0.0), 1.0)) * SCORE_WEIGHTS["epss"]
        + crit * SCORE_WEIGHTS["criticality"]
    )
    return round(value * 10.0, 2)


def tier_for(score):
    for threshold, name in TIER_THRESHOLDS:
        if score >= threshold:
            return name
    return "LOW"


# ---------------------------------------------------------------------------
# Fix effort  (Capstone 2 extension)
#
# Business risk tells a team what matters. It does not tell them what is worth
# the next twenty minutes. A remediation queue that ignores remediation cost
# produces a better-ordered list that developers still do not act on, which is
# the failure Mohayeji et al. observed: automation exists, alerts remain open.
#
# Effort is deliberately kept ORTHOGONAL to the risk score. It does not enter
# composite_score(), because discounting a critical finding for being awkward to
# fix would be exactly the wrong behaviour. Effort is a second axis, used to
# derive a separate "quick wins" view over the same queue.
#
# The signal is free: GitHub's Dependabot alert payload carries
# security_vulnerability.first_patched_version. The semver distance between the
# installed version and that patched version is a good proxy for how likely the
# upgrade is to break something.
# ---------------------------------------------------------------------------

EFFORT_BANDS = {
    "PATCH":   {"effort": 0.10, "multiplier": 1.00,
                "label": "Patch bump", "note": "Backwards compatible by convention"},
    "MINOR":   {"effort": 0.40, "multiplier": 0.80,
                "label": "Minor bump", "note": "New functionality, should be compatible"},
    "MAJOR":   {"effort": 0.85, "multiplier": 0.50,
                "label": "Major bump", "note": "Breaking changes expected"},
    "MAJOR_MULTI": {"effort": 1.00, "multiplier": 0.35,
                    "label": "Multiple major versions",
                    "note": "Substantial upgrade work"},
    "UNKNOWN": {"effort": 0.50, "multiplier": 0.70,
                "label": "Unknown", "note": "Versions could not be compared"},
    "NO_FIX":  {"effort": 1.00, "multiplier": 0.00,
                "label": "No patch available",
                "note": "Cannot be remediated by upgrading; needs mitigation"},
}


def _version_parts(version):
    """Leading integer components of a version string, or None."""
    import re

    if not version:
        return None
    numbers = re.findall(r"\d+", str(version))
    if not numbers:
        return None
    parts = [int(n) for n in numbers[:3]]
    while len(parts) < 3:
        parts.append(0)
    return parts


def fix_effort(installed_version, patched_version):
    """
    Classify the upgrade from installed_version to patched_version.

    Returns a dict with the band, an effort value in [0, 1], a multiplier used
    by quick_win_score, and a human-readable label. `patched_version` of None
    means Dependabot has no fix, which is the highest-effort case rather than
    the lowest.
    """
    if not patched_version:
        return dict(EFFORT_BANDS["NO_FIX"], band="NO_FIX",
                    from_version=installed_version, to_version=None)

    current, target = _version_parts(installed_version), _version_parts(patched_version)
    if current is None or target is None:
        return dict(EFFORT_BANDS["UNKNOWN"], band="UNKNOWN",
                    from_version=installed_version, to_version=patched_version)

    major_gap = target[0] - current[0]
    if major_gap >= 2:
        band = "MAJOR_MULTI"
    elif major_gap == 1:
        band = "MAJOR"
    elif target[1] != current[1]:
        band = "MINOR"
    else:
        band = "PATCH"

    return dict(EFFORT_BANDS[band], band=band,
                from_version=installed_version, to_version=patched_version)


def quick_win_score(business_score, effort):
    """
    Value per unit of effort, on the same 0-10 scale as the business score.

    A quick win is a finding that matters to the business AND is cheap to fix.
    The multiplier discounts rather than reorders: a 9.0 finding needing a major
    upgrade (4.5) still outranks a 3.0 finding needing a patch bump (3.0), which
    is correct -- effort breaks ties, it does not overturn importance.
    """
    multiplier = (effort or {}).get("multiplier", EFFORT_BANDS["UNKNOWN"]["multiplier"])
    return round((business_score or 0.0) * multiplier, 2)
