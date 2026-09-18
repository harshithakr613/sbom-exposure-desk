"""
Zero-Day Risk Score -- scoring a finding that has no CVE.

The standard composite is

    score = (CVSS x 0.5) + (EPSS x 0.3) + (criticality x 0.2)

Both CVSS and EPSS are derived from a *published CVE record*. Neither exists
before an identifier is assigned, so the established formula cannot rank a
zero-day at all: the highest-risk findings are exactly the ones it drops.

Rather than invent a parallel formula, this keeps the same shape and substitutes
each missing term with a documented proxy:

    CVSS -> Consensus Severity Proxy   from the published severity assessments
    EPSS -> Disclosure-Stage Prior     from where the finding sits in the
                                       disclosure lifecycle and whether it is
                                       still unpatched

Every substitution is recorded in the explanation, so a reviewer can always see
which terms were measured and which were proxied. A score built on two proxies
is not the same evidence as one built on a published CVSS vector, and the output
says so instead of presenting a single undifferentiated number.
"""

import logging

from . import bia
from .zeroday_feeds import (
    STAGE_COMMITMENT, STAGE_IDENTIFIED, STAGE_PATCHED, STAGE_REVEALED,
)
from .zeroday_match import TIER_CONFIDENCE, TIER_PROJECT, TIER_PURL

log = logging.getLogger("sbom_c2.zeroday_score")

# Severity band -> CVSS-equivalent, using the midpoint of each CVSS v3.1
# qualitative range rather than its ceiling. Mapping "high" to 8.9 would make
# every high finding outrank most measured criticals.
SEVERITY_TO_CVSS = {
    "critical": 9.5,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.5,
    "none": 0.5,
}

# Disclosure-Stage Prior: a stand-in for exploitation probability.
#
# The reasoning is imminence, not observed exploitation. A finding that has been
# revealed but not patched is the dangerous quadrant -- the defect is public
# enough to be rediscovered and there is no fix to apply. Once patched, the
# residual risk is that the upgrade has not been done yet, which is lower.
# A sealed commitment scores low not because it is safe but because nothing can
# be acted on, and inflating it would flood the queue with items no one can fix.
STAGE_PRIOR = {
    STAGE_COMMITMENT: 0.15,
    STAGE_REVEALED: 0.55,
    STAGE_IDENTIFIED: 0.40,
    STAGE_PATCHED: 0.20,
}

# Unpatched at reveal is worse than the stage alone implies.
UNPATCHED_UPLIFT = 0.15

# Confirmed in-the-wild exploitation replaces the prior outright. This is the
# one override in the system: at that point the question is no longer how
# likely exploitation is.
KEV_PRIOR = 0.95


def consensus_severity(finding):
    """
    Derive a CVSS-equivalent from whatever severity assessments exist.

    Precedence is maintainer, then security firm, then model: the maintainer
    knows the codebase, the firm reviewed it independently, the model proposed
    it. Where all three are published they agree exactly 85.2% of the time and
    within one band 97.1% (n=1017), so this is a tie-break, not a correction.

    Returns (score, band, basis) where basis names the assessments used.
    """
    severities = {k: v for k, v in (finding.get("severities") or {}).items() if v}

    for key in ("maintainer", "vendor", "model"):
        band = severities.get(key)
        if band:
            others = [b for k, b in severities.items() if k != key]
            basis = "%s severity" % key
            if others:
                basis += " (%d assessments, %s)" % (
                    len(severities),
                    "agreed" if len(set(severities.values())) == 1 else "differed")
            return SEVERITY_TO_CVSS.get(band, 5.0), band, basis

    band = finding.get("severity_band")
    if band:
        return SEVERITY_TO_CVSS.get(band, 5.0), band, "feed severity band"

    # No severity anywhere. Assume medium rather than zero: a confirmed defect
    # with an unstated severity is not a non-issue, and scoring it 0 would hide
    # it at the bottom of the queue.
    return SEVERITY_TO_CVSS["medium"], "medium", "assumed medium (none published)"


def disclosure_prior(finding):
    """Exploitation-probability stand-in. Returns (prior, basis)."""
    if finding.get("exploited"):
        return KEV_PRIOR, "confirmed exploited in the wild (CISA KEV)"

    stage = finding.get("stage") or STAGE_REVEALED
    prior = STAGE_PRIOR.get(stage, 0.4)
    basis = "disclosure stage %s" % finding.get("stage_label", stage)

    if stage in (STAGE_REVEALED, STAGE_IDENTIFIED) and not finding.get("patched"):
        prior = min(prior + UNPATCHED_UPLIFT, 0.9)
        basis += ", unpatched"
    return prior, basis


def score_exposure(finding, criticality, regimes=None, tier=TIER_PURL,
                   confidence=None, cvss=None, epss=None):
    """
    Score one zero-day exposure.

    cvss / epss may be supplied when the finding has since received an
    identifier and real values are available; whatever is passed is used, and
    only the missing terms are proxied. That is what makes the zero-day and
    published paths directly comparable: same formula, same weights, and the
    explanation records which terms were measured.

    `confidence` discounts the result by the evidence tier that produced the
    match, so a T0 project-name hit cannot outrank a verified PURL match of
    equal severity.
    """
    substitutions = {}

    if cvss is None:
        cvss, band, basis = consensus_severity(finding)
        substitutions["cvss"] = {
            "substituted_with": "Consensus Severity Proxy",
            "band": band, "basis": basis, "value": cvss,
        }
    if epss is None:
        epss, basis = disclosure_prior(finding)
        substitutions["epss"] = {
            "substituted_with": "Disclosure-Stage Prior",
            "basis": basis, "value": round(epss, 3),
        }

    result = bia.composite_score(cvss, epss, criticality, regimes)

    discount = confidence if confidence is not None else TIER_CONFIDENCE.get(tier, 0.5)
    discount = max(0.0, min(float(discount), 1.0))
    adjusted = round(result["score"] * discount, 2)

    return {
        "score": adjusted,
        "undiscounted_score": result["score"],
        "tier": bia.tier_for(adjusted),
        "evidence_tier": tier,
        "evidence_confidence": round(discount, 3),
        "base_score": result["base_score"],
        "compliance_factor": result["compliance_factor"],
        "regimes": result["regimes"],
        "contributions": result["contributions"],
        "substitutions": substitutions,
        "degraded": bool(substitutions),
        "exploited": bool(finding.get("exploited")),
        "kev_due_date": finding.get("kev_due_date").isoformat()
        if finding.get("kev_due_date") else None,
    }


def explain(scored):
    """One-line human summary, for the dashboard and the CSV export."""
    parts = []
    for term, detail in (scored.get("substitutions") or {}).items():
        parts.append("%s proxied by %s (%s)" % (
            term.upper(), detail["substituted_with"], detail["basis"]))
    if not parts:
        parts.append("scored on published CVSS and EPSS")
    parts.append("evidence %s at %.0f%% confidence" % (
        scored.get("evidence_tier"), 100 * scored.get("evidence_confidence", 0)))
    if scored.get("exploited"):
        parts.append("ESCALATED: confirmed exploitation")
    return "; ".join(parts)


def rank(scored_rows):
    """
    Order the zero-day queue.

    Confirmed exploitation first regardless of anything else, then score, then
    verified evidence ahead of unverified at equal score -- so a T0 name match
    never displaces a PURL-verified finding from the top of the queue.
    """
    return sorted(
        scored_rows,
        key=lambda r: (
            not r.get("exploited"),
            -(r.get("score") or 0.0),
            r.get("evidence_tier") == TIER_PROJECT,
        ))
