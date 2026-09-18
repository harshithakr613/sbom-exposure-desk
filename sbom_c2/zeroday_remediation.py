"""
Remediation for vulnerabilities that have no patch  (Capstone 2, Objective 3).

Automated remediation is patch-dependent by construction. Dependabot raises a
pull request only once a fixed version exists, so through the entire window
before disclosure there is no version to upgrade to, no advisory to link, and
no alert is raised at all. The repositories carrying the exposure are never
named.

That window is precisely when exposure is highest: the defect is confirmed and
real, and no fix is available. This module answers the question the existing
tooling cannot -- what can actually be done right now -- by deriving a staged
response from the disclosure state of the finding rather than from the presence
of a patch.

The four stages mirror the disclosure lifecycle of Capstone 1:

    T0 Commitment   nothing is actionable; hold and watch
    T1 Revealed     THE GAP -- project known, no identifier, no patch
    T2 Identified   an advisory exists; conventional tooling can finally act
    T3 Patched      a fixed version exists; verify the upgrade

Stage T1 is the contribution. No existing tool raises anything here, because
there is no identifier to key on and no patched version to upgrade to.
"""

import datetime as dt
import logging

from .zeroday_feeds import (
    STAGE_COMMITMENT, STAGE_IDENTIFIED, STAGE_PATCHED, STAGE_REVEALED,
)

log = logging.getLogger("sbom_c2.zeroday_remediation")


def _now():
    return dt.datetime.now(dt.timezone.utc)


# ---------------------------------------------------------------------------
# Compensating controls
# ---------------------------------------------------------------------------
#
# When no patch exists the only available response is to reduce reachability or
# blast radius. What that means in practice depends on the class of defect, so
# the advice is keyed on the bug class the disclosure feed publishes -- which is
# available at T1, before any identifier.
#
# These are deliberately concrete. "Apply compensating controls" is not
# actionable advice; "reject path separators in the filename parameter at the
# gateway before the request reaches the library" is.

BUG_CLASS_CONTROLS = {
    "path-traversal": [
        "Reject encoded and literal path separators in affected parameters at "
        "the gateway, before the request reaches the library",
        "Run the service against a read-only filesystem mount where possible",
    ],
    "sql-injection": [
        "Enforce parameterised queries in the calling code; the library "
        "defect cannot be reached if no untrusted value is interpolated",
        "Apply a WAF rule for the affected endpoint as a stop-gap",
    ],
    "xss": [
        "Tighten Content-Security-Policy on the affected routes to block "
        "inline script execution",
        "Escape at the template layer rather than relying on the library",
    ],
    "deserialization": [
        "Restrict deserialisation to an allow-list of expected types",
        "Reject untrusted serialised input at the boundary",
    ],
    "code-injection": [
        "Remove untrusted input from any path that reaches the affected API",
        "Run the component in a restricted sandbox or separate process",
    ],
    "ssrf": [
        "Apply egress filtering so the service cannot reach internal ranges",
        "Validate and allow-list destination hosts before the request is made",
    ],
    "auth-bypass": [
        "Enforce authorisation at the gateway as well as in the application, "
        "so a library-level bypass is not sufficient on its own",
        "Review and shorten session lifetimes on affected endpoints",
    ],
    "signature-bypass": [
        "Add an independent signature verification step outside the affected "
        "library",
        "Reject inputs whose signature algorithm is not explicitly expected",
    ],
    "improper-cert-validation": [
        "Pin certificates or enforce validation at the transport layer outside "
        "the affected library",
    ],
    "denial-of-service": [
        "Apply request size limits and timeouts in front of the component",
        "Rate-limit the affected endpoint",
    ],
    "privilege-escalation": [
        "Run the component under a least-privilege account",
        "Restrict which users can reach the affected functionality",
    ],
    "idor": [
        "Enforce object-level authorisation in the calling code rather than "
        "relying on the library",
    ],
}

# Memory-safety classes share a response: the defect is in native code and the
# realistic mitigation is to stop untrusted input reaching it.
MEMORY_SAFETY = (
    "heap-buffer-overflow", "stack-buffer-overflow", "buffer-overflow",
    "use-after-free", "double-free", "oob-read", "oob-write",
    "integer-overflow", "integer-underflow", "off-by-one",
)
MEMORY_SAFETY_CONTROLS = [
    "Stop untrusted input reaching the affected parser; validate size and "
    "structure at the boundary before the component is called",
    "Isolate the component in a separate process so a memory-safety failure "
    "does not compromise the host application",
]

GENERIC_CONTROLS = [
    "Pin the dependency at its current version so an unreviewed upgrade cannot "
    "change behaviour while the finding is open",
    "Reduce reachability: confirm whether the affected code path is used at "
    "all, and remove the dependency if it is not",
]


def compensating_controls(bug_class):
    """Concrete mitigations for a bug class, most specific first."""
    key = (bug_class or "").strip().lower()
    if key in BUG_CLASS_CONTROLS:
        return BUG_CLASS_CONTROLS[key] + GENERIC_CONTROLS[:1]
    if key in MEMORY_SAFETY:
        return MEMORY_SAFETY_CONTROLS + GENERIC_CONTROLS[:1]
    return GENERIC_CONTROLS


# ---------------------------------------------------------------------------
# The ladder
# ---------------------------------------------------------------------------

LADDER = {
    STAGE_COMMITMENT: {
        "stage_label": "T0",
        "name": "Commitment",
        "patch_available": False,
        "summary": "A finding exists but its project is withheld while the "
                   "disclosure window is open.",
        "why": "The disclosure programme deliberately publishes only a hash "
               "commitment at this stage. No asset-level action is possible, "
               "and the system does not attempt to infer the target.",
    },
    STAGE_REVEALED: {
        "stage_label": "T1",
        "name": "Revealed, no patch",
        "patch_available": False,
        "summary": "The affected project and bug class are known. There is no "
                   "CVE, no advisory and no fixed version.",
        "why": "This is the gap. Dependabot cannot raise a pull request "
               "because there is no version to upgrade to, and no scanner "
               "fires because there is no identifier to key on.",
    },
    STAGE_IDENTIFIED: {
        "stage_label": "T2",
        "name": "Identifier assigned",
        "patch_available": None,
        "summary": "A CVE or GitHub Security Advisory now exists. Conventional "
                   "tooling can act from this point.",
        "why": "Hand off to the native security-update flow where a fix "
               "exists; continue with compensating controls where it does not.",
    },
    STAGE_PATCHED: {
        "stage_label": "T3",
        "name": "Patched upstream",
        "patch_available": True,
        "summary": "A fixed version has been released.",
        "why": "The remaining risk is that the upgrade has not been applied. "
               "Verify and close the loop.",
    },
}


def ladder_stage(finding):
    """Which rung a finding sits on."""
    stage = finding.get("stage") or STAGE_REVEALED
    return stage if stage in LADDER else STAGE_REVEALED


def upgrade_target(finding):
    """The version to move to, where the feed publishes one."""
    return finding.get("fixed_version")


def remediation_plan(finding, repository=None, processes=None, owner=None):
    """
    What can be done about this finding, right now.

    Returns actions ordered by what a developer should do first, each with the
    reason it applies. Where a fixed version exists the upgrade leads; where it
    does not, the plan is compensating controls plus a tracked, time-boxed risk
    exception -- which is a real answer, not a placeholder.
    """
    stage = ladder_stage(finding)
    rung = LADDER[stage]
    fixed = upgrade_target(finding)
    exploited = bool(finding.get("exploited"))
    bug_class = finding.get("bug_class")

    actions, blocked = [], []

    if stage == STAGE_COMMITMENT:
        actions.append({
            "action": "Hold on the watchlist",
            "detail": "Verify the published commitment hash and re-check on "
                      "each poll. No repository can be named yet.",
            "automatable": True,
        })
        blocked.append("No project is published, so no repository can be "
                       "identified.")

    else:
        if fixed:
            actions.append({
                "action": "Upgrade to %s" % fixed,
                "detail": "A fixed version is published. This is the complete "
                          "remediation; everything below is unnecessary once "
                          "the upgrade is merged and deployed.",
                "automatable": True,
            })
        else:
            blocked.append(
                "No fixed version has been published, so there is nothing to "
                "upgrade to. Dependabot cannot act on this finding.")
            for control in compensating_controls(bug_class):
                actions.append({
                    "action": "Compensating control",
                    "detail": control,
                    "automatable": False,
                })
            actions.append({
                "action": "Raise a time-boxed risk exception",
                "detail": "Record the exposure with the accountable owner and "
                          "a review date, so an unpatchable finding is "
                          "consciously accepted rather than silently ignored.",
                "automatable": False,
            })

        if finding.get("cve_ids") or finding.get("ghsa_ids"):
            identifier = (finding.get("cve_ids") or finding.get("ghsa_ids"))[0]
            actions.append({
                "action": "Link the native security alert",
                "detail": "An identifier (%s) now exists, so the finding can "
                          "be correlated to its Dependabot alert and handed "
                          "off." % identifier,
                "automatable": True,
            })
        elif not fixed:
            blocked.append(
                "No CVE or GHSA identifier exists, so there is no advisory to "
                "correlate against and no scanner will raise this.")

    urgency, urgency_reason = _urgency(stage, exploited, fixed, processes)

    return {
        "stage": stage,
        "stage_label": rung["stage_label"],
        "stage_name": rung["name"],
        "stage_summary": rung["summary"],
        "why_this_stage": rung["why"],
        "is_the_gap": stage == STAGE_REVEALED,
        "patch_available": bool(fixed),
        "upgrade_target": fixed,
        "bug_class": bug_class,
        "actions": actions,
        "blocked": blocked,
        "urgency": urgency,
        "urgency_reason": urgency_reason,
        "owner": owner,
        "repository": repository,
        "processes": [p.get("name") for p in (processes or [])],
    }


URGENCY_ORDER = ["immediate", "high", "planned", "watch"]


def _urgency(stage, exploited, fixed, processes):
    """
    How soon this needs attention, in words a developer can act on.

    Confirmed exploitation overrides everything: at that point the question is
    no longer how much the asset is worth. Otherwise the driver is business
    consequence, because a developer deciding what to fix first is choosing
    between systems, not between CVSS vectors.
    """
    if exploited:
        return "immediate", ("Confirmed exploited in the wild (CISA KEV). This "
                             "outranks business context.")

    revenue_name = regulated_name = any_name = None
    for p in processes or []:
        name = p.get("name")
        any_name = any_name or name
        if p.get("regulatory_scope"):
            regulated_name = regulated_name or name
        if p.get("revenue_dependency") == "direct":
            revenue_name = revenue_name or name
    revenue, regulated = bool(revenue_name), bool(regulated_name)

    if stage == STAGE_COMMITMENT:
        return "watch", "Nothing is actionable until the project is revealed."

    if revenue and not fixed:
        return "immediate", (
            "Supports a revenue-critical process (%s) and no fix exists, so "
            "compensating controls are the only available response."
            % revenue_name)
    if regulated and not fixed:
        return "high", (
            "%s is in regulatory scope and this cannot be patched yet, so the "
            "exposure needs a recorded decision rather than a silent wait."
            % regulated_name)
    if revenue or regulated:
        return "high", ("Supports %s. A fix exists, so upgrade rather than "
                        "mitigate." % (revenue_name or regulated_name
                                       or any_name))
    if not fixed:
        return "planned", ("No fix available, but the affected repository "
                           "supports no revenue-critical or regulated "
                           "process.")
    return "planned", "A fix exists and the business impact is limited."


# ---------------------------------------------------------------------------
# Alerting
# ---------------------------------------------------------------------------

def alert_for(plan, finding, exposure_id=None):
    """
    An alert for the dashboard notification bar.

    Only findings that genuinely need attention produce one. An alert nobody
    can act on trains people to dismiss the bar, which costs more than the
    alert is worth.
    """
    if plan["urgency"] not in ("immediate", "high"):
        return None
    return {
        "exposure_id": exposure_id,
        "urgency": plan["urgency"],
        "headline": _headline(plan, finding),
        "reason": plan["urgency_reason"],
        "repository": plan["repository"],
        "processes": plan["processes"],
        "owner": plan["owner"],
        "stage_label": plan["stage_label"],
        "patch_available": plan["patch_available"],
        "first_action": plan["actions"][0]["detail"] if plan["actions"] else None,
        "raised_at": _now().isoformat(),
    }


def _headline(plan, finding):
    package = finding.get("package_name") or finding.get("project") or "a component"
    if plan["patch_available"]:
        return "%s in %s \u2014 patch available, upgrade to %s" % (
            package, plan["repository"] or "your portfolio", plan["upgrade_target"])
    return "%s in %s \u2014 zero-day, no patch available" % (
        package, plan["repository"] or "your portfolio")


def summarise(plans):
    """Counts for the notification bar, without listing every finding."""
    counts = {u: 0 for u in URGENCY_ORDER}
    unpatchable = 0
    for plan in plans:
        counts[plan["urgency"]] = counts.get(plan["urgency"], 0) + 1
        if plan["is_the_gap"]:
            unpatchable += 1
    return {
        "total": len(plans),
        "by_urgency": counts,
        "needs_attention": counts["immediate"] + counts["high"],
        "unpatchable": unpatchable,
        "note": "Findings at stage T1 have no identifier and no fixed version. "
                "No other tool raises these.",
    }
