"""
Remediation orchestration (Objective 3).

Correlates our exposures with GitHub Dependabot alerts, provides the deep-link
handoff, and detects resolution. Read-only: the merge stays with the repository
owner on GitHub, which is what makes this safe to run against any organisation.
"""

import datetime as dt
from urllib.parse import quote

from . import bia
from .github_client import GitHubClient
from .models import Exposure, RemediationEvent, Repository


def _now():
    return dt.datetime.now(dt.timezone.utc)


def _parse_ts(value):
    if not value:
        return None
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def correlate_alerts(session, client: GitHubClient):
    """
    Match each Dependabot alert to an exposure record.

    Matching proceeds in two passes, because identifier agreement cannot be
    assumed. OSV aggregates advisories from several sources and may return a
    PYSEC or GO record carrying no CVE alias, while Dependabot describes the
    same vulnerability under a GHSA. The identifiers never meet even though both
    describe the same package at the same version.

      Pass 1  identifier match on GHSA or CVE, narrowed by package where a
              repository has several findings for one advisory. High confidence.

      Pass 2  for findings still unlinked, match on package name, ecosystem and
              installed version. Recorded as a lower-confidence link so an
              analyst can see which route produced it.

    Returns counts by pass rather than a single total, so coverage can be
    reported honestly.
    """
    alerts = [GitHubClient.alert_identity(a)
              for a in client.list_dependabot_alerts()]

    by_repo = {}
    for alert in alerts:
        if alert["repository"]:
            by_repo.setdefault(alert["repository"], []).append(alert)

    linked_by_identifier = 0
    linked_by_package = 0
    already = 0

    for full_name, repo_alerts in by_repo.items():
        repository = (session.query(Repository)
                      .filter_by(full_name=full_name).one_or_none())
        if repository is None:
            continue

        exposures = (session.query(Exposure)
                     .filter_by(repository_id=repository.id).all())

        # ---------------- pass one: identifier ----------------------------
        claimed = set()
        for alert in repo_alerts:
            candidates = [
                e for e in exposures
                if (alert["ghsa_id"] and e.advisory_id == alert["ghsa_id"])
                or (alert["cve_id"] and e.cve_id == alert["cve_id"])
            ]
            if len(candidates) > 1 and alert["package"]:
                narrowed = [e for e in candidates
                            if (e.component_name or "").lower() == alert["package"]]
                candidates = narrowed or candidates

            for exposure in candidates:
                claimed.add(exposure.id)
                if exposure.dependabot_alert_number == alert["number"]:
                    already += 1
                else:
                    linked_by_identifier += 1
                _apply_alert(exposure, alert, "identifier")

        # ---------------- pass two: package and version -------------------
        # Only findings the first pass did not claim, so a confident match is
        # never replaced by a weaker one.
        unlinked = [e for e in exposures
                    if e.id not in claimed and e.dependabot_alert_number is None]
        if not unlinked:
            continue

        for alert in repo_alerts:
            if not alert["package"]:
                continue
            for exposure in unlinked:
                if exposure.dependabot_alert_number is not None:
                    continue
                if (exposure.component_name or "").lower() != alert["package"]:
                    continue
                if (alert["ecosystem"] and exposure.ecosystem
                        and alert["ecosystem"] != exposure.ecosystem.lower()):
                    continue
                # The installed version must fall inside the range Dependabot
                # reports as vulnerable, otherwise this is a different finding
                # on the same package.
                if not _version_in_alert_range(exposure.component_version,
                                               alert.get("vulnerable_range")):
                    continue
                _apply_alert(exposure, alert, "package")
                linked_by_package += 1

    session.commit()
    return {
        "alerts_seen": len(alerts),
        "linked_by_identifier": linked_by_identifier,
        "linked_by_package": linked_by_package,
        "already_linked": already,
        "note": ("Package-level matches are lower confidence than identifier "
                 "matches and are recorded as such."),
    }


def _apply_alert(exposure, alert, how):
    """Attach an alert to a finding and recompute its fix effort."""
    exposure.dependabot_alert_number = alert["number"]
    exposure.dependabot_alert_url = alert["html_url"]
    exposure.alert_match_method = how
    exposure.first_patched_version = alert.get("first_patched_version")
    effort = bia.fix_effort(exposure.component_version,
                            exposure.first_patched_version)
    exposure.fix_effort_band = effort["band"]
    exposure.quick_win_score = bia.quick_win_score(exposure.business_score, effort)


def _version_in_alert_range(version, vulnerable_range):
    """
    Evaluate a version against Dependabot's stated range, for example
    "< 1.2.6" or ">= 2.0.0, < 2.15.0".

    An unparseable range returns True rather than False: the alert is on the
    same package in the same repository, so excluding it would more likely lose
    a real match than prevent a wrong one.
    """
    from . import matching

    if not version or not vulnerable_range:
        return True
    if matching.is_constraint(version):
        return True

    for clause in str(vulnerable_range).split(","):
        clause = clause.strip()
        parts = clause.split()
        if len(parts) == 2:
            operator, bound = parts
        elif clause[:2] in ("<=", ">=", "=="):
            operator, bound = clause[:2], clause[2:]
        elif clause[:1] in ("<", ">", "="):
            operator, bound = clause[:1], clause[1:]
        else:
            continue
        try:
            order = matching.compare_versions(version, bound.strip())
        except matching.InvalidVersion:
            continue
        ok = {"<": order < 0, "<=": order <= 0, ">": order > 0,
              ">=": order >= 0, "=": order == 0, "==": order == 0}.get(operator)
        if ok is False:
            return False
    return True


def refresh_resolution_state(session, client: GitHubClient):
    """
    Re-read alert state and move exposures to resolved.

    The resolution timestamp is taken from GitHub's fixed_at rather than from
    the moment we happened to poll, so Mean Time to Remediate reflects when the
    fix actually landed.
    """
    alerts = {}
    for raw in client.list_dependabot_alerts():
        identity = GitHubClient.alert_identity(raw)
        if identity["repository"] and identity["number"] is not None:
            alerts[(identity["repository"], identity["number"])] = identity

    transitions = {"resolved": 0, "reopened": 0}
    exposures = session.query(Exposure).filter(
        Exposure.dependabot_alert_number.isnot(None)).all()

    for exposure in exposures:
        repository = session.get(Repository, exposure.repository_id)
        if repository is None:
            continue
        alert = alerts.get((repository.full_name, exposure.dependabot_alert_number))
        if alert is None:
            continue

        alert_closed = alert["state"] in ("fixed", "dismissed", "auto_dismissed")

        if alert_closed and exposure.state != "resolved":
            exposure.state = "resolved"
            exposure.resolved_at = (
                _parse_ts(alert["fixed_at"])
                or _parse_ts(alert["dismissed_at"])
                or _now()
            )
            session.add(RemediationEvent(
                exposure_id=exposure.id, event_type="resolved",
                from_state="open", to_state="resolved",
                detail="dependabot alert %s -> %s" % (alert["number"], alert["state"]),
                occurred_at=exposure.resolved_at))
            transitions["resolved"] += 1

        elif not alert_closed and exposure.state == "resolved":
            exposure.state = "open"
            exposure.resolved_at = None
            session.add(RemediationEvent(
                exposure_id=exposure.id, event_type="reopened",
                from_state="resolved", to_state="open",
                detail="dependabot alert %s reopened" % alert["number"]))
            transitions["reopened"] += 1

    session.commit()
    return transitions


def handoff_url(exposure, repository):
    """
    The one-click deep link presented in the dashboard.

    Falls back to the repository's Dependabot alert list when no specific alert
    has been correlated, so the link is never dead. Callers must consult
    handoff_is_precise() before labelling it, because sending a developer to a
    list of forty alerts under a button that promised one is worse than telling
    them plainly that no alert is linked.
    """
    if exposure.dependabot_alert_url:
        return exposure.dependabot_alert_url
    if exposure.dependabot_alert_number:
        return "https://github.com/%s/security/dependabot/%s" % (
            repository.full_name, exposure.dependabot_alert_number)
    return "https://github.com/%s/security/dependabot" % repository.full_name


def handoff_is_precise(exposure):
    """True when the link goes to one specific alert rather than the list."""
    return bool(exposure.dependabot_alert_url
                or exposure.dependabot_alert_number)


def handoff_search_url(exposure, repository):
    """
    A filtered alert list for the uncorrelated case.

    Where no specific alert is known, pre-filtering the list by package name at
    least puts the developer in front of the right few rather than all of them.
    """
    package = (exposure.component_name or "").split(":")[-1]
    if not package:
        return "https://github.com/%s/security/dependabot" % repository.full_name
    return ("https://github.com/%s/security/dependabot?q=is%%3Aopen+package%%3A%s"
            % (repository.full_name, quote(package)))


def record_handoff(session, exposure):
    """Log that a user opened the handoff, so the funnel can be reported."""
    session.add(RemediationEvent(
        exposure_id=exposure.id, event_type="handoff_opened",
        from_state=exposure.state, to_state=exposure.state,
        detail="user opened dependabot alert"))
    session.commit()
