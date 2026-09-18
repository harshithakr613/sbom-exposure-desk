"""
FastAPI application.

This is the process you run. It serves:
  * a JSON API over the pipeline, the business-context model, the remediation
    handoff and the impact metrics
  * the existing single-file dashboard from ./dashboard, so the browser loads
    the UI and the data from the same origin and no CORS setup is needed

Run with:  uvicorn sbom_c2.api:app --reload
Then open: http://127.0.0.1:8000
"""

import csv
import datetime as dt
import re
import io
import json
import logging
import os

from fastapi import Body, Depends, FastAPI, HTTPException
from fastapi.responses import FileResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy.orm import Session

from sqlalchemy import func

from . import (bia, config, evaluate, feeds, impact, matching,
               pipeline, quality, remediation, reports, sbom_formats,
               worklist, zeroday_feeds, zeroday_match, zeroday_remediation,
               zeroday_score)
from .scheduler import scheduler
from .db import get_session, init_db
from .github_client import GitHubClient
from .models import (
    BusinessProcess, Component, Exposure, ProcessRepositoryLink,
    RemediationEvent, Repository, ZeroDayExposure, ZeroDayFinding,
)

# A full sync takes minutes and is otherwise silent; INFO logging shows which
# stage it has reached, which matters when the alternative is a blank terminal.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(name)s  %(message)s",
    datefmt="%H:%M:%S")

app = FastAPI(title="Business-Context-Aware Vulnerability Prioritization",
              version="1.0")

DASHBOARD_DIR = os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "dashboard")


@app.on_event("startup")
async def startup():
    init_db()
    # Background CVE ingestion worker (Capstone 1, Phase 2). Off unless asked
    # for, so a demonstration run is never disturbed by a scheduled refresh.
    if os.environ.get("ENABLE_SCHEDULER", "").lower() in ("1", "true", "yes"):
        scheduler.start()


@app.on_event("shutdown")
async def shutdown():
    await scheduler.stop()


def client():
    token, org = config.require_github()
    return GitHubClient(token, org)


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class ProcessIn(BaseModel):
    name: str
    description: str | None = None
    owner: str | None = None
    revenue_dependency: str = "none"
    customer_facing: bool = False
    availability_requirement: str = "low"
    data_sensitivity: str = "public"
    regulatory_scope: str | None = None
    source_document: str | None = None
    source_reference: str | None = None


class LinkIn(BaseModel):
    process_id: int
    repository_id: int
    role: str = "implements"


# ---------------------------------------------------------------------------
# Health and ingestion
# ---------------------------------------------------------------------------

@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    """
    Answer the browser's automatic icon request.

    Browsers request this unprompted; without a route it logs a 404 on every
    page load, which looks like a fault during a demonstration and is not one.
    """
    return Response(status_code=204)


@app.get("/api/health")
def health(session: Session = Depends(get_session)):
    return {
        "status": "ok",
        "org": config.GITHUB_ORG,
        "github_token_present": bool(config.GITHUB_TOKEN),
        "repositories": session.query(Repository).count(),
        "exposures": session.query(Exposure).count(),
        "business_processes": session.query(BusinessProcess).count(),
    }


@app.post("/api/sync")
def sync(session: Session = Depends(get_session)):
    """Full pipeline: discover -> ingest SBOMs -> correlate -> score."""
    return pipeline.run_full_pipeline(session, client())


@app.post("/api/sync/repositories")
def sync_repositories(session: Session = Depends(get_session)):
    return {"repositories": pipeline.sync_repositories(session, client())}


@app.post("/api/sync/repository")
def sync_one_repository(full_name: str, session: Session = Depends(get_session)):
    """
    Re-ingest a single repository.

    GitHub's SBOM generation times out on large dependency trees; when that
    happens the repository is skipped rather than failing the whole run, and
    this endpoint retries it once GitHub has finished generating the graph.
    """
    repository = (session.query(Repository)
                  .filter_by(full_name=full_name).one_or_none())
    if repository is None:
        raise HTTPException(404, "repository not known; run /api/sync first")

    count = pipeline.ingest_sbom(session, client(), repository)
    if count == 0:
        return {"repository": full_name, "components": 0,
                "note": "GitHub returned no SBOM. It may still be generating "
                        "the dependency graph; try again in a few minutes."}

    components = [{"name": c.name, "ecosystem": c.ecosystem, "version": c.version}
                  for c in session.query(Component).filter_by(
                      repository_id=repository.id)]
    advisories = pipeline.refresh_vulnerability_data(session, components)
    exposures = pipeline.correlate_repository(session, repository, advisories)
    scored = pipeline.score_repository(session, repository)
    return {"repository": full_name, "components": count,
            "advisories": len(advisories), "exposures": exposures,
            "scored": scored}


@app.post("/api/correlate/repository")
def correlate_one_repository(full_name: str,
                             session: Session = Depends(get_session)):
    """
    Correlate a single repository against vulnerability data, without
    re-ingesting its SBOM.

    A repository created by direct SBOM upload has no GitHub source, so
    `/api/sync/repository` would return zero components for it. This runs the
    same correlation and scoring against components already stored, and is
    scoped to one repository rather than the whole portfolio.
    """
    repository = (session.query(Repository)
                  .filter_by(full_name=full_name).one_or_none())
    if repository is None:
        raise HTTPException(404, "repository not known")

    components = [{"name": c.name, "ecosystem": c.ecosystem,
                   "version": c.version}
                  for c in session.query(Component).filter_by(
                      repository_id=repository.id)]
    if not components:
        return {"repository": full_name, "components": 0,
                "note": "no components stored for this repository"}

    advisories = pipeline.refresh_vulnerability_data(session, components)
    exposures = pipeline.correlate_repository(session, repository, advisories)
    scored = pipeline.score_repository(session, repository)
    return {"repository": full_name, "components": len(components),
            "advisories": len(advisories), "exposures": exposures,
            "scored": scored}


# ---------------------------------------------------------------------------
# Repositories and findings
# ---------------------------------------------------------------------------

@app.get("/api/repositories")
def list_repositories(session: Session = Depends(get_session)):
    out = []
    for repo in session.query(Repository).all():
        processes, regimes = pipeline.repository_business_context(session, repo)
        open_count = (session.query(Exposure)
                      .filter_by(repository_id=repo.id, state="open").count())
        out.append({
            "id": repo.id,
            "full_name": repo.full_name,
            "name": repo.name,
            "ecosystem": repo.ecosystem,
            "manual_criticality_tier": repo.manual_criticality_tier,
            "business_processes": [p.name for p in processes],
            "regulatory_scope": regimes,
            "open_findings": open_count,
            "last_ingested_at": (repo.last_ingested_at.isoformat()
                                 if repo.last_ingested_at else None),
        })
    return sorted(out, key=lambda r: -r["open_findings"])


@app.get("/api/exposures")
def list_exposures(state: str | None = "open", limit: int = 200,
                   dedupe: bool = False,
                   session: Session = Depends(get_session)):
    """
    The prioritised remediation queue -- business score descending.

    `dedupe=true` collapses findings that describe the same vulnerability in the
    same place. A CVE is frequently published under several advisory
    identifiers -- CVE-2021-23337 appears as both GHSA-35jh-r3h4-6jhm and
    GHSA-r5fr-rjxr-66jc, and PyPI advisories are commonly duplicated between
    GHSA and PYSEC. Each is a distinct advisory record and worth keeping, but a
    developer sees one thing to fix, not two. Deduplication groups on
    (repository, component, version, CVE) and keeps the highest-scoring member.
    """
    query = session.query(Exposure)
    if state and state != "all":
        query = query.filter(Exposure.state == state)

    rows = query.all()
    if dedupe:
        rows = _dedupe_exposures(rows)
    rows.sort(key=lambda e: -(e.business_score or 0))

    repos = {r.id: r for r in session.query(Repository).all()}
    out = []
    for exposure in rows[:limit]:
        repo = repos.get(exposure.repository_id)
        out.append({
            "id": exposure.id,
            "repository": repo.full_name if repo else None,
            "cve_id": exposure.cve_id,
            "advisory_id": exposure.advisory_id,
            "component": exposure.component_name,
            "version": exposure.component_version,
            "ecosystem": exposure.ecosystem,
            "direct": exposure.direct,
            "match_type": exposure.match_type,
            "business_score": exposure.business_score,
            "baseline_score": exposure.baseline_score,
            "tier": exposure.tier,
            "state": exposure.state,
            "explanation": (json.loads(exposure.score_explanation)
                            if exposure.score_explanation else None),
            "dependabot_alert_url": exposure.dependabot_alert_url,
            "first_patched_version": exposure.first_patched_version,
            "fix_effort_band": exposure.fix_effort_band,
            "alert_match_method": exposure.alert_match_method,
            "fix_effort_label": (bia.EFFORT_BANDS.get(exposure.fix_effort_band) or {}
                                 ).get("label"),
            "quick_win_score": exposure.quick_win_score,
            "detected_at": (exposure.detected_at.isoformat()
                            if exposure.detected_at else None),
            "resolved_at": (exposure.resolved_at.isoformat()
                            if exposure.resolved_at else None),
        })
    return out


@app.get("/api/exposures/{exposure_id}")
def get_exposure(exposure_id: int, session: Session = Depends(get_session)):
    exposure = session.get(Exposure, exposure_id)
    if exposure is None:
        raise HTTPException(404, "no such finding")
    repo = session.get(Repository, exposure.repository_id)
    events = (session.query(RemediationEvent)
              .filter_by(exposure_id=exposure_id)
              .order_by(RemediationEvent.occurred_at).all())
    return {
        "id": exposure.id,
        "repository": repo.full_name if repo else None,
        "cve_id": exposure.cve_id,
        "component": exposure.component_name,
        "version": exposure.component_version,
        "business_score": exposure.business_score,
        "baseline_score": exposure.baseline_score,
        "tier": exposure.tier,
        "state": exposure.state,
        "explanation": (json.loads(exposure.score_explanation)
                        if exposure.score_explanation else None),
        "handoff_url": remediation.handoff_url(exposure, repo) if repo else None,
        "handoff_precise": remediation.handoff_is_precise(exposure),
        "alert_match_method": exposure.alert_match_method,
        "handoff_search_url": (remediation.handoff_search_url(exposure, repo)
                               if repo else None),
        "dependabot_alert_number": exposure.dependabot_alert_number,
        "timeline": [
            {"event": e.event_type, "detail": e.detail,
             "at": e.occurred_at.isoformat() if e.occurred_at else None}
            for e in events
        ],
    }


@app.post("/api/exposures/{exposure_id}/handoff")
def handoff(exposure_id: int, session: Session = Depends(get_session)):
    """The one-click deep link. Records that the handoff was opened."""
    exposure = session.get(Exposure, exposure_id)
    if exposure is None:
        raise HTTPException(404, "no such finding")
    repo = session.get(Repository, exposure.repository_id)
    remediation.record_handoff(session, exposure)
    return {"url": remediation.handoff_url(exposure, repo)}


def _dedupe_exposures(rows):
    """
    Collapse findings describing the same vulnerability in the same place.

    Grouped on (repository, component, version, CVE). Findings without a CVE
    keep their advisory id as the key, so genuinely distinct advisories are not
    merged merely because both lack a CVE. The highest-scoring member of each
    group is retained.
    """
    grouped = {}
    for exposure in rows:
        key = (exposure.repository_id,
               (exposure.component_name or "").lower(),
               exposure.component_version,
               exposure.cve_id or exposure.advisory_id)
        best = grouped.get(key)
        if best is None or (exposure.business_score or 0) > (best.business_score or 0):
            grouped[key] = exposure
    return list(grouped.values())


@app.get("/api/triage-funnel")
def triage_funnel(session: Session = Depends(get_session)):
    """
    How a component inventory narrows to a day's work.

    The single most useful number this system produces is not how much it
    found, but how much it lets a team ignore. This reports each stage of that
    reduction, from every component in the estate down to the findings that are
    both business-critical and cheap to fix.
    """
    from .models import Component

    components = session.query(Component).count()
    all_findings = session.query(Exposure).filter(Exposure.state == "open").all()
    unique = _dedupe_exposures(all_findings)

    critical = [e for e in unique if e.tier == "CRITICAL"]
    regulated = [e for e in unique if (e.compliance_factor or 1.0) > 1.0]
    top_tier = sorted(unique, key=lambda e: -(e.business_score or 0))[:10]
    quick = [e for e in unique
             if e.quick_win_score and e.fix_effort_band == "PATCH"]

    def pct(part, whole):
        return round(100 * part / whole, 1) if whole else 0.0

    stages = [
        {"stage": "Components inventoried", "count": components,
         "note": "every dependency across the organisation"},
        {"stage": "Vulnerability findings", "count": len(all_findings),
         "note": "components matched to a published advisory",
         "reduction_from_previous": pct(len(all_findings), components)},
        {"stage": "Distinct vulnerabilities", "count": len(unique),
         "note": "after collapsing duplicate advisory records",
         "reduction_from_previous": pct(len(unique), len(all_findings))},
        {"stage": "Business-critical", "count": len(critical),
         "note": "CRITICAL tier once business context is applied",
         "reduction_from_previous": pct(len(critical), len(unique))},
        {"stage": "Top 10 to act on", "count": len(top_tier),
         "note": "the queue a team actually works through today"},
    ]

    return {
        "stages": stages,
        "headline": ("%d components reduced to %d findings, %d distinct, "
                     "%d business-critical"
                     % (components, len(all_findings), len(unique), len(critical))),
        "duplicate_records_collapsed": len(all_findings) - len(unique),
        "in_regulatory_scope": len(regulated),
        "patch_level_quick_wins": len(quick),
        "overall_reduction_pct": pct(len(critical), components),
    }


class RepositoryIn(BaseModel):
    full_name: str
    manual_criticality_tier: str = "medium"


@app.post("/api/repositories/add")
def add_repository(payload: RepositoryIn,
                   session: Session = Depends(get_session)):
    """
    Begin monitoring a repository named explicitly.

    /api/sync discovers everything in the configured organisation. This adds a
    single repository by full name, including one outside that organisation, so
    the tool can be pointed at whatever an engineer actually needs to watch
    rather than only at a whole org. The repository must be visible to the
    configured token, which is verified before anything is stored.
    """
    full_name = payload.full_name.strip().strip("/")
    if "/" not in full_name:
        raise HTTPException(400, "use the owner/repository form, for example "
                                 "octocat/hello-world")

    gh = client()
    probe = gh._request("GET", "/repos/%s" % full_name, tolerate_failure=True)
    if probe is None:
        raise HTTPException(
            404, "GitHub returned nothing for '%s'. Check the name, and that "
                 "the configured token can see it." % full_name)
    info = probe.json()

    existing = (session.query(Repository)
                .filter_by(full_name=full_name).one_or_none())
    row = existing or Repository(full_name=full_name,
                                 name=info.get("name") or full_name.split("/")[-1])
    row.default_branch = info.get("default_branch") or "main"
    row.ecosystem = info.get("language")
    row.manual_criticality_tier = payload.manual_criticality_tier
    if existing is None:
        session.add(row)
    session.commit()

    count = pipeline.ingest_sbom(session, gh, row)
    if count == 0:
        return {"repository": full_name, "added": True, "components": 0,
                "exposures": 0,
                "note": "Added, but GitHub returned no SBOM yet. It may still "
                        "be generating the dependency graph; scan again shortly."}

    components = [{"name": c.name, "ecosystem": c.ecosystem, "version": c.version}
                  for c in session.query(Component).filter_by(repository_id=row.id)]
    advisories = pipeline.refresh_vulnerability_data(session, components)
    exposures = pipeline.correlate_repository(session, row, advisories)
    pipeline.score_repository(session, row)
    return {"repository": full_name, "added": True, "components": count,
            "exposures": exposures, "note": None}


@app.delete("/api/repositories/{repository_id}")
def remove_repository(repository_id: int,
                      session: Session = Depends(get_session)):
    """Stop monitoring a repository and discard its findings."""
    row = session.get(Repository, repository_id)
    if row is None:
        raise HTTPException(404, "no such repository")
    name = row.full_name
    session.delete(row)
    session.commit()
    return {"removed": name}


@app.get("/api/status")
def status(session: Session = Depends(get_session)):
    """
    Freshness and health, for the interface to display.

    A dashboard that cannot say when its data was gathered invites the reader to
    assume it is current, which is the wrong default.
    """
    from .models import Component

    last = None
    for repo in session.query(Repository).all():
        if repo.last_ingested_at and (last is None or repo.last_ingested_at > last):
            last = repo.last_ingested_at

    unmapped = [r.full_name for r in session.query(Repository).all()
                if not session.query(ProcessRepositoryLink)
                .filter_by(repository_id=r.id).count()]
    never = [r.full_name for r in session.query(Repository).all()
             if r.last_ingested_at is None]
    linked = (session.query(Exposure)
              .filter(Exposure.dependabot_alert_number.isnot(None)).count())

    return {
        "last_scan": last.isoformat() if last else None,
        "repositories": session.query(Repository).count(),
        "components": session.query(Component).count(),
        "unmapped_repositories": unmapped,
        "never_scanned": never,
        "findings_linked_to_alerts": linked,
        "business_processes": session.query(BusinessProcess).count(),
    }


# ---------------------------------------------------------------------------
# Zero-day lookup
#
# The founding question of this project: a vulnerability is disclosed, and a
# security team needs to know within minutes which of its applications contain
# the affected component. Answering it must not require a full portfolio scan,
# because the advisory may post-date the last ingestion by hours.
#
# The lookup therefore works in two passes. Findings already correlated are
# returned immediately. If the advisory is unknown to the local knowledge base,
# it is fetched live from OSV, its affected packages are extracted, and the
# stored component inventory is searched directly -- so a CVE published this
# morning can be answered against an inventory ingested last week.
# ---------------------------------------------------------------------------

ADVISORY_PREFIXES = ("CVE-", "GHSA-", "PYSEC-", "GO-", "RUSTSEC-", "OSV-",
                     "MAL-", "USN-", "DSA-", "RHSA-")


def classify_query(text):
    """
    Work out what the user pasted.

    A security engineer is handed an advisory identifier, a Package URL, or
    simply a package name, depending on who is asking. Requiring them to know
    which form the tool accepts is a needless obstacle, so it is inferred.
    """
    raw = (text or "").strip()
    if not raw:
        return None, None

    if raw.lower().startswith("pkg:"):
        parsed = matching.parse_purl(raw)
        if parsed:
            return "package", {"name": parsed["name"],
                               "ecosystem": parsed.get("ecosystem"),
                               "version": parsed.get("version")}
        return "package", {"name": raw, "ecosystem": None, "version": None}

    # Advisory identifiers are case-sensitive in OSV, so only the prefix is
    # normalised for comparison; the identifier itself is passed through as
    # typed.
    if any(raw.upper().startswith(p) for p in ADVISORY_PREFIXES):
        prefix, _, rest = raw.partition("-")
        return "advisory", prefix.upper() + "-" + rest

    # A comparison, as an advisory states it: "lodash < 4.17.21" means every
    # version below the fix is affected. Evaluating that against the inventory
    # is the whole question, and doing it by eye across a dozen versions is
    # where mistakes are made.
    comparison = re.match(r"^(.+?)\s*(<=|>=|<|>|==|=)\s*([0-9][^\s]*)$", raw)
    if comparison:
        return "package", {
            "name": comparison.group(1).strip(),
            "ecosystem": None,
            "version": None,
            "operator": {"=": "=="}.get(comparison.group(2), comparison.group(2)),
            "bound": comparison.group(3).strip(),
        }

    # A package name, optionally with a version. The separator is the last "@",
    # which leaves a leading "@" on a scoped npm package where it belongs.
    name, version = raw, None
    at = raw.rfind("@")
    if at > 0:
        name, version = raw[:at], raw[at + 1:]
    return "package", {"name": name.strip(),
                       "ecosystem": None,
                       "version": (version or "").strip() or None}


@app.get("/api/lookup")
def zero_day_lookup(cve: str, session: Session = Depends(get_session)):
    """
    Which repositories are exposed?

    Accepts an advisory identifier (CVE, GHSA, PYSEC and similar), a Package
    URL, or a plain package name with an optional version.
    """
    from .models import Component

    kind, parsed = classify_query(cve)
    if kind is None:
        raise HTTPException(400, "supply a CVE, GHSA, Package URL or package name")

    if kind == "package":
        return _package_lookup(session, parsed)

    identifier = parsed

    repos = {r.id: r for r in session.query(Repository).all()}

    # Pass one: already correlated and scored.
    known = (session.query(Exposure)
             .filter((Exposure.cve_id == identifier) |
                     (Exposure.advisory_id == identifier)).all())
    if known:
        known.sort(key=lambda e: -(e.business_score or 0))
        return {
            "identifier": identifier,
            "source": "already correlated",
            "advisory_known_locally": True,
            "affected_repository_count": len({e.repository_id for e in known}),
            "findings": [_lookup_row(session, e, repos.get(e.repository_id))
                         for e in known],
            "note": None,
        }

    # Pass two: unknown locally, so retrieve the advisory and search the
    # inventory directly. This is the zero-day path.
    advisory = feeds.fetch_osv_advisory(identifier)
    if advisory is None and identifier.startswith("CVE-"):
        # OSV indexes many advisories under an ecosystem identifier with the
        # CVE recorded only as an alias, so a direct fetch can miss.
        try:
            found = feeds.requests.post(
                "%s/query" % feeds.OSV_API, json={"query": identifier},
                headers={"User-Agent": config.USER_AGENT}, timeout=20)
            if found.ok:
                vulns = found.json().get("vulns") or []
                if vulns:
                    advisory = vulns[0]
        except Exception:
            advisory = None

    if advisory is None:
        return {
            "identifier": identifier, "source": "not found",
            "advisory_known_locally": False,
            "affected_repository_count": 0, "findings": [],
            "note": ("No advisory with that identifier was found. Check the "
                     "identifier, or the advisory may not yet be published to "
                     "the vulnerability database."),
        }

    matches, packages = [], []
    for affected in advisory.get("affected", []) or []:
        pkg = affected.get("package", {}) or {}
        name = (pkg.get("name") or "").lower()
        ecosystem = (pkg.get("ecosystem") or "")
        if not name:
            continue
        packages.append("%s (%s)" % (pkg.get("name"), ecosystem or "unknown"))

        query = session.query(Component).filter(
            func.lower(Component.name) == name)
        if ecosystem:
            query = query.filter(Component.ecosystem == ecosystem)

        for component in query.all():
            hit, match_type = matching.advisory_affects({
                "name": component.name, "version": component.version,
                "ecosystem": component.ecosystem}, advisory)
            if not hit:
                continue
            repo = repos.get(component.repository_id)
            processes, regimes = ([], [])
            if repo is not None:
                processes, regimes = pipeline.repository_business_context(
                    session, repo)
            criticality, _ = bia.repository_criticality(
                [p.as_attributes() for p in processes])
            score, vector = feeds.extract_cvss(advisory)
            result = bia.composite_score(score, None, criticality, regimes)
            matches.append({
                "repository": repo.full_name if repo else None,
                "business_process": "; ".join(p.name for p in processes) or None,
                "regulatory_scope": regimes,
                "component": component.name,
                "version": component.version,
                "ecosystem": component.ecosystem,
                "direct": component.direct,
                "dependency_path": component.dependency_path,
                "match_type": match_type,
                "indicative_score": result["score"],
                "indicative_tier": result["tier"],
                "repository_url": ("https://github.com/%s" % repo.full_name
                                   if repo else None),
            })

    matches.sort(key=lambda m: -(m["indicative_score"] or 0))
    return {
        "identifier": identifier,
        "source": "live advisory lookup against stored inventory",
        "advisory_known_locally": False,
        "advisory_summary": advisory.get("summary")
                            or (advisory.get("details") or "")[:300],
        "affected_packages": packages,
        "affected_repository_count": len({m["repository"] for m in matches}),
        "findings": matches,
        "note": ("Scores are indicative: they use the advisory's severity and "
                 "the repository's derived business criticality, but no EPSS "
                 "value, since exploitation probability is fetched during a "
                 "full scan. Run a scan to record these as tracked findings."),
    }


def _package_lookup(session, spec):
    """
    Where is this package used, and is any copy of it vulnerable?

    Answers the question a security engineer is asked when a package is named
    rather than an advisory: do we use this anywhere, at what versions, and does
    any of it matter. Every version present is reported, not only the vulnerable
    ones, because "we use it but at a safe version" is itself the answer to the
    question that was asked.
    """
    from .models import Component

    name = (spec.get("name") or "").lower()
    if not name:
        raise HTTPException(400, "supply a package name")

    repos = {r.id: r for r in session.query(Repository).all()}

    query = session.query(Component).filter(func.lower(Component.name) == name)
    if spec.get("ecosystem"):
        query = query.filter(Component.ecosystem == spec["ecosystem"])
    components = query.all()

    # Fall back to a contains match so "log4j" finds "log4j-core".
    partial = False
    if not components:
        components = (session.query(Component)
                      .filter(func.lower(Component.name).like("%%%s%%" % name))
                      .all())
        partial = bool(components)

    if not components:
        return {
            "identifier": spec.get("name"), "query_kind": "package",
            "source": "inventory search", "advisory_known_locally": False,
            "affected_repository_count": 0, "findings": [],
            "note": ("No component matching that name is present in any "
                     "monitored repository. Check the spelling, or the package "
                     "may genuinely not be in use."),
        }

    wanted = spec.get("version")
    operator, bound = spec.get("operator"), spec.get("bound")

    def below_threshold(version):
        """Evaluate a component version against an advisory's stated bound."""
        if not operator or not version:
            return None
        try:
            order = matching.compare_versions(version, bound)
        except matching.InvalidVersion:
            return None
        return {"<": order < 0, "<=": order <= 0, ">": order > 0,
                ">=": order >= 0, "==": order == 0}[operator]

    findings, versions, unknown_versions = [], set(), 0
    for component in components:
        if component.version:
            versions.add(str(component.version))
        if wanted and str(component.version) != str(wanted):
            continue

        verdict = below_threshold(component.version)
        if operator:
            if verdict is None:
                unknown_versions += 1
            elif verdict is False:
                continue

        repo = repos.get(component.repository_id)
        exposure = None
        if repo is not None:
            exposure = (session.query(Exposure)
                        .filter_by(repository_id=repo.id,
                                   component_name=component.name,
                                   component_version=component.version)
                        .order_by(Exposure.business_score.desc()).first())
        processes, regimes = ([], [])
        if repo is not None:
            processes, regimes = pipeline.repository_business_context(session, repo)

        findings.append({
            "repository": repo.full_name if repo else None,
            "business_process": "; ".join(p.name for p in processes) or None,
            "regulatory_scope": regimes,
            "component": component.name,
            "version": component.version,
            "ecosystem": component.ecosystem,
            "direct": component.direct,
            "dependency_path": component.dependency_path,
            "match_type": exposure.match_type if exposure else None,
            "indicative_score": exposure.business_score if exposure else None,
            "indicative_tier": exposure.tier if exposure else "NO KNOWN ISSUE",
            "state": exposure.state if exposure else None,
            "cve_id": exposure.cve_id if exposure else None,
            "dependabot_alert_url": (exposure.dependabot_alert_url
                                     if exposure else None),
            "repository_url": ("https://github.com/%s" % repo.full_name
                               if repo else None),
        })

    findings.sort(key=lambda f: -(f["indicative_score"] or 0))
    vulnerable = [f for f in findings if f["indicative_score"] is not None]

    if operator:
        affected_versions = sorted({str(f["version"]) for f in findings
                                    if f["version"]})
        safe = sorted(v for v in versions if v not in affected_versions)
        note = ("%d component%s in the estate satisf%s %s %s %s. "
                % (len(findings), "" if len(findings) == 1 else "s",
                   "ies" if len(findings) == 1 else "y",
                   spec.get("name"), operator, bound))
        if safe:
            note += ("Also present at %s, which the stated range does not cover. "
                     % ", ".join(safe))
        if unknown_versions:
            note += ("%d component%s declare a version constraint rather than a "
                     "resolved version and could not be evaluated; they are "
                     "included so they are not silently missed. "
                     % (unknown_versions, "" if unknown_versions == 1 else "s"))
        if vulnerable:
            note += "%d already match a published advisory." % len(vulnerable)
    else:
        note = ("%d of these copies has a known vulnerability."
                % len(vulnerable)) if vulnerable else (
            "This package is present but no copy of it currently matches a known "
            "advisory. Versions in use: %s." % ", ".join(sorted(versions)))
    if partial:
        note = "Matched by partial name. " + note

    return {
        "identifier": (("%s %s %s" % (spec.get("name"), operator, bound))
                       if operator else spec.get("name")),
        "query_kind": "package",
        "version_rule": ("%s %s" % (operator, bound)) if operator else None,
        "source": ("inventory search against the stated version range"
                   if operator else "inventory search"),
        "advisory_known_locally": bool(vulnerable),
        "advisory_summary": ("Present in %d repositor%s at version%s %s"
                             % (len({f["repository"] for f in findings}),
                                "y" if len({f["repository"] for f in findings}) == 1
                                else "ies",
                                "" if len(versions) == 1 else "s",
                                ", ".join(sorted(versions)) or "unresolved")),
        "affected_packages": sorted(versions),
        "affected_repository_count": len({f["repository"] for f in findings}),
        "vulnerable_count": len(vulnerable),
        "findings": findings,
        "note": note,
    }


def _lookup_row(session, exposure, repo):
    processes, regimes = ([], [])
    if repo is not None:
        processes, regimes = pipeline.repository_business_context(session, repo)
    return {
        "repository": repo.full_name if repo else None,
        "business_process": "; ".join(p.name for p in processes) or None,
        "regulatory_scope": regimes,
        "component": exposure.component_name,
        "version": exposure.component_version,
        "ecosystem": exposure.ecosystem,
        "direct": exposure.direct,
        "dependency_path": exposure.dependency_path,
        "match_type": exposure.match_type,
        "indicative_score": exposure.business_score,
        "indicative_tier": exposure.tier,
        "state": exposure.state,
        "dependabot_alert_url": exposure.dependabot_alert_url,
        "repository_url": ("https://github.com/%s" % repo.full_name
                           if repo else None),
    }


# ---------------------------------------------------------------------------
# Business context  (Objective 1)
# ---------------------------------------------------------------------------

@app.get("/api/business-processes")
def list_processes(session: Session = Depends(get_session)):
    out = []
    for process in session.query(BusinessProcess).all():
        links = (session.query(ProcessRepositoryLink)
                 .filter_by(process_id=process.id).all())
        repos = [session.get(Repository, l.repository_id) for l in links]
        out.append({
            "id": process.id,
            "name": process.name,
            "description": process.description,
            "owner": process.owner,
            "revenue_dependency": process.revenue_dependency,
            "customer_facing": process.customer_facing,
            "availability_requirement": process.availability_requirement,
            "data_sensitivity": process.data_sensitivity,
            "regulatory_scope": process.regimes(),
            "source_document": process.source_document,
            "source_reference": process.source_reference,
            "repositories": [r.full_name for r in repos if r],
        })
    return out


@app.post("/api/business-processes")
def create_process(payload: ProcessIn, session: Session = Depends(get_session)):
    existing = (session.query(BusinessProcess)
                .filter_by(name=payload.name).one_or_none())
    process = existing or BusinessProcess(name=payload.name)
    for field, value in payload.model_dump().items():
        setattr(process, field, value)
    if existing is None:
        session.add(process)
    session.commit()
    return {"id": process.id, "name": process.name, "created": existing is None}


@app.post("/api/business-processes/link")
def link_process(payload: LinkIn, session: Session = Depends(get_session)):
    if session.get(BusinessProcess, payload.process_id) is None:
        raise HTTPException(404, "no such business process")
    repository = session.get(Repository, payload.repository_id)
    if repository is None:
        raise HTTPException(404, "no such repository")

    existing = (session.query(ProcessRepositoryLink)
                .filter_by(process_id=payload.process_id,
                           repository_id=payload.repository_id).one_or_none())
    if existing is None:
        session.add(ProcessRepositoryLink(**payload.model_dump()))
        session.commit()

    # Business context changed, so this repository's findings must be rescored.
    rescored = pipeline.score_repository(session, repository)
    return {"linked": True, "rescored_findings": rescored}


@app.post("/api/rescore")
def rescore(session: Session = Depends(get_session)):
    """Recompute every score. Cheap, and useful after editing weights."""
    total = sum(pipeline.score_repository(session, r)
                for r in session.query(Repository).all())
    return {"rescored_findings": total}


# ---------------------------------------------------------------------------
# Remediation orchestration  (Objective 3)
# ---------------------------------------------------------------------------

@app.post("/api/remediation/correlate")
def correlate_alerts(session: Session = Depends(get_session)):
    return remediation.correlate_alerts(session, client())


@app.post("/api/remediation/refresh")
def refresh_state(session: Session = Depends(get_session)):
    return remediation.refresh_resolution_state(session, client())


@app.get("/api/remediation/coverage")
def alert_coverage(session: Session = Depends(get_session)):
    """
    How many open findings have a Dependabot alert behind them, and why the
    rest do not.

    Reported because a finding without an alert is not a failure but does need
    explaining, and an interface that shows the gap without accounting for it
    invites the reader to assume something is broken.
    """
    open_rows = session.query(Exposure).filter(Exposure.state == "open").all()
    linked = [e for e in open_rows if e.dependabot_alert_number is not None]
    unlinked = [e for e in open_rows if e.dependabot_alert_number is None]

    reasons = {"version not resolved": 0, "no advisory identifier": 0,
               "no matching alert": 0}
    for e in unlinked:
        if e.match_type == "NO_VERSION":
            reasons["version not resolved"] += 1
        elif not e.cve_id:
            reasons["no advisory identifier"] += 1
        else:
            reasons["no matching alert"] += 1

    by_method = {}
    for e in linked:
        key = e.alert_match_method or "identifier"
        by_method[key] = by_method.get(key, 0) + 1

    total = len(open_rows) or 1
    return {
        "open_findings": len(open_rows),
        "linked": len(linked),
        "unlinked": len(unlinked),
        "coverage_pct": round(100 * len(linked) / total, 1),
        "linked_by_method": by_method,
        "unlinked_reasons": reasons,
        "explanation": (
            "A finding without an alert is still a real finding. Dependabot and "
            "the vulnerability database do not cover identically: the database "
            "aggregates more sources, and Dependabot applies its own inclusion "
            "rules. Findings whose manifest declares a version constraint rather "
            "than a resolved version cannot be matched to an alert at all."),
    }


# ---------------------------------------------------------------------------
# Impact measurement  (Objective 4)
# ---------------------------------------------------------------------------

@app.get("/api/impact")
def get_impact(session: Session = Depends(get_session)):
    return impact.compute_impact(session)


@app.post("/api/impact/snapshot")
def take_snapshot(session: Session = Depends(get_session)):
    return impact.capture_snapshot(session)


@app.get("/api/impact/history")
def impact_history(session: Session = Depends(get_session)):
    return impact.snapshot_history(session)


# ---------------------------------------------------------------------------
# Evaluation  (Phase 6)
# ---------------------------------------------------------------------------

@app.get("/api/evaluation")
def evaluation(k: int | None = None, session: Session = Depends(get_session)):
    """
    Compare business-aware against technical-only ranking.

    Ground truth is read from ground_truth.json -- a file written before any
    score is computed, so the comparison is not circular.
    """
    path = os.path.join(os.path.dirname(DASHBOARD_DIR), "ground_truth.json")
    if not os.path.exists(path):
        raise HTTPException(
            400, "ground_truth.json not found -- annotate findings first")

    with open(path) as handle:
        truth = {int(key): int(value) for key, value in json.load(handle).items()}

    findings = [
        {"id": e.id,
         "business_score": e.business_score,
         "baseline_score": e.baseline_score}
        for e in session.query(Exposure).all()
    ]
    result = evaluate.compare_rankings(findings, truth, k)
    result["precision_at_10_business"] = evaluate.precision_at_k(
        result["business_ranking"], truth, 10)
    result["precision_at_10_baseline"] = evaluate.precision_at_k(
        result["baseline_ranking"], truth, 10)
    return result


@app.get("/api/quick-wins")
def quick_wins(limit: int = 10, session: Session = Depends(get_session)):
    """
    Findings that matter to the business AND are cheap to fix.

    A second view over the same queue, ranked by quick_win_score rather than
    business score. Effort never alters the risk score itself -- discounting a
    critical finding for being awkward to fix would be exactly wrong. It breaks
    ties and answers a different question: what is worth the next twenty
    minutes. Findings with no available patch are excluded, because they cannot
    be remediated by upgrading and need mitigation instead.
    """
    from .models import Exposure

    rows = (session.query(Exposure)
            .filter(Exposure.state == "open")
            .filter(Exposure.quick_win_score.isnot(None))
            .filter(Exposure.fix_effort_band != "NO_FIX")
            .all())
    rows.sort(key=lambda e: -(e.quick_win_score or 0))

    repos = {r.id: r for r in session.query(Repository).all()}
    out = []
    for exposure in rows[:limit]:
        repo = repos.get(exposure.repository_id)
        processes, _ = ([], [])
        if repo is not None:
            processes, _ = pipeline.repository_business_context(session, repo)
        band = bia.EFFORT_BANDS.get(exposure.fix_effort_band) or {}
        out.append({
            "id": exposure.id,
            "repository": repo.full_name if repo else None,
            "business_process": "; ".join(p.name for p in processes),
            "cve_id": exposure.cve_id,
            "component": exposure.component_name,
            "upgrade": "%s -> %s" % (exposure.component_version,
                                     exposure.first_patched_version),
            "fix_effort_band": exposure.fix_effort_band,
            "alert_match_method": exposure.alert_match_method,
            "fix_effort_label": band.get("label"),
            "fix_effort_note": band.get("note"),
            "business_score": exposure.business_score,
            "quick_win_score": exposure.quick_win_score,
            "dependabot_alert_url": exposure.dependabot_alert_url,
        })
    return out


@app.get("/api/blast-radius")
def blast_radius(session: Session = Depends(get_session)):
    """
    One advisory, many repositories.

    Fixing a single package can protect several business processes at once.
    Grouping by advisory turns a list of chores into a list of leverage, and the
    data is already there -- the same advisory_id simply appears on more than
    one repository.
    """
    from .models import Exposure

    repos = {r.id: r for r in session.query(Repository).all()}
    grouped = {}
    for exposure in session.query(Exposure).filter(Exposure.state == "open"):
        key = exposure.cve_id or exposure.advisory_id
        entry = grouped.setdefault(key, {
            "identifier": key,
            "component": exposure.component_name,
            "repositories": [],
            "business_processes": set(),
            "max_business_score": 0.0,
        })
        repo = repos.get(exposure.repository_id)
        if repo is not None:
            entry["repositories"].append(repo.full_name)
            processes, _ = pipeline.repository_business_context(session, repo)
            entry["business_processes"].update(p.name for p in processes)
        entry["max_business_score"] = max(
            entry["max_business_score"], exposure.business_score or 0.0)

    out = []
    for entry in grouped.values():
        entry["business_processes"] = sorted(entry["business_processes"])
        entry["repository_count"] = len(set(entry["repositories"]))
        entry["repositories"] = sorted(set(entry["repositories"]))
        entry["process_count"] = len(entry["business_processes"])
        out.append(entry)

    out.sort(key=lambda e: (-e["repository_count"], -e["max_business_score"]))
    return out


# ---------------------------------------------------------------------------
# Export
#
# Security teams live in spreadsheets and ticketing systems, and an examiner
# will ask whether findings can leave the tool. CSV for triage and audit
# evidence, JSON for machine consumption. Both respect the current filter, so
# what you download is what you were looking at.
# ---------------------------------------------------------------------------

# NO_VERSION marks a finding where the manifest declared a constraint such as
# "^1.15.1" rather than a resolved version, so the range could not be evaluated.
EXPORT_COLUMNS = [
    "rank", "repository", "business_process", "regulatory_scope",
    "cve_id", "advisory_id", "component", "version", "ecosystem",
    "direct_dependency", "match_type", "cvss_contribution", "epss_contribution",
    "criticality_contribution", "compliance_factor",
    "business_score", "baseline_score", "tier", "state",
    "dependabot_alert_url", "detected_at", "resolved_at",
]


def _export_rows(session, state):
    from .models import Exposure

    query = session.query(Exposure)
    if state and state != "all":
        query = query.filter(Exposure.state == state)
    rows = sorted(query.all(), key=lambda e: -(e.business_score or 0))

    repos = {r.id: r for r in session.query(Repository).all()}
    out = []
    for rank, exposure in enumerate(rows, 1):
        repo = repos.get(exposure.repository_id)
        processes, regimes = ([], [])
        if repo is not None:
            processes, regimes = pipeline.repository_business_context(session, repo)
        explanation = (json.loads(exposure.score_explanation)
                       if exposure.score_explanation else {})
        contributions = explanation.get("contributions", {})
        out.append({
            "rank": rank,
            "repository": repo.full_name if repo else "",
            "business_process": "; ".join(p.name for p in processes),
            "regulatory_scope": ",".join(regimes),
            "cve_id": exposure.cve_id or "",
            "advisory_id": exposure.advisory_id or "",
            "component": exposure.component_name or "",
            "version": exposure.component_version or "",
            "ecosystem": exposure.ecosystem or "",
            "direct_dependency": "yes" if exposure.direct else "no",
            "match_type": exposure.match_type or "",
            "cvss_contribution": contributions.get("cvss", ""),
            "epss_contribution": contributions.get("epss", ""),
            "criticality_contribution": contributions.get("criticality", ""),
            "compliance_factor": exposure.compliance_factor or 1.0,
            "business_score": exposure.business_score,
            "baseline_score": exposure.baseline_score,
            "tier": exposure.tier or "",
            "state": exposure.state or "",
            "dependabot_alert_url": exposure.dependabot_alert_url or "",
            "detected_at": (exposure.detected_at.isoformat()
                            if exposure.detected_at else ""),
            "resolved_at": (exposure.resolved_at.isoformat()
                            if exposure.resolved_at else ""),
        })
    return out


def _stamp(extension):
    return "remediation-queue-%s.%s" % (
        dt.datetime.now().strftime("%Y%m%d-%H%M"), extension)


@app.get("/api/export/csv")
def export_csv(state: str | None = "open",
               session: Session = Depends(get_session)):
    """The prioritised queue as CSV, ranked exactly as the dashboard shows it."""
    rows = _export_rows(session, state)
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=EXPORT_COLUMNS)
    writer.writeheader()
    writer.writerows(rows)
    buffer.seek(0)
    return StreamingResponse(
        iter([buffer.getvalue()]), media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=%s" % _stamp("csv")})


@app.get("/api/export/json")
def export_json(state: str | None = "open",
                session: Session = Depends(get_session)):
    """Full export including the impact summary, for audit evidence."""
    payload = {
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "organisation": config.GITHUB_ORG,
        "filter_state": state,
        "scoring_model": {
            "weights": bia.SCORE_WEIGHTS,
            "criticality_weights": bia.CRITICALITY_WEIGHTS,
            "compliance_uplift_per_regime": bia.COMPLIANCE_UPLIFT_PER_REGIME,
            "max_compliance_uplift": bia.MAX_COMPLIANCE_UPLIFT,
        },
        "impact": impact.compute_impact(session),
        "findings": _export_rows(session, state),
    }
    body = json.dumps(payload, indent=2)
    return StreamingResponse(
        iter([body]), media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=%s" % _stamp("json")})


# ---------------------------------------------------------------------------
# SBOM upload  (Capstone 1, Objective 1 - ingestion sources 2 and 3)
#
# One endpoint serves both remaining sources: a CI/CD workflow posts the SBOM
# its build produced, and an analyst uploads one by hand. CycloneDX 1.4+ and
# SPDX 2.3 are both accepted and the format is detected from the document.
# ---------------------------------------------------------------------------

@app.post("/api/sbom/upload")
def upload_sbom(repository: str,
                document: dict = Body(...),
                session: Session = Depends(get_session)):
    """Ingest an SBOM posted directly rather than pulled from GitHub."""
    try:
        components, metadata = sbom_formats.parse(document)
    except sbom_formats.UnsupportedSBOM as error:
        raise HTTPException(400, str(error))

    if not components:
        raise HTTPException(400, "SBOM contains no components")

    row = (session.query(Repository)
           .filter_by(full_name=repository).one_or_none())
    if row is None:
        row = Repository(full_name=repository,
                         name=repository.split("/")[-1])
        session.add(row)
        session.flush()

    source = "%s upload (%s)" % (metadata["format"], metadata.get("tool") or "unknown tool")
    stored = pipeline.store_components(
        session, row, components,
        sbom=document if metadata["format"] == "SPDX" else None,
        source=source)

    return {
        "repository": repository,
        "format": metadata["format"],
        "spec_version": metadata.get("spec_version"),
        "tool": metadata.get("tool"),
        "components_received": len(components),
        "components_stored": stored,
        "quality": quality.assess(components, source).as_dict(),
    }


@app.get("/api/sbom/quality")
def sbom_quality(session: Session = Depends(get_session)):
    """Quality gate results per repository, worst first."""
    out = []
    for repo in session.query(Repository).all():
        out.append({
            "repository": repo.full_name,
            "source": repo.sbom_source,
            "score": repo.sbom_quality_score,
            "passed": repo.sbom_quality_passed,
            "has_dependency_chains": repo.has_dependency_chains,
            "detail": (json.loads(repo.sbom_quality_issues)
                       if repo.sbom_quality_issues else None),
        })
    out.sort(key=lambda r: (r["score"] is not None, r["score"] or 0))
    return out


# ---------------------------------------------------------------------------
# Dependency graph  (Capstone 1, Objective 2)
# ---------------------------------------------------------------------------

@app.get("/api/graph/exposure")
def component_exposure(name: str, ecosystem: str | None = None,
                       session: Session = Depends(get_session)):
    """
    Which repositories contain this component?

    The Capstone 1 question, answered by traversing the reverse dependency
    graph across the whole organisation rather than scanning per repository.
    """
    graph = pipeline.build_reverse_graph(session)
    return graph.blast_radius(ecosystem, name)


@app.get("/api/graph/shared")
def shared_components(minimum: int = 2, session: Session = Depends(get_session)):
    """Components present in several repositories, most widespread first."""
    graph = pipeline.build_reverse_graph(session)
    return {
        "backend": pipeline.depgraph.BACKEND,
        "components_indexed": graph.component_count,
        "repositories_indexed": graph.repository_count,
        "shared": graph.shared_components(minimum)[:50],
    }


@app.get("/api/graph/chain/{exposure_id}")
def dependency_chain(exposure_id: int, session: Session = Depends(get_session)):
    """
    The dependency path from the repository root to a vulnerable component.

    Returns null when the SBOM carries no relationship data, which is the
    honest answer for a flat inventory rather than a fabricated chain.
    """
    from .models import Component

    exposure = session.get(Exposure, exposure_id)
    if exposure is None:
        raise HTTPException(404, "no such finding")
    component = (session.query(Component)
                 .filter_by(repository_id=exposure.repository_id,
                            name=exposure.component_name).first())
    repo = session.get(Repository, exposure.repository_id)
    return {
        "exposure_id": exposure_id,
        "repository": repo.full_name if repo else None,
        "component": exposure.component_name,
        "chain": component.dependency_path if component else None,
        "depth": component.depth if component else None,
        "direct": component.direct if component else None,
        "chain_available": bool(repo and repo.has_dependency_chains),
        "note": (None if (repo and repo.has_dependency_chains) else
                 "This SBOM carries no dependency relationships, so the "
                 "component is detected but its chain cannot be reconstructed."),
    }


# ---------------------------------------------------------------------------
# Audit report  (Capstone 1, Phase 5)
# ---------------------------------------------------------------------------

@app.get("/api/report")
def audit_report(state: str | None = "open", limit: int = 50,
                 session: Session = Depends(get_session)):
    """Downloadable audit report of the prioritised queue."""
    findings = _export_rows(session, state)
    body, media_type, filename = reports.build_report(
        [_report_row(f) for f in findings],
        impact.compute_impact(session),
        config.GITHUB_ORG,
        bia.SCORE_WEIGHTS,
        limit)
    return StreamingResponse(
        iter([body]), media_type=media_type,
        headers={"Content-Disposition": "attachment; filename=%s" % filename})


def _report_row(row):
    return {
        "repository": row["repository"],
        "business_process": row["business_process"],
        "cve_id": row["cve_id"],
        "advisory_id": row["advisory_id"],
        "component": row["component"],
        "version": row["version"],
        "business_score": row["business_score"],
        "tier": row["tier"],
        "explanation": {"contributions": {
            "cvss": row["cvss_contribution"] or None,
            "epss": row["epss_contribution"] or None,
            "criticality": row["criticality_contribution"] or None,
        }},
    }


# ---------------------------------------------------------------------------
# Scheduler
# ---------------------------------------------------------------------------

@app.get("/api/scheduler")
def scheduler_status():
    return scheduler.status()


@app.post("/api/scheduler/start")
def scheduler_start():
    scheduler.start()
    return scheduler.status()


@app.post("/api/scheduler/stop")
async def scheduler_stop():
    await scheduler.stop()
    return scheduler.status()



# ---------------------------------------------------------------------------
# Ranking evaluation  (Objective 4)
#
# The claim is that business-aware ordering beats technical-only ordering.
# Demonstrating that the two differ is not the same as demonstrating one is
# better, so a human grades a sample on business consequence and both orderings
# are scored against that grading using NDCG.
#
# Two design points matter and both are visible in the response. The sample is
# POOLED -- the union of the top k from each ranking -- because grading only the
# business-aware top twenty would favour it by construction. And the worksheet
# omits both scores, because a grader who can see what the model decided is
# measuring their agreement with it rather than judging independently.
# ---------------------------------------------------------------------------

POOL_DEPTH = 20


class GradeIn(BaseModel):
    exposure_id: int
    relevance: int
    rationale: str | None = None


class GradesIn(BaseModel):
    graded_by: str | None = None
    grades: list[GradeIn]


def _gradeable(session):
    """Open, scored findings, de-duplicated so one vulnerability is graded once."""
    rows = (session.query(Exposure)
            .filter(Exposure.state == "open")
            .filter(Exposure.business_score.isnot(None))
            .filter(Exposure.baseline_score.isnot(None)).all())
    seen, unique = set(), []
    for e in rows:
        key = (e.repository_id, (e.component_name or "").lower(),
               e.component_version, e.cve_id or e.advisory_id)
        if key not in seen:
            seen.add(key)
            unique.append(e)
    return unique


@app.get("/api/evaluation/worksheet")
def evaluation_worksheet(depth: int = POOL_DEPTH,
                         session: Session = Depends(get_session)):
    """
    The findings to grade, with both scores deliberately withheld.

    Sorted by business process rather than by either ranking, so the order
    carries no signal about what the model decided and grading by process is
    natural.
    """
    from .models import GroundTruthGrade

    findings = _gradeable(session)
    if not findings:
        return {"pool": [], "note": "No scored open findings. Scan and seed "
                                    "business context first."}

    by_business = sorted(findings, key=lambda e: -(e.business_score or 0))[:depth]
    by_technical = sorted(findings, key=lambda e: -(e.baseline_score or 0))[:depth]
    pool, seen = [], set()
    for e in by_business + by_technical:
        if e.id not in seen:
            seen.add(e.id)
            pool.append(e)

    existing = {}
    for g in session.query(GroundTruthGrade).all():
        existing[(g.repository_full_name, (g.component_name or "").lower(),
                  g.component_version, g.advisory)] = g.relevance

    repos = {r.id: r for r in session.query(Repository).all()}
    rows = []
    for e in pool:
        repo = repos.get(e.repository_id)
        processes, regimes = ([], [])
        if repo is not None:
            processes, regimes = pipeline.repository_business_context(session, repo)
        key = (repo.full_name if repo else None,
               (e.component_name or "").lower(), e.component_version,
               e.cve_id or e.advisory_id)
        rows.append({
            "exposure_id": e.id,
            "repository": repo.full_name if repo else None,
            "business_process": "; ".join(p.name for p in processes) or None,
            "regulatory_scope": regimes,
            "component": e.component_name,
            "version": e.component_version or "unresolved",
            "advisory": e.cve_id or e.advisory_id,
            "direct": e.direct,
            "relevance": existing.get(key),
        })

    rows.sort(key=lambda r: ((r["business_process"] or "zzz"),
                             r["repository"] or "", r["component"] or ""))
    overlap = len(by_business) + len(by_technical) - len(pool)
    return {
        "pool": rows,
        "pool_size": len(rows),
        "depth": depth,
        "in_both_rankings": overlap,
        "graded": sum(1 for r in rows if r["relevance"] is not None),
        "note": ("Grade on what each finding would cost if left unfixed, not on "
                 "technical severity. Scores are withheld so the judgement is "
                 "independent of the model."),
    }


@app.post("/api/evaluation/grades")
def save_grades(payload: GradesIn, session: Session = Depends(get_session)):
    """Record or update the human grading."""
    from .models import GroundTruthGrade

    repos = {r.id: r for r in session.query(Repository).all()}
    saved = 0
    for item in payload.grades:
        if item.relevance not in (0, 1, 2, 3):
            raise HTTPException(400, "relevance must be 0, 1, 2 or 3")
        exposure = session.get(Exposure, item.exposure_id)
        if exposure is None:
            continue
        repo = repos.get(exposure.repository_id)
        key = dict(repository_full_name=repo.full_name if repo else None,
                   component_name=exposure.component_name,
                   component_version=exposure.component_version,
                   advisory=exposure.cve_id or exposure.advisory_id)
        row = session.query(GroundTruthGrade).filter_by(**key).one_or_none()
        if row is None:
            row = GroundTruthGrade(**key)
            session.add(row)
        row.exposure_id = exposure.id
        row.relevance = item.relevance
        row.rationale = item.rationale
        row.graded_by = payload.graded_by
        saved += 1
    session.commit()
    return {"saved": saved,
            "total_graded": session.query(GroundTruthGrade).count()}


def _truth_map(session):
    from .models import GroundTruthGrade

    findings = _gradeable(session)
    index = {}
    for e in findings:
        repo = session.get(Repository, e.repository_id)
        index[(repo.full_name if repo else None,
               (e.component_name or "").lower(), e.component_version,
               e.cve_id or e.advisory_id)] = e
    truth, matched = {}, []
    for g in session.query(GroundTruthGrade).all():
        e = index.get((g.repository_full_name, (g.component_name or "").lower(),
                       g.component_version, g.advisory))
        if e is not None:
            truth[e.id] = g.relevance
            matched.append(e)
    return truth, matched


def _factors(exposure):
    detail = json.loads(exposure.score_explanation or "{}")
    c = detail.get("contributions", {})
    return {"cvss": (c.get("cvss", 0) or 0) / (bia.SCORE_WEIGHTS["cvss"] * 10),
            "epss": (c.get("epss", 0) or 0) / (bia.SCORE_WEIGHTS["epss"] * 10),
            "criticality": (c.get("criticality", 0) or 0)
                           / (bia.SCORE_WEIGHTS["criticality"] * 10),
            "compliance": exposure.compliance_factor or 1.0}


@app.get("/api/evaluation/run")
def run_evaluation(k: int | None = None,
                   session: Session = Depends(get_session)):
    """
    Score both rankings against the recorded grading, and test whether the
    result survives a change in the criticality weight.
    """
    truth, findings = _truth_map(session)
    if len(truth) < 4:
        raise HTTPException(
            400, "At least four findings must be graded before the comparison "
                 "is meaningful. %d graded so far." % len(truth))

    spread = sorted(set(truth.values()))
    k = k or min(POOL_DEPTH, len(findings))
    rows = [{"id": e.id, "business_score": e.business_score,
             "baseline_score": e.baseline_score} for e in findings]
    result = evaluate.compare_rankings(rows, truth, k)

    cached = {e.id: _factors(e) for e in findings}
    sensitivity = []
    for w_crit in (0.05, 0.10, 0.15, 0.20, 0.25, 0.30, 0.35, 0.40):
        remaining = 1.0 - w_crit
        w_cvss, w_epss = remaining * (0.5 / 0.8), remaining * (0.3 / 0.8)
        scored = []
        for e in findings:
            f = cached[e.id]
            base = (f["cvss"] * w_cvss + f["epss"] * w_epss
                    + f["criticality"] * w_crit)
            scored.append({"id": e.id,
                           "business_score": min(base * f["compliance"], 1.0) * 10,
                           "baseline_score": e.baseline_score})
        r = evaluate.compare_rankings(scored, truth, k)
        sensitivity.append({
            "criticality_weight": w_crit,
            "cvss_weight": round(w_cvss, 3), "epss_weight": round(w_epss, 3),
            "ndcg_business_aware": r["ndcg_business_aware"],
            "ndcg_technical_only": r["ndcg_technical_only"],
            "delta": r["delta"],
            "published_model": abs(w_crit - 0.20) < 1e-9})

    better = sum(1 for s in sensitivity if s["delta"] > 0)
    lookup = {e.id: e for e in findings}

    def name(eid):
        e = lookup[eid]
        repo = session.get(Repository, e.repository_id)
        return {"repository": repo.full_name if repo else None,
                "component": e.component_name,
                "advisory": e.cve_id or e.advisory_id,
                "grade": truth.get(eid)}

    return {
        "graded": len(truth),
        "evaluated": len(findings),
        "k": k,
        "grade_distribution": {str(g): sum(1 for v in truth.values() if v == g)
                               for g in spread},
        "uniform_grading": len(spread) == 1,
        "ndcg_business_aware": result["ndcg_business_aware"],
        "ndcg_technical_only": result["ndcg_technical_only"],
        "delta": result["delta"],
        "relative_improvement_pct": result["relative_improvement_pct"],
        "precision_at": {
            str(cut): {
                "business_aware": evaluate.precision_at_k(
                    result["business_ranking"], truth, cut),
                "technical_only": evaluate.precision_at_k(
                    result["baseline_ranking"], truth, cut)}
            for cut in (3, 5, 10) if cut <= len(findings)},
        "sensitivity": sensitivity,
        "robust_at": better,
        "sensitivity_points": len(sensitivity),
        "top_business_aware": [name(i) for i in result["business_ranking"][:10]],
        "top_technical_only": [name(i) for i in result["baseline_ranking"][:10]],
    }


@app.delete("/api/evaluation/grades")
def clear_grades(session: Session = Depends(get_session)):
    from .models import GroundTruthGrade

    count = session.query(GroundTruthGrade).delete()
    session.commit()
    return {"cleared": count}


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

if os.path.isdir(DASHBOARD_DIR):
    app.mount("/static", StaticFiles(directory=DASHBOARD_DIR), name="static")

    @app.get("/")
    def dashboard():
        return FileResponse(os.path.join(DASHBOARD_DIR, "index.html"))


# ---------------------------------------------------------------------------
# Zero-day / pre-disclosure layer  (Capstone 1, Objectives 2-5)
# ---------------------------------------------------------------------------

ZERO_DAY_SOURCE_INFO = {
    "cvd": {
        "name": "Anthropic CVD ledger (findings discovered by Claude "
                "Mythos Preview and other Claude models)",
        "endpoint": config.CVD_LEDGER_URL,
        "auth": "none",
        "identifier": "ANT-YYYY-XXXXXXXX",
        "publishes": "hash commitment, then project and bug class, then "
                     "CVE/GHSA, then patch",
        "evidence": "project name only at reveal",
        "limits": "one high-quality stream, not a complete zero-day feed; "
                  "most findings never receive any identifier. Mythos is the "
                  "discovery engine behind these findings, not a queryable "
                  "API -- this ledger is the public interface to them. The "
                  "disclosed set is also a subset of what the models found, "
                  "since human triage is the rate-limiting step",
    },
    "ossfuzz": {
        "name": "OSS-Fuzz (published as OSV records)",
        "endpoint": "%s/query  |  %s/OSS-Fuzz/all.zip" % (config.OSV_API,
                                                          config.OSV_BUCKET),
        "auth": "none",
        "identifier": "OSV-YYYY-NNNN",
        "publishes": "crash type, crash state, pkg:generic purl, GIT "
                     "introduced and fixed commit ranges",
        "evidence": "upstream repository plus commit range",
        "limits": "public 90 days after report or 30 after the fix; commit "
                  "matching needs an SBOM that records a commit",
    },
    "ghsa": {
        "name": "GitHub Advisory Database",
        "endpoint": "%s/advisories" % config.GITHUB_API,
        "auth": "token recommended (works anonymously, heavily rate limited)",
        "identifier": "GHSA-xxxx-xxxx-xxxx",
        "publishes": "ecosystem, affected and fixed version ranges, aliases",
        "evidence": "PURL plus version range",
        "limits": "a GHSA is usually issued before NVD indexes the CVE, so "
                  "this is pre-NVD rather than pre-patch. GitHub Security Lab "
                  "findings arrive here: the Security Lab site publishes only "
                  "after a patch exists and offers no JSON API",
    },
    "debian": {
        "name": "Debian Security Tracker (TEMP entries)",
        "endpoint": config.DEBIAN_TRACKER_JSON,
        "auth": "none",
        "identifier": "TEMP-000000-NNNNNN",
        "publishes": "package, unfixed status and urgency for issues with no CVE",
        "evidence": "package name, sometimes a fixed version",
        "limits": "TEMP names are explicitly unstable; joined on package name, "
                  "never persisted as a key",
    },
    "euvd": {
        "name": "ENISA EU Vulnerability Database",
        "endpoint": "%s/search" % config.EUVD_API,
        "auth": "none",
        "identifier": "EUVD-YYYY-NNNNN",
        "publishes": "vendor and product, CVSS, EPSS, exploited flag",
        "evidence": "vendor and product strings",
        "limits": "beta and slow; list endpoints cap at 8 records",
    },
    "kev": {
        "name": "CISA Known Exploited Vulnerabilities",
        "endpoint": config.KEV_FEED_URL,
        "auth": "none",
        "identifier": "CVE (by definition)",
        "publishes": "confirmed in-the-wild exploitation, required action, "
                     "mandated due date, ransomware flag",
        "evidence": "enrichment only, not a correlation source",
        "limits": "not a pre-CVE feed; it is the one signal permitted to "
                  "override business-context ranking",
    },
}


@app.get("/api/zeroday/sources")
def zero_day_sources():
    """
    The feed inventory, with each source's limits stated alongside it.

    Exposed as an endpoint rather than buried in a README so the claim being
    made about each feed is inspectable at runtime -- including the two that
    are easy to overstate: GitHub Security Lab is not polled directly, and KEV
    is not a pre-CVE source.
    """
    return {
        "enabled": config.ZERODAY_SOURCES,
        "sources": ZERO_DAY_SOURCE_INFO,
        "stages": {
            "T0": "commitment - hash only, project withheld, nothing to correlate",
            "T1": "revealed - project and bug class, no identifier",
            "T2": "identified - CVE and/or GHSA assigned",
            "T3": "patched - fix shipped upstream",
        },
        "evidence_tiers": {
            "T3_PURL": "package plus affected semantic version range",
            "T2_PRODUCT": "vendor and product strings, fuzzy matched",
            "T1_COMMIT": "upstream repository plus GIT commit range",
            "T0_PROJECT": "project name alone, over-inclusive by design",
        },
    }


@app.post("/api/zeroday/sync")
def zero_day_sync(sources: str | None = None,
                  session: Session = Depends(get_session)):
    """
    Poll the pre-disclosure feeds, store, correlate and score.

    Deliberately separate from /api/sync: this needs no SBOM re-ingest, only
    the inventory already stored, so it is cheap enough to run every few
    minutes. That is what makes alerting within minutes of a reveal possible.
    """
    selected = [s.strip() for s in sources.split(",")] if sources else None
    return pipeline.run_zero_day_pipeline(
        session, sources=selected, github_token=config.GITHUB_TOKEN)


@app.get("/api/zeroday/findings")
def zero_day_findings(stage: str | None = None, source: str | None = None,
                      limit: int = 200, session: Session = Depends(get_session)):
    """Stored pre-disclosure findings, newest reveal first."""
    query = session.query(ZeroDayFinding)
    if stage:
        query = query.filter(ZeroDayFinding.stage == stage)
    if source:
        query = query.filter(ZeroDayFinding.source == source)

    rows = (query.order_by(ZeroDayFinding.revealed_at.desc().nullslast(),
                           ZeroDayFinding.first_seen_at.desc())
            .limit(min(limit, 1000)).all())
    return {
        "count": len(rows),
        "findings": [_zero_day_finding_row(r) for r in rows],
    }


def _zero_day_finding_row(row):
    return {
        "id": row.id,
        "source": row.source,
        "source_id": row.source_id,
        "stage": row.stage,
        "stage_label": zeroday_feeds.STAGE_LABEL.get(row.stage),
        "evidence_tier": row.evidence_tier,
        "project": row.project,
        "bug_class": row.bug_class,
        "summary": row.summary,
        "package": row.package_name,
        "ecosystem": row.ecosystem,
        "purl": row.purl,
        "repo_url": row.repo_url,
        "severity": row.severity_band,
        "cve_ids": [c for c in (row.cve_ids or "").split(",") if c],
        "ghsa_ids": [g for g in (row.ghsa_ids or "").split(",") if g],
        "patched": bool(row.patched),
        "exploited": bool(row.exploited),
        "kev_due_date": row.kev_due_date.isoformat() if row.kev_due_date else None,
        "revealed_at": row.revealed_at.isoformat() if row.revealed_at else None,
        "first_seen_at": row.first_seen_at.isoformat() if row.first_seen_at else None,
        "url": row.url,
    }


@app.get("/api/zeroday/exposures")
def zero_day_exposures(state: str | None = "open", tier: str | None = None,
                       verified_only: bool = False, limit: int = 200,
                       session: Session = Depends(get_session)):
    """
    Which repositories are exposed to a pre-disclosure finding, and on what
    evidence.

    Ordered by the same rule the queue uses: confirmed exploitation first, then
    score, then verified evidence ahead of unverified.
    """
    query = (session.query(ZeroDayExposure, ZeroDayFinding, Repository)
             .join(ZeroDayFinding, ZeroDayExposure.finding_id == ZeroDayFinding.id)
             .join(Repository, ZeroDayExposure.repository_id == Repository.id))
    if state:
        query = query.filter(ZeroDayExposure.state == state)
    if tier:
        query = query.filter(ZeroDayExposure.evidence_tier == tier)
    if verified_only:
        query = query.filter(ZeroDayExposure.verified.is_(True))

    rows = []
    for exposure, finding, repository in query.limit(min(limit, 1000)).all():
        try:
            explanation = json.loads(exposure.score_explanation or "{}")
        except ValueError:
            explanation = {}
        rows.append({
            "id": exposure.id,
            "repository": repository.full_name,
            "component": exposure.component_name,
            "version": exposure.component_version,
            "ecosystem": exposure.ecosystem,
            "score": exposure.zero_day_score,
            "tier": exposure.tier,
            "evidence_tier": exposure.evidence_tier,
            "confidence": exposure.match_confidence,
            "verified": bool(exposure.verified),
            "degraded": bool(exposure.degraded),
            "match_reason": exposure.match_reason,
            "explanation": explanation.get("summary"),
            "substitutions": explanation.get("substitutions"),
            "state": exposure.state,
            "detected_at": exposure.detected_at.isoformat()
            if exposure.detected_at else None,
            "finding": _zero_day_finding_row(finding),
        })

    rows = zeroday_score.rank(
        [dict(r, exploited=r["finding"]["exploited"],
              evidence_tier=r["evidence_tier"]) for r in rows])
    return {"count": len(rows), "exposures": rows}


@app.get("/api/zeroday/watchlist")
def zero_day_watchlist(session: Session = Depends(get_session)):
    """
    Findings that cannot be correlated yet.

    Two distinct populations, kept apart because they mean different things:

      sealed        still at commitment stage. The ledger withholds the project
                    deliberately during the disclosure window, and this system
                    does not attempt to infer it. Held, counted, not guessed at.
      unmatched     revealed, but nothing in the inventory matched. Evidence
                    that the feed covers projects the organisation does not use
                    -- which is a true negative, not a failure.
    """
    sealed = (session.query(ZeroDayFinding)
              .filter(ZeroDayFinding.stage == zeroday_feeds.STAGE_COMMITMENT)
              .all())
    matched_ids = {row[0] for row in
                   session.query(ZeroDayExposure.finding_id).distinct()}
    unmatched = [f for f in session.query(ZeroDayFinding)
                 .filter(ZeroDayFinding.stage != zeroday_feeds.STAGE_COMMITMENT)
                 .all() if f.id not in matched_ids]

    return {
        "sealed": {
            "count": len(sealed),
            "note": "Commitment stage: project withheld by the disclosure "
                    "programme. No correlation is attempted.",
            "findings": [
                {"source": f.source, "source_id": f.source_id,
                 "severity": f.severity_band,
                 "committed_at": f.committed_at.isoformat()
                 if f.committed_at else None}
                for f in sealed[:100]
            ],
        },
        "unmatched": {
            "count": len(unmatched),
            "note": "Revealed but not present in this inventory.",
            "findings": [_zero_day_finding_row(f) for f in unmatched[:100]],
        },
    }


@app.post("/api/zeroday/exposures/{exposure_id}/acknowledge")
def acknowledge_zero_day(exposure_id: int, owner: str = "unassigned",
                         session: Session = Depends(get_session)):
    """
    Record an owner's confirmation of an unverified finding.

    T0 and T2 matches are over-inclusive by construction, so they produce a
    review queue rather than an automated action. This is the human step that
    turns a candidate into a confirmed exposure, and it is recorded so the
    T0 false-positive rate can be measured afterwards rather than asserted.
    """
    exposure = session.query(ZeroDayExposure).get(exposure_id)
    if exposure is None:
        raise HTTPException(status_code=404, detail="exposure not found")
    exposure.acknowledged_by = owner
    exposure.acknowledged_at = dt.datetime.now(dt.timezone.utc)
    exposure.verified = True
    session.commit()
    return {"id": exposure.id, "acknowledged_by": owner,
            "acknowledged_at": exposure.acknowledged_at.isoformat()}


@app.get("/api/zeroday/metrics")
def zero_day_metrics(session: Session = Depends(get_session)):
    """
    Objective 5 evidence: Pre-CVE Lead Time plus a per-tier breakdown.

    Accuracy is reported per evidence tier and never as a single figure.
    Averaging a deliberately over-inclusive T0 name match together with a
    verified PURL match would produce a number that means nothing.
    """
    tiers = {}
    for tier, count in (session.query(
            ZeroDayExposure.evidence_tier, func.count(ZeroDayExposure.id))
            .group_by(ZeroDayExposure.evidence_tier).all()):
        verified = (session.query(func.count(ZeroDayExposure.id))
                    .filter(ZeroDayExposure.evidence_tier == tier,
                            ZeroDayExposure.verified.is_(True)).scalar())
        tiers[tier or "unknown"] = {
            "exposures": count,
            "verified": verified,
            "confirmation_rate": round(verified / count, 3) if count else None,
        }

    stages = {stage or "unknown": count for stage, count in session.query(
        ZeroDayFinding.stage, func.count(ZeroDayFinding.id))
        .group_by(ZeroDayFinding.stage).all()}

    total_findings = session.query(func.count(ZeroDayFinding.id)).scalar() or 0
    with_identifier = (session.query(func.count(ZeroDayFinding.id))
                       .filter((ZeroDayFinding.cve_ids.isnot(None)) |
                               (ZeroDayFinding.ghsa_ids.isnot(None))).scalar() or 0)

    return {
        "findings_total": total_findings,
        "findings_by_stage": stages,
        "with_identifier": with_identifier,
        "without_identifier": total_findings - with_identifier,
        "identifier_coverage": round(with_identifier / total_findings, 3)
        if total_findings else None,
        "coverage_note": "Findings with no identifier are invisible to every "
                         "CVE-keyed scanner. This proportion is the blind spot "
                         "the project measures. Read it as a lower bound on "
                         "coverage, not a census: the CVD ledger's own "
                         "CVE/GHSA mapping is known to be incomplete, so some "
                         "findings counted here as unidentified do have an "
                         "advisory recorded elsewhere.",
        "exposures_by_tier": tiers,
        "exploited_open": (session.query(func.count(ZeroDayExposure.id))
                           .join(ZeroDayFinding)
                           .filter(ZeroDayFinding.exploited.is_(True),
                                   ZeroDayExposure.state == "open").scalar()),
        "lead_time": pipeline.pre_cve_lead_time(session),
    }


# ---------------------------------------------------------------------------
# Zero-day remediation and the fix worklist  (Capstone 2, Objectives 3-4)
# ---------------------------------------------------------------------------

def _process_attrs(session, repository):
    """Business attributes of every process this repository supports."""
    links = (session.query(ProcessRepositoryLink)
             .filter_by(repository_id=repository.id).all())
    out = []
    for link in links:
        p = link.process
        if p is None:
            continue
        out.append({
            "name": p.name,
            "owner": p.owner,
            "revenue_dependency": p.revenue_dependency,
            "customer_facing": bool(p.customer_facing),
            "availability_requirement": p.availability_requirement,
            "data_sensitivity": p.data_sensitivity,
            "regulatory_scope": p.regulatory_scope or "",
        })
    return out


def _owner_of(processes):
    """The accountable owner: the most business-critical process wins."""
    for key in ("direct", "indirect"):
        for p in processes:
            if p.get("revenue_dependency") == key and p.get("owner"):
                return p["owner"]
    for p in processes:
        if p.get("owner"):
            return p["owner"]
    return None


def _zero_day_plans(session, state="open"):
    """Every open zero-day exposure with its remediation plan attached."""
    rows = (session.query(ZeroDayExposure, ZeroDayFinding, Repository)
            .join(ZeroDayFinding, ZeroDayExposure.finding_id == ZeroDayFinding.id)
            .join(Repository, ZeroDayExposure.repository_id == Repository.id))
    if state:
        rows = rows.filter(ZeroDayExposure.state == state)

    out = []
    for exposure, finding, repository in rows.all():
        processes = _process_attrs(session, repository)
        f = pipeline._finding_to_dict(finding)
        plan = zeroday_remediation.remediation_plan(
            f, repository=repository.full_name, processes=processes,
            owner=_owner_of(processes))
        out.append((exposure, finding, repository, processes, f, plan))
    return out


@app.get("/api/zeroday/remediation")
def zero_day_remediation(session: Session = Depends(get_session)):
    """
    The remediation ladder for every open zero-day exposure.

    Each finding carries the stage it sits on, what can actually be done there,
    and what is blocked and why. Stage T1 is the contribution: project known,
    no identifier, no fixed version, so no existing tool raises anything.
    """
    plans = _zero_day_plans(session)
    rows = []
    for exposure, finding, repository, processes, f, plan in plans:
        rows.append({
            "exposure_id": exposure.id,
            "repository": repository.full_name,
            "component": exposure.component_name,
            "version": exposure.component_version,
            "source": finding.source,
            "source_id": finding.source_id,
            "summary": finding.summary,
            "severity": finding.severity_band,
            "url": finding.url,
            "score": exposure.zero_day_score,
            "evidence_tier": exposure.evidence_tier,
            "plan": plan,
        })
    order = {u: i for i, u in enumerate(zeroday_remediation.URGENCY_ORDER)}
    rows.sort(key=lambda r: (order.get(r["plan"]["urgency"], 9),
                             -(r["score"] or 0)))

    return {
        "count": len(rows),
        "ladder": {k: {kk: vv for kk, vv in v.items()}
                   for k, v in zeroday_remediation.LADDER.items()},
        "summary": zeroday_remediation.summarise([r["plan"] for r in rows]),
        "findings": rows,
    }


@app.get("/api/zeroday/alerts")
def zero_day_alerts(session: Session = Depends(get_session)):
    """
    Active alerts for the dashboard notification bar.

    Only findings a person should act on today produce an alert. An alert
    nobody can act on trains people to dismiss the bar, which costs more than
    the alert is worth.
    """
    alerts = []
    for exposure, finding, repository, processes, f, plan in _zero_day_plans(session):
        alert = zeroday_remediation.alert_for(plan, f, exposure_id=exposure.id)
        if alert:
            alerts.append(alert)
    order = {u: i for i, u in enumerate(zeroday_remediation.URGENCY_ORDER)}
    alerts.sort(key=lambda a: order.get(a["urgency"], 9))
    return {
        "count": len(alerts),
        "immediate": sum(1 for a in alerts if a["urgency"] == "immediate"),
        "unpatchable": sum(1 for a in alerts if not a["patch_available"]),
        "alerts": alerts[:25],
    }


@app.post("/api/zeroday/exposures/{exposure_id}/action")
def record_remediation_action(exposure_id: int, action: str,
                              owner: str = "unassigned",
                              note: str | None = None,
                              session: Session = Depends(get_session)):
    """
    Record what was actually done about an unpatchable finding.

    Where no fix exists the response is a decision rather than an upgrade --
    a control applied, a dependency pinned, a risk accepted. Recording it is
    what turns the ladder from advice into an auditable remediation trail, and
    it is what allows an accepted risk to be reviewed later rather than
    forgotten.
    """
    exposure = session.query(ZeroDayExposure).get(exposure_id)
    if exposure is None:
        raise HTTPException(status_code=404, detail="exposure not found")

    allowed = {"pinned", "control_applied", "exception_raised",
               "upgraded", "not_affected", "acknowledged"}
    if action not in allowed:
        raise HTTPException(
            status_code=400,
            detail="action must be one of %s" % ", ".join(sorted(allowed)))

    now = dt.datetime.now(dt.timezone.utc)
    exposure.acknowledged_by = owner
    exposure.acknowledged_at = now
    exposure.verified = True
    if action in ("upgraded", "not_affected"):
        exposure.state = "resolved"
        exposure.resolved_at = now

    session.add(RemediationEvent(
        exposure_id=exposure.id,
        event_type="zero_day_%s" % action,
        from_state="open",
        to_state=exposure.state,
        detail=json.dumps({"owner": owner, "note": note,
                           "component": exposure.component_name})))
    session.commit()
    return {"exposure_id": exposure.id, "action": action, "owner": owner,
            "state": exposure.state, "recorded_at": now.isoformat()}


@app.get("/api/worklist")
def fix_worklist(size: int = 10, session: Session = Depends(get_session)):
    """
    What to fix first, and why, in business terms.

    This replaces the NDCG ranking evaluation. A developer choosing what to fix
    does not ask whether one ordering correlates better with a graded list than
    another; they ask which of these matters most and why. So the list is
    ordered by business consequence and every position states its reason in one
    sentence, with the technical score shown only as supporting detail.
    """
    items = []

    # Published CVE findings.
    for exposure, repository in (
            session.query(Exposure, Repository)
            .join(Repository, Exposure.repository_id == Repository.id)
            .filter(Exposure.state == "open").all()):
        processes = _process_attrs(session, repository)
        items.append({
            "kind": "published",
            "exposure_id": exposure.id,
            "repository": repository.full_name,
            "component": exposure.component_name,
            "version": exposure.component_version,
            "identifier": exposure.cve_id or exposure.advisory_id,
            "score": exposure.business_score,
            "tier": exposure.tier,
            "patch_available": bool(exposure.first_patched_version),
            "upgrade_target": exposure.first_patched_version,
            "exploited": False,
            "processes": processes,
        })

    # Pre-disclosure findings.
    for exposure, finding, repository, processes, f, plan in _zero_day_plans(session):
        items.append({
            "kind": "zero-day",
            "exposure_id": exposure.id,
            "repository": repository.full_name,
            "component": exposure.component_name,
            "version": exposure.component_version,
            "identifier": (finding.cve_ids or finding.ghsa_ids
                           or finding.source_id),
            "score": exposure.zero_day_score,
            "tier": exposure.tier,
            "patch_available": plan["patch_available"],
            "upgrade_target": plan["upgrade_target"],
            "exploited": bool(finding.exploited),
            "stage_label": plan["stage_label"],
            "processes": processes,
        })

    rows, summary = worklist.build(items, size=size)
    for row in rows:
        row["process_names"] = [p["name"] for p in row.get("processes", [])]
        row["owner"] = _owner_of(row.get("processes", []))
        row.pop("processes", None)
    return {"summary": summary, "worklist": rows}
