"""
Ingestion, correlation and scoring pipeline.

Phase 2 (service implementation of the Capstone 1 pipeline) plus Phase 4
(business-aware rescoring) live here.
"""

import datetime as dt
import json
import logging

from . import (bia, config, cpe, depgraph, feeds, matching, quality,
               sbom_formats, zeroday_feeds, zeroday_match, zeroday_score)
from .github_client import GitHubClient
from .models import (
    BusinessProcess, Component, Exposure, ProcessRepositoryLink, RemediationEvent,
    Repository, Vulnerability, ZeroDayExposure, ZeroDayFinding,
)


log = logging.getLogger("sbom_c2.pipeline")


def _now():
    return dt.datetime.now(dt.timezone.utc)


# --------------------------------------------------------------------------
# Ingestion
# --------------------------------------------------------------------------

def sync_repositories(session, client: GitHubClient):
    """Discover repositories in the demonstration organisation."""
    found = 0
    for repo in client.list_org_repositories():
        full_name = repo["full_name"]
        row = session.query(Repository).filter_by(full_name=full_name).one_or_none()
        if row is None:
            row = Repository(full_name=full_name, name=repo["name"])
            session.add(row)
        row.default_branch = repo.get("default_branch") or "main"
        row.ecosystem = repo.get("language")
        found += 1
    session.commit()
    return found


def ingest_sbom(session, client: GitHubClient, repository: Repository):
    """
    Pull the dependency graph SBOM, apply the quality gate, reconstruct
    dependency chains where the SBOM supports it, and store components.
    """
    sbom = client.fetch_sbom(repository.full_name)
    if not sbom:
        return 0

    components, _meta = sbom_formats.parse_spdx(sbom)
    return store_components(session, repository, components, sbom=sbom,
                            source="GitHub Dependency Graph API")


def store_components(session, repository: Repository, components, sbom=None,
                     source="upload"):
    """
    Shared ingestion path for every SBOM source.

    Applies the quality gate, walks the SPDX relationship graph to recover
    dependency chains and directness where present, then replaces the stored
    component set for the repository.
    """
    report = quality.assess(components, source)
    repository.sbom_quality_score = report.score
    repository.sbom_quality_passed = report.passed
    repository.sbom_quality_issues = json.dumps(report.as_dict())
    repository.sbom_source = source

    # Rejected components are recorded, never silently dropped: a repository
    # must not look clean merely because its SBOM was unusable.
    admitted, rejected = quality.admissible(components)
    if not admitted:
        admitted = components

    chains = depgraph.DependencyChainGraph.from_spdx(sbom) if sbom else None
    repository.has_dependency_chains = bool(chains and chains.has_relationships)

    session.query(Component).filter_by(repository_id=repository.id).delete()
    for comp in admitted:
        path = depth = None
        if chains and chains.has_relationships:
            chain = chains.chain_to(comp["name"])
            if chain:
                path = " \u2192 ".join(chain)
                depth = len(chain) - 1
        session.add(Component(
            repository_id=repository.id,
            name=comp["name"],
            version=comp.get("version"),
            ecosystem=comp.get("ecosystem"),
            purl=comp.get("purl"),
            cpe=comp.get("cpe"),
            direct=(depth == 1) if depth is not None else bool(comp.get("direct")),
            depth=depth,
            dependency_path=path,
        ))
    repository.last_ingested_at = _now()
    session.commit()
    return len(admitted)


def refresh_vulnerability_data(session, components):
    """
    Query OSV for advisories affecting these components, enrich with EPSS, and
    upsert into the vulnerability knowledge base.
    """
    advisories = feeds.query_osv_batch(components)

    cve_ids = []
    for adv in advisories:
        cve = next((a for a in adv.get("aliases", []) if a.startswith("CVE-")), None)
        if cve:
            cve_ids.append(cve)
    epss = feeds.fetch_epss(cve_ids)

    for adv in advisories:
        advisory_id = adv.get("id")
        if not advisory_id:
            continue
        cve = next((a for a in adv.get("aliases", []) if a.startswith("CVE-")), None)
        cvss, vector = feeds.extract_cvss(adv)
        row = (session.query(Vulnerability)
               .filter_by(advisory_id=advisory_id).one_or_none())
        if row is None:
            row = Vulnerability(advisory_id=advisory_id)
            session.add(row)
        row.cve_id = cve
        row.summary = adv.get("summary") or (adv.get("details") or "")[:500]
        row.cvss_score = cvss
        row.cvss_vector = vector
        if cve and cve in epss:
            row.epss_score = epss[cve]["epss"]
            row.epss_percentile = epss[cve]["percentile"]
        row.fetched_at = _now()

    session.commit()
    return advisories


# --------------------------------------------------------------------------
# Correlation
# --------------------------------------------------------------------------

def _cpe_fallback_findings(components, advisories, existing):
    """
    Secondary correlation for components lacking a usable PURL.

    Zahan et al. found many published SBOMs omit Package URLs; without this path
    those components are invisible. Matches are marked CPE_FUZZY so an analyst
    can see which findings came from the lower-confidence route.
    """
    already = {(f["component_name"], f["advisory_id"]) for f in existing}
    out = []
    for comp in components:
        if comp.get("purl") or not comp.get("cpe"):
            continue
        for advisory in advisories:
            advisory_id = advisory.get("id")
            if (comp["name"], advisory_id) in already:
                continue
            cpes = []
            for affected in advisory.get("affected", []) or []:
                db = affected.get("database_specific") or {}
                cpes.extend(db.get("cpes") or [])
            matched, score, _fields = cpe.best_match(cpes, comp) if cpes else (None, 0.0, None)
            if matched:
                already.add((comp["name"], advisory_id))
                out.append({
                    "advisory_id": advisory_id,
                    "aliases": advisory.get("aliases", []),
                    "cve_id": next((a for a in advisory.get("aliases", [])
                                    if a.startswith("CVE-")), None),
                    "component_name": comp["name"],
                    "component_version": comp.get("version"),
                    "ecosystem": comp.get("ecosystem"),
                    "purl": None,
                    "direct": bool(comp.get("direct")),
                    "path": comp.get("path"),
                    "match_type": "CPE_FUZZY",
                    "match_confidence": score,
                    "summary": advisory.get("summary") or "",
                })
    return out


def build_reverse_graph(session):
    """
    Organisation-wide component -> repository graph.

    Answers the Capstone 1 question directly: a CVE lands on a package, which
    repositories are exposed? Rebuilt per request; cheap at this scale.
    """
    repo_components = {}
    for repository in session.query(Repository).all():
        repo_components[repository.full_name] = [
            {"name": c.name, "ecosystem": c.ecosystem, "version": c.version}
            for c in session.query(Component).filter_by(
                repository_id=repository.id)
        ]
    return depgraph.ReverseDependencyGraph.build(repo_components)


def correlate_repository(session, repository: Repository, advisories):
    """
    Correlate this repository's components against the advisory set and persist
    the resulting exposures. Existing findings are updated, not duplicated, so
    detected_at and the remediation history survive a re-run.
    """
    components = [
        {
            "name": c.name, "version": c.version, "ecosystem": c.ecosystem,
            "purl": c.purl, "direct": c.direct, "path": c.dependency_path,
        }
        for c in session.query(Component).filter_by(repository_id=repository.id)
    ]
    index = matching.advisory_index(advisories)
    findings = matching.correlate(components, index)

    # CPE fallback: components with no PURL cannot be matched by the primary
    # path, so their CPE is compared against each advisory's affected products.
    findings += _cpe_fallback_findings(components, advisories, findings)

    created = 0
    for finding in findings:
        existing = (session.query(Exposure).filter_by(
            repository_id=repository.id,
            component_name=finding["component_name"],
            component_version=finding["component_version"],
            advisory_id=finding["advisory_id"]).one_or_none())
        if existing:
            existing.match_type = finding["match_type"]
            continue

        exposure = Exposure(
            repository_id=repository.id,
            advisory_id=finding["advisory_id"],
            cve_id=finding["cve_id"],
            component_name=finding["component_name"],
            component_version=finding["component_version"],
            ecosystem=finding["ecosystem"],
            purl=finding["purl"],
            direct=finding["direct"],
            dependency_path=finding["path"],
            match_type=finding["match_type"],
            match_confidence=finding.get("match_confidence"),
            state="open",
            detected_at=_now(),
        )
        session.add(exposure)
        session.flush()
        session.add(RemediationEvent(
            exposure_id=exposure.id, event_type="detected",
            from_state=None, to_state="open",
            detail="matched via %s" % finding["match_type"]))
        created += 1

    session.commit()
    return created


# --------------------------------------------------------------------------
# Scoring  (Objective 2)
# --------------------------------------------------------------------------

def repository_business_context(session, repository: Repository):
    """Collect the business processes a repository supports, and their regimes."""
    links = (session.query(ProcessRepositoryLink)
             .filter_by(repository_id=repository.id).all())
    processes = [link.process for link in links if link.process is not None]
    regimes = sorted({r for p in processes for r in p.regimes()})
    return processes, regimes


def score_repository(session, repository: Repository):
    """
    Recompute both scores for every exposure on this repository.

    Both are stored: business_score drives the queue, baseline_score preserves
    the Capstone 1 ordering so Phase 6 has something to measure against.
    """
    processes, regimes = repository_business_context(session, repository)
    criticality, detail = bia.repository_criticality(
        [p.as_attributes() for p in processes])

    exposures = session.query(Exposure).filter_by(repository_id=repository.id).all()
    scored = 0
    for exposure in exposures:
        vuln = (session.query(Vulnerability)
                .filter_by(advisory_id=exposure.advisory_id).one_or_none())
        cvss = vuln.cvss_score if vuln else None
        epss = vuln.epss_score if vuln else None

        result = bia.composite_score(cvss, epss, criticality, regimes)
        exposure.business_score = result["score"]
        exposure.tier = result["tier"]
        exposure.derived_criticality = criticality
        exposure.compliance_factor = result["compliance_factor"]
        exposure.baseline_score = bia.baseline_score(
            cvss, epss, repository.manual_criticality_tier)
        exposure.score_explanation = json.dumps({
            "contributions": result["contributions"],
            "base_score": result["base_score"],
            "compliance_factor": result["compliance_factor"],
            "regimes": result["regimes"],
            "driving_process": detail.get("driving_process"),
            "criticality_contributions": detail.get("contributions"),
        })
        scored += 1

    session.commit()
    return scored


def run_full_pipeline(session, client: GitHubClient):
    """
    Discover -> ingest -> correlate -> score, across the whole organisation.

    A failure on one repository must not abandon the other seventeen. GitHub
    generates dependency-graph SBOMs on demand and its generator times out on
    large trees, so per-repository failures are recorded and the run continues.
    """
    summary = {
        "repositories": 0, "components": 0, "exposures": 0, "scored": 0,
        "ingested_repositories": 0, "skipped_repositories": [], "errors": [],
    }
    summary["repositories"] = sync_repositories(session, client)

    repositories = session.query(Repository).all()
    all_components = []

    for repository in repositories:
        try:
            count = ingest_sbom(session, client, repository)
        except Exception as error:  # one bad repository, not a failed run
            session.rollback()
            log.warning("ingest failed for %s: %s", repository.full_name, error)
            summary["errors"].append("%s: %s" % (repository.full_name, error))
            count = 0

        if count == 0:
            summary["skipped_repositories"].append(repository.full_name)
            continue

        summary["components"] += count
        summary["ingested_repositories"] += 1
        all_components.extend(
            {"name": c.name, "ecosystem": c.ecosystem, "version": c.version}
            for c in session.query(Component).filter_by(repository_id=repository.id)
        )

    if not all_components:
        summary["errors"].append(
            "No components ingested. GitHub may still be generating dependency "
            "graphs for these repositories; retry in a few minutes.")
        return summary

    advisories = refresh_vulnerability_data(session, all_components)
    summary["advisories"] = len(advisories)

    for repository in repositories:
        try:
            summary["exposures"] += correlate_repository(
                session, repository, advisories)
            summary["scored"] += score_repository(session, repository)
        except Exception as error:
            session.rollback()
            log.warning("scoring failed for %s: %s", repository.full_name, error)
            summary["errors"].append("%s: %s" % (repository.full_name, error))

    return summary


# --------------------------------------------------------------------------
# Zero-day / pre-disclosure pipeline  (Capstone 1, Objectives 2-5)
# --------------------------------------------------------------------------

def _csv(values):
    return ",".join(str(v) for v in values or []) or None


def store_zero_day_findings(session, findings):
    """
    Upsert normalised pre-disclosure findings.

    Upsert rather than replace, because `first_seen_at` is the measurement that
    makes Pre-CVE Lead Time possible: it records when this system could first
    have acted, which is the whole comparison against identifier-keyed tooling.
    Wiping and reinserting on every poll would destroy it.
    """
    created = updated = 0
    for finding in findings:
        source, source_id = finding.get("source"), finding.get("source_id")
        if not source or not source_id:
            continue

        row = (session.query(ZeroDayFinding)
               .filter_by(source=source, source_id=str(source_id)).one_or_none())
        if row is None:
            row = ZeroDayFinding(source=source, source_id=str(source_id),
                                 first_seen_at=_now())
            session.add(row)
            created += 1
        else:
            updated += 1

        row.stage = finding.get("stage")
        row.evidence_tier = finding.get("evidence_tier")
        row.project = finding.get("project")
        row.bug_class = finding.get("bug_class")
        row.summary = finding.get("summary")
        row.package_name = finding.get("package_name")
        row.ecosystem = finding.get("ecosystem")
        row.purl = finding.get("purl")
        row.repo_url = finding.get("repo_url")
        row.severity_band = finding.get("severity_band")
        row.severities = json.dumps(finding.get("severities") or {})
        row.commit_ranges = json.dumps(finding.get("commit_ranges") or [])
        row.affected_ranges = json.dumps(finding.get("affected_ranges") or [])
        row.fixed_version = finding.get("fixed_version")
        row.cve_ids = _csv(finding.get("cve_ids"))
        row.ghsa_ids = _csv(finding.get("ghsa_ids"))
        row.patched = bool(finding.get("patched"))
        row.exploited = bool(finding.get("exploited"))
        row.kev_due_date = finding.get("kev_due_date")
        row.committed_at = finding.get("committed_at")
        row.revealed_at = finding.get("revealed_at")
        row.patched_at = finding.get("patched_at")
        row.last_seen_at = _now()
        row.url = finding.get("url")

    session.commit()
    return created, updated


def _components_by_repository(session):
    """Inventory in the shape the tier matchers expect."""
    out = {}
    for repository in session.query(Repository).all():
        out[repository.full_name] = [
            {
                "name": c.name, "version": c.version, "ecosystem": c.ecosystem,
                "purl": c.purl, "cpe": c.cpe, "direct": c.direct,
                "path": c.dependency_path,
            }
            for c in session.query(Component).filter_by(repository_id=repository.id)
        ]
    return out


def correlate_zero_day(session, findings=None):
    """
    Correlate stored findings against the inventory and persist the exposures.

    Each hit is scored in degraded mode -- Consensus Severity Proxy for CVSS,
    Disclosure-Stage Prior for EPSS -- and discounted by the confidence of the
    tier that produced the match, so a T0 project-name hit cannot outrank a
    PURL-verified finding of equal severity.
    """
    if findings is None:
        findings = [_finding_to_dict(r) for r in
                    session.query(ZeroDayFinding).filter(
                        ZeroDayFinding.stage != zeroday_feeds.STAGE_COMMITMENT)]

    inventory = _components_by_repository(session)
    results = zeroday_match.correlate(findings, inventory)

    repositories = {r.full_name: r for r in session.query(Repository).all()}
    created = 0

    for row in results:
        repository = repositories.get(row["repository"])
        if repository is None:
            continue
        finding = row["finding"]
        stored = (session.query(ZeroDayFinding).filter_by(
            source=finding["source"],
            source_id=str(finding["source_id"])).one_or_none())
        if stored is None:
            continue

        processes, regimes = repository_business_context(session, repository)
        criticality, _detail = bia.repository_criticality(
            [p.as_attributes() for p in processes])

        scored = zeroday_score.score_exposure(
            finding, criticality, regimes,
            tier=row["tier"], confidence=row["confidence"])

        exposure = (session.query(ZeroDayExposure).filter_by(
            finding_id=stored.id, repository_id=repository.id,
            component_name=row["component_name"],
            component_version=row["component_version"]).one_or_none())
        if exposure is None:
            exposure = ZeroDayExposure(
                finding_id=stored.id, repository_id=repository.id,
                component_name=row["component_name"],
                component_version=row["component_version"],
                detected_at=_now(), state="open")
            session.add(exposure)
            created += 1

        exposure.ecosystem = row["ecosystem"]
        exposure.purl = row["purl"]
        exposure.evidence_tier = row["tier"]
        exposure.match_confidence = row["confidence"]
        exposure.match_reason = row["reason"]
        exposure.verified = row["verified"]
        exposure.zero_day_score = scored["score"]
        exposure.tier = scored["tier"]
        exposure.degraded = scored["degraded"]
        exposure.score_explanation = json.dumps({
            "summary": zeroday_score.explain(scored),
            "substitutions": scored["substitutions"],
            "contributions": scored["contributions"],
            "evidence_tier": scored["evidence_tier"],
            "evidence_confidence": scored["evidence_confidence"],
            "match_reason": row["reason"],
            "undiscounted_score": scored["undiscounted_score"],
        }, default=str)

    session.commit()
    return created, zeroday_match.tier_breakdown(results)


def _finding_to_dict(row):
    """Rehydrate a stored finding into the shape the matchers and scorer use."""
    def _load(text, default):
        try:
            return json.loads(text) if text else default
        except ValueError:
            return default

    return zeroday_feeds.PreDisclosureFinding.make(
        source=row.source,
        source_id=row.source_id,
        stage=row.stage,
        evidence_tier=row.evidence_tier,
        project=row.project,
        bug_class=row.bug_class,
        summary=row.summary,
        package_name=row.package_name,
        ecosystem=row.ecosystem,
        purl=row.purl,
        repo_url=row.repo_url,
        commit_ranges=_load(row.commit_ranges, []),
        affected_ranges=_load(row.affected_ranges, []),
        fixed_version=row.fixed_version,
        severity_band=row.severity_band,
        severities=_load(row.severities, {}),
        cve_ids=[c for c in (row.cve_ids or "").split(",") if c],
        ghsa_ids=[g for g in (row.ghsa_ids or "").split(",") if g],
        patched=bool(row.patched),
        exploited=bool(row.exploited),
        kev_due_date=row.kev_due_date,
        committed_at=row.committed_at,
        revealed_at=row.revealed_at,
        patched_at=row.patched_at,
        url=row.url,
    )


def run_zero_day_pipeline(session, sources=None, github_token=None,
                          use_kev=True):
    """
    Poll the pre-disclosure feeds, store, correlate and score.

    Runs independently of the CVE pipeline on purpose. The published path needs
    a full SBOM ingest; this one only needs the inventory that is already
    stored, so it can poll every few minutes without re-pulling dependency
    graphs -- which is what makes minutes-after-reveal alerting achievable.

    OSS-Fuzz is queried per project rather than by downloading the whole
    ecosystem dump, using the project names already present in the inventory.
    """
    summary = {"sources": sources or config.ZERODAY_SOURCES,
               "fetched": 0, "created": 0, "updated": 0,
               "exposures": 0, "tiers": {}, "errors": {}}

    projects = sorted({
        zeroday_match.normalise_project(c.name)
        for c in session.query(Component).all() if c.name
    })

    findings, errors = zeroday_feeds.collect(
        sources=summary["sources"], projects=projects,
        github_token=github_token)
    summary["errors"] = errors
    summary["fetched"] = len(findings)

    if use_kev:
        try:
            zeroday_feeds.enrich_with_kev(findings)
        except Exception as error:
            log.warning("KEV enrichment skipped: %s", error)
            summary["errors"]["kev"] = str(error)

    created, updated = store_zero_day_findings(session, findings)
    summary["created"], summary["updated"] = created, updated

    actionable = [f for f in findings
                  if f.get("stage") != zeroday_feeds.STAGE_COMMITMENT]
    exposures, tiers = correlate_zero_day(session, actionable)
    summary["exposures"], summary["tiers"] = exposures, tiers

    summary["watchlist"] = sum(
        1 for f in findings if f.get("stage") == zeroday_feeds.STAGE_COMMITMENT)
    return summary


def pre_cve_lead_time(session):
    """
    Pre-CVE Lead Time  (Capstone 1, Objective 5).

    For every finding this system saw before an identifier existed and which
    later received one, how many days earlier did it become actionable here
    than it would have been for a tool keyed on the published feed?

    The ground truth is constructed from findings that eventually *did* get an
    identifier, so the comparison against identifier-keyed tooling is exact
    rather than hypothetical. Findings that never receive an identifier are
    excluded from the mean and counted separately -- they are the stronger
    result, but they have no comparison date, so folding them in would inflate
    the average with an arbitrary number.
    """
    rows, never = [], 0
    for finding in session.query(ZeroDayFinding).all():
        has_identifier = bool(finding.cve_ids or finding.ghsa_ids)
        first_seen = finding.revealed_at or finding.first_seen_at
        if not has_identifier:
            if finding.stage in (zeroday_feeds.STAGE_REVEALED,):
                never += 1
            continue

        published = (session.query(Vulnerability)
                     .filter(Vulnerability.cve_id.in_(
                         [c for c in (finding.cve_ids or "").split(",") if c]))
                     .first()) if finding.cve_ids else None
        published_at = published.published_at if published else None
        if not (first_seen and published_at):
            continue

        if first_seen.tzinfo is None:
            first_seen = first_seen.replace(tzinfo=dt.timezone.utc)
        if published_at.tzinfo is None:
            published_at = published_at.replace(tzinfo=dt.timezone.utc)

        rows.append({
            "source": finding.source,
            "source_id": finding.source_id,
            "project": finding.project,
            "revealed_at": first_seen.isoformat(),
            "identifier_published_at": published_at.isoformat(),
            "lead_time_days": round(
                (published_at - first_seen).total_seconds() / 86400.0, 2),
        })

    lead_times = [r["lead_time_days"] for r in rows if r["lead_time_days"] > 0]
    return {
        "measured": len(rows),
        "with_positive_lead_time": len(lead_times),
        "mean_lead_time_days": round(sum(lead_times) / len(lead_times), 2)
        if lead_times else None,
        "median_lead_time_days": round(sorted(lead_times)[len(lead_times) // 2], 2)
        if lead_times else None,
        "no_identifier_ever": never,
        "note": "Findings that never received an identifier are counted "
                "separately: they have no publication date to compare against, "
                "and they are the population no identifier-keyed tool can see "
                "at all.",
        "rows": rows[:100],
    }
