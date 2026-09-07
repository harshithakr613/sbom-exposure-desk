"""
Ingestion, correlation and scoring pipeline.

Phase 2 (service implementation of the Capstone 1 pipeline) plus Phase 4
(business-aware rescoring) live here.
"""

import datetime as dt
import json
import logging

from . import bia, cpe, depgraph, feeds, matching, quality, sbom_formats
from .github_client import GitHubClient
from .models import (
    BusinessProcess, Component, Exposure, ProcessRepositoryLink, RemediationEvent,
    Repository, Vulnerability,
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
