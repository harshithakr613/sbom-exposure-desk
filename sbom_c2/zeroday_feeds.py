"""
Pre-disclosure ("zero-day") vulnerability feeds.

Every scanner on the market is *identifier-keyed*: it cannot act until a CVE or
GHSA record exists. This module ingests the stage before that. Six sources are
normalised into one PreDisclosureFinding record so that adding a seventh is a
parser, not a redesign.

    Anthropic CVD ledger  hash commitment -> project -> CVE/GHSA -> patch
                          (the findings are discovered by Claude Mythos
                          Preview and other Claude models; the ledger is how
                          they reach the public -- see fetch_cvd_ledger)
    OSS-Fuzz (via OSV)    crash + pkg:generic purl + GIT commit ranges
    Debian tracker        package + unfixed status for issues with no CVE
    ENISA EUVD            EU-assigned records, independent of NVD
    GitHub Advisory DB    GHSA issued days-to-weeks before NVD indexes the CVE
    CISA KEV              confirmed in-the-wild exploitation + mandated due date

Two distinctions run through the whole module and are easy to conflate:

  stage         where the finding sits in the *disclosure lifecycle*
                (commitment -> revealed -> identified -> patched)
  evidence_tier what can actually be *matched against an SBOM* right now
                (project name only -> commit range -> vendor/product -> PURL)

They are not the same thing. A Debian TEMP entry has no identifier (early
stage) but names a package (deep evidence). Keeping them separate is what lets
the correlator pick a matcher per finding instead of assuming every source
hands over a version range.

Network failures are never fatal: a source that is down returns an empty list
and the run continues with the others.
"""

import datetime as dt
import logging
import re

import requests

from .config import (
    CVD_LEDGER_URL, CVD_PAYLOAD_URL, DEBIAN_TRACKER_JSON, EUVD_API,
    GITHUB_API, HTTP_TIMEOUT, KEV_FEED_URL, OSV_API, OSV_BUCKET, USER_AGENT,
    ZERODAY_MAX_RECORDS,
)

log = logging.getLogger("sbom_c2.zeroday_feeds")

_HEADERS = {"User-Agent": USER_AGENT}

# Disclosure lifecycle. Ordered, so `STAGES.index(stage)` gives progression.
STAGE_COMMITMENT = "commitment"   # T0  hash only, project withheld
STAGE_REVEALED = "revealed"       # T1  project + bug class, no identifier
STAGE_IDENTIFIED = "identified"   # T2  CVE and/or GHSA assigned
STAGE_PATCHED = "patched"         # T3  fix shipped upstream
STAGES = [STAGE_COMMITMENT, STAGE_REVEALED, STAGE_IDENTIFIED, STAGE_PATCHED]

STAGE_LABEL = {
    STAGE_COMMITMENT: "T0", STAGE_REVEALED: "T1",
    STAGE_IDENTIFIED: "T2", STAGE_PATCHED: "T3",
}

# What the finding gives us to match an SBOM against, best first.
TIER_PURL = "T3_PURL"        # package + affected semantic version range
TIER_PRODUCT = "T2_PRODUCT"  # vendor / product strings, no PURL
TIER_COMMIT = "T1_COMMIT"    # upstream repository + GIT commit range
TIER_PROJECT = "T0_PROJECT"  # project name alone

SEVERITY_BANDS = ("critical", "high", "medium", "low", "none")


def _now():
    return dt.datetime.now(dt.timezone.utc)


def _parse_date(value):
    """Tolerant ISO-8601 parse. Feeds disagree on trailing Z and precision."""
    if not value:
        return None
    text = str(value).strip().replace("Z", "+00:00")
    for candidate in (text, text.split("T")[0]):
        try:
            parsed = dt.datetime.fromisoformat(candidate)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=dt.timezone.utc)
            return parsed
        except ValueError:
            continue
    return None


def _band(value):
    """Normalise any of the feeds' severity vocabularies to one band."""
    if value is None:
        return None
    text = str(value).strip().lower()
    if text in SEVERITY_BANDS:
        return text
    try:  # some feeds hand back a numeric CVSS instead of a word
        score = float(text)
    except ValueError:
        return None
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "none"


class PreDisclosureFinding(dict):
    """
    One normalised finding.

    A dict subclass rather than a dataclass so it serialises straight to JSON
    for the API and persists without a translation layer.
    """

    @classmethod
    def make(cls, source, source_id, stage, evidence_tier, **kwargs):
        record = cls({
            "source": source,
            "source_id": source_id,
            "stage": stage,
            "stage_label": STAGE_LABEL.get(stage, "T?"),
            "evidence_tier": evidence_tier,
            "project": None,
            "bug_class": None,
            "summary": None,
            "package_name": None,
            "ecosystem": None,
            "purl": None,
            "repo_url": None,
            "commit_ranges": [],     # [{"introduced": sha, "fixed": sha}]
            "affected_ranges": [],   # OSV-style affected[] entries
            "fixed_version": None,
            "severity_band": None,
            "severities": {},        # {"maintainer": "high", "vendor": ...}
            "cve_ids": [],
            "ghsa_ids": [],
            "patched": False,
            "exploited": False,
            "kev_due_date": None,
            "committed_at": None,
            "revealed_at": None,
            "patched_at": None,
            "url": None,
        })
        record.update(kwargs)
        return record


# ---------------------------------------------------------------------------
# 1. Anthropic CVD ledger  -- the earliest signal available anywhere
# ---------------------------------------------------------------------------

def fetch_cvd_ledger(limit=ZERODAY_MAX_RECORDS):
    """
    Anthropic's Coordinated Vulnerability Disclosure ledger.

    Provenance, because it is the point of the whole exercise: since February
    2026 Anthropic has used Claude Mythos Preview -- and subsequently other
    Mythos-class and Claude models -- to find vulnerabilities in open-source
    software, then engaged external security research firms to reproduce and
    severity-assess each finding before disclosing it to maintainers. Mythos is
    the discovery engine, not a queryable feed; this ledger is the public
    interface to what it found, and there is no separate Mythos API to call.

    Worth noting for any accuracy claim made about this feed: the disclosed set
    is a *subset* of what the models found, because independent human triage is
    the rate-limiting step. The published counts therefore understate the
    population, and the blind spot this project measures is if anything wider
    than the ledger shows.

    Staged disclosure: a SHA-3-512 hash commitment is published first with the
    project withheld, then the project and bug class are revealed, then any
    CVE/GHSA, then the patch. This is the only public feed that exposes the
    pre-reveal stage at all.

    The system deliberately does not attempt to de-anonymise a sealed
    commitment. T0 entries are recorded and held on a watchlist; no correlation
    is attempted against them, because there is nothing to correlate.
    """
    entries = _get_json(CVD_LEDGER_URL)
    if entries is None:
        entries = _get_json(CVD_PAYLOAD_URL)
    if entries is None:
        return []

    rows = _unwrap_list(entries, ("entries", "findings", "ledger", "records", "data"))

    # Parse the whole ledger before applying the cap.
    #
    # The ledger is ordered newest commitment first, and the newest findings are
    # precisely the ones still inside their disclosure window -- sealed, with no
    # project. Slicing the first N therefore returns almost nothing but
    # commitments and stops before reaching any revealed finding, which is the
    # only kind that can be correlated. The ledger is a few thousand records, so
    # parsing all of it costs nothing; the cap is applied afterwards, to a list
    # sorted so actionable findings survive it.
    out = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        cve_ids = [c for c in (row.get("cve_ids") or []) if c]
        ghsa_ids = [g for g in (row.get("ghsa_ids") or []) if g]
        revealed = bool(row.get("revealed")) or bool(row.get("revealed_at")) \
            or bool(row.get("project"))
        patched = bool(row.get("patched")) or bool(row.get("patched_at"))

        if patched:
            stage = STAGE_PATCHED
        elif cve_ids or ghsa_ids:
            stage = STAGE_IDENTIFIED
        elif revealed:
            stage = STAGE_REVEALED
        else:
            stage = STAGE_COMMITMENT

        # Evidence: the ledger names a project, never a package version range.
        tier = TIER_PROJECT if revealed else None

        severities = {
            key: _band(row.get(field))
            for key, field in (("model", "claude_severity"),
                               ("vendor", "vendor_severity"),
                               ("maintainer", "maintainer_severity"))
            if _band(row.get(field))
        }

        source_id = row.get("ant_id") or row.get("id") or row.get("hash")
        if not source_id:
            continue

        out.append(PreDisclosureFinding.make(
            source="cvd",
            source_id=str(source_id),
            stage=stage,
            evidence_tier=tier,
            project=row.get("project"),
            bug_class=row.get("bug_class"),
            summary=row.get("summary") or row.get("bug_class"),
            severity_band=_consensus_band(severities),
            severities=severities,
            cve_ids=cve_ids,
            ghsa_ids=ghsa_ids,
            patched=patched,
            committed_at=_parse_date(row.get("committed_at")),
            revealed_at=_parse_date(row.get("revealed_at")),
            patched_at=_parse_date(row.get("patched_at")),
            url=row.get("url") or (
                "https://red.anthropic.com/2026/cvd/findings/%s.html" % source_id
                if str(source_id).startswith("ANT-") else None),
            raw_status=row.get("status"),
            reveal_tier=row.get("reveal_tier"),
            commitment_hash=row.get("hash"),
        ))

    # Actionable first (revealed, identified, patched), newest within each
    # group, then cap. Sealed commitments are still returned so the watchlist
    # count is honest, but they no longer crowd out everything else.
    out.sort(key=lambda f: (STAGES.index(f["stage"]) == 0,
                            -(f["revealed_at"] or f["committed_at"]
                              or dt.datetime.min.replace(
                                  tzinfo=dt.timezone.utc)).timestamp()))
    actionable = sum(1 for f in out if f["stage"] != STAGE_COMMITMENT)
    log.info("CVD ledger: %d findings parsed (%d actionable, %d sealed); "
             "returning %d", len(out), actionable, len(out) - actionable,
             min(len(out), limit))
    return out[:limit]


def _consensus_band(severities):
    """
    Maintainer beats security firm beats model.

    The maintainer knows the codebase, the firm reviewed it independently, the
    model proposed it. Where all three are published they agree exactly 85.2%
    of the time and within one band 97.1% (n=1017), so this precedence is a
    tie-break rather than a correction.
    """
    for key in ("maintainer", "vendor", "model"):
        if severities.get(key):
            return severities[key]
    return None


# ---------------------------------------------------------------------------
# 2. OSS-Fuzz, consumed through OSV
# ---------------------------------------------------------------------------

def fetch_ossfuzz(limit=ZERODAY_MAX_RECORDS, projects=None):
    """
    OSS-Fuzz findings, which OSV publishes as OSV-YYYY-NNNN records.

    Deliberately *not* scraped from the issue tracker. OSS-Fuzz exports into
    OSV, so this is a real API rather than a fragile scrape against a UI that
    has already migrated once.

    These records are the reason a commit-range matcher exists at all: they
    carry `pkg:generic/<project>` and GIT introduced/fixed commit ranges rather
    than a semantic version range, so no PURL-and-semver matcher can use them.
    """
    records = _osv_ecosystem_dump("OSS-Fuzz", limit=limit, projects=projects)
    return [_from_osv(r, source="ossfuzz") for r in records]


def _from_osv(record, source):
    """Normalise one OSV record. Shared by the OSS-Fuzz and GHSA paths."""
    aliases = record.get("aliases") or []
    cve_ids = [a for a in aliases if str(a).startswith("CVE-")]
    ghsa_ids = [a for a in aliases if str(a).startswith("GHSA-")]
    if str(record.get("id", "")).startswith("GHSA-"):
        ghsa_ids.append(record["id"])

    package_name = ecosystem = purl = repo_url = fixed_version = None
    commit_ranges, affected_ranges = [], []

    for affected in record.get("affected") or []:
        package = affected.get("package") or {}
        package_name = package_name or package.get("name")
        ecosystem = ecosystem or package.get("ecosystem")
        purl = purl or package.get("purl")
        affected_ranges.append(affected)
        for rng in affected.get("ranges") or []:
            if rng.get("type") == "GIT":
                repo_url = repo_url or rng.get("repo")
                introduced = fixed = None
                for event in rng.get("events") or []:
                    introduced = event.get("introduced", introduced)
                    fixed = event.get("fixed", fixed)
                if introduced or fixed:
                    commit_ranges.append({"repo": rng.get("repo"),
                                          "introduced": introduced,
                                          "fixed": fixed})
            else:
                for event in rng.get("events") or []:
                    if event.get("fixed"):
                        fixed_version = event["fixed"]

    patched = bool(fixed_version) or any(c.get("fixed") for c in commit_ranges)

    # Evidence tier follows what the record actually contains, not its source.
    if purl and not str(purl).startswith("pkg:generic/") and affected_ranges:
        tier = TIER_PURL
    elif commit_ranges:
        tier = TIER_COMMIT
    elif package_name:
        tier = TIER_PURL if ecosystem else TIER_PROJECT
    else:
        tier = TIER_PROJECT

    if patched:
        stage = STAGE_PATCHED
    elif cve_ids or ghsa_ids:
        stage = STAGE_IDENTIFIED
    else:
        stage = STAGE_REVEALED

    ecosystem_specific = {}
    for affected in record.get("affected") or []:
        ecosystem_specific.update(affected.get("ecosystem_specific") or {})

    return PreDisclosureFinding.make(
        source=source,
        source_id=record.get("id"),
        stage=stage,
        evidence_tier=tier,
        project=package_name,
        bug_class=record.get("summary"),
        summary=record.get("summary") or (record.get("details") or "")[:500],
        package_name=package_name,
        ecosystem=ecosystem,
        purl=purl,
        repo_url=repo_url,
        commit_ranges=commit_ranges,
        affected_ranges=affected_ranges,
        fixed_version=fixed_version,
        severity_band=_band(ecosystem_specific.get("severity")
                            or _severity_from_osv(record)),
        cve_ids=sorted(set(cve_ids)),
        ghsa_ids=sorted(set(ghsa_ids)),
        patched=patched,
        revealed_at=_parse_date(record.get("published")),
        patched_at=_parse_date(record.get("modified")) if patched else None,
        url="https://osv.dev/vulnerability/%s" % record.get("id"),
    )


def _severity_from_osv(record):
    """OSV `severity[]` holds CVSS vectors; database_specific often holds a band."""
    db = record.get("database_specific") or {}
    if db.get("severity"):
        return db["severity"]
    for entry in record.get("severity") or []:
        if entry.get("score"):
            return entry["score"]
    return None


def _osv_ecosystem_dump(ecosystem, limit, projects=None):
    """
    Pull records for one OSV ecosystem.

    The bulk zip is the documented route for a whole ecosystem, but it is tens
    of megabytes and unpacking it on every poll is wasteful. For the projects
    actually present in the inventory, a targeted /v1/query per project is far
    cheaper, so that path is preferred whenever the caller supplies a project
    list and the dump is only used as the unfiltered fallback.
    """
    if projects:
        out, seen = [], set()
        for project in list(projects)[:limit]:
            for record in _osv_query_package(project, ecosystem):
                if record.get("id") and record["id"] not in seen:
                    seen.add(record["id"])
                    out.append(record)
        return out

    payload = _get_zip_json(
        "%s/%s/all.zip" % (OSV_BUCKET, ecosystem.replace(" ", "%20")), limit)
    return payload or []


def _osv_query_package(name, ecosystem):
    try:
        response = requests.post(
            "%s/query" % OSV_API,
            json={"package": {"name": name, "ecosystem": ecosystem}},
            headers=_HEADERS, timeout=HTTP_TIMEOUT)
        response.raise_for_status()
        return response.json().get("vulns", []) or []
    except requests.RequestException as error:
        log.debug("OSV query failed for %s/%s: %s", ecosystem, name, error)
        return []


# ---------------------------------------------------------------------------
# 3. Debian Security Tracker -- issues carrying no CVE at all
# ---------------------------------------------------------------------------

TEMP_NAME = re.compile(r"^TEMP-\d+-[0-9A-Za-z]+$")


def fetch_debian_temp(limit=ZERODAY_MAX_RECORDS):
    """
    Debian tracks issues that have no CVE under generated TEMP-000000-NNNNNN
    names.

    Debian's own documentation warns these names are unstable and change when
    the database is rebuilt, so the TEMP id is carried for display only. The
    join key is the *package name*, never the identifier -- persisting a TEMP id
    as a foreign key would silently corrupt the inventory on the next refresh.
    """
    data = _get_json(DEBIAN_TRACKER_JSON)
    if not isinstance(data, dict):
        return []

    out = []
    for package, issues in data.items():
        if not isinstance(issues, dict):
            continue
        for identifier, detail in issues.items():
            if not TEMP_NAME.match(str(identifier)):
                continue  # has a real CVE; the published feed already covers it
            releases = (detail or {}).get("releases") or {}
            unfixed = any((r or {}).get("status") == "open"
                          for r in releases.values())
            urgency = next((r.get("urgency") for r in releases.values()
                            if isinstance(r, dict) and r.get("urgency")), None)
            fixed_version = next(
                (r.get("fixed_version") for r in releases.values()
                 if isinstance(r, dict) and r.get("fixed_version")), None)

            out.append(PreDisclosureFinding.make(
                source="debian",
                source_id=str(identifier),
                stage=STAGE_REVEALED if unfixed else STAGE_PATCHED,
                evidence_tier=TIER_PURL if fixed_version else TIER_PROJECT,
                project=package,
                package_name=package,
                ecosystem="Debian",
                summary=(detail or {}).get("description"),
                severity_band=_band(_urgency_to_band(urgency)),
                fixed_version=fixed_version,
                patched=not unfixed,
                url="https://security-tracker.debian.org/tracker/%s" % identifier,
            ))
            if len(out) >= limit:
                log.info("Debian: %d TEMP findings (capped)", len(out))
                return out
    log.info("Debian: %d TEMP findings", len(out))
    return out


def _urgency_to_band(urgency):
    return {"high": "high", "medium": "medium", "low": "low",
            "unimportant": "none", "not yet assigned": None}.get(
        str(urgency or "").lower())


# ---------------------------------------------------------------------------
# 4. ENISA EUVD -- assigned independently of NVD, so it sometimes lands first
# ---------------------------------------------------------------------------

def fetch_euvd(limit=100, page_size=50):
    """
    The EU Vulnerability Database.

    Useful because ENISA assigns independently of NVD, so a record can appear
    here before the CVE is indexed in the US feed. It is still beta: the list
    endpoints cap at 8 records and /search is slow, so this paginates
    conservatively and gives up quietly rather than stalling a run.
    """
    out = []
    for page in range((limit // page_size) + 1):
        params = {
            "fromScore": 0, "toScore": 10, "fromEpss": 0, "toEpss": 100,
            "page": page, "size": min(page_size, limit - len(out)),
        }
        payload = _get_json("%s/search" % EUVD_API, params=params)
        items = _unwrap_list(payload, ("items", "content", "results"))
        if not items:
            break
        for row in items:
            if not isinstance(row, dict):
                continue
            identifier = row.get("id") or row.get("enisaId")
            if not identifier:
                continue
            aliases = row.get("aliases") or ""
            cve_ids = re.findall(r"CVE-\d{4}-\d{4,7}", str(aliases)) or \
                re.findall(r"CVE-\d{4}-\d{4,7}", str(row.get("description", "")))
            exploited = bool(row.get("exploitedSince") or row.get("exploited"))
            out.append(PreDisclosureFinding.make(
                source="euvd",
                source_id=str(identifier),
                stage=STAGE_IDENTIFIED if cve_ids else STAGE_REVEALED,
                evidence_tier=TIER_PRODUCT,
                project=_euvd_product(row),
                summary=(row.get("description") or "")[:500],
                severity_band=_band(row.get("baseScore")),
                cve_ids=sorted(set(cve_ids)),
                exploited=exploited,
                revealed_at=_parse_date(row.get("datePublished")),
                url="https://euvd.enisa.europa.eu/enisaid?id=%s" % identifier,
                vendor=_euvd_vendor(row),
            ))
        if len(out) >= limit:
            break
    log.info("EUVD: %d findings", len(out))
    return out[:limit]


def _euvd_product(row):
    products = row.get("enisaIdProduct") or row.get("products") or []
    if isinstance(products, list) and products:
        first = products[0]
        if isinstance(first, dict):
            return (first.get("product") or {}).get("name") or first.get("name")
        return str(first)
    return row.get("product")


def _euvd_vendor(row):
    vendors = row.get("enisaIdVendor") or row.get("vendors") or []
    if isinstance(vendors, list) and vendors:
        first = vendors[0]
        if isinstance(first, dict):
            return (first.get("vendor") or {}).get("name") or first.get("name")
        return str(first)
    return row.get("vendor")


# ---------------------------------------------------------------------------
# 5. GitHub Advisory Database -- GHSA ahead of NVD
# ---------------------------------------------------------------------------

def fetch_github_advisories(token=None, limit=100, ecosystem=None):
    """
    Recent GHSA records.

    A GHSA is routinely published days to weeks before the matching CVE is
    indexed in NVD, so a scanner keyed on NVD is late even for advisories that
    do eventually get an identifier. Findings from GitHub Security Lab arrive
    through this feed -- the Security Lab site itself publishes only after a
    patch exists and offers no JSON API, so it is not polled directly.
    """
    headers = dict(_HEADERS)
    headers["Accept"] = "application/vnd.github+json"
    if token:
        headers["Authorization"] = "Bearer %s" % token

    params = {"per_page": min(100, limit), "sort": "published",
              "direction": "desc", "type": "reviewed"}
    if ecosystem:
        params["ecosystem"] = ecosystem

    payload = _get_json("%s/advisories" % GITHUB_API, params=params,
                        headers=headers)
    if not isinstance(payload, list):
        return []

    out = []
    for row in payload[:limit]:
        ghsa = row.get("ghsa_id")
        if not ghsa:
            continue
        cve = row.get("cve_id")
        vulns = row.get("vulnerabilities") or []
        package = ecosystem_name = purl = fixed = None
        if vulns:
            first = vulns[0] or {}
            pkg = first.get("package") or {}
            package = pkg.get("name")
            ecosystem_name = _github_ecosystem(pkg.get("ecosystem"))
            fixed = first.get("first_patched_version")
            if package and ecosystem_name:
                purl = "pkg:%s/%s" % (str(pkg.get("ecosystem")).lower(), package)

        out.append(PreDisclosureFinding.make(
            source="ghsa",
            source_id=ghsa,
            # A GHSA with no CVE is still pre-identifier as far as NVD-keyed
            # tooling is concerned, which is the comparison that matters here.
            stage=STAGE_IDENTIFIED if cve else STAGE_REVEALED,
            evidence_tier=TIER_PURL if package else TIER_PRODUCT,
            project=package,
            package_name=package,
            ecosystem=ecosystem_name,
            purl=purl,
            summary=row.get("summary"),
            severity_band=_band(row.get("severity")),
            fixed_version=fixed,
            cve_ids=[cve] if cve else [],
            ghsa_ids=[ghsa],
            patched=bool(fixed),
            revealed_at=_parse_date(row.get("published_at")),
            url=row.get("html_url"),
            affected_ranges=_github_ranges(vulns),
        ))
    log.info("GHSA: %d advisories", len(out))
    return out


GITHUB_ECOSYSTEM = {
    "npm": "npm", "pip": "PyPI", "maven": "Maven", "go": "Go",
    "rust": "crates.io", "rubygems": "RubyGems", "nuget": "NuGet",
    "composer": "Packagist", "erlang": "Hex", "pub": "Pub", "swift": "SwiftURL",
}


def _github_ecosystem(name):
    return GITHUB_ECOSYSTEM.get(str(name or "").lower())


GITHUB_RANGE_TERM = re.compile(r"^(>=|>|<=|<|=)\s*(.+)$")


def parse_github_version_range(text, first_patched=None):
    """
    Convert GitHub's range syntax into OSV `events`.

    GitHub expresses an affected range as a human-readable constraint string --
    `< 4.17.21`, `>= 1.0.0, < 1.2.3`, `= 2.1.0` -- rather than as OSV events.
    Carrying that string through untranslated means the matcher has no bound to
    evaluate, so it falls back to "package matched, no version bound" and
    reports *every* installed version as affected. Observed against the live
    feed: js-yaml 3.14.0, 3.14.1, 4.1.0 and 4.3.1 all matched one advisory,
    including versions that already contain the fix.

    Returns [] when nothing parseable is present, which the matcher treats as
    genuinely unbounded rather than silently assuming a bound.
    """
    introduced = fixed = last_affected = None

    for part in str(text or "").split(","):
        term = GITHUB_RANGE_TERM.match(part.strip())
        if not term:
            continue
        operator, version = term.group(1), term.group(2).strip()
        if operator in (">=", ">"):
            introduced = version
        elif operator == "<":
            fixed = version
        elif operator == "<=":
            last_affected = version
        elif operator == "=":
            introduced = introduced or version
            last_affected = version

    if fixed is None and first_patched:
        fixed = first_patched
    if introduced is None and fixed is None and last_affected is None:
        return []

    events = [{"introduced": introduced or "0"}]
    if fixed:
        events.append({"fixed": fixed})
    elif last_affected:
        events.append({"last_affected": last_affected})
    return events


def _github_ranges(vulns):
    """
    Shape GitHub's advisory entries into the OSV `affected[]` form.

    One advisory may list several packages -- a vulnerability in
    `@vitest/mocker` is also reported against `vitest`, and `joi` against
    `@hapi/joi` -- so every entry is carried, not just the first.
    """
    out = []
    for vuln in vulns or []:
        pkg = (vuln or {}).get("package") or {}
        raw_range = vuln.get("vulnerable_version_range")
        events = parse_github_version_range(
            raw_range, vuln.get("first_patched_version"))
        entry = {
            "package": {"name": pkg.get("name"),
                        "ecosystem": _github_ecosystem(pkg.get("ecosystem"))},
            "database_specific": {"vulnerable_version_range": raw_range},
            "ranges": [{"type": "ECOSYSTEM", "events": events}] if events else [],
        }
        out.append(entry)
    return out


# ---------------------------------------------------------------------------
# 6. CISA KEV -- confirmed exploitation, the one permitted escalation
# ---------------------------------------------------------------------------

def fetch_kev():
    """
    Known Exploited Vulnerabilities.

    Not a pre-CVE feed -- every entry has a CVE by definition. It is here
    because it is the only signal allowed to override business-context ranking:
    once exploitation is confirmed in the wild, the question stops being how
    much the asset is worth. Federal remediation deadlines come from BOD 22-01
    and BOD 26-04, and `dueDate` carries them.

    Returns {cve_id: {...}} for cheap lookup during scoring.
    """
    payload = _get_json(KEV_FEED_URL)
    if not isinstance(payload, dict):
        return {}
    out = {}
    for row in payload.get("vulnerabilities", []) or []:
        cve = row.get("cveID")
        if not cve:
            continue
        out[cve] = {
            "date_added": _parse_date(row.get("dateAdded")),
            "due_date": _parse_date(row.get("dueDate")),
            "required_action": row.get("requiredAction"),
            "ransomware": str(row.get("knownRansomwareCampaignUse", "")).lower()
            == "known",
            "product": row.get("product"),
            "vendor": row.get("vendorProject"),
        }
    log.info("KEV: %d exploited CVEs", len(out))
    return out


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------

SOURCES = {
    "cvd": fetch_cvd_ledger,
    "ossfuzz": fetch_ossfuzz,
    "debian": fetch_debian_temp,
    "euvd": fetch_euvd,
    "ghsa": fetch_github_advisories,
}


def collect(sources=None, projects=None, github_token=None, limit=None):
    """
    Poll every enabled source and return one normalised list.

    A source that fails is logged and skipped. Partial data beats no data: an
    ENISA outage must not stop the CVD ledger being correlated.
    """
    selected = list(sources) if sources else list(SOURCES)
    limit = limit or ZERODAY_MAX_RECORDS
    findings, errors = [], {}

    for name in selected:
        fetcher = SOURCES.get(name)
        if fetcher is None:
            errors[name] = "unknown source"
            continue
        try:
            if name == "ossfuzz":
                rows = fetcher(limit=limit, projects=projects)
            elif name == "ghsa":
                rows = fetcher(token=github_token, limit=min(limit, 100))
            elif name == "euvd":
                rows = fetcher(limit=min(limit, 100))
            else:
                rows = fetcher(limit=limit)
            findings.extend(rows)
        except Exception as error:            # one dead feed, not a dead run
            log.warning("zero-day source %s failed: %s", name, error)
            errors[name] = str(error)

    return findings, errors


def enrich_with_kev(findings, kev=None):
    """Mark findings whose CVE appears in KEV. Mutates and returns the list."""
    kev = kev if kev is not None else fetch_kev()
    if not kev:
        return findings
    for finding in findings:
        for cve in finding.get("cve_ids") or []:
            entry = kev.get(cve)
            if entry:
                finding["exploited"] = True
                finding["kev_due_date"] = entry.get("due_date")
                finding["kev_ransomware"] = entry.get("ransomware")
                break
    return findings


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def _get_json(url, params=None, headers=None):
    try:
        response = requests.get(url, params=params,
                                headers=headers or _HEADERS,
                                timeout=HTTP_TIMEOUT)
        if response.status_code == 404:
            log.debug("%s -> 404", url)
            return None
        response.raise_for_status()
        return response.json()
    except (requests.RequestException, ValueError) as error:
        log.warning("fetch failed %s: %s", url, error)
        return None


def _get_zip_json(url, limit):
    """Stream an OSV `all.zip` and decode up to `limit` records."""
    import io
    import json
    import zipfile

    try:
        response = requests.get(url, headers=_HEADERS, timeout=HTTP_TIMEOUT * 4)
        response.raise_for_status()
    except requests.RequestException as error:
        log.warning("bulk download failed %s: %s", url, error)
        return []

    out = []
    try:
        with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
            for name in archive.namelist()[:limit]:
                if not name.endswith(".json"):
                    continue
                try:
                    out.append(json.loads(archive.read(name)))
                except ValueError:
                    continue
    except zipfile.BadZipFile as error:
        log.warning("bad zip from %s: %s", url, error)
    return out


def _unwrap_list(payload, keys):
    """Feeds disagree on whether the list is top level or under a key."""
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for key in keys:
            value = payload.get(key)
            if isinstance(value, list):
                return value
    return []
