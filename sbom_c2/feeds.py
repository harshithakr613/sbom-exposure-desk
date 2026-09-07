"""
Vulnerability and exploitation feeds.

OSV supplies advisories (and aliases through to CVE ids); EPSS supplies
exploitation probability. Both are free and unauthenticated, which keeps the
demonstration reproducible by anyone marking this project.
"""

import logging

import requests

from . import cvss
from .config import EPSS_API, HTTP_TIMEOUT, OSV_API, USER_AGENT

log = logging.getLogger("sbom_c2.feeds")

_HEADERS = {"User-Agent": USER_AGENT, "Content-Type": "application/json"}

# OSV's querybatch caps request size; chunk to stay well inside it.
BATCH_SIZE = 100
EPSS_CHUNK = 100

# Ecosystems OSV accepts. A GitHub dependency-graph SBOM also lists GitHub
# Actions and other non-package dependencies, whose PURL types OSV rejects --
# and because querybatch is all-or-nothing, a single unrecognised ecosystem
# returns 400 for the entire batch. Filtering up front is what makes the call
# reliable rather than intermittently fatal.
OSV_ECOSYSTEMS = {
    "npm", "PyPI", "Maven", "Go", "crates.io", "RubyGems", "NuGet",
    "Packagist", "Hex", "Pub", "SwiftURL", "CRAN", "Bitnami",
    "Alpine", "Debian", "Ubuntu", "Rocky Linux", "AlmaLinux", "Android",
    "GitHub Actions", "Linux", "OSS-Fuzz", "ConanCenter",
}


def query_osv_batch(components):
    """
    Look up advisories for many components in one round trip.

    POST /v1/querybatch returns id-only stubs, so each distinct advisory is then
    fetched once via /v1/vulns/{id} -- far fewer calls than querying per package.

    Two robustness measures matter here. Components whose ecosystem OSV does not
    recognise are dropped before the call, and a batch that still fails is split
    in half and retried, so one malformed entry costs a single query rather than
    the whole run.
    """
    queries, skipped = [], {}
    seen = set()

    for comp in components:
        name = comp.get("name")
        ecosystem = comp.get("ecosystem")
        version = comp.get("version")
        if not name or not ecosystem:
            continue
        if ecosystem not in OSV_ECOSYSTEMS:
            skipped[ecosystem] = skipped.get(ecosystem, 0) + 1
            continue

        key = (ecosystem, name, str(version) if version else None)
        if key in seen:
            continue
        seen.add(key)

        query = {"package": {"name": name, "ecosystem": ecosystem}}
        if version:
            query["version"] = str(version)
        queries.append(query)

    if skipped:
        log.info("OSV: skipped unsupported ecosystems %s", skipped)
    log.info("OSV: querying %d distinct components", len(queries))

    advisory_ids = set()
    for start in range(0, len(queries), BATCH_SIZE):
        advisory_ids |= _querybatch(queries[start:start + BATCH_SIZE])

    log.info("OSV: %d distinct advisories to fetch", len(advisory_ids))
    return [a for a in (fetch_osv_advisory(i) for i in sorted(advisory_ids)) if a]


def _querybatch(chunk):
    """
    Submit one batch, halving and retrying on rejection.

    OSV rejects a batch outright if any single query is malformed, so a binary
    split isolates the offending entry in log2(n) requests instead of losing the
    whole chunk.
    """
    if not chunk:
        return set()

    try:
        response = requests.post(
            "%s/querybatch" % OSV_API, json={"queries": chunk},
            headers=_HEADERS, timeout=HTTP_TIMEOUT)
        response.raise_for_status()
    except requests.HTTPError as error:
        status = getattr(error.response, "status_code", None)
        if status == 400 and len(chunk) > 1:
            middle = len(chunk) // 2
            return _querybatch(chunk[:middle]) | _querybatch(chunk[middle:])
        if len(chunk) == 1:
            log.warning("OSV rejected query %s (%s)", chunk[0], status)
            return set()
        raise
    except requests.RequestException as error:
        log.warning("OSV request failed: %s", error)
        return set()

    found = set()
    for result in response.json().get("results", []):
        for vuln in result.get("vulns", []) or []:
            if vuln.get("id"):
                found.add(vuln["id"])
    return found


def fetch_osv_advisory(advisory_id):
    """One advisory. A failure here skips that advisory, never the run."""
    try:
        response = requests.get("%s/vulns/%s" % (OSV_API, advisory_id),
                                headers={"User-Agent": USER_AGENT},
                                timeout=HTTP_TIMEOUT)
        if response.status_code == 404:
            return None
        response.raise_for_status()
        return response.json()
    except requests.RequestException as error:
        log.warning("could not fetch advisory %s: %s", advisory_id, error)
        return None


def extract_cvss(advisory):
    """
    Pull a CVSS v3.x base score out of an OSV record.

    Delegates to the specification arithmetic in cvss.py. An earlier heuristic
    approximated the score from impact metrics alone, ignoring Attack Complexity
    and Scope, which reported almost every finding at 10.0.
    """
    score, vector, source = cvss.score_from_advisory(advisory)
    if source == "qualitative":
        log.debug("advisory %s has no CVSS vector; using severity band",
                  advisory.get("id"))
    return score, vector


def fetch_epss(cve_ids):
    """
    Fetch EPSS probabilities for a list of CVE ids.
    Returns {cve_id: {"epss": float, "percentile": float}}.
    """
    scores = {}
    ids = [c for c in cve_ids if c and c.startswith("CVE-")]
    for start in range(0, len(ids), EPSS_CHUNK):
        chunk = ids[start:start + EPSS_CHUNK]
        try:
            response = requests.get(
                EPSS_API, params={"cve": ",".join(chunk)},
                headers={"User-Agent": USER_AGENT}, timeout=HTTP_TIMEOUT)
            response.raise_for_status()
        except requests.RequestException as error:
            log.warning("EPSS chunk failed, continuing without it: %s", error)
            continue
        for row in response.json().get("data", []):
            try:
                scores[row["cve"]] = {
                    "epss": float(row.get("epss", 0.0)),
                    "percentile": float(row.get("percentile", 0.0)),
                }
            except (TypeError, ValueError):
                continue
    return scores
