"""
GitHub API client.

Three endpoints matter for this project:
  * Dependency Graph SBOM   -> the component inventory (Capstone 1 ingestion)
  * Dependabot alerts       -> the remediation handoff target (Objective 3)
  * Repository listing      -> discovering what is in the demonstration org

Read-only scopes are sufficient throughout. Merge actions stay with the
repository owner on GitHub, which is the design decision the proposal commits to.
"""

import logging
import time

import requests

from .config import GITHUB_API, HTTP_TIMEOUT, USER_AGENT

log = logging.getLogger("sbom_c2.github")


class GitHubError(RuntimeError):
    pass


class GitHubClient:
    def __init__(self, token, org, api=GITHUB_API):
        if not token:
            raise GitHubError("a GitHub token is required")
        self.org = org
        self.api = api.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": "Bearer %s" % token,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": USER_AGENT,
        })

    # -- plumbing ----------------------------------------------------------

    # GitHub generates the dependency-graph SBOM on demand, and for a large
    # dependency tree its own generator can time out with a 500. That is a
    # transient server-side failure, not a client error, so it is retried with
    # backoff before being reported.
    TRANSIENT_STATUSES = (500, 502, 503, 504)

    def _request(self, method, path, tolerate_failure=False, **kwargs):
        url = path if path.startswith("http") else "%s%s" % (self.api, path)
        last_error = None

        for attempt in range(4):
            try:
                response = self.session.request(
                    method, url, timeout=HTTP_TIMEOUT, **kwargs)
            except requests.RequestException as error:
                last_error = "network error: %s" % error
                time.sleep(2 ** attempt)
                continue

            # Secondary rate limit / abuse detection asks us to back off.
            if response.status_code in (403, 429):
                remaining = response.headers.get("x-ratelimit-remaining")
                if remaining == "0" or "retry-after" in response.headers:
                    wait = int(response.headers.get("retry-after", 2 ** attempt))
                    time.sleep(min(wait, 60))
                    last_error = "rate limited"
                    continue

            if response.status_code == 404:
                return None

            if response.status_code in self.TRANSIENT_STATUSES:
                last_error = "%s: %s" % (response.status_code,
                                         response.text[:200])
                # Backoff grows quickly: GitHub's SBOM generator needs time,
                # not immediate retries.
                time.sleep(min(5 * (2 ** attempt), 45))
                continue

            if not response.ok:
                raise GitHubError("%s %s -> %s: %s" % (
                    method, url, response.status_code, response.text[:300]))
            return response

        message = "%s %s failed after retries (%s)" % (method, url, last_error)
        if tolerate_failure:
            log.warning(message)
            return None
        raise GitHubError(message)

    def _paginate(self, path, params=None):
        params = dict(params or {})
        params.setdefault("per_page", 100)
        while path:
            response = self._request("GET", path, params=params)
            if response is None:
                return
            payload = response.json()
            for item in payload if isinstance(payload, list) else []:
                yield item
            # Subsequent pages carry their params in the Link header already.
            path = response.links.get("next", {}).get("url")
            params = None

    # -- repositories ------------------------------------------------------

    def list_org_repositories(self):
        return list(self._paginate("/orgs/%s/repos" % self.org))

    # -- SBOM --------------------------------------------------------------

    def fetch_sbom(self, full_name):
        """
        GET /repos/{owner}/{repo}/dependency-graph/sbom

        Returns the SPDX document, or None when the dependency graph has not
        been generated yet -- which is normal for the first minutes after a
        repository is created.
        """
        response = self._request(
            "GET", "/repos/%s/dependency-graph/sbom" % full_name,
            tolerate_failure=True)
        if response is None:
            return None
        try:
            return response.json().get("sbom")
        except ValueError:
            log.warning("unparseable SBOM response for %s", full_name)
            return None

    @staticmethod
    def parse_sbom_components(sbom):
        """
        Flatten an SPDX SBOM into the component shape the correlator expects.

        GitHub emits one package per dependency with an externalRef of type
        purl. The root package describes the repository itself and is skipped.
        """
        from .matching import parse_purl

        components = []
        seen = set()
        for package in (sbom or {}).get("packages", []):
            name = package.get("name") or ""
            if name.startswith("com.github.") or not name:
                continue  # the repository's own root package

            purl = None
            for ref in package.get("externalRefs", []):
                if ref.get("referenceType") == "purl":
                    purl = ref.get("referenceLocator")
                    break

            parsed = parse_purl(purl) if purl else None
            version = package.get("versionInfo") or (parsed or {}).get("version")
            resolved_name = (parsed or {}).get("name") or name.split(":", 1)[-1]
            ecosystem = (parsed or {}).get("ecosystem")

            key = (resolved_name, version, ecosystem)
            if key in seen:
                continue
            seen.add(key)

            components.append({
                "name": resolved_name,
                "version": version,
                "ecosystem": ecosystem,
                "purl": purl,
                # The SPDX export does not mark directness reliably, so we treat
                # relationship-free packages as transitive rather than guess.
                "direct": package.get("relationship") == "DIRECT",
                "path": None,
            })
        return components

    # -- Dependabot --------------------------------------------------------

    def list_dependabot_alerts(self, state=None):
        """
        Org-wide Dependabot alerts.
        GET /orgs/{org}/dependabot/alerts
        """
        params = {}
        if state:
            params["state"] = state
        return list(self._paginate(
            "/orgs/%s/dependabot/alerts" % self.org, params))

    def list_repo_dependabot_alerts(self, full_name, state=None):
        params = {}
        if state:
            params["state"] = state
        return list(self._paginate(
            "/repos/%s/dependabot/alerts" % full_name, params))

    @staticmethod
    def alert_identity(alert):
        """
        Extract the (cve, ghsa, package, ecosystem) tuple used to correlate an
        alert with one of our exposure records.
        """
        advisory = alert.get("security_advisory") or {}
        vulnerability = alert.get("security_vulnerability") or {}
        package = vulnerability.get("package") or {}
        patched = (vulnerability.get("first_patched_version") or {}).get("identifier")
        return {
            "first_patched_version": patched,
            "vulnerable_range": vulnerability.get("vulnerable_version_range"),
            "number": alert.get("number"),
            "state": alert.get("state"),
            "cve_id": advisory.get("cve_id"),
            "ghsa_id": advisory.get("ghsa_id"),
            "package": (package.get("name") or "").lower(),
            "ecosystem": (package.get("ecosystem") or "").lower(),
            "html_url": alert.get("html_url"),
            "created_at": alert.get("created_at"),
            "fixed_at": alert.get("fixed_at"),
            "dismissed_at": alert.get("dismissed_at"),
            "repository": ((alert.get("repository") or {}).get("full_name")),
        }
