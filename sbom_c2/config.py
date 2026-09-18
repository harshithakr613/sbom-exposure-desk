"""Runtime configuration, read from the environment."""

import os


def _env(name, default=None, required=False):
    value = os.environ.get(name, default)
    if required and not value:
        raise RuntimeError(
            "%s is not set. Copy .env.example to .env and fill it in." % name
        )
    return value


# SQLite by default so the project runs with no database server. Point
# DATABASE_URL at PostgreSQL for the deployed build -- the SQLAlchemy models
# are unchanged either way.
DATABASE_URL = _env("DATABASE_URL", "sqlite:///./sbom_c2.db")

GITHUB_TOKEN = _env("GITHUB_TOKEN")
GITHUB_ORG = _env("GITHUB_ORG")
GITHUB_API = _env("GITHUB_API", "https://api.github.com")

OSV_API = "https://api.osv.dev/v1"
OSV_BUCKET = "https://storage.googleapis.com/osv-vulnerabilities"
EPSS_API = "https://api.first.org/data/v1/epss"

# ---------------------------------------------------------------------------
# Pre-disclosure ("zero-day") feeds.
#
# All unauthenticated except the GitHub advisory feed, which works anonymously
# but is rate limited far more aggressively without a token. Overridable from
# the environment so a marker behind a proxy, or a source that moves, does not
# require a code change.
# ---------------------------------------------------------------------------

CVD_LEDGER_URL = _env("CVD_LEDGER_URL",
                      "https://red.anthropic.com/2026/cvd/data/ledger.json")
CVD_PAYLOAD_URL = _env("CVD_PAYLOAD_URL",
                       "https://red.anthropic.com/2026/cvd/data/payload.json")
DEBIAN_TRACKER_JSON = _env(
    "DEBIAN_TRACKER_JSON",
    "https://security-tracker.debian.org/tracker/data/json")
EUVD_API = _env("EUVD_API", "https://euvdservices.enisa.europa.eu/api")
KEV_FEED_URL = _env(
    "KEV_FEED_URL",
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json")

# Which sources a sync polls by default. Comma separated so a demonstration can
# run against one feed without editing code.
ZERODAY_SOURCES = [
    s.strip() for s in
    _env("ZERODAY_SOURCES", "cvd,ossfuzz,ghsa,debian,euvd").split(",")
    if s.strip()
]

# Per-source record cap. The Debian tracker JSON alone is large; without a cap
# a demonstration sync becomes a several-minute download.
ZERODAY_MAX_RECORDS = int(_env("ZERODAY_MAX_RECORDS", "500"))

HTTP_TIMEOUT = float(_env("HTTP_TIMEOUT", "30"))
USER_AGENT = "sbom-c2-analyzer/1.0 (REVA Capstone 2)"


def require_github():
    """Fail loudly and early rather than 401-ing halfway through an ingest."""
    if not GITHUB_TOKEN:
        raise RuntimeError("GITHUB_TOKEN is not set")
    if not GITHUB_ORG:
        raise RuntimeError("GITHUB_ORG is not set")
    return GITHUB_TOKEN, GITHUB_ORG
