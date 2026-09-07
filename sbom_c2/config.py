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
EPSS_API = "https://api.first.org/data/v1/epss"

HTTP_TIMEOUT = float(_env("HTTP_TIMEOUT", "30"))
USER_AGENT = "sbom-c2-analyzer/1.0 (REVA Capstone 2)"


def require_github():
    """Fail loudly and early rather than 401-ing halfway through an ingest."""
    if not GITHUB_TOKEN:
        raise RuntimeError("GITHUB_TOKEN is not set")
    if not GITHUB_ORG:
        raise RuntimeError("GITHUB_ORG is not set")
    return GITHUB_TOKEN, GITHUB_ORG
