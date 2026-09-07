"""
Correlation engine (carried forward from Capstone 1, implemented as a service).

Dual-mode matching:
  1. PURL exact match on (ecosystem, name), then version-range evaluation.
  2. CPE / normalised-name fuzzy fallback for components whose SBOM entry has
     no usable PURL -- the case Zahan et al. showed is common in practice.

Pure logic. `packaging` is used for PEP 440 / semver-ish comparison when it is
available, with a tolerant fallback so the module still imports without it.
"""

import re
from difflib import SequenceMatcher
from urllib.parse import unquote

try:  # pragma: no cover - environment dependent
    from packaging.version import Version, InvalidVersion
    _HAVE_PACKAGING = True
except Exception:  # pragma: no cover
    _HAVE_PACKAGING = False

    class InvalidVersion(ValueError):
        pass


# OSV ecosystem <-> PURL type. Kept explicit rather than lowercasing blindly,
# because "Go" / "golang" and "Maven" / "maven" both appear in the wild.
PURL_TYPE_TO_OSV = {
    "npm": "npm",
    "pypi": "PyPI",
    "maven": "Maven",
    "golang": "Go",
    "cargo": "crates.io",
    "gem": "RubyGems",
    "nuget": "NuGet",
    "composer": "Packagist",
}

FUZZY_THRESHOLD = 0.88

def parse_purl(purl):
    """
    Parse a Package URL into its parts.

    Format:  pkg:TYPE/NAMESPACE.../NAME@VERSION?QUALIFIERS#SUBPATH

    Parsed by explicit splitting rather than one regex, because the namespace is
    variable-depth and optional -- a single pattern gets scoped npm names and
    dotted Maven group ids wrong in opposite directions.

    Returns None when the string is not a PURL, which signals the caller to fall
    back to fuzzy matching rather than discard the component entirely.
    """
    if not purl or not str(purl).startswith("pkg:"):
        return None

    body = str(purl).strip()[len("pkg:"):]
    body = body.split("#", 1)[0].split("?", 1)[0]
    if not body:
        return None

    version = None
    if "@" in body:
        body, version = body.rsplit("@", 1)
        version = unquote(version) or None

    segments = [unquote(s) for s in body.split("/") if s]
    if len(segments) < 2:
        return None

    ptype = segments[0].lower()
    name = segments[-1]
    namespace = "/".join(segments[1:-1]) or None

    if namespace:
        # Maven identifies a package as group:artifact; OSV expects that form.
        # Everything else (npm scopes, Go module paths) keeps the slash.
        separator = ":" if ptype == "maven" else "/"
        full_name = namespace + separator + name
    else:
        full_name = name

    return {
        "type": ptype,
        "ecosystem": PURL_TYPE_TO_OSV.get(ptype, ptype),
        "namespace": namespace,
        "name": full_name,
        "version": version,
    }


# Manifests frequently declare a constraint rather than a resolved version --
# "^1.15.1", ">= 8.0.0", "~2.4". GitHub's dependency graph passes these through
# verbatim. Treating "^1.15.1" as exactly 1.15.1 is wrong: the installed version
# could be anything up to 2.0.0, so a range evaluation against it is a guess.
CONSTRAINT_PREFIX = ("^", "~", ">", "<", "=", "!")


def is_constraint(version):
    """True when a version string is a range specifier, not a concrete version."""
    if version is None:
        return False
    text = str(version).strip()
    return bool(text) and (text[0] in CONSTRAINT_PREFIX or text in ("*", "latest"))


def _coerce(version):
    """Best-effort comparable version object."""
    if version is None:
        raise InvalidVersion("no version")
    text = str(version).strip().lstrip("vV")
    if _HAVE_PACKAGING:
        try:
            return Version(text)
        except InvalidVersion:
            pass
    # Fallback: compare dotted integer runs, ignoring trailing qualifiers.
    parts = re.findall(r"\d+", text)
    if not parts:
        raise InvalidVersion("uncomparable version %r" % version)
    return tuple(int(p) for p in parts[:4])


def compare_versions(a, b):
    """Return -1, 0 or 1. Raises InvalidVersion if either side is uncomparable."""
    va, vb = _coerce(a), _coerce(b)
    if type(va) is not type(vb):
        # One parsed via packaging and one did not; fall back to tuples for both.
        va, vb = tuple(int(p) for p in re.findall(r"\d+", str(a))[:4]), \
                 tuple(int(p) for p in re.findall(r"\d+", str(b))[:4])
    if va < vb:
        return -1
    if va > vb:
        return 1
    return 0


def version_in_range(version, affected_range):
    """
    Evaluate one OSV `affected[].ranges[]` entry against a concrete version.

    OSV expresses ranges as an ordered event list, e.g.
        [{"introduced": "0"}, {"fixed": "4.17.21"}]
    A version is affected when it is >= an `introduced` boundary and strictly
    below the next `fixed` / `last_affected` boundary.
    """
    events = affected_range.get("events") or []
    affected = False
    for event in events:
        if "introduced" in event:
            intro = event["introduced"]
            try:
                if intro == "0" or compare_versions(version, intro) >= 0:
                    affected = True
            except InvalidVersion:
                continue
        elif "fixed" in event:
            try:
                if compare_versions(version, event["fixed"]) >= 0:
                    affected = False
            except InvalidVersion:
                continue
        elif "last_affected" in event:
            try:
                if compare_versions(version, event["last_affected"]) > 0:
                    affected = False
            except InvalidVersion:
                continue
    return affected


def advisory_affects(component, advisory):
    """
    Does `advisory` (an OSV record) affect `component`?

    Returns (bool, match_type). match_type is "PURL_EXACT", "VERSION_LIST",
    "FUZZY_NAME" or None -- recorded on the exposure so the dashboard can show
    which path produced each finding, as Capstone 1 did.

    Exact name matches take absolute precedence over fuzzy ones. A single
    advisory often lists several packages: GHSA-67hx-6x53-jw92 covers both
    "@babel/traverse" (fixed in 7.23.2) and the legacy "babel-traverse" (never
    fixed). Those names are similar enough to clear a fuzzy threshold, so
    evaluating every entry allowed a *patched* @babel/traverse to match the
    unfixed babel-traverse range and be reported as vulnerable. Fuzzy matching
    is therefore consulted only when the advisory names no package matching this
    component exactly.
    """
    comp_name = (component.get("name") or "").lower()
    comp_eco = (component.get("ecosystem") or "").lower()
    comp_version = component.get("version")

    # A constraint is not a resolved version, so range arithmetic cannot be
    # applied to it. Treat it as unknown and let the "no version" path decide.
    if is_constraint(comp_version):
        comp_version = None

    exact_entries, fuzzy_entries = [], []
    for affected in advisory.get("affected", []):
        pkg = affected.get("package", {})
        name = (pkg.get("name") or "").lower()
        eco = (pkg.get("ecosystem") or "").lower()

        # Ecosystem must agree when both sides declare one.
        if eco and comp_eco and eco != comp_eco:
            continue

        if name == comp_name:
            exact_entries.append(affected)
        elif SequenceMatcher(None, name, comp_name).ratio() >= FUZZY_THRESHOLD:
            fuzzy_entries.append(affected)

    # An exact entry settles the question on its own, including negatively.
    if exact_entries:
        return _evaluate_entries(exact_entries, comp_version, exact=True)
    if fuzzy_entries:
        return _evaluate_entries(fuzzy_entries, comp_version, exact=False)
    return False, None


def _evaluate_entries(entries, comp_version, exact):
    """Evaluate a component version against a set of affected-package entries."""
    base_type = "PURL_EXACT" if exact else "FUZZY_NAME"

    for affected in entries:
        # An explicit version list beats range arithmetic when present.
        versions = affected.get("versions") or []
        if comp_version and versions and str(comp_version) in versions:
            return True, "VERSION_LIST" if exact else base_type

        for rng in affected.get("ranges", []):
            if comp_version and version_in_range(comp_version, rng):
                return True, base_type

        # A component with no version is flagged rather than silently dropped,
        # but only on an exact name match: doing so on a fuzzy match would
        # report an unrelated package purely because its name looked similar.
        if not comp_version and exact:
            return True, "NO_VERSION" if exact else base_type

    return False, None


def correlate(components, advisories_by_key):
    """
    Correlate SBOM components against advisories.

    components:        list of dicts with name, ecosystem, version, purl,
                       direct (bool), path (dependency chain, optional)
    advisories_by_key: {(ecosystem_lower, name_lower): [osv advisory, ...]}

    Returns a list of exposure dicts, one per (component, advisory) pair.
    """
    exposures = []
    for comp in components:
        keys = {((comp.get("ecosystem") or "").lower(), (comp.get("name") or "").lower())}
        candidates = []
        for key in keys:
            candidates.extend(advisories_by_key.get(key, []))
        # Fuzzy fallback: widen to every advisory in the same ecosystem.
        if not candidates:
            eco = (comp.get("ecosystem") or "").lower()
            for (adv_eco, _adv_name), advs in advisories_by_key.items():
                if adv_eco == eco:
                    candidates.extend(advs)

        seen = set()
        for adv in candidates:
            adv_id = adv.get("id")
            if adv_id in seen:
                continue
            hit, match_type = advisory_affects(comp, adv)
            if hit:
                seen.add(adv_id)
                exposures.append(
                    {
                        "advisory_id": adv_id,
                        "aliases": adv.get("aliases", []),
                        "cve_id": next(
                            (a for a in adv.get("aliases", []) if a.startswith("CVE-")),
                            None,
                        ),
                        "component_name": comp.get("name"),
                        "component_version": comp.get("version"),
                        "ecosystem": comp.get("ecosystem"),
                        "purl": comp.get("purl"),
                        "direct": bool(comp.get("direct")),
                        "path": comp.get("path"),
                        "match_type": match_type,
                        "summary": adv.get("summary") or adv.get("details", "")[:200],
                    }
                )
    return exposures


def advisory_index(advisories):
    """Build the {(ecosystem, name): [advisory]} index `correlate` expects."""
    index = {}
    for adv in advisories:
        for affected in adv.get("affected", []):
            pkg = affected.get("package", {})
            key = ((pkg.get("ecosystem") or "").lower(), (pkg.get("name") or "").lower())
            index.setdefault(key, []).append(adv)
    return index
