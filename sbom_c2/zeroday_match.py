"""
Progressive-evidence correlation for pre-disclosure findings.

A pre-CVE finding does not arrive with uniform evidence. Keying the whole
engine on PURL -- which is what every commercial scanner does -- silently
discards everything that has not reached a published version range yet, and
that is precisely the population this project exists to catch.

So there is one matcher per evidence level:

  T3  PURL + semantic version range   the tier existing scanners implement
  T2  vendor / product strings        CPE normalisation + fuzzy match
  T1  upstream repo + GIT commit      OSS-Fuzz records live here
  T0  project name alone              CVD ledger at reveal

Every match records the tier that produced it, so precision and recall are
reported per tier rather than averaged into one misleading number. T0 in
particular is deliberately over-inclusive: it produces a watchlist an owner
confirms, never an automated action.
"""

import logging
import re

from . import cpe as cpe_module
from . import matching
from .zeroday_feeds import (
    TIER_COMMIT, TIER_PRODUCT, TIER_PROJECT, TIER_PURL,
)

log = logging.getLogger("sbom_c2.zeroday_match")

# Confidence attached to a match, by the tier that produced it. These are not
# probabilities; they order the review queue and feed the score's confidence
# discount, so a T0 name match never outranks a verified PURL hit.
TIER_CONFIDENCE = {
    TIER_PURL: 0.95,
    TIER_COMMIT: 0.85,
    TIER_PRODUCT: 0.60,
    TIER_PROJECT: 0.35,
}

TIER_ORDER = [TIER_PURL, TIER_COMMIT, TIER_PRODUCT, TIER_PROJECT]

# A strong tier only counts as verified when its evidence was fully evaluated;
# the discounted paths (no version bound, no pinned commit) fall below this.
VERIFIED_CONFIDENCE = 0.85

# A project-name match is worthless if it fires on every component, so names
# below this length are ignored at T0 entirely.
MIN_PROJECT_NAME = 4
PROJECT_FUZZY_THRESHOLD = 0.93

# Below this length, T0 requires an *exact* normalised match rather than a
# similarity score. A one-character difference between two short package names
# is weak evidence, not strong: `htslib` (a C bioinformatics library) and
# `tslib` (the TypeScript runtime helper) score 0.91 and are entirely
# unrelated. Short near-misses are so common across ecosystems that they are
# the basis of typosquatting, so treating them as a hit produces exactly the
# kind of false positive that discredits the whole T0 tier.
PROJECT_EXACT_BELOW = 10

# Names of very different lengths are not the same project, whatever the
# character overlap suggests.
PROJECT_MAX_LENGTH_DELTA = 3

# Distribution and language packaging decorate the same upstream project in
# predictable ways: `python-requests`, `ruby-httparty`, `lodash-dev`. Those are
# stripped before comparison.
#
# Note `lib` is deliberately NOT stripped. libxml2, libpng and libcurl are the
# real upstream names, and folding them to xml2/png/curl invents equivalences
# that do not exist -- a false positive at T0 is far more expensive than a
# missed prefix, because T0 already fires on name similarity alone.
_AFFIX = re.compile(
    r"^(?:python[-_]|py[-_]|node[-_]|golang[-_]|go[-_]|rust[-_]|ruby[-_]|"
    r"rb[-_]|php[-_]|perl[-_]|r[-_]cran[-_])"
    r"|(?:[-_](?:dev|devel|bin|src|common|doc|utils))$")


def normalise_project(name):
    """
    Fold a project or package name to a comparable form.

    Package identifiers carry their coordinates in three different shapes and
    only the trailing segment names the project:

        org.apache.logging.log4j:log4j-core   Maven group:artifact
        @babel/traverse                       npm scope
        github.com/gin-gonic/gin              Go module path
    """
    if not name:
        return ""
    text = str(name).strip().lower()
    if ":" in text:                      # Maven group:artifact
        text = text.rsplit(":", 1)[-1]
    if text.startswith("@") and "/" in text:
        # An npm scope is part of the package's identity, not a path prefix.
        # Dropping it collapses @tiptap/core, @vueuse/core, @eslint/core and
        # every other scoped `core` package to the same string, so one advisory
        # matches all of them at 1.00 similarity.
        text = text[1:].replace("/", "-", 1)
    elif "/" in text:                    # Go module path, repo path
        text = text.rstrip("/").rsplit("/", 1)[-1]
    text = re.sub(r"[^a-z0-9]+", "-", text).strip("-")
    previous = None
    while previous != text:              # strip stacked affixes
        previous = text
        text = _AFFIX.sub("", text).strip("-")
    return text


def normalise_repo_url(url):
    """
    Fold a repository URL so the same repo compares equal however it is written.

        https://github.com/Owner/Repo.git
        git@github.com:Owner/Repo.git
        github.com/owner/repo
    """
    if not url:
        return ""
    text = str(url).strip().lower()
    text = re.sub(r"^(?:git\+)?(?:https?://|git://|ssh://)?(?:git@)?", "", text)
    # SCP-style `host:owner/repo` -- convert the host separator to a slash.
    text = re.sub(r"^([a-z0-9.\-]+):(?!//)", r"\1/", text)
    text = re.sub(r"\.git$", "", text)
    return text.rstrip("/")


def _similar(a, b):
    try:
        from rapidfuzz import fuzz
        return fuzz.ratio(a, b) / 100.0
    except Exception:                        # difflib fallback, same contract
        from difflib import SequenceMatcher
        return SequenceMatcher(None, a, b).ratio()


# ---------------------------------------------------------------------------
# Tier matchers. Each returns (matched: bool, confidence: float, reason: str).
# ---------------------------------------------------------------------------

def match_purl(finding, component):
    """
    T3 -- package identity plus a version-range test.

    Requires the finding to carry OSV-shaped `affected[]` entries. Where the
    component records a constraint (`^1.2.3`) rather than a resolved version,
    the range cannot be honestly evaluated, so the match is reported at reduced
    confidence rather than asserted.
    """
    ranges = finding.get("affected_ranges") or []
    if not ranges:
        return False, 0.0, ""

    comp_name = (component.get("name") or "").lower()
    comp_eco = component.get("ecosystem")
    comp_version = component.get("version")

    parsed = matching.parse_purl(component.get("purl"))
    if parsed:
        comp_name = (parsed["name"] or comp_name).lower()
        comp_eco = parsed["ecosystem"] or comp_eco
        # The component's own `version` wins over the one embedded in the PURL.
        # Both come from the same SBOM and normally agree, but when they do not
        # it is because the resolved version was updated and the PURL string was
        # not -- and silently preferring the stale PURL would evaluate the range
        # against a version the repository no longer uses.
        comp_version = comp_version or parsed["version"]

    for affected in ranges:
        package = affected.get("package") or {}
        if (package.get("name") or "").lower() != comp_name:
            continue
        if package.get("ecosystem") and comp_eco and \
                package["ecosystem"] != comp_eco:
            continue

        if not comp_version or matching.is_constraint(comp_version):
            return True, TIER_CONFIDENCE[TIER_PURL] * 0.7, \
                "package identity matched; version %r is a constraint, range " \
                "not evaluated" % comp_version

        for rng in affected.get("ranges") or []:
            if rng.get("type") == "GIT":
                continue
            if matching.version_in_range(comp_version, rng):
                return True, TIER_CONFIDENCE[TIER_PURL], \
                    "version %s inside affected range" % comp_version

        versions = affected.get("versions") or []
        if versions and str(comp_version) in [str(v) for v in versions]:
            return True, TIER_CONFIDENCE[TIER_PURL], \
                "version %s in explicit affected list" % comp_version

        if not (affected.get("ranges") or versions):
            return True, TIER_CONFIDENCE[TIER_PURL] * 0.8, \
                "package matched; advisory declares no version bound"

    return False, 0.0, ""


def match_commit(finding, component):
    """
    T1 -- upstream repository plus a GIT introduced/fixed commit range.

    This tier exists because OSS-Fuzz records carry `pkg:generic/<project>` and
    commit ranges rather than semantic versions, so no PURL-and-semver matcher
    can consume them at all.

    The honest limitation, stated rather than hidden: it can only *confirm* a
    hit when the SBOM records a resolved commit, and many CI-generated SBOMs
    record only a version. Where the repository matches but no commit is
    recorded, the finding is reported as a repository-level candidate at
    reduced confidence for an owner to confirm.
    """
    ranges = finding.get("commit_ranges") or []
    if not ranges:
        return False, 0.0, ""

    comp_repo = normalise_repo_url(component.get("repo_url")
                                   or component.get("source_url"))
    comp_commit = (component.get("commit") or component.get("revision") or "")
    comp_project = normalise_project(component.get("name"))

    for entry in ranges:
        repo = normalise_repo_url(entry.get("repo") or finding.get("repo_url"))
        if not repo:
            continue

        repo_matches = bool(comp_repo) and (comp_repo == repo
                                            or comp_repo.endswith(repo)
                                            or repo.endswith(comp_repo))
        if not repo_matches:
            # No repo URL in the SBOM: fall back to the trailing path segment,
            # which is the project name in practice.
            tail = normalise_project(repo.rsplit("/", 1)[-1])
            repo_matches = bool(tail) and tail == comp_project
        if not repo_matches:
            continue

        if comp_commit:
            introduced = entry.get("introduced")
            fixed = entry.get("fixed")
            if fixed and _same_commit(comp_commit, fixed):
                return False, 0.0, ""          # pinned exactly at the fix
            if introduced and _same_commit(comp_commit, introduced):
                return True, TIER_CONFIDENCE[TIER_COMMIT], \
                    "pinned commit is the introducing commit"
            return True, TIER_CONFIDENCE[TIER_COMMIT] * 0.8, \
                "repository matched; pinned commit %s not proven outside the " \
                "range" % comp_commit[:12]

        return True, TIER_CONFIDENCE[TIER_COMMIT] * 0.6, \
            "repository matched; SBOM records no commit, so the range could " \
            "not be evaluated"

    return False, 0.0, ""


def _same_commit(a, b):
    """Compare SHAs allowing for abbreviation on either side."""
    a, b = str(a).strip().lower(), str(b).strip().lower()
    if not a or not b:
        return False
    shortest = min(len(a), len(b))
    return shortest >= 7 and a[:shortest] == b[:shortest]


def match_product(finding, component):
    """
    T2 -- vendor and product strings, no PURL.

    Recall-oriented and therefore the tier that needs explicit false-positive
    control: the threshold is deliberately high and a bare vendor match with no
    product agreement is rejected.
    """
    product = finding.get("project") or finding.get("package_name")
    vendor = finding.get("vendor")
    if not product:
        return False, 0.0, ""

    if component.get("cpe"):
        matched, score, _fields = cpe_module.best_match(
            ["cpe:2.3:a:%s:%s:*:*:*:*:*:*:*:*" % (vendor or "*", product)],
            component)
        if matched:
            return True, min(TIER_CONFIDENCE[TIER_PRODUCT] + score * 0.2, 0.8), \
                "CPE product match on %s" % product

    # A finding for one ecosystem cannot affect a component in another. Without
    # this, a Packagist advisory for predis/predis matched a PyPI redis.
    finding_eco = finding.get("ecosystem")
    component_eco = component.get("ecosystem")
    if finding_eco and component_eco and finding_eco != component_eco:
        return False, 0.0, ""

    left, right = normalise_project(product), normalise_project(component.get("name"))
    if not left or not right or len(left) < MIN_PROJECT_NAME:
        return False, 0.0, ""

    # Same length discipline as T0. httpx2 against httpx scores 0.91, and a
    # trailing digit is how a typosquat is built, not how one project is
    # spelled twice.
    if abs(len(left) - len(right)) > PROJECT_MAX_LENGTH_DELTA:
        return False, 0.0, ""
    if max(len(left), len(right)) < PROJECT_EXACT_BELOW and left != right:
        return False, 0.0, ""

    ratio = _similar(left, right)
    if ratio >= PROJECT_FUZZY_THRESHOLD:
        return True, TIER_CONFIDENCE[TIER_PRODUCT] * ratio, \
            "product name %s ~ component %s (%.2f)" % (left, right, ratio)
    return False, 0.0, ""


def match_project(finding, component):
    """
    T0 -- project name alone, no version and no identifier.

    This is the CVD ledger at reveal: the project is known, nothing else is.
    Over-inclusive by design. Every hit is flagged unverified and routed to an
    owner rather than escalated automatically, because the alternative -- doing
    nothing until a CVE exists -- is what this whole project argues against.
    """
    project = finding.get("project")
    if not project:
        return False, 0.0, ""

    # T0 is reserved for findings that no identifier-keyed tool can see. Once a
    # CVE or GHSA exists, the published OSV path matches the same finding on
    # PURL and version range, which is both precise and version-aware. Matching
    # it again here by name adds no coverage and only contributes noise, so the
    # weakest tier stands down as soon as a stronger route exists.
    if finding.get("cve_ids") or finding.get("ghsa_ids"):
        return False, 0.0, ""

    left = normalise_project(project)
    if len(left) < MIN_PROJECT_NAME:
        return False, 0.0, ""

    candidates = [component.get("name")]
    parsed = matching.parse_purl(component.get("purl"))
    if parsed:
        candidates.append(parsed["name"])
        if parsed.get("namespace"):
            candidates.append(parsed["namespace"])
    if component.get("repo_url"):
        candidates.append(normalise_repo_url(component["repo_url"]).rsplit("/", 1)[-1])

    for candidate in candidates:
        right = normalise_project(candidate)
        if not right:
            continue
        if right == left:
            return True, TIER_CONFIDENCE[TIER_PROJECT], \
                "project name exact match on %s" % left

        # Fuzzy matching is only admissible where a near-miss is genuinely
        # unlikely: comparable lengths, and long enough that one differing
        # character is not most of the difference between two real projects.
        if abs(len(left) - len(right)) > PROJECT_MAX_LENGTH_DELTA:
            continue
        if max(len(left), len(right)) < PROJECT_EXACT_BELOW:
            continue

        ratio = _similar(left, right)
        if ratio >= PROJECT_FUZZY_THRESHOLD:
            return True, TIER_CONFIDENCE[TIER_PROJECT] * ratio, \
                "project name %s ~ %s (%.2f)" % (left, right, ratio)
    return False, 0.0, ""


MATCHERS = [
    (TIER_PURL, match_purl),
    (TIER_COMMIT, match_commit),
    (TIER_PRODUCT, match_product),
    (TIER_PROJECT, match_project),
]

# Depth of evidence each tier requires, so a finding is never matched by a
# matcher that needs more than it actually carries.
TIER_RANK = {TIER_PURL: 3, TIER_COMMIT: 2, TIER_PRODUCT: 1, TIER_PROJECT: 0}


def applicable_matchers(finding):
    """
    The single matcher a finding's evidence entitles it to.

    Exactly one, deliberately -- no cascade to weaker tiers. A finding declares
    what evidence it carries, and that evidence selects the matcher.

    Cascading was the original design and it was wrong. A GHSA advisory for
    `pkg:npm/@tiptap/core` carries a precise package identity; when the PURL
    matcher correctly rejected `@vueuse/core`, the cascade fell through to
    fuzzy name matching and reported a hit anyway. One advisory produced seven
    false positives across unrelated packages that merely shared a name
    fragment. The same fall-through matched `httpx2` to `httpx` and a Packagist
    `predis/predis` to a PyPI `redis`.

    The principle: when a finding names a package precisely and that package is
    not in the inventory, the answer is "not affected". Reaching for a weaker
    matcher is not a fallback, it is fabrication. The weak tiers exist for
    findings that genuinely have nothing better -- an EUVD record with only
    vendor and product strings, a CVD ledger entry with only a project name --
    not as a second chance for findings that already failed a precise test.
    """
    declared = finding.get("evidence_tier")
    if not declared:
        return []
    return [(tier, matcher) for tier, matcher in MATCHERS if tier == declared]


# ---------------------------------------------------------------------------
# Correlation
# ---------------------------------------------------------------------------

def correlate_finding(finding, components):
    """
    Match one finding against a repository's components.

    Tiers are tried best-first and the first hit per component wins, so a
    component that matches on PURL is never also reported as a weak name match.
    """
    matchers = applicable_matchers(finding)
    hits = []
    for component in components:
        for tier, matcher in matchers:
            try:
                matched, confidence, reason = matcher(finding, component)
            except Exception as error:       # a bad record, not a failed run
                log.debug("matcher %s failed on %s: %s",
                          tier, finding.get("source_id"), error)
                continue
            if matched:
                hits.append({
                    "component": component,
                    "tier": tier,
                    "confidence": round(confidence, 3),
                    "reason": reason,
                    # Verified means the evidence was actually evaluated, not
                    # merely that the tier is a strong one. A PURL match with no
                    # version bound, or a repository match with no commit, is a
                    # candidate for review -- calling it verified would overstate
                    # exactly the thing this tier is supposed to prove.
                    "verified": (tier in (TIER_PURL, TIER_COMMIT)
                                 and confidence >= VERIFIED_CONFIDENCE),
                })
                break
    return hits


def correlate(findings, components_by_repository):
    """
    Correlate every finding across the whole inventory.

    Returns [{finding, repository, component, tier, confidence, reason}], which
    is the blast radius: which repositories are exposed, and on what evidence.

    Findings still at the commitment stage are skipped rather than guessed at.
    The ledger withholds the project deliberately during that window, and
    attempting to infer it would defeat the purpose of a coordinated
    disclosure programme. They are held on the watchlist instead.
    """
    results = []
    for finding in findings:
        if finding.get("stage") == "commitment":
            continue
        if not finding.get("evidence_tier"):
            continue
        for repository, components in components_by_repository.items():
            for hit in correlate_finding(finding, components):
                results.append({
                    "finding": finding,
                    "repository": repository,
                    "component_name": hit["component"].get("name"),
                    "component_version": hit["component"].get("version"),
                    "ecosystem": hit["component"].get("ecosystem"),
                    "purl": hit["component"].get("purl"),
                    "tier": hit["tier"],
                    "confidence": hit["confidence"],
                    "reason": hit["reason"],
                    "verified": hit["verified"],
                })
    log.info("zero-day correlation: %d exposures from %d findings",
             len(results), len(findings))
    return results


def tier_breakdown(results):
    """Per-tier counts, so accuracy is never reported as a single average."""
    counts = {tier: 0 for tier in TIER_ORDER}
    for row in results:
        counts[row["tier"]] = counts.get(row["tier"], 0) + 1
    return counts
