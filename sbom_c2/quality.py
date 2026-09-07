"""
SBOM quality gate  (Capstone 1, Objective 1 / Phase 1)

Torres-Arias et al. argue that an SBOM lacking standardised identifiers is
insufficient for automated vulnerability analysis: you cannot correlate what you
cannot identify. This module implements that as an admission check, scoring each
SBOM on four dimensions and refusing components that carry neither a PURL nor a
CPE.

The gate is deliberately advisory rather than fatal. An SBOM that fails overall
is still ingested, but the failure is recorded and surfaced, because silently
dropping a repository's inventory would create exactly the invisible risk the
project exists to remove.

Pure logic, no third-party imports.
"""

# Weightings for the overall quality score. Identifier coverage dominates,
# because it is the dimension that determines whether correlation can work at
# all; the others degrade accuracy rather than prevent it.
DIMENSION_WEIGHTS = {
    "identifier_coverage": 0.45,
    "version_completeness": 0.30,
    "ecosystem_coverage": 0.15,
    "metadata_completeness": 0.10,
}

PASS_THRESHOLD = 0.60
IDENTIFIER_MINIMUM = 0.50


class QualityGateResult:
    def __init__(self, passed, score, dimensions, issues, component_count,
                 rejected):
        self.passed = passed
        self.score = score
        self.dimensions = dimensions
        self.issues = issues
        self.component_count = component_count
        self.rejected = rejected

    def as_dict(self):
        return {
            "passed": self.passed,
            "score": self.score,
            "dimensions": self.dimensions,
            "issues": self.issues,
            "component_count": self.component_count,
            "rejected_components": len(self.rejected),
            "rejected_sample": [c.get("name") for c in self.rejected[:10]],
        }


def component_is_identifiable(component):
    """A component is correlatable if it carries a PURL or a CPE."""
    return bool(component.get("purl") or component.get("cpe"))


def assess(components, source=None):
    """
    Score an SBOM's fitness for automated vulnerability correlation.

    components: the parsed component list
    source:     where the SBOM came from, recorded in the issue text

    Returns a QualityGateResult.
    """
    total = len(components)
    if total == 0:
        return QualityGateResult(
            passed=False, score=0.0,
            dimensions={k: 0.0 for k in DIMENSION_WEIGHTS},
            issues=["SBOM contains no components"],
            component_count=0, rejected=[])

    identifiable = [c for c in components if component_is_identifiable(c)]
    versioned = [c for c in components if c.get("version")]
    with_ecosystem = [c for c in components if c.get("ecosystem")]
    with_name = [c for c in components if c.get("name")]

    dimensions = {
        "identifier_coverage": round(len(identifiable) / total, 4),
        "version_completeness": round(len(versioned) / total, 4),
        "ecosystem_coverage": round(len(with_ecosystem) / total, 4),
        "metadata_completeness": round(len(with_name) / total, 4),
    }

    score = round(sum(dimensions[k] * w for k, w in DIMENSION_WEIGHTS.items()), 4)

    issues = []
    if dimensions["identifier_coverage"] < IDENTIFIER_MINIMUM:
        issues.append(
            "Only %.0f%% of components carry a PURL or CPE; correlation "
            "accuracy will be materially reduced (Zahan et al.)"
            % (dimensions["identifier_coverage"] * 100))
    if dimensions["version_completeness"] < 0.80:
        issues.append(
            "%.0f%% of components lack a version; these cannot be evaluated "
            "against advisory version ranges"
            % ((1 - dimensions["version_completeness"]) * 100))
    if dimensions["ecosystem_coverage"] < 0.80:
        issues.append(
            "%.0f%% of components lack an ecosystem, forcing name-only matching"
            % ((1 - dimensions["ecosystem_coverage"]) * 100))
    if source:
        issues = ["[%s] %s" % (source, i) for i in issues]

    passed = (score >= PASS_THRESHOLD
              and dimensions["identifier_coverage"] >= IDENTIFIER_MINIMUM)

    rejected = [c for c in components if not component_is_identifiable(c)]

    return QualityGateResult(passed, score, dimensions, issues, total, rejected)


def admissible(components):
    """
    Split components into those that can be correlated and those that cannot.

    Returns (admitted, rejected). Rejected components are reported rather than
    discarded quietly, so a repository never appears clean merely because its
    SBOM was unusable.
    """
    admitted, rejected = [], []
    for component in components:
        (admitted if component_is_identifiable(component) else rejected).append(
            component)
    return admitted, rejected
