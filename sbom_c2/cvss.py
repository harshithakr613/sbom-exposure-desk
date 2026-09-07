"""
CVSS v3.1 Base Score computation.

OSV records usually carry a CVSS vector string rather than a numeric score, so
the score has to be computed. An earlier version of this module approximated it
from the impact metrics alone, which ignored Attack Complexity and Scope and
consequently reported almost everything at 10.0 -- lodash CVE-2021-23337 scored
10.0 against a published 7.2.

This implements the specification arithmetic exactly, following the equations in
the FIRST CVSS v3.1 Specification Document, section 8.1. Scores computed here
match the published NVD base scores.

Pure logic, no third-party imports.
"""

import math

# Metric weights, from the specification's Table 15.
ATTACK_VECTOR = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
ATTACK_COMPLEXITY = {"L": 0.77, "H": 0.44}
USER_INTERACTION = {"N": 0.85, "R": 0.62}
IMPACT = {"H": 0.56, "L": 0.22, "N": 0.0}

# Privileges Required is weighted differently when Scope is Changed, because
# crossing a security boundary makes holding privileges less of an obstacle.
PRIVILEGES_REQUIRED = {
    False: {"N": 0.85, "L": 0.62, "H": 0.27},   # Scope Unchanged
    True:  {"N": 0.85, "L": 0.68, "H": 0.50},   # Scope Changed
}

SEVERITY_BANDS = [(9.0, "CRITICAL"), (7.0, "HIGH"), (4.0, "MEDIUM"),
                  (0.1, "LOW")]

# Where no vector is available at all, a qualitative band is the only signal.
# These are midpoints of each band, used as a clearly-labelled fallback.
QUALITATIVE_FALLBACK = {
    "CRITICAL": 9.5, "HIGH": 7.5, "MODERATE": 5.5, "MEDIUM": 5.5,
    "LOW": 3.0, "NONE": 0.0,
}


class InvalidVector(ValueError):
    """Raised when a string is not a parseable CVSS vector."""


def parse_vector(vector):
    """
    Parse a CVSS vector string into its metric abbreviations.

    Accepts both the prefixed form, "CVSS:3.1/AV:N/AC:L/...", and a bare
    metric list. Returns a dict, or raises InvalidVector.
    """
    if not vector or not isinstance(vector, str):
        raise InvalidVector("no vector supplied")

    metrics = {}
    for part in vector.strip().split("/"):
        if ":" not in part:
            continue
        key, _, value = part.partition(":")
        key = key.strip().upper()
        if key == "CVSS":          # the version prefix, not a metric
            continue
        metrics[key] = value.strip().upper()

    required = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
    missing = [m for m in required if m not in metrics]
    if missing:
        raise InvalidVector("vector missing metrics: %s" % ", ".join(missing))
    return metrics


def _roundup(value):
    """
    The specification's Roundup function, section 8.1.

    Ordinary rounding is not equivalent: CVSS rounds *up* to one decimal place,
    and the specification defines it over integer arithmetic to avoid the
    floating-point drift that a naive ceil would introduce.
    """
    integer = int(round(value * 100000))
    if integer % 10000 == 0:
        return integer / 100000.0
    return (math.floor(integer / 10000) + 1) / 10.0


def base_score(vector):
    """
    Compute the CVSS v3.1 Base Score from a vector string.

    Returns a float in [0.0, 10.0]. Raises InvalidVector on unparseable input.
    """
    m = parse_vector(vector)
    scope_changed = m["S"] == "C"

    try:
        av = ATTACK_VECTOR[m["AV"]]
        ac = ATTACK_COMPLEXITY[m["AC"]]
        pr = PRIVILEGES_REQUIRED[scope_changed][m["PR"]]
        ui = USER_INTERACTION[m["UI"]]
        conf, integ, avail = IMPACT[m["C"]], IMPACT[m["I"]], IMPACT[m["A"]]
    except KeyError as error:
        raise InvalidVector("unrecognised metric value: %s" % error)

    iss = 1 - ((1 - conf) * (1 - integ) * (1 - avail))

    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * pow(iss - 0.02, 15)
    else:
        impact = 6.42 * iss

    if impact <= 0:
        return 0.0

    exploitability = 8.22 * av * ac * pr * ui
    combined = impact + exploitability
    if scope_changed:
        combined *= 1.08

    return _roundup(min(combined, 10.0))


def severity(score):
    """Qualitative severity rating for a numeric score."""
    if score is None:
        return None
    for threshold, label in SEVERITY_BANDS:
        if score >= threshold:
            return label
    return "NONE"


def score_from_advisory(advisory):
    """
    Extract a base score from an OSV advisory.

    Returns (score, vector, source). `source` records how the score was
    obtained -- "vector" for a computed score, "qualitative" for a band midpoint,
    None when nothing is available -- so a report can distinguish a calculated
    value from an estimate rather than presenting both as equivalent.
    """
    for entry in advisory.get("severity", []) or []:
        if not str(entry.get("type", "")).upper().startswith("CVSS_V3"):
            continue
        raw = entry.get("score")

        # Some ecosystems record the number directly rather than a vector.
        try:
            return round(float(raw), 1), None, "numeric"
        except (TypeError, ValueError):
            pass

        try:
            return base_score(raw), raw, "vector"
        except InvalidVector:
            continue

    band = str((advisory.get("database_specific") or {}).get("severity", "")).upper()
    if band in QUALITATIVE_FALLBACK:
        return QUALITATIVE_FALLBACK[band], None, "qualitative"

    return None, None, None
