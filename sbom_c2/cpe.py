"""
CPE 2.3 parsing and fuzzy matching  (Capstone 1, Objective 2 — fallback path)

PURL identifies a package as its ecosystem knows it. CPE identifies a product as
NIST's National Vulnerability Database catalogues it. PURL is the more precise
identifier and is always tried first; this module is the fallback for components
whose SBOM entry carries no usable PURL — the case Zahan et al. found to be
common in published SBOMs.

Matching decomposes the CPE into vendor, product and version, then compares
vendor and product by string similarity. RapidFuzz is used when available for
speed; difflib provides an equivalent pure-standard-library fallback so the
module never becomes an installation problem.
"""

import re
from urllib.parse import unquote

try:  # pragma: no cover - environment dependent
    from rapidfuzz import fuzz as _fuzz

    def _ratio(a, b):
        return _fuzz.ratio(a, b) / 100.0

    BACKEND = "rapidfuzz"
except Exception:  # pragma: no cover
    from difflib import SequenceMatcher

    def _ratio(a, b):
        return SequenceMatcher(None, a, b).ratio()

    BACKEND = "difflib"


# Vendor and product must both look right before a match is declared. Product
# similarity is weighted higher because vendor naming is the more inconsistent
# of the two across advisory sources.
VENDOR_WEIGHT = 0.35
PRODUCT_WEIGHT = 0.65
MATCH_THRESHOLD = 0.85

CPE23_PREFIX = "cpe:2.3:"
CPE22_PREFIX = "cpe:/"

PART_NAMES = {"a": "application", "o": "operating_system", "h": "hardware"}


def parse_cpe(cpe):
    """
    Decompose a CPE 2.3 (or legacy 2.2) string.

    cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*
             |  |      |      |
             |  vendor  |      version
             part       product

    Returns a dict, or None when the string is not a CPE. Wildcards and
    not-applicable markers are normalised to None so callers can treat a missing
    field uniformly.
    """
    if not cpe:
        return None
    text = str(cpe).strip()

    if text.startswith(CPE23_PREFIX):
        fields = _split_cpe23(text[len(CPE23_PREFIX):])
    elif text.startswith(CPE22_PREFIX):
        fields = text[len(CPE22_PREFIX):].split(":")
    else:
        return None

    def field(index):
        if index >= len(fields):
            return None
        value = unquote(fields[index]).strip()
        if value in ("", "*", "-", "ANY", "NA"):
            return None
        return value.lower().replace("_", " ")

    part = field(0)
    return {
        "part": part,
        "part_name": PART_NAMES.get(part, part),
        "vendor": field(1),
        "product": field(2),
        "version": field(3),
        "update": field(4),
    }


def _split_cpe23(body):
    """
    Split on colons while respecting backslash escaping.

    CPE 2.3 escapes literal colons as \\:, so a naive split corrupts any field
    containing one — which happens in real vendor and product names.
    """
    fields, current, escaped = [], [], False
    for ch in body:
        if escaped:
            current.append(ch)
            escaped = False
        elif ch == "\\":
            escaped = True
        elif ch == ":":
            fields.append("".join(current))
            current = []
        else:
            current.append(ch)
    fields.append("".join(current))
    return fields


def _normalise(text):
    """Strip punctuation and common noise so 'log4j-core' ~ 'log4j core'."""
    if not text:
        return ""
    text = str(text).lower()
    text = re.sub(r"[._\-/:]+", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def similarity(cpe_fields, component):
    """
    Score how closely a parsed CPE matches an SBOM component.

    Package names are frequently qualified — "org.apache.logging.log4j:log4j-core"
    for Maven, "@babel/traverse" for npm — while a CPE product is the bare
    product name, "log4j". Comparing the two whole strings scores badly for
    pairs that plainly refer to the same thing, so the component name is broken
    into tokens and the CPE product is compared against the most favourable of
    the whole name, the trailing artifact, and each token.

    Returns a float in [0, 1].
    """
    if not cpe_fields:
        return 0.0

    raw_name = str(component.get("name") or "")
    name = _normalise(raw_name)
    namespace = _normalise(component.get("namespace") or "")
    product = _normalise(cpe_fields.get("product"))
    vendor = _normalise(cpe_fields.get("vendor"))

    if not product or not name:
        return 0.0

    # Trailing artifact: log4j-core from org.apache.logging.log4j:log4j-core
    artifact = _normalise(re.split(r"[:/]", raw_name)[-1])
    tokens = [t for t in name.split(" ") if t]

    product_flat = product.replace(" ", "")
    candidates = [name, artifact] + tokens
    product_score = max(_ratio(product, c) for c in candidates if c)

    # A product name contained within the package name is a strong signal that
    # whole-string similarity underweights: "log4j" inside "log4j-core".
    if artifact and product_flat and product_flat in artifact.replace(" ", ""):
        product_score = max(product_score, 0.95)

    if vendor:
        vendor_flat = vendor.replace(" ", "")
        vendor_score = max(
            _ratio(vendor, namespace) if namespace else 0.0,
            max((_ratio(vendor, t) for t in tokens), default=0.0),
            # Vendors commonly appear inside the package coordinate, as
            # "apache" does within "org.apache.logging.log4j".
            1.0 if vendor_flat and vendor_flat in name.replace(" ", "") else 0.0,
        )
    else:
        # No vendor recorded: judge on product alone rather than penalising.
        vendor_score = product_score

    return round(product_score * PRODUCT_WEIGHT + vendor_score * VENDOR_WEIGHT, 4)


def match(cpe, component, threshold=MATCH_THRESHOLD):
    """
    Decide whether a CPE refers to this component.

    Returns (matched, score, parsed_fields). Version is deliberately not
    compared here — range evaluation is the correlator's job, and a CPE that
    names one affected version should not be read as excluding the others.
    """
    fields = parse_cpe(cpe)
    if fields is None:
        return False, 0.0, None
    score = similarity(fields, component)
    return score >= threshold, score, fields


def best_match(cpe_list, component, threshold=MATCH_THRESHOLD):
    """Highest-scoring CPE from a list, or (None, 0.0) if none clears the bar."""
    best, best_score = None, 0.0
    for cpe in cpe_list or []:
        matched, score, _ = match(cpe, component, threshold)
        if matched and score > best_score:
            best, best_score = cpe, score
    return best, best_score
