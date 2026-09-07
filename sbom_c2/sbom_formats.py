"""
SBOM format parsing  (Capstone 1, Objective 1 — ingestion sources 2 and 3)

Capstone 1 specified three ingestion sources: the GitHub Dependency Graph API,
CI/CD-generated SBOMs from Syft or CycloneDX CLI, and direct upload through a
REST endpoint. The first is handled by github_client. This module handles the
other two, which share a code path: a CI/CD workflow posts the same document a
human would upload by hand.

Both CycloneDX 1.4+ and SPDX 2.3 are accepted, and the format is detected from
the document rather than declared, so callers do not have to know which tool
produced it.
"""

from .matching import parse_purl


class UnsupportedSBOM(ValueError):
    """Raised when a document is neither CycloneDX nor SPDX."""


def detect_format(document):
    """Identify the SBOM format from its own structure."""
    if not isinstance(document, dict):
        raise UnsupportedSBOM("SBOM must be a JSON object")
    if document.get("bomFormat") == "CycloneDX" or "components" in document:
        return "cyclonedx"
    if document.get("spdxVersion") or "packages" in document:
        return "spdx"
    raise UnsupportedSBOM(
        "Unrecognised SBOM: expected CycloneDX (bomFormat) or SPDX (spdxVersion)")


def parse(document):
    """
    Parse any supported SBOM into the component shape the correlator expects.

    Returns (components, metadata).
    """
    fmt = detect_format(document)
    if fmt == "cyclonedx":
        return parse_cyclonedx(document)
    return parse_spdx(document)


def parse_cyclonedx(document):
    """
    CycloneDX 1.4+.

    Components carry `purl` directly and may list CPEs under `cpe`. The
    top-level metadata.component describes the subject of the SBOM and is not
    itself a dependency, so it is excluded.
    """
    metadata = {
        "format": "CycloneDX",
        "spec_version": document.get("specVersion"),
        "serial_number": document.get("serialNumber"),
        "tool": _cyclonedx_tool(document),
        "subject": ((document.get("metadata") or {})
                    .get("component") or {}).get("name"),
    }

    components, seen = [], set()
    for entry in document.get("components", []) or []:
        name = entry.get("name")
        if not name:
            continue
        purl = entry.get("purl")
        parsed = parse_purl(purl) if purl else None
        version = entry.get("version") or (parsed or {}).get("version")
        ecosystem = (parsed or {}).get("ecosystem")

        key = (name, version, ecosystem)
        if key in seen:
            continue
        seen.add(key)

        components.append({
            "name": (parsed or {}).get("name") or name,
            "version": version,
            "ecosystem": ecosystem,
            "purl": purl,
            "cpe": entry.get("cpe"),
            "namespace": (parsed or {}).get("namespace") or entry.get("group"),
            # CycloneDX marks development-only components; keep the flag so the
            # scoring layer can reason about dependency scope later.
            "scope": entry.get("scope"),
            "direct": False,
            "path": None,
        })
    return components, metadata


def _cyclonedx_tool(document):
    tools = (document.get("metadata") or {}).get("tools")
    if isinstance(tools, dict):
        tools = tools.get("components") or []
    for tool in tools or []:
        if isinstance(tool, dict) and tool.get("name"):
            return "%s %s" % (tool.get("name"), tool.get("version") or "")
    return None


def parse_spdx(document):
    """
    SPDX 2.3, including GitHub's dependency-graph export.

    Identifiers live in externalRefs, typed PACKAGE-MANAGER/purl or SECURITY/cpe23Type.
    """
    creation = document.get("creationInfo") or {}
    metadata = {
        "format": "SPDX",
        "spec_version": document.get("spdxVersion"),
        "serial_number": document.get("documentNamespace"),
        "tool": ", ".join(creation.get("creators", []) or []) or None,
        "subject": document.get("name"),
    }

    components, seen = [], set()
    for package in document.get("packages", []) or []:
        name = package.get("name")
        if not name:
            continue
        # GitHub names the repository's own root package com.github.<owner>/<repo>
        if str(name).startswith("com.github."):
            continue

        purl = cpe = None
        for ref in package.get("externalRefs", []) or []:
            ref_type = ref.get("referenceType")
            if ref_type == "purl" and not purl:
                purl = ref.get("referenceLocator")
            elif ref_type in ("cpe23Type", "cpe22Type") and not cpe:
                cpe = ref.get("referenceLocator")

        parsed = parse_purl(purl) if purl else None
        version = package.get("versionInfo") or (parsed or {}).get("version")
        resolved = (parsed or {}).get("name") or str(name).split(":", 1)[-1]
        ecosystem = (parsed or {}).get("ecosystem")

        key = (resolved, version, ecosystem)
        if key in seen:
            continue
        seen.add(key)

        components.append({
            "name": resolved,
            "version": version,
            "ecosystem": ecosystem,
            "purl": purl,
            "cpe": cpe,
            "namespace": (parsed or {}).get("namespace"),
            "scope": None,
            "spdx_id": package.get("SPDXID"),
            "direct": False,
            "path": None,
        })
    return components, metadata
