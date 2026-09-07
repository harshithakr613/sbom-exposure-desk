#!/usr/bin/env python3
"""
Build the demonstration GitHub organisation.

Creates (or forks) the repositories described in data/demo_org.json, commits a
dependency manifest pinned to known-vulnerable versions, and enables the
dependency graph, Dependabot alerts and Dependabot security updates.

    python scripts/setup_demo_org.py --mode create      # recommended
    python scripts/setup_demo_org.py --mode fork
    python scripts/setup_demo_org.py --check            # did alerts arrive?

WHY TWO MODES
-------------
`create` makes small purpose-named repositories whose root manifest pins the
vulnerable versions. Dependabot scans root manifests reliably, so alerts appear
within minutes. The repository names map cleanly onto business processes, which
is what the prioritisation demo needs.

`fork` forks a real upstream project and then commits the pinned manifest over
it. Closer to the proposal's wording, but forks do NOT get Dependabot alerts by
default -- this script enables them explicitly, and even then propagation is
slower and occasionally does not happen at all.

Run `create` unless you specifically need forks. If you use forks, run it
tonight and verify with --check tomorrow morning, not an hour before the demo.

The token needs a fine-grained PAT scoped to the organisation with write access
to Administration and Contents. Read-only is enough for the analyzer itself;
this setup script is the only part that writes.
"""

import argparse
import base64
import json
import os
import sys
import time

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sbom_c2 import config  # noqa: E402

API = config.GITHUB_API
HERE = os.path.dirname(os.path.abspath(__file__))
SPEC_PATH = os.path.join(os.path.dirname(HERE), "data", "demo_org.json")


def session(token):
    s = requests.Session()
    s.headers.update({
        "Authorization": "Bearer %s" % token,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": config.USER_AGENT,
    })
    return s


# ---------------------------------------------------------------------------
# Manifest rendering
# ---------------------------------------------------------------------------

def render_manifest(repo):
    """Produce the manifest text that pins the vulnerable versions."""
    kind = repo["manifest"]
    pins = repo["pins"]

    if kind == "package.json":
        return json.dumps({
            "name": repo["name"],
            "version": "1.0.0",
            "description": repo["description"],
            "private": True,
            "dependencies": {k: v for k, v in pins.items()},
        }, indent=2) + "\n"

    if kind == "requirements.txt":
        lines = ["# %s" % repo["description"], ""]
        lines += ["%s==%s" % (k, v) for k, v in pins.items()]
        return "\n".join(lines) + "\n"

    if kind == "pom.xml":
        deps = []
        for coordinate, version in pins.items():
            group, artifact = coordinate.split(":", 1)
            deps.append(
                "    <dependency>\n"
                "      <groupId>%s</groupId>\n"
                "      <artifactId>%s</artifactId>\n"
                "      <version>%s</version>\n"
                "    </dependency>" % (group, artifact, version))
        return (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<project xmlns="http://maven.apache.org/POM/4.0.0">\n'
            "  <modelVersion>4.0.0</modelVersion>\n"
            "  <groupId>com.demo</groupId>\n"
            "  <artifactId>%s</artifactId>\n"
            "  <version>1.0.0</version>\n"
            "  <dependencies>\n%s\n  </dependencies>\n"
            "</project>\n" % (repo["name"], "\n".join(deps)))

    raise ValueError("unsupported manifest type: %s" % kind)


def readme_for(repo):
    cves = ", ".join(repo.get("known_cves", []))
    return (
        "# %s\n\n%s\n\n"
        "## Purpose\n\n"
        "This repository is part of a controlled demonstration organisation for an "
        "MSc Cybersecurity capstone project on business-context-aware vulnerability "
        "prioritisation. Its dependency manifest is **deliberately pinned to known-"
        "vulnerable versions** so that detection and remediation can be demonstrated "
        "against a known ground truth.\n\n"
        "**Do not use this code for anything.** It exists to be scanned.\n\n"
        "## Expected findings\n\n%s\n" % (
            repo["name"], repo["description"], cves or "see manifest")
    )


# ---------------------------------------------------------------------------
# GitHub operations
# ---------------------------------------------------------------------------

def create_repo(s, org, repo):
    url = "%s/orgs/%s/repos" % (API, org)
    response = s.post(url, json={
        "name": repo["name"],
        "description": repo["description"][:300],
        "private": False,
        "auto_init": True,
        "has_issues": True,
    })
    if response.status_code == 422:
        print("    exists already, reusing")
        return True
    if not response.ok:
        print("    FAILED to create: %s %s" % (response.status_code, response.text[:200]))
        return False
    time.sleep(2)  # let GitHub finish initialising the default branch
    return True


def fork_repo(s, org, repo):
    upstream = repo["fork_from"]

    # Re-running the script must be safe: an existing fork is reused rather
    # than re-forked, since GitHub rejects a second fork of the same upstream.
    if s.get("%s/repos/%s/%s" % (API, org, repo["name"])).ok:
        print("    exists already, reusing")
        return True

    response = s.post("%s/repos/%s/forks" % (API, upstream),
                      json={"organization": org, "name": repo["name"]})
    if not response.ok:
        print("    FAILED to fork %s: %s %s" % (
            upstream, response.status_code, response.text[:200]))
        return False
    # Forking is asynchronous; the repository is not immediately writable.
    for _ in range(15):
        time.sleep(4)
        if s.get("%s/repos/%s/%s" % (API, org, repo["name"])).ok:
            return True
    print("    fork did not become available in time")
    return False


def put_file(s, org, name, path, content, message):
    url = "%s/repos/%s/%s/contents/%s" % (API, org, name, path)
    payload = {
        "message": message,
        "content": base64.b64encode(content.encode()).decode(),
    }
    existing = s.get(url)
    if existing.ok:
        payload["sha"] = existing.json().get("sha")
    response = s.put(url, json=payload)
    if not response.ok:
        print("    FAILED to write %s: %s %s" % (
            path, response.status_code, response.text[:200]))
        return False
    return True


def enable_security(s, org, name):
    """
    Turn on the dependency graph, Dependabot alerts and security updates.

    These are separate endpoints and all three matter. Alerts do not appear
    without the dependency graph, and no pull requests appear without security
    updates. Forks in particular need this done explicitly.
    """
    base = "%s/repos/%s/%s" % (API, org, name)
    results = {}
    for label, path in (("dependency_graph", "/automated-security-fixes"),
                        ("vulnerability_alerts", "/vulnerability-alerts")):
        response = s.put(base + path)
        results[label] = response.status_code in (200, 204)
    # Explicitly enable the dependency graph via the settings API.
    response = s.patch(base, json={
        "security_and_analysis": {
            "dependabot_security_updates": {"status": "enabled"},
        }
    })
    results["security_updates"] = response.ok
    return results


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def preflight():
    """
    Verify the token and organisation before creating anything.

    A token missing one scope fails silently halfway through and leaves a
    half-built organisation, so check everything up front.
    """
    token, org = config.require_github()
    s = session(token)

    print("Preflight")
    print("  organisation : %s" % org)

    who = s.get("%s/user" % API)
    if who.status_code == 401:
        sys.exit("  FAIL: token rejected (401). Check GITHUB_TOKEN in .env.")
    if not who.ok:
        sys.exit("  FAIL: %s %s" % (who.status_code, who.text[:200]))
    print("  token user   : %s" % who.json().get("login"))

    org_response = s.get("%s/orgs/%s" % (API, org))
    if org_response.status_code == 404:
        sys.exit("  FAIL: organisation '%s' not visible to this token.\n"
                 "        Check the spelling, and that the token's resource owner\n"
                 "        is the organisation rather than your personal account." % org)
    if not org_response.ok:
        sys.exit("  FAIL: %s %s" % (org_response.status_code, org_response.text[:200]))
    print("  org visible  : yes")

    # Repo creation is the permission most often missed.
    probe = s.get("%s/orgs/%s/repos" % (API, org), params={"per_page": 1})
    if not probe.ok:
        sys.exit("  FAIL: cannot list org repositories (%s). Token needs\n"
                 "        Administration: Read and write." % probe.status_code)
    existing = [r["name"] for r in s.get(
        "%s/orgs/%s/repos" % (API, org), params={"per_page": 100}).json()]
    print("  existing repos: %d %s" % (len(existing), existing if existing else ""))

    spec = json.load(open(SPEC_PATH))
    planned = [r["name"] for r in spec["repositories"]]
    clash = sorted(set(planned) & set(existing))
    if clash:
        print("  NOTE: these already exist and will be reused: %s" % ", ".join(clash))

    print("  planned      : %d repositories" % len(planned))
    print("\nPreflight passed.\n")
    return True

def build(mode):
    preflight()
    token, org = config.require_github()
    s = session(token)
    spec = json.load(open(SPEC_PATH))

    built = []
    for repo in spec["repositories"]:
        print("\n[%s] %s" % (mode, repo["name"]))

        ok = create_repo(s, org, repo) if mode == "create" else fork_repo(s, org, repo)
        if not ok:
            continue

        # In fork mode the upstream manifest is left alone and the pinned one
        # goes into capstone-demo/. GitHub's dependency graph scans manifests
        # anywhere in the repository, so the fork keeps its real transitive
        # dependency tree AND gains the deliberately vulnerable versions.
        path = (repo["manifest"] if mode == "create"
                else "capstone-demo/%s" % repo["manifest"])
        manifest = render_manifest(repo)
        if not put_file(s, org, repo["name"], path, manifest,
                        "Pin dependencies to known-vulnerable versions for "
                        "capstone demonstration"):
            continue
        print("    wrote %s (%d pinned packages)" % (path, len(repo["pins"])))

        readme_path = ("README.md" if mode == "create"
                       else "capstone-demo/README.md")
        put_file(s, org, repo["name"], readme_path, readme_for(repo),
                 "Explain the purpose of this demonstration repository")

        flags = enable_security(s, org, repo["name"])
        print("    security: %s" % ", ".join(
            "%s=%s" % (k, "on" if v else "FAILED") for k, v in flags.items()))
        if mode == "fork" and not all(flags.values()):
            print("    NOTE: GitHub disables Dependabot on forks by default. "
                  "If alerts do not appear, enable them manually at "
                  "https://github.com/%s/%s/settings/security_analysis"
                  % (org, repo["name"]))
        built.append(repo["name"])

    print("\n%d/%d repositories ready in %s" % (
        len(built), len(spec["repositories"]), org))
    print("\nDependabot needs time to scan. Wait at least 30 minutes, then run:")
    print("    python scripts/setup_demo_org.py --check")


def check():
    """Report how many Dependabot alerts each repository has produced."""
    token, org = config.require_github()
    s = session(token)
    spec = json.load(open(SPEC_PATH))

    total = 0
    print("Dependabot alert counts for %s\n" % org)
    for repo in spec["repositories"]:
        name = repo["name"]
        response = s.get("%s/repos/%s/%s/dependabot/alerts" % (API, org, name),
                         params={"state": "open", "per_page": 100})
        if response.status_code == 404:
            print("  %-26s repository or alerts not available" % name)
            continue
        if not response.ok:
            print("  %-26s error %s" % (name, response.status_code))
            continue
        alerts = response.json()
        total += len(alerts)
        expected = len(repo.get("known_cves", []))
        flag = "" if alerts else "   <-- nothing yet"
        print("  %-26s %2d alerts (expected roughly %d)%s" % (
            name, len(alerts), expected, flag))

    print("\nTotal open alerts: %d" % total)
    if total == 0:
        print("\nNothing yet. Dependabot can take 30-60 minutes on new repositories.\n"
              "If it is still empty after a few hours, check that Dependabot alerts\n"
              "are enabled under Organisation Settings -> Code security.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=["create", "fork"], default="create")
    parser.add_argument("--check", action="store_true",
                        help="report Dependabot alert counts and exit")
    parser.add_argument("--preflight", action="store_true",
                        help="verify token and organisation access, then exit")
    args = parser.parse_args()

    if args.check:
        check()
    elif args.preflight:
        preflight()
    else:
        build(args.mode)


if __name__ == "__main__":
    main()
