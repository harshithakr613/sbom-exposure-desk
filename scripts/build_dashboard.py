#!/usr/bin/env python3
"""
Rewire the Capstone 1 dashboard to the live API.

The Capstone 1 dashboard is a single self-contained HTML file with its data
baked in as three JavaScript constants: EXPOSURES, REPOS and CVE_FEED. This
script replaces those three literals with a loader that fetches the same shapes
from the running FastAPI service, and writes the result to dashboard/index.html.

Roughly 1,200 lines of working UI are preserved untouched. Only the data source
changes -- which is precisely the step that turns the Capstone 1 prototype into
a running system.

    python scripts/build_dashboard.py ../path/to/sbom-analyzer-v3.html

Re-run it whenever you edit the original dashboard.
"""

import argparse
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_DIR = os.path.join(ROOT, "dashboard")
OUT_FILE = os.path.join(OUT_DIR, "index.html")

LOADER = r"""
// ---------------------------------------------------------------------------
// LIVE DATA LOADER  (Capstone 2)
//
// Capstone 1 shipped these three structures as hard-coded literals. They are
// now fetched from the FastAPI service and mapped into exactly the same shapes,
// so every render function below continues to work unchanged.
// ---------------------------------------------------------------------------

let EXPOSURES = [];
let REPOS = [];
let CVE_FEED = [];
let DATA_TS = 'loading...';

const API = (location.origin && location.origin !== 'null') ? location.origin
                                                            : 'http://127.0.0.1:8000';

async function api(path, options) {
  const response = await fetch(API + path, options);
  if (!response.ok) throw new Error(path + ' -> ' + response.status);
  return response.json();
}

function severityFor(cvss) {
  if (cvss >= 9) return 'CRITICAL';
  if (cvss >= 7) return 'HIGH';
  if (cvss >= 4) return 'MEDIUM';
  return 'LOW';
}

function shortRepo(fullName) {
  return (fullName || '').split('/').pop();
}

async function loadLiveData() {
  const [repos, exposures] = await Promise.all([
    api('/api/repositories'),
    api('/api/exposures?state=all&limit=500'),
  ]);

  REPOS = repos.map(r => ({
    name: r.name,
    eco: (r.ecosystem || 'mixed').toLowerCase(),
    total: r.component_count || 0,
    source: 'github.com/' + r.full_name,
    status: r.open_findings > 0 ? 'exposed' : 'clean',
    exposures: r.open_findings,
    version: '-',
    branch: 'main',
    desc: (r.business_processes || []).length
      ? 'Supports: ' + r.business_processes.join(', ')
      : 'No business process mapped',
  }));

  EXPOSURES = exposures.map(e => ({
    id: e.id,
    repo: shortRepo(e.repository),
    full_repo: e.repository,
    cve: e.cve_id || e.advisory_id,
    vuln: (e.explanation && e.explanation.summary) || e.component + ' vulnerability',
    package: e.component,
    version: e.version,
    purl: e.purl || '',
    match: e.match_type,
    cvss: (e.explanation ? e.explanation.contributions.cvss * 2 : 0),
    epss: (e.explanation ? e.explanation.contributions.epss * 33.3 : 0),
    pct: 0,
    published: (e.detected_at || '').slice(0, 10),
    severity: severityFor(e.explanation ? e.explanation.contributions.cvss * 2 : 0),
    score: e.business_score,
    baseline: e.baseline_score,
    tier: e.tier,
    components: 0,
    ecosystem: e.ecosystem,
    source: 'github.com/' + e.repository,
    branch: 'main',
    status: e.state === 'resolved' ? 'RESOLVED' : 'VULNERABLE',
    crit: Math.round((e.explanation ? e.explanation.contributions.criticality : 0) * 5),
    handoff: e.dependabot_alert_url,
  }));

  // The CVE feed is a de-duplicated view of the same findings.
  const byCve = new Map();
  EXPOSURES.forEach(e => {
    if (!byCve.has(e.cve)) {
      byCve.set(e.cve, {
        id: e.cve, title: e.vuln, pkg: e.package + ' ' + e.version,
        cvss: e.cvss, epss: e.epss, pct: e.pct, pub: e.published,
        sev: e.severity, affected: 1, isNew: false,
        desc: e.vuln, fix: 'Handled via the linked Dependabot security update.',
      });
    } else {
      byCve.get(e.cve).affected += 1;
    }
  });
  CVE_FEED = Array.from(byCve.values());

  DATA_TS = new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC';
}

window.addEventListener('DOMContentLoaded', async () => {
  try {
    await loadLiveData();
  } catch (error) {
    console.error('Could not reach the API:', error);
    document.body.insertAdjacentHTML('afterbegin',
      '<div style="background:#b91c1c;color:#fff;padding:10px 16px;font:14px system-ui">' +
      'Cannot reach the analyzer API at ' + API +
      '. Start it with <code>uvicorn sbom_c2.api:app --reload</code>, then reload.' +
      '</div>');
  }
  if (typeof init === 'function') init();
});
"""


def find_const_block(text, name):
    """Locate `const NAME = ...;` including a multi-line literal."""
    start = text.find("const %s = " % name)
    if start < 0:
        return None
    i = text.find("[", start)
    if i < 0:
        return None
    depth, j, in_string, quote, escaped = 0, i, False, "", False
    while j < len(text):
        ch = text[j]
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                in_string = False
        elif ch in "\"'`":
            in_string, quote = True, ch
        elif ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
            if depth == 0:
                end = text.find(";", j)
                return start, (end + 1 if end > 0 else j + 1)
        j += 1
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", help="path to the Capstone 1 dashboard HTML")
    args = parser.parse_args()

    if not os.path.exists(args.source):
        sys.exit("Source dashboard not found: %s" % args.source)

    text = open(args.source, encoding="utf-8", errors="replace").read()

    removed = []
    for name in ("EXPOSURES", "REPOS", "CVE_FEED"):
        span = find_const_block(text, name)
        if span is None:
            print("  warning: could not locate const %s -- left as is" % name)
            continue
        start, end = span
        text = text[:start] + ("/* %s now loaded from the API */" % name) + text[end:]
        removed.append(name)

    # DATA_TS is a simple one-liner; the loader owns it now.
    text = re.sub(r"const DATA_TS = [^;]+;", "/* DATA_TS set by the loader */", text, count=1)

    # The original called init() directly; the loader calls it after fetching.
    text = re.sub(r"^\s*init\(\);\s*$", "", text, flags=re.M)

    anchor = text.rfind("</script>")
    if anchor < 0:
        sys.exit("No </script> found -- is this the right file?")
    text = text[:anchor] + LOADER + "\n" + text[anchor:]

    os.makedirs(OUT_DIR, exist_ok=True)
    with open(OUT_FILE, "w", encoding="utf-8") as handle:
        handle.write(text)

    print("rewired %s -> %s" % (", ".join(removed), OUT_FILE))
    print("Start the API, then open http://127.0.0.1:8000")


if __name__ == "__main__":
    main()
