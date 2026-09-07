# SBOM-Based Business-Context-Aware Vulnerability Prioritization

Capstone 1 + Capstone 2, MSc Cybersecurity, REVA University
Harshitha KR · R22MSC56

---

## What this actually is

A **locally-run web application**. Not a hosted website, not an installer.

- A **Python service** (FastAPI) that talks to GitHub, OSV and EPSS, stores results in a **SQLite file**, and exposes a JSON API.
- A **browser dashboard** served by that same service at `http://127.0.0.1:8000`.
- A **demonstration GitHub organisation** holding the repositories being analysed.

For the viva you run one command on your laptop, open a browser, and everything is live: real repositories, real CVEs, real Dependabot alerts. Clicking a finding's handoff button jumps to the actual alert on github.com.

**Do not deploy this to a public server.** There is no authentication, it holds a GitHub token, and hosting it would cost you a day you do not have. Localhost is the correct answer and no examiner will object.

### Which parts are Capstone 1 vs Capstone 2

| Layer | Capstone |
|---|---|
| SBOM ingestion, OSV/EPSS feeds, dual-mode correlation, composite scoring, dashboard | 1 |
| Business context model, BIA engine, Dependabot orchestration, impact measurement, NDCG evaluation | 2 |

One codebase. Capstone 2 modules import Capstone 1 modules and extend them — which is why building this once satisfies both.

---

## Setup

### 1. Create the GitHub organisation

On github.com: profile menu → **Your organizations** → **New organization** → **Free** plan.
Name it something like `sbom-analyzer-demo`.

Then **Settings → Code security** and enable, at organisation level:
- Dependency graph
- Dependabot alerts
- Dependabot security updates

All three are free on every plan, public and private repositories.

### 2. Create a token

**Settings → Developer settings → Personal access tokens → Fine-grained tokens.**
Scope it to your new organisation only.

| Permission | Access | Needed for |
|---|---|---|
| Administration | Read and write | setup script only |
| Contents | Read and write | setup script only |
| Dependabot alerts | Read | remediation correlation |
| Metadata | Read | everything |

After setup you can regenerate a read-only token. The analyzer never writes.

### 3. Install

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env               # then edit it
set -a; source .env; set +a        # Windows: set the variables manually
```

### 4. Build the demonstration organisation

```bash
python scripts/setup_demo_org.py --mode create
```

Creates eight repositories with manifests pinned to real vulnerable versions, and enables Dependabot on each. **Do this first and leave it alone for at least half an hour** — Dependabot's scan latency is the one thing you cannot rush.

```bash
python scripts/setup_demo_org.py --check      # how many alerts have appeared
```

### 5. Exposure Desk — the application

`dashboard/index.html`, served by the API at `http://127.0.0.1:8000`. Nothing to
build; it reads live from the endpoints.

Six screens. **Overview** opens with how many findings threaten a
business-critical service, the narrowing from components to today's work, the
priority distribution, and the biggest movers. **Findings** is the ranked queue,
with an arrow on each row showing how far business context shifted it against
ranking by technical severity alone. Clicking any row opens the full record:
score composition, business context, the affected dependency, and a history
showing detection through to resolution. **Repositories** links out to GitHub
and to each repository's Dependabot alerts. **Business context** is the form
that captures process attributes and rescores on save. **CVE lookup**
answers the founding question directly: give it an advisory identifier and it
reports which repositories are exposed, fetching the advisory live where it
post-dates the last scan. **Risk reduction** reports MTTR and business risk
eliminated, and lists which business processes still carry open findings.

Every figure that is derived rather than read carries an explain marker stating
how it was computed, because a score a reader cannot interrogate is a score they
have to take on trust. Summary tiles are clickable and filter the queue.
Business processes can be edited when a BRD changes, and the affected findings
rescore on save. Repositories can be added individually by name, including from
outside the configured organisation. Long-running actions report progress,
elapsed time, and any repositories that were skipped.

Earlier interfaces are kept for reference: `dashboard/aperture-light.html`
(a light theme with a ranking-comparison view and a weighting simulator),
`dashboard/console-simple.html`, and
`dashboard/legacy-capstone1-dashboard.html` (the Capstone 1 prototype).

---

## Run order

```bash
uvicorn sbom_c2.api:app --reload
```

Then, in a second terminal:

```bash
curl -X POST localhost:8000/api/sync                    # ingest, correlate, score
python scripts/seed_business_context.py                 # business context + rescore
curl -X POST localhost:8000/api/remediation/correlate   # link Dependabot alerts
curl localhost:8000/api/impact
curl localhost:8000/api/triage-funnel     # components -> findings -> today's work
curl "localhost:8000/api/exposures?dedupe=true"   # collapse duplicate advisories
curl localhost:8000/api/quick-wins        # high value, cheap to fix
curl localhost:8000/api/blast-radius      # one advisory, many processes
curl -OJ localhost:8000/api/export/csv    # download the ranked queue
curl -OJ localhost:8000/api/report        # PDF audit report
curl localhost:8000/api/sbom/quality      # SBOM quality gate per repository
curl "localhost:8000/api/graph/exposure?name=lodash&ecosystem=npm"
curl localhost:8000/api/graph/shared      # components across several repos
```

### Optional: the other two ingestion sources

```bash
# A CI/CD workflow or an analyst posts an SBOM directly.
# CycloneDX 1.4+ and SPDX 2.3 both accepted; format detected from the document.
curl -X POST "localhost:8000/api/sbom/upload?repository=org/my-service" \
     -H 'Content-Type: application/json' --data @sbom.cdx.json
```

### Optional: PostgreSQL instead of SQLite

```bash
docker compose up -d
export DATABASE_URL=postgresql+psycopg://sbom:sbom@localhost:5432/sbom_c2
pip install "psycopg[binary]"
uvicorn sbom_c2.api:app --reload
```

No application code changes: the SQLAlchemy models are identical either way.

### Optional: background CVE ingestion worker

```bash
export ENABLE_SCHEDULER=1     # polls alert state hourly
curl localhost:8000/api/scheduler
```

Open **http://127.0.0.1:8000**.

### The evaluation, in the right order

This sequence matters. Generating the worksheet **before** looking at business scores is what keeps the evaluation from being circular — and it is the thing an examiner will probe.

```bash
python scripts/evaluate_ranking.py --worksheet
# grade the relevance column 0-3 in ground_truth_worksheet.csv
python scripts/evaluate_ranking.py --import ground_truth_worksheet.csv
python scripts/evaluate_ranking.py --run
```

The worksheet contains the union of the top twenty from each ranking, shuffled,
with both scores omitted. Pooling keeps the comparison fair without requiring
every finding to be graded; hiding the scores keeps the grading independent of
the model; shuffling stops the row order anchoring the grader.

`--run` reports NDCG and precision at k for both rankings, and a sensitivity
analysis varying the criticality weight from 0.05 to 0.40. If the business-aware
ranking only wins at one weighting, the result is an artefact of that choice and
the analysis will say so.

---

## Tests

```bash
python -m unittest discover -s tests -v
```

46 tests covering the BIA scoring engine, PURL parsing, version-range evaluation, correlation, NDCG and MTTR. No network or database required — these are the parts where bugs actually live.

---

## Demo script for the viva

1. **Dashboard, repository view.** Eight repositories, live from a real GitHub org.
2. **Prioritised queue.** `payments-api` at the top, `internal-logging-utils` near the bottom — *despite comparable CVSS*.
3. **Open one finding's explanation.** Show the factor contributions and the driving business process. This is Objective 2 made visible.
4. **The money comparison.** Same CVE: payments **8.41 CRITICAL** vs logging **5.24 MEDIUM**. Capstone 1 scored both **6.51**. One slide, whole thesis.
5. **Click the handoff.** Jump to the real Dependabot alert on github.com. Merge the PR live if you are feeling confident.
6. **Refresh state.** `POST /api/remediation/refresh` — the finding moves to resolved with a real timestamp.
7. **Impact view.** MTTR and business risk eliminated, computed from that actual event.
8. **Evaluation.** NDCG for business-aware vs technical-only, against the independent ground truth.

Steps 5–7 are the strongest ninety seconds you have. Merge at least one PR earlier in the week so the loop is proven before you are standing in front of anyone.

---

## Known limitations — state these before you are asked

- **Dependency chains depend on the SBOM.** Chains are reconstructed from SPDX
  `relationships` where the source provides them, and `/api/graph/chain/{id}`
  returns null with an explanatory note where it does not. GitHub's
  dependency-graph export populates relationships inconsistently, so transitive
  components are always *detected* but the path is not always *renderable*.
  Uploaded CycloneDX and SPDX documents from Syft usually carry richer
  relationship data.
- **Exact matches take precedence over fuzzy ones.** A single advisory often
  names several packages with similar names and different fix states. Fuzzy
  matching is consulted only when no exactly-named package appears in that
  advisory, otherwise a patched package can match a sibling's unfixed range.
- **Constraints are not versions.** Where a manifest declares `^1.15.1` or
  `>= 8.0.0`, the installed version is unknown, so range evaluation is skipped
  and the finding is marked `NO_VERSION` rather than evaluated against a guess.
- **CPE matching is name-similarity based.** Vendor and product are compared,
  version is left to the correlator's range evaluation. It is a recall
  mechanism for components lacking a PURL, not a replacement for exact matching,
  and every such finding is marked `CPE_FUZZY` with its confidence score.
- **The scheduler is in-process.** Suitable for a single node; a multi-node
  deployment would use Celery with a broker. Stated rather than implied.
- **CVSS from vectors.** OSV usually carries a CVSS vector rather than a number. `feeds.extract_cvss` approximates a base score from the vector's core metrics. Fine for ordering; do not present it as an authoritative CVSS calculation.
- **Business risk is an index, not a currency.** Summing business-aware scores is monotonic in what matters. It is not money.
- **Small MTTR sample.** On a demo organisation this will be a handful of findings. The API reports the sample size deliberately — quote it.
- **Fix effort needs a correlated alert.** The patched version comes from the
  Dependabot alert payload, so `/api/quick-wins` is empty until
  `/api/remediation/correlate` has run.
- **BRD parsing is out of scope.** Attributes are transcribed into structured forms. Stated as future work in the proposal.

---

## Layout

```
sbom_c2/
  bia.py            Business Impact Analysis engine        Objectives 1-2
  matching.py       PURL parsing, version ranges, correlation   Capstone 1
  evaluate.py       NDCG, precision@k                      Phase 6
  impact.py         MTTR, fix rate, risk eliminated        Objective 4
  cvss.py           CVSS v3.1 base score arithmetic        C1 Objective 3
  quality.py        SBOM quality gate                      C1 Objective 1
  cpe.py            CPE 2.3 parsing, fuzzy matching        C1 Objective 2
  depgraph.py       reverse + chain graphs (NetworkX)      C1 Objective 2
  sbom_formats.py   CycloneDX / SPDX parsing               C1 Objective 1
  reports.py        PDF audit report                       C1 Phase 5
  scheduler.py      background ingestion worker            C1 Phase 2
  models.py         Relational schema
  github_client.py  SBOM + Dependabot alerts
  feeds.py          OSV + EPSS
  pipeline.py       Ingest -> correlate -> score
  remediation.py    Alert correlation, handoff, resolution Objective 3
  api.py            FastAPI application
scripts/
  setup_demo_org.py        Build the demonstration organisation
  seed_business_context.py Seed processes and repository links
  make_ground_truth.py     Annotation worksheet and import
  build_dashboard.py       Rewire the Capstone 1 dashboard
data/demo_org.json         Repositories, pins, business processes
tests/                     88 unit tests
```

`bia.py`, `matching.py` and `evaluate.py` have no third-party imports. That is deliberate: the parts carrying the intellectual argument are the parts you can test, read and defend without any infrastructure running.
