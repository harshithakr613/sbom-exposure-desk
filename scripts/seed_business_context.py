#!/usr/bin/env python3
"""
Seed the business-context model from data/demo_org.json.

In production an analyst fills these in through the dashboard form, transcribing
them from a Business Requirements Document. For the demonstration they are
seeded from the same file that defines the organisation, so the mapping between
repository and business process is reproducible and reviewable.

    python scripts/seed_business_context.py
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sbom_c2 import config, pipeline                       # noqa: E402
from sbom_c2.db import SessionLocal, init_db               # noqa: E402
from sbom_c2.models import (                               # noqa: E402
    BusinessProcess, ProcessRepositoryLink, Repository)

SPEC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "data", "demo_org.json")

# Manual tiers as a Capstone 1 engineer would plausibly have set them: mostly
# uniform, because that is exactly the failure mode this project addresses.
# Kept deliberately so the baseline ranking is realistic rather than a straw man.
DEFAULT_MANUAL_TIER = "high"


def main():
    init_db()
    session = SessionLocal()
    spec = json.load(open(SPEC))
    org = config.GITHUB_ORG

    created, linked, missing = 0, 0, []

    for item in spec["business_processes"]:
        process = (session.query(BusinessProcess)
                   .filter_by(name=item["name"]).one_or_none())
        if process is None:
            process = BusinessProcess(name=item["name"])
            session.add(process)
            created += 1

        process.description = item.get("description")
        process.owner = item.get("owner")
        process.revenue_dependency = item["revenue_dependency"]
        process.customer_facing = item["customer_facing"]
        process.availability_requirement = item["availability_requirement"]
        process.data_sensitivity = item["data_sensitivity"]
        process.regulatory_scope = item.get("regulatory_scope") or ""
        process.source_document = item.get("source_document")
        process.source_reference = item.get("source_reference")
        session.flush()

        for repo_name in item.get("repositories", []):
            full_name = "%s/%s" % (org, repo_name)
            repository = (session.query(Repository)
                          .filter_by(full_name=full_name).one_or_none())
            if repository is None:
                missing.append(full_name)
                continue
            if repository.manual_criticality_tier in (None, "medium"):
                repository.manual_criticality_tier = DEFAULT_MANUAL_TIER

            exists = (session.query(ProcessRepositoryLink)
                      .filter_by(process_id=process.id,
                                 repository_id=repository.id).one_or_none())
            if exists is None:
                session.add(ProcessRepositoryLink(
                    process_id=process.id, repository_id=repository.id,
                    role="implements"))
                linked += 1

    session.commit()

    rescored = sum(pipeline.score_repository(session, r)
                   for r in session.query(Repository).all())

    print("business processes created: %d" % created)
    print("repository links created:   %d" % linked)
    print("findings rescored:          %d" % rescored)
    if missing:
        print("\nNot found in the database (run POST /api/sync first):")
        for name in missing:
            print("  %s" % name)
    session.close()


if __name__ == "__main__":
    main()
