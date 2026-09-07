"""
Relational schema.

Capstone 1 tables:  Repository, Component, Vulnerability, Exposure
Capstone 2 tables:  BusinessProcess, ProcessRepositoryLink, RemediationEvent,
                    ImpactSnapshot
"""

import datetime as dt

from sqlalchemy import (
    Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text,
    UniqueConstraint,
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


def _now():
    return dt.datetime.now(dt.timezone.utc)


# --------------------------------------------------------------------------
# Capstone 1 core
# --------------------------------------------------------------------------

class Repository(Base):
    __tablename__ = "repositories"

    id = Column(Integer, primary_key=True)
    full_name = Column(String(255), unique=True, nullable=False)  # org/repo
    name = Column(String(255), nullable=False)
    default_branch = Column(String(120), default="main")
    ecosystem = Column(String(60))
    # Retained so Phase 6 can compute the Capstone 1 baseline ranking.
    manual_criticality_tier = Column(String(20), default="medium")
    last_ingested_at = Column(DateTime)

    # SBOM quality gate (Capstone 1, Objective 1)
    sbom_source = Column(String(120))
    sbom_quality_score = Column(Float)
    sbom_quality_passed = Column(Boolean)
    sbom_quality_issues = Column(Text)
    has_dependency_chains = Column(Boolean, default=False)

    components = relationship("Component", back_populates="repository",
                              cascade="all, delete-orphan")
    exposures = relationship("Exposure", back_populates="repository",
                             cascade="all, delete-orphan")
    process_links = relationship("ProcessRepositoryLink",
                                 back_populates="repository",
                                 cascade="all, delete-orphan")


class Component(Base):
    __tablename__ = "components"
    __table_args__ = (UniqueConstraint("repository_id", "name", "version",
                                       name="uq_component"),)

    id = Column(Integer, primary_key=True)
    repository_id = Column(Integer, ForeignKey("repositories.id"), nullable=False)
    name = Column(String(255), nullable=False)
    version = Column(String(120))
    ecosystem = Column(String(60))
    purl = Column(String(500))
    cpe = Column(String(500))
    direct = Column(Boolean, default=False)
    depth = Column(Integer)
    dependency_path = Column(Text)

    repository = relationship("Repository", back_populates="components")


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True)
    advisory_id = Column(String(80), unique=True, nullable=False)  # GHSA-... / OSV
    cve_id = Column(String(40), index=True)
    summary = Column(Text)
    cvss_score = Column(Float)
    cvss_vector = Column(String(200))
    epss_score = Column(Float)
    epss_percentile = Column(Float)
    published_at = Column(DateTime)
    fetched_at = Column(DateTime, default=_now)


class Exposure(Base):
    """One (repository, component, vulnerability) finding."""

    __tablename__ = "exposures"
    __table_args__ = (UniqueConstraint("repository_id", "component_name",
                                       "component_version", "advisory_id",
                                       name="uq_exposure"),)

    id = Column(Integer, primary_key=True)
    repository_id = Column(Integer, ForeignKey("repositories.id"), nullable=False)
    advisory_id = Column(String(80), nullable=False)
    cve_id = Column(String(40), index=True)
    component_name = Column(String(255), nullable=False)
    component_version = Column(String(120))
    ecosystem = Column(String(60))
    purl = Column(String(500))
    direct = Column(Boolean, default=False)
    dependency_path = Column(Text)
    match_type = Column(String(30))          # PURL_EXACT / VERSION_LIST / FUZZY_NAME / CPE_FUZZY
    match_confidence = Column(Float)

    # Scoring
    baseline_score = Column(Float)           # Capstone 1, manual tier
    business_score = Column(Float)           # Capstone 2, derived criticality
    tier = Column(String(20))
    derived_criticality = Column(Float)
    compliance_factor = Column(Float)
    score_explanation = Column(Text)         # JSON: per-factor contributions

    # Remediation lifecycle
    state = Column(String(20), default="open", index=True)   # open / resolved
    dependabot_alert_number = Column(Integer)
    dependabot_alert_url = Column(String(500))
    first_patched_version = Column(String(120))
    alert_match_method = Column(String(20))   # identifier / package
    fix_effort_band = Column(String(20))
    quick_win_score = Column(Float)
    detected_at = Column(DateTime, default=_now)
    resolved_at = Column(DateTime)

    repository = relationship("Repository", back_populates="exposures")


# --------------------------------------------------------------------------
# Capstone 2 additions
# --------------------------------------------------------------------------

class BusinessProcess(Base):
    """A business process described in a BRD (Objective 1)."""

    __tablename__ = "business_processes"

    id = Column(Integer, primary_key=True)
    name = Column(String(255), unique=True, nullable=False)
    description = Column(Text)
    owner = Column(String(255))

    revenue_dependency = Column(String(20), default="none")        # none/indirect/direct
    customer_facing = Column(Boolean, default=False)
    availability_requirement = Column(String(20), default="low")   # low..critical
    data_sensitivity = Column(String(20), default="public")        # public..regulated
    regulatory_scope = Column(String(255))                         # "PCI-DSS,GDPR"

    # Provenance, so every derived score is traceable to its source document.
    source_document = Column(String(255))
    source_reference = Column(String(255))
    created_at = Column(DateTime, default=_now)

    repository_links = relationship("ProcessRepositoryLink",
                                    back_populates="process",
                                    cascade="all, delete-orphan")

    def regimes(self):
        return [r.strip() for r in (self.regulatory_scope or "").split(",") if r.strip()]

    def as_attributes(self):
        """Shape the BIA engine expects."""
        return {
            "name": self.name,
            "revenue_dependency": self.revenue_dependency,
            "customer_facing": self.customer_facing,
            "availability_requirement": self.availability_requirement,
            "data_sensitivity": self.data_sensitivity,
        }


class ProcessRepositoryLink(Base):
    __tablename__ = "process_repository_links"
    __table_args__ = (UniqueConstraint("process_id", "repository_id",
                                       name="uq_process_repo"),)

    id = Column(Integer, primary_key=True)
    process_id = Column(Integer, ForeignKey("business_processes.id"), nullable=False)
    repository_id = Column(Integer, ForeignKey("repositories.id"), nullable=False)
    role = Column(String(120))   # e.g. "implements", "supports"

    process = relationship("BusinessProcess", back_populates="repository_links")
    repository = relationship("Repository", back_populates="process_links")


class RemediationEvent(Base):
    """State transitions observed on a finding (Objective 3)."""

    __tablename__ = "remediation_events"

    id = Column(Integer, primary_key=True)
    exposure_id = Column(Integer, ForeignKey("exposures.id"), nullable=False)
    event_type = Column(String(40))     # detected / handoff_opened / resolved / reopened
    from_state = Column(String(20))
    to_state = Column(String(20))
    detail = Column(Text)
    occurred_at = Column(DateTime, default=_now)


class GroundTruthGrade(Base):
    """
    A human judgement of how urgently a finding deserves remediation.

    Stored separately from the exposure so that grading survives a rescan: the
    evaluation is a record of what a person decided, and losing it because the
    inventory refreshed would make the result unreproducible. Graded on business
    consequence alone, before any business-aware score is seen.
    """

    __tablename__ = "ground_truth_grades"
    __table_args__ = (UniqueConstraint("repository_full_name", "component_name",
                                       "component_version", "advisory",
                                       name="uq_grade"),)

    id = Column(Integer, primary_key=True)
    exposure_id = Column(Integer)
    repository_full_name = Column(String(255))
    component_name = Column(String(255))
    component_version = Column(String(120))
    advisory = Column(String(80))
    relevance = Column(Integer, nullable=False)     # 0-3
    graded_by = Column(String(120))
    graded_at = Column(DateTime, default=_now)
    rationale = Column(Text)


class ImpactSnapshot(Base):
    """Persisted metrics so the dashboard can plot a trend (Objective 4)."""

    __tablename__ = "impact_snapshots"

    id = Column(Integer, primary_key=True)
    captured_at = Column(DateTime, default=_now)
    open_count = Column(Integer)
    resolved_count = Column(Integer)
    fix_rate = Column(Float)
    mttr_hours = Column(Float)
    business_risk_open = Column(Float)
    business_risk_eliminated = Column(Float)
    processes_protected = Column(Integer)
    compliance_exposure_open = Column(Integer)
