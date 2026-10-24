"""
ComplianceVault — Data Models & Schemas

Pydantic models for the governance layer. These extend the
tradeguard_core schemas with governance-specific fields like
overrides, RBAC metadata, and audit verification results.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


# ═══════════════════════════════════════════════════════════════
# Enums
# ═══════════════════════════════════════════════════════════════

class RiskLevel(str, Enum):
    GREEN = "GREEN"
    YELLOW = "YELLOW"
    RED = "RED"


class PipelineStatus(str, Enum):
    PROCESSING = "processing"
    AWAITING_REVIEW = "awaiting_review"
    APPROVED = "approved"
    BLOCKED = "blocked"
    OVERRIDDEN = "overridden"


class UserRole(str, Enum):
    OPERATOR = "operator"
    COMPLIANCE_OFFICER = "compliance_officer"
    ADMIN = "admin"


# ═══════════════════════════════════════════════════════════════
# User & Auth Models
# ═══════════════════════════════════════════════════════════════

class User(BaseModel):
    """Represents a system user with RBAC role."""
    username: str
    name: str
    role: UserRole
    permissions: list[str] = []


class LoginRequest(BaseModel):
    """Login request payload."""
    username: str
    password: str


# ═══════════════════════════════════════════════════════════════
# Document & Compliance Models
# ═══════════════════════════════════════════════════════════════

class DocumentSummary(BaseModel):
    """Summary view of a processed document for the dashboard list."""
    document_id: str
    pipeline_status: str
    overall_risk: str = ""
    shipper_name: str = ""
    consignee_name: str = ""
    cargo_description: str = ""
    port_of_loading: str = ""
    port_of_discharge: str = ""
    sanctions_risk: str = ""
    hs_code: str = ""
    hs_confidence: float = 0.0
    human_review_required: bool = False
    risk_factors: list[str] = []
    started_at: str = ""
    completed_at: Optional[str] = None
    submitted_by: str = ""


class AuditEntry(BaseModel):
    """A single entry in the hash-chained audit log."""
    timestamp: str
    node: str
    action: str
    input: dict | str = {}
    output: dict | str = {}
    confidence: Optional[float] = None
    risk_level: Optional[str] = None
    metadata: Optional[dict] = None
    hash: str = ""


class OverrideRequest(BaseModel):
    """
    Request for a Compliance Officer Override.

    Per EU AI Act Article 14, human oversight must allow authorized
    persons to override AI decisions. The justification is mandatory
    and becomes part of the immutable audit trail.
    """
    new_decision: str = Field(
        ...,
        description="The overridden decision: 'approve' or 'reject'",
        pattern="^(approve|reject)$",
    )
    justification: str = Field(
        ...,
        min_length=20,
        description=(
            "Written justification for the override. Must be at least "
            "20 characters. This is immutably logged for regulatory compliance."
        ),
        examples=[
            "After manual review of shipping records and direct contact with "
            "the exporter, confirmed this is a legitimate textile shipment. "
            "Name similarity to sanctioned entity is coincidental — different "
            "registration number and jurisdiction."
        ],
    )
    officer_name: str = Field(
        ...,
        description="Name of the compliance officer performing the override",
    )


class AuditVerificationResult(BaseModel):
    """Result of verifying the integrity of an audit chain."""
    document_id: str
    is_valid: bool
    message: str
    entries_verified: int
    verified_at: str
    verified_by: str


class ExportReportRequest(BaseModel):
    """Request to export a compliance report as PDF."""
    document_id: str
    include_audit_trail: bool = True
    include_sanctions_detail: bool = True
    include_hs_detail: bool = True


class DashboardStats(BaseModel):
    """Aggregate statistics for the dashboard overview."""
    total_documents: int = 0
    approved_count: int = 0
    blocked_count: int = 0
    awaiting_review_count: int = 0
    processing_count: int = 0
    overridden_count: int = 0
    green_count: int = 0
    yellow_count: int = 0
    red_count: int = 0
    avg_processing_time_ms: float = 0.0
    audit_chains_verified: int = 0
    audit_chains_broken: int = 0
