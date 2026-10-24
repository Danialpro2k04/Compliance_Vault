"""
ComplianceVault — Document Store

In-memory store for tracking documents processed through the
TradeGuard pipeline. In production, this would be a database.

This store provides:
  - Document state caching (synced from tradeguard_core)
  - Override tracking with immutable logging
  - Filtering and search across all documents
  - Statistics aggregation for the dashboard
"""

import hashlib
import json
from datetime import datetime, timezone
from typing import Optional

from app.audit_store import append_governance_event, verify_document_audit_chain
from app.schemas import DashboardStats


# ═══════════════════════════════════════════════════════════════
# In-memory Document Store
# Maps: document_id → full document state dict
# ═══════════════════════════════════════════════════════════════

_documents: dict[str, dict] = {}


def store_document(document_id: str, state: dict, submitted_by: str = "") -> dict:
    """
    Store or update a document's state in the vault.

    Args:
        document_id: The TG-YYYY-MM-XXXX document ID
        state: Full state dict from the tradeguard_core pipeline
        submitted_by: Username of who submitted this document
    """
    existing = _documents.get(document_id, {})

    doc = {
        **state,
        "document_id": document_id,
        "submitted_by": submitted_by or existing.get("submitted_by", "system"),
        "stored_at": datetime.now(timezone.utc).isoformat(),
        "overrides": existing.get("overrides", []),
    }

    _documents[document_id] = doc
    return doc


def get_document(document_id: str) -> Optional[dict]:
    """Retrieve a document by ID."""
    return _documents.get(document_id)


def get_all_documents(
    status_filter: Optional[str] = None,
    risk_filter: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    submitted_by: Optional[str] = None,
) -> list[dict]:
    """
    Get all documents with optional filtering.

    Filters:
        status_filter: Filter by pipeline_status (approved, blocked, awaiting_review, etc.)
        risk_filter: Filter by overall_risk (GREEN, YELLOW, RED)
        date_from: ISO date string — only docs started on or after this date
        date_to: ISO date string — only docs started on or before this date
        submitted_by: Filter by submitting user
    """
    docs = list(_documents.values())

    if status_filter:
        docs = [d for d in docs if d.get("pipeline_status") == status_filter]

    if risk_filter:
        docs = [d for d in docs if d.get("overall_risk") == risk_filter]

    if submitted_by:
        docs = [d for d in docs if d.get("submitted_by") == submitted_by]

    if date_from:
        docs = [
            d for d in docs
            if d.get("started_at", "") >= date_from
        ]

    if date_to:
        docs = [
            d for d in docs
            if d.get("started_at", "") <= date_to + "T23:59:59"
        ]

    # Sort by started_at descending (newest first)
    docs.sort(key=lambda d: d.get("started_at", ""), reverse=True)

    return docs


def record_override(
    document_id: str,
    new_decision: str,
    justification: str,
    officer_name: str,
    officer_username: str,
    officer_role: str,
) -> dict:
    """
    Record a Compliance Officer Override.

    This is the most sensitive operation in the system. It allows
    an authorized person to override any AI decision. Per EU AI Act
    Article 14, this must be:
      1. Performed by an authorized person
      2. With mandatory written justification
      3. Immutably logged in the audit trail

    The override is:
      - Hash-chained into the document's audit log
      - Recorded in the governance audit log
      - Visible in the dashboard with full details

    Returns:
        The override record dict
    """
    doc = _documents.get(document_id)
    if not doc:
        raise ValueError(f"Document {document_id} not found")

    # Get the current state for the override record
    previous_status = doc.get("pipeline_status", "unknown")
    previous_risk = doc.get("overall_risk", "")

    # Build the override record
    override = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "officer_name": officer_name,
        "officer_username": officer_username,
        "officer_role": officer_role,
        "previous_status": previous_status,
        "previous_risk": previous_risk,
        "new_decision": new_decision,
        "justification": justification,
    }

    # Hash-chain the override into the document's audit log
    audit_log = doc.get("audit_log", [])
    prev_hash = audit_log[-1].get("hash", "") if audit_log else ""

    override_audit = {
        "timestamp": override["timestamp"],
        "node": "compliance_officer_override",
        "action": (
            f"OVERRIDE by {officer_name} ({officer_role}): "
            f"{previous_status} → {new_decision}"
        ),
        "input": {
            "previous_status": previous_status,
            "previous_risk": previous_risk,
        },
        "output": {
            "new_decision": new_decision,
            "justification": justification,
        },
    }

    entry_json = json.dumps(override_audit, sort_keys=True, default=str)
    chain_input = prev_hash + entry_json
    override_audit["hash"] = hashlib.sha256(chain_input.encode()).hexdigest()

    # Update the document
    new_status = "approved" if new_decision == "approve" else "blocked"
    doc["pipeline_status"] = new_status
    doc["human_decision"] = new_decision
    doc["human_justification"] = justification
    doc["reviewed_by"] = officer_name
    doc["overrides"] = doc.get("overrides", []) + [override]
    doc["audit_log"] = audit_log + [override_audit]
    doc["override_count"] = len(doc["overrides"])

    _documents[document_id] = doc

    # Log in the governance audit trail
    append_governance_event(
        event_type="override",
        actor=officer_username,
        actor_role=officer_role,
        action=(
            f"Override on {document_id}: {previous_status} → {new_decision} "
            f"(officer: {officer_name})"
        ),
        document_id=document_id,
        details={
            "previous_status": previous_status,
            "new_decision": new_decision,
            "justification": justification,
        },
    )

    return override


def get_dashboard_stats() -> DashboardStats:
    """Compute aggregate statistics for the dashboard overview."""
    docs = list(_documents.values())

    if not docs:
        return DashboardStats()

    stats = DashboardStats(
        total_documents=len(docs),
        approved_count=sum(1 for d in docs if d.get("pipeline_status") == "approved"),
        blocked_count=sum(1 for d in docs if d.get("pipeline_status") == "blocked"),
        awaiting_review_count=sum(
            1 for d in docs if d.get("pipeline_status") == "awaiting_review"
        ),
        processing_count=sum(
            1 for d in docs if d.get("pipeline_status") == "processing"
        ),
        overridden_count=sum(1 for d in docs if d.get("overrides")),
        green_count=sum(1 for d in docs if d.get("overall_risk") == "GREEN"),
        yellow_count=sum(1 for d in docs if d.get("overall_risk") == "YELLOW"),
        red_count=sum(1 for d in docs if d.get("overall_risk") == "RED"),
    )

    # Average processing time
    times = []
    for d in docs:
        report = d.get("compliance_report", {})
        if isinstance(report, dict):
            timing = report.get("timing", {})
            if timing.get("processing_time_ms"):
                times.append(timing["processing_time_ms"])
    if times:
        stats.avg_processing_time_ms = round(sum(times) / len(times), 2)

    # Audit chain verification stats
    for d in docs:
        audit_log = d.get("audit_log", [])
        if audit_log:
            is_valid, _ = verify_document_audit_chain(audit_log)
            if is_valid:
                stats.audit_chains_verified += 1
            else:
                stats.audit_chains_broken += 1

    return stats


def seed_sample_documents():
    """
    Seed the store with sample documents for demonstration.
    These represent documents that have already been processed
    through the tradeguard_core pipeline.
    """
    sample_docs = [
        {
            "document_id": "TG-2026-10-A1B2",
            "pipeline_status": "approved",
            "overall_risk": "GREEN",
            "shipper_name": "Pakistan Cotton Exports Ltd",
            "consignee_name": "Rotterdam Textiles BV",
            "cargo_description": "500 cartons of mens cotton polo shirts, 100% cotton, knitted, sizes M-XXL",
            "port_of_loading": "Karachi",
            "port_of_discharge": "Rotterdam",
            "sanctions_risk": "GREEN",
            "hs_code": "610510",
            "hs_confidence": 0.92,
            "human_review_required": False,
            "human_decision": "approve",
            "human_justification": "Automatic clearance — all checks GREEN",
            "reviewed_by": "SYSTEM (auto-approve)",
            "risk_factors": [],
            "document_discrepancies": [],
            "started_at": "2026-10-20T08:00:00+00:00",
            "completed_at": "2026-10-20T08:00:03+00:00",
            "submitted_by": "ali",
            "shipper_screening": {
                "risk_level": "GREEN",
                "matches": [],
                "query_name": "Pakistan Cotton Exports Ltd",
            },
            "consignee_screening": {
                "risk_level": "GREEN",
                "matches": [],
                "query_name": "Rotterdam Textiles BV",
            },
            "hs_classification": {
                "result": {
                    "primary_code": "610510",
                    "primary_description": "Men's or boys' shirts of cotton, knitted",
                    "confidence": 0.92,
                    "is_ambiguous": False,
                    "reasoning": {
                        "chapter": "61 — Knitted or crocheted apparel",
                        "heading": "6105 — Men's shirts, knitted",
                        "subheading": "610510 — Of cotton",
                    },
                }
            },
            "compliance_report": {
                "document_id": "TG-2026-10-A1B2",
                "pipeline_status": "approved",
                "overall_risk": "GREEN",
                "timing": {
                    "started_at": "2026-10-20T08:00:00+00:00",
                    "completed_at": "2026-10-20T08:00:03+00:00",
                    "processing_time_ms": 3200,
                },
            },
            "audit_log": _build_sample_audit_chain("TG-2026-10-A1B2", "GREEN"),
        },
        {
            "document_id": "TG-2026-10-C3D4",
            "pipeline_status": "awaiting_review",
            "overall_risk": "YELLOW",
            "shipper_name": "Gulf Maritime Trading LLC",
            "consignee_name": "Hamburg Port Services GmbH",
            "cargo_description": "200 units industrial water pumps, stainless steel, centrifugal type",
            "port_of_loading": "Dubai",
            "port_of_discharge": "Hamburg",
            "sanctions_risk": "YELLOW",
            "hs_code": "841370",
            "hs_confidence": 0.78,
            "human_review_required": True,
            "human_decision": "",
            "human_justification": "",
            "reviewed_by": "",
            "risk_factors": [
                "Sanctions: Shipper 'Gulf Maritime Trading LLC' flagged for possible match (YELLOW)",
                "HS classification ambiguous: code 841370 with 78% confidence",
            ],
            "document_discrepancies": [],
            "started_at": "2026-10-21T10:30:00+00:00",
            "completed_at": None,
            "submitted_by": "ali",
            "shipper_screening": {
                "risk_level": "YELLOW",
                "matches": [
                    {
                        "matched_name": "Gulf Maritime Services FZE",
                        "combined_score": 0.72,
                        "source": "OFAC SDN",
                    }
                ],
                "query_name": "Gulf Maritime Trading LLC",
            },
            "consignee_screening": {
                "risk_level": "GREEN",
                "matches": [],
                "query_name": "Hamburg Port Services GmbH",
            },
            "hs_classification": {
                "result": {
                    "primary_code": "841370",
                    "primary_description": "Centrifugal pumps, other",
                    "confidence": 0.78,
                    "is_ambiguous": True,
                    "reasoning": {
                        "chapter": "84 — Machinery and mechanical appliances",
                        "heading": "8413 — Pumps for liquids",
                        "subheading": "841370 — Other centrifugal pumps",
                    },
                    "alternative_codes": [
                        {"code": "841350", "description": "Reciprocating pumps", "confidence": 0.15},
                    ],
                }
            },
            "compliance_report": {},
            "audit_log": _build_sample_audit_chain("TG-2026-10-C3D4", "YELLOW"),
        },
        {
            "document_id": "TG-2026-10-E5F6",
            "pipeline_status": "blocked",
            "overall_risk": "RED",
            "shipper_name": "Rosoboronexport JSC",
            "consignee_name": "Damascus Steel Works",
            "cargo_description": "50 units precision machine tools, CNC lathe, 5-axis",
            "port_of_loading": "Saint Petersburg",
            "port_of_discharge": "Latakia",
            "sanctions_risk": "RED",
            "hs_code": "",
            "hs_confidence": 0.0,
            "human_review_required": True,
            "human_decision": "",
            "human_justification": "",
            "reviewed_by": "",
            "risk_factors": [
                "SANCTIONS HIT: Shipper 'Rosoboronexport JSC' matched sanctioned entity "
                "'Rosoboronexport' (score: 0.98)",
                "SANCTIONS HIT: Consignee 'Damascus Steel Works' matched sanctioned entity "
                "'Damascus Steel Industries' (score: 0.91)",
            ],
            "document_discrepancies": [],
            "started_at": "2026-10-22T14:15:00+00:00",
            "completed_at": "2026-10-22T14:15:02+00:00",
            "submitted_by": "sarah",
            "shipper_screening": {
                "risk_level": "RED",
                "matches": [
                    {
                        "matched_name": "Rosoboronexport",
                        "combined_score": 0.98,
                        "source": "OFAC SDN",
                    }
                ],
                "query_name": "Rosoboronexport JSC",
            },
            "consignee_screening": {
                "risk_level": "RED",
                "matches": [
                    {
                        "matched_name": "Damascus Steel Industries",
                        "combined_score": 0.91,
                        "source": "EU Consolidated",
                    }
                ],
                "query_name": "Damascus Steel Works",
            },
            "hs_classification": {
                "skipped": True,
                "reason": "sanctions_risk == RED",
            },
            "compliance_report": {
                "document_id": "TG-2026-10-E5F6",
                "pipeline_status": "blocked",
                "overall_risk": "RED",
                "timing": {
                    "started_at": "2026-10-22T14:15:00+00:00",
                    "completed_at": "2026-10-22T14:15:02+00:00",
                    "processing_time_ms": 1850,
                },
            },
            "audit_log": _build_sample_audit_chain("TG-2026-10-E5F6", "RED"),
        },
        {
            "document_id": "TG-2026-10-G7H8",
            "pipeline_status": "approved",
            "overall_risk": "GREEN",
            "shipper_name": "Lahore Surgical Instruments Co.",
            "consignee_name": "MedTech Supplies UK Ltd",
            "cargo_description": "2000 pcs stainless steel surgical scissors, forged, assorted sizes",
            "port_of_loading": "Karachi",
            "port_of_discharge": "Felixstowe",
            "sanctions_risk": "GREEN",
            "hs_code": "901890",
            "hs_confidence": 0.88,
            "human_review_required": False,
            "human_decision": "approve",
            "human_justification": "Automatic clearance — all checks GREEN",
            "reviewed_by": "SYSTEM (auto-approve)",
            "risk_factors": [],
            "document_discrepancies": [],
            "started_at": "2026-10-23T09:00:00+00:00",
            "completed_at": "2026-10-23T09:00:04+00:00",
            "submitted_by": "ali",
            "shipper_screening": {
                "risk_level": "GREEN",
                "matches": [],
                "query_name": "Lahore Surgical Instruments Co.",
            },
            "consignee_screening": {
                "risk_level": "GREEN",
                "matches": [],
                "query_name": "MedTech Supplies UK Ltd",
            },
            "hs_classification": {
                "result": {
                    "primary_code": "901890",
                    "primary_description": "Instruments and appliances used in medical sciences",
                    "confidence": 0.88,
                    "is_ambiguous": False,
                    "reasoning": {
                        "chapter": "90 — Optical, medical instruments",
                        "heading": "9018 — Medical/surgical instruments",
                        "subheading": "901890 — Other instruments",
                    },
                }
            },
            "compliance_report": {
                "document_id": "TG-2026-10-G7H8",
                "pipeline_status": "approved",
                "overall_risk": "GREEN",
                "timing": {
                    "started_at": "2026-10-23T09:00:00+00:00",
                    "completed_at": "2026-10-23T09:00:04+00:00",
                    "processing_time_ms": 4100,
                },
            },
            "audit_log": _build_sample_audit_chain("TG-2026-10-G7H8", "GREEN"),
        },
    ]

    for doc in sample_docs:
        _documents[doc["document_id"]] = doc


def _build_sample_audit_chain(doc_id: str, risk_level: str) -> list[dict]:
    """
    Build a realistic hash-chained audit trail for a sample document.
    Each entry is properly chained to the previous one.
    """
    import hashlib
    import json

    entries = []
    prev_hash = ""

    steps = [
        {
            "node": "document_intake",
            "action": "Received trade document (SIMULATION MODE — using sample B/L data)",
            "input": {"document_path": "simulation"},
            "output": {"status": "success", "pages": 1, "doc_type": "bill_of_lading"},
        },
        {
            "node": "entity_extraction",
            "action": "Parsed extraction result into structured trade entities",
            "input": {"pages_analyzed": 1},
            "output": {"shipper": "extracted", "consignee": "extracted"},
        },
        {
            "node": "sanctions_screening",
            "action": "Screened shipper + consignee against OFAC/EU/UN sanctions lists",
            "input": {"entities_screened": 2},
            "output": {"combined_risk": risk_level},
            "risk_level": risk_level if risk_level != "GREEN" else None,
        },
    ]

    if risk_level != "RED":
        steps.append({
            "node": "hs_classification",
            "action": "Classified cargo into HS tariff code",
            "input": {"cargo": "sample cargo description"},
            "output": {"hs_code": "610510", "confidence": 0.92},
            "confidence": 0.92,
        })
    else:
        steps.append({
            "node": "hs_classification",
            "action": "SKIPPED — sanctions screening returned RED",
            "input": {"cargo": "skipped"},
            "output": {"skipped": True},
        })

    steps.append({
        "node": "risk_assessment",
        "action": f"Aggregated compliance signals → overall risk: {risk_level}",
        "input": {"sanctions_risk": risk_level},
        "output": {"overall_risk": risk_level, "human_review_required": risk_level != "GREEN"},
        "risk_level": risk_level,
    })

    if risk_level == "GREEN":
        steps.append({
            "node": "auto_approve",
            "action": "Shipment AUTO-CLEARED — all compliance checks passed",
            "input": {"overall_risk": "GREEN"},
            "output": {"pipeline_status": "approved"},
            "risk_level": "GREEN",
        })
    elif risk_level == "RED":
        steps.append({
            "node": "block_alert",
            "action": "Shipment BLOCKED — sanctions match detected",
            "input": {"overall_risk": "RED"},
            "output": {"pipeline_status": "blocked"},
            "risk_level": "RED",
        })
    else:
        steps.append({
            "node": "human_review",
            "action": "Pipeline PAUSED — awaiting human compliance officer review",
            "input": {"overall_risk": "YELLOW"},
            "output": {"pipeline_status": "awaiting_review"},
            "risk_level": "YELLOW",
        })

    steps.append({
        "node": "report_generator",
        "action": f"Compiled final compliance report — status: {risk_level.lower()}",
        "input": {"state_fields_used": 12},
        "output": {"overall_risk": risk_level},
    })

    base_time = "2026-10-20T08:00:0"
    for i, step in enumerate(steps):
        entry = {
            "timestamp": f"{base_time}{i}+00:00",
            "node": step["node"],
            "action": step["action"],
            "input": step.get("input", {}),
            "output": step.get("output", {}),
        }
        if step.get("confidence") is not None:
            entry["confidence"] = step["confidence"]
        if step.get("risk_level") is not None:
            entry["risk_level"] = step["risk_level"]

        entry_json = json.dumps(entry, sort_keys=True, default=str)
        chain_input = prev_hash + entry_json
        entry["hash"] = hashlib.sha256(chain_input.encode()).hexdigest()
        prev_hash = entry["hash"]

        entries.append(entry)

    return entries


# Auto-seed initial documents on module import
seed_sample_documents()
