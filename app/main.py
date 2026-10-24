"""
ComplianceVault — FastAPI Application (Week 6: Governance & Audit Dashboard)

This is the governance layer for TradeGuard. It provides:
  1. Web dashboard for viewing all processed documents
  2. Full agent decision chain drill-down per document
  3. Hash-chained tamper-evident audit logs
  4. RBAC with Operator / Compliance Officer / Admin roles
  5. Compliance Officer Override with mandatory justification
  6. PDF export for regulatory submission
  7. Audit chain integrity verification

API Endpoints:
  GET   /                              — Dashboard (HTML)
  GET   /login                         — Login page (HTML)
  POST  /api/login                     — Authenticate
  POST  /api/logout                    — Logout
  GET   /api/documents                 — List all documents (filtered)
  GET   /api/documents/{doc_id}        — Full document detail + audit trail
  POST  /api/override/{doc_id}         — Compliance Officer Override
  GET   /api/verify/{doc_id}           — Verify document audit chain
  GET   /api/verify/governance         — Verify governance audit chain
  GET   /api/export/{doc_id}           — Export PDF compliance report
  GET   /api/stats                     — Dashboard statistics
  GET   /api/governance-log            — Governance event log
  GET   /api/users                     — List users (admin only)
  GET   /health                        — Health check
"""

import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, Request, Cookie, Query
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from typing import Optional

from app.config import VAULT_PORT, TRADEGUARD_CORE_URL
from app.schemas import OverrideRequest
from app.rbac import authenticate, get_session, logout, check_permission, get_all_users
from app.document_store import (
    get_document,
    get_all_documents,
    record_override,
    get_dashboard_stats,
    seed_sample_documents,
    store_document,
)
from app.audit_store import (
    append_governance_event,
    read_governance_events,
    verify_governance_chain,
    verify_document_audit_chain,
)
from app.pdf_exporter import generate_compliance_pdf


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Seed sample documents on startup for demonstration."""
    seed_sample_documents()
    append_governance_event(
        event_type="system_start",
        actor="system",
        actor_role="admin",
        action="ComplianceVault governance dashboard started",
        metadata={"version": "1.0.0"},
    )
    yield


app = FastAPI(
    title="ComplianceVault — Governance & Audit Dashboard",
    description=(
        "Week 6 of TradeGuard: The governance layer providing tamper-evident "
        "audit trails, RBAC, compliance officer overrides, and regulatory "
        "report export. Built for EU AI Act Article 50 compliance and "
        "ISO/IEC 42001 AI Management System standards."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# Mount static files
static_dir = os.path.join(os.path.dirname(__file__), "static")
templates_dir = os.path.join(os.path.dirname(__file__), "templates")
app.mount("/static", StaticFiles(directory=static_dir), name="static")
templates = Jinja2Templates(directory=templates_dir)





# ═══════════════════════════════════════════════════════════════
# Helper: Get current user from session cookie
# ═══════════════════════════════════════════════════════════════

def _get_current_user(session_token: Optional[str] = None) -> Optional[dict]:
    """Extract the current user from the session cookie."""
    if not session_token:
        return None
    return get_session(session_token)


# ═══════════════════════════════════════════════════════════════
# HTML Pages (Server-Side Rendered)
# ═══════════════════════════════════════════════════════════════

@app.get("/", response_class=HTMLResponse)
def dashboard_page(request: Request, session_token: Optional[str] = Cookie(None)):
    """Main dashboard — shows all documents with status indicators."""
    user = _get_current_user(session_token)
    if not user:
        return RedirectResponse(url="/login", status_code=302)

    documents = get_all_documents()
    stats = get_dashboard_stats()

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "user": user,
            "documents": documents,
            "stats": stats,
        },
    )


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    """Login page."""
    return templates.TemplateResponse(request=request, name="login.html")


@app.get("/document/{document_id}", response_class=HTMLResponse)
def document_detail_page(
    request: Request,
    document_id: str,
    session_token: Optional[str] = Cookie(None),
):
    """Document detail page — shows full agent decision chain + audit trail."""
    user = _get_current_user(session_token)
    if not user:
        return RedirectResponse(url="/login", status_code=302)

    doc = get_document(document_id)
    if not doc:
        raise HTTPException(status_code=404, detail=f"Document {document_id} not found")

    # Verify audit chain integrity
    audit_log = doc.get("audit_log", [])
    chain_valid, chain_msg = verify_document_audit_chain(audit_log)

    # Check permissions
    can_override = check_permission(session_token, "override_decision")
    can_review = check_permission(session_token, "review_flagged")
    can_export = check_permission(session_token, "export_reports")
    can_verify = check_permission(session_token, "verify_integrity")

    return templates.TemplateResponse(
        request=request,
        name="document_detail.html",
        context={
            "user": user,
            "document": doc,
            "audit_log": audit_log,
            "chain_valid": chain_valid,
            "chain_msg": chain_msg,
            "can_override": can_override,
            "can_review": can_review,
            "can_export": can_export,
            "can_verify": can_verify,
        },
    )


# ═══════════════════════════════════════════════════════════════
# API: Authentication
# ═══════════════════════════════════════════════════════════════

@app.post("/api/login")
def api_login(request_body: dict):
    """Authenticate and return a session token."""
    username = request_body.get("username", "")
    password = request_body.get("password", "")

    token = authenticate(username, password)
    if not token:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    response = JSONResponse(content={
        "status": "authenticated",
        "username": username,
        "message": "Login successful",
    })
    response.set_cookie(
        key="session_token",
        value=token,
        httponly=True,
        samesite="lax",
        max_age=3600 * 8,  # 8 hours
    )
    return response


@app.post("/api/logout")
def api_logout(session_token: Optional[str] = Cookie(None)):
    """Invalidate the session."""
    if session_token:
        logout(session_token)
    response = JSONResponse(content={"status": "logged_out"})
    response.delete_cookie("session_token")
    return response


# ═══════════════════════════════════════════════════════════════
# API: Documents
# ═══════════════════════════════════════════════════════════════

@app.get("/api/documents")
def api_list_documents(
    status: Optional[str] = Query(None),
    risk: Optional[str] = Query(None),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    session_token: Optional[str] = Cookie(None),
):
    """List all documents with optional filters."""
    user = _get_current_user(session_token)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    docs = get_all_documents(
        status_filter=status,
        risk_filter=risk,
        date_from=date_from,
        date_to=date_to,
    )

    # Operators can only see their own documents
    if user["role"] == "operator":
        docs = [d for d in docs if d.get("submitted_by") == user["username"]]

    # Return summary view (no full audit logs)
    summaries = []
    for d in docs:
        summaries.append({
            "document_id": d.get("document_id"),
            "pipeline_status": d.get("pipeline_status"),
            "overall_risk": d.get("overall_risk"),
            "shipper_name": d.get("shipper_name"),
            "consignee_name": d.get("consignee_name"),
            "cargo_description": d.get("cargo_description", "")[:80],
            "port_of_loading": d.get("port_of_loading"),
            "port_of_discharge": d.get("port_of_discharge"),
            "sanctions_risk": d.get("sanctions_risk"),
            "hs_code": d.get("hs_code"),
            "hs_confidence": d.get("hs_confidence"),
            "risk_factors": d.get("risk_factors", []),
            "human_review_required": d.get("human_review_required"),
            "started_at": d.get("started_at"),
            "completed_at": d.get("completed_at"),
            "submitted_by": d.get("submitted_by"),
            "override_count": len(d.get("overrides", [])),
        })

    return {"documents": summaries, "total": len(summaries)}


@app.get("/api/documents/{document_id}")
def api_document_detail(
    document_id: str,
    session_token: Optional[str] = Cookie(None),
):
    """Get full document detail including audit trail."""
    user = _get_current_user(session_token)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    doc = get_document(document_id)
    if not doc:
        raise HTTPException(status_code=404, detail=f"Document {document_id} not found")

    # Operators can only see their own documents
    if user["role"] == "operator" and doc.get("submitted_by") != user["username"]:
        raise HTTPException(status_code=403, detail="Access denied")

    # Verify chain
    audit_log = doc.get("audit_log", [])
    chain_valid, chain_msg = verify_document_audit_chain(audit_log)

    return {
        **doc,
        "audit_chain_valid": chain_valid,
        "audit_chain_message": chain_msg,
    }


# ═══════════════════════════════════════════════════════════════
# API: Compliance Officer Override
# ═══════════════════════════════════════════════════════════════

@app.post("/api/override/{document_id}")
def api_override(
    document_id: str,
    req: OverrideRequest,
    session_token: Optional[str] = Cookie(None),
):
    """
    Override an AI decision on a document.

    Requires 'override_decision' permission (Admin only).
    The override is immutably logged in both the document's
    audit chain and the governance audit log.
    """
    user = _get_current_user(session_token)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    if not check_permission(session_token, "override_decision"):
        raise HTTPException(
            status_code=403,
            detail="Only administrators can override AI decisions",
        )

    try:
        override = record_override(
            document_id=document_id,
            new_decision=req.new_decision,
            justification=req.justification,
            officer_name=req.officer_name,
            officer_username=user["username"],
            officer_role=user["role"],
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

    return {
        "status": "override_recorded",
        "document_id": document_id,
        "override": override,
        "message": (
            f"Decision overridden to '{req.new_decision}' by {req.officer_name}. "
            f"Override immutably logged in audit trail."
        ),
    }


# ═══════════════════════════════════════════════════════════════
# API: Audit Chain Verification
# ═══════════════════════════════════════════════════════════════

@app.get("/api/verify/{document_id}")
def api_verify_document_chain(
    document_id: str,
    session_token: Optional[str] = Cookie(None),
):
    """Verify the integrity of a document's audit chain."""
    user = _get_current_user(session_token)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    doc = get_document(document_id)
    if not doc:
        raise HTTPException(status_code=404, detail=f"Document {document_id} not found")

    audit_log = doc.get("audit_log", [])
    is_valid, message = verify_document_audit_chain(audit_log)

    # Log the verification
    append_governance_event(
        event_type="verify",
        actor=user["username"],
        actor_role=user["role"],
        action=f"Verified audit chain for {document_id}: {'VALID' if is_valid else 'BROKEN'}",
        document_id=document_id,
        details={"is_valid": is_valid, "message": message, "entries": len(audit_log)},
    )

    return {
        "document_id": document_id,
        "is_valid": is_valid,
        "message": message,
        "entries_verified": len(audit_log),
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "verified_by": user["name"],
    }


@app.get("/api/verify/governance")
def api_verify_governance_chain(
    session_token: Optional[str] = Cookie(None),
):
    """Verify the integrity of the governance audit chain."""
    user = _get_current_user(session_token)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    if not check_permission(session_token, "verify_integrity"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    is_valid, message, count = verify_governance_chain()

    return {
        "is_valid": is_valid,
        "message": message,
        "entries_verified": count,
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "verified_by": user["name"],
    }


# ═══════════════════════════════════════════════════════════════
# API: PDF Export
# ═══════════════════════════════════════════════════════════════

@app.get("/api/export/{document_id}")
def api_export_pdf(
    document_id: str,
    include_audit: bool = Query(True),
    session_token: Optional[str] = Cookie(None),
):
    """Export a compliance report as PDF."""
    user = _get_current_user(session_token)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    if not check_permission(session_token, "export_reports"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    doc = get_document(document_id)
    if not doc:
        raise HTTPException(status_code=404, detail=f"Document {document_id} not found")

    filepath = generate_compliance_pdf(
        document=doc,
        include_audit_trail=include_audit,
        exported_by=user["name"],
    )

    # Log the export
    append_governance_event(
        event_type="export",
        actor=user["username"],
        actor_role=user["role"],
        action=f"Exported PDF compliance report for {document_id}",
        document_id=document_id,
        details={"include_audit": include_audit, "filepath": filepath},
    )

    return FileResponse(
        path=filepath,
        media_type="application/pdf",
        filename=os.path.basename(filepath),
    )


# ═══════════════════════════════════════════════════════════════
# API: Statistics & Governance Log
# ═══════════════════════════════════════════════════════════════

@app.get("/api/stats")
def api_stats(session_token: Optional[str] = Cookie(None)):
    """Get dashboard statistics."""
    user = _get_current_user(session_token)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    stats = get_dashboard_stats()
    return stats.model_dump()


@app.get("/api/governance-log")
def api_governance_log(
    limit: int = Query(50, ge=1, le=500),
    event_type: Optional[str] = Query(None),
    session_token: Optional[str] = Cookie(None),
):
    """Get governance events (admin only)."""
    user = _get_current_user(session_token)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    if not check_permission(session_token, "view_audit_chain"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    events = read_governance_events(limit=limit, event_type=event_type)
    return {"events": events, "total": len(events)}


@app.get("/api/users")
def api_users(session_token: Optional[str] = Cookie(None)):
    """List all users (admin only)."""
    user = _get_current_user(session_token)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    if not check_permission(session_token, "manage_users"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    return {"users": get_all_users()}


# ═══════════════════════════════════════════════════════════════
# Health Check
# ═══════════════════════════════════════════════════════════════

@app.get("/health")
def health_check():
    """Health check for the governance dashboard."""
    gov_valid, gov_msg, gov_count = verify_governance_chain()
    stats = get_dashboard_stats()

    return {
        "status": "healthy",
        "service": "ComplianceVault v1.0.0",
        "tradeguard_core_url": TRADEGUARD_CORE_URL,
        "documents_tracked": stats.total_documents,
        "governance_chain": {
            "valid": gov_valid,
            "message": gov_msg,
            "entries": gov_count,
        },
    }
