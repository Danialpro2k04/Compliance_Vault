"""
Tests for ComplianceVault — Week 6: Governance & Audit Dashboard

Tests cover:
  1. Hash-chained audit store integrity
  2. RBAC authentication and authorization
  3. Document store operations
  4. Override recording and audit chaining
  5. Audit chain verification (valid and tampered)
  6. Dashboard stats computation
"""

import hashlib
import json
import os
import tempfile

import pytest

# Override audit file path before imports
os.environ["GOVERNANCE_AUDIT_FILE"] = os.path.join(
    tempfile.mkdtemp(), "test_governance_audit.jsonl"
)

from app.audit_store import (
    append_governance_event,
    read_governance_events,
    verify_governance_chain,
    verify_document_audit_chain,
    AUDIT_FILE,
)
from app.rbac import authenticate, get_session, check_permission, logout
from app.document_store import (
    store_document,
    get_document,
    get_all_documents,
    record_override,
    get_dashboard_stats,
    seed_sample_documents,
    _build_sample_audit_chain,
)


# ═══════════════════════════════════════════════════════════════
# 1. Audit Store Tests
# ═══════════════════════════════════════════════════════════════

class TestAuditStore:
    """Test the hash-chained governance audit store."""

    def setup_method(self):
        """Clear audit file before each test."""
        if os.path.exists(AUDIT_FILE):
            os.remove(AUDIT_FILE)

    def test_append_event_creates_entry(self):
        entry = append_governance_event(
            event_type="test",
            actor="test_user",
            actor_role="admin",
            action="Test action",
        )
        assert entry["event_type"] == "test"
        assert entry["actor"] == "test_user"
        assert entry["hash"] != ""
        assert len(entry["hash"]) == 64  # SHA-256 hex

    def test_hash_chain_integrity(self):
        """Multiple events should form a valid hash chain."""
        for i in range(5):
            append_governance_event(
                event_type="test",
                actor="user",
                actor_role="admin",
                action=f"Action {i}",
            )

        is_valid, message, count = verify_governance_chain()
        assert is_valid is True
        assert count == 5

    def test_tamper_detection(self):
        """Modifying a past entry should break the chain."""
        for i in range(3):
            append_governance_event(
                event_type="test",
                actor="user",
                actor_role="admin",
                action=f"Action {i}",
            )

        # Tamper with the first entry
        with open(AUDIT_FILE, "r") as f:
            lines = f.readlines()

        entry = json.loads(lines[0])
        entry["action"] = "TAMPERED ACTION"
        lines[0] = json.dumps(entry) + "\n"

        with open(AUDIT_FILE, "w") as f:
            f.writelines(lines)

        is_valid, message, count = verify_governance_chain()
        assert is_valid is False
        assert "broken" in message.lower() or "Chain broken" in message

    def test_read_events_with_filter(self):
        append_governance_event(
            event_type="login",
            actor="alice",
            actor_role="admin",
            action="Alice logged in",
        )
        append_governance_event(
            event_type="override",
            actor="bob",
            actor_role="compliance_officer",
            action="Bob overrode decision",
        )
        append_governance_event(
            event_type="login",
            actor="charlie",
            actor_role="operator",
            action="Charlie logged in",
        )

        # Filter by event type
        logins = read_governance_events(event_type="login")
        assert len(logins) == 2

        # Filter by actor
        bob_events = read_governance_events(actor="bob")
        assert len(bob_events) == 1
        assert bob_events[0]["event_type"] == "override"

    def test_empty_chain_is_valid(self):
        is_valid, message, count = verify_governance_chain()
        assert is_valid is True
        assert count == 0


# ═══════════════════════════════════════════════════════════════
# 2. Document Audit Chain Tests
# ═══════════════════════════════════════════════════════════════

class TestDocumentAuditChain:
    """Test per-document hash-chained audit trails."""

    def test_sample_chain_is_valid(self):
        """Sample audit chains should verify correctly."""
        chain = _build_sample_audit_chain("TG-TEST-001", "GREEN")
        is_valid, message = verify_document_audit_chain(chain)
        assert is_valid is True
        assert len(chain) > 0

    def test_all_risk_levels_produce_valid_chains(self):
        for risk in ["GREEN", "YELLOW", "RED"]:
            chain = _build_sample_audit_chain(f"TG-TEST-{risk}", risk)
            is_valid, message = verify_document_audit_chain(chain)
            assert is_valid is True, f"Chain for {risk} risk failed: {message}"

    def test_tampered_document_chain_detected(self):
        chain = _build_sample_audit_chain("TG-TEST-TAMPER", "GREEN")
        # Tamper with middle entry
        chain[2]["action"] = "TAMPERED"
        is_valid, message = verify_document_audit_chain(chain)
        assert is_valid is False

    def test_empty_chain_is_valid(self):
        is_valid, message = verify_document_audit_chain([])
        assert is_valid is True


# ═══════════════════════════════════════════════════════════════
# 3. RBAC Tests
# ═══════════════════════════════════════════════════════════════

class TestRBAC:
    """Test Role-Based Access Control."""

    def setup_method(self):
        if os.path.exists(AUDIT_FILE):
            os.remove(AUDIT_FILE)

    def test_valid_login(self):
        token = authenticate("danyal", "admin123")
        assert token is not None
        assert len(token) == 64  # hex(32 bytes)

    def test_invalid_password(self):
        token = authenticate("danyal", "wrong_password")
        assert token is None

    def test_invalid_username(self):
        token = authenticate("nonexistent", "password")
        assert token is None

    def test_session_retrieval(self):
        token = authenticate("danyal", "admin123")
        session = get_session(token)
        assert session is not None
        assert session["username"] == "danyal"
        assert session["role"] == "admin"

    def test_admin_has_override_permission(self):
        token = authenticate("danyal", "admin123")
        assert check_permission(token, "override_decision") is True
        assert check_permission(token, "manage_users") is True
        assert check_permission(token, "verify_integrity") is True

    def test_officer_cannot_override(self):
        token = authenticate("sarah", "officer123")
        assert check_permission(token, "override_decision") is False
        assert check_permission(token, "review_flagged") is True
        assert check_permission(token, "export_reports") is True

    def test_operator_limited_permissions(self):
        token = authenticate("ali", "operator123")
        assert check_permission(token, "override_decision") is False
        assert check_permission(token, "review_flagged") is False
        assert check_permission(token, "view_documents") is True
        assert check_permission(token, "submit_documents") is True

    def test_logout_invalidates_session(self):
        token = authenticate("danyal", "admin123")
        assert get_session(token) is not None
        logout(token)
        assert get_session(token) is None


# ═══════════════════════════════════════════════════════════════
# 4. Document Store Tests
# ═══════════════════════════════════════════════════════════════

class TestDocumentStore:
    """Test the document store operations."""

    def setup_method(self):
        from app import document_store
        document_store._documents.clear()
        if os.path.exists(AUDIT_FILE):
            os.remove(AUDIT_FILE)

    def test_store_and_retrieve(self):
        store_document("TG-TEST-001", {
            "pipeline_status": "approved",
            "overall_risk": "GREEN",
            "shipper_name": "Test Corp",
        }, submitted_by="test_user")

        doc = get_document("TG-TEST-001")
        assert doc is not None
        assert doc["pipeline_status"] == "approved"
        assert doc["submitted_by"] == "test_user"

    def test_filter_by_status(self):
        store_document("TG-1", {"pipeline_status": "approved", "overall_risk": "GREEN", "started_at": "2026-01-01"})
        store_document("TG-2", {"pipeline_status": "blocked", "overall_risk": "RED", "started_at": "2026-01-02"})
        store_document("TG-3", {"pipeline_status": "approved", "overall_risk": "GREEN", "started_at": "2026-01-03"})

        approved = get_all_documents(status_filter="approved")
        assert len(approved) == 2

        blocked = get_all_documents(risk_filter="RED")
        assert len(blocked) == 1

    def test_override_recording(self):
        chain = _build_sample_audit_chain("TG-OVERRIDE", "GREEN")
        store_document("TG-OVERRIDE", {
            "pipeline_status": "approved",
            "overall_risk": "GREEN",
            "audit_log": chain,
            "started_at": "2026-01-01",
        })

        override = record_override(
            document_id="TG-OVERRIDE",
            new_decision="reject",
            justification="Override test — shipment needs re-review after new intelligence",
            officer_name="Test Officer",
            officer_username="test",
            officer_role="admin",
        )

        doc = get_document("TG-OVERRIDE")
        assert doc["pipeline_status"] == "blocked"
        assert len(doc["overrides"]) == 1
        assert doc["overrides"][0]["new_decision"] == "reject"

        # Verify the override is properly hash-chained
        is_valid, msg = verify_document_audit_chain(doc["audit_log"])
        assert is_valid is True, f"Chain broken after override: {msg}"

    def test_dashboard_stats(self):
        seed_sample_documents()
        stats = get_dashboard_stats()
        assert stats.total_documents == 4
        assert stats.approved_count >= 1
        assert stats.blocked_count >= 1

    def test_nonexistent_document_override_fails(self):
        with pytest.raises(ValueError):
            record_override(
                document_id="NONEXISTENT",
                new_decision="approve",
                justification="This should fail because document doesn't exist",
                officer_name="Test",
                officer_username="test",
                officer_role="admin",
            )


# ═══════════════════════════════════════════════════════════════
# 5. Integration: Override → Audit Chain → Verification
# ═══════════════════════════════════════════════════════════════

class TestOverrideIntegration:
    """Test the full override → audit → verify flow."""

    def setup_method(self):
        from app import document_store
        document_store._documents.clear()
        if os.path.exists(AUDIT_FILE):
            os.remove(AUDIT_FILE)

    def test_override_creates_governance_event(self):
        chain = _build_sample_audit_chain("TG-INT-001", "RED")
        store_document("TG-INT-001", {
            "pipeline_status": "blocked",
            "overall_risk": "RED",
            "audit_log": chain,
            "started_at": "2026-01-01",
        })

        record_override(
            document_id="TG-INT-001",
            new_decision="approve",
            justification="After thorough investigation, confirmed false positive on sanctions match",
            officer_name="Integration Test",
            officer_username="test",
            officer_role="admin",
        )

        # Check governance audit log
        events = read_governance_events(event_type="override")
        assert len(events) >= 1
        assert events[0]["document_id"] == "TG-INT-001"

        # Check governance chain is valid
        is_valid, _, _ = verify_governance_chain()
        assert is_valid is True

    def test_multiple_overrides_chain_correctly(self):
        chain = _build_sample_audit_chain("TG-MULTI", "GREEN")
        store_document("TG-MULTI", {
            "pipeline_status": "approved",
            "overall_risk": "GREEN",
            "audit_log": chain,
            "started_at": "2026-01-01",
        })

        # Override 1: approve → reject
        record_override(
            document_id="TG-MULTI",
            new_decision="reject",
            justification="New intelligence suggests potential sanctions evasion scheme",
            officer_name="Officer A",
            officer_username="a",
            officer_role="admin",
        )

        # Override 2: reject → approve
        record_override(
            document_id="TG-MULTI",
            new_decision="approve",
            justification="Further investigation cleared the entity — false alarm confirmed",
            officer_name="Officer B",
            officer_username="b",
            officer_role="admin",
        )

        doc = get_document("TG-MULTI")
        assert len(doc["overrides"]) == 2
        assert doc["pipeline_status"] == "approved"

        # Full chain (original + 2 overrides) should verify
        is_valid, msg = verify_document_audit_chain(doc["audit_log"])
        assert is_valid is True, f"Chain broken: {msg}"


# ═══════════════════════════════════════════════════════════════
# 6. PDF Export Tests
# ═══════════════════════════════════════════════════════════════

class TestPDFExport:
    """Test PDF generation for regulatory submission."""

    def test_pdf_generation_all_status_types(self):
        from app.pdf_exporter import generate_compliance_pdf

        seed_sample_documents()
        for doc_id in ["TG-2026-10-A1B2", "TG-2026-10-C3D4", "TG-2026-10-E5F6", "TG-2026-10-G7H8"]:
            doc = get_document(doc_id)
            filepath = generate_compliance_pdf(doc, exported_by="Danyal Wahdat")
            assert os.path.exists(filepath)
            assert os.path.getsize(filepath) > 1000  # Non-trivial PDF


# ═══════════════════════════════════════════════════════════════
# 7. FastAPI Route Tests
# ═══════════════════════════════════════════════════════════════

class TestAPIRoutes:
    """Test key FastAPI endpoints using TestClient."""

    def test_health_check(self):
        from fastapi.testclient import TestClient
        from app.main import app

        with TestClient(app) as client:
            resp = client.get("/health")
            assert resp.status_code == 200
            data = resp.json()
            assert data["status"] == "healthy"
            assert "governance_chain" in data

    def test_login_page_renders_html(self):
        from fastapi.testclient import TestClient
        from app.main import app

        with TestClient(app) as client:
            resp = client.get("/login")
            assert resp.status_code == 200
            assert "ComplianceVault" in resp.text
            assert "Sign In" in resp.text

    def test_dashboard_and_document_detail_html(self):
        from fastapi.testclient import TestClient
        from app.main import app

        with TestClient(app) as client:
            # Login
            login_resp = client.post("/api/login", json={"username": "danyal", "password": "admin123"})
            assert login_resp.status_code == 200
            client.cookies.set("session_token", login_resp.cookies.get("session_token"))

            # View dashboard
            dash_resp = client.get("/")
            assert dash_resp.status_code == 200
            assert "Processed Documents" in dash_resp.text

            # View document detail
            doc_resp = client.get("/document/TG-2026-10-A1B2")
            assert doc_resp.status_code == 200
            assert "Hash-Chained Audit Trail" in doc_resp.text

