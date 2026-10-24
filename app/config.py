"""
ComplianceVault — Configuration

Service URLs, RBAC roles, and governance settings.
Loads from environment variables with sensible defaults.
"""

import os
from dotenv import load_dotenv

load_dotenv()

# ═══════════════════════════════════════════════════════════════
# TradeGuard Core Pipeline URL
# ComplianceVault connects to the Week 5 pipeline service
# ═══════════════════════════════════════════════════════════════

TRADEGUARD_CORE_URL = os.getenv(
    "TRADEGUARD_CORE_URL", "http://localhost:8005"
)

# ═══════════════════════════════════════════════════════════════
# ComplianceVault Settings
# ═══════════════════════════════════════════════════════════════

# Port for the governance dashboard
VAULT_PORT = int(os.getenv("VAULT_PORT", "8006"))

# Secret key for session management (change in production!)
SECRET_KEY = os.getenv("SECRET_KEY", "compliance-vault-dev-key-change-me")

# ═══════════════════════════════════════════════════════════════
# RBAC — Role-Based Access Control
# Three roles with progressively more access:
#   Operator:           Can view documents, submit for processing
#   Compliance Officer: Can view + review YELLOW-flagged shipments
#   Admin:              Full access + override any decision + manage users
# ═══════════════════════════════════════════════════════════════

ROLES = {
    "operator": {
        "display_name": "Operator",
        "permissions": [
            "view_documents",
            "submit_documents",
            "view_own_reports",
        ],
        "description": "Can submit and track trade documents through the pipeline",
    },
    "compliance_officer": {
        "display_name": "Compliance Officer",
        "permissions": [
            "view_documents",
            "submit_documents",
            "view_own_reports",
            "view_all_reports",
            "review_flagged",
            "export_reports",
        ],
        "description": "Can review flagged shipments and approve/reject them",
    },
    "admin": {
        "display_name": "Administrator",
        "permissions": [
            "view_documents",
            "submit_documents",
            "view_own_reports",
            "view_all_reports",
            "review_flagged",
            "export_reports",
            "override_decision",
            "manage_users",
            "view_audit_chain",
            "verify_integrity",
        ],
        "description": "Full system access including decision overrides and user management",
    },
}

# ═══════════════════════════════════════════════════════════════
# Default Users (in production, this would be a database)
# ═══════════════════════════════════════════════════════════════

DEFAULT_USERS = {
    "danyal": {
        "name": "Danyal Wahdat",
        "role": "admin",
        "password": "admin123",  # In production: hashed + salted
    },
    "sarah": {
        "name": "Sarah Khan",
        "role": "compliance_officer",
        "password": "officer123",
    },
    "ali": {
        "name": "Ali Ahmed",
        "role": "operator",
        "password": "operator123",
    },
}
