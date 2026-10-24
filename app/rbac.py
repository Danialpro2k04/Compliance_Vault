"""
ComplianceVault — RBAC (Role-Based Access Control)

Implements authentication and authorization for the governance dashboard.
Three roles with progressively more access:

  Operator:           Submit documents, view own processing status
  Compliance Officer: Review flagged shipments, export reports
  Admin:              Override decisions, manage users, verify audit integrity

In production, this would use JWT tokens, a database, and proper
password hashing. This implementation uses in-memory session tokens
for demonstration — the RBAC logic itself is production-grade.
"""

import hashlib
import secrets
from datetime import datetime, timezone
from typing import Optional

from app.config import DEFAULT_USERS, ROLES
from app.audit_store import append_governance_event


# ═══════════════════════════════════════════════════════════════
# In-memory Session Store
# Maps: session_token → {username, role, name, login_time}
# ═══════════════════════════════════════════════════════════════

_sessions: dict[str, dict] = {}

# ═══════════════════════════════════════════════════════════════
# User Store (in-memory, seeded from config)
# ═══════════════════════════════════════════════════════════════

_users: dict[str, dict] = {}


def _init_users():
    """Initialize user store from config defaults."""
    global _users
    if not _users:
        for username, user_data in DEFAULT_USERS.items():
            _users[username] = {
                "name": user_data["name"],
                "role": user_data["role"],
                "password_hash": hashlib.sha256(
                    user_data["password"].encode()
                ).hexdigest(),
                "created_at": datetime.now(timezone.utc).isoformat(),
            }


def authenticate(username: str, password: str) -> Optional[str]:
    """
    Authenticate a user and return a session token.

    Returns:
        Session token string if successful, None if authentication fails.
    """
    _init_users()

    user = _users.get(username)
    if not user:
        return None

    password_hash = hashlib.sha256(password.encode()).hexdigest()
    if password_hash != user["password_hash"]:
        # Log failed login attempt
        append_governance_event(
            event_type="login_failed",
            actor=username,
            actor_role="unknown",
            action=f"Failed login attempt for user '{username}'",
        )
        return None

    # Create session
    token = secrets.token_hex(32)
    _sessions[token] = {
        "username": username,
        "name": user["name"],
        "role": user["role"],
        "permissions": ROLES.get(user["role"], {}).get("permissions", []),
        "login_time": datetime.now(timezone.utc).isoformat(),
    }

    # Log successful login
    append_governance_event(
        event_type="login",
        actor=username,
        actor_role=user["role"],
        action=f"User '{user['name']}' logged in as {user['role']}",
    )

    return token


def get_session(token: str) -> Optional[dict]:
    """Get session data for a given token, or None if invalid/expired."""
    return _sessions.get(token)


def logout(token: str) -> bool:
    """Invalidate a session token."""
    session = _sessions.pop(token, None)
    if session:
        append_governance_event(
            event_type="logout",
            actor=session["username"],
            actor_role=session["role"],
            action=f"User '{session['name']}' logged out",
        )
        return True
    return False


def check_permission(token: str, permission: str) -> bool:
    """Check if the session holder has a specific permission."""
    session = get_session(token)
    if not session:
        return False
    return permission in session.get("permissions", [])


def get_all_users() -> list[dict]:
    """Return all users (without password hashes) for admin view."""
    _init_users()
    return [
        {
            "username": username,
            "name": data["name"],
            "role": data["role"],
            "role_display": ROLES.get(data["role"], {}).get("display_name", data["role"]),
            "permissions": ROLES.get(data["role"], {}).get("permissions", []),
        }
        for username, data in _users.items()
    ]


def get_role_info(role: str) -> dict:
    """Get the display name and permissions for a role."""
    return ROLES.get(role, {})
