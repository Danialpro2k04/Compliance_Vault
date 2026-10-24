"""
ComplianceVault — Hash-Chained Audit Store

The governance layer's own append-only audit store. This wraps and
extends the tradeguard_core audit module with:
  - Persistent storage (JSON-lines file, append-only)
  - Governance-specific events (overrides, logins, exports)
  - Independent chain verification
  - Tamper detection reporting

Each governance event is hash-chained to the previous one, creating
an independent audit trail for governance actions (separate from the
pipeline's per-document audit chain, but cross-referenced by document_id).

Storage format: JSONL (one JSON object per line, append-only)
This makes the file naturally append-only — you can only add lines,
and any modification to earlier lines breaks the hash chain.
"""

import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Optional


# ═══════════════════════════════════════════════════════════════
# Governance Audit Store
# ═══════════════════════════════════════════════════════════════

AUDIT_FILE = os.getenv(
    "GOVERNANCE_AUDIT_FILE",
    os.path.join(os.path.dirname(__file__), "..", "data", "governance_audit.jsonl"),
)


def _ensure_audit_dir():
    """Create the data directory if it doesn't exist."""
    os.makedirs(os.path.dirname(os.path.abspath(AUDIT_FILE)), exist_ok=True)


def _get_last_hash() -> str:
    """Read the hash from the last line of the audit file."""
    _ensure_audit_dir()
    if not os.path.exists(AUDIT_FILE):
        return ""
    try:
        with open(AUDIT_FILE, "r") as f:
            last_line = ""
            for line in f:
                line = line.strip()
                if line:
                    last_line = line
            if last_line:
                entry = json.loads(last_line)
                return entry.get("hash", "")
    except (json.JSONDecodeError, IOError):
        pass
    return ""


def append_governance_event(
    event_type: str,
    actor: str,
    actor_role: str,
    action: str,
    document_id: str = "",
    details: Optional[dict] = None,
    metadata: Optional[dict] = None,
) -> dict:
    """
    Append a governance event to the immutable audit log.

    Events include: login, override, export, verification, etc.
    Each event is hash-chained to the previous one.

    Args:
        event_type: Category of event (login, override, export, verify, etc.)
        actor: Username of the person performing the action
        actor_role: Role of the actor (operator, compliance_officer, admin)
        action: Human-readable description of what happened
        document_id: Optional document ID this event relates to
        details: Optional structured details about the event
        metadata: Optional extra metadata

    Returns:
        The created audit entry dict (including its chain hash)
    """
    _ensure_audit_dir()

    prev_hash = _get_last_hash()

    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "actor": actor,
        "actor_role": actor_role,
        "action": action,
    }

    if document_id:
        entry["document_id"] = document_id
    if details:
        entry["details"] = details
    if metadata:
        entry["metadata"] = metadata

    # Build the hash chain
    entry_json = json.dumps(entry, sort_keys=True, default=str)
    chain_input = prev_hash + entry_json
    entry["hash"] = hashlib.sha256(chain_input.encode()).hexdigest()

    # Append to JSONL file (append-only!)
    with open(AUDIT_FILE, "a") as f:
        f.write(json.dumps(entry, default=str) + "\n")

    return entry


def read_governance_events(
    limit: int = 100,
    event_type: Optional[str] = None,
    document_id: Optional[str] = None,
    actor: Optional[str] = None,
) -> list[dict]:
    """
    Read governance events from the audit log, with optional filters.

    Returns events in reverse chronological order (newest first).
    """
    _ensure_audit_dir()
    if not os.path.exists(AUDIT_FILE):
        return []

    events = []
    try:
        with open(AUDIT_FILE, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    # Apply filters
                    if event_type and entry.get("event_type") != event_type:
                        continue
                    if document_id and entry.get("document_id") != document_id:
                        continue
                    if actor and entry.get("actor") != actor:
                        continue
                    events.append(entry)
                except json.JSONDecodeError:
                    continue
    except IOError:
        return []

    # Reverse for newest-first, then limit
    events.reverse()
    return events[:limit]


def verify_governance_chain() -> tuple[bool, str, int]:
    """
    Verify the integrity of the entire governance audit chain.

    Returns:
        (is_valid, message, entries_checked)
    """
    _ensure_audit_dir()
    if not os.path.exists(AUDIT_FILE):
        return True, "No governance events recorded yet", 0

    prev_hash = ""
    count = 0

    try:
        with open(AUDIT_FILE, "r") as f:
            for i, line in enumerate(f):
                line = line.strip()
                if not line:
                    continue

                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    return False, f"Corrupted JSON at line {i + 1}", count

                stored_hash = entry.get("hash", "")

                # Rebuild entry without hash to verify
                entry_copy = {k: v for k, v in entry.items() if k != "hash"}
                entry_json = json.dumps(entry_copy, sort_keys=True, default=str)
                expected_hash = hashlib.sha256(
                    (prev_hash + entry_json).encode()
                ).hexdigest()

                if stored_hash != expected_hash:
                    return (
                        False,
                        f"Chain broken at entry {i + 1} "
                        f"(event: {entry.get('event_type', '?')}, "
                        f"actor: {entry.get('actor', '?')})",
                        count,
                    )

                prev_hash = stored_hash
                count += 1

    except IOError as e:
        return False, f"IO error reading audit file: {e}", count

    return True, f"Governance chain intact — {count} entries verified", count


def verify_document_audit_chain(audit_log: list[dict]) -> tuple[bool, str]:
    """
    Verify a per-document audit chain from the tradeguard_core pipeline.

    This is the same algorithm as tradeguard_core/app/audit.py but
    available here so the dashboard can verify chains independently.

    Returns:
        (is_valid, message)
    """
    prev_hash = ""
    for i, entry in enumerate(audit_log):
        stored_hash = entry.get("hash", "")
        entry_copy = {k: v for k, v in entry.items() if k != "hash"}
        entry_json = json.dumps(entry_copy, sort_keys=True, default=str)
        expected_hash = hashlib.sha256(
            (prev_hash + entry_json).encode()
        ).hexdigest()

        if stored_hash != expected_hash:
            return False, f"Chain broken at entry {i} (node: {entry.get('node', '?')})"
        prev_hash = stored_hash

    return True, f"Chain intact — {len(audit_log)} entries verified"
