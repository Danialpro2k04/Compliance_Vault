"""
ComplianceVault — PDF Report Exporter

Generates professional PDF compliance reports suitable for
regulatory submission. Uses fpdf2 for PDF generation.

Report sections:
  1. Document summary (parties, ports, cargo)
  2. Sanctions screening results
  3. HS tariff classification
  4. Risk assessment decision
  5. Human review decision (if applicable)
  6. Override history (if applicable)
  7. Full hash-chained audit trail
"""

import os
from datetime import datetime, timezone
from typing import Optional

from fpdf import FPDF


def _clean_text(text: any) -> str:
    """Sanitize Unicode characters for standard PDF core fonts (Latin-1)."""
    if text is None:
        return "N/A"
    if not isinstance(text, str):
        text = str(text)
    replacements = {
        "\u2014": "--",
        "\u2013": "-",
        "\u2192": "->",
        "\u2018": "'",
        "\u2019": "'",
        "\u201c": '"',
        "\u201d": '"',
        "\u2022": "*",
        "\u2026": "...",
        "✅": "[PASSED]",
        "🚫": "[BLOCKED]",
        "⏳": "[PENDING]",
        "⚙️": "[PROCESSING]",
        "🔄": "[OVERRIDDEN]",
        "🟢": "[GREEN]",
        "🟡": "[YELLOW]",
        "🔴": "[RED]",
        "🛡️": "[TRADEGUARD]",
        "⚠️": "[WARNING]",
    }
    for orig, repl in replacements.items():
        text = text.replace(orig, repl)
    return text.encode("latin-1", "replace").decode("latin-1")


class ComplianceReportPDF(FPDF):
    """Custom PDF class with TradeGuard branding."""

    def header(self):
        self.set_font("Helvetica", "B", 14)
        self.cell(0, 10, "TradeGuard - Compliance Report", align="C", new_x="LMARGIN", new_y="NEXT")
        self.set_font("Helvetica", "I", 8)
        self.cell(0, 5, "ComplianceVault Governance Dashboard | Confidential", align="C", new_x="LMARGIN", new_y="NEXT")
        self.line(10, self.get_y() + 2, 200, self.get_y() + 2)
        self.ln(6)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}}", align="C")

    def section_title(self, title: str):
        self.set_font("Helvetica", "B", 11)
        self.set_fill_color(230, 240, 250)
        self.cell(0, 8, f"  {_clean_text(title)}", fill=True, new_x="LMARGIN", new_y="NEXT")
        self.ln(2)

    def add_field(self, label: str, value: str, bold_value: bool = False):
        self.set_font("Helvetica", "B", 9)
        self.cell(55, 6, f"{_clean_text(label)}:", new_x="RIGHT", new_y="TOP")
        if bold_value:
            self.set_font("Helvetica", "B", 9)
        else:
            self.set_font("Helvetica", "", 9)
        rem_w = max(10, self.epw - 55)
        self.multi_cell(rem_w, 6, _clean_text(value), new_x="LMARGIN", new_y="NEXT")

    def add_risk_badge(self, label: str, risk: str):
        self.set_font("Helvetica", "B", 9)
        self.cell(55, 6, f"{_clean_text(label)}:", new_x="RIGHT", new_y="TOP")

        colors = {
            "GREEN": (34, 139, 34),
            "YELLOW": (218, 165, 32),
            "RED": (220, 20, 60),
        }
        r, g, b = colors.get(risk, (128, 128, 128))
        self.set_text_color(r, g, b)
        self.set_font("Helvetica", "B", 10)
        rem_w = max(10, self.epw - 55)
        self.cell(rem_w, 6, _clean_text(risk), new_x="LMARGIN", new_y="NEXT")
        self.set_text_color(0, 0, 0)


def generate_compliance_pdf(
    document: dict,
    include_audit_trail: bool = True,
    include_sanctions_detail: bool = True,
    include_hs_detail: bool = True,
    exported_by: str = "System",
) -> str:
    """
    Generate a PDF compliance report for a processed document.

    Args:
        document: Full document state dict from the document store
        include_audit_trail: Whether to include the full audit chain
        include_sanctions_detail: Whether to include sanctions match details
        include_hs_detail: Whether to include HS classification details
        exported_by: Name of the user who requested the export

    Returns:
        Path to the generated PDF file
    """
    pdf = ComplianceReportPDF()
    pdf.alias_nb_pages()
    pdf.add_page()

    doc_id = document.get("document_id", "Unknown")

    # ── 1. Document Summary ──
    pdf.section_title("1. DOCUMENT SUMMARY")
    pdf.add_field("Document ID", doc_id, bold_value=True)
    pdf.add_field("Pipeline Status", document.get("pipeline_status", "N/A"))
    pdf.add_risk_badge("Overall Risk", document.get("overall_risk", "N/A"))
    pdf.add_field("Submitted By", document.get("submitted_by", "N/A"))
    pdf.add_field("Started At", document.get("started_at", "N/A"))
    pdf.add_field("Completed At", document.get("completed_at", "N/A"))
    pdf.ln(4)

    # ── 2. Trade Parties ──
    pdf.section_title("2. TRADE PARTIES & ROUTE")
    pdf.add_field("Shipper", document.get("shipper_name", "N/A"))
    pdf.add_field("Consignee", document.get("consignee_name", "N/A"))
    pdf.add_field("Port of Loading", document.get("port_of_loading", "N/A"))
    pdf.add_field("Port of Discharge", document.get("port_of_discharge", "N/A"))
    pdf.add_field("Cargo Description", document.get("cargo_description", "N/A"))
    pdf.ln(4)

    # ── 3. Sanctions Screening ──
    pdf.section_title("3. SANCTIONS SCREENING")
    pdf.add_risk_badge("Sanctions Risk", document.get("sanctions_risk", "N/A"))

    if include_sanctions_detail:
        shipper_screening = document.get("shipper_screening", {})
        consignee_screening = document.get("consignee_screening", {})

        pdf.add_field(
            "Shipper Result",
            f"{shipper_screening.get('risk_level', 'N/A')} — "
            f"{len(shipper_screening.get('matches', []))} match(es)",
        )
        pdf.add_field(
            "Consignee Result",
            f"{consignee_screening.get('risk_level', 'N/A')} — "
            f"{len(consignee_screening.get('matches', []))} match(es)",
        )

        # Show top matches if any
        for party, screening in [("Shipper", shipper_screening), ("Consignee", consignee_screening)]:
            matches = screening.get("matches", [])
            if matches:
                for m in matches[:3]:
                    pdf.add_field(
                        f"  {party} Match",
                        f"{m.get('matched_name', '?')} "
                        f"(score: {m.get('combined_score', '?')}, "
                        f"source: {m.get('source', '?')})",
                    )
    pdf.ln(4)

    # ── 4. HS Classification ──
    pdf.section_title("4. HS TARIFF CLASSIFICATION")
    hs_class = document.get("hs_classification", {})
    if hs_class.get("skipped"):
        pdf.add_field("Status", f"SKIPPED — {hs_class.get('reason', 'unknown reason')}")
    else:
        pdf.add_field("HS Code", document.get("hs_code", "N/A"), bold_value=True)
        pdf.add_field("Confidence", f"{document.get('hs_confidence', 0):.0%}")

        if include_hs_detail and isinstance(hs_class, dict):
            result = hs_class.get("result", {})
            pdf.add_field("Description", result.get("primary_description", "N/A"))
            reasoning = result.get("reasoning", {})
            if reasoning:
                pdf.add_field("Chapter", reasoning.get("chapter", "N/A"))
                pdf.add_field("Heading", reasoning.get("heading", "N/A"))
                pdf.add_field("Subheading", reasoning.get("subheading", "N/A"))
    pdf.ln(4)

    # ── 5. Risk Factors ──
    risk_factors = document.get("risk_factors", [])
    if risk_factors:
        pdf.section_title("5. RISK FACTORS")
        for i, factor in enumerate(risk_factors, 1):
            pdf.set_font("Helvetica", "", 9)
            pdf.multi_cell(pdf.epw, 5, _clean_text(f"  {i}. {factor}"), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(4)

    # ── 6. Human Review / Decision ──
    pdf.section_title("6. DECISION & HUMAN REVIEW")
    pdf.add_field("Decision", document.get("human_decision", "N/A"))
    pdf.add_field("Justification", document.get("human_justification", "N/A"))
    pdf.add_field("Reviewed By", document.get("reviewed_by", "N/A"))

    # Overrides
    overrides = document.get("overrides", [])
    if overrides:
        pdf.ln(2)
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(pdf.epw, 6, f"  Override History ({len(overrides)} override(s)):", new_x="LMARGIN", new_y="NEXT")
        for i, ov in enumerate(overrides, 1):
            pdf.set_font("Helvetica", "", 8)
            pdf.multi_cell(
                pdf.epw, 5,
                _clean_text(
                    f"    #{i}: {ov.get('previous_status')} -> {ov.get('new_decision')} "
                    f"by {ov.get('officer_name')} at {ov.get('timestamp', '')[:19]} | "
                    f"Reason: {ov.get('justification', '')[:100]}"
                ),
                new_x="LMARGIN", new_y="NEXT",
            )
        pdf.ln(4)

    # ── 7. Audit Trail ──
    if include_audit_trail:
        audit_log = document.get("audit_log", [])
        if audit_log:
            pdf.add_page()
            pdf.section_title(f"7. HASH-CHAINED AUDIT TRAIL ({len(audit_log)} entries)")
            pdf.set_font("Helvetica", "I", 8)
            pdf.multi_cell(
                pdf.epw, 4,
                "Each entry below contains a SHA-256 hash of the previous entry. "
                "If any entry has been modified, subsequent hashes will not verify. "
                "Use the ComplianceVault /api/verify endpoint to validate integrity.",
                new_x="LMARGIN", new_y="NEXT",
            )
            pdf.ln(3)

            for i, entry in enumerate(audit_log):
                pdf.set_font("Helvetica", "B", 8)
                node = entry.get("node", "?")
                ts = entry.get("timestamp", "?")[:19]
                pdf.cell(pdf.epw, 5, _clean_text(f"Entry {i} | {node} | {ts}"), new_x="LMARGIN", new_y="NEXT")

                pdf.set_font("Helvetica", "", 7)
                pdf.multi_cell(pdf.epw, 4, _clean_text(f"  Action: {entry.get('action', '?')}"), new_x="LMARGIN", new_y="NEXT")

                if entry.get("confidence") is not None:
                    pdf.multi_cell(pdf.epw, 4, _clean_text(f"  Confidence: {entry['confidence']:.2%}"), new_x="LMARGIN", new_y="NEXT")
                if entry.get("risk_level"):
                    pdf.multi_cell(pdf.epw, 4, _clean_text(f"  Risk Level: {entry['risk_level']}"), new_x="LMARGIN", new_y="NEXT")

                hash_val = entry.get("hash", "?")
                pdf.set_font("Courier", "", 6)
                pdf.multi_cell(pdf.epw, 3, _clean_text(f"  Hash: {hash_val}"), new_x="LMARGIN", new_y="NEXT")
                pdf.ln(2)

    # ── Export metadata ──
    pdf.add_page()
    pdf.section_title("EXPORT METADATA")
    pdf.add_field("Generated At", datetime.now(timezone.utc).isoformat())
    pdf.add_field("Generated By", exported_by)
    pdf.add_field("System", "ComplianceVault v1.0 (TradeGuard Week 6)")
    pdf.set_font("Helvetica", "I", 8)
    pdf.ln(4)
    pdf.multi_cell(
        pdf.epw, 4,
        "This report was generated by the ComplianceVault governance system. "
        "The audit trail uses SHA-256 hash chaining for tamper evidence. "
        "Any modification to the audit entries can be detected by "
        "verifying the chain hashes. This report is intended for "
        "regulatory submission under EU AI Act Article 50 transparency "
        "requirements and ISO/IEC 42001 AI Management System standards.",
        new_x="LMARGIN", new_y="NEXT",
    )

    # Save to file
    reports_dir = os.path.join(os.path.dirname(__file__), "..", "data", "reports")
    os.makedirs(reports_dir, exist_ok=True)

    filename = f"compliance_report_{doc_id}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.pdf"
    filepath = os.path.join(reports_dir, filename)
    pdf.output(filepath)

    return filepath
