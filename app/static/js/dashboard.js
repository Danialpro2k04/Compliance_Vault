/**
 * ComplianceVault — Dashboard JavaScript
 * Week 6: Governance & Audit Layer
 */

// ═══════════════════════════════════════════════════════════════
// Logout
// ═══════════════════════════════════════════════════════════════

async function logout() {
    try {
        await fetch('/api/logout', { method: 'POST' });
    } catch (e) {
        // Ignore errors
    }
    window.location.href = '/login';
}


// ═══════════════════════════════════════════════════════════════
// Document Filtering (client-side for instant response)
// ═══════════════════════════════════════════════════════════════

function filterDocuments() {
    const statusFilter = document.getElementById('statusFilter')?.value || '';
    const riskFilter = document.getElementById('riskFilter')?.value || '';

    const rows = document.querySelectorAll('.doc-row');
    rows.forEach(row => {
        const status = row.getAttribute('data-status');
        const risk = row.getAttribute('data-risk');

        let visible = true;
        if (statusFilter && status !== statusFilter) visible = false;
        if (riskFilter && risk !== riskFilter) visible = false;

        row.style.display = visible ? '' : 'none';
    });
}


// ═══════════════════════════════════════════════════════════════
// Keyboard Shortcuts
// ═══════════════════════════════════════════════════════════════

document.addEventListener('keydown', (e) => {
    // Ctrl+Shift+V: Verify all chains
    if (e.ctrlKey && e.shiftKey && e.key === 'V') {
        e.preventDefault();
        verifyAllChains();
    }
});

async function verifyAllChains() {
    try {
        const response = await fetch('/api/verify/governance');
        if (response.ok) {
            const data = await response.json();
            alert(`Governance Chain Verification:\n\n${data.is_valid ? '✅ VALID' : '❌ BROKEN'}\n${data.message}`);
        } else if (response.status === 403) {
            alert('Insufficient permissions to verify governance chain.');
        }
    } catch (err) {
        alert('Error verifying governance chain.');
    }
}
