/**
 * Audit log functionality for admin dashboard
 */

class AuditManager {
    /**
     * Filter audit logs by date range
     */
    filter() {
        const from = document.getElementById('audit-from').value;
        const to = document.getElementById('audit-to').value;
        const rows = document.querySelectorAll('#audit-tbody tr');
        let shown = 0;

        rows.forEach(row => {
            const timeCell = row.children[0];
            if (!timeCell) return;
            
            const timeStr = timeCell.textContent.trim();
            // Parse as YYYY-MM-DD HH:MM:SS
            const date = new Date(timeStr.replace(' ', 'T'));
            let show = true;

            if (from) {
                const fromDate = new Date(from);
                if (date < fromDate) show = false;
            }
            
            if (to) {
                // To date is inclusive, so add 1 day
                const toDate = new Date(to);
                toDate.setDate(toDate.getDate() + 1);
                if (date >= toDate) show = false;
            }

            row.style.display = show ? '' : 'none';
            if (show) shown++;
        });

        const noResults = document.getElementById('log-no-results');
        if (noResults) {
            noResults.style.display = shown ? 'none' : 'block';
        }
    }

    /**
     * Clear date filters
     */
    clearFilters() {
        const fromInput = document.getElementById('audit-from');
        const toInput = document.getElementById('audit-to');
        
        if (fromInput) fromInput.value = '';
        if (toInput) toInput.value = '';
        
        this.filter();
    }
}

// Global audit manager instance
const auditManager = new AuditManager();
