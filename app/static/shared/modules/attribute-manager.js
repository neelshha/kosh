/**
 * Attribute management functionality for admin dashboard
 */

class AttributeManager {
    /**
     * Add a new attribute
     */
    async add() {
        const attrInput = document.getElementById('new-attr');
        const attr = attrInput.value.trim();
        const errorDiv = document.getElementById('attr-error');
        
        this.clearError();

        if (!attr) {
            this.showError('Attribute name is required');
            return;
        }

        try {
            const response = await fetch('/admin/add_attribute', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ attr })
            });

            const result = await response.json();
            if (result.success) {
                attrInput.value = '';
                window.location.reload();
            } else {
                this.showError(result.error || 'Error adding attribute');
            }
        } catch (error) {
            this.showError('Network error');
        }
    }

    /**
     * Remove an attribute
     * @param {string} attr - Attribute to remove
     */
    async remove(attr) {
        if (!confirm(`Remove attribute "${attr}"? This will remove it from all users and policies.`)) {
            return;
        }

        this.clearError();

        try {
            const response = await fetch('/admin/remove_attribute', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ attr })
            });

            const result = await response.json();
            if (result.success) {
                window.location.reload();
            } else {
                this.showError(result.error || 'Error removing attribute');
            }
        } catch (error) {
            this.showError('Network error');
        }
    }

    /**
     * Show error message
     * @param {string} message - Error message
     */
    showError(message) {
        const errorDiv = document.getElementById('attr-error');
        if (errorDiv) {
            errorDiv.textContent = message;
            errorDiv.style.display = 'block';
        }
    }

    /**
     * Clear error message
     */
    clearError() {
        const errorDiv = document.getElementById('attr-error');
        if (errorDiv) {
            errorDiv.style.display = 'none';
            errorDiv.textContent = '';
        }
    }
}

// Global attribute manager instance
const attributeManager = new AttributeManager();
