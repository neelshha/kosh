/**
 * UI helper utilities for admin dashboard
 */

class UIHelpers {
    /**
     * Show loading state on an element
     * @param {HTMLElement} element - Element to show loading state on
     * @param {string} text - Loading text to display
     */
    showLoading(element, text = 'Loading...') {
        if (element) {
            element.style.opacity = '0.6';
            element.style.pointerEvents = 'none';
            element.setAttribute('data-original-text', element.textContent);
            element.textContent = text;
        }
    }

    /**
     * Hide loading state on an element
     * @param {HTMLElement} element - Element to hide loading state on
     */
    hideLoading(element) {
        if (element) {
            element.style.opacity = '1';
            element.style.pointerEvents = 'auto';
            const originalText = element.getAttribute('data-original-text');
            if (originalText) {
                element.textContent = originalText;
                element.removeAttribute('data-original-text');
            }
        }
    }

    /**
     * Escape HTML to prevent XSS
     * @param {string} text - Text to escape
     * @returns {string} Escaped text
     */
    escapeHtml(text) {
        if (typeof text !== 'string') return text;
        const map = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#039;'
        };
        return text.replace(/[&<>"']/g, m => map[m]);
    }

    /**
     * Format attributes as HTML badges
     * @param {string} attributesStr - Comma-separated attributes string
     * @returns {string} HTML with styled badges
     */
    formatAttributesAsHtml(attributesStr) {
        if (!attributesStr || attributesStr.trim() === '') {
            return '<div class="flex flex-wrap gap-1"></div>';
        }

        const attributes = attributesStr.split(',').map(attr => attr.trim()).filter(Boolean);
        const badges = attributes.map(attr => 
            `<span class="inline-flex px-2 py-1 text-xs rounded-full bg-notion-accent/20 text-notion-accent">${this.escapeHtml(attr)}</span>`
        ).join('');

        return `<div class="flex flex-wrap gap-1">${badges}</div>`;
    }

    /**
     * Force Tailwind to re-evaluate styles for dynamic content
     * @param {HTMLElement} element - Element to refresh styles for
     */
    refreshTailwindStyles(element) {
        if (!element) return;

        // Force a reflow by temporarily changing and restoring classes
        const originalClass = element.className;
        element.className = originalClass + ' ';
        element.offsetHeight; // Trigger reflow
        element.className = originalClass;

        // Also refresh child elements
        const children = element.querySelectorAll('*');
        children.forEach(child => {
            const childClass = child.className;
            child.className = childClass + ' ';
            child.offsetHeight;
            child.className = childClass;
        });
    }

    /**
     * Reinitialize Lucide icons when new content is added
     */
    reinitializeLucideIcons() {
        if (typeof lucide !== 'undefined') {
            lucide.createIcons();
        }
    }

    /**
     * Setup keyboard shortcuts
     */
    setupKeyboardShortcuts() {
        document.addEventListener('keydown', (e) => {
            // ESC to close modal
            if (e.key === 'Escape') {
                modalManager.close();
            }

            // Ctrl/Cmd + K to focus search
            if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
                e.preventDefault();
                const userSearch = document.getElementById('user-search');
                if (userSearch) {
                    userSearch.focus();
                }
            }
        });
    }
}

// Global UI helpers instance
const uiHelpers = new UIHelpers();
