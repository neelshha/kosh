/**
 * Modal utilities for admin dashboard
 */

class ModalManager {
    constructor() {
        this.modalRoot = document.getElementById('modal-root');
    }

    /**
     * Show a modal with the given HTML content
     * @param {string} html - HTML content for the modal
     */
    show(html) {
        if (!this.modalRoot) return;
        
        this.modalRoot.innerHTML = `
            <div class="fixed inset-0 bg-black bg-opacity-40 flex items-center justify-center z-50" onclick="modalManager.close(event)">
                <div class="bg-notion-card p-6 rounded-xl shadow-xl min-w-[320px] max-w-lg relative animate-fade-in" onclick="event.stopPropagation();">
                    <button onclick="modalManager.close()" class="absolute top-2 right-2 text-notion-text-secondary hover:text-notion-text text-xl leading-none" aria-label="Close modal">&times;</button>
                    ${html}
                </div>
            </div>
        `;
        
        // Reinitialize icons for modal content
        setTimeout(uiHelpers.reinitializeLucideIcons, 10);
    }

    /**
     * Close the modal
     * @param {Event} e - Event object (optional)
     */
    close(e) {
        if (!e || e.target === e.currentTarget) {
            if (this.modalRoot) {
                this.modalRoot.innerHTML = '';
            }
        }
    }

    /**
     * Show inline error message in a form
     * @param {HTMLFormElement} form - Form element
     * @param {string} message - Error message
     */
    showInlineError(form, message) {
        let err = form.querySelector('.inline-error');
        if (!err) {
            err = document.createElement('div');
            err.className = 'inline-error text-red-400 text-sm mt-2';
            form.appendChild(err);
        }
        err.textContent = message;
    }
}

// Global modal manager instance
const modalManager = new ModalManager();
