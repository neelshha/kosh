/**
 * Toast notification system for admin dashboard
 */

class ToastManager {
    constructor() {
        this.toastRoot = document.getElementById('toast-root');
        this.colors = {
            success: 'bg-green-500',
            error: 'bg-red-500',
            warning: 'bg-yellow-500',
            info: 'bg-blue-500'
        };
        this.icons = {
            success: '<i data-lucide="check-circle" class="w-5 h-5"></i>',
            error: '<i data-lucide="x-circle" class="w-5 h-5"></i>',
            warning: '<i data-lucide="alert-triangle" class="w-5 h-5"></i>',
            info: '<i data-lucide="info" class="w-5 h-5"></i>'
        };
    }

    /**
     * Show a toast notification
     * @param {string} message - Message to display
     * @param {string} type - Type of toast (success, error, warning, info)
     */
    show(message, type = 'success') {
        if (!this.toastRoot) return;

        const color = this.colors[type] || this.colors.success;
        const icon = this.icons[type] || this.icons.success;

        const toast = document.createElement('div');
        toast.className = `pointer-events-auto max-w-sm w-full rounded-lg px-4 py-3 text-white shadow-lg transform transition-all duration-300 ${color} opacity-0 translate-y-2 flex items-center space-x-2`;
        toast.style.boxShadow = '0 4px 12px rgba(0, 0, 0, 0.5)';

        toast.innerHTML = `
            <div class="flex-shrink-0">${icon}</div>
            <div class="flex-1 text-sm font-medium">${message}</div>
            <button onclick="this.parentElement.remove()" class="flex-shrink-0 ml-2 text-white/80 hover:text-white" aria-label="Close notification">
                <i data-lucide="x" class="w-4 h-4"></i>
            </button>
        `;

        this.toastRoot.appendChild(toast);

        // Trigger animation
        setTimeout(() => {
            toast.style.opacity = '1';
            toast.style.transform = 'translateY(0)';
        }, 10);

        // Auto-dismiss after 4 seconds
        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transform = 'translateY(-8px)';
            setTimeout(() => {
                if (toast.parentNode) {
                    toast.remove();
                }
            }, 300);
        }, 4000);

        // Reinitialize icons
        setTimeout(uiHelpers.reinitializeLucideIcons, 10);
    }
}

// Global toast manager instance
const toastManager = new ToastManager();
