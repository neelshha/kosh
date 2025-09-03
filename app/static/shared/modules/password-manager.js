/**
 * Password Manager
 * Handles password change modal functionality
 */

class PasswordManager {
    constructor(notificationManager) {
        this.notification = notificationManager;
        this.elements = {};
        this.init();
    }

    init() {
        this.cacheElements();
        this.bindEvents();
    }

    cacheElements() {
        this.elements = {
            openBtn: document.getElementById('change-password-btn'),
            modal: document.getElementById('change-password-modal'),
            closeBtn: document.getElementById('close-change-password'),
            firstInput: document.getElementById('modal_new_password'),
            confirmInput: document.getElementById('modal_confirm_password'),
            toggleBtn: document.getElementById('toggle-password-visibility'),
            submitBtn: document.getElementById('change-password-submit'),
            errorEl: document.getElementById('password-error'),
            form: document.getElementById('change-password-form')
        };
    }

    bindEvents() {
        this.elements.openBtn?.addEventListener('click', () => this.openModal());
        this.elements.closeBtn?.addEventListener('click', () => this.closeModal());
        this.elements.toggleBtn?.addEventListener('click', () => this.togglePasswordVisibility());
        
        this.elements.firstInput?.addEventListener('input', () => this.validatePasswords());
        this.elements.confirmInput?.addEventListener('input', () => this.validatePasswords());
        
        this.elements.form?.addEventListener('submit', (e) => this.handleSubmit(e));
        
        // Modal backdrop click
        this.elements.modal?.addEventListener('click', (e) => {
            if (e.target === this.elements.modal) this.closeModal();
        });
        
        // Keyboard navigation
        document.addEventListener('keydown', (e) => this.handleKeydown(e));
    }

    openModal() {
        if (!this.elements.modal) return;
        
        this.elements.modal.classList.remove('hidden');
        this.elements.modal.classList.add('flex');
        this.elements.modal.setAttribute('aria-hidden', 'false');
        
        // Focus first input for accessibility
        setTimeout(() => this.elements.firstInput?.focus(), 60);
    }

    closeModal() {
        if (!this.elements.modal) return;
        
        this.elements.modal.classList.add('hidden');
        this.elements.modal.classList.remove('flex');
        this.elements.modal.setAttribute('aria-hidden', 'true');
        
        // Reset form
        this.resetForm();
        
        try { 
            this.elements.openBtn?.focus(); 
        } catch (e) { 
            // ignore focus errors
        }
    }

    resetForm() {
        this.elements.form?.reset();
        
        if (this.elements.errorEl) {
            this.elements.errorEl.style.display = 'none';
        }
        
        if (this.elements.submitBtn) {
            this.elements.submitBtn.disabled = true;
            this.elements.submitBtn.setAttribute('aria-disabled', 'true');
        }
        
        // Reset input styling
        this.elements.firstInput?.classList.remove('border-red-500', 'border-green-500');
        this.elements.confirmInput?.classList.remove('border-red-500', 'border-green-500');
        
        // Reset password visibility
        if (this.elements.firstInput) {
            this.elements.firstInput.type = 'password';
        }
        
        if (this.elements.toggleBtn) {
            this.elements.toggleBtn.setAttribute('aria-label', 'Show password');
            const icon = this.elements.toggleBtn.querySelector('i');
            if (icon) {
                icon.setAttribute('data-lucide', 'eye');
                lucide.createIcons();
            }
        }
    }

    togglePasswordVisibility() {
        if (!this.elements.firstInput || !this.elements.toggleBtn) return;
        
        const icon = this.elements.toggleBtn.querySelector('i');
        
        if (this.elements.firstInput.type === 'password') {
            this.elements.firstInput.type = 'text';
            this.elements.toggleBtn.setAttribute('aria-label', 'Hide password');
            if (icon) {
                icon.setAttribute('data-lucide', 'eye-off');
                lucide.createIcons();
            }
        } else {
            this.elements.firstInput.type = 'password';
            this.elements.toggleBtn.setAttribute('aria-label', 'Show password');
            if (icon) {
                icon.setAttribute('data-lucide', 'eye');
                lucide.createIcons();
            }
        }
    }

    validatePasswords() {
        const p1 = this.elements.firstInput?.value || '';
        const p2 = this.elements.confirmInput?.value || '';
        
        // Clear previous styling
        this.elements.firstInput?.classList.remove('border-red-500', 'border-green-500');
        this.elements.confirmInput?.classList.remove('border-red-500', 'border-green-500');
        
        if (p1.length === 0 || p2.length === 0) {
            this.hideError();
            this.disableSubmit();
            return;
        }
        
        // Password strength validation
        if (p1.length < 8) {
            this.showError('Password must be at least 8 characters long.');
            this.elements.firstInput?.classList.add('border-red-500');
            this.disableSubmit();
            return;
        }
        
        if (p1 === p2) {
            this.hideError();
            this.elements.firstInput?.classList.add('border-green-500');
            this.elements.confirmInput?.classList.add('border-green-500');
            this.enableSubmit();
        } else {
            this.showError('Passwords do not match.');
            this.elements.confirmInput?.classList.add('border-red-500');
            this.disableSubmit();
        }
    }

    showError(message) {
        if (this.elements.errorEl) {
            this.elements.errorEl.textContent = message;
            this.elements.errorEl.style.display = 'block';
        }
    }

    hideError() {
        if (this.elements.errorEl) {
            this.elements.errorEl.style.display = 'none';
        }
    }

    enableSubmit() {
        if (this.elements.submitBtn) {
            this.elements.submitBtn.disabled = false;
            this.elements.submitBtn.setAttribute('aria-disabled', 'false');
        }
    }

    disableSubmit() {
        if (this.elements.submitBtn) {
            this.elements.submitBtn.disabled = true;
            this.elements.submitBtn.setAttribute('aria-disabled', 'true');
        }
    }

    async handleSubmit(e) {
        e.preventDefault();
        
        if (this.elements.submitBtn?.disabled) return;
        
        // Show loading state
        const originalText = this.elements.submitBtn.innerHTML;
        this.elements.submitBtn.disabled = true;
        this.elements.submitBtn.innerHTML = '<span>Changing...</span>';
        
        try {
            const formData = new FormData(this.elements.form);
            const response = await fetch(this.elements.form.action, {
                method: 'POST',
                body: formData
            });
            
            const data = await response.json();
            
            if (data.success) {
                this.notification.show('Password changed successfully!', 'success');
                this.closeModal();
            } else {
                this.notification.show(data.message || 'Failed to change password. Please try again.', 'error');
            }
        } catch (error) {
            console.error('Error:', error);
            this.notification.show('An error occurred. Please try again.', 'error');
        } finally {
            if (this.elements.submitBtn) {
                this.elements.submitBtn.disabled = false;
                this.elements.submitBtn.innerHTML = originalText;
            }
        }
    }

    handleKeydown(e) {
        if (e.key === 'Escape' && this.elements.modal?.classList.contains('flex')) {
            this.closeModal();
        }
        
        // Ctrl/Cmd + Enter to submit form
        if ((e.ctrlKey || e.metaKey) && e.key === 'Enter' && 
            this.elements.modal?.classList.contains('flex') && 
            !this.elements.submitBtn?.disabled) {
            this.elements.form?.dispatchEvent(new Event('submit'));
        }
        
        // Handle tab navigation within modal
        if (e.key === 'Tab' && this.elements.modal?.classList.contains('flex')) {
            this.handleTabNavigation(e);
        }
    }

    handleTabNavigation(e) {
        const focusableElements = this.elements.modal?.querySelectorAll('input, button');
        if (!focusableElements || focusableElements.length === 0) return;
        
        const firstElement = focusableElements[0];
        const lastElement = focusableElements[focusableElements.length - 1];

        if (e.shiftKey && document.activeElement === firstElement) {
            e.preventDefault();
            lastElement.focus();
        } else if (!e.shiftKey && document.activeElement === lastElement) {
            e.preventDefault();
            firstElement.focus();
        }
    }
}
