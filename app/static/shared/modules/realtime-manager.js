/**
 * Real-time synchronization functionality for admin dashboard
 */

class RealTimeManager {
    constructor() {
        this.socket = null;
        this.usersTable = null;
        this.policiesTable = null;
        this.auditTable = null;
        this.attributesContainer = null;
    }

    /**
     * Initialize real-time functionality
     */
    initialize() {
        if (typeof io === 'undefined') {
            console.warn('Socket.IO not available');
            return;
        }

        this.socket = io();
        this.cacheDOMElements();
        this.setupSocketEvents();
        this.setupConnectionIndicator();
    }

    /**
     * Cache DOM elements for performance
     */
    cacheDOMElements() {
        this.usersTable = document.querySelector('#users-tbody');
        this.policiesTable = document.querySelector('#policies-table tbody');
        this.auditTable = document.querySelector('#audit-tbody');
        this.attributesContainer = document.querySelector('.flex.flex-wrap.gap-3.mt-2');
    }

    /**
     * Setup Socket.IO event handlers
     */
    setupSocketEvents() {
        if (!this.socket) return;

        // Join admin room
        this.socket.emit('join_admin');

        // Connection events
        this.socket.on('joined_admin', (data) => {
            console.log('✅ Connected to admin real-time updates');
        });

        this.socket.on('connect', () => {
            console.log('🔌 Connected to server');
            this.updateConnectionStatus(true);
        });

        this.socket.on('disconnect', () => {
            console.log('🔌 Disconnected from server');
            toastManager.show('Connection lost - trying to reconnect...', 'warning');
            this.updateConnectionStatus(false);
        });

        this.socket.on('reconnect', () => {
            console.log('🔌 Reconnected to server');
            toastManager.show('Reconnected! Real-time updates restored', 'success');
            this.socket.emit('join_admin'); // Rejoin admin room
        });

        // User management events
        this.socket.on('user_added', (data) => {
            console.log('👤 User added:', data);
            this.addUserToTable(data.user, data.attributes);
            this.updateUserCountStatus();
        });

        this.socket.on('user_updated', (data) => {
            console.log('👤 User updated:', data);
            this.updateUserInTable(data.user, data.attributes);
        });

        this.socket.on('user_deleted', (data) => {
            console.log('👤 User deleted:', data);
            this.removeUserFromTable(data.user);
            toastManager.show(`User "${data.user}" deleted`, 'warning');
            this.updateUserCountStatus();
        });

        this.socket.on('users_bulk_deleted', (data) => {
            console.log('👥 Users bulk deleted:', data);
            data.users.forEach(user => this.removeUserFromTable(user));
            toastManager.show(`${data.users.length} users deleted`, 'warning');
            this.updateUserCountStatus();
        });

        this.socket.on('users_bulk_attrs_updated', (data) => {
            console.log('👥 Users bulk attributes updated:', data);
            data.users.forEach(user => this.updateUserInTable(user, data.attributes));
        });

        // Policy management events
        this.socket.on('policy_added', (data) => {
            console.log('📄 Policy added:', data);
            this.addPolicyToTable(data.file, data.policy);
            toastManager.show(`Policy for "${data.file}" added`, 'success');
        });

        this.socket.on('policy_updated', (data) => {
            console.log('📄 Policy updated:', data);
            this.updatePolicyInTable(data.file, data.policy);
            toastManager.show(`Policy for "${data.file}" updated`, 'info');
        });

        this.socket.on('policy_deleted', (data) => {
            console.log('📄 Policy deleted:', data);
            this.removePolicyFromTable(data.file);
            toastManager.show(`Policy for "${data.file}" deleted`, 'warning');
        });

        this.socket.on('policies_bulk_deleted', (data) => {
            console.log('📄 Policies bulk deleted:', data);
            data.files.forEach(file => this.removePolicyFromTable(file));
            toastManager.show(`${data.files.length} policies deleted`, 'warning');
        });

        // Audit log events
        this.socket.on('audit_log_added', (data) => {
            console.log('📋 Audit log added:', data);
            this.addAuditLogToTable(data);
        });

        // Attribute events
        this.socket.on('attribute_added', (data) => {
            console.log('🏷️ Attribute added:', data);
            this.addAttributeToUI(data.attribute);
            toastManager.show(`Attribute "${data.attribute}" added`, 'success');
            this.updateGlobalAttributes(data.attribute, 'add');
        });

        this.socket.on('attribute_removed', (data) => {
            console.log('🏷️ Attribute removed:', data);
            this.removeAttributeFromUI(data.attribute);
            toastManager.show(`Attribute "${data.attribute}" removed`, 'warning');
            this.updateGlobalAttributes(data.attribute, 'remove');
        });
    }

    /**
     * Update connection status indicator
     * @param {boolean} connected - Connection status
     */
    updateConnectionStatus(connected) {
        const indicator = document.getElementById('connection-indicator');
        if (indicator) {
            if (connected) {
                indicator.className = 'w-3 h-3 bg-green-500 rounded-full';
                indicator.title = 'Connected';
            } else {
                indicator.className = 'w-3 h-3 bg-red-500 rounded-full';
                indicator.title = 'Disconnected';
            }
        }
    }

    /**
     * Setup connection status indicator
     */
    setupConnectionIndicator() {
        window.addEventListener('load', () => {
            const navbar = document.querySelector('nav .flex.items-center.space-x-4');
            if (navbar) {
                const indicator = document.createElement('div');
                indicator.className = 'flex items-center space-x-2';
                indicator.innerHTML = `
                    <div id="connection-indicator" class="w-3 h-3 bg-gray-500 rounded-full animate-pulse" title="Connecting..."></div>
                    <span class="text-xs text-notion-text-secondary">Real-time</span>
                `;
                navbar.insertBefore(indicator, navbar.firstChild);
            }
        });
    }

    /**
     * Add user to table (real-time)
     * @param {string} user - Username
     * @param {string|Array} attributes - User attributes
     */
    addUserToTable(user, attributes) {
        if (!this.usersTable) return;

        const attributesStr = Array.isArray(attributes) ? attributes.join(', ') : attributes;
        const tr = document.createElement('tr');
        tr.className = 'hover:bg-notion-hover transition-colors duration-150';

        tr.innerHTML = `
            <td class="px-2 py-3">
                <input type="checkbox" name="user_bulk" value="${uiHelpers.escapeHtml(user)}" 
                    aria-label="Select user ${uiHelpers.escapeHtml(user)}">
            </td>
            <td class="px-4 py-3 font-medium text-notion-text">${uiHelpers.escapeHtml(user)}</td>
            <td class="px-4 py-3">${uiHelpers.formatAttributesAsHtml(attributesStr)}</td>
            <td class="px-4 py-3">
                <div class="flex flex-col sm:flex-row items-start space-y-1 sm:space-y-0 sm:space-x-2">
                    <button type="button" class="btn-action btn-action-edit edit-user-link" 
                        data-user='${uiHelpers.escapeHtml(user)}' data-attrs='${uiHelpers.escapeHtml(attributesStr)}' 
                        aria-label="Edit user ${uiHelpers.escapeHtml(user)}" title="Edit user">
                        <i data-lucide="edit-2" class="w-4 h-4"></i>
                    </button>
                    <button type="button" class="btn-action btn-action-delete delete-user-link" 
                        data-user='${uiHelpers.escapeHtml(user)}' 
                        aria-label="Delete user ${uiHelpers.escapeHtml(user)}" title="Delete user">
                        <i data-lucide="trash-2" class="w-4 h-4"></i>
                    </button>
                </div>
            </td>
        `;

        this.usersTable.insertBefore(tr, this.usersTable.firstChild);
        adminLinks.setup();
        setTimeout(uiHelpers.reinitializeLucideIcons, 10);
    }

    /**
     * Update user in table (real-time)
     * @param {string} user - Username
     * @param {string|Array} attributes - User attributes
     */
    updateUserInTable(user, attributes) {
        if (!this.usersTable) return;

        const inputs = Array.from(this.usersTable.querySelectorAll('input[name="user_bulk"]'));
        const match = inputs.find(i => i.value === user);
        if (match) {
            const tr = match.closest('tr');
            if (tr) {
                const attributesStr = Array.isArray(attributes) ? attributes.join(', ') : attributes;

                const attributesCell = tr.children[2];
                attributesCell.innerHTML = uiHelpers.formatAttributesAsHtml(attributesStr);

                const editBtn = tr.querySelector('.edit-user-link');
                if (editBtn) {
                    editBtn.setAttribute('data-attrs', attributesStr);
                }

                uiHelpers.refreshTailwindStyles(tr);
            }
        }
    }

    /**
     * Remove user from table (real-time)
     * @param {string} user - Username
     */
    removeUserFromTable(user) {
        if (!this.usersTable) return;

        const inputs = Array.from(this.usersTable.querySelectorAll('input[name="user_bulk"]'));
        const match = inputs.find(i => i.value === user);
        if (match) {
            const tr = match.closest('tr');
            if (tr) tr.remove();
        }
    }

    /**
     * Add policy to table (real-time)
     * @param {string} file - Filename
     * @param {string} policy - Policy string
     */
    addPolicyToTable(file, policy) {
        if (!this.policiesTable) return;

        const tr = document.createElement('tr');
        tr.className = 'hover:bg-notion-hover transition-colors duration-150';

        tr.innerHTML = `
            <td class="px-2 py-3">
                <input type="checkbox" name="policy_bulk" value="${uiHelpers.escapeHtml(file)}" 
                    aria-label="Select policy ${uiHelpers.escapeHtml(file)}">
            </td>
            <td class="px-4 py-3 font-medium text-notion-text">${uiHelpers.escapeHtml(file)}</td>
            <td class="px-4 py-3">${uiHelpers.escapeHtml(policy)}</td>
            <td class="px-4 py-3">N/A</td>
            <td class="px-4 py-3">
                <div class="flex flex-col sm:flex-row items-start space-y-1 sm:space-y-0 sm:space-x-2">
                    <button type="button" class="btn-action btn-action-edit edit-policy-link" 
                        data-file='${uiHelpers.escapeHtml(file)}' data-policy='${uiHelpers.escapeHtml(policy)}' 
                        aria-label="Edit policy ${uiHelpers.escapeHtml(file)}" title="Edit policy">
                        <i data-lucide="edit-2" class="w-4 h-4"></i>
                    </button>
                    <button type="button" class="btn-action btn-action-delete" 
                        onclick="policyManager.delete('${uiHelpers.escapeHtml(file)}')" 
                        aria-label="Delete policy ${uiHelpers.escapeHtml(file)}" title="Delete policy">
                        <i data-lucide="trash-2" class="w-4 h-4"></i>
                    </button>
                </div>
            </td>
        `;

        this.policiesTable.insertBefore(tr, this.policiesTable.firstChild);
        adminLinks.setup();
        setTimeout(uiHelpers.reinitializeLucideIcons, 10);
    }

    /**
     * Update policy in table (real-time)
     * @param {string} file - Filename
     * @param {string} policy - Policy string
     */
    updatePolicyInTable(file, policy) {
        if (!this.policiesTable) return;

        const inputs = Array.from(this.policiesTable.querySelectorAll('input[name="policy_bulk"]'));
        const match = inputs.find(i => i.value === file);
        if (match) {
            const tr = match.closest('tr');
            if (tr) {
                const policyCell = tr.children[2];
                policyCell.textContent = policy;

                const editBtn = tr.querySelector('.edit-policy-link');
                if (editBtn) {
                    editBtn.setAttribute('data-policy', policy);
                }

                uiHelpers.refreshTailwindStyles(tr);
            }
        }
    }

    /**
     * Remove policy from table (real-time)
     * @param {string} file - Filename
     */
    removePolicyFromTable(file) {
        if (!this.policiesTable) return;

        const inputs = Array.from(this.policiesTable.querySelectorAll('input[name="policy_bulk"]'));
        const match = inputs.find(i => i.value === file);
        if (match) {
            const tr = match.closest('tr');
            if (tr) tr.remove();
        }
    }

    /**
     * Add audit log to table (real-time)
     * @param {Object} logEntry - Log entry data
     */
    addAuditLogToTable(logEntry) {
        if (!this.auditTable) return;

        const tr = document.createElement('tr');
        tr.className = 'hover:bg-notion-hover transition';

        tr.innerHTML = `
            <td class="px-4 py-2">${uiHelpers.escapeHtml(logEntry.time)}</td>
            <td class="px-4 py-2">${uiHelpers.escapeHtml(logEntry.user)}</td>
            <td class="px-4 py-2">${uiHelpers.escapeHtml(logEntry.action)}</td>
            <td class="px-4 py-2">${uiHelpers.escapeHtml(logEntry.details)}</td>
        `;

        this.auditTable.insertBefore(tr, this.auditTable.firstChild);

        // Limit audit log entries to prevent memory issues (keep latest 100)
        const rows = this.auditTable.querySelectorAll('tr');
        if (rows.length > 100) {
            for (let i = 100; i < rows.length; i++) {
                rows[i].remove();
            }
        }
    }

    /**
     * Add attribute to UI (real-time)
     * @param {string} attribute - Attribute name
     */
    addAttributeToUI(attribute) {
        if (!this.attributesContainer) return;

        const span = document.createElement('span');
        span.className = 'bg-notion-accent/20 text-notion-accent px-3 py-2 rounded-full flex items-center shadow-sm transition-all duration-150 hover:bg-notion-accent/30';

        span.innerHTML = `
            <span class="mr-2">${uiHelpers.escapeHtml(attribute)}</span>
            <button type="button"
                class="ml-1 px-2 py-1 rounded-full bg-notion-card text-notion-text-secondary hover:bg-notion-hover hover:text-white transition"
                onclick="attributeManager.remove('${uiHelpers.escapeHtml(attribute)}')"
                aria-label="Remove attribute ${uiHelpers.escapeHtml(attribute)}">
                &times;
            </button>
        `;

        this.attributesContainer.appendChild(span);
    }

    /**
     * Remove attribute from UI (real-time)
     * @param {string} attribute - Attribute name
     */
    removeAttributeFromUI(attribute) {
        if (!this.attributesContainer) return;

        const spans = this.attributesContainer.querySelectorAll('span');
        spans.forEach(span => {
            const textSpan = span.querySelector('span');
            if (textSpan && textSpan.textContent.trim() === attribute) {
                span.remove();
            }
        });
    }

    /**
     * Update global attributes array
     * @param {string} attribute - Attribute name
     * @param {string} action - 'add' or 'remove'
     */
    updateGlobalAttributes(attribute, action) {
        if (!window.allAttributes) window.allAttributes = [];

        if (action === 'add') {
            if (!window.allAttributes.includes(attribute)) {
                window.allAttributes.push(attribute);
                window.allAttributes.sort();
            }
        } else if (action === 'remove') {
            const index = window.allAttributes.indexOf(attribute);
            if (index > -1) {
                window.allAttributes.splice(index, 1);
            }
        }
    }

    /**
     * Update user count status
     */
    updateUserCountStatus() {
        setTimeout(() => {
            if (userManager) {
                userManager.filter();
            }
        }, 10);
    }
}

// Global real-time manager instance
const realTimeManager = new RealTimeManager();
