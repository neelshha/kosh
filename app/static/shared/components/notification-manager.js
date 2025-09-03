/**
 * Notification Manager
 * Handles all notification display and management
 */

class NotificationManager {
    constructor() {
        this.notifications = [];
    }

    show(message, type = 'success') {
        const notification = this.createNotification(message, type);
        document.body.appendChild(notification);
        this.notifications.push(notification);
        
        // Show notification with animation
        setTimeout(() => notification.classList.add('show'), 100);
        
        // Auto-hide after 3 seconds
        setTimeout(() => {
            this.hide(notification);
        }, 3000);
        
        return notification;
    }

    createNotification(message, type) {
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.textContent = message;
        
        // Add close button
        const closeBtn = document.createElement('button');
        closeBtn.innerHTML = '×';
        closeBtn.className = 'ml-2 text-lg font-bold opacity-70 hover:opacity-100';
        closeBtn.onclick = () => this.hide(notification);
        
        notification.appendChild(closeBtn);
        
        return notification;
    }

    hide(notification) {
        if (!notification || !notification.parentNode) return;
        
        notification.classList.remove('show');
        
        setTimeout(() => {
            if (notification.parentNode) {
                document.body.removeChild(notification);
            }
            
            // Remove from tracking array
            const index = this.notifications.indexOf(notification);
            if (index > -1) {
                this.notifications.splice(index, 1);
            }
        }, 300);
    }

    hideAll() {
        this.notifications.forEach(notification => this.hide(notification));
    }
}
