/**
 * Dashboard Main Module
 * Handles dashboard initialization and coordination between modules
 */

class Dashboard {
    constructor() {
        this.socket = null;
        this.modules = {};
        this.init();
    }

    init() {
        // Initialize Socket.IO
        this.initSocket();
        
        // Initialize modules
        this.initModules();
        
        // Initialize Lucide icons
        lucide.createIcons();
    }

    initSocket() {
        this.socket = io();
        
        // Join dashboard updates room when connecting
        this.socket.on('connect', () => {
            this.socket.emit('join_dashboard');
        });
        
        // Handle file upload events
        this.socket.on('file_uploaded', (data) => {
            console.log('File uploaded:', data);
            this.modules.fileManager?.refreshFileList();
            this.modules.notification?.show(`New file(s) uploaded by ${data.uploader}`, 'success');
        });
        
        // Handle file deletion events
        this.socket.on('file_deleted', (data) => {
            console.log('File deleted:', data);
            this.modules.fileManager?.refreshFileList();
            this.modules.notification?.show(`File ${data.filename} was deleted`, 'info');
        });
    }

    initModules() {
        // Initialize notification system
        this.modules.notification = new NotificationManager();
        
        // Initialize file manager
        this.modules.fileManager = new DashboardFileManager(this.modules.notification);
        
        // Initialize upload manager
        this.modules.uploadManager = new UploadManager(this.modules.notification);
        
        // Initialize password manager
        this.modules.passwordManager = new PasswordManager(this.modules.notification);
    }

    getSocket() {
        return this.socket;
    }

    getModule(name) {
        return this.modules[name];
    }
}

// Initialize dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.dashboard = new Dashboard();
});
