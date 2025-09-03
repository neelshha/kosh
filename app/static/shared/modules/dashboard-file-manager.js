/**
 * Dashboard File Manager
 * Handles file display, deletion, and real-time updates for the dashboard
 */

class DashboardFileManager {
    constructor(notificationManager) {
        this.notification = notificationManager;
        this.init();
    }

    init() {
        // Bind delete file functions to global scope for template compatibility
        window.deleteFile = this.deleteFile.bind(this);
    }

    async refreshFileList() {
        try {
            const response = await fetch('/api/files');
            const data = await response.json();
            
            if (data.files) {
                this.updateFileDisplay(data.files);
            }
        } catch (error) {
            console.error('Error refreshing file list:', error);
        }
    }

    updateFileDisplay(files) {
        const fileSection = document.querySelector('.space-y-3');
        const noFilesSection = document.querySelector('.text-center.py-16');
        const parentContainer = fileSection ? fileSection.parentElement : (noFilesSection ? noFilesSection.parentElement : null);
        
        if (!parentContainer) return;
        
        // Clear existing content
        parentContainer.innerHTML = '';
        
        if (files.length === 0) {
            this.renderNoFilesView(parentContainer);
        } else {
            this.renderFilesView(parentContainer, files);
        }
        
        // Reinitialize Lucide icons
        lucide.createIcons();
    }

    renderNoFilesView(container) {
        container.innerHTML = `
            <div class="text-center py-16">
                <div class="w-16 h-16 bg-notion-border rounded-full flex items-center justify-center mx-auto mb-4">
                    <i data-lucide="file-plus" class="w-8 h-8 text-notion-text-secondary"></i>
                </div>
                <h4 class="text-lg font-medium text-notion-text mb-2 font-title">No files yet</h4>
                <p class="text-notion-text-secondary text-sm mb-6 font-content">Upload your first file to get started with secure encryption</p>
                <button onclick="document.getElementById('file-input').click()" class="btn-primary px-4 py-2 rounded-lg text-white text-sm font-medium flex items-center space-x-2 mx-auto">
                    <i data-lucide="upload" class="w-4 h-4"></i>
                    <span>Upload your first file</span>
                </button>
            </div>
        `;
    }

    renderFilesView(container, files) {
        const filesContainer = document.createElement('div');
        filesContainer.className = 'space-y-3';
        
        files.forEach(file => {
            const fileItem = this.createFileItem(file);
            filesContainer.appendChild(fileItem);
        });
        
        container.appendChild(filesContainer);
    }

    createFileItem(file) {
        const fileItem = document.createElement('div');
        fileItem.className = 'file-item p-4 rounded-lg border border-notion-border bg-notion-bg/50';
        
        const senderInfo = this.getSenderInfo(file);
        const deleteButton = this.getDeleteButton(file);
        
        fileItem.innerHTML = `
            <div class="flex items-center justify-between">
                <div class="flex items-center space-x-3">
                    <div class="w-8 h-8 bg-notion-accent/10 rounded-lg flex items-center justify-center">
                        <i data-lucide="file" class="w-4 h-4 text-notion-accent"></i>
                    </div>
                    <div>
                        <h4 class="text-notion-text font-medium filename" title="${file.filename.replace('.enc', '')}">${file.filename.replace('.enc', '')}</h4>
                        <p class="text-notion-text-secondary text-xs">${senderInfo}</p>
                    </div>
                </div>
                <div class="flex items-center space-x-2">
                    <a href="/download/${file.filename}" class="btn-primary px-4 py-2 rounded-lg text-white text-sm font-medium flex items-center space-x-2">
                        <i data-lucide="download" class="w-4 h-4"></i>
                        <span>Download</span>
                    </a>
                    ${deleteButton}
                </div>
            </div>
        `;
        
        return fileItem;
    }

    getSenderInfo(file) {
        if (file.sender) {
            if (file.is_owner) {
                return '<span class="text-green-400">Uploaded by you</span>';
            } else {
                return `Uploaded by: ${file.sender}`;
            }
        } else {
            return '<span class="text-orange-400">Uploader unknown</span>';
        }
    }

    getDeleteButton(file) {
        if (!file.is_owner) return '';
        
        return `
            <button onclick="deleteFile('${file.filename}')" class="bg-red-600 hover:bg-red-700 px-4 py-2 rounded-lg text-white text-sm font-medium flex items-center space-x-2 transition-colors">
                <i data-lucide="trash-2" class="w-4 h-4"></i>
                <span>Delete</span>
            </button>
        `;
    }

    async deleteFile(filename) {
        if (!confirm(`Are you sure you want to delete "${filename.replace('.enc', '')}"? This action cannot be undone.`)) {
            return;
        }

        try {
            const response = await fetch('/delete_file', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ filename: filename })
            });

            const data = await response.json();
            
            if (data.success) {
                this.notification.show(`File "${filename.replace('.enc', '')}" deleted successfully`, 'success');
            } else {
                this.notification.show(`Error deleting file: ${data.error}`, 'error');
            }
        } catch (error) {
            console.error('Error:', error);
            this.notification.show('Error deleting file. Please try again.', 'error');
        }
    }
}
