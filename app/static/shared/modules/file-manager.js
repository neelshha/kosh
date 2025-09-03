/**
 * File management functionality for admin dashboard
 */

class FileManager {
    /**
     * Delete a file
     * @param {string} filename - Filename to delete
     */
    async delete(filename) {
        if (!confirm(`Delete file "${filename}"?`)) return;

        try {
            const response = await fetch('/admin/delete_file', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ filename })
            });

            const result = await response.json();
            if (result.success) {
                window.location.reload();
            } else {
                toastManager.show('Error deleting file', 'error');
            }
        } catch (error) {
            toastManager.show('Network error', 'error');
        }
    }
}

// Global file manager instance
const fileManager = new FileManager();
