/**
 * Clipboard Manager Utility (Client-Side)
 * 
 * Auto-clears clipboard after password copy operations.
 * Provides manual clear option and tracks clipboard state
 */

// Configuration
const CLIPBOARD_CLEAR_TIME = process.env.CLIPBOARD_CLEAR_TIME || 30000; // 30 seconds

class ClipboardManager {
    constructor() {
        this.clearTimeouts = [];
        this.trackedData = new Set();
    }
    
    /**
     * Copy text to clipboard with auto-clear
     * @param {string} text - Text to copy
     * @param {number} clearAfterMs - Time to wait before clearing (default: 30s)
     * @returns {Promise<boolean>} - Success status
     */
    async copyWithAutoClear(text, clearAfterMs = CLIPBOARD_CLEAR_TIME) {
        try {
            // Copy to clipboard
            await navigator.clipboard.writeText(text);
            
            //Track this data
            this.trackedData.add(text);
            
            console.log(`Copied to clipboard. Will auto-clear in ${clearAfterMs / 1000} seconds.`);
            
            // Set timeout to clear
            const timeoutId = setTimeout(async () => {
                await this.clearIfMatches(text);
            }, clearAfterMs);
            
            this.clearTimeouts.push(timeoutId);
            
            return true;
        } catch (error) {
            console.error('Failed to copy to clipboard:', error);
            return false;
        }
    }
    
    /**
     * Clear clipboard if it still contains our tracked data
     * @param {string} expectedText - The text we expect to find
     * @returns {Promise<boolean>} - True if clipboard was cleared
     */
    async clearIfMatches(expectedText) {
        try {
            // Read current clipboard content
            const currentText = await navigator.clipboard.readText();
            
            // Only clear if clipboard still contains our data
            if (currentText === expectedText && this.trackedData.has(expectedText)) {
                await navigator.clipboard.writeText('');
                this.trackedData.delete(expectedText);
                console.log('🗑️  Auto-cleared password from clipboard');
                return true;
            }
            
            // If content changed, don't clear (user copied something else)
            this.trackedData.delete(expectedText);
            return false;
        } catch (error) {
            console.error('Failed to clear clipboard:', error);
            return false;
        }
    }
    
    /**
     * Manually clear clipboard immediately
     * @returns {Promise<boolean>}
     */
    async clearNow() {
        try {
            await navigator.clipboard.writeText('');
            
            // Clear all timeouts
            for (const timeoutId of this.clearTimeouts) {
                clearTimeout(timeoutId);
            }
            this.clearTimeouts = [];
            this.trackedData.clear();
            
            console.log('Clipboard cleared manually');
            return true;
        } catch (error) {
            console.error('Failed to clear clipboard:', error);
            return false;
        }
    }
    
    /**
     * Cancel all pending clear operations
     */
    cancelAllClears() {
        for (const timeoutId of this.clearTimeouts) {
            clearTimeout(timeoutId);
        }
        this.clearTimeouts = [];
        this.trackedData.clear();
        console.log('Cancelled all pending clipboard clears');
    }
    
    /**
     * Get count of pending clear operations
     * @returns {number}
     */
    getPendingClearCount() {
        return this.clearTimeouts.length;
    }
}

// Export singleton instance
if (typeof module !== 'undefined' && module.exports) {
    module.exports = new ClipboardManager();
} else if (typeof window !== 'undefined') {
    window.clipboardManager = new ClipboardManager();
}
