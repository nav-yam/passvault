/**
 * Memory Cleanup and Secure Data Management Utility
 * 
 * Provides functions and classes to securely handle sensitive data in memory.
 * Implements zeroization, auto-cleanup, and TTL-based key management.
 */

const crypto = require('crypto');

/**
 * Zeroizes a buffer by overwriting it with zeros
 * @param {Buffer} buffer - The buffer to zeroize
 * @returns {Buffer} - The zeroized buffer (for chaining)
 */
function zeroizeBuffer(buffer) {
    if (!buffer || !Buffer.isBuffer(buffer)) {
        return buffer;
    }
    
    // Overwrite with zeros
    buffer.fill(0);
    
    // Additional pass with random data for extra security
    crypto.randomFillSync(buffer);
    
    // Final pass with zeros
    buffer.fill(0);
    
    return buffer;
}

/**
 * Zeroizes a string by converting to buffer, overwriting, and returning null
 * @param {string} str - The string to zeroize
 * @returns {null}
 */
function zeroizeString(str) {
    if (typeof str !== 'string') {
        return null;
    }
    
    // Convert to buffer and zeroize
    const buffer = Buffer.from(str, 'utf8');
    zeroizeBuffer(buffer);
    
    return null;
}

/**
 * SecureString class - Auto-zeroizing string wrapper for sensitive data
 * Usage: const securePassword = new SecureString('my-password', 60000); // 1 minute TTL
 */
class SecureString {
    constructor(value, ttlMs = 300000) { // Default 5 minutes
        this._buffer = Buffer.from(value, 'utf8');
        this._ttl = ttlMs;
        this._createdAt = Date.now();
        this._accessed = 0;
        
        // Auto-cleanup after TTL
        if (ttlMs > 0) {
            this._timeout = setTimeout(() => {
                this.destroy();
            }, ttlMs);
        }
    }
    
    /**
     * Get the string value
     * @returns {string|null} - The value or null if destroyed
     */
    getValue() {
        if (this.isDestroyed()) {
            return null;
        }
        
        this._accessed++;
        return this._buffer.toString('utf8');
    }
    
    /**
     * Check if the secure string has been destroyed
     * @returns {boolean}
     */
    isDestroyed() {
        return this._buffer === null;
    }
    
    /**
     * Check if TTL has expired
     * @returns {boolean}
     */
    isExpired() {
        if (this._ttl <= 0) return false;
        return (Date.now() - this._createdAt) > this._ttl;
    }
    
    /**
     * Destroy and zeroize the secure string
     */
    destroy() {
        if (this._buffer) {
            zeroizeBuffer(this._buffer);
            this._buffer = null;
        }
        
        if (this._timeout) {
            clearTimeout(this._timeout);
            this._timeout = null;
        }
    }
    
    /**
     * Get metadata about the secure string
     * @returns {Object}
     */
    getMetadata() {
        return {
            createdAt: this._createdAt,
            ttl: this._ttl,
            accessed: this._accessed,
            isDestroyed: this.isDestroyed(),
            isExpired: this.isExpired()
        };
    }
}

/**
 * KeyManager class - Secure storage for encryption keys with TTL
 * Automatically zeroizes keys after timeout and provides lifecycle management
 */
class KeyManager {
    constructor() {
        this._keys = new Map();
        this._cleanupInterval = null;
        
        // Start periodic cleanup (every 60 seconds)
        this._startCleanup();
    }
    
    /**
     * Store an encryption key with TTL
     * @param {string} keyId - Unique identifier for the key
     * @param {Buffer|string} key - The encryption key
     * @param {number} ttlMs - Time-to-live in milliseconds (default: 5 minutes)
     * @returns {boolean} - Success status
     */
    storeKey(keyId, key, ttlMs = 300000) {
        try {
            // Clear existing key if present
            this.clearKey(keyId);
            
            // Convert to buffer if string
            const keyBuffer = Buffer.isBuffer(key) ? Buffer.from(key) : Buffer.from(key, 'hex');
            
            // Create secure storage entry
            const entry = {
                buffer: keyBuffer,
                createdAt: Date.now(),
                ttl: ttlMs,
                accessed: 0,
                timeout: null
            };
            
            // Set auto-cleanup timeout
            if (ttlMs > 0) {
                entry.timeout = setTimeout(() => {
                    this.clearKey(keyId);
                }, ttlMs);
            }
            
            this._keys.set(keyId, entry);
            return true;
        } catch (error) {
            console.error('Failed to store key:', error.message);
            return false;
        }
    }
    
    /**
     * Retrieve an encryption key
     * @param {string} keyId - Unique identifier for the key
     * @returns {Buffer|null} - The key buffer or null if not found/expired
     */
    retrieveKey(keyId) {
        const entry = this._keys.get(keyId);
        
        if (!entry) {
            return null;
        }
        
        // Check if expired
        if (entry.ttl > 0 && (Date.now() - entry.createdAt) > entry.ttl) {
            this.clearKey(keyId);
            return null;
        }
        
        entry.accessed++;
        return entry.buffer;
    }
    
    /**
     * Clear and zeroize a specific key
     * @param {string} keyId - Unique identifier for the key
     * @returns {boolean} - Success status
     */
    clearKey(keyId) {
        const entry = this._keys.get(keyId);
        
        if (!entry) {
            return false;
        }
        
        // Clear timeout
        if (entry.timeout) {
            clearTimeout(entry.timeout);
        }
        
        // Zeroize the key buffer
        zeroizeBuffer(entry.buffer);
        
        // Remove from map
        this._keys.delete(keyId);
        
        return true;
    }
    
    /**
     * Clear all stored keys
     * @returns {number} - Number of keys cleared
     */
    clearAll() {
        let count = 0;
        
        for (const keyId of this._keys.keys()) {
            if (this.clearKey(keyId)) {
                count++;
            }
        }
        
        return count;
    }
    
    /**
     * Get metadata about a stored key
     * @param {string} keyId - Unique identifier for the key
     * @returns {Object|null}
     */
    getKeyMetadata(keyId) {
        const entry = this._keys.get(keyId);
        
        if (!entry) {
            return null;
        }
        
        return {
            createdAt: entry.createdAt,
            ttl: entry.ttl,
            accessed: entry.accessed,
            isExpired: entry.ttl > 0 && (Date.now() - entry.createdAt) > entry.ttl,
            hasBuffer: !!entry.buffer
        };
    }
    
    /**
     * Get list of all key IDs
     * @returns {Array<string>}
     */
    getAllKeyIds() {
        return Array.from(this._keys.keys());
    }
    
    /**
     * Start periodic cleanup of expired keys
     * @private
     */
    _startCleanup() {
        if (this._cleanupInterval) {
            return;
        }
        
        this._cleanupInterval = setInterval(() => {
            this._cleanupExpired();
        }, 60000); // Run every 60 seconds
        
        // Don't prevent Node.js from exiting
        if (this._cleanupInterval.unref) {
            this._cleanupInterval.unref();
        }
    }
    
    /**
     * Cleanup expired keys
     * @private
     */
    _cleanupExpired() {
        const now = Date.now();
        const expiredKeys = [];
        
        for (const [keyId, entry] of this._keys.entries()) {
            if (entry.ttl > 0 && (now - entry.createdAt) > entry.ttl) {
                expiredKeys.push(keyId);
            }
        }
        
        for (const keyId of expiredKeys) {
            this.clearKey(keyId);
        }
        
        if (expiredKeys.length > 0) {
            console.log(`[KeyManager] Cleaned up ${expiredKeys.length} expired keys`);
        }
    }
    
    /**
     * Stop the cleanup interval and clear all keys
     */
    shutdown() {
        if (this._cleanupInterval) {
            clearInterval(this._cleanupInterval);
            this._cleanupInterval = null;
        }
        
        this.clearAll();
    }
}

// Create singleton instance
const globalKeyManager = new KeyManager();

module.exports = {
    zeroizeBuffer,
    zeroizeString,
    SecureString,
    KeyManager,
    globalKeyManager
};
