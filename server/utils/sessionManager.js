/**
 * Session Manager
 * 
 * Centralized session state management with TTL and sliding expiration.
 * Tracks active sessions, enforces timeouts, and provides lifecycle management.
 */

const crypto = require('crypto');

// Configuration (can be overridden via environment variables)
const SESSION_TIMEOUT = parseInt(process.env.SESSION_TIMEOUT) || 900000; // 15 minutes
const MAX_SESSION_LIFETIME = parseInt(process.env.MAX_SESSION_LIFETIME) || 86400000; // 24 hours
const CLEANUP_INTERVAL = parseInt(process.env.SESSION_CLEANUP_INTERVAL) || 300000; // 5 minutes

class SessionManager {
    constructor() {
        this._sessions = new Map();
        this._userSessions = new Map(); // userId -> Set of session tokens
        this._cleanupInterval = null;
        
        // Start periodic cleanup
        this._startCleanup();
    }
    
    /**
     * Create a new session
     * @param {number} userId - User ID
     * @param {string} token - JWT token
     * @param {Object} data - Additional session data
     * @returns {Object} - Session object
     */
    createSession(userId, token, data = {}) {
        const now = Date.now();
        const tokenHash = this._hashToken(token);
        
        const session = {
            userId,
            tokenHash,
            data,
            createdAt: now,
            lastActivity: now,
            expiresAt: now + SESSION_TIMEOUT,
            maxExpiresAt: now + MAX_SESSION_LIFETIME,
            ipAddress: data.ipAddress || null,
            userAgent: data.userAgent || null
        };
        
        // Store session
        this._sessions.set(tokenHash, session);
        
        // Track user's sessions
        if (!this._userSessions.has(userId)) {
            this._userSessions.set(userId, new Set());
        }
        this._userSessions.get(userId).add(tokenHash);
        
        return session;
    }
    
    /**
     * Get a session and refresh it (sliding expiration)
     * @param {string} token - JWT token
     * @returns {Object|null} - Session object or null if not found/expired
     */
    getSession(token) {
        const tokenHash = this._hashToken(token);
        const session = this._sessions.get(tokenHash);
        
        if (!session) {
            return null;
        }
        
        const now = Date.now();
        
        // Check if session has expired (inactivity timeout)
        if (now > session.expiresAt) {
            this.invalidateSession(token);
            return null;
        }
        
        // Check if session has exceeded max lifetime
        if (now > session.maxExpiresAt) {
            this.invalidateSession(token);
            return null;
        }
        
        // Refresh session (sliding expiration)
        session.lastActivity = now;
        session.expiresAt = now + SESSION_TIMEOUT;
        
        return session;
    }
    
    /**
     * Invalidate a specific session
     * @param {string} token - JWT token
     * @returns {boolean} - Success status
     */
    invalidateSession(token) {
        const tokenHash = this._hashToken(token);
        const session = this._sessions.get(tokenHash);
        
        if (!session) {
            return false;
        }
        
        // Remove from user's session set
        const userSessionSet = this._userSessions.get(session.userId);
        if (userSessionSet) {
            userSessionSet.delete(tokenHash);
            
            // Clean up empty sets
            if (userSessionSet.size === 0) {
                this._userSessions.delete(session.userId);
            }
        }
        
        // Remove session
        this._sessions.delete(tokenHash);
        
        return true;
    }
    
    /**
     * Invalidate all sessions for a user
     * @param {number} userId - User ID
     * @returns {number} - Number of sessions invalidated
     */
    invalidateUserSessions(userId) {
        const userSessionSet = this._userSessions.get(userId);
        
        if (!userSessionSet) {
            return 0;
        }
        
        let count = 0;
        for (const tokenHash of userSessionSet) {
            this._sessions.delete(tokenHash);
            count++;
        }
        
        this._userSessions.delete(userId);
        
        return count;
    }
    
    /**
     * Get all active sessions for a user
     * @param {number} userId - User ID
     * @returns {Array<Object>} - Array of session objects
     */
    getUserSessions(userId) {
        const userSessionSet = this._userSessions.get(userId);
        
        if (!userSessionSet) {
            return [];
        }
        
        const sessions = [];
        for (const tokenHash of userSessionSet) {
            const session = this._sessions.get(tokenHash);
            if (session) {
                sessions.push({
                    createdAt: session.createdAt,
                    lastActivity: session.lastActivity,
                    expiresAt: session.expiresAt,
                    ipAddress: session.ipAddress,
                    userAgent: session.userAgent
                });
            }
        }
        
        return sessions;
    }
    
    /**
     * Check if a session exists and is valid
     * @param {string} token - JWT token
     * @returns {boolean}
     */
    hasValidSession(token) {
        return this.getSession(token) !== null;
    }
    
    /**
     * Get total number of active sessions
     * @returns {number}
     */
    getActiveSessionCount() {
        return this._sessions.size;
    }
    
    /**
     * Get total number of active users with sessions
     * @returns {number}
     */
    getActiveUserCount() {
        return this._userSessions.size;
    }
    
    /**
     * Cleanup expired sessions
     * @returns {number} - Number of sessions cleaned up
     */
    cleanupExpired() {
        const now = Date.now();
        const expiredSessions = [];
        
        for (const [tokenHash, session] of this._sessions.entries()) {
            if (now > session.expiresAt || now > session.maxExpiresAt) {
                expiredSessions.push(tokenHash);
            }
        }
        
        for (const tokenHash of expiredSessions) {
            const session = this._sessions.get(tokenHash);
            if (session) {
                // Remove from user's session set
                const userSessionSet = this._userSessions.get(session.userId);
                if (userSessionSet) {
                    userSessionSet.delete(tokenHash);
                    if (userSessionSet.size === 0) {
                        this._userSessions.delete(session.userId);
                    }
                }
            }
            this._sessions.delete(tokenHash);
        }
        
        if (expiredSessions.length > 0) {
            console.log(`[SessionManager] Cleaned up ${expiredSessions.length} expired sessions`);
        }
        
        return expiredSessions.length;
    }
    
    /**
     * Hash a token for storage (prevents token exposure in memory dumps)
     * @private
     * @param {string} token - JWT token
     * @returns {string} - SHA-256 hash of token
     */
    _hashToken(token) {
        return crypto.createHash('sha256').update(token).digest('hex');
    }
    
    /**
     * Start periodic cleanup of expired sessions
     * @private
     */
    _startCleanup() {
        if (this._cleanupInterval) {
            return;
        }
        
        this._cleanupInterval = setInterval(() => {
            this.cleanupExpired();
        }, CLEANUP_INTERVAL);
        
        // Don't prevent Node.js from exiting
        if (this._cleanupInterval.unref) {
            this._cleanupInterval.unref();
        }
    }
    
    /**
     * Stop the cleanup interval and clear all sessions
     */
    shutdown() {
        if (this._cleanupInterval) {
            clearInterval(this._cleanupInterval);
            this._cleanupInterval = null;
        }
        
        this._sessions.clear();
        this._userSessions.clear();
    }
}

// Create singleton instance
const globalSessionManager = new SessionManager();

module.exports = {
    SessionManager,
    globalSessionManager,
    SESSION_TIMEOUT,
    MAX_SESSION_LIFETIME
};
