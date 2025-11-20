/**
 * CSRF Protection Middleware
 * Prevents Cross-Site Request Forgery attacks
 */

const crypto = require('crypto');

// Store CSRF tokens in memory (in production, use Redis or similar)
const csrfTokens = new Map();
const TOKEN_EXPIRY = 24 * 60 * 60 * 1000; // 24 hours

/**
 * Generates a CSRF token
 */
function generateCsrfToken() {
    return crypto.randomBytes(32).toString('hex');
}

/**
 * Creates and stores a CSRF token for the session
 */
function createCsrfToken(req, res, next) {
    const token = generateCsrfToken();
    const expiresAt = Date.now() + TOKEN_EXPIRY;
    
    // Store token with user ID or IP as key
    const key = req.user ? `user_${req.user.userId}` : `ip_${req.ip}`;
    csrfTokens.set(key, { token, expiresAt });
    
    // Set token in response header for client to read
    res.setHeader('X-CSRF-Token', token);
    
    // Also set in response body for JSON responses
    if (req.method === 'GET' && req.path.startsWith('/api/')) {
        // For GET requests, we'll include it in the response
        req.csrfToken = token;
    }
    
    next();
}

/**
 * Validates CSRF token from request
 */
function validateCsrfToken(req, res, next) {
    // Skip CSRF for GET, HEAD, OPTIONS requests (read-only)
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
        return next();
    }

    // Get token from header (preferred) or body
    const token = req.headers['x-csrf-token'] || req.body._csrf;
    
    if (!token) {
        return res.status(403).json({ 
            error: 'CSRF token missing. Please refresh the page and try again.' 
        });
    }

    // Get stored token
    const key = req.user ? `user_${req.user.userId}` : `ip_${req.ip}`;
    const stored = csrfTokens.get(key);

    if (!stored) {
        return res.status(403).json({ 
            error: 'CSRF token not found. Please refresh the page and try again.' 
        });
    }

    // Check if token expired
    if (Date.now() > stored.expiresAt) {
        csrfTokens.delete(key);
        return res.status(403).json({ 
            error: 'CSRF token expired. Please refresh the page and try again.' 
        });
    }

    // Validate token
    if (stored.token !== token) {
        return res.status(403).json({ 
            error: 'Invalid CSRF token. Please refresh the page and try again.' 
        });
    }

    // Token is valid, continue
    next();
}

/**
 * Cleans up expired tokens periodically
 */
function cleanupExpiredTokens() {
    const now = Date.now();
    for (const [key, value] of csrfTokens.entries()) {
        if (now > value.expiresAt) {
            csrfTokens.delete(key);
        }
    }
}

// Clean up expired tokens every hour
setInterval(cleanupExpiredTokens, 60 * 60 * 1000);

/**
 * Middleware to get CSRF token (for authenticated endpoints)
 * This should be called after authentication
 */
function getCsrfToken(req, res, next) {
    if (req.user) {
        const key = `user_${req.user.userId}`;
        const stored = csrfTokens.get(key);
        
        if (stored && Date.now() <= stored.expiresAt) {
            res.setHeader('X-CSRF-Token', stored.token);
            req.csrfToken = stored.token;
        } else {
            // Generate new token
            createCsrfToken(req, res, next);
            return;
        }
    }
    next();
}

module.exports = {
    createCsrfToken,
    validateCsrfToken,
    getCsrfToken,
    generateCsrfToken
};

