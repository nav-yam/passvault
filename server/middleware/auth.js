const jwt = require('jsonwebtoken');
const { globalSessionManager } = require('../utils/sessionManager');

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// Authentication middleware with session tracking
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    // Verify JWT token
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired token' });
        }
        
        // Check if session exists and is valid (sliding expiration)
        const session = globalSessionManager.getSession(token);
        if (!session) {
            return res.status(401).json({ error: 'Session expired or invalid. Please login again.' });
        }
        
        // Verify session belongs to the same user
        if (session.userId !== user.userId) {
            return res.status(403).json({ error: 'Session mismatch' });
        }
        
        // Attach user info and session to request
        req.user = user;
        req.session = session;
        req.token = token;
        
        // Add security headers
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('X-Frame-Options', 'DENY');
        res.setHeader('X-XSS-Protection', '1; mode=block');
        res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
        
        next();
    });
};

module.exports = authenticateToken;
