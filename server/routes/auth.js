const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const db = require('better-sqlite3')('./db/app.db');
const { generateSalt } = require('../utils/encryption');
const { sanitizeObject } = require('../utils/security');
const { globalSessionManager } = require('../utils/sessionManager');
const authenticateToken = require('../middleware/auth');

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// Register endpoint
router.post('/register', async (req, res) => {
    try {
        req.body = sanitizeObject(req.body, ['password']);
        const { username, password } = req.body;

        // Validate input
        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password are required' });
        }

        if (password.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters long' });
        }

        // Check if user already exists
        const existingUser = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
        if (existingUser) {
            return res.status(409).json({ error: 'Username already exists' });
        }

        // Hash password
        const saltRounds = 10;
        const password_hash = await bcrypt.hash(password, saltRounds);

        // Generate encryption salt for password encryption
        const encryptionSalt = generateSalt();
        const encryptionSaltHex = encryptionSalt.toString('hex');

        // Insert user into database (use argon2 for new users)
        const stmt = db.prepare('INSERT INTO users (username, password_hash, encryption_salt, key_derivation_algo) VALUES (?, ?, ?, ?)');
        const info = stmt.run(username, password_hash, encryptionSaltHex, 'argon2');
        const userId = info.lastInsertRowid;

        // Create default vault for new user
        const vaultStmt = db.prepare('INSERT INTO vaults (name, user_id) VALUES (?, ?)');
        vaultStmt.run('Default Vault', userId);

        // Generate JWT token
        const token = jwt.sign(
            { userId, username },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        // Create session
        globalSessionManager.createSession(userId, token, {
            ipAddress: req.ip || req.connection.remoteAddress,
            userAgent: req.headers['user-agent']
        });

        res.status(201).json({
            message: 'User registered successfully',
            token,
            user: { id: userId, username }
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Login endpoint
router.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Validate input
        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password are required' });
        }

        // Find user (include key derivation algorithm)
        const user = db.prepare('SELECT id, username, password_hash, key_derivation_algo FROM users WHERE username = ?').get(username);
        if (!user) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }

        // Verify password
        const isValidPassword = await bcrypt.compare(password, user.password_hash);
        if (!isValidPassword) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }

        // Migrate PBKDF2 users to Argon2 on successful login
        if (!user.key_derivation_algo || user.key_derivation_algo === 'pbkdf2') {
            try {
                db.prepare('UPDATE users SET key_derivation_algo = ? WHERE id = ?').run('argon2', user.id);
                console.log(`Migrated user ${user.username} from PBKDF2 to Argon2`);
            } catch (error) {
                console.error('Failed to migrate user to Argon2:', error);
                // Continue anyway - not critical
            }
        }

        // Generate JWT token
        const token = jwt.sign(
            { userId: user.id, username: user.username },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        // Create session
        globalSessionManager.createSession(user.id, token, {
            ipAddress: req.ip || req.connection.remoteAddress,
            userAgent: req.headers['user-agent']
        });

        res.json({
            message: 'Login successful',
            token,
            user: { id: user.id, username: user.username }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Logout endpoint - invalidate current session
router.post('/logout', authenticateToken, (req, res) => {
    try {
        const token = req.token;
        
        // Invalidate the session
        const invalidated = globalSessionManager.invalidateSession(token);
        
        if (invalidated) {
            res.json({ message: 'Logout successful' });
        } else {
            res.status(404).json({ error: 'Session not found' });
        }
    } catch (error) {
        console.error('Logout error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Logout all sessions - invalidate all user sessions
router.post('/logout/all', authenticateToken, (req, res) => {
    try {
        const userId = req.user.userId;
        
        // Invalidate all sessions for this user
        const count = globalSessionManager.invalidateUserSessions(userId);
        
        res.json({
            message: `Logged out from ${count} device(s) successfully`,
            sessionCount: count
        });
    } catch (error) {
        console.error('Logout all error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get active sessions
router.get('/sessions', authenticateToken, (req, res) => {
    try {
        const userId = req.user.userId;
        const sessions = globalSessionManager.getUserSessions(userId);
        
        res.json({ sessions });
    } catch (error) {
        console.error('Get sessions error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

module.exports = router;
