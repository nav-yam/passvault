const db = require('better-sqlite3')('./db/app.db');

// Initialize rate limit table if it doesn't exist
db.exec(`
    CREATE TABLE IF NOT EXISTS rate_limits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        vault_id INTEGER,
        attempt_type TEXT NOT NULL,
        failed_attempts INTEGER DEFAULT 0,
        lockout_until INTEGER,
        last_attempt INTEGER DEFAULT (strftime('%s', 'now')),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_rate_limits_user_vault ON rate_limits(user_id, vault_id, attempt_type);
`);

/**
 * Rate limiting middleware with exponential backoff
 * Tracks failed password attempts and implements cooldown periods
 * 
 * @param {string} attemptType - Type of attempt ('master_password', 'vault_unlock', etc.)
 * @param {number} maxAttempts - Maximum allowed attempts before lockout (default: 3)
 * @param {number} baseCooldown - Base cooldown in seconds (default: 30)
 */
function createRateLimiter(attemptType = 'master_password', maxAttempts = 3, baseCooldown = 30) {
    return (req, res, next) => {
        try {
            const userId = req.user?.userId;
            if (!userId) {
                return res.status(401).json({ error: 'Authentication required' });
            }

            // Safely extract vault_id from params, body, or query
            const vaultId = (req.params && req.params.vault_id) || 
                          (req.body && req.body.vault_id) || 
                          (req.query && req.query.vault_id) || 
                          null;
            const now = Math.floor(Date.now() / 1000);

            // Get or create rate limit record
            let rateLimit = db.prepare(`
                SELECT * FROM rate_limits 
                WHERE user_id = ? AND vault_id IS ? AND attempt_type = ?
            `).get(userId, vaultId, attemptType);

            if (!rateLimit) {
                db.prepare(`
                    INSERT INTO rate_limits (user_id, vault_id, attempt_type, failed_attempts, last_attempt)
                    VALUES (?, ?, ?, 0, ?)
                `).run(userId, vaultId, attemptType, now);
                rateLimit = db.prepare(`
                    SELECT * FROM rate_limits 
                    WHERE user_id = ? AND vault_id IS ? AND attempt_type = ?
                `).get(userId, vaultId, attemptType);
            }

            // Check if user is currently locked out
            if (rateLimit.lockout_until && rateLimit.lockout_until > now) {
                const remainingSeconds = rateLimit.lockout_until - now;
                const remainingMinutes = Math.ceil(remainingSeconds / 60);
                return res.status(429).json({ 
                    error: `Too many failed attempts. Please try again in ${remainingMinutes} minute(s).`,
                    retryAfter: remainingSeconds
                });
            }

            // Reset lockout if it has expired
            if (rateLimit.lockout_until && rateLimit.lockout_until <= now) {
                db.prepare(`
                    UPDATE rate_limits 
                    SET failed_attempts = 0, lockout_until = NULL 
                    WHERE user_id = ? AND vault_id IS ? AND attempt_type = ?
                `).run(userId, vaultId, attemptType);
                rateLimit.failed_attempts = 0;
                rateLimit.lockout_until = null;
            }

            // Attach rate limit info to request for tracking failures
            req.rateLimit = {
                userId,
                vaultId,
                attemptType,
                failedAttempts: rateLimit.failed_attempts,
                recordId: rateLimit.id
            };

            next();
        } catch (error) {
            console.error('Rate limit check error:', error);
            // On error, allow the request to proceed (fail open for availability)
            next();
        }
    };
}

/**
 * Record a failed attempt and apply exponential backoff
 * Returns true if a response was sent (rate limited), false otherwise
 */
function recordFailedAttempt(req, res) {
    try {
        if (!req.rateLimit) return false;

        const { userId, vaultId, attemptType, failedAttempts, recordId } = req.rateLimit;
        const now = Math.floor(Date.now() / 1000);
        const newFailedAttempts = failedAttempts + 1;
        const maxAttempts = 3;
        const baseCooldown = 30;

        let lockoutUntil = null;
        
        if (newFailedAttempts >= maxAttempts) {
            // Exponential backoff: 30s, 60s, 120s for attempts 3, 4, 5...
            const cooldownSeconds = baseCooldown * Math.pow(2, Math.min(newFailedAttempts - maxAttempts, 2));
            lockoutUntil = now + cooldownSeconds;
        }

        db.prepare(`
            UPDATE rate_limits 
            SET failed_attempts = ?, lockout_until = ?, last_attempt = ?
            WHERE id = ?
        `).run(newFailedAttempts, lockoutUntil, now, recordId);

        if (lockoutUntil) {
            // Rate limit triggered - send 429 response
            const cooldownMinutes = Math.ceil((lockoutUntil - now) / 60);
            res.status(429).json({
                error: `Too many failed attempts. Please try again in ${cooldownMinutes} minute(s).`,
                retryAfter: lockoutUntil - now
            });
            return true; // Response sent
        }

        // For first two attempts, don't send a response - let normal error handling proceed
        // This allows the endpoint to return 200 with decryptionError for better UX
        return false; // No response sent, continue with normal error handling
    } catch (error) {
        console.error('Failed to record failed attempt:', error);
        return false;
    }
}

/**
 * Reset failed attempts on successful authentication
 */
function resetFailedAttempts(req) {
    try {
        if (!req.rateLimit) return;

        const { userId, vaultId, attemptType } = req.rateLimit;
        db.prepare(`
            UPDATE rate_limits 
            SET failed_attempts = 0, lockout_until = NULL 
            WHERE user_id = ? AND vault_id IS ? AND attempt_type = ?
        `).run(userId, vaultId, attemptType);
    } catch (error) {
        console.error('Failed to reset failed attempts:', error);
    }
}

module.exports = {
    createRateLimiter,
    recordFailedAttempt,
    resetFailedAttempts
};

