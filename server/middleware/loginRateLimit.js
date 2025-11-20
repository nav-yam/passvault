const db = require('better-sqlite3')('./db/app.db');

// Initialize login rate limit table
function initializeLoginRateLimitTable() {
    db.exec(`
        CREATE TABLE IF NOT EXISTS login_rate_limits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL,
            failed_attempts INTEGER DEFAULT 0,
            last_attempt INTEGER,
            lockout_until INTEGER,
            UNIQUE(ip_address)
        );
    `);
}

initializeLoginRateLimitTable();

/**
 * Middleware to check if IP is rate limited for login
 */
function checkLoginRateLimit(req, res, next) {
    try {
        const ipAddress = req.ip || req.connection.remoteAddress;
        const now = Math.floor(Date.now() / 1000);

        const rateLimit = db.prepare('SELECT * FROM login_rate_limits WHERE ip_address = ?').get(ipAddress);

        if (rateLimit && rateLimit.lockout_until && rateLimit.lockout_until > now) {
            const remainingSeconds = rateLimit.lockout_until - now;
            return res.status(429).json({
                error: `Too many failed attempts. Please try again in ${remainingSeconds} seconds.`,
                retryAfter: remainingSeconds
            });
        }

        // If lockout expired, reset it (lazy reset)
        if (rateLimit && rateLimit.lockout_until && rateLimit.lockout_until <= now) {
             db.prepare('UPDATE login_rate_limits SET failed_attempts = 0, lockout_until = NULL WHERE id = ?').run(rateLimit.id);
        }

        next();
    } catch (error) {
        console.error('Login rate limit check error:', error);
        // Fail open
        next();
    }
}

/**
 * Record a failed login attempt
 * @returns {boolean} true if the user is now locked out
 */
function recordLoginFailure(req, res) {
    try {
        const ipAddress = req.ip || req.connection.remoteAddress;
        const now = Math.floor(Date.now() / 1000);
        const MAX_ATTEMPTS = 3;
        const LOCKOUT_DURATION = 30; // 30 seconds

        console.log(`[RateLimit] Recording failure for IP: ${ipAddress}`);

        let rateLimit = db.prepare('SELECT * FROM login_rate_limits WHERE ip_address = ?').get(ipAddress);

        if (!rateLimit) {
            console.log('[RateLimit] New record created');
            db.prepare('INSERT INTO login_rate_limits (ip_address, failed_attempts, last_attempt) VALUES (?, 1, ?)').run(ipAddress, now);
            return false;
        }

        console.log(`[RateLimit] Existing record: attempts=${rateLimit.failed_attempts}, last=${rateLimit.last_attempt}`);

        if (now - rateLimit.last_attempt > 30) {
             console.log('[RateLimit] Resetting due to timeout');
             db.prepare('UPDATE login_rate_limits SET failed_attempts = 1, last_attempt = ?, lockout_until = NULL WHERE id = ?').run(now, rateLimit.id);
             return false;
        }

        const newFailedAttempts = rateLimit.failed_attempts + 1;
        let lockoutUntil = null;

        if (newFailedAttempts >= MAX_ATTEMPTS) {
            lockoutUntil = now + LOCKOUT_DURATION;
            console.log(`[RateLimit] Lockout triggered! Until: ${lockoutUntil}`);
        }

        db.prepare('UPDATE login_rate_limits SET failed_attempts = ?, last_attempt = ?, lockout_until = ? WHERE id = ?')
            .run(newFailedAttempts, now, lockoutUntil, rateLimit.id);

        if (lockoutUntil) {
             return true;
        }
        
        return false;

    } catch (error) {
        console.error('Record login failure error:', error);
        return false;
    }
}

/**
 * Reset failed attempts on successful login
 */
function resetLoginFailure(req) {
    try {
        const ipAddress = req.ip || req.connection.remoteAddress;
        db.prepare('DELETE FROM login_rate_limits WHERE ip_address = ?').run(ipAddress);
    } catch (error) {
        console.error('Reset login failure error:', error);
    }
}

module.exports = {
    checkLoginRateLimit,
    recordLoginFailure,
    resetLoginFailure
};
