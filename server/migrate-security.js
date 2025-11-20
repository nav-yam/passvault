/**
 * Database Migration Script
 * Adds new columns and tables for enhanced security features
 */

const db = require('better-sqlite3')('./db/app.db');

console.log('🔧 Running database migration for security enhancements...\n');

try {
    // Check if key_derivation_algo column exists
    const columnsQuery = db.prepare("PRAGMA table_info(users)");
    const columns = columnsQuery.all();
    const hasKeyDerivationColumn = columns.some(col => col.name === 'key_derivation_algo');
    
    if (!hasKeyDerivationColumn) {
        console.log('Adding key_derivation_algo column to users table...');
        db.prepare('ALTER TABLE users ADD COLUMN key_derivation_algo VARCHAR(20) DEFAULT \'pbkdf2\'').run();
        console.log('✅ Added key_derivation_algo column\n');
    } else {
        console.log('✓ key_derivation_algo column already exists\n');
    }
    
    // Create active_sessions table if it doesn't exist
    console.log('Creating active_sessions table...');
    db.prepare(`
        CREATE TABLE IF NOT EXISTS active_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token_hash VARCHAR(64) NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME NOT NULL,
            ip_address VARCHAR(45),
            user_agent TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    `).run();
    console.log('✅ Created active_sessions table\n');
    
    // Create indexes
    console.log('Creating indexes for active_sessions...');
    db.prepare(`CREATE INDEX IF NOT EXISTS idx_sessions_token ON active_sessions(token_hash)`).run();
    db.prepare(`CREATE INDEX IF NOT EXISTS idx_sessions_expires ON active_sessions(expires_at)`).run();
    db.prepare(`CREATE INDEX IF NOT EXISTS idx_sessions_user ON active_sessions(user_id)`).run();
    console.log('✅ Created indexes\n');
    
    console.log('🎉 Migration completed successfully!');
    
} catch (error) {
    console.error('❌ Migration failed:', error.message);
    process.exit(1);
}

db.close();
