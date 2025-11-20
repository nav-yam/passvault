const db = require('better-sqlite3')('./db/app.db');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    encryption_salt TEXT,
    key_derivation_algo TEXT DEFAULT 'pbkdf2'
);

CREATE TABLE IF NOT EXISTS vaults (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    vault_key_encrypted TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS vault_members (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vault_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    encrypted_vault_key TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (vault_id) REFERENCES vaults(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(vault_id, user_id)
);

CREATE TABLE IF NOT EXISTS items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    password TEXT,
    user_id INTEGER,
    vault_id INTEGER,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (vault_id) REFERENCES vaults(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action TEXT NOT NULL,
    ip_address TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    encrypted_details TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);
`);

// Migrate existing tables: add encryption_salt to users if it doesn't exist
try {
    db.exec(`ALTER TABLE users ADD COLUMN encryption_salt TEXT;`);
    console.log("✅ Added encryption_salt column to users table");
} catch (e) {
    // Column already exists, ignore
}

// Migrate existing tables: add key_derivation_algo to users if it doesn't exist
try {
    db.exec(`ALTER TABLE users ADD COLUMN key_derivation_algo TEXT DEFAULT 'pbkdf2';`);
    console.log("✅ Added key_derivation_algo column to users table");
} catch (e) {
    // Column already exists, ignore
}

// Migrate existing tables: add password to items if it doesn't exist
try {
    db.exec(`ALTER TABLE items ADD COLUMN password TEXT;`);
    console.log("✅ Added password column to items table");
} catch (e) {
    // Column already exists, ignore
}

// Migrate existing tables: add vault_id to items if it doesn't exist
try {
    db.exec(`ALTER TABLE items ADD COLUMN vault_id INTEGER;`);
    console.log("✅ Added vault_id column to items table");
} catch (e) {
    // Column already exists, ignore
}

// Migrate existing tables: add vault_key_encrypted to vaults if it doesn't exist
try {
    db.exec(`ALTER TABLE vaults ADD COLUMN vault_key_encrypted TEXT;`);
    console.log("✅ Added vault_key_encrypted column to vaults table");
} catch (e) {
    // Column already exists, ignore
}

// Create default vaults for existing users and migrate items
try {
    const users = db.prepare('SELECT id FROM users').all();
    for (const user of users) {
        // Check if user already has a default vault
        const existingVault = db.prepare('SELECT id FROM vaults WHERE user_id = ? AND name = ?').get(user.id, 'Default Vault');
        
        if (!existingVault) {
            // Create default vault for user
            const vaultStmt = db.prepare('INSERT INTO vaults (name, user_id) VALUES (?, ?)');
            const vaultInfo = vaultStmt.run('Default Vault', user.id);
            const defaultVaultId = vaultInfo.lastInsertRowid;
            
            // Migrate existing items without vault_id to default vault
            db.prepare('UPDATE items SET vault_id = ? WHERE user_id = ? AND vault_id IS NULL').run(defaultVaultId, user.id);
            console.log(`✅ Created default vault for user ${user.id} and migrated items`);
        }
    }
} catch (e) {
    console.error("⚠️ Error creating default vaults:", e.message);
}

console.log("📦 Database setup complete.");
