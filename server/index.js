const express = require('express');
const cors = require('cors');
const db = require('better-sqlite3')('./db/app.db');
const authRoutes = require('./routes/auth');
const authenticateToken = require('./middleware/auth');
const checkVaultAccess = require('./middleware/vaultAccess');
const { createRateLimiter, recordFailedAttempt, resetFailedAttempts } = require('./middleware/rateLimit');
const { encrypt, decrypt, encryptWithKey, decryptWithKey, generateVaultKey } = require('./utils/encryption');

const app = express();
app.use(cors());
app.use(express.json());

app.use('/api', authRoutes);

app.get('/api/ping', (req, res) => {
    res.json({ message: 'pong' });
});

function getVaultKey(vaultId, userId, masterPassword) {
    const vault = db.prepare('SELECT user_id, vault_key_encrypted FROM vaults WHERE id = ?').get(vaultId);
    if (!vault) return null;

    if (vault.user_id === userId) {
        if (!vault.vault_key_encrypted) return null;
        const user = db.prepare('SELECT encryption_salt FROM users WHERE id = ?').get(userId);
        if (!user || !user.encryption_salt) return null;
        try {
            const salt = Buffer.from(user.encryption_salt, 'hex');
            const decrypted = decrypt(vault.vault_key_encrypted, masterPassword, salt);
            if (!decrypted || decrypted.trim() === '') {
                console.error('Decrypted vault key is empty for owner');
                return null;
            }
            return decrypted;
        } catch (error) {
            console.error('Failed to decrypt owner vault key:', error.message);
            return null;
        }
    } else {
        const member = db.prepare('SELECT encrypted_vault_key FROM vault_members WHERE vault_id = ? AND user_id = ?').get(vaultId, userId);
        if (!member) return null;
        
        if (!member.encrypted_vault_key || member.encrypted_vault_key.trim() === '') {
            return null;
        }
        
        const user = db.prepare('SELECT encryption_salt FROM users WHERE id = ?').get(userId);
        if (!user || !user.encryption_salt) return null;
        try {
            const salt = Buffer.from(user.encryption_salt, 'hex');
            const decrypted = decrypt(member.encrypted_vault_key, masterPassword, salt);
            if (!decrypted || decrypted.trim() === '') {
                return null;
            }
            return decrypted;
        } catch (error) {
            // Decryption failed - likely wrong master password
            console.error('Failed to decrypt member vault key:', error.message);
            return null;
        }
    }
}

function ensureVaultKey(vaultId, userId, masterPassword) {
    const vault = db.prepare('SELECT vault_key_encrypted FROM vaults WHERE id = ?').get(vaultId);
    if (!vault) return null;
    
    if (vault.vault_key_encrypted) {
        return getVaultKey(vaultId, userId, masterPassword);
    }
    
    const vaultKey = generateVaultKey();
    const user = db.prepare('SELECT encryption_salt FROM users WHERE id = ?').get(userId);
    if (!user || !user.encryption_salt) return null;
    
    const salt = Buffer.from(user.encryption_salt, 'hex');
    const encryptedVaultKey = encrypt(vaultKey.toString('hex'), masterPassword, salt);
    db.prepare('UPDATE vaults SET vault_key_encrypted = ? WHERE id = ?').run(encryptedVaultKey, vaultId);
    
    return vaultKey.toString('hex');
}

function isSharedVault(vaultId) {
    const memberCount = db.prepare('SELECT COUNT(*) as count FROM vault_members WHERE vault_id = ?').get(vaultId);
    return memberCount.count > 0;
}

app.get('/api/vaults', authenticateToken, (req, res) => {
    try {
        const owned = db.prepare('SELECT id, name, created_at, user_id as owner_id FROM vaults WHERE user_id = ?').all(req.user.userId);
        const shared = db.prepare(`
            SELECT v.id, v.name, v.created_at, v.user_id as owner_id 
            FROM vaults v
            INNER JOIN vault_members vm ON v.id = vm.vault_id
            WHERE vm.user_id = ?
        `).all(req.user.userId);
        
        const allVaults = [...owned, ...shared.map(v => ({ ...v, is_shared: true }))];
        res.json(allVaults);
    } catch (error) {
        console.error('Error fetching vaults:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/vaults', authenticateToken, (req, res) => {
    try {
        const { name, masterPassword } = req.body;
        if (!name) {
            return res.status(400).json({ error: 'Vault name is required' });
        }
        if (!masterPassword) {
            return res.status(400).json({ error: 'Master password is required' });
        }

        const user = db.prepare('SELECT encryption_salt FROM users WHERE id = ?').get(req.user.userId);
        if (!user || !user.encryption_salt) {
            return res.status(500).json({ error: 'User encryption salt not found' });
        }

        const vaultKey = generateVaultKey();
        const salt = Buffer.from(user.encryption_salt, 'hex');
        const encryptedVaultKey = encrypt(vaultKey.toString('hex'), masterPassword, salt);

        const stmt = db.prepare('INSERT INTO vaults (name, user_id, vault_key_encrypted) VALUES (?, ?, ?)');
        const info = stmt.run(name, req.user.userId, encryptedVaultKey);
        res.json({ id: info.lastInsertRowid, name });
    } catch (error) {
        console.error('Error creating vault:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/vaults/:vault_id/members', authenticateToken, checkVaultAccess, createRateLimiter('vault_unlock', 3, 30), (req, res) => {
    try {
        if (!req.vaultAccess || !req.vaultAccess.isOwner) {
            return res.status(403).json({ error: 'Only vault owner can add members' });
        }

        const vaultId = parseInt(req.params.vault_id);
        const { username, ownerMasterPassword, memberMasterPassword } = req.body;
        if (!username) {
            return res.status(400).json({ error: 'Username is required' });
        }

        const targetUser = db.prepare('SELECT id, encryption_salt FROM users WHERE username = ?').get(username);
        if (!targetUser) {
            return res.status(404).json({ error: 'User not found' });
        }

        if (targetUser.id === req.user.userId) {
            return res.status(400).json({ error: 'Cannot add yourself as a member' });
        }

        const existing = db.prepare('SELECT id FROM vault_members WHERE vault_id = ? AND user_id = ?').get(vaultId, targetUser.id);
        if (existing) {
            return res.status(409).json({ error: 'User is already a member' });
        }

        const vaultKeyHex = ensureVaultKey(vaultId, req.user.userId, ownerMasterPassword);
        if (!vaultKeyHex) {
            // Invalid master password - record failed attempt
            const rateLimitResponse = recordFailedAttempt(req, res);
            if (rateLimitResponse) return; // Rate limit response already sent
            return res.status(400).json({ error: 'Invalid owner master password' });
        }
        // Success - reset failed attempts
        resetFailedAttempts(req);

        let memberEncryptedKey = null;
        if (memberMasterPassword) {
            // Encrypt vault key with member's master password
            const memberUser = db.prepare('SELECT encryption_salt FROM users WHERE id = ?').get(targetUser.id);
            if (memberUser && memberUser.encryption_salt) {
                const memberSalt = Buffer.from(memberUser.encryption_salt, 'hex');
                memberEncryptedKey = encrypt(vaultKeyHex, memberMasterPassword, memberSalt);
            }
        }

        const stmt = db.prepare('INSERT INTO vault_members (vault_id, user_id, encrypted_vault_key) VALUES (?, ?, ?)');
        stmt.run(vaultId, targetUser.id, memberEncryptedKey);
        res.json({ success: true, message: memberEncryptedKey ? 'Member added successfully.' : 'Member added. They will need to provide their master password when first accessing the vault.' });
    } catch (error) {
        console.error('Error adding vault member:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.delete('/api/vaults/:vault_id/members/:user_id', authenticateToken, checkVaultAccess, (req, res) => {
    try {
        if (!req.vaultAccess || !req.vaultAccess.isOwner) {
            return res.status(403).json({ error: 'Only vault owner can remove members' });
        }

        const vaultId = parseInt(req.params.vault_id);
        const targetUserId = parseInt(req.params.user_id);

        const stmt = db.prepare('DELETE FROM vault_members WHERE vault_id = ? AND user_id = ?');
        stmt.run(vaultId, targetUserId);
        res.json({ success: true });
    } catch (error) {
        console.error('Error removing vault member:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/api/vaults/:vault_id/members', authenticateToken, checkVaultAccess, (req, res) => {
    try {
        const vaultId = parseInt(req.params.vault_id);
        const members = db.prepare(`
            SELECT u.id, u.username, vm.created_at
            FROM vault_members vm
            INNER JOIN users u ON vm.user_id = u.id
            WHERE vm.vault_id = ?
        `).all(vaultId);
        res.json(members);
    } catch (error) {
        console.error('Error fetching vault members:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/api/items', authenticateToken, createRateLimiter('vault_unlock', 3, 30), (req, res) => {
    try {
        const { masterPassword } = req.query;
        let vaultId = req.query.vault_id;

        if (!vaultId) {
            const defaultVault = db.prepare('SELECT id FROM vaults WHERE user_id = ? AND name = ?').get(req.user.userId, 'Default Vault');
            if (!defaultVault) {
                return res.status(404).json({ error: 'Default vault not found' });
            }
            vaultId = defaultVault.id;
        }

        const vaultIdInt = parseInt(vaultId);
        if (isNaN(vaultIdInt)) {
            return res.status(400).json({ error: 'Invalid vault_id' });
        }

        const vault = db.prepare('SELECT user_id FROM vaults WHERE id = ?').get(vaultIdInt);
        if (!vault) {
            // Return 403 instead of 404 for security (don't reveal if vault exists)
            return res.status(403).json({ error: 'Access denied to this vault' });
        }

        // Check if user has access to this vault (owner or member)
        if (vault.user_id !== req.user.userId) {
            const member = db.prepare('SELECT id FROM vault_members WHERE vault_id = ? AND user_id = ?').get(vaultIdInt, req.user.userId);
            if (!member) {
                return res.status(403).json({ error: 'Access denied to this vault' });
            }
        }

        const items = db.prepare('SELECT id, name, description, password, user_id, vault_id FROM items WHERE vault_id = ?').all(vaultIdInt);

        if (masterPassword) {
            // Check if vault has a vault key (can be shared)
            const vaultInfo = db.prepare('SELECT vault_key_encrypted FROM vaults WHERE id = ?').get(vaultIdInt);
            const hasVaultKey = vaultInfo && vaultInfo.vault_key_encrypted;
            
            let vaultKeyHex = null;
            if (hasVaultKey) {
                // Vault has a vault key, so use it for decryption (shared vault pattern)
                vaultKeyHex = getVaultKey(vaultIdInt, req.user.userId, masterPassword);
                if (!vaultKeyHex) {
                    // Check if member exists but doesn't have encrypted_vault_key
                    const member = db.prepare('SELECT encrypted_vault_key FROM vault_members WHERE vault_id = ? AND user_id = ?').get(vaultIdInt, req.user.userId);
                    if (member && !member.encrypted_vault_key) {
                        return res.json(items.map(item => ({
                            ...item,
                            password: null,
                            decryptionError: 'Vault key not initialized for this member. Please contact the vault owner.'
                        })));
                    }
                    // Invalid master password - record failed attempt
                    const rateLimitResponse = recordFailedAttempt(req, res);
                    if (rateLimitResponse) return; // Rate limit response already sent
                    return res.json(items.map(item => ({
                        ...item,
                        password: null,
                        decryptionError: 'Failed to decrypt. Invalid master password or vault key not initialized. Please contact the vault owner.'
                    })));
                }
                // Success - reset failed attempts
                resetFailedAttempts(req);
            }

            const decryptedItems = items.map(item => {
                const decryptedItem = { ...item };
                if (item.password) {
                    try {
                        if (hasVaultKey && vaultKeyHex) {
                            // Decrypt using vault key
                            const vaultKey = Buffer.from(vaultKeyHex, 'hex');
                            decryptedItem.password = decryptWithKey(item.password, vaultKey);
                        } else {
                            // Decrypt using master password directly (private vault)
                            const user = db.prepare('SELECT encryption_salt FROM users WHERE id = ?').get(req.user.userId);
                            const salt = Buffer.from(user.encryption_salt, 'hex');
                            decryptedItem.password = decrypt(item.password, masterPassword, salt);
                        }
                    } catch (error) {
                        decryptedItem.password = null;
                        decryptedItem.decryptionError = `Failed to decrypt password: ${error.message}`;
                    }
                }
                return decryptedItem;
            });
            return res.json(decryptedItems);
        } else {
            const safeItems = items.map(item => ({
                id: item.id,
                name: item.name,
                description: item.description,
                user_id: item.user_id,
                vault_id: item.vault_id,
                hasPassword: !!item.password
            }));
            return res.json(safeItems);
        }
    } catch (error) {
        console.error('Error fetching items:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/items', authenticateToken, createRateLimiter('vault_unlock', 3, 30), (req, res) => {
    try {
        const { name, description, password, masterPassword, vault_id } = req.body;
        if (!name) {
            return res.status(400).json({ error: 'Name is required' });
        }

        let vaultId = vault_id;
        if (!vaultId) {
            const defaultVault = db.prepare('SELECT id FROM vaults WHERE user_id = ? AND name = ?').get(req.user.userId, 'Default Vault');
            if (!defaultVault) {
                return res.status(404).json({ error: 'Default vault not found' });
            }
            vaultId = defaultVault.id;
        }

        const vaultIdInt = parseInt(vaultId);
        if (isNaN(vaultIdInt)) {
            return res.status(400).json({ error: 'Invalid vault_id' });
        }

        const vault = db.prepare('SELECT user_id FROM vaults WHERE id = ?').get(vaultIdInt);
        if (!vault) {
            // Return 403 instead of 404 for security (don't reveal if vault exists)
            return res.status(403).json({ error: 'Access denied to this vault' });
        }

        // Check if user has access to this vault (owner or member)
        if (vault.user_id !== req.user.userId) {
            const member = db.prepare('SELECT id FROM vault_members WHERE vault_id = ? AND user_id = ?').get(vaultIdInt, req.user.userId);
            if (!member) {
                return res.status(403).json({ error: 'Access denied to this vault' });
            }
        }

        let encryptedPassword = null;
        if (password) {
            if (!masterPassword) {
                return res.status(400).json({ error: 'masterPassword is required' });
            }

            try {
                // Check if vault has a vault key (can be shared)
                const vaultInfo = db.prepare('SELECT vault_key_encrypted FROM vaults WHERE id = ?').get(vaultIdInt);
                const hasVaultKey = vaultInfo && vaultInfo.vault_key_encrypted;
                
                let vaultKeyHex = null;
                if (hasVaultKey) {
                    // Vault has a vault key, so use it for encryption (shared vault pattern)
                    vaultKeyHex = getVaultKey(vaultIdInt, req.user.userId, masterPassword);
                    if (!vaultKeyHex) {
                        // Invalid master password - record failed attempt
                        const rateLimitResponse = recordFailedAttempt(req, res);
                        if (rateLimitResponse) return; // Rate limit response already sent
                        return res.status(400).json({ error: 'Invalid master password for vault. Please provide the correct master password.' });
                    }
                    // Success - reset failed attempts
                    resetFailedAttempts(req);
                    const vaultKey = Buffer.from(vaultKeyHex, 'hex');
                    if (vaultKey.length !== 32) {
                        console.error(`Invalid vault key length: ${vaultKey.length}, expected 32`);
                        return res.status(500).json({ error: 'Invalid vault key format' });
                    }
                    encryptedPassword = encryptWithKey(password, vaultKey);
                } else {
                    // Private vault without vault key, use master password directly
                    const user = db.prepare('SELECT encryption_salt FROM users WHERE id = ?').get(req.user.userId);
                    if (!user || !user.encryption_salt) {
                        return res.status(500).json({ error: 'User encryption salt not found' });
                    }
                    const salt = Buffer.from(user.encryption_salt, 'hex');
                    encryptedPassword = encrypt(password, masterPassword, salt);
                }
            } catch (error) {
                console.error('Encryption error:', error);
                return res.status(500).json({ error: 'Failed to encrypt password' });
            }
        }

        const stmt = db.prepare('INSERT INTO items (name, description, password, user_id, vault_id) VALUES (?, ?, ?, ?, ?)');
        const info = stmt.run(name, description, encryptedPassword, req.user.userId, vaultIdInt);
        res.json({ id: info.lastInsertRowid });
    } catch (error) {
        console.error('Error creating item:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.put('/api/items/:id', authenticateToken, createRateLimiter('vault_unlock', 3, 30), (req, res) => {
    try {
        const { name, description, password, masterPassword, vault_id } = req.body;
        const itemId = req.params.id;

        const existingItem = db.prepare('SELECT id, vault_id FROM items WHERE id = ?').get(itemId);
        if (!existingItem) {
            return res.status(404).json({ error: 'Item not found' });
        }

        const vaultId = existingItem.vault_id || vault_id;
        const vault = db.prepare('SELECT user_id FROM vaults WHERE id = ?').get(vaultId);
        if (!vault) {
            return res.status(404).json({ error: 'Vault not found' });
        }

        if (vault.user_id !== req.user.userId) {
            const member = db.prepare('SELECT id FROM vault_members WHERE vault_id = ? AND user_id = ?').get(vaultId, req.user.userId);
            if (!member) {
                return res.status(403).json({ error: 'Access denied' });
            }
        }

        if (vault_id !== undefined && vault_id !== existingItem.vault_id) {
            const targetVaultIdInt = parseInt(vault_id);
            if (isNaN(targetVaultIdInt)) {
                return res.status(400).json({ error: 'Invalid vault_id' });
            }
            const targetVault = db.prepare('SELECT user_id FROM vaults WHERE id = ?').get(targetVaultIdInt);
            if (!targetVault) {
                return res.status(404).json({ error: 'Target vault not found' });
            }
            // Check if user has access to target vault (owner or member)
            if (targetVault.user_id !== req.user.userId) {
                const member = db.prepare('SELECT id FROM vault_members WHERE vault_id = ? AND user_id = ?').get(targetVaultIdInt, req.user.userId);
                if (!member) {
                    return res.status(403).json({ error: 'Access denied to target vault' });
                }
            }
        }

        function updateItem() {
            const updates = [];
            const values = [];

            if (name !== undefined) {
                updates.push('name = ?');
                values.push(name);
            }
            if (description !== undefined) {
                updates.push('description = ?');
                values.push(description);
            }
            if (vault_id !== undefined) {
                updates.push('vault_id = ?');
                values.push(parseInt(vault_id));
            }
            if (password !== undefined) {
                if (!masterPassword) {
                    return res.status(400).json({ error: 'masterPassword is required' });
                }

                try {
                    const targetVaultId = vault_id !== undefined ? parseInt(vault_id) : existingItem.vault_id;
                    // Check if vault has a vault key (can be shared)
                    const vaultInfo = db.prepare('SELECT vault_key_encrypted FROM vaults WHERE id = ?').get(targetVaultId);
                    const hasVaultKey = vaultInfo && vaultInfo.vault_key_encrypted;
                    
                    let vaultKeyHex = null;
                    if (hasVaultKey) {
                        // Vault has a vault key, so use it for encryption (shared vault pattern)
                        vaultKeyHex = getVaultKey(targetVaultId, req.user.userId, masterPassword);
                        if (!vaultKeyHex) {
                            // Invalid master password - record failed attempt
                            const rateLimitResponse = recordFailedAttempt(req, res);
                            if (rateLimitResponse) return; // Rate limit response already sent
                            return res.status(400).json({ error: 'Invalid master password for vault. Please provide the correct master password.' });
                        }
                        // Success - reset failed attempts
                        resetFailedAttempts(req);
                        const vaultKey = Buffer.from(vaultKeyHex, 'hex');
                        const encryptedPassword = encryptWithKey(password, vaultKey);
                        updates.push('password = ?');
                        values.push(encryptedPassword);
                    } else {
                        // Private vault without vault key, use master password directly
                        const user = db.prepare('SELECT encryption_salt FROM users WHERE id = ?').get(req.user.userId);
                        const salt = Buffer.from(user.encryption_salt, 'hex');
                        const encryptedPassword = encrypt(password, masterPassword, salt);
                        updates.push('password = ?');
                        values.push(encryptedPassword);
                    }
                } catch (error) {
                    console.error('Encryption error:', error);
                    return res.status(500).json({ error: 'Failed to encrypt password' });
                }
            }

            if (updates.length === 0) {
                return res.status(400).json({ error: 'No fields to update' });
            }

            values.push(itemId);
            const stmt = db.prepare(`UPDATE items SET ${updates.join(', ')} WHERE id = ?`);
            stmt.run(...values);
            res.json({ updated: true });
        }

        updateItem();
    } catch (error) {
        console.error('Error updating item:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.delete('/api/items/:id', authenticateToken, (req, res) => {
    try {
        const itemId = req.params.id;
        const item = db.prepare('SELECT vault_id FROM items WHERE id = ?').get(itemId);
        if (!item) {
            return res.status(404).json({ error: 'Item not found' });
        }

        const vault = db.prepare('SELECT user_id FROM vaults WHERE id = ?').get(item.vault_id);
        if (!vault) {
            return res.status(404).json({ error: 'Vault not found' });
        }

        if (vault.user_id !== req.user.userId) {
            const member = db.prepare('SELECT id FROM vault_members WHERE vault_id = ? AND user_id = ?').get(item.vault_id, req.user.userId);
            if (!member) {
                return res.status(403).json({ error: 'Access denied' });
            }
        }

        const stmt = db.prepare('DELETE FROM items WHERE id = ?');
        stmt.run(itemId);
        res.json({ deleted: true });
    } catch (error) {
        console.error('Error deleting item:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.listen(3000, '0.0.0.0', () => {
    console.log('🚀 Server running at http://localhost:3000');
});
