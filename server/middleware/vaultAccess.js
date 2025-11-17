const db = require('better-sqlite3')('./db/app.db');

const checkVaultAccess = (req, res, next) => {
    try {
        const vaultId = req.params.vault_id || req.body.vault_id || req.query.vault_id;
        const userId = req.user.userId;

        if (!vaultId) {
            req.vaultAccess = null;
            return next();
        }

        const vaultIdInt = parseInt(vaultId);
        if (isNaN(vaultIdInt)) {
            return res.status(400).json({ error: 'Invalid vault ID' });
        }

        const vault = db.prepare('SELECT user_id FROM vaults WHERE id = ?').get(vaultIdInt);
        if (!vault) {
            return res.status(404).json({ error: 'Vault not found' });
        }

        if (vault.user_id === userId) {
            req.vaultAccess = { hasAccess: true, isOwner: true };
            return next();
        }

        const member = db.prepare('SELECT id FROM vault_members WHERE vault_id = ? AND user_id = ?').get(vaultIdInt, userId);
        if (member) {
            req.vaultAccess = { hasAccess: true, isOwner: false };
            return next();
        }

        return res.status(403).json({ error: 'Access denied to this vault' });
    } catch (error) {
        console.error('Vault access check error:', error);
        return res.status(500).json({ error: 'Internal server error' });
    }
};

module.exports = checkVaultAccess;

