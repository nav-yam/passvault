const crypto = require('crypto');

// Constants for key derivation
const PBKDF2_ITERATIONS = 100000; // High iteration count for security
const KEY_LENGTH = 32; // 32 bytes = 256 bits for AES-256
const SALT_LENGTH = 32; // 32 bytes for salt
const IV_LENGTH = 12; // 12 bytes for GCM IV (96 bits recommended)
const TAG_LENGTH = 16; // 16 bytes for GCM authentication tag
const ALGORITHM = 'aes-256-gcm';

/**
 * Derives an encryption key from a master password and salt using PBKDF2
 * @param {string} masterPassword - The user's master password
 * @param {Buffer} salt - The salt for key derivation
 * @returns {Buffer} - The derived encryption key (32 bytes)
 */
function deriveKey(masterPassword, salt) {
    return crypto.pbkdf2Sync(
        masterPassword,
        salt,
        PBKDF2_ITERATIONS,
        KEY_LENGTH,
        'sha256'
    );
}

/**
 * Generates a random salt for key derivation
 * @returns {Buffer} - Random salt (32 bytes)
 */
function generateSalt() {
    return crypto.randomBytes(SALT_LENGTH);
}

/**
 * Encrypts plaintext using AES-256-GCM
 * @param {string} plaintext - The text to encrypt
 * @param {string} masterPassword - The user's master password
 * @param {Buffer} salt - The salt for key derivation
 * @returns {string} - Encrypted data as hex string (format: iv:tag:encrypted)
 */
function encrypt(plaintext, masterPassword, salt) {
    if (!plaintext) {
        return null;
    }

    // Derive encryption key from master password
    const key = deriveKey(masterPassword, salt);

    // Generate random IV for this encryption
    const iv = crypto.randomBytes(IV_LENGTH);

    // Create cipher
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv);

    // Encrypt the plaintext
    let encrypted = cipher.update(plaintext, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    // Get authentication tag
    const tag = cipher.getAuthTag();

    // Return format: iv:tag:encrypted (all as hex)
    return `${iv.toString('hex')}:${tag.toString('hex')}:${encrypted}`;
}

/**
 * Decrypts ciphertext using AES-256-GCM
 * @param {string} ciphertext - The encrypted data (format: iv:tag:encrypted)
 * @param {string} masterPassword - The user's master password
 * @param {Buffer} salt - The salt for key derivation
 * @returns {string} - Decrypted plaintext
 * @throws {Error} - If decryption fails (invalid password, corrupted data, etc.)
 */
function decrypt(ciphertext, masterPassword, salt) {
    if (!ciphertext) {
        return null;
    }

    try {
        // Parse the ciphertext format: iv:tag:encrypted
        const parts = ciphertext.split(':');
        if (parts.length !== 3) {
            throw new Error('Invalid ciphertext format');
        }

        const [ivHex, tagHex, encrypted] = parts;
        const iv = Buffer.from(ivHex, 'hex');
        const tag = Buffer.from(tagHex, 'hex');

        // Derive decryption key from master password
        const key = deriveKey(masterPassword, salt);

        // Create decipher
        const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
        decipher.setAuthTag(tag);

        // Decrypt
        let decrypted = decipher.update(encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');

        return decrypted;
    } catch (error) {
        throw new Error('Decryption failed: ' + error.message);
    }
}

function encryptWithKey(plaintext, key) {
    if (!plaintext || !key) {
        return null;
    }

    const keyBuffer = Buffer.isBuffer(key) ? key : Buffer.from(key, 'hex');
    if (keyBuffer.length !== KEY_LENGTH) {
        throw new Error('Invalid key length');
    }

    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, keyBuffer, iv);
    
    let encrypted = cipher.update(plaintext, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const tag = cipher.getAuthTag();

    return `${iv.toString('hex')}:${tag.toString('hex')}:${encrypted}`;
}

function decryptWithKey(ciphertext, key) {
    if (!ciphertext || !key) {
        return null;
    }

    try {
        const parts = ciphertext.split(':');
        if (parts.length !== 3) {
            throw new Error('Invalid ciphertext format');
        }

        const [ivHex, tagHex, encrypted] = parts;
        const iv = Buffer.from(ivHex, 'hex');
        const tag = Buffer.from(tagHex, 'hex');
        const keyBuffer = Buffer.isBuffer(key) ? key : Buffer.from(key, 'hex');
        
        if (keyBuffer.length !== KEY_LENGTH) {
            throw new Error('Invalid key length');
        }

        const decipher = crypto.createDecipheriv(ALGORITHM, keyBuffer, iv);
        decipher.setAuthTag(tag);

        let decrypted = decipher.update(encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');

        return decrypted;
    } catch (error) {
        throw new Error('Decryption failed: ' + error.message);
    }
}

function generateVaultKey() {
    return crypto.randomBytes(KEY_LENGTH);
}

module.exports = {
    encrypt,
    decrypt,
    encryptWithKey,
    decryptWithKey,
    generateSalt,
    generateVaultKey,
    deriveKey
};

