const crypto = require('crypto');
const argon2 = require('argon2');
const { zeroizeBuffer } = require('./memoryCleanup');

// Constants for key derivation
const PBKDF2_ITERATIONS = 100000; // High iteration count for security
const KEY_LENGTH = 32; // 32 bytes = 256 bits for AES-256
const SALT_LENGTH = 32; // 32 bytes for salt
const IV_LENGTH = 12; // 12 bytes for GCM IV (96 bits recommended)
const TAG_LENGTH = 16; // 16 bytes for GCM authentication tag
const ALGORITHM = 'aes-256-gcm';
const PEPPER = process.env.PEPPER || 'default-pepper-change-in-production-and-keep-secret';

// Argon2id configuration (OWASP recommended parameters)
const ARGON2_OPTIONS = {
    type: argon2.argon2id,
    memoryCost: 65536, // 64 MB
    timeCost: 3,       // 3 iterations
    parallelism: 4,    // 4 threads
    hashLength: KEY_LENGTH
};

/**
 * Hashes a password using Argon2id with Salt and Pepper
 * @param {string} password - The password to hash
 * @returns {Promise<string>} - The hashed password
 */
async function hashPassword(password) {
    try {
        // Append pepper to password before hashing
        const passwordWithPepper = password + PEPPER;
        return await argon2.hash(passwordWithPepper, ARGON2_OPTIONS);
    } catch (error) {
        throw new Error('Password hashing failed: ' + error.message);
    }
}

/**
 * Verifies a password against a hash using Argon2id and Pepper
 * @param {string} password - The password to verify
 * @param {string} hash - The stored hash
 * @returns {Promise<boolean>} - True if password matches
 */
async function verifyPassword(password, hash) {
    try {
        const passwordWithPepper = password + PEPPER;
        return await argon2.verify(hash, passwordWithPepper);
    } catch (error) {
        return false;
    }
}

/**
 * Derives an encryption key from a master password and salt using PBKDF2 (legacy)
 * @param {string} masterPassword - The user's master password
 * @param {Buffer} salt - The salt for key derivation
 * @returns {Buffer} - The derived encryption key (32 bytes)
 */
function deriveKey(masterPassword, salt) {
    const key = crypto.pbkdf2Sync(
        masterPassword,
        salt,
        PBKDF2_ITERATIONS,
        KEY_LENGTH,
        'sha256'
    );
    return key;
}

/**
 * Derives an encryption key using Argon2id (recommended for new users)
 * @param {string} masterPassword - The user's master password
 * @param {Buffer} salt - The salt for key derivation
 * @returns {Promise<Buffer>} - The derived encryption key (32 bytes)
 */
async function deriveKeyArgon2(masterPassword, salt) {
    try {
        const hash = await argon2.hash(masterPassword, {
            ...ARGON2_OPTIONS,
            salt: salt,
            raw: true // Return raw buffer instead of encoded string
        });
        return hash;
    } catch (error) {
        throw new Error('Argon2 key derivation failed: ' + error.message);
    }
}

/**
 * Derives an encryption key synchronously using Argon2id
 * @param {string} masterPassword - The user's master password
 * @param {Buffer} salt - The salt for key derivation
 * @returns {Buffer} - The derived encryption key (32 bytes)
 */
function deriveKeyArgon2Sync(masterPassword, salt) {
    try {
        // Use crypto.scryptSync as fallback for sync operations
        // In production, prefer async deriveKeyArgon2
        const hash = crypto.scryptSync(masterPassword, salt, KEY_LENGTH, {
            N: 65536, // CPU/memory cost parameter
            r: 8,     // Block size parameter
            p: 1,     // Parallelization parameter
            maxmem: 128 * 1024 * 1024 // 128 MB max memory
        });
        return hash;
    } catch (error) {
        throw new Error('Scrypt key derivation failed: ' + error.message);
    }
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
 * @param {string} algorithm - Key derivation algorithm ('pbkdf2' or 'argon2', default: 'pbkdf2')
 * @returns {string} - Encrypted data as hex string (format: iv:tag:encrypted)
 */
function encrypt(plaintext, masterPassword, salt, algorithm = 'pbkdf2') {
    if (!plaintext) {
        return null;
    }

    let key = null;
    try {
        // Derive encryption key from master password
        if (algorithm === 'argon2') {
            key = deriveKeyArgon2Sync(masterPassword, salt);
        } else {
            key = deriveKey(masterPassword, salt);
        }

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
    } finally {
        // Zeroize the key after use
        if (key) {
            zeroizeBuffer(key);
        }
    }
}

/**
 * Decrypts ciphertext using AES-256-GCM
 * @param {string} ciphertext - The encrypted data (format: iv:tag:encrypted)
 * @param {string} masterPassword - The user's master password
 * @param {Buffer} salt - The salt for key derivation
 * @param {string} algorithm - Key derivation algorithm ('pbkdf2' or 'argon2', default: 'pbkdf2')
 * @returns {string} - Decrypted plaintext
 * @throws {Error} - If decryption fails (invalid password, corrupted data, etc.)
 */
function decrypt(ciphertext, masterPassword, salt, algorithm = 'pbkdf2') {
    if (!ciphertext) {
        return null;
    }

    let key = null;
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
        if (algorithm === 'argon2') {
            key = deriveKeyArgon2Sync(masterPassword, salt);
        } else {
            key = deriveKey(masterPassword, salt);
        }

        // Create decipher
        const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
        decipher.setAuthTag(tag);

        // Decrypt
        let decrypted = decipher.update(encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');

        return decrypted;
    } catch (error) {
        throw new Error('Decryption failed: ' + error.message);
    } finally {
        // Zeroize the key after use
        if (key) {
            zeroizeBuffer(key);
        }
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
    deriveKey,
    deriveKeyArgon2,
    deriveKeyArgon2Sync,
    hashPassword,
    verifyPassword
};

