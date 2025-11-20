/**
 * Path Security Middleware
 * 
 * Prevents path traversal attacks by validating file paths and filenames.
 * Ensures user-controlled input doesn't escape intended directories.
 */

const path = require('path');

/**
 * Sanitize a filename by removing dangerous characters and sequences
 * @param {string} filename - The filename to sanitize
 * @returns {string} - Sanitized filename
 */
function sanitizeFilename(filename) {
    if (typeof filename !== 'string') {
        throw new Error('Filename must be a string');
    }
    
    // Remove any directory traversal patterns
    const sanitized = filename
        .replace(/\.\./g, '')      // Remove ..
        .replace(/\.\//g, '')      // Remove ./
        .replace(/\\/g, '')        // Remove backslashes
        .replace(/\//g, '')        // Remove forward slashes
        .replace(/:/g, '')         // Remove colons (Windows drive letters)
        .replace(/\*/g, '')        // Remove wildcards
        .replace(/\?/g, '')        // Remove question marks
        .replace(/"/g, '')         // Remove quotes
        .replace(/</g, '')         // Remove less than
        .replace(/>/g, '')         // Remove greater than
        .replace(/\|/g, '')        // Remove pipe
        .replace(/\0/g, '')        // Remove null bytes
        .trim();
    
    // Ensure filename is not empty after sanitization
    if (sanitized.length === 0) {
        throw new Error('Filename cannot be empty after sanitization');
    }
    
    // Ensure filename doesn't start with a dot (hidden files on Unix)
    if (sanitized.startsWith('.')) {
        throw new Error('Filename cannot start with a dot');
    }
    
    return sanitized;
}

/**
 * Validate a file path to ensure it doesn't escape a base directory
 * @param {string} basePath - The base directory (absolute path)
 * @param {string} userPath - The user-provided path component
 * @returns {string} - Resolved safe path
 * @throws {Error} - If path is unsafe
 */
function validatePath(basePath, userPath) {
    if (!basePath || !userPath) {
        throw new Error('Base path and user path are required');
    }
    
    // Resolve the full path
    const resolvedPath = path.resolve(basePath, userPath);
    
    // Normalize both paths
    const normalizedBase = path.normalize(basePath);
    const normalizedResolved = path.normalize(resolvedPath);
    
    // Ensure the resolved path starts with the base path
    if (!normalizedResolved.startsWith(normalizedBase)) {
        throw new Error('Path traversal detected: Path escapes base directory');
    }
    
    return resolvedPath;
}

/**
 * Middleware to validate vault names and item names for path safety
 * @param {Request} req - Express request object
 * @param {Response} res - Express response object
 * @param {Function} next - Next middleware function
 */
function validateNames(req, res, next) {
    try {
        // Check vault names in request body
        if (req.body && req.body.name) {
            try {
                req.body.name = sanitizeFilename(req.body.name);
            } catch (error) {
                return res.status(400).json({ error: `Invalid name: ${error.message}` });
            }
        }
        
        // Check vault names in query params
        if (req.query && req.query.name) {
            try {
                req.query.name = sanitizeFilename(req.query.name);
            } catch (error) {
                return res.status(400).json({ error: `Invalid name: ${error.message}` });
            }
        }
        
        next();
    } catch (error) {
        console.error('Path validation error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
}

/**
 * Whitelist of allowed characters for filenames
 * Alphanumeric, spaces, hyphens, underscores, and basic punctuation
 */
const ALLOWED_FILENAME_CHARS = /^[a-zA-Z0-9\s\-_.,!@#$%^&*()\[\]{}+=~`]+$/;

/**
 * Validate filename against whitelist
 * @param {string} filename - The filename to validate
 * @returns {boolean} - True if valid, false otherwise
 */
function isValidFilename(filename) {
    if (typeof filename !== 'string' || filename.length === 0) {
        return false;
    }
    
    // Check against whitelist
    if (!ALLOWED_FILENAME_CHARS.test(filename)) {
        return false;
    }
    
    // Additional checks
    if (filename.includes('..')) return false;
    if (filename.includes('/')) return false;
    if (filename.includes('\\')) return false;
    if (filename.startsWith('.')) return false;
    
    return true;
}

module.exports = {
    sanitizeFilename,
    validatePath,
    validateNames,
    isValidFilename
};
