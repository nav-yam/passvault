/**
 * Sanitization and Encoding Utility
 * 
 * Provides functions to sanitize user inputs to prevent XSS and Injection attacks.
 * Uses HTML entity encoding to render malicious scripts harmless while preserving data.
 */

/**
 * Encodes HTML special characters in a string.
 * @param {string} text - The input string to sanitize.
 * @returns {string} - The sanitized string with HTML entities.
 */
function sanitizeInput(text) {
    if (typeof text !== 'string') {
        return text;
    }
    
    return text
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;")
        .replace(/\//g, "&#x2F;") // Forward slash to prevent closing tags like </script>
        .trim();
}

/**
 * Recursively sanitizes all string properties of an object.
 * @param {Object} obj - The object to sanitize.
 * @param {Array<string>} excludeFields - List of field names to exclude from sanitization (e.g., passwords).
 * @returns {Object} - A new object with sanitized values.
 */
function sanitizeObject(obj, excludeFields = []) {
    if (typeof obj !== 'object' || obj === null) {
        return obj;
    }

    if (Array.isArray(obj)) {
        return obj.map(item => sanitizeObject(item, excludeFields));
    }

    const sanitized = {};
    for (const [key, value] of Object.entries(obj)) {
        if (excludeFields.includes(key)) {
            sanitized[key] = value;
        } else if (typeof value === 'string') {
            sanitized[key] = sanitizeInput(value);
        } else if (typeof value === 'object') {
            sanitized[key] = sanitizeObject(value, excludeFields);
        } else {
            sanitized[key] = value;
        }
    }
    return sanitized;
}

module.exports = {
    sanitizeInput,
    sanitizeObject
};
