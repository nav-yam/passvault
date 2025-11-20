/**
 * Sanitization Utilities
 * Prevents XSS attacks by encoding/sanitizing user input for display
 */

/**
 * HTML entity encoding to prevent XSS
 * Encodes dangerous characters that could be used in script injection
 */
function encodeHtml(str) {
    if (str === null || str === undefined) {
        return '';
    }

    const strValue = String(str);
    const htmlEscapes = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#x27;',
        '/': '&#x2F;',
        '`': '&#x60;',
        '=': '&#x3D;'
    };

    return strValue.replace(/[&<>"'`=\/]/g, (match) => htmlEscapes[match]);
}

/**
 * Encodes all values in an object for HTML display
 */
function encodeObjectForHtml(obj) {
    if (obj === null || obj === undefined) {
        return obj;
    }

    if (typeof obj === 'string') {
        return encodeHtml(obj);
    }

    if (Array.isArray(obj)) {
        return obj.map(item => encodeObjectForHtml(item));
    }

    if (typeof obj === 'object') {
        const encoded = {};
        for (const [key, value] of Object.entries(obj)) {
            encoded[key] = encodeObjectForHtml(value);
        }
        return encoded;
    }

    return obj;
}

/**
 * Sanitizes string for database storage
 * Removes null bytes and control characters
 */
function sanitizeForDatabase(str) {
    if (str === null || str === undefined) {
        return str;
    }

    if (typeof str !== 'string') {
        return String(str);
    }

    // Remove null bytes
    let sanitized = str.replace(/\x00/g, '');
    
    // Remove control characters except newline, carriage return, and tab
    sanitized = sanitized.replace(/[\x01-\x08\x0B-\x0C\x0E-\x1F]/g, '');
    
    return sanitized;
}

/**
 * Sanitizes object for database storage
 */
function sanitizeObjectForDatabase(obj) {
    if (obj === null || obj === undefined) {
        return obj;
    }

    if (typeof obj === 'string') {
        return sanitizeForDatabase(obj);
    }

    if (Array.isArray(obj)) {
        return obj.map(item => sanitizeObjectForDatabase(item));
    }

    if (typeof obj === 'object') {
        const sanitized = {};
        for (const [key, value] of Object.entries(obj)) {
            sanitized[key] = sanitizeObjectForDatabase(value);
        }
        return sanitized;
    }

    return obj;
}

/**
 * Validates and sanitizes JSON input
 * Prevents JSON injection attacks
 */
function sanitizeJsonInput(jsonStr) {
    if (typeof jsonStr !== 'string') {
        return null;
    }

    try {
        const parsed = JSON.parse(jsonStr);
        return sanitizeObjectForDatabase(parsed);
    } catch (error) {
        return null;
    }
}

/**
 * Encodes URL parameters to prevent injection
 */
function encodeUrlParam(param) {
    if (param === null || param === undefined) {
        return '';
    }
    return encodeURIComponent(String(param));
}

module.exports = {
    encodeHtml,
    encodeObjectForHtml,
    sanitizeForDatabase,
    sanitizeObjectForDatabase,
    sanitizeJsonInput,
    encodeUrlParam
};

