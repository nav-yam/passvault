/**
 * Input Validation Utilities
 * Implements strict whitelist-based validation to prevent injection attacks
 */

// Dangerous characters that should be blocked
const DANGEROUS_CHARS = /[<>\/\\"';{}()\[\]`$&|*?~=+%]/g;

/**
 * Validates username using whitelist approach
 * Allowed: alphanumeric, underscore, hyphen, dot
 * Length: 3-50 characters
 */
function validateUsername(username) {
    if (typeof username !== 'string') {
        return { valid: false, error: 'Username must be a string' };
    }

    if (username.length < 3 || username.length > 50) {
        return { valid: false, error: 'Username must be between 3 and 50 characters' };
    }

    // Whitelist: alphanumeric, underscore, hyphen, dot
    const usernamePattern = /^[a-zA-Z0-9._-]+$/;
    if (!usernamePattern.test(username)) {
        return { 
            valid: false, 
            error: 'Username can only contain letters, numbers, underscores, hyphens, and dots' 
        };
    }

    // Check for dangerous patterns
    if (DANGEROUS_CHARS.test(username)) {
        return { valid: false, error: 'Username contains invalid characters' };
    }

    return { valid: true };
}

/**
 * Validates password
 * Note: Passwords should allow special characters for security, but we validate structure
 * Length: 6-200 characters
 */
function validatePassword(password) {
    if (typeof password !== 'string') {
        return { valid: false, error: 'Password must be a string' };
    }

    if (password.length < 6 || password.length > 200) {
        return { valid: false, error: 'Password must be between 6 and 200 characters' };
    }

    // Check for null bytes and control characters (except newline/tab)
    if (/[\x00-\x08\x0B-\x0C\x0E-\x1F]/.test(password)) {
        return { valid: false, error: 'Password contains invalid control characters' };
    }

    return { valid: true };
}

/**
 * Validates vault/item name using whitelist approach
 * Allowed: alphanumeric, spaces, underscore, hyphen, dot, comma, apostrophe
 * Length: 1-100 characters
 */

function validateWebsiteLabel(label) {
    if (typeof label !== 'string') {
        return { valid: false, error: 'Website name must be a string' };
    }

    if (label.length < 1 || label.length > 100) {
        return { valid: false, error: 'Website name must be between 1 and 100 characters' };
    }

    // Whitelist; explicitly excludes < > / \ " ' ; { } ( )
    const pattern = /^[a-zA-Z0-9\s._:-]+$/;
    if (!pattern.test(label)) {
        return { 
            valid: false, 
            error: 'Website name can only contain letters, numbers, spaces, and basic punctuation (._:-)' 
        };
    }

    if (DANGEROUS_CHARS.test(label)) {
        return { valid: false, error: 'Website name contains invalid characters' };
    }

    if (label !== label.trim()) {
        return { valid: false, error: 'Website name cannot have leading or trailing whitespace' };
    }

    return { valid: true, value: label.trim() };
}
/**
 * Validates password label (same rules as general name)
 */
function validatePasswordLabel(label) {
    // Reuse validateName but with better error message
    const result = validateName(label);
    if (!result.valid) return { valid: false, error: 'Password label: ' + result.error };
    return { valid: true, value: label.trim() };
}

/**
 * Validates notes with a whitelist approach.
 * More lenient than labels, but still excludes injection chars.
 * Allowed: letters, numbers, whitespace, . , ! ? - _ : @ #
 * Length: 0-1000
 */
function validateNotes(notes) {
    if (notes === null || notes === undefined || notes === '') {
        return { valid: true, value: '' };
    }

    if (typeof notes !== 'string') {
        return { valid: false, error: 'Notes must be a string' };
    }

    if (notes.length > 1000) {
        return { valid: false, error: 'Notes must be 1000 characters or less' };
    }

    // Whitelist; excludes < > / \ " ' ; { } ( ) etc.
    const pattern = /^[a-zA-Z0-9\s.,!?@#:_-]*$/;
    if (!pattern.test(notes)) {
        return { 
            valid: false, 
            error: 'Notes contain invalid characters' 
        };
    }

    if (DANGEROUS_CHARS.test(notes)) {
        return { valid: false, error: 'Notes contain invalid characters' };
    }

    // No control chars
    if (/[\x00-\x08\x0B-\x0C\x0E-\x1F]/.test(notes)) {
        return { valid: false, error: 'Notes contain invalid control characters' };
    }

    return { valid: true, value: notes };
}

function validateName(name) {
    if (typeof name !== 'string') {
        return { valid: false, error: 'Name must be a string' };
    }

    if (name.length < 1 || name.length > 100) {
        return { valid: false, error: 'Name must be between 1 and 100 characters' };
    }

    // Whitelist: alphanumeric, spaces, underscore, hyphen, dot, comma, apostrophe
    const namePattern = /^[a-zA-Z0-9\s._'-]+$/;
    if (!namePattern.test(name)) {
        return { 
            valid: false, 
            error: 'Name can only contain letters, numbers, spaces, and basic punctuation (.,_\'-)' 
        };
    }

    // Check for dangerous patterns
    if (DANGEROUS_CHARS.test(name)) {
        return { valid: false, error: 'Name contains invalid characters' };
    }

    // Prevent leading/trailing whitespace
    if (name !== name.trim()) {
        return { valid: false, error: 'Name cannot have leading or trailing whitespace' };
    }

        return { valid: true, value: name.trim() };
}

/**
 * Validates description with more lenient rules but still safe
 * Allowed: Most printable characters except dangerous script injection chars
 * Length: 0-1000 characters
 */
function validateDescription(description) {
    if (description === null || description === undefined) {
        return { valid: true }; // Optional field
    }

    if (typeof description !== 'string') {
        return { valid: false, error: 'Description must be a string' };
    }

    if (description.length > 1000) {
        return { valid: false, error: 'Description must be 1000 characters or less' };
    }

    // Block script injection characters: < > / \ " ' ; { } ( ) [ ] ` $ & | * ? ~ = + %
    if (DANGEROUS_CHARS.test(description)) {
        return { valid: false, error: 'Description contains invalid characters' };
    }

    // Check for null bytes and control characters
    if (/[\x00-\x08\x0B-\x0C\x0E-\x1F]/.test(description)) {
        return { valid: false, error: 'Description contains invalid control characters' };
    }

    return { valid: true };
}

/**
 * Validates integer ID from params/query
 */
function validateId(id, fieldName = 'ID') {
    if (id === null || id === undefined) {
        return { valid: false, error: `${fieldName} is required` };
    }

    const idStr = String(id);
    const idNum = parseInt(idStr, 10);

    if (isNaN(idNum) || idNum <= 0 || idNum.toString() !== idStr.trim()) {
        return { valid: false, error: `${fieldName} must be a positive integer` };
    }

    // Check for dangerous characters
    if (DANGEROUS_CHARS.test(idStr)) {
        return { valid: false, error: `${fieldName} contains invalid characters` };
    }

    return { valid: true, value: idNum };
}

/**
 * Validates master password (same as regular password but with specific name)
 */
function validateMasterPassword(password) {
    return validatePassword(password);
}

/**
 * Validates all string inputs in an object recursively
 */
function validateObject(obj, schema) {
    const errors = [];
    const validated = {};

    for (const [key, validator] of Object.entries(schema)) {
        if (obj.hasOwnProperty(key)) {
            const result = validator(obj[key]);
            if (!result.valid) {
                errors.push({ field: key, error: result.error });
            } else {
                validated[key] = result.value !== undefined ? result.value : obj[key];
            }
        } else if (validator.required) {
            errors.push({ field: key, error: `${key} is required` });
        }
    }

    return {
        valid: errors.length === 0,
        errors,
        data: validated
    };
}

/**
 * Sanitizes a string by removing dangerous characters
 * This is a fallback - validation should catch issues first
 */
function sanitizeString(str) {
    if (typeof str !== 'string') {
        return '';
    }
    return str.replace(DANGEROUS_CHARS, '').trim();
}

module.exports = {
    validateUsername,
    validatePassword,
    validateName,
    validateDescription,
    validateId,
    validateMasterPassword,
    validateObject,
    sanitizeString,
    DANGEROUS_CHARS,
    validateWebsiteLabel,
    validatePasswordLabel,
    validateNotes
};

