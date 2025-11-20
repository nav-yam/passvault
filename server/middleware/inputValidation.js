/**
 * Input Validation Middleware
 * Validates and sanitizes all user inputs before processing
 */

const {
    validateUsername,
    validatePassword,
    validateName,
    validateDescription,
    validateId,
    validateMasterPassword,
    sanitizeString
} = require('../utils/validation');

const {
    validateWebsiteLabel,
    validatePasswordLabel,
    validateNotes
} = require('../utils/validation');

const { sanitizeForDatabase } = require('../utils/sanitization');

/**
 * Validates request body fields
 */
function validateBody(schema) {
    return (req, res, next) => {
        const errors = [];
        const sanitized = {};

        for (const [field, validator] of Object.entries(schema)) {
            if (req.body.hasOwnProperty(field)) {
                const value = req.body[field];
                
                // Sanitize before validation
                const sanitizedValue = typeof value === 'string' 
                    ? sanitizeForDatabase(value) 
                    : value;

                const result = validator(sanitizedValue);
                if (!result.valid) {
                    errors.push({ field, error: result.error });
                } else {
                    sanitized[field] = result.value !== undefined ? result.value : sanitizedValue;
                }
            } else if (schema[field].required) {
                errors.push({ field, error: `${field} is required` });
            }
        }

        if (errors.length > 0) {
            return res.status(400).json({ 
                error: 'Validation failed', 
                details: errors 
            });
        }

        // Replace req.body with sanitized version
        req.body = { ...req.body, ...sanitized };
        next();
    };
}

/**
 * Validates route parameters
 */
function validateParams(schema) {
    return (req, res, next) => {
        const errors = [];
        const sanitized = {};

        for (const [param, validator] of Object.entries(schema)) {
            if (req.params.hasOwnProperty(param)) {
                const result = validator(req.params[param], param);
                if (!result.valid) {
                    errors.push({ param, error: result.error });
                } else {
                    sanitized[param] = result.value;
                }
            } else if (schema[param].required) {
                errors.push({ param, error: `${param} is required` });
            }
        }

        if (errors.length > 0) {
            return res.status(400).json({ 
                error: 'Invalid route parameters', 
                details: errors 
            });
        }

        // Replace req.params with sanitized version
        req.params = { ...req.params, ...sanitized };
        next();
    };
}

/**
 * Validates query parameters
 */
function validateQuery(schema) {
    return (req, res, next) => {
        const errors = [];
        const sanitized = {};

        for (const [param, validator] of Object.entries(schema)) {
            if (req.query.hasOwnProperty(param)) {
                const value = req.query[param];
                
                // Sanitize string query params
                const sanitizedValue = typeof value === 'string' 
                    ? sanitizeForDatabase(value) 
                    : value;

                const result = validator(sanitizedValue, param);
                if (!result.valid) {
                    errors.push({ param, error: result.error });
                } else {
                    sanitized[param] = result.value !== undefined ? result.value : sanitizedValue;
                }
            } else if (schema[param] && schema[param].required) {
                errors.push({ param, error: `${param} is required` });
            }
        }

        if (errors.length > 0) {
            return res.status(400).json({ 
                error: 'Invalid query parameters', 
                details: errors 
            });
        }

        // Replace req.query with sanitized version
        req.query = { ...req.query, ...sanitized };
        next();
    };
}

/**
 * Validates registration input
 */
const validateRegister = validateBody({
    username: (val) => {
        const result = validateUsername(val);
        return { ...result, required: true };
    },
    password: (val) => {
        const result = validatePassword(val);
        return { ...result, required: true };
    }
});

/**
 * Validates login input
 */
const validateLogin = validateBody({
    username: (val) => {
        const result = validateUsername(val);
        return { ...result, required: true };
    },
    password: (val) => {
        const result = validatePassword(val);
        return { ...result, required: true };
    }
});

/**
 * Validates vault creation input
 */
const validateVaultCreate = validateBody({
    name: (val) => {
        const result = validateName(val);
        return { ...result, required: true };
    },
    masterPassword: (val) => {
        const result = validateMasterPassword(val);
        return { ...result, required: true };
    }
});

/**
 * Validates item creation/update input
 * We assume:
 *   name = password label
 *   description = notes
 */
const validateItem = validateBody({
    // password label
    name: (val) => {
        if (val === undefined) return { valid: true, required: false };
        const result = validatePasswordLabel(val);
        return { ...result, required: false };
    },
    // notes / description
    description: (val) => {
        if (val === undefined) return { valid: true, required: false };
        const result = validateNotes(val);
        return { ...result, required: false };
    },
    password: (val) => {
        if (val === undefined) return { valid: true, required: false };
        if (typeof val !== 'string') {
            return { valid: false, error: 'Password must be a string', required: false };
        }
        if (val.length > 500) {
            return { valid: false, error: 'Password must be 500 characters or less', required: false };
        }
        // Reject control chars except newline/tab
        if (/[\x00-\x08\x0B-\x0C\x0E-\x1F]/.test(val)) {
            return { valid: false, error: 'Password contains invalid control characters', required: false };
        }
        return { valid: true, required: false };
    },
    masterPassword: (val) => {
        if (val === undefined) return { valid: true, required: false };
        const result = validateMasterPassword(val);
        return { ...result, required: false };
    },
    vault_id: (val) => {
        if (val === undefined) return { valid: true, required: false };
        const result = validateId(val, 'vault_id');
        return { ...result, required: false };
    }
});

/**
 * Validates vault member addition input
 */
const validateAddMember = validateBody({
    username: (val) => {
        const result = validateUsername(val);
        return { ...result, required: true };
    },
    ownerMasterPassword: (val) => {
        const result = validateMasterPassword(val);
        return { ...result, required: true };
    },
    memberMasterPassword: (val) => {
        if (val === undefined) return { valid: true, required: false };
        const result = validateMasterPassword(val);
        return { ...result, required: false };
    }
});

/**
 * Validates vault ID parameter
 */
const validateVaultId = validateParams({
    vault_id: (val) => {
        const result = validateId(val, 'vault_id');
        return { ...result, required: true };
    }
});

/**
 * Validates user ID parameter
 */
const validateUserId = validateParams({
    user_id: (val) => {
        const result = validateId(val, 'user_id');
        return { ...result, required: true };
    }
});

/**
 * Validates item ID parameter
 */
const validateItemId = validateParams({
    id: (val) => {
        const result = validateId(val, 'item_id');
        return { ...result, required: true };
    }
});

/**
 * Validates query parameters for items endpoint
 */
const validateItemsQuery = validateQuery({
    vault_id: (val) => {
        if (val === undefined) return { valid: true, required: false };
        const result = validateId(val, 'vault_id');
        return { ...result, required: false };
    },
    masterPassword: (val) => {
        if (val === undefined) return { valid: true, required: false };
        const result = validateMasterPassword(val);
        return { ...result, required: false };
    }
});

module.exports = {
    validateBody,
    validateParams,
    validateQuery,
    validateRegister,
    validateLogin,
    validateVaultCreate,
    validateItem,
    validateAddMember,
    validateVaultId,
    validateUserId,
    validateItemId,
    validateItemsQuery
};


