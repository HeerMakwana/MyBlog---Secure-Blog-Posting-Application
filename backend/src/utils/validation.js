/**
 * Input Validation Utility
 * Implements server-side validation with safe error messages
 */

const securityConfig = require('../config/security');

// Generic error messages that don't leak system information
const SAFE_ERRORS = {
  INVALID_INPUT: 'Invalid input provided',
  INVALID_CREDENTIALS: 'Invalid credentials',
  VALIDATION_FAILED: 'Validation failed',
  UNAUTHORIZED: 'Unauthorized access',
  FORBIDDEN: 'Access denied',
  NOT_FOUND: 'Resource not found',
  RATE_LIMITED: 'Too many requests. Please try again later',
  SERVER_ERROR: 'An error occurred. Please try again'
};

/**
 * Sanitize string input - remove potentially dangerous characters
 * @param {string} input - Input to sanitize
 * @returns {string}
 */
const sanitizeString = (input) => {
  if (typeof input !== 'string') return '';
  return input
    .trim()
    .replace(/[<>]/g, '') // Remove HTML brackets
    .replace(/javascript:/gi, '') // Remove javascript: protocol
    .replace(/on\w+=/gi, ''); // Remove event handlers
};

/**
 * Validate email format
 * @param {string} email - Email to validate
 * @returns {{ valid: boolean, error?: string }}
 */
const validateEmail = (email) => {
  if (!email || typeof email !== 'string') {
    return { valid: false, error: 'Email is required' };
  }

  const sanitized = sanitizeString(email).toLowerCase();
  
  if (sanitized.length > securityConfig.validation.email.maxLength) {
    return { valid: false, error: 'Email is too long' };
  }

  if (!securityConfig.validation.email.pattern.test(sanitized)) {
    return { valid: false, error: 'Invalid email format' };
  }

  return { valid: true, value: sanitized };
};

/**
 * Validate username
 * @param {string} username - Username to validate
 * @returns {{ valid: boolean, error?: string }}
 */
const validateUsername = (username) => {
  if (!username || typeof username !== 'string') {
    return { valid: false, error: 'Username is required' };
  }

  const sanitized = sanitizeString(username);
  const { minLength, maxLength, pattern } = securityConfig.validation.username;

  if (sanitized.length < minLength) {
    return { valid: false, error: `Username must be at least ${minLength} characters` };
  }

  if (sanitized.length > maxLength) {
    return { valid: false, error: `Username cannot exceed ${maxLength} characters` };
  }

  if (!pattern.test(sanitized)) {
    return { valid: false, error: 'Username can only contain letters, numbers, and underscores' };
  }

  return { valid: true, value: sanitized };
};

/**
 * Validate password strength
 * @param {string} password - Password to validate
 * @returns {{ valid: boolean, error?: string }}
 */
const validatePassword = (password) => {
  if (!password || typeof password !== 'string') {
    return { valid: false, error: 'Password is required' };
  }

  const config = securityConfig.password;

  if (password.length < config.minLength) {
    return { valid: false, error: `Password must be at least ${config.minLength} characters` };
  }

  if (password.length > config.maxLength) {
    return { valid: false, error: `Password cannot exceed ${config.maxLength} characters` };
  }

  if (config.requireUppercase && !/[A-Z]/.test(password)) {
    return { valid: false, error: 'Password must contain at least one uppercase letter' };
  }

  if (config.requireLowercase && !/[a-z]/.test(password)) {
    return { valid: false, error: 'Password must contain at least one lowercase letter' };
  }

  if (config.requireNumbers && !/\d/.test(password)) {
    return { valid: false, error: 'Password must contain at least one number' };
  }

  if (config.requireSpecialChars) {
    const specialRegex = new RegExp(`[${config.specialChars.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, '\\$&')}]`);
    if (!specialRegex.test(password)) {
      return { valid: false, error: 'Password must contain at least one special character' };
    }
  }

  // Check for common weak passwords
  const commonPasswords = ['password', '123456', 'qwerty', 'admin', 'letmein'];
  if (commonPasswords.some(weak => password.toLowerCase().includes(weak))) {
    return { valid: false, error: 'Password is too common. Please choose a stronger password' };
  }

  return { valid: true };
};

/**
 * Validate post title
 * @param {string} title - Title to validate
 * @returns {{ valid: boolean, error?: string }}
 */
const validatePostTitle = (title) => {
  if (!title || typeof title !== 'string') {
    return { valid: false, error: 'Title is required' };
  }

  const sanitized = sanitizeString(title);
  const { minLength, maxLength } = securityConfig.validation.postTitle;

  if (sanitized.length < minLength) {
    return { valid: false, error: `Title must be at least ${minLength} characters` };
  }

  if (sanitized.length > maxLength) {
    return { valid: false, error: `Title cannot exceed ${maxLength} characters` };
  }

  return { valid: true, value: sanitized };
};

/**
 * Validate post body
 * @param {string} body - Body to validate
 * @returns {{ valid: boolean, error?: string }}
 */
const validatePostBody = (body) => {
  if (!body || typeof body !== 'string') {
    return { valid: false, error: 'Body is required' };
  }

  const sanitized = sanitizeString(body);
  const { minLength, maxLength } = securityConfig.validation.postBody;

  if (sanitized.length < minLength) {
    return { valid: false, error: `Body must be at least ${minLength} characters` };
  }

  if (sanitized.length > maxLength) {
    return { valid: false, error: `Body cannot exceed ${maxLength} characters` };
  }

  return { valid: true, value: sanitized };
};

/**
 * Validate MongoDB ObjectId
 * @param {string} id - ID to validate
 * @returns {{ valid: boolean, error?: string }}
 */
const validateObjectId = (id) => {
  if (!id || typeof id !== 'string') {
    return { valid: false, error: SAFE_ERRORS.INVALID_INPUT };
  }

  if (!/^[a-fA-F0-9]{24}$/.test(id)) {
    return { valid: false, error: SAFE_ERRORS.INVALID_INPUT };
  }

  return { valid: true };
};

/**
 * Validate TOTP code
 * @param {string} code - TOTP code to validate
 * @returns {{ valid: boolean, error?: string }}
 */
const validateTOTPCode = (code) => {
  if (!code || typeof code !== 'string') {
    return { valid: false, error: 'Verification code is required' };
  }

  // TOTP codes are 6 digits
  if (!/^\d{6}$/.test(code)) {
    return { valid: false, error: 'Invalid verification code format' };
  }

  return { valid: true };
};

/**
 * Validate backup code
 * @param {string} code - Backup code to validate
 * @returns {{ valid: boolean, error?: string }}
 */
const validateBackupCode = (code) => {
  if (!code || typeof code !== 'string') {
    return { valid: false, error: 'Backup code is required' };
  }

  // Backup codes are 8 alphanumeric characters
  if (!/^[A-Za-z0-9]{8}$/.test(code)) {
    return { valid: false, error: 'Invalid backup code format' };
  }

  return { valid: true };
};

/**
 * Create validation middleware
 * @param {Object} schema - Validation schema
 * @returns {Function}
 */
const createValidator = (schema) => {
  return (req, res, next) => {
    const errors = [];

    for (const [field, validator] of Object.entries(schema)) {
      const value = req.body[field];
      const result = validator(value);

      if (!result.valid) {
        errors.push({ field, message: result.error });
      } else if (result.value !== undefined) {
        req.body[field] = result.value; // Use sanitized value
      }
    }

    if (errors.length > 0) {
      return res.status(400).json({
        success: false,
        message: SAFE_ERRORS.VALIDATION_FAILED,
        errors
      });
    }

    next();
  };
};

module.exports = {
  SAFE_ERRORS,
  sanitizeString,
  validateEmail,
  validateUsername,
  validatePassword,
  validatePostTitle,
  validatePostBody,
  validateObjectId,
  validateTOTPCode,
  validateBackupCode,
  createValidator
};
