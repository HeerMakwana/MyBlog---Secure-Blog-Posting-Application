/**
 * Environment Configuration Validator
 * Validates that all required environment variables are set and properly configured
 * Prevents application startup with invalid configuration
 */

const fs = require('fs');
const path = require('path');

class EnvironmentValidator {
  constructor() {
    this.errors = [];
    this.warnings = [];
  }

  /**
   * Validate that required environment variable is set
   */
  validateRequired(key, description) {
    const value = process.env[key];
    if (!value) {
      this.errors.push(`❌ Required: ${key} - ${description}`);
      return false;
    }
    return true;
  }

  /**
   * Validate environment variable length
   */
  validateMinLength(key, minLength, description) {
    const value = process.env[key];
    if (value && value.length < minLength) {
      this.errors.push(`❌ ${key} must be at least ${minLength} characters. ${description}`);
      return false;
    }
    return true;
  }

  /**
   * Validate environment variable matches pattern
   */
  validatePattern(key, pattern, description) {
    const value = process.env[key];
    if (value && !pattern.test(value)) {
      this.errors.push(`❌ ${key} format invalid. ${description}`);
      return false;
    }
    return true;
  }

  /**
   * Validate boolean environment variable
   */
  validateBoolean(key) {
    const value = process.env[key];
    if (value && !['true', 'false'].includes(value.toLowerCase())) {
      this.errors.push(`❌ ${key} must be 'true' or 'false'`);
      return false;
    }
    return true;
  }

  /**
   * Validate numeric environment variable
   */
  validateNumeric(key, minValue, maxValue) {
    const value = process.env[key];
    if (value) {
      const num = parseInt(value, 10);
      if (isNaN(num)) {
        this.errors.push(`❌ ${key} must be a number`);
        return false;
      }
      if (minValue !== undefined && num < minValue) {
        this.errors.push(`❌ ${key} must be at least ${minValue}`);
        return false;
      }
      if (maxValue !== undefined && num > maxValue) {
        this.errors.push(`❌ ${key} must not exceed ${maxValue}`);
        return false;
      }
    }
    return true;
  }

  /**
   * Validate URL format
   */
  validateUrl(key) {
    const value = process.env[key];
    if (value) {
      try {
        new URL(value);
      } catch {
        this.errors.push(`❌ ${key} must be a valid URL`);
        return false;
      }
    }
    return true;
  }

  /**
   * Validate email format
   */
  validateEmail(key) {
    const value = process.env[key];
    if (value) {
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(value)) {
        this.errors.push(`❌ ${key} must be a valid email address`);
        return false;
      }
    }
    return true;
  }

  /**
   * Add a warning (non-blocking)
   */
  addWarning(message) {
    this.warnings.push(`⚠️  ${message}`);
  }

  /**
   * Validate all security-critical environment variables
   */
  validateAll() {
    // Server Configuration
    this.validateRequired('NODE_ENV', 'Must be development, test, or production');
    this.validatePattern(
      'NODE_ENV',
      /^(development|test|production)$/,
      'Must be one of: development, test, production'
    );

    // Database Configuration
    this.validateRequired('MONGODB_URI', 'MongoDB connection string required');
    this.validateUrl('MONGODB_URI');

    // JWT Secrets - CRITICAL
    if (process.env.NODE_ENV === 'production') {
      this.validateRequired('JWT_SECRET', 'JWT secret required');
      this.validateMinLength(
        'JWT_SECRET',
        64,
        'Generate with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"'
      );

      this.validateRequired('SESSION_SECRET', 'Session secret required');
      this.validateMinLength(
        'SESSION_SECRET',
        64,
        'Generate with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"'
      );

      this.validateRequired('CSRF_SECRET', 'CSRF secret required');
      this.validateMinLength(
        'CSRF_SECRET',
        32,
        'Generate with: node -e "console.log(require(\'crypto\').randomBytes(16).toString(\'hex\'))"'
      );

      this.validateRequired('ENCRYPTION_KEY', 'Encryption key required');
      this.validateMinLength(
        'ENCRYPTION_KEY',
        64,
        'Generate with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"'
      );

      // Warn if using default/insecure values
      if (process.env.JWT_SECRET?.includes('change-this') ||
          process.env.JWT_SECRET?.length < 64) {
        this.addWarning('JWT_SECRET appears to be insecure. Use a 64+ character random string.');
      }
    }

    // Cookie Security
    this.validateBoolean('COOKIE_SECURE');
    this.validateBoolean('COOKIE_HTTP_ONLY');
    this.validateBoolean('COOKIE_SAME_SITE');

    // CORS Origins
    this.validateRequired('ALLOWED_ORIGINS', 'At least one allowed origin required');

    // Rate Limiting
    this.validateNumeric('RATE_LIMIT_WINDOW_MS', 1000, 86400000);
    this.validateNumeric('RATE_LIMIT_MAX_REQUESTS', 1, 10000);
    this.validateNumeric('RATE_LIMIT_AUTH_MAX_REQUESTS', 1, 100);

    // Admin Bootstrap
    if (process.env.ADMIN_USERNAME) {
      this.validateRequired('ADMIN_EMAIL', 'Admin email required if admin username is set');
      this.validateEmail('ADMIN_EMAIL');
      this.validateRequired('ADMIN_PASSWORD', 'Admin password required if admin username is set');
      this.validateMinLength(
        'ADMIN_PASSWORD',
        12,
        'Admin password should be at least 12 characters'
      );
    }

    // Email Configuration
    if (process.env.NODE_ENV === 'production') {
      if (process.env.ENABLE_EMAIL_VERIFICATION !== 'false') {
        this.validateRequired('SMTP_HOST', 'SMTP host required for email verification');
        this.validateRequired('SMTP_PORT', 'SMTP port required');
        this.validateRequired('SMTP_USER', 'SMTP user required');
        this.validateRequired('SMTP_PASS', 'SMTP password required');
        this.validateRequired('EMAIL_FROM', 'Email sender address required');
      }
    }

    // Security Features
    this.validateBoolean('ENABLE_AUDIT_LOGGING');
    this.validateBoolean('ENABLE_RATE_LIMITING');
    this.validateBoolean('ENABLE_CSRF_PROTECTION');
    this.validateBoolean('ENABLE_EMAIL_VERIFICATION');
    this.validateBoolean('ENABLE_ACCOUNT_LOCKOUT');
    this.validateBoolean('ENABLE_CAPTCHA');

    // Password Policy
    this.validateNumeric('PASSWORD_MIN_LENGTH', 8, 128);
    this.validateNumeric('PASSWORD_MAX_LENGTH', 16, 1024);

    // Production-specific validations
    if (process.env.NODE_ENV === 'production') {
      if (process.env.COOKIE_SECURE === 'false') {
        this.errors.push(
          '❌ COOKIE_SECURE must be true in production (requires HTTPS)'
        );
      }

      if (!process.env.ALLOWED_ORIGINS ||
          process.env.ALLOWED_ORIGINS.includes('localhost') ||
          process.env.ALLOWED_ORIGINS.includes('*')) {
        this.errors.push(
          '❌ ALLOWED_ORIGINS must specify production domain(s), not localhost or *'
        );
      }

      if (process.env.LOG_SENSITIVE_DATA === 'true') {
        this.addWarning('LOG_SENSITIVE_DATA is enabled in production - consider disabling');
      }

      if (process.env.TRUST_PROXY !== '1') {
        this.addWarning(
          'TRUST_PROXY should be 1 if behind a reverse proxy (nginx, cloudflare, etc.)'
        );
      }
    }

    // Development-specific warnings
    if (process.env.NODE_ENV === 'development') {
      if (process.env.JWT_SECRET?.length < 64) {
        this.addWarning('JWT_SECRET is short. Use a 64+ character string in development.');
      }
    }

    return this.errors.length === 0;
  }

  /**
   * Print validation results
   */
  printResults() {
    console.log('\n═══════════════════════════════════════════════════════════');
    console.log('  ENVIRONMENT CONFIGURATION VALIDATION');
    console.log('═══════════════════════════════════════════════════════════\n');

    if (this.errors.length === 0 && this.warnings.length === 0) {
      console.log('✅ All environment variables validated successfully!\n');
      return true;
    }

    if (this.errors.length > 0) {
      console.log('ERRORS (Configuration Invalid):\n');
      this.errors.forEach(err => console.log(`  ${err}`));
      console.log();
    }

    if (this.warnings.length > 0) {
      console.log('WARNINGS (Non-blocking):\n');
      this.warnings.forEach(warn => console.log(`  ${warn}`));
      console.log();
    }

    console.log('═══════════════════════════════════════════════════════════\n');
    return this.errors.length === 0;
  }
}

/**
 * Validate and exit if configuration is invalid
 */
function validateEnvironment() {
  const validator = new EnvironmentValidator();
  const isValid = validator.validateAll();
  const hasOutput = validator.printResults();

  if (!isValid) {
    console.error('❌ Environment configuration validation failed!');
    console.error('Please fix the errors above and try again.\n');
    process.exit(1);
  }

  return validator;
}

module.exports = {
  EnvironmentValidator,
  validateEnvironment
};
