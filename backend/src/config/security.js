/**
 * Security Configuration
 * Centralized security settings with secure defaults
 */

module.exports = {
  // JWT Configuration
  jwt: {
    secret: process.env.JWT_SECRET || 'CHANGE-THIS-IN-PRODUCTION-' + require('crypto').randomBytes(32).toString('hex'),
    expiresIn: '1h', // Short-lived tokens for security
    refreshExpiresIn: '7d',
    algorithm: 'HS256'
  },

  // Password Requirements
  password: {
    minLength: 12,
    maxLength: 128,
    requireUppercase: true,
    requireLowercase: true,
    requireNumbers: true,
    requireSpecialChars: true,
    specialChars: '!@#$%^&*()_+-=[]{}|;:,.<>?',
    maxAttempts: 5,
    lockoutDuration: 15 * 60 * 1000 // 15 minutes
  },

  // Rate Limiting
  rateLimit: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 100, // General requests
    authMaxRequests: 5, // Auth attempts per window
    mfaMaxRequests: 3, // MFA attempts per window
    passwordResetMaxRequests: 3
  },

  // Session Configuration
  session: {
    maxAge: 60 * 60 * 1000, // 1 hour
    absoluteMaxAge: 24 * 60 * 60 * 1000, // 24 hours absolute max
    inactivityTimeout: 30 * 60 * 1000, // 30 minutes inactivity
    maxConcurrentSessions: 5
  },

  // Email Verification
  emailVerification: {
    required: true,
    tokenExpiry: 24 * 60 * 60 * 1000, // 24 hours
    resendCooldown: 60 * 1000 // 1 minute between resends
  },

  // MFA Configuration
  mfa: {
    totpWindow: 1, // Accept codes from previous/next period
    backupCodesCount: 10,
    backupCodeLength: 8,
    securityQuestionsRequired: 3,
    deviceTrustDuration: 30 * 24 * 60 * 60 * 1000 // 30 days
  },

  // Input Validation Limits
  validation: {
    username: {
      minLength: 3,
      maxLength: 30,
      pattern: /^[A-Za-z0-9_]+$/
    },
    email: {
      maxLength: 254,
      pattern: /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    },
    postTitle: {
      minLength: 3,
      maxLength: 255
    },
    postBody: {
      minLength: 5,
      maxLength: 50000
    }
  },

  // Security Headers
  headers: {
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:", "https:"],
        connectSrc: ["'self'"],
        fontSrc: ["'self'"],
        objectSrc: ["'none'"],
        mediaSrc: ["'self'"],
        frameSrc: ["'none'"],
        upgradeInsecureRequests: []
      }
    },
    hsts: {
      maxAge: 31536000, // 1 year
      includeSubDomains: true,
      preload: true
    }
  },

  // Audit Logging
  audit: {
    enabled: true,
    logLevel: 'info',
    sensitiveFields: ['password', 'totpSecret', 'backupCodes', 'securityAnswers'],
    retentionDays: 90
  },

  // Account Security
  account: {
    defaultRole: 'customer',
    emailVerificationRequired: true,
    autoLockOnSuspiciousActivity: true,
    requireReauthForSensitiveOps: true
  }
};
