/**
 * Rate Limiting Middleware
 * Protects against brute force and DoS attacks
 */

const securityConfig = require('../config/security');
const { logAuditEvent } = require('../utils/auditLogger');
const { SAFE_ERRORS } = require('../utils/validation');

// In-memory store for rate limiting (use Redis in production)
const rateLimitStore = new Map();

/**
 * Clean up expired entries periodically
 */
setInterval(() => {
  const now = Date.now();
  for (const [key, data] of rateLimitStore.entries()) {
    if (data.resetTime < now) {
      rateLimitStore.delete(key);
    }
  }
}, 60000); // Clean up every minute

/**
 * Get client identifier for rate limiting
 * @param {Object} req - Express request
 * @returns {string}
 */
const getClientId = (req) => {
  // Use IP address as primary identifier
  const ip = req.ip || req.connection?.remoteAddress || 'unknown';
  // Optionally include user ID for authenticated requests
  const userId = req.user?._id?.toString() || '';
  return `${ip}:${userId}`;
};

/**
 * Create rate limiter middleware
 * @param {Object} options - Rate limiter options
 * @returns {Function}
 */
const createRateLimiter = (options = {}) => {
  const {
    windowMs = securityConfig.rateLimit.windowMs,
    maxRequests = securityConfig.rateLimit.maxRequests,
    message = SAFE_ERRORS.RATE_LIMITED,
    keyPrefix = 'rl',
    skipSuccessfulRequests = false,
    skipFailedRequests = false
  } = options;

  return async (req, res, next) => {
    const clientId = `${keyPrefix}:${getClientId(req)}`;
    const now = Date.now();

    // Get or create rate limit data
    let data = rateLimitStore.get(clientId);
    
    if (!data || data.resetTime < now) {
      data = {
        count: 0,
        resetTime: now + windowMs
      };
      rateLimitStore.set(clientId, data);
    }

    // Increment request count
    data.count++;

    // Set rate limit headers
    res.set({
      'X-RateLimit-Limit': maxRequests,
      'X-RateLimit-Remaining': Math.max(0, maxRequests - data.count),
      'X-RateLimit-Reset': Math.ceil(data.resetTime / 1000)
    });

    // Check if limit exceeded
    if (data.count > maxRequests) {
      // Log rate limit exceeded
      await logAuditEvent({
        eventType: 'RATE_LIMIT_EXCEEDED',
        userId: req.user?._id,
        username: req.user?.username,
        req,
        action: `Rate limit exceeded: ${keyPrefix}`,
        status: 'BLOCKED',
        details: { 
          limit: maxRequests, 
          requests: data.count,
          windowMs 
        },
        riskLevel: 'MEDIUM'
      });

      res.set('Retry-After', Math.ceil((data.resetTime - now) / 1000));
      
      return res.status(429).json({
        success: false,
        message,
        retryAfter: Math.ceil((data.resetTime - now) / 1000)
      });
    }

    // Add skip handlers for conditional counting
    if (skipSuccessfulRequests || skipFailedRequests) {
      const originalJson = res.json.bind(res);
      res.json = function(body) {
        const isSuccess = res.statusCode >= 200 && res.statusCode < 300;
        if ((skipSuccessfulRequests && isSuccess) || (skipFailedRequests && !isSuccess)) {
          data.count--;
        }
        return originalJson(body);
      };
    }

    next();
  };
};

/**
 * General rate limiter
 */
const generalRateLimiter = createRateLimiter({
  keyPrefix: 'general',
  maxRequests: securityConfig.rateLimit.maxRequests
});

/**
 * Strict rate limiter for authentication endpoints
 */
const authRateLimiter = createRateLimiter({
  keyPrefix: 'auth',
  maxRequests: securityConfig.rateLimit.authMaxRequests,
  windowMs: 15 * 60 * 1000, // 15 minutes
  skipSuccessfulRequests: false // Count all attempts
});

/**
 * MFA rate limiter
 */
const mfaRateLimiter = createRateLimiter({
  keyPrefix: 'mfa',
  maxRequests: securityConfig.rateLimit.mfaMaxRequests,
  windowMs: 15 * 60 * 1000
});

/**
 * Password reset rate limiter
 */
const passwordResetRateLimiter = createRateLimiter({
  keyPrefix: 'pwreset',
  maxRequests: securityConfig.rateLimit.passwordResetMaxRequests,
  windowMs: 60 * 60 * 1000 // 1 hour
});

/**
 * Account lockout tracking
 */
const loginAttemptStore = new Map();

/**
 * Track failed login attempts and lock accounts
 * @param {string} identifier - Username or email
 * @param {boolean} success - Whether login was successful
 * @returns {{ locked: boolean, attemptsRemaining: number }}
 */
const trackLoginAttempt = (identifier, success) => {
  const key = `login:${identifier.toLowerCase()}`;
  const now = Date.now();
  const lockoutDuration = securityConfig.password.lockoutDuration;
  const maxAttempts = securityConfig.password.maxAttempts;

  let data = loginAttemptStore.get(key);

  if (!data || data.resetTime < now) {
    data = {
      attempts: 0,
      resetTime: now + lockoutDuration,
      lockedUntil: null
    };
  }

  if (success) {
    // Clear on successful login
    loginAttemptStore.delete(key);
    return { locked: false, attemptsRemaining: maxAttempts };
  }

  data.attempts++;
  
  if (data.attempts >= maxAttempts) {
    data.lockedUntil = now + lockoutDuration;
  }

  loginAttemptStore.set(key, data);

  return {
    locked: data.lockedUntil && data.lockedUntil > now,
    attemptsRemaining: Math.max(0, maxAttempts - data.attempts),
    lockedUntil: data.lockedUntil
  };
};

/**
 * Check if account is locked
 * @param {string} identifier - Username or email
 * @returns {{ locked: boolean, lockedUntil?: number }}
 */
const isAccountLocked = (identifier) => {
  const key = `login:${identifier.toLowerCase()}`;
  const data = loginAttemptStore.get(key);
  const now = Date.now();

  if (!data || !data.lockedUntil) {
    return { locked: false };
  }

  if (data.lockedUntil > now) {
    return { 
      locked: true, 
      lockedUntil: data.lockedUntil,
      remainingTime: Math.ceil((data.lockedUntil - now) / 1000)
    };
  }

  // Lock expired, clear data
  loginAttemptStore.delete(key);
  return { locked: false };
};

module.exports = {
  createRateLimiter,
  generalRateLimiter,
  authRateLimiter,
  mfaRateLimiter,
  passwordResetRateLimiter,
  trackLoginAttempt,
  isAccountLocked
};
