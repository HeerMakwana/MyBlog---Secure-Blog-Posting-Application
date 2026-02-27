/**
 * CSRF Protection Middleware
 * Implements the Synchronizer Token Pattern for CSRF protection
 * Uses double-submit cookie method with server-side validation
 */

const crypto = require('crypto');
const { logAuditEvent } = require('../utils/auditLogger');

// Token configuration
const CSRF_TOKEN_LENGTH = 32;
const CSRF_COOKIE_NAME = 'csrf_token';
const CSRF_HEADER_NAME = 'x-csrf-token';

/**
 * Generate a cryptographically secure CSRF token
 */
const generateCsrfToken = () => {
  return crypto.randomBytes(CSRF_TOKEN_LENGTH).toString('hex');
};

/**
 * Hash CSRF token for secure comparison
 */
const hashToken = (token) => {
  const secret = process.env.CSRF_SECRET || 'csrf-secret-change-in-production';
  return crypto.createHmac('sha256', secret).update(token).digest('hex');
};

/**
 * Timing-safe token comparison to prevent timing attacks
 */
const safeCompare = (a, b) => {
  if (typeof a !== 'string' || typeof b !== 'string') {
    return false;
  }
  
  try {
    return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
  } catch {
    return false;
  }
};

/**
 * Get CSRF cookie options
 */
const getCsrfCookieOptions = () => {
  const isProduction = process.env.NODE_ENV === 'production';
  
  return {
    httpOnly: false, // Must be readable by JavaScript to send in header
    secure: isProduction || process.env.COOKIE_SECURE === 'true',
    sameSite: process.env.COOKIE_SAME_SITE || 'strict',
    maxAge: parseInt(process.env.SESSION_MAX_AGE, 10) || 60 * 60 * 1000, // Match session lifetime
    path: '/',
    domain: isProduction ? process.env.COOKIE_DOMAIN : undefined
  };
};

/**
 * Middleware to set CSRF token cookie
 * Should be called early in the middleware chain
 */
const setCsrfToken = (req, res, next) => {
  // Generate new token if not present in session
  if (!req.session?.csrfToken) {
    const token = generateCsrfToken();
    const hashedToken = hashToken(token);
    
    // Store hashed token in session for server-side validation
    if (req.session) {
      req.session.csrfToken = hashedToken;
    }
    
    // Set unhashed token in cookie for client to read and send back
    res.cookie(CSRF_COOKIE_NAME, token, getCsrfCookieOptions());
    
    // Also expose token via response header for SPA convenience
    res.setHeader('X-CSRF-Token', token);
  }
  
  next();
};

/**
 * CSRF validation middleware
 * Validates token from header/body against session token
 */
const validateCsrfToken = async (req, res, next) => {
  // Skip CSRF validation for safe methods
  const safeMethods = ['GET', 'HEAD', 'OPTIONS'];
  if (safeMethods.includes(req.method)) {
    return next();
  }
  
  try {
    // Get token from request (header or body)
    const tokenFromHeader = req.headers[CSRF_HEADER_NAME];
    const tokenFromBody = req.body?._csrf;
    const tokenFromQuery = req.query?._csrf;
    const tokenFromCookie = req.cookies?.[CSRF_COOKIE_NAME];
    
    const submittedToken = tokenFromHeader || tokenFromBody || tokenFromQuery;
    
    // Validate token presence
    if (!submittedToken) {
      await logAuditEvent({
        eventType: 'SUSPICIOUS_ACTIVITY',
        userId: req.session?.userId,
        req,
        action: 'CSRF token missing',
        status: 'BLOCKED',
        riskLevel: 'HIGH',
        details: { path: req.path, method: req.method }
      });
      
      return res.status(403).json({
        success: false,
        message: 'CSRF token missing'
      });
    }
    
    // Validate session token exists
    if (!req.session?.csrfToken) {
      await logAuditEvent({
        eventType: 'SUSPICIOUS_ACTIVITY',
        userId: req.session?.userId,
        req,
        action: 'CSRF session token missing',
        status: 'BLOCKED',
        riskLevel: 'HIGH',
        details: { path: req.path, method: req.method }
      });
      
      return res.status(403).json({
        success: false,
        message: 'CSRF validation failed - session expired'
      });
    }
    
    // Hash submitted token and compare with session token
    const hashedSubmittedToken = hashToken(submittedToken);
    
    if (!safeCompare(hashedSubmittedToken, req.session.csrfToken)) {
      await logAuditEvent({
        eventType: 'SUSPICIOUS_ACTIVITY',
        userId: req.session?.userId,
        req,
        action: 'CSRF token mismatch',
        status: 'BLOCKED',
        riskLevel: 'HIGH',
        details: { path: req.path, method: req.method }
      });
      
      return res.status(403).json({
        success: false,
        message: 'CSRF validation failed'
      });
    }
    
    // Token is valid - optionally rotate token for extra security
    if (process.env.CSRF_ROTATE_ON_USE === 'true') {
      const newToken = generateCsrfToken();
      req.session.csrfToken = hashToken(newToken);
      res.cookie(CSRF_COOKIE_NAME, newToken, getCsrfCookieOptions());
      res.setHeader('X-CSRF-Token', newToken);
    }
    
    next();
  } catch (error) {
    console.error('CSRF validation error:', error);
    return res.status(403).json({
      success: false,
      message: 'CSRF validation failed'
    });
  }
};

/**
 * Combined CSRF middleware
 * Sets token on all requests, validates on state-changing requests
 */
const csrfProtection = [setCsrfToken, validateCsrfToken];

/**
 * Skip CSRF validation for specific routes (e.g., webhooks)
 * Use with caution!
 */
const skipCsrf = (req, res, next) => {
  req.skipCsrf = true;
  next();
};

/**
 * Conditional CSRF validation that respects skipCsrf flag
 */
const conditionalCsrfValidation = async (req, res, next) => {
  if (req.skipCsrf) {
    return next();
  }
  return validateCsrfToken(req, res, next);
};

/**
 * CSRF token endpoint - returns current token for SPAs
 */
const csrfTokenEndpoint = (req, res) => {
  const token = generateCsrfToken();
  const hashedToken = hashToken(token);
  
  if (req.session) {
    req.session.csrfToken = hashedToken;
  }
  
  res.cookie(CSRF_COOKIE_NAME, token, getCsrfCookieOptions());
  
  res.json({
    success: true,
    csrfToken: token
  });
};

/**
 * Middleware to add CSRF token to response locals (for server-rendered views)
 */
const csrfTokenLocals = (req, res, next) => {
  // Generate token if needed
  if (!req.session?.csrfToken) {
    const token = generateCsrfToken();
    const hashedToken = hashToken(token);
    
    if (req.session) {
      req.session.csrfToken = hashedToken;
    }
    
    res.cookie(CSRF_COOKIE_NAME, token, getCsrfCookieOptions());
    res.locals.csrfToken = token;
  } else {
    // Extract token from cookie for locals
    res.locals.csrfToken = req.cookies?.[CSRF_COOKIE_NAME] || '';
  }
  
  next();
};

module.exports = {
  generateCsrfToken,
  setCsrfToken,
  validateCsrfToken,
  csrfProtection,
  skipCsrf,
  conditionalCsrfValidation,
  csrfTokenEndpoint,
  csrfTokenLocals,
  CSRF_COOKIE_NAME,
  CSRF_HEADER_NAME
};
