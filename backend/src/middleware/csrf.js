/**
 * CSRF Protection Middleware
 * Implements Double Submit Cookie pattern for CSRF protection
 */

const crypto = require('crypto');

// CSRF Configuration
const CSRF_CONFIG = {
  tokenLength: 32, // 256 bits
  cookieName: 'XSRF-TOKEN',
  headerName: 'X-XSRF-TOKEN',
  cookieOptions: {
    httpOnly: false, // Must be readable by JavaScript
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    path: '/'
  },
  // Methods that don't require CSRF validation (safe methods)
  safeMethods: ['GET', 'HEAD', 'OPTIONS']
};

/**
 * Generate a cryptographically secure CSRF token
 */
const generateCsrfToken = () => {
  return crypto.randomBytes(CSRF_CONFIG.tokenLength).toString('hex');
};

/**
 * Constant-time string comparison to prevent timing attacks
 */
const safeCompare = (a, b) => {
  if (typeof a !== 'string' || typeof b !== 'string') {
    return false;
  }
  if (a.length !== b.length) {
    return false;
  }
  return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
};

/**
 * Middleware to set CSRF token cookie
 * Should be applied to all routes to ensure a token is always available
 */
const setCsrfToken = (req, res, next) => {
  // Check if token already exists in cookie
  let token = req.cookies?.[CSRF_CONFIG.cookieName];
  
  // Generate new token if none exists or if it's invalid
  if (!token || token.length !== CSRF_CONFIG.tokenLength * 2) {
    token = generateCsrfToken();
    res.cookie(CSRF_CONFIG.cookieName, token, CSRF_CONFIG.cookieOptions);
  }
  
  // Store token on request for potential use
  req.csrfToken = token;
  
  next();
};

/**
 * Middleware to validate CSRF token
 * Should be applied to state-changing routes (POST, PUT, DELETE, PATCH)
 */
const validateCsrfToken = (req, res, next) => {
  // Skip validation for safe methods
  if (CSRF_CONFIG.safeMethods.includes(req.method)) {
    return next();
  }

  // Get token from cookie
  const cookieToken = req.cookies?.[CSRF_CONFIG.cookieName];
  
  // Get token from header (also check alternative header names)
  const headerToken = req.headers[CSRF_CONFIG.headerName.toLowerCase()] ||
                     req.headers['x-csrf-token'] ||
                     req.headers['csrf-token'];

  // Validate tokens exist
  if (!cookieToken) {
    console.warn('CSRF validation failed: No cookie token', {
      path: req.path,
      method: req.method,
      ip: req.ip
    });
    return res.status(403).json({
      success: false,
      message: 'CSRF validation failed: Missing token'
    });
  }

  if (!headerToken) {
    console.warn('CSRF validation failed: No header token', {
      path: req.path,
      method: req.method,
      ip: req.ip
    });
    return res.status(403).json({
      success: false,
      message: 'CSRF validation failed: Missing token in header'
    });
  }

  // Validate tokens match using constant-time comparison
  if (!safeCompare(cookieToken, headerToken)) {
    console.warn('CSRF validation failed: Token mismatch', {
      path: req.path,
      method: req.method,
      ip: req.ip
    });
    return res.status(403).json({
      success: false,
      message: 'CSRF validation failed: Invalid token'
    });
  }

  next();
};

/**
 * Combined middleware for CSRF protection
 * Sets token and validates on non-safe methods
 */
const csrfProtection = (req, res, next) => {
  setCsrfToken(req, res, () => {
    validateCsrfToken(req, res, next);
  });
};

/**
 * Route handler to get a fresh CSRF token
 * Useful for SPAs to fetch token before making requests
 */
const getCsrfToken = (req, res) => {
  // Use the token already set by setCsrfToken middleware
  // or generate a new one if needed
  let token = req.csrfToken;
  
  if (!token) {
    token = generateCsrfToken();
    res.cookie(CSRF_CONFIG.cookieName, token, CSRF_CONFIG.cookieOptions);
  }
  
  res.json({ 
    success: true,
    csrfToken: token 
  });
};

module.exports = {
  setCsrfToken,
  validateCsrfToken,
  csrfProtection,
  getCsrfToken,
  CSRF_CONFIG
};
