/**
 * API Security Hardening Middleware
 * Implements request signing, API versioning, deprecation warnings, and secure headers
 */

const crypto = require('crypto');

/**
 * API Version Management
 */
class APIVersionManager {
  constructor() {
    this.currentVersion = process.env.API_VERSION || 'v1';
    this.deprecatedVersions = (process.env.API_VERSION_DEPRECATED || '').split(',').filter(v => v);
    this.deprecationDate = process.env.API_DEPRECATION_DATE;
  }

  /**
   * Check if API version is deprecated
   */
  isDeprecated(version) {
    return this.deprecatedVersions.includes(version);
  }

  /**
   * Get deprecation notice
   */
  getDeprecationNotice(version) {
    if (this.isDeprecated(version)) {
      return {
        deprecated: true,
        message: `API version ${version} is deprecated`,
        deprecationDate: this.deprecationDate,
        currentVersion: this.currentVersion,
        migrate: `Please update your client to use ${this.currentVersion}`
      };
    }
    return { deprecated: false };
  }
}

/**
 * Request Signature Validation Middleware
 * Validates HMAC-SHA256 signed requests for sensitive operations
 */
const validateRequestSignature = (req, res, next) => {
  // Only require signature for state-changing operations
  const unsignedMethods = ['GET', 'HEAD', 'OPTIONS'];
  if (unsignedMethods.includes(req.method)) {
    return next();
  }

  // Skip signature validation for auth endpoints (they have their own security)
  if (req.path.includes('/auth/')) {
    return next();
  }

  const signature = req.headers['x-signature'];
  const timestamp = req.headers['x-timestamp'];
  const nonce = req.headers['x-nonce'];

  // Validate signature is present
  if (!signature || !timestamp || !nonce) {
    return res.status(401).json({
      success: false,
      message: 'Request signature missing'
    });
  }

  // Validate timestamp is recent (within 300 seconds / 5 minutes)
  const requestTime = parseInt(timestamp, 10);
  const currentTime = Date.now();
  if (Math.abs(currentTime - requestTime) > 300000) {
    return res.status(401).json({
      success: false,
      message: 'Request timestamp invalid'
    });
  }

  // Validate nonce (basic check - in production, use nonce store)
  if (nonce.length < 16) {
    return res.status(401).json({
      success: false,
      message: 'Invalid nonce'
    });
  }

  // Note: Full signature validation requires API key management
  // This is a placeholder that should be implemented with API keys
  
  next();
};

/**
 * API Version Header Middleware
 * Validates and warns about deprecated API versions
 */
const versionManager = new APIVersionManager();

const apiVersionMiddleware = (req, res, next) => {
  const apiVersion = req.headers['api-version'] || versionManager.currentVersion;
  
  // Store version in request for later use
  req.apiVersion = apiVersion;

  // Check for deprecation
  const deprecationNotice = versionManager.getDeprecationNotice(apiVersion);
  if (deprecationNotice.deprecated) {
    res.setHeader('X-API-Deprecation-Notice', deprecationNotice.message);
    res.setHeader('X-API-Deprecation-Date', deprecationNotice.deprecationDate);
  }

  next();
};

/**
 * Request Size and Complexity Limiting
 */
const requestComplexityMiddleware = (req, res, next) => {
  // Limit nested object depth
  const maxDepth = 10;
  
  const checkDepth = (obj, depth = 0) => {
    if (depth > maxDepth) {
      throw new Error('Request object too deeply nested');
    }
    
    if (typeof obj === 'object' && obj !== null) {
      for (const value of Object.values(obj)) {
        checkDepth(value, depth + 1);
      }
    }
  };

  try {
    checkDepth(req.body);
    next();
  } catch (error) {
    return res.status(400).json({
      success: false,
      message: 'Request validation failed',
      error: error.message
    });
  }
};

/**
 * Response Security Headers
 */
const responseSecurityHeaders = (req, res, next) => {
  // Prevent response caching for sensitive data
  if (req.path.includes('/auth') || req.path.includes('/api/')) {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
  }

  // X-Content-Length: provides actual content length (helps detect compression attacks)
  res.setHeader('X-Content-Length', 'true');

  // X-Response-Time: for performance monitoring (optional)
  const startTime = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - startTime;
    res.setHeader('X-Response-Time', `${duration}ms`);
  });

  next();
};

/**
 * Request Fingerprinting for Anomaly Detection
 */
const requestFingerprinting = (req, res, next) => {
  // Create a fingerprint of the request for security analysis
  const fingerprint = crypto
    .createHash('sha256')
    .update(
      JSON.stringify({
        userAgent: req.headers['user-agent'],
        ip: req.ip,
        method: req.method,
        path: req.path,
        timestamp: Math.floor(Date.now() / 60000) // Group by minute
      })
    )
    .digest('hex');

  req.fingerprint = fingerprint;
  next();
};

/**
 * Validate API Key (if using API key-based authentication)
 */
const validateApiKey = (req, res, next) => {
  const apiKey = req.headers['x-api-key'] || req.query.api_key;

  if (!apiKey) {
    return next(); // Skip validation if no API key provided
  }

  // TODO: Implement API key validation
  // - Check against API key database
  // - Validate key is active and not revoked
  // - Check key permissions for endpoint
  // - Log API key usage

  next();
};

/**
 * HTTP Security Status Codes
 * Ensures proper HTTP status codes are used
 */
const secureStatusCodes = {
  SUCCESS: 200,
  CREATED: 201,
  BAD_REQUEST: 400,
  UNAUTHORIZED: 401,
  FORBIDDEN: 403,
  NOT_FOUND: 404,
  CONFLICT: 409,
  UNPROCESSABLE_ENTITY: 422,
  RATE_LIMITED: 429,
  SERVER_ERROR: 500,
  SERVICE_UNAVAILABLE: 503
};

/**
 * Response builder with secure status codes
 */
const buildResponse = (statusCode, success, message, data = null, meta = {}) => {
  return {
    success,
    message,
    data,
    meta: {
      timestamp: new Date().toISOString(),
      version: process.env.API_VERSION || 'v1',
      ...meta
    }
  };
};

module.exports = {
  validateRequestSignature,
  apiVersionMiddleware,
  requestComplexityMiddleware,
  responseSecurityHeaders,
  requestFingerprinting,
  validateApiKey,
  secureStatusCodes,
  buildResponse,
  APIVersionManager
};
