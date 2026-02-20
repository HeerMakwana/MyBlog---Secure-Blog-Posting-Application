/**
 * Security Headers Middleware
 * Implements defense-in-depth with security headers
 */

const securityConfig = require('../config/security');

/**
 * Apply security headers to all responses
 */
const securityHeaders = (req, res, next) => {
  // Content Security Policy
  const csp = securityConfig.headers.contentSecurityPolicy;
  const cspString = Object.entries(csp.directives)
    .map(([directive, values]) => {
      const kebabDirective = directive.replace(/([A-Z])/g, '-$1').toLowerCase();
      if (Array.isArray(values) && values.length === 0) {
        return kebabDirective;
      }
      return `${kebabDirective} ${values.join(' ')}`;
    })
    .join('; ');
  
  res.setHeader('Content-Security-Policy', cspString);

  // HTTP Strict Transport Security
  const hsts = securityConfig.headers.hsts;
  let hstsValue = `max-age=${hsts.maxAge}`;
  if (hsts.includeSubDomains) hstsValue += '; includeSubDomains';
  if (hsts.preload) hstsValue += '; preload';
  res.setHeader('Strict-Transport-Security', hstsValue);

  // Prevent MIME type sniffing
  res.setHeader('X-Content-Type-Options', 'nosniff');

  // Prevent clickjacking
  res.setHeader('X-Frame-Options', 'DENY');

  // XSS Protection (legacy, but still useful)
  res.setHeader('X-XSS-Protection', '1; mode=block');

  // Referrer Policy
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

  // Permissions Policy (formerly Feature-Policy)
  res.setHeader('Permissions-Policy', 
    'accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()');

  // Cache control for sensitive data
  if (req.path.includes('/api/auth') || req.path.includes('/api/admin')) {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
  }

  // Remove server identification
  res.removeHeader('X-Powered-By');

  next();
};

/**
 * CORS configuration middleware
 */
const corsConfig = {
  origin: (origin, callback) => {
    // Allow requests with no origin (mobile apps, curl, etc.)
    if (!origin) return callback(null, true);
    
    const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',') || [
      'http://localhost:3000',
      'http://localhost:5000'
    ];
    
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'X-CSRF-Token'],
  exposedHeaders: ['X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset'],
  maxAge: 86400 // 24 hours
};

/**
 * Request sanitization middleware
 * Removes potentially dangerous data from requests
 */
const sanitizeRequest = (req, res, next) => {
  // Remove null bytes from all string values
  const sanitize = (obj) => {
    if (typeof obj === 'string') {
      return obj.replace(/\0/g, '');
    }
    if (Array.isArray(obj)) {
      return obj.map(sanitize);
    }
    if (obj && typeof obj === 'object') {
      const sanitized = {};
      for (const [key, value] of Object.entries(obj)) {
        // Block prototype pollution
        if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
          continue;
        }
        sanitized[key] = sanitize(value);
      }
      return sanitized;
    }
    return obj;
  };

  if (req.body) req.body = sanitize(req.body);
  if (req.query) req.query = sanitize(req.query);
  if (req.params) req.params = sanitize(req.params);

  next();
};

/**
 * Request size limiter
 */
const requestSizeLimiter = (maxSize = '10kb') => {
  return (req, res, next) => {
    const contentLength = parseInt(req.headers['content-length'] || '0', 10);
    const maxBytes = parseSize(maxSize);
    
    if (contentLength > maxBytes) {
      return res.status(413).json({
        success: false,
        message: 'Request entity too large'
      });
    }
    
    next();
  };
};

/**
 * Parse size string to bytes
 */
const parseSize = (size) => {
  const units = { b: 1, kb: 1024, mb: 1024 * 1024, gb: 1024 * 1024 * 1024 };
  const match = String(size).toLowerCase().match(/^(\d+)(b|kb|mb|gb)?$/);
  if (!match) return 10240; // Default 10kb
  return parseInt(match[1], 10) * (units[match[2]] || 1);
};

/**
 * Security middleware chain for sensitive operations
 */
const sensitiveOperationChain = [
  securityHeaders,
  sanitizeRequest
];

module.exports = {
  securityHeaders,
  corsConfig,
  sanitizeRequest,
  requestSizeLimiter,
  sensitiveOperationChain
};
