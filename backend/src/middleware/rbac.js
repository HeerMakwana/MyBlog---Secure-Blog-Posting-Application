/**
 * RBAC Permission Middleware
 * Implements granular permission checking for routes
 */

const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { ROLES, PERMISSIONS, hasPermission, hasMinimumRole } = require('../config/roles');
const securityConfig = require('../config/security');
const { logAuditEvent } = require('../utils/auditLogger');
const { SAFE_ERRORS } = require('../utils/validation');

/**
 * Get JWT secret
 */
const getJwtSecret = () => {
  return securityConfig.jwt.secret;
};

/**
 * Generate JWT token
 * @param {string} userId - User ID
 * @param {Object} options - Token options
 * @returns {string}
 */
const generateToken = (userId, options = {}) => {
  const { mfaPending = false, sessionId = null } = options;
  
  return jwt.sign(
    { 
      id: userId, 
      mfaPending,
      sessionId,
      iat: Math.floor(Date.now() / 1000)
    },
    getJwtSecret(),
    { 
      expiresIn: mfaPending ? '5m' : securityConfig.jwt.expiresIn,
      algorithm: securityConfig.jwt.algorithm
    }
  );
};

/**
 * Authentication middleware - verifies JWT and loads user
 * Fails closed (denies access by default)
 */
const authenticate = async (req, res, next) => {
  try {
    let token;

    // Extract token from Authorization header
    if (req.headers.authorization?.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    }

    // Fail closed: no token = no access
    if (!token) {
      return res.status(401).json({
        success: false,
        message: SAFE_ERRORS.UNAUTHORIZED
      });
    }

    // Verify token
    let decoded;
    try {
      decoded = jwt.verify(token, getJwtSecret());
    } catch (err) {
      // Log suspicious activity for invalid tokens
      await logAuditEvent({
        eventType: 'PERMISSION_DENIED',
        req,
        action: 'Invalid token presented',
        status: 'FAILURE',
        riskLevel: 'MEDIUM'
      });

      return res.status(401).json({
        success: false,
        message: SAFE_ERRORS.UNAUTHORIZED
      });
    }

    // Check if MFA is pending - restrict access
    if (decoded.mfaPending) {
      return res.status(401).json({
        success: false,
        message: 'MFA verification required'
      });
    }

    // Load user from database
    const user = await User.findById(decoded.id);
    
    // Fail closed: user not found = no access
    if (!user) {
      return res.status(401).json({
        success: false,
        message: SAFE_ERRORS.UNAUTHORIZED
      });
    }

    // Check if account is locked
    if (user.isLocked) {
      await logAuditEvent({
        eventType: 'PERMISSION_DENIED',
        userId: user._id,
        username: user.username,
        req,
        action: 'Locked account access attempt',
        status: 'BLOCKED',
        riskLevel: 'HIGH'
      });

      return res.status(403).json({
        success: false,
        message: 'Account is locked. Please contact support.'
      });
    }

    // Check if email is verified (if required)
    if (securityConfig.account.emailVerificationRequired && !user.emailVerified) {
      return res.status(403).json({
        success: false,
        message: 'Please verify your email address'
      });
    }

    // Check session validity
    if (decoded.sessionId && user.sessions) {
      const session = user.sessions.find(s => s.sessionId === decoded.sessionId);
      if (!session || session.revokedAt) {
        return res.status(401).json({
          success: false,
          message: SAFE_ERRORS.UNAUTHORIZED
        });
      }
    }

    // Update last activity
    user.lastActivity = new Date();
    await user.save({ validateBeforeSave: false });

    req.user = user;
    req.tokenData = decoded;
    next();
  } catch (error) {
    console.error('Authentication error:', error.message);
    return res.status(401).json({
      success: false,
      message: SAFE_ERRORS.UNAUTHORIZED
    });
  }
};

/**
 * Optional authentication - loads user if token present, continues if not
 */
const optionalAuth = async (req, res, next) => {
  try {
    let token;

    if (req.headers.authorization?.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    }

    if (token) {
      try {
        const decoded = jwt.verify(token, getJwtSecret());
        if (!decoded.mfaPending) {
          const user = await User.findById(decoded.id);
          if (user && !user.isLocked) {
            req.user = user;
            req.tokenData = decoded;
          }
        }
      } catch (err) {
        // Token invalid, but that's okay for optional auth
      }
    }

    next();
  } catch (error) {
    next();
  }
};

/**
 * Require specific permission
 * @param {string} permission - Required permission
 * @returns {Function}
 */
const requirePermission = (permission) => {
  return async (req, res, next) => {
    // Fail closed: no user = no permission
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: SAFE_ERRORS.UNAUTHORIZED
      });
    }

    const userRole = req.user.role || ROLES.CUSTOMER;

    if (!hasPermission(userRole, permission)) {
      await logAuditEvent({
        eventType: 'PERMISSION_DENIED',
        userId: req.user._id,
        username: req.user.username,
        req,
        action: `Permission denied: ${permission}`,
        status: 'BLOCKED',
        details: { requiredPermission: permission, userRole },
        riskLevel: 'MEDIUM'
      });

      return res.status(403).json({
        success: false,
        message: SAFE_ERRORS.FORBIDDEN
      });
    }

    next();
  };
};

/**
 * Require minimum role level
 * @param {string} role - Minimum required role
 * @returns {Function}
 */
const requireRole = (role) => {
  return async (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: SAFE_ERRORS.UNAUTHORIZED
      });
    }

    const userRole = req.user.role || ROLES.CUSTOMER;

    if (!hasMinimumRole(userRole, role)) {
      await logAuditEvent({
        eventType: 'PERMISSION_DENIED',
        userId: req.user._id,
        username: req.user.username,
        req,
        action: `Role denied: requires ${role}`,
        status: 'BLOCKED',
        details: { requiredRole: role, userRole },
        riskLevel: 'MEDIUM'
      });

      return res.status(403).json({
        success: false,
        message: SAFE_ERRORS.FORBIDDEN
      });
    }

    next();
  };
};

/**
 * Check if user owns the resource
 * @param {Function} getResourceOwnerId - Function to get resource owner ID from request
 * @returns {Function}
 */
const requireOwnership = (getResourceOwnerId) => {
  return async (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: SAFE_ERRORS.UNAUTHORIZED
      });
    }

    try {
      const resourceOwnerId = await getResourceOwnerId(req);
      
      if (!resourceOwnerId) {
        return res.status(404).json({
          success: false,
          message: SAFE_ERRORS.NOT_FOUND
        });
      }

      const isOwner = req.user._id.toString() === resourceOwnerId.toString();
      const isAdmin = req.user.role === ROLES.ADMINISTRATOR;

      if (!isOwner && !isAdmin) {
        await logAuditEvent({
          eventType: 'PERMISSION_DENIED',
          userId: req.user._id,
          username: req.user.username,
          req,
          action: 'Ownership check failed',
          status: 'BLOCKED',
          details: { resourceOwnerId: resourceOwnerId.toString() },
          riskLevel: 'HIGH'
        });

        return res.status(403).json({
          success: false,
          message: SAFE_ERRORS.FORBIDDEN
        });
      }

      req.isOwner = isOwner;
      req.isAdmin = isAdmin;
      next();
    } catch (error) {
      return res.status(500).json({
        success: false,
        message: SAFE_ERRORS.SERVER_ERROR
      });
    }
  };
};

/**
 * Admin only middleware (shorthand)
 */
const adminOnly = requireRole(ROLES.ADMINISTRATOR);

/**
 * Editor or above middleware (shorthand)
 */
const editorOrAbove = requireRole(ROLES.EDITOR);

/**
 * Combined protection middleware (authenticate + optional permission)
 * @param {string} permission - Optional permission to check
 * @returns {Function[]}
 */
const protect = (permission = null) => {
  const middlewares = [authenticate];
  
  if (permission) {
    middlewares.push(requirePermission(permission));
  }
  
  return middlewares;
};

module.exports = {
  getJwtSecret,
  generateToken,
  authenticate,
  optionalAuth,
  requirePermission,
  requireRole,
  requireOwnership,
  adminOnly,
  editorOrAbove,
  protect
};
