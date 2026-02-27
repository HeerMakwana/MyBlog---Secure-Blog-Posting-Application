/**
 * Session Management Middleware
 * Implements secure session handling with MongoDB store
 * Features: Secure cookies, session regeneration, inactivity timeout
 */

const session = require('express-session');
const MongoStore = require('connect-mongo');
const crypto = require('crypto');
const { logAuditEvent } = require('../utils/auditLogger');

/**
 * Generate a cryptographically secure session ID
 */
const generateSessionId = () => {
  return crypto.randomBytes(32).toString('hex');
};

/**
 * Create session configuration with secure defaults
 */
const createSessionConfig = () => {
  const isProduction = process.env.NODE_ENV === 'production';
  
  return {
    // Session ID generator
    genid: () => generateSessionId(),
    
    // Session name (avoid default 'connect.sid' for security)
    name: process.env.SESSION_NAME || 'myblog_session',
    
    // Session secret - must be strong in production
    secret: process.env.SESSION_SECRET || 'change-this-secret-in-production',
    
    // Don't save uninitialized sessions
    saveUninitialized: false,
    
    // Don't resave unchanged sessions
    resave: false,
    
    // Cookie configuration with security settings
    cookie: {
      // Secure in production (HTTPS only)
      secure: isProduction || process.env.COOKIE_SECURE === 'true',
      
      // Prevent client-side JS access
      httpOnly: process.env.COOKIE_HTTP_ONLY !== 'false',
      
      // CSRF protection via SameSite
      sameSite: process.env.COOKIE_SAME_SITE || 'strict',
      
      // Session max age (default 1 hour)
      maxAge: parseInt(process.env.SESSION_MAX_AGE, 10) || 60 * 60 * 1000,
      
      // Domain (set in production)
      domain: isProduction ? process.env.COOKIE_DOMAIN : undefined,
      
      // Path restriction
      path: '/'
    },
    
    // MongoDB session store
    store: MongoStore.create({
      mongoUrl: process.env.MONGODB_URI || 'mongodb://localhost:27017/myblog',
      collectionName: 'sessions',
      ttl: parseInt(process.env.SESSION_MAX_AGE, 10) / 1000 || 3600, // TTL in seconds
      autoRemove: 'native', // Use MongoDB TTL index
      crypto: {
        secret: process.env.SESSION_SECRET || 'change-this-secret-in-production'
      },
      touchAfter: 24 * 3600, // Lazy session update (once per day)
      stringify: false
    }),
    
    // Rolling sessions - reset maxAge on each request
    rolling: true
  };
};

/**
 * Session middleware
 */
const sessionMiddleware = session(createSessionConfig());

/**
 * Session regeneration middleware
 * Regenerates session ID to prevent session fixation attacks
 * Should be called after successful authentication
 */
const regenerateSession = (req) => {
  return new Promise((resolve, reject) => {
    const oldSessionId = req.sessionID;
    const sessionData = { ...req.session };
    
    // Remove session properties that shouldn't be copied
    delete sessionData.cookie;
    
    req.session.regenerate((err) => {
      if (err) {
        console.error('Session regeneration error:', err);
        return reject(err);
      }
      
      // Restore session data to new session
      Object.assign(req.session, sessionData);
      
      // Track session creation time
      req.session.createdAt = new Date();
      req.session.regeneratedAt = new Date();
      req.session.regenerationCount = (sessionData.regenerationCount || 0) + 1;
      
      // Log session regeneration
      logAuditEvent({
        eventType: 'SESSION_CREATED',
        userId: req.session.userId,
        req,
        action: 'Session regenerated',
        status: 'SUCCESS',
        details: { 
          oldSessionId: oldSessionId.substring(0, 8) + '...',
          newSessionId: req.sessionID.substring(0, 8) + '...'
        }
      }).catch(console.error);
      
      resolve(req.sessionID);
    });
  });
};

/**
 * Destroy session completely
 * Clears session from store and client cookie
 */
const destroySession = (req, res) => {
  return new Promise((resolve, reject) => {
    const sessionId = req.sessionID;
    const userId = req.session?.userId;
    
    req.session.destroy((err) => {
      if (err) {
        console.error('Session destruction error:', err);
        return reject(err);
      }
      
      // Clear the session cookie
      const cookieName = process.env.SESSION_NAME || 'myblog_session';
      res.clearCookie(cookieName, {
        path: '/',
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict'
      });
      
      // Log session destruction
      logAuditEvent({
        eventType: 'SESSION_REVOKED',
        userId,
        req,
        action: 'Session destroyed',
        status: 'SUCCESS',
        details: { sessionId: sessionId?.substring(0, 8) + '...' }
      }).catch(console.error);
      
      resolve();
    });
  });
};

/**
 * Session activity tracking middleware
 * Updates last activity timestamp and checks for inactivity timeout
 */
const trackSessionActivity = async (req, res, next) => {
  if (!req.session) {
    return next();
  }
  
  const now = new Date();
  const inactivityTimeout = parseInt(process.env.SESSION_INACTIVITY_TIMEOUT, 10) || 30 * 60 * 1000; // 30 minutes
  const absoluteTimeout = parseInt(process.env.SESSION_ABSOLUTE_TIMEOUT, 10) || 24 * 60 * 60 * 1000; // 24 hours
  
  // Check for inactivity timeout
  if (req.session.lastActivity) {
    const lastActivity = new Date(req.session.lastActivity);
    const inactiveTime = now - lastActivity;
    
    if (inactiveTime > inactivityTimeout) {
      // Session expired due to inactivity
      await logAuditEvent({
        eventType: 'SESSION_EXPIRED',
        userId: req.session.userId,
        req,
        action: 'Session expired due to inactivity',
        status: 'SUCCESS',
        details: { inactiveMinutes: Math.floor(inactiveTime / 60000) }
      });
      
      await destroySession(req, res);
      return res.status(401).json({
        success: false,
        message: 'Session expired due to inactivity. Please log in again.'
      });
    }
  }
  
  // Check for absolute session timeout
  if (req.session.createdAt) {
    const sessionAge = now - new Date(req.session.createdAt);
    
    if (sessionAge > absoluteTimeout) {
      await logAuditEvent({
        eventType: 'SESSION_EXPIRED',
        userId: req.session.userId,
        req,
        action: 'Session expired due to absolute timeout',
        status: 'SUCCESS',
        details: { sessionAgeHours: Math.floor(sessionAge / 3600000) }
      });
      
      await destroySession(req, res);
      return res.status(401).json({
        success: false,
        message: 'Session expired. Please log in again.'
      });
    }
  }
  
  // Update last activity
  req.session.lastActivity = now;
  
  next();
};

/**
 * Initialize session for authenticated user
 */
const initializeUserSession = async (req, user) => {
  // Regenerate session to prevent fixation
  await regenerateSession(req);
  
  // Set session data
  req.session.userId = user._id.toString();
  req.session.username = user.username;
  req.session.role = user.role;
  req.session.isAuthenticated = true;
  req.session.createdAt = new Date();
  req.session.lastActivity = new Date();
  req.session.ipAddress = req.ip;
  req.session.userAgent = req.get('User-Agent');
  
  // Save session
  return new Promise((resolve, reject) => {
    req.session.save((err) => {
      if (err) {
        console.error('Session save error:', err);
        return reject(err);
      }
      resolve(req.sessionID);
    });
  });
};

/**
 * Validate session middleware
 * Checks if session is valid and user is authenticated
 */
const validateSession = (req, res, next) => {
  if (!req.session || !req.session.isAuthenticated) {
    return res.status(401).json({
      success: false,
      message: 'Not authenticated'
    });
  }
  
  // Additional security checks
  const currentIp = req.ip;
  const currentUserAgent = req.get('User-Agent');
  
  // Warn if IP changed (don't block - could be legitimate)
  if (req.session.ipAddress && req.session.ipAddress !== currentIp) {
    logAuditEvent({
      eventType: 'SUSPICIOUS_ACTIVITY',
      userId: req.session.userId,
      req,
      action: 'IP address changed during session',
      status: 'SUCCESS',
      details: { 
        originalIp: req.session.ipAddress,
        currentIp 
      },
      riskLevel: 'MEDIUM'
    }).catch(console.error);
  }
  
  next();
};

module.exports = {
  sessionMiddleware,
  regenerateSession,
  destroySession,
  trackSessionActivity,
  initializeUserSession,
  validateSession,
  createSessionConfig
};
