/**
 * Audit Logger
 * Logs security events for monitoring and compliance
 */

const mongoose = require('mongoose');

// Audit Log Schema
const auditLogSchema = new mongoose.Schema({
  timestamp: {
    type: Date,
    default: Date.now
  },
  eventType: {
    type: String,
    required: true,
    enum: [
      'AUTH_LOGIN_SUCCESS',
      'AUTH_LOGIN_FAILURE',
      'AUTH_LOGOUT',
      'AUTH_REGISTER',
      'AUTH_PASSWORD_CHANGE',
      'AUTH_PASSWORD_RESET_REQUEST',
      'AUTH_PASSWORD_RESET_COMPLETE',
      'MFA_ENABLED',
      'MFA_DISABLED',
      'MFA_VERIFICATION_SUCCESS',
      'MFA_VERIFICATION_FAILURE',
      'MFA_BACKUP_CODE_USED',
      'ACCOUNT_LOCKED',
      'ACCOUNT_UNLOCKED',
      'ACCOUNT_EMAIL_VERIFIED',
      'ROLE_CHANGED',
      'PERMISSION_DENIED',
      'RATE_LIMIT_EXCEEDED',
      'SUSPICIOUS_ACTIVITY',
      'SESSION_CREATED',
      'SESSION_EXPIRED',
      'SESSION_REVOKED',
      'POST_CREATED',
      'POST_UPDATED',
      'POST_DELETED',
      'USER_UPDATED',
      'USER_DELETED',
      'ADMIN_ACTION',
      'SECURITY_CONFIG_CHANGED'
    ],
    index: true
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    index: true
  },
  username: String,
  ipAddress: String,
  userAgent: String,
  resourceType: String,
  resourceId: String,
  action: String,
  status: {
    type: String,
    enum: ['SUCCESS', 'FAILURE', 'BLOCKED'],
    default: 'SUCCESS'
  },
  details: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  },
  riskLevel: {
    type: String,
    enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
    default: 'LOW'
  }
});

// TTL index to auto-delete old logs (90 days)
auditLogSchema.index({ timestamp: 1 }, { expireAfterSeconds: 90 * 24 * 60 * 60 });

const AuditLog = mongoose.model('AuditLog', auditLogSchema);

/**
 * Sanitize details object to remove sensitive information
 * @param {Object} details - Details object
 * @returns {Object}
 */
const sanitizeDetails = (details) => {
  if (!details) return {};
  
  const sensitiveFields = ['password', 'totpSecret', 'backupCodes', 'securityAnswers', 'token'];
  const sanitized = { ...details };
  
  for (const field of sensitiveFields) {
    if (sanitized[field]) {
      sanitized[field] = '[REDACTED]';
    }
  }
  
  return sanitized;
};

/**
 * Extract client info from request
 * @param {Object} req - Express request object
 * @returns {Object}
 */
const extractClientInfo = (req) => {
  return {
    ipAddress: req.ip || req.connection?.remoteAddress || 'unknown',
    userAgent: req.get('User-Agent') || 'unknown'
  };
};

/**
 * Log an audit event
 * @param {Object} options - Log options
 * @returns {Promise<void>}
 */
const logAuditEvent = async ({
  eventType,
  userId,
  username,
  req,
  resourceType,
  resourceId,
  action,
  status = 'SUCCESS',
  details = {},
  riskLevel = 'LOW'
}) => {
  try {
    const clientInfo = req ? extractClientInfo(req) : {};
    
    await AuditLog.create({
      eventType,
      userId,
      username,
      ...clientInfo,
      resourceType,
      resourceId,
      action,
      status,
      details: sanitizeDetails(details),
      riskLevel
    });

    // Log high-risk events to console as well
    if (riskLevel === 'HIGH' || riskLevel === 'CRITICAL') {
      console.warn(`[SECURITY ALERT] ${eventType}:`, {
        userId,
        username,
        ...clientInfo,
        status,
        riskLevel
      });
    }
  } catch (error) {
    // Don't throw - audit logging should not break the application
    console.error('Audit logging error:', error.message);
  }
};

/**
 * Get audit logs with filtering
 * @param {Object} filters - Query filters
 * @param {Object} options - Pagination options
 * @returns {Promise<Object>}
 */
const getAuditLogs = async (filters = {}, options = {}) => {
  const {
    page = 1,
    limit = 50,
    sortBy = 'timestamp',
    sortOrder = -1
  } = options;

  const query = {};

  if (filters.eventType) query.eventType = filters.eventType;
  if (filters.userId) query.userId = filters.userId;
  if (filters.status) query.status = filters.status;
  if (filters.riskLevel) query.riskLevel = filters.riskLevel;
  if (filters.startDate || filters.endDate) {
    query.timestamp = {};
    if (filters.startDate) query.timestamp.$gte = new Date(filters.startDate);
    if (filters.endDate) query.timestamp.$lte = new Date(filters.endDate);
  }

  const skip = (page - 1) * limit;

  const [logs, total] = await Promise.all([
    AuditLog.find(query)
      .sort({ [sortBy]: sortOrder })
      .skip(skip)
      .limit(limit)
      .lean(),
    AuditLog.countDocuments(query)
  ]);

  return {
    logs,
    pagination: {
      page,
      limit,
      total,
      pages: Math.ceil(total / limit)
    }
  };
};

module.exports = {
  AuditLog,
  logAuditEvent,
  getAuditLogs,
  sanitizeDetails,
  extractClientInfo
};
