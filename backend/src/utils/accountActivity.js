/**
 * Account Activity Logger
 * Enhanced logging for account-related security events
 * Tracks login attempts, session events, security changes
 */

const mongoose = require('mongoose');
const { logAuditEvent } = require('./auditLogger');

// Account Activity Schema for detailed activity tracking
const accountActivitySchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  activityType: {
    type: String,
    required: true,
    enum: [
      'LOGIN_SUCCESS',
      'LOGIN_FAILURE',
      'LOGOUT',
      'SESSION_CREATED',
      'SESSION_EXPIRED',
      'SESSION_REVOKED',
      'PASSWORD_CHANGED',
      'PASSWORD_RESET_REQUESTED',
      'PASSWORD_RESET_COMPLETED',
      'EMAIL_CHANGED',
      'MFA_ENABLED',
      'MFA_DISABLED',
      'MFA_VERIFIED',
      'MFA_FAILED',
      'ACCOUNT_LOCKED',
      'ACCOUNT_UNLOCKED',
      'PROFILE_UPDATED',
      'SECURITY_SETTINGS_CHANGED',
      'API_KEY_CREATED',
      'API_KEY_REVOKED',
      'TRUSTED_DEVICE_ADDED',
      'TRUSTED_DEVICE_REMOVED',
      'SUSPICIOUS_ACTIVITY_DETECTED'
    ],
    index: true
  },
  timestamp: {
    type: Date,
    default: Date.now,
    index: true
  },
  ipAddress: {
    type: String,
    required: true
  },
  userAgent: String,
  location: {
    country: String,
    city: String,
    region: String
  },
  device: {
    type: String,
    browser: String,
    os: String
  },
  sessionId: String,
  status: {
    type: String,
    enum: ['SUCCESS', 'FAILURE', 'BLOCKED', 'WARNING'],
    default: 'SUCCESS'
  },
  details: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  },
  riskScore: {
    type: Number,
    min: 0,
    max: 100,
    default: 0
  }
});

// TTL index - keep activity logs for 1 year
accountActivitySchema.index({ timestamp: 1 }, { expireAfterSeconds: 365 * 24 * 60 * 60 });

// Compound index for user activity queries
accountActivitySchema.index({ userId: 1, timestamp: -1 });

const AccountActivity = mongoose.model('AccountActivity', accountActivitySchema);

/**
 * Parse User-Agent string to extract device info
 */
const parseUserAgent = (userAgent) => {
  if (!userAgent) return {};
  
  const ua = userAgent.toLowerCase();
  
  // Detect browser
  let browser = 'Unknown';
  if (ua.includes('chrome') && !ua.includes('edg')) browser = 'Chrome';
  else if (ua.includes('firefox')) browser = 'Firefox';
  else if (ua.includes('safari') && !ua.includes('chrome')) browser = 'Safari';
  else if (ua.includes('edg')) browser = 'Edge';
  else if (ua.includes('opera') || ua.includes('opr')) browser = 'Opera';
  
  // Detect OS
  let os = 'Unknown';
  if (ua.includes('windows')) os = 'Windows';
  else if (ua.includes('mac')) os = 'macOS';
  else if (ua.includes('linux')) os = 'Linux';
  else if (ua.includes('android')) os = 'Android';
  else if (ua.includes('ios') || ua.includes('iphone') || ua.includes('ipad')) os = 'iOS';
  
  // Detect device type
  let deviceType = 'Desktop';
  if (ua.includes('mobile') || ua.includes('android') || ua.includes('iphone')) {
    deviceType = 'Mobile';
  } else if (ua.includes('tablet') || ua.includes('ipad')) {
    deviceType = 'Tablet';
  }
  
  return { browser, os, type: deviceType };
};

/**
 * Calculate risk score based on activity patterns
 */
const calculateRiskScore = async (userId, activityType, req) => {
  let riskScore = 0;
  
  try {
    // Check for unusual patterns
    const recentActivity = await AccountActivity.find({
      userId,
      timestamp: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
    }).sort({ timestamp: -1 }).limit(100);
    
    // Factor 1: Failed login attempts in last 24h
    const failedLogins = recentActivity.filter(a => a.activityType === 'LOGIN_FAILURE').length;
    if (failedLogins >= 5) riskScore += 30;
    else if (failedLogins >= 3) riskScore += 15;
    else if (failedLogins >= 1) riskScore += 5;
    
    // Factor 2: Multiple IP addresses in last 24h
    const uniqueIps = new Set(recentActivity.map(a => a.ipAddress));
    if (uniqueIps.size >= 5) riskScore += 20;
    else if (uniqueIps.size >= 3) riskScore += 10;
    
    // Factor 3: Unusual activity time (if we have history)
    // This would require more sophisticated analysis
    
    // Factor 4: MFA failures
    const mfaFailures = recentActivity.filter(a => a.activityType === 'MFA_FAILED').length;
    if (mfaFailures >= 3) riskScore += 25;
    else if (mfaFailures >= 1) riskScore += 10;
    
    // Factor 5: Account lockouts in history
    const lockouts = recentActivity.filter(a => a.activityType === 'ACCOUNT_LOCKED').length;
    if (lockouts >= 1) riskScore += 20;
    
    // Cap at 100
    riskScore = Math.min(riskScore, 100);
    
  } catch (error) {
    console.error('Risk score calculation error:', error);
  }
  
  return riskScore;
};

/**
 * Log account activity
 */
const logAccountActivity = async ({
  userId,
  activityType,
  req,
  status = 'SUCCESS',
  details = {},
  skipAuditLog = false
}) => {
  try {
    const ipAddress = req?.ip || req?.connection?.remoteAddress || 'unknown';
    const userAgent = req?.get?.('User-Agent') || '';
    const device = parseUserAgent(userAgent);
    
    // Calculate risk score for security-sensitive activities
    const sensitiveActivities = ['LOGIN_FAILURE', 'MFA_FAILED', 'SUSPICIOUS_ACTIVITY_DETECTED'];
    const riskScore = sensitiveActivities.includes(activityType) 
      ? await calculateRiskScore(userId, activityType, req)
      : 0;
    
    const activity = await AccountActivity.create({
      userId,
      activityType,
      ipAddress,
      userAgent,
      device,
      sessionId: req?.sessionID,
      status,
      details,
      riskScore
    });
    
    // Also log to audit log for compliance
    if (!skipAuditLog) {
      const auditEventType = mapToAuditEventType(activityType);
      if (auditEventType) {
        await logAuditEvent({
          eventType: auditEventType,
          userId,
          req,
          action: activityType,
          status,
          details: { ...details, activityId: activity._id },
          riskLevel: riskScore >= 50 ? 'HIGH' : riskScore >= 25 ? 'MEDIUM' : 'LOW'
        });
      }
    }
    
    // Alert on high risk activities
    if (riskScore >= 50) {
      console.warn(`[HIGH RISK ACTIVITY] User ${userId}: ${activityType} (Risk: ${riskScore})`);
      // In production, trigger alerts here
    }
    
    return activity;
  } catch (error) {
    console.error('Account activity logging error:', error);
  }
};

/**
 * Map activity types to audit event types
 */
const mapToAuditEventType = (activityType) => {
  const mapping = {
    'LOGIN_SUCCESS': 'AUTH_LOGIN_SUCCESS',
    'LOGIN_FAILURE': 'AUTH_LOGIN_FAILURE',
    'LOGOUT': 'AUTH_LOGOUT',
    'SESSION_CREATED': 'SESSION_CREATED',
    'SESSION_EXPIRED': 'SESSION_EXPIRED',
    'SESSION_REVOKED': 'SESSION_REVOKED',
    'PASSWORD_CHANGED': 'AUTH_PASSWORD_CHANGE',
    'PASSWORD_RESET_REQUESTED': 'AUTH_PASSWORD_RESET_REQUEST',
    'PASSWORD_RESET_COMPLETED': 'AUTH_PASSWORD_RESET_COMPLETE',
    'MFA_ENABLED': 'MFA_ENABLED',
    'MFA_DISABLED': 'MFA_DISABLED',
    'MFA_VERIFIED': 'MFA_VERIFICATION_SUCCESS',
    'MFA_FAILED': 'MFA_VERIFICATION_FAILURE',
    'ACCOUNT_LOCKED': 'ACCOUNT_LOCKED',
    'ACCOUNT_UNLOCKED': 'ACCOUNT_UNLOCKED',
    'SUSPICIOUS_ACTIVITY_DETECTED': 'SUSPICIOUS_ACTIVITY'
  };
  
  return mapping[activityType];
};

/**
 * Get recent account activity for a user
 */
const getAccountActivity = async (userId, options = {}) => {
  const {
    limit = 50,
    page = 1,
    activityTypes = null,
    startDate = null,
    endDate = null
  } = options;
  
  const query = { userId };
  
  if (activityTypes && activityTypes.length > 0) {
    query.activityType = { $in: activityTypes };
  }
  
  if (startDate || endDate) {
    query.timestamp = {};
    if (startDate) query.timestamp.$gte = new Date(startDate);
    if (endDate) query.timestamp.$lte = new Date(endDate);
  }
  
  const skip = (page - 1) * limit;
  
  const [activities, total] = await Promise.all([
    AccountActivity.find(query)
      .sort({ timestamp: -1 })
      .skip(skip)
      .limit(limit)
      .lean(),
    AccountActivity.countDocuments(query)
  ]);
  
  return {
    activities,
    pagination: {
      page,
      limit,
      total,
      pages: Math.ceil(total / limit)
    }
  };
};

/**
 * Get security summary for a user
 */
const getSecuritySummary = async (userId) => {
  const last30Days = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
  
  const [
    loginCount,
    failedLoginCount,
    mfaFailures,
    suspiciousActivities,
    uniqueIps,
    lastLogin
  ] = await Promise.all([
    AccountActivity.countDocuments({
      userId,
      activityType: 'LOGIN_SUCCESS',
      timestamp: { $gte: last30Days }
    }),
    AccountActivity.countDocuments({
      userId,
      activityType: 'LOGIN_FAILURE',
      timestamp: { $gte: last30Days }
    }),
    AccountActivity.countDocuments({
      userId,
      activityType: 'MFA_FAILED',
      timestamp: { $gte: last30Days }
    }),
    AccountActivity.countDocuments({
      userId,
      activityType: 'SUSPICIOUS_ACTIVITY_DETECTED',
      timestamp: { $gte: last30Days }
    }),
    AccountActivity.distinct('ipAddress', {
      userId,
      timestamp: { $gte: last30Days }
    }),
    AccountActivity.findOne({
      userId,
      activityType: 'LOGIN_SUCCESS'
    }).sort({ timestamp: -1 })
  ]);
  
  return {
    last30Days: {
      successfulLogins: loginCount,
      failedLogins: failedLoginCount,
      mfaFailures,
      suspiciousActivities,
      uniqueIpAddresses: uniqueIps.length
    },
    lastLogin: lastLogin?.timestamp || null,
    lastLoginIp: lastLogin?.ipAddress || null,
    securityScore: calculateSecurityScore({
      failedLoginCount,
      mfaFailures,
      suspiciousActivities
    })
  };
};

/**
 * Calculate overall security score
 */
const calculateSecurityScore = ({ failedLoginCount, mfaFailures, suspiciousActivities }) => {
  let score = 100;
  
  // Deduct for failed logins
  score -= Math.min(failedLoginCount * 2, 20);
  
  // Deduct for MFA failures
  score -= Math.min(mfaFailures * 5, 25);
  
  // Deduct for suspicious activities
  score -= Math.min(suspiciousActivities * 10, 30);
  
  return Math.max(score, 0);
};

module.exports = {
  AccountActivity,
  logAccountActivity,
  getAccountActivity,
  getSecuritySummary,
  parseUserAgent,
  calculateRiskScore
};
