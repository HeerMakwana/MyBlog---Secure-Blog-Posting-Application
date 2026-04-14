/**
 * Enhanced Security Audit Logger
 * Logs all security events with comprehensive context for compliance and forensics
 */

const fs = require('fs');
const path = require('path');

class SecurityAuditLogger {
  constructor() {
    this.logsDir = path.join(__dirname, '../../logs');
    this.ensureLogsDirectory();
    
    // Risk levels
    this.RISK_LEVELS = {
      LOW: 'LOW',
      MEDIUM: 'MEDIUM',
      HIGH: 'HIGH',
      CRITICAL: 'CRITICAL'
    };

    // Event types
    this.EVENT_TYPES = {
      // Authentication events
      LOGIN_SUCCESS: 'LOGIN_SUCCESS',
      LOGIN_FAILURE: 'LOGIN_FAILURE',
      LOGIN_ACCOUNT_LOCKOUT: 'LOGIN_ACCOUNT_LOCKOUT',
      REGISTER_SUCCESS: 'REGISTER_SUCCESS',
      REGISTER_FAILURE: 'REGISTER_FAILURE',
      LOGOUT: 'LOGOUT',
      SESSION_TIMEOUT: 'SESSION_TIMEOUT',
      SESSION_REVOCATION: 'SESSION_REVOCATION',
      
      // Authorization events
      PERMISSION_DENIED: 'PERMISSION_DENIED',
      UNAUTHORIZED_ACCESS: 'UNAUTHORIZED_ACCESS',
      ROLE_CHANGE: 'ROLE_CHANGE',
      
      // Account events
      PASSWORD_CHANGE: 'PASSWORD_CHANGE',
      PASSWORD_RESET: 'PASSWORD_RESET',
      EMAIL_CHANGE: 'EMAIL_CHANGE',
      EMAIL_VERIFIED: 'EMAIL_VERIFIED',
      ACCOUNT_DISABLED: 'ACCOUNT_DISABLED',
      ACCOUNT_DELETED: 'ACCOUNT_DELETED',
      
      // Security events
      RATE_LIMIT_EXCEEDED: 'RATE_LIMIT_EXCEEDED',
      CSRF_TOKEN_INVALID: 'CSRF_TOKEN_INVALID',
      XSS_DETECTED: 'XSS_DETECTED',
      SQL_INJECTION_DETECTED: 'SQL_INJECTION_DETECTED',
      SUSPICIOUS_ACTIVITY: 'SUSPICIOUS_ACTIVITY',
      BRUTE_FORCE_ATTEMPT: 'BRUTE_FORCE_ATTEMPT',
      CAPTCHA_FAILED: 'CAPTCHA_FAILED',
      
      // Data events
      DATA_ACCESS: 'DATA_ACCESS',
      DATA_MODIFICATION: 'DATA_MODIFICATION',
      DATA_DELETION: 'DATA_DELETION',
      SENSITIVE_DATA_ACCESS: 'SENSITIVE_DATA_ACCESS',
      
      // Admin events
      ADMIN_ACTION: 'ADMIN_ACTION',
      USER_IMPERSONATION: 'USER_IMPERSONATION',
      CONFIG_CHANGE: 'CONFIG_CHANGE',
      
      // System events
      API_ERROR: 'API_ERROR',
      DATABASE_ERROR: 'DATABASE_ERROR',
      EXTERNAL_SERVICE_ERROR: 'EXTERNAL_SERVICE_ERROR'
    };
  }

  /**
   * Ensure logs directory exists
   */
  ensureLogsDirectory() {
    if (!fs.existsSync(this.logsDir)) {
      fs.mkdirSync(this.logsDir, { recursive: true });
    }
  }

  /**
   * Get request context (IP, User-Agent, etc.)
   */
  getRequestContext(req) {
    return {
      ip: req.ip || req.connection.remoteAddress || 'unknown',
      userAgent: req.headers['user-agent'] || 'unknown',
      method: req.method,
      path: req.path,
      referrer: req.headers.referer || 'unknown'
    };
  }

  /**
   * Log a security event
   */
  log({
    eventType,
    riskLevel = this.RISK_LEVELS.LOW,
    userId = null,
    username = null,
    action,
    status = 'SUCCESS',
    req = null,
    additionalData = {}
  }) {
    const logEntry = {
      timestamp: new Date().toISOString(),
      eventType,
      riskLevel,
      userId,
      username,
      action,
      status,
      requestContext: req ? this.getRequestContext(req) : null,
      additionalData,
      // Non-repudiation: hostname of server where event occurred
      hostname: require('os').hostname(),
      environment: process.env.NODE_ENV || 'unknown'
    };

    // Log to console for immediate visibility
    this.logToConsole(logEntry);

    // Log to file for persistence
    this.logToFile(logEntry);

    // Alert if critical
    if (riskLevel === this.RISK_LEVELS.CRITICAL) {
      this.alertCriticalEvent(logEntry);
    }

    return logEntry;
  }

  /**
   * Log authentication success
   */
  logAuthenticationSuccess(userId, username, req) {
    return this.log({
      eventType: this.EVENT_TYPES.LOGIN_SUCCESS,
      riskLevel: this.RISK_LEVELS.LOW,
      userId,
      username,
      action: 'User successfully authenticated',
      status: 'SUCCESS',
      req
    });
  }

  /**
   * Log authentication failure
   */
  logAuthenticationFailure(username, reason, req) {
    return this.log({
      eventType: this.EVENT_TYPES.LOGIN_FAILURE,
      riskLevel: this.RISK_LEVELS.MEDIUM,
      username,
      action: 'Authentication attempt failed',
      status: 'FAILURE',
      req,
      additionalData: { reason }
    });
  }

  /**
   * Log account lockout
   */
  logAccountLockout(userId, username, attemptCount, req) {
    return this.log({
      eventType: this.EVENT_TYPES.LOGIN_ACCOUNT_LOCKOUT,
      riskLevel: this.RISK_LEVELS.HIGH,
      userId,
      username,
      action: 'Account locked due to failed login attempts',
      status: 'BLOCKED',
      req,
      additionalData: { failedAttempts: attemptCount }
    });
  }

  /**
   * Log unauthorized access attempt
   */
  logUnauthorizedAccess(userId, username, resource, req) {
    return this.log({
      eventType: this.EVENT_TYPES.UNAUTHORIZED_ACCESS,
      riskLevel: this.RISK_LEVELS.HIGH,
      userId,
      username,
      action: `Attempted unauthorized access to ${resource}`,
      status: 'BLOCKED',
      req,
      additionalData: { resource }
    });
  }

  /**
   * Log permission denied
   */
  logPermissionDenied(userId, username, action, resource, req) {
    return this.log({
      eventType: this.EVENT_TYPES.PERMISSION_DENIED,
      riskLevel: this.RISK_LEVELS.MEDIUM,
      userId,
      username,
      action: `Permission denied: ${action} on ${resource}`,
      status: 'BLOCKED',
      req,
      additionalData: { resource, requiredPermission: action }
    });
  }

  /**
   * Log rate limit exceeded
   */
  logRateLimitExceeded(identifier, endpoint, req) {
    return this.log({
      eventType: this.EVENT_TYPES.RATE_LIMIT_EXCEEDED,
      riskLevel: this.RISK_LEVELS.MEDIUM,
      username: identifier,
      action: `Rate limit exceeded on ${endpoint}`,
      status: 'BLOCKED',
      req,
      additionalData: { endpoint, identifier }
    });
  }

  /**
   * Log suspicious activity
   */
  logSuspiciousActivity(userId, username, description, req) {
    return this.log({
      eventType: this.EVENT_TYPES.SUSPICIOUS_ACTIVITY,
      riskLevel: this.RISK_LEVELS.HIGH,
      userId,
      username,
      action: description,
      status: 'ALERT',
      req,
      additionalData: { description }
    });
  }

  /**
   * Log data modification
   */
  logDataModification(userId, username, resource, changeType, changes, req) {
    return this.log({
      eventType: this.EVENT_TYPES.DATA_MODIFICATION,
      riskLevel: this.RISK_LEVELS.MEDIUM,
      userId,
      username,
      action: `${changeType} data: ${resource}`,
      status: 'SUCCESS',
      req,
      additionalData: { resource, changeType, changedFields: Object.keys(changes) }
    });
  }

  /**
   * Log to console with color coding
   */
  logToConsole(logEntry) {
    const riskColors = {
      LOW: '\x1b[32m',      // Green
      MEDIUM: '\x1b[33m',   // Yellow
      HIGH: '\x1b[31m',     // Red
      CRITICAL: '\x1b[35m'  // Magenta
    };

    const resetColor = '\x1b[0m';
    const color = riskColors[logEntry.riskLevel] || resetColor;

    const logMessage = `${color}[${logEntry.eventType}] ${logEntry.action} - Risk: ${logEntry.riskLevel}${resetColor}`;
    console.log(`[${logEntry.timestamp}] ${logMessage}`);

    if (logEntry.userId) {
      console.log(`  User: ${logEntry.userId} (${logEntry.username})`);
    }
    if (logEntry.requestContext?.ip) {
      console.log(`  IP: ${logEntry.requestContext.ip}`);
    }
  }

  /**
   * Log to file (append mode)
   */
  logToFile(logEntry) {
    const filename = `audit-${this.getDateString()}.log`;
    const filepath = path.join(this.logsDir, filename);
    
    const logLine = JSON.stringify(logEntry) + '\n';
    
    try {
      fs.appendFileSync(filepath, logLine);
    } catch (error) {
      console.error(`Failed to write audit log: ${error.message}`);
    }
  }

  /**
   * Alert critical event (could integrate with external monitoring)
   */
  alertCriticalEvent(logEntry) {
    // TODO: Integrate with external monitoring (Sentry, Datadog, etc.)
    console.error('🚨 CRITICAL SECURITY EVENT:', logEntry);
    
    // For now, log to separate critical events file
    const criticalLogPath = path.join(this.logsDir, 'critical-events.log');
    try {
      fs.appendFileSync(criticalLogPath, JSON.stringify(logEntry) + '\n');
    } catch (error) {
      console.error(`Failed to write critical event log: ${error.message}`);
    }
  }

  /**
   * Get date string for log filename (YYYY-MM-DD)
   */
  getDateString() {
    return new Date().toISOString().split('T')[0];
  }

  /**
   * Read audit logs for a specific date
   */
  readLogsForDate(date) {
    const filename = `audit-${date}.log`;
    const filepath = path.join(this.logsDir, filename);

    if (!fs.existsSync(filepath)) {
      return [];
    }

    const content = fs.readFileSync(filepath, 'utf8');
    return content
      .split('\n')
      .filter(line => line.trim())
      .map(line => {
        try {
          return JSON.parse(line);
        } catch {
          return null;
        }
      })
      .filter(Boolean);
  }

  /**
   * Get logs for a user
   */
  getUserLogs(userId, days = 30) {
    const logs = [];
    const now = new Date();

    for (let i = 0; i < days; i++) {
      const date = new Date(now);
      date.setDate(date.getDate() - i);
      const dateString = date.toISOString().split('T')[0];
      
      const dayLogs = this.readLogsForDate(dateString);
      logs.push(...dayLogs.filter(log => log.userId === userId));
    }

    return logs;
  }

  /**
   * Get suspicious activity logs
   */
  getSuspiciousActivity(days = 7) {
    const logs = [];
    const now = new Date();

    for (let i = 0; i < days; i++) {
      const date = new Date(now);
      date.setDate(date.getDate() - i);
      const dateString = date.toISOString().split('T')[0];
      
      const dayLogs = this.readLogsForDate(dateString);
      const suspicious = dayLogs.filter(log => 
        log.riskLevel === this.RISK_LEVELS.HIGH ||
        log.riskLevel === this.RISK_LEVELS.CRITICAL
      );
      logs.push(...suspicious);
    }

    return logs;
  }

  /**
   * Clean up old logs based on retention policy
   */
  cleanupOldLogs(retentionDays = 90) {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - retentionDays);

    try {
      const files = fs.readdirSync(this.logsDir);
      files.forEach(file => {
        const filepath = path.join(this.logsDir, file);
        const stat = fs.statSync(filepath);
        
        if (stat.mtime < cutoffDate) {
          fs.unlinkSync(filepath);
          console.log(`Deleted old log file: ${file}`);
        }
      });
    } catch (error) {
      console.error(`Error cleaning up old logs: ${error.message}`);
    }
  }
}

// Create singleton instance
let auditLoggerInstance = null;

function getAuditLogger() {
  if (!auditLoggerInstance) {
    auditLoggerInstance = new SecurityAuditLogger();
  }
  return auditLoggerInstance;
}

module.exports = {
  SecurityAuditLogger,
  getAuditLogger
};
