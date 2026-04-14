/**
 * Database Security Layer
 * Implements parameterized queries, input validation, and connection security
 */

const mongoose = require('mongoose');

class DatabaseSecurityManager {
  /**
   * Initialize secure database connection with connection pooling
   */
  static async initializeSecureConnection() {
    try {
      const mongoUri = process.env.MONGODB_URI;
      if (!mongoUri) {
        throw new Error('MONGODB_URI not configured');
      }

      const options = {
        // Connection pooling
        maxPoolSize: parseInt(process.env.MONGODB_POOL_MAX || 20),
        minPoolSize: parseInt(process.env.MONGODB_POOL_MIN || 5),
        maxConnecting: 2,

        // Timeout settings
        serverSelectionTimeoutMS: parseInt(process.env.MONGODB_CONNECTION_TIMEOUT || 5000),
        socketTimeoutMS: parseInt(process.env.MONGODB_SOCKET_TIMEOUT || 45000),
        waitQueueTimeoutMS: 10000,

        // Retry logic
        retryWrites: true,
        retryReads: true,

        // Authentication
        authSource: 'admin',

        // Connection monitoring
        monitorCommands: true,

        // Compression
        compressors: ['snappy', 'zlib'],

        // AppName for monitoring
        appName: 'MyBlog-Secure'
      };

      // Additional options for Atlas
      if (mongoUri.includes('mongodb+srv://')) {
        options.tls = true;
        options.tlsInsecure = false;
      }

      // Handle development certificate issues (NOT for production)
      if (process.env.NODE_ENV === 'development' && mongoUri.includes('localhost')) {
        // Local MongoDB doesn't require special handling
      }

      mongoose.connection.on('error', (error) => {
        console.error('MongoDB Connection Error:', error);
        // TODO: Alert monitoring service
      });

      mongoose.connection.on('disconnected', () => {
        console.warn('MongoDB Disconnected');
      });

      mongoose.connection.on('reconnected', () => {
        console.log('MongoDB Reconnected');
      });

      return await mongoose.connect(mongoUri, options);
    } catch (error) {
      console.error('Failed to initialize secure database connection:', error);
      process.exit(1);
    }
  }

  /**
   * Escape special characters in strings to prevent NoSQL injection
   * MongoDB injection: field names starting with $, operators like $where
   */
  static sanitizeQueryField(key) {
    if (typeof key !== 'string') return key;
    
    // Prevent field names starting with $
    if (key.startsWith('$')) {
      throw new Error(`Invalid field name: ${key}`);
    }
    
    // Prevent prototype pollution
    if (['__proto__', 'constructor', 'prototype'].includes(key)) {
      throw new Error(`Forbidden field name: ${key}`);
    }

    return key;
  }

  /**
   * Deep sanitize object to prevent injection and prototype pollution
   */
  static sanitizeObject(obj, depth = 0) {
    if (depth > 10) {
      throw new Error('Object nesting too deep');
    }

    if (obj === null || obj === undefined) {
      return obj;
    }

    if (typeof obj !== 'object') {
      return obj;
    }

    if (Array.isArray(obj)) {
      return obj.map(item => this.sanitizeObject(item, depth + 1));
    }

    const sanitized = {};
    for (const [key, value] of Object.entries(obj)) {
      // Sanitize key
      this.sanitizeQueryField(key);

      // Sanitize value
      if (value && typeof value === 'object') {
        sanitized[key] = this.sanitizeObject(value, depth + 1);
      } else if (typeof value === 'string') {
        // Prevent NoSQL injection operators
        if (value.startsWith('$') || value.startsWith('{$')) {
          throw new Error('Suspicious value detected in query');
        }
        sanitized[key] = value;
      } else {
        sanitized[key] = value;
      }
    }

    return sanitized;
  }

  /**
   * Escape regex special characters
   */
  static escapeRegex(string) {
    return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  /**
   * Create safe regex for search (case-insensitive)
   */
  static createSafeRegex(pattern) {
    const escaped = this.escapeRegex(pattern);
    return new RegExp(escaped, 'i');
  }

  /**
   * Validate ObjectId format
   */
  static isValidObjectId(id) {
    return mongoose.Types.ObjectId.isValid(id);
  }

  /**
   * Safe query using parameterized approach
   * Example: User.findOne({ email: sanitizedEmail }) instead of User.findOne({ $where: ... })
   */
  static async safeFind(Model, query, options = {}) {
    const sanitizedQuery = this.sanitizeObject(query);
    return Model.findOne(sanitizedQuery, options.projection || '-password', options);
  }

  /**
   * Safe update with field validation
   */
  static async safeUpdate(Model, filter, update, options = {}) {
    const sanitizedFilter = this.sanitizeObject(filter);
    const sanitizedUpdate = this.sanitizeObject(update);

    // Prevent direct $set usage - use explicit fields
    if (sanitizedUpdate.$set && typeof sanitizedUpdate.$set === 'object') {
      this.sanitizeObject(sanitizedUpdate.$set);
    }

    return Model.findOneAndUpdate(
      sanitizedFilter,
      sanitizedUpdate,
      { new: true, ...options }
    );
  }

  /**
   * Safe deletion with confirmation
   */
  static async safeDelete(Model, filter, confirmFlag = false) {
    if (!confirmFlag) {
      throw new Error('Deletion requires explicit confirmation');
    }

    const sanitizedFilter = this.sanitizeObject(filter);
    return Model.findOneAndDelete(sanitizedFilter);
  }

  /**
   * Get database statistics for monitoring
   */
  static async getDatabaseStats() {
    try {
      const db = mongoose.connection.getClient().db();
      const stats = await db.stats();
      
      return {
        dataSize: stats.dataSize,
        storageSize: stats.storageSize,
        indexes: stats.indexes,
        collections: stats.collections,
        avgObjSize: stats.avgObjSize,
        ok: stats.ok
      };
    } catch (error) {
      console.error('Error getting database stats:', error);
      return null;
    }
  }

  /**
   * Check connection health
   */
  static async healthCheck() {
    try {
      const adminDb = mongoose.connection.getClient().db('admin');
      await adminDb.admin().ping();
      return { status: 'healthy', timestamp: new Date().toISOString() };
    } catch (error) {
      return { status: 'unhealthy', error: error.message, timestamp: new Date().toISOString() };
    }
  }

  /**
   * Create backup
   */
  static async backupDatabase() {
    if (!process.env.BACKUP_ENABLED || process.env.BACKUP_ENABLED === 'false') {
      throw new Error('Backups are not enabled');
    }

    // Note: This is a placeholder. Actual backup should use mongodump or Atlas backups
    console.log('Database backup triggered (use mongodump or Atlas backup tools)');
    
    return {
      backup_id: `backup-${Date.now()}`,
      timestamp: new Date().toISOString(),
      status: 'backup_initiated',
      note: 'Use mongodump or Atlas backup tools for complete backup'
    };
  }
}

module.exports = {
  DatabaseSecurityManager
};
