require('dotenv').config();
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');

// ============= SECURITY VALIDATION =============
// Validate environment configuration before starting
const { validateEnvironment } = require('./config/envValidator');
validateEnvironment();

// ============= SECURITY IMPORTS =============
const { securityHeaders, corsConfig, sanitizeRequest } = require('./middleware/securityHeaders');
const { generalRateLimiter } = require('./middleware/rateLimiter');
const { setCsrfToken, validateCsrfToken, getCsrfToken } = require('./middleware/csrf');
const {
  apiVersionMiddleware,
  requestComplexityMiddleware,
  responseSecurityHeaders,
  requestFingerprinting
} = require('./middleware/apiSecurity');
const { authenticate, adminOnly } = require('./middleware/rbac');
const { DatabaseSecurityManager } = require('./config/databaseSecurity');
const { getAuditLogger } = require('./utils/securityAuditLogger');
const { getEncryptionService } = require('./utils/encryption');

// ============= DATABASE CONNECTION =============
async function initializeDatabase() {
  try {
    await DatabaseSecurityManager.initializeSecureConnection();
    console.log('✅ Secure database connection established');
    
    // Check database health
    const health = await DatabaseSecurityManager.healthCheck();
    console.log('📊 Database Health:', health.status);
  } catch (error) {
    console.error('❌ Failed to initialize database:', error.message);
    process.exit(1);
  }
}

// ============= ROUTE IMPORTS =============
const authRoutes = require('./routes/auth');
const postRoutes = require('./routes/posts');
const userRoutes = require('./routes/users');
const adminRoutes = require('./routes/admin');

// ============= EXPRESS APP SETUP =============
const app = express();

// Initialize security services
const auditLogger = getAuditLogger();
const encryptionService = getEncryptionService();

// Trust proxy for accurate IP detection behind reverse proxies
app.set('trust proxy', parseInt(process.env.TRUST_PROXY || 1));

// Connect to MongoDB with security checks
initializeDatabase();

// Security Middleware Chain (Defense in Depth)
// 1. Security Headers (CSP, HSTS, etc.)
app.use(securityHeaders);

// 2. CORS with strict configuration
app.use(cors(corsConfig));

// 3. Body parsing with size limits
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// 3.5 Cookie parsing (required for CSRF)
app.use(cookieParser());

// 4. Request sanitization (XSS, prototype pollution prevention)
app.use(sanitizeRequest);

// 5. API versioning and complexity checking
app.use(apiVersionMiddleware);
app.use(requestComplexityMiddleware);

// 6. Request fingerprinting for anomaly detection
app.use(requestFingerprinting);

// 7. Response security headers
app.use(responseSecurityHeaders);

// 8. General rate limiting
app.use(generalRateLimiter);

// 9. CSRF Protection - set token on all requests
app.use(setCsrfToken);

// CSRF token endpoint (must be before CSRF validation)
app.get('/api/csrf-token', getCsrfToken);

// 10. CSRF Validation for state-changing requests
app.use(validateCsrfToken);

// Health check (no rate limiting)
app.get('/api/health', async (req, res) => {
  try {
    const dbHealth = await DatabaseSecurityManager.healthCheck();
    res.json({
      status: 'ok',
      message: 'Server is running',
      timestamp: new Date().toISOString(),
      database: dbHealth.status
    });
  } catch (error) {
    res.status(503).json({
      status: 'unhealthy',
      message: 'Service unavailable',
      timestamp: new Date().toISOString()
    });
  }
});

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/posts', postRoutes);
app.use('/api/users', userRoutes);
app.use('/api/admin', adminRoutes);

// Security audit endpoint (admin only)
app.get('/api/admin/security/logs', authenticate, adminOnly, (req, res) => {
  try {
    const logs = auditLogger.readLogsForDate(new Date().toISOString().split('T')[0]);
    res.json({ success: true, logs, count: logs.length });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to retrieve logs' });
  }
});

// 404 handler - fail closed
app.use((req, res) => {
  res.status(404).json({ success: false, message: 'Resource not found' });
});

// Error handling middleware - safe error messages
app.use((err, req, res, next) => {
  // Log full error for debugging (server-side only)
  console.error('Error:', {
    message: err.message,
    stack: process.env.NODE_ENV === 'development' ? err.stack : undefined,
    path: req.path,
    method: req.method
  });
  
  // Return safe error message to client
  const statusCode = err.statusCode || 500;
  const message = statusCode === 500 
    ? 'An error occurred. Please try again.' 
    : err.message;
  
  res.status(statusCode).json({ 
    success: false, 
    message
  });
});

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT} in ${process.env.NODE_ENV || 'development'} mode`);
  console.log('Security features enabled: RBAC, Rate Limiting, Security Headers, Audit Logging');
});
