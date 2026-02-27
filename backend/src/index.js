require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const connectDB = require('./config/database');

// Security imports
const { securityHeaders, corsConfig, sanitizeRequest } = require('./middleware/securityHeaders');
const { generalRateLimiter } = require('./middleware/rateLimiter');
const { sessionMiddleware, trackSessionActivity } = require('./middleware/session');
const { setCsrfToken, validateCsrfToken, csrfTokenEndpoint } = require('./middleware/csrf');

// Route imports
const authRoutes = require('./routes/auth');
const postRoutes = require('./routes/posts');
const userRoutes = require('./routes/users');
const adminRoutes = require('./routes/admin');

const app = express();

// Trust proxy for accurate IP detection behind reverse proxies
app.set('trust proxy', process.env.TRUST_PROXY ? parseInt(process.env.TRUST_PROXY, 10) : 1);

// Connect to MongoDB
connectDB();

// ===== SECURITY MIDDLEWARE CHAIN (Defense in Depth) =====

// 1. Helmet - Additional security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameSrc: ["'none'"],
      upgradeInsecureRequests: process.env.NODE_ENV === 'production' ? [] : null
    }
  },
  crossOriginEmbedderPolicy: false, // May need to adjust for your use case
  crossOriginResourcePolicy: { policy: "same-origin" }
}));

// 2. Custom Security Headers (CSP, HSTS, etc.)
app.use(securityHeaders);

// 3. CORS with strict configuration
app.use(cors(corsConfig));

// 4. Cookie Parser (required for session and CSRF)
app.use(cookieParser(process.env.SESSION_SECRET));

// 5. Body parsing with size limits
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// 6. Request sanitization (XSS, prototype pollution prevention)
app.use(sanitizeRequest);

// 7. General rate limiting
app.use(generalRateLimiter);

// 8. Session middleware
app.use(sessionMiddleware);

// 9. Session activity tracking
app.use(trackSessionActivity);

// 10. CSRF Token setup (sets token on all requests)
app.use(setCsrfToken);

// ===== ROUTES =====

// CSRF Token endpoint - get a fresh token
app.get('/api/csrf-token', csrfTokenEndpoint);

// Health check (no CSRF, no rate limiting impact)
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    message: 'Server is running', 
    timestamp: new Date().toISOString(),
    sessionActive: !!req.session?.isAuthenticated
  });
});

// Auth routes - CSRF protection on state-changing routes
app.use('/api/auth', authRoutes);

// Protected routes with CSRF validation
app.use('/api/posts', validateCsrfToken, postRoutes);
app.use('/api/users', validateCsrfToken, userRoutes);
app.use('/api/admin', validateCsrfToken, adminRoutes);

// ===== ERROR HANDLING =====

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
  
  // Handle CSRF errors specifically
  if (err.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({
      success: false,
      message: 'Invalid CSRF token. Please refresh and try again.'
    });
  }
  
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
  console.log('Security features enabled: RBAC, Rate Limiting, Security Headers, Session Management, CSRF Protection, Audit Logging');
});
