require('dotenv').config();
const express = require('express');
const cors = require('cors');
const connectDB = require('./config/database');

// Security imports
const { securityHeaders, corsConfig, sanitizeRequest } = require('./middleware/securityHeaders');
const { generalRateLimiter } = require('./middleware/rateLimiter');

// Route imports
const authRoutes = require('./routes/auth');
const postRoutes = require('./routes/posts');
const userRoutes = require('./routes/users');
const adminRoutes = require('./routes/admin');

const app = express();

// Trust proxy for accurate IP detection behind reverse proxies
app.set('trust proxy', 1);

// Connect to MongoDB
connectDB();

// Security Middleware Chain (Defense in Depth)
// 1. Security Headers (CSP, HSTS, etc.)
app.use(securityHeaders);

// 2. CORS with strict configuration
app.use(cors(corsConfig));

// 3. Body parsing with size limits
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// 4. Request sanitization (XSS, prototype pollution prevention)
app.use(sanitizeRequest);

// 5. General rate limiting
app.use(generalRateLimiter);

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/posts', postRoutes);
app.use('/api/users', userRoutes);
app.use('/api/admin', adminRoutes);

// Health check (no rate limiting)
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', message: 'Server is running', timestamp: new Date().toISOString() });
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
