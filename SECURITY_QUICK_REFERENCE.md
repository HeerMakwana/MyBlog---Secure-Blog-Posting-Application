# MyBlog Security - Quick Reference Guide

## 🚀 Quick Start Checklist

### Before Running the Application

```bash
# 1. Copy environment template
cp backend/.env.example backend/.env

# 2. Generate secure secrets (in bash/terminal)
JWT_SECRET=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")
SESSION_SECRET=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")
CSRF_SECRET=$(node -e "console.log(require('crypto').randomBytes(16).toString('hex'))")
ENCRYPTION_KEY=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")

# 3. Update .env with your values
# Edit backend/.env and add the secrets above
# Set MONGODB_URI, ALLOWED_ORIGINS, SMTP settings

# 4. Validate configuration
npm run test:security

# 5. Start application
npm run dev
```

## 🔐 Core Security Features

### 1. Authentication
- ✅ **CAPTCHA** - Math challenge to prevent bot registration
- ✅ **JWT Tokens** - Cryptographic session tokens (1-hour expiry)
- ✅ **Password Hashing** - bcryptjs with cost factor 12
- ✅ **Rate Limiting** - 5 login attempts per 15 minutes
- ✅ **Account Lockout** - 15-minute lockout after 5 failed attempts
- ✅ **Email Verification** - Required before account activation

### 2. Authorization
- ✅ **RBAC** - Four-tier role system (Guest, Customer, Editor, Admin)
- ✅ **Permission Checking** - Middleware validates permissions per endpoint
- ✅ **Audit Logging** - All access attempts logged

### 3. Data Protection
- ✅ **Encryption at Rest** - AES-256-GCM for sensitive data
- ✅ **HTTPS/TLS** - All traffic encrypted in transit
- ✅ **Secure Cookies** - HttpOnly, Secure, SameSite=Strict
- ✅ **CSRF Protection** - Double-submit cookie pattern

### 4. Network Security
- ✅ **Security Headers** - CSP, HSTS, X-Frame-Options, etc.
- ✅ **CORS** - Whitelist allowed origins only
- ✅ **Request Validation** - Size limits, complexity checks
- ✅ **Input Sanitization** - XSS, injection prevention

### 5. Monitoring
- ✅ **Audit Logging** - Comprehensive event tracking
- ✅ **Anomaly Detection** - Request fingerprinting
- ✅ **Critical Alerts** - High/Critical events logged separately
- ✅ **Log Retention** - Automatic cleanup after 90 days

---

## 📋 Common Tasks

### Using Encryption Service

```javascript
const { getEncryptionService } = require('./utils/encryption');
const encryption = getEncryptionService();

// Encrypt a string
const encrypted = encryption.encrypt('sensitive data');
// Returns: "iv:authTag:encrypted" (hex-encoded)

// Decrypt
const decrypted = encryption.decrypt(encrypted);

// Encrypt/decrypt objects
const encryptedObj = encryption.encryptObject({ secret: 'data' });
const decryptedObj = encryption.decryptObject(encryptedObj);

// Generate random token
const token = encryption.generateToken(32); // 32 bytes
```

### Using Audit Logger

```javascript
const { getAuditLogger } = require('./utils/securityAuditLogger');
const auditLogger = getAuditLogger();

// Log successful authentication
auditLogger.logAuthenticationSuccess(userId, username, req);

// Log failed authentication
auditLogger.logAuthenticationFailure(username, 'Invalid password', req);

// Log unauthorized access
auditLogger.logUnauthorizedAccess(userId, username, '/api/admin', req);

// Log permission denied
auditLogger.logPermissionDenied(userId, username, 'DELETE_USER', 'users/123', req);

// Log suspicious activity
auditLogger.logSuspiciousActivity(userId, username, 'Multiple failed logins', req);

// Log data modification
auditLogger.logDataModification(userId, username, 'Post #123', 'UPDATE', changedFields, req);

// Get logs for specific user
const userLogs = auditLogger.getUserLogs(userId, 30); // Last 30 days

// Get suspicious activity
const suspicious = auditLogger.getSuspiciousActivity(7); // Last 7 days
```

### Using Database Security

```javascript
const { DatabaseSecurityManager } = require('./config/databaseSecurity');

// Safe query with parameterization
const user = await DatabaseSecurityManager.safeFind(User, { email: userEmail });

// Safe update
const updated = await DatabaseSecurityManager.safeUpdate(
  User,
  { _id: userId },
  { name, email }
);

// Safe delete with confirmation
const deleted = await DatabaseSecurityManager.safeDelete(
  User,
  { _id: userId },
  true // Requires explicit confirmation
);

// Check database health
const health = await DatabaseSecurityManager.healthCheck();

// Get database statistics
const stats = await DatabaseSecurityManager.getDatabaseStats();

// Create backup
const backup = await DatabaseSecurityManager.backupDatabase();
```

### Checking Permissions in Routes

```javascript
const { checkPermission } = require('./middleware/rbac');
const { protect } = require('./middleware/auth');

// Require authentication + specific permission
router.delete(
  '/api/users/:id',
  protect,
  checkPermission('DELETE_USER'),
  async (req, res) => {
    // Only admins can delete users
  }
);

// Require authentication only
router.get(
  '/api/profile',
  protect,
  async (req, res) => {
    // req.user contains authenticated user
    res.json(req.user);
  }
);
```

---

## 🧪 Testing Security

### Run Security Tests

```bash
npm run test:security
```

Output shows:
- ✅ Environment variables validation
- ✅ Security headers configuration
- ✅ CORS configuration
- ✅ Password policy
- ✅ Rate limiting
- ✅ File permissions
- ✅ Encryption setup
- ✅ HTTPS configuration
- ✅ Logging setup
- ✅ Dependencies

### Check Dependencies

```bash
# Audit for vulnerabilities
npm audit

# Show detailed vulnerabilities
npm audit --json

# Auto-fix safe vulnerabilities
npm audit fix

# Update specific package
npm update package-name
```

### Manual Security Test Examples

```bash
# Test CSRF protection
curl -X POST http://localhost:5000/api/posts \
  -H "Content-Type: application/json" \
  -d '{"title":"test"}'
# Expected: 403 Forbidden (missing CSRF token)

# Test rate limiting
for i in {1..10}; do
  curl -X POST http://localhost:5000/api/auth/login \
    -H "Content-Type: application/json" \
    -d '{"username":"test","password":"test"}'
done
# After 5 attempts: 429 Too Many Requests

# Test input validation
curl -X POST http://localhost:5000/api/posts \
  -H "Content-Type: application/json" \
  -d '{"title":"<script>alert(1)</script>"}'
# Expected: Input validation error, scripts removed
```

---

## 🔑 Environment Variables Reference

### Required (Production)
```env
NODE_ENV=production
MONGODB_URI=mongodb+srv://...
JWT_SECRET=<64-char-random-string>
SESSION_SECRET=<64-char-random-string>
CSRF_SECRET=<32-char-random-string>
ENCRYPTION_KEY=<64-hex-char-string>
ALLOWED_ORIGINS=https://yourdomain.com
```

### Recommended (Production)
```env
COOKIE_SECURE=true
COOKIE_HTTP_ONLY=true
COOKIE_SAME_SITE=strict
ENABLE_AUDIT_LOGGING=true
ENABLE_RATE_LIMITING=true
ENABLE_CSRF_PROTECTION=true
ENABLE_EMAIL_VERIFICATION=true
ENABLE_ACCOUNT_LOCKOUT=true
ENABLE_CAPTCHA=true
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASS=app-password
EMAIL_FROM=noreply@yourdomain.com
```

### Optional
```env
LOG_LEVEL=info
LOG_SENSITIVE_DATA=false
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100
PASSWORD_MIN_LENGTH=12
TRUST_PROXY=1
BACKUP_ENABLED=true
AUDIT_LOG_RETENTION_DAYS=90
```

---

## 📚 Key Files Reference

| File | Purpose |
|------|---------|
| `.env.example` | Template for environment variables |
| `src/config/envValidator.js` | Validates env configuration at startup |
| `src/config/security.js` | Central security configuration |
| `src/config/databaseSecurity.js` | Database query safety & connection management |
| `src/middleware/securityHeaders.js` | Security headers & CORS setup |
| `src/middleware/csrf.js` | CSRF token generation & validation |
| `src/middleware/rateLimiter.js` | Rate limiting for different endpoints |
| `src/middleware/apiSecurity.js` | API versioning, request validation, fingerprinting |
| `src/utils/encryption.js` | AES-256-GCM encryption service |
| `src/utils/securityAuditLogger.js` | Comprehensive audit logging |
| `src/utils/validation.js` | Input validation utilities |
| `scripts/securityTests.js` | Automated security test suite |
| `SECURITY_IMPLEMENTATION.md` | Full security documentation |

---

## 🚨 Common Security Mistakes to Avoid

### ❌ Bad
```javascript
// Storing passwords in logs
console.log(`User ${username} logged in with password ${password}`);

// Using insecure secrets
JWT_SECRET="my-secret"  // Too short!

// Exposing user errors
res.status(401).json({ message: "User not found" }); // Tells attacker user doesn't exist

// Allowing all origins
cors({ origin: '*' }); // MASSIVE CSRF vulnerability

// Using password instead of bcrypt
const isValid = password === user.password; // NEVER
```

### ✅ Good
```javascript
// Never log passwords
const eventLog = { username, action: 'login', success: true };
console.log(eventLog); // Password never included

// Use cryptographically secure secrets
JWT_SECRET = "process.env.JWT_SECRET" // From 64-char random env var

// Generic error message
res.status(401).json({ message: "Invalid credentials" }); // Never reveals if user exists

// Whitelist specific origins
cors({ 
  origin: ['https://yourdomain.com', 'https://www.yourdomain.com'],
  credentials: true
});

// Always use bcrypt
const isValid = await bcrypt.compare(password, hashedPassword);
```

---

## 📞 Getting Help

### Documentation
- Full guide: [SECURITY_IMPLEMENTATION.md](./SECURITY_IMPLEMENTATION.md)
- API endpoints: See route files in `src/routes/`
- Configuration: [backend/.env.example](./backend/.env.example)

### Troubleshooting
1. **Environment validation fails**: Run `npm run test:security`
2. **Authentication not working**: Check JWT_SECRET length (must be 64+ chars)
3. **CSRF errors**: Ensure CSRF_SECRET is set in .env
4. **Database connection fails**: Verify MONGODB_URI and network access
5. **Logs not written**: Check `backend/logs/` directory exists and has write permissions

### Security Issues
**DO NOT** create public GitHub issues for security problems.  
Report to: `security@yourdomain.com`

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2024-04-11 | Initial security implementation |

**Last Updated**: 2024-04-11  
**Status**: ✅ All security features implemented and tested
