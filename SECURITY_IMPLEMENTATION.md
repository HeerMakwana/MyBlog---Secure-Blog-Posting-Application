# MyBlog Security Implementation Guide

## Table of Contents

1. [Overview](#overview)
2. [Security Architecture](#security-architecture)
3. [Environment Setup](#environment-setup)
4. [Authentication & Authorization](#authentication--authorization)
5. [Data Protection](#data-protection)
6. [Network Security](#network-security)
7. [Logging & Monitoring](#logging--monitoring)
8. [Incident Response](#incident-response)
9. [Deployment Security](#deployment-security)
10. [Security Testing](#security-testing)
11. [Compliance & Audit](#compliance--audit)

---

## Overview

This document provides comprehensive security implementation details for the MyBlog application. MyBlog implements **defense-in-depth** security with multiple layers of protection:

- **Layer 1**: Network & Transport Security (HTTPS, CORS, TLS)
- **Layer 2**: Input Validation & Sanitization (XSS, injection prevention)
- **Layer 3**: Authentication & Session Management (JWT, rate limiting, account lockout)
- **Layer 4**: Authorization & Access Control (RBAC, permission checking)
- **Layer 5**: Cryptography & Encryption (AES-256-GCM for sensitive data)
- **Layer 6**: Logging & Monitoring (comprehensive audit logging)

---

## Security Architecture

### 1. Request Processing Pipeline

```
Client Request
    ↓
[1] Security Headers (CSP, HSTS, X-Frame-Options)
    ↓
[2] CORS Validation
    ↓
[3] Request Size Limiting (10KB max)
    ↓
[4] Request Sanitization (XSS, prototype pollution)
    ↓
[5] API Versioning Check
    ↓
[6] Request Complexity Validation
    ↓
[7] Request Fingerprinting
    ↓
[8] Response Security Headers
    ↓
[9] Rate Limiting
    ↓
[10] CSRF Token Validation
    ↓
[11] Authentication (JWT)
    ↓
[12] Authorization (RBAC)
    ↓
[13] Input Validation
    ↓
[14] Business Logic
    ↓
[15] Audit Logging
    ↓
Safe Response to Client
```

### 2. Security Services

#### Environment Validator (`src/config/envValidator.js`)
- Validates all environment variables at startup
- Checks secret key lengths and formats
- Detects insecure configurations in production
- Prevents application startup with invalid configuration

#### Encryption Service (`src/utils/encryption.js`)
- **Algorithm**: AES-256-GCM (authenticated encryption)
- **Key Length**: 256 bits (32 bytes)
- **IV**: 128 bits (16 bytes) random per encryption
- **Auth Tag**: 128 bits (16 bytes) for integrity verification

#### Security Audit Logger (`src/utils/securityAuditLogger.js`)
- Logs all security-relevant events
- Assigns risk levels (LOW, MEDIUM, HIGH, CRITICAL)
- Automatic log rotation and cleanup
- Forensic trail for incident analysis

#### Database Security (`src/config/databaseSecurity.js`)
- Connection pooling and timeout management
- Query parameterization for injection prevention
- Input sanitization (NoSQL injection prevention)
- Database health monitoring

#### API Security (`src/middleware/apiSecurity.js`)
- API versioning and deprecation warnings
- Request signature validation
- Request complexity limiting
- Request fingerprinting for anomaly detection

---

## Environment Setup

### 1. Create Production .env File

```bash
# Copy template and customize
cp backend/.env.example backend/.env
```

### 2. Generate Secure Secrets

```bash
# Generate 64-character random string for JWT_SECRET
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"

# Generate 64-character random string for SESSION_SECRET
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"

# Generate 32-character CSRF_SECRET
node -e "console.log(require('crypto').randomBytes(16).toString('hex'))"

# Generate 64-char hex ENCRYPTION_KEY
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

### 3. Configure Critical Variables

```env
# HTTPS/TLS
NODE_ENV=production
COOKIE_SECURE=true
COOKIE_HTTP_ONLY=true
COOKIE_SAME_SITE=strict

# Secrets (use generated values above)
JWT_SECRET=<generated-64-char-string>
SESSION_SECRET=<generated-64-char-string>
CSRF_SECRET=<generated-32-char-string>
ENCRYPTION_KEY=<generated-64-char-hex-string>

# Database (use MongoDB Atlas with authentication)
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/myblog

# CORS (specify your domain only, no wildcards)
ALLOWED_ORIGINS=https://yourdomain.com,https://www.yourdomain.com

# Email (required for account verification)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-app-email@gmail.com
SMTP_PASS=app-specific-password

# Security Features
ENABLE_AUDIT_LOGGING=true
ENABLE_RATE_LIMITING=true
ENABLE_CSRF_PROTECTION=true
ENABLE_EMAIL_VERIFICATION=true
ENABLE_ACCOUNT_LOCKOUT=true
ENABLE_CAPTCHA=true
```

### 4. Validate Configuration

```bash
npm run test:security
```

Expected output:
```
═══════════════════════════════════════════════════════
  🔒 MyBlog Security Test Suite
═══════════════════════════════════════════════════════

✅ All security tests passed! 🎉
```

---

## Authentication & Authorization

### 1. User Registration

1. **Client** → POST `/api/auth/register` with username, email, password, captcha
2. **Server**:
   - Validates CAPTCHA challenge
   - Validates email format and uniqueness
   - Validates password strength (12+ chars, upper, lower, number, special)
   - Hashes password with bcryptjs (cost factor 12)
   - Creates user with `role: 'customer'` (least privilege)
   - Generates email verification token
   - Sends verification email
   - Returns JWT token (1-hour expiry)

### 2. User Login

```
Flow: CAPTCHA Challenge → Password Validation → Account Status Check → Token Issue
```

1. **Client** requests CAPTCHA challenge
2. **Server** returns math problem (a ± b = ?)
3. **Client** solves CAPTCHA, sends with username/password
4. **Server**:
   - Validates CAPTCHA answer
   - Checks username/email exists
   - Verifies password hash
   - Checks if account is locked (5 failed attempts = 15-min lockout)
   - Checks if email is verified
   - Generates JWT token
   - Logs successful authentication event
   - Returns token + user profile

### 3. JWT Token Structure

```
{
  "id": "user_mongodb_id",
  "iat": 1234567890,        // Issued at
  "exp": 1234571490,        // Expires in 1 hour
  "algorithm": "HS256"
}
```

**Secret Requirements**:
- Minimum 64 characters (256 bits)
- Cryptographically random
- Never share or expose
- Rotate in case of compromise

### 4. Role-Based Access Control (RBAC)

| Role | Level | Permissions |
|------|-------|-----------|
| Guest | 0 | Read public posts |
| Customer | 1 | Manage own profile, create posts |
| Editor | 2 | Create/edit/delete own posts |
| Admin | 3 | All permissions + user management |

**How to check permissions**:

```javascript
// In route handlers
const { checkPermission } = require('../middleware/rbac');

app.delete('/api/users/:userId', checkPermission('DELETE_USER'), async (req, res) => {
  // Only users with DELETE_USER permission can execute
});
```

### 5. Account Lockout Protection

After 5 failed login attempts within 15 minutes:
- Account is locked for 15 minutes
- Subsequent login attempts are rejected
- Email notification sent to account owner
- Event logged as HIGH-risk security event

```javascript
{
  eventType: 'LOGIN_ACCOUNT_LOCKOUT',
  riskLevel: 'HIGH',
  userId: user._id,
  failedAttempts: 5,
  lockedUntil: '2026/04/17T14:30:00Z'
}
```

---

## Data Protection

### 1. Encryption at Rest

Sensitive data fields are encrypted using AES-256-GCM:

```javascript
const { getEncryptionService } = require('./utils/encryption');
const encryption = getEncryptionService();

// Encrypt
const encryptedData = encryption.encrypt(sensitiveString);
// Returns: "iv:authTag:encrypted" (hex-encoded)

// Decrypt
const decrypted = encryption.decrypt(encryptedData);
```

**Fields to encrypt** (by default):
- Backup codes (if TOTP enabled)
- Security answers (if security questions enabled)
- API keys
- Payment information

### 2. Password Hashing

Using **bcryptjs** with cost factor 12:

```javascript
const bcrypt = require('bcryptjs');

// Hash password
const hashedPassword = await bcrypt.hash(password, 12);

// Verify password
const isValid = await bcrypt.compare(inputPassword, hashedPassword);
```

**Never**:
- Store passwords in plaintext
- Use simple hashing (MD5, SHA1)
- Use reversible encryption for passwords
- Log passwords in any form

### 3. Secure Data Deletion

```javascript
// Securely remove deleted user data
app.delete('/api/account', async (req, res) => {
  const userId = req.user._id;
  
  // Delete user data
  await User.deleteOne({ _id: userId });
  
  // Revoke all active sessions
  await Session.deleteMany({ userId });
  
  // Log deletion event
  auditLogger.log({
    eventType: 'ACCOUNT_DELETED',
    userId,
    action: 'User account permanently deleted',
    status: 'SUCCESS'
  });
  
  res.json({ success: true, message: 'Account deleted permanently' });
});
```

---

## Network Security

### 1. HTTPS/TLS Requirements

Production deployment **must** use HTTPS with:

- **Protocol**: TLS 1.2 or 1.3
- **Certificates**: Valid, CA-signed (not self-signed)
- **HSTS**: Enabled with preload list (max-age=31536000)
- **Enforced Redirection**: HTTP → HTTPS

Configure in `.env`:
```env
COOKIE_SECURE=true
NODE_ENV=production
```

### 2. CORS Configuration

Only allow requests from trusted origins:

```env
# Correct
ALLOWED_ORIGINS=https://yourdomain.com,https://www.yourdomain.com

# Wrong - Security Risk!
ALLOWED_ORIGINS=*
ALLOWED_ORIGINS=http://localhost:3000,https://yourdomain.com
```

### 3. Security Headers

All responses include security headers:

| Header | Value | Purpose |
|--------|-------|---------|
| `Content-Security-Policy` | `default-src 'self'` | XSS prevention |
| `Strict-Transport-Security` | `max-age=31536000` | Force HTTPS |
| `X-Content-Type-Options` | `nosniff` | Prevent MIME sniffing |
| `X-Frame-Options` | `DENY` | Prevent clickjacking |
| `X-XSS-Protection` | `1; mode=block` | Legacy XSS filter |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Limit referrer leakage |

### 4. CSRF Protection

Implements **Double-Submit Cookie** pattern:

1. Server generates CSRF token (random 32-byte cryptographic string)
2. Token sent in both:
   - HTTP-only cookie: `XSRF-TOKEN`
   - JSON response header: `X-CSRF-Token`
3. Client must include token in `X-XSRF-TOKEN` header for state-changing requests (POST, PUT, DELETE)
4. Server validates token matches cookie value

```javascript
// Get CSRF token
GET /api/csrf-token

// Use token in requests
POST /api/auth/register
Headers: {
  'X-XSRF-TOKEN': '<token-from-cookie>'
}
```

---

## Logging & Monitoring

### 1. Event Types Logged

Every security event logs:
- **Timestamp** (ISO 8601)
- **Event Type** (LOGIN_SUCCESS, PERMISSION_DENIED, etc.)
- **Risk Level** (LOW, MEDIUM, HIGH, CRITICAL)
- **User ID** and username
- **Request Context** (IP, User-Agent, path, referer)
- **Status** (SUCCESS, FAILURE, BLOCKED)
- **Additional Data** (event-specific details)

### 2. Log Files

Logs are written to `backend/logs/`:

```
logs/
├── audit-2026-04-17.log       # Daily audit log
├── audit-2026-04-17-archive.log
└── critical-events.log        # Critical-level events only
```

Each line is a JSON object:
```json
{
  "timestamp": "2026/04/17T12:00:00Z",
  "eventType": "LOGIN_SUCCESS",
  "riskLevel": "LOW",
  "userId": "507f1f77bcf86cd799439011",
  "username": "john_doe",
  "action": "User successfully authenticated",
  "status": "SUCCESS",
  "requestContext": {
    "ip": "192.168.1.100",
    "userAgent": "Mozilla/5.0...",
    "method": "POST",
    "path": "/api/auth/login"
  }
}
```

### 3. Monitoring Dashboard Queries

**Recent login failures** (last 24 hours):
```javascript
const logs = auditLogger.readLogsForDate(new Date().toISOString().split('T')[0]);
const failures = logs.filter(l => 
  l.eventType === 'LOGIN_FAILURE' && 
  l.timestamp > new Date(Date.now() - 86400000)
);
```

**Suspicious activity** (last 7 days):
```javascript
const suspicious = auditLogger.getSuspiciousActivity(7);
suspicious.forEach(event => {
  console.log(`${event.username}: ${event.action}`);
});
```

### 4. Log Retention

Logs are automatically cleaned up based on retention policy:

```env
# Retain logs for 90 days
AUDIT_LOG_RETENTION_DAYS=90
```

Cleanup runs automatically; manual cleanup:
```javascript
auditLogger.cleanupOldLogs(90);
```

---

## Incident Response

### 1. Security Incident Reports

If you discover a security vulnerability, **DO NOT** create a public GitHub issue.

**Report to**: security@yourdomain.com

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (optional)

**Response SLA**: 24-48 hours

### 2. Responding to Account Compromise

If a user reports account compromise:

1. **Immediate**:
   - Revoke all active sessions for the user
   - Force password reset on next login
   - Log the incident

```javascript
// Revoke all sessions
await Session.deleteMany({ userId: user._id });

// Force password reset
await User.updateOne({ _id: user._id }, { 
  passwordResetRequired: true,
  lastPasswordChange: new Date()
});
```

2. **Follow-up**:
   - Send security alert email
   - Request password change
   - Enable additional security features (if available)
   - Review recent activity logs

### 3. Responding to Rate Limit Attacks

Automated detection of brute-force attempts:

```javascript
// Automatically triggered when rate limit exceeded
auditLogger.log({
  eventType: 'RATE_LIMIT_EXCEEDED',
  riskLevel: 'MEDIUM',
  username: attacker_identifier,
  action: 'Rate limit exceeded on /api/auth/login',
  additionalData: {
    endpoint: '/api/auth/login',
    attempts: 100,
    timeWindow: '15min'
  }
});
```

**Mitigation**:
- IP-based blocking (optional, at reverse proxy level)
- Temporary account lockout
- Notify account owner
- Review logs manually

---

## Deployment Security

### 1. Production Checklist

```bash
# Before deploying to production:

# 1. Generate all secrets
export JWT_SECRET=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")
export SESSION_SECRET=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")
export CSRF_SECRET=$(node -e "console.log(require('crypto').randomBytes(16).toString('hex'))")
export ENCRYPTION_KEY=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")

# 2. Run security tests
npm run test:security

# 3. Check for vulnerabilities
npm audit

# 4. Verify environment variables
npm run test:security

# 5. Enable HTTPS/TLS at reverse proxy
# Configure nginx/cloudflare/ALB with SSL certificate

# 6. Set environment mode
export NODE_ENV=production

# 7. Deploy
npm run start
```

### 2. Reverse Proxy Configuration (nginx)

```nginx
server {
    listen 443 ssl http2;
    server_name yourdomain.com;

    # SSL/TLS Configuration
    ssl_certificate     /path/to/certificate.crt;
    ssl_certificate_key /path/to/private.key;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;
    
    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-XSS-Protection "1; mode=block" always;

    # Reverse Proxy to Backend
    location /api/ {
        proxy_pass http://backend:5000;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Frontend
    location / {
        proxy_pass http://frontend:3000;
    }
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name yourdomain.com;
    return 301 https://$server_name$request_uri;
}
```

### 3. Database Security

**MongoDB Atlas Configuration**:

1. **Network Access**:
   - Whitelist only your application servers
   - Use VPC peering for private network access
   - Never allow `0.0.0.0/0`

2. **Authentication**:
   - Enable database user authentication
   - Use strong passwords (20+ characters)
   - Enable IP whitelist

3. **Encryption**:
   - Enable encryption at rest
   - Enable encryption in transit (TLS)
   - Enable backups with encryption

4. **Monitoring**:
   - Enable database activity monitoring
   - Set up alerts for suspicious activity
   - Review audit logs regularly

---

## Security Testing

### 1. Automated Security Tests

Run security test suite:
```bash
npm run test:security
```

This validates:
- Environment variables
- Security headers
- CORS configuration
- Password policy
- Rate limiting
- File permissions
- Encryption setup
- HTTPS configuration
- Logging setup
- Dependencies

### 2. Manual Security Testing

**OWASP Top 10 Tests**:

1. **SQL/NoSQL Injection**:
   ```bash
   # Test with special characters
   POST /api/posts { "title": "'; DROP TABLE users; --" }
   # Expected: Input validation error, no database modification
   ```

2. **Cross-Site Scripting (XSS)**:
   ```bash
   # Test with script tags
   POST /api/posts { "body": "<script>alert('XSS')</script>" }
   # Expected: Script tags removed/escaped
   ```

3. **Cross-Site Request Forgery (CSRF)**:
   ```bash
   # Test without CSRF token
   POST /api/posts (without X-CSRF-Token header)
   # Expected: 403 Forbidden
   ```

4. **Broken Authentication**:
   ```bash
   # Test with invalid JWT
   GET /api/posts -H "Authorization: Bearer invalid.token.here"
   # Expected: 401 Unauthorized
   ```

5. **Sensitive Data Exposure**:
   ```bash
   # Test password logging
   POST /api/auth/register { "password": "secret" }
   # Verify password not in logs/errors
   ```

### 3. Dependency Vulnerability Scanning

```bash
# Check for known vulnerabilities
npm audit

# Auto-fix fixable vulnerabilities
npm audit fix

# Manual patch process
npm update <package>@latest
npm install
npm run test  # Ensure nothing breaks
```

### 4. Load/Stress Testing

Use tools like `ab` (ApacheBench) or `k6`:

```bash
# Simple load test
ab -n 1000 -c 10 https://yourdomain.com/api/posts

# Expected results:
# - Rate limiting engages after threshold
# - Requests queued gracefully
# - Server remains responsive
# - No information leakage in error responses
```

---

## Compliance & Audit

### 1. GDPR Compliance

**Data Privacy Features**:

- Email verification required for account creation
- User can export their data: `GET /api/account/export`
- User can delete their account: `DELETE /api/account`
- Data retention policy: Delete after 1 year of inactivity (configurable)
- Audit logs show all data access/modifications

**Configuration**:
```env
# GDPR settings
ENABLE_GDPR_EXPORT=true
ENABLE_ACCOUNT_DELETION=true
DATA_RETENTION_DAYS=365
```

### 2. Security Certifications

To achieve security certifications:

#### OWASP ASVS (Application Security Verification Standard)
- Level 1: Basic security checks ✅
- Level 2: Authentication & access control ✅  
- Level 3: Cryptography & data protection (partial)

#### PCI DSS (if handling payments)
- Encryption at rest and in transit ✅
- Access control and authentication ✅
- Regular security testing ✅
- Incident response procedures ✅

### 3. Regular Audit Schedule

| Task | Frequency | Owner |
|------|-----------|-------|
| Security test suite | Every build | CI/CD |
| Dependency audit | Weekly | Dev Team |
| Log review | Daily | Administrator |
| Penetration test | Quarterly | Security Team |
| Security training | Annually | All staff |
| Incident review | As needed | Security Team |

### 4. Security Policy Examples

**Password Reset Expiry**:
- Token valid for 24 hours
- One-time use only
- Email sent when reset used

**Session Expiry**:
- Idle timeout: 30 minutes
- Absolute timeout: 24 hours
- Session revocation on logout
- All sessions revoked on password change

---

## Support & Additional Resources

- **OWASP Top 10**: https://owasp.org/Top10/
- **NIST Cybersecurity Framework**: https://www.nist.gov/cyberframework
- **Mozilla Web Security**: https://infosec.mozilla.org/
- **Node.js Security Best Practices**: https://nodejs.org/en/docs/guides/security/


---

## Consolidated Summary

This section merges the removed summary, quick reference, and report content into this single canonical guide.

### Executive Summary

- Defense-in-depth security is implemented across environment validation, authentication, authorization, request validation, encryption, audit logging, and frontend token handling.
- The tester-facing API path is the Firebase Functions app in `functions/`, while `backend/` remains the local standalone API.
- The application should fail closed when secrets, CORS, or origin settings are misconfigured.

### Quick Start

1. Copy `backend/.env.example` to `backend/.env` and `functions/.env.example` to `functions/.env` as needed.
2. Generate strong secrets for `JWT_SECRET`, `SESSION_SECRET`, `CSRF_SECRET`, and `ENCRYPTION_KEY`.
3. Set `ALLOWED_ORIGINS` to exact production or local origins only.
4. Run `npm run test:security` before sharing to testers.
5. Start the local stack or emulator after validation.

### Core Security Features

- Authentication: CAPTCHA, JWT, bcrypt hashing, rate limiting, account lockout, email verification.
- Authorization: RBAC with admin-only controls on sensitive endpoints.
- Data protection: AES-256-GCM at rest, HTTPS/TLS in transit, secure cookies, CSRF protection.
- Monitoring: Audit logging, critical event logging, request fingerprinting, retention cleanup.
- Input validation: Request size limits, prototype pollution prevention, XSS and injection mitigation.

### Operational Checklist

- Use 64+ character random secrets for JWT and session signing.
- Keep `COOKIE_SECURE=true` in production.
- Never allow wildcard CORS origins in production.
- Confirm admin-only endpoints are protected by authentication and role checks.
- Verify token handling in the frontend uses secure storage and supports legacy migration when needed.

### Testing and Handoff

- `npm run test:security` is the primary pre-share validation step.
- `npm audit` should be reviewed before packaging a tester build.
- Functions security leakage checks require a running API server or emulator.
- For Firebase Functions tests, set `SECURITY_TEST_BASE_URL` when the default host differs.

### Key Files

- `backend/src/config/envValidator.js`
- `backend/src/middleware/auth.js`
- `backend/src/index.js`
- `functions/index.js`
- `functions/middleware/auth.js`
- `frontend/src/config/securityConfig.js`
- `frontend/src/services/api.js`
- `frontend/src/context/AuthContext.js`

### Report Highlights

- RBAC is least-privilege by design, with admin capabilities isolated from standard user flows.
- Fail-safe defaults are enforced at the config and middleware layers.
- Security logs and audit trails are intended for incident review and compliance evidence.
- The current deployment guidance assumes HTTPS behind a reverse proxy or Firebase Hosting.
