/**
 * Authentication Routes - Secure Implementation
 * Implements: Rate limiting, input validation, audit logging, MFA with backup codes,
 * Secure sessions, CSRF protection
 */

const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const User = require('../models/User');
const { authenticate, generateToken, getJwtSecret } = require('../middleware/rbac');
const { authRateLimiter, mfaRateLimiter, trackLoginAttempt, isAccountLocked } = require('../middleware/rateLimiter');
const { validateCsrfToken } = require('../middleware/csrf');
const { 
  regenerateSession, 
  destroySession, 
  initializeUserSession 
} = require('../middleware/session');
const { logAuditEvent } = require('../utils/auditLogger');
const { logAccountActivity } = require('../utils/accountActivity');
const { 
  validateEmail, 
  validateUsername, 
  validatePassword, 
  validateTOTPCode,
  validateBackupCode,
  SAFE_ERRORS 
} = require('../utils/validation');
const { generateSecret, generateOtpAuthUrl, generateQRCode, verifyTOTP, generateTOTP } = require('../utils/totp');
const { ROLES } = require('../config/roles');
const securityConfig = require('../config/security');

// Security questions list
const SECURITY_QUESTIONS = [
  { id: 1, question: "What was the name of your first pet?" },
  { id: 2, question: "In what city were you born?" },
  { id: 3, question: "What is your mother's maiden name?" },
  { id: 4, question: "What was the name of your elementary school?" },
  { id: 5, question: "What was the make of your first car?" },
  { id: 6, question: "What is your favorite movie?" },
  { id: 7, question: "What was the name of your childhood best friend?" },
  { id: 8, question: "What street did you grow up on?" }
];

/**
 * POST /api/auth/register
 * Register a new user with email verification
 */
router.post('/register', authRateLimiter, async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // Input validation
    const usernameResult = validateUsername(username);
    if (!usernameResult.valid) {
      return res.status(400).json({ success: false, message: usernameResult.error });
    }

    const emailResult = validateEmail(email);
    if (!emailResult.valid) {
      return res.status(400).json({ success: false, message: emailResult.error });
    }

    const passwordResult = validatePassword(password);
    if (!passwordResult.valid) {
      return res.status(400).json({ success: false, message: passwordResult.error });
    }

    // Check for existing user (use safe error message)
    const existingUser = await User.findOne({
      $or: [{ email: emailResult.value }, { username: usernameResult.value }]
    });

    if (existingUser) {
      // Don't reveal which field is taken
      return res.status(400).json({
        success: false,
        message: 'Registration failed. Please check your information.'
      });
    }

    // Create user with default role (EDITOR for blog platforms)
    const user = await User.create({ 
      username: usernameResult.value, 
      email: emailResult.value, 
      password,
      role: ROLES.EDITOR, // Default to EDITOR for blog platforms (can create/edit own posts)
      emailVerified: !securityConfig.account.emailVerificationRequired // Set based on config
    });

    // Generate email verification token
    let verificationToken = null;
    if (securityConfig.account.emailVerificationRequired) {
      verificationToken = user.generateEmailVerificationToken();
      await user.save({ validateBeforeSave: false });
      
      // In production, send verification email here
      console.log(`[DEV] Email verification token for ${user.email}: ${verificationToken}`);
    }

    // Audit log
    await logAuditEvent({
      eventType: 'AUTH_REGISTER',
      userId: user._id,
      username: user.username,
      req,
      action: 'User registered',
      status: 'SUCCESS',
      details: { emailVerificationRequired: securityConfig.account.emailVerificationRequired }
    });

    // Log account activity
    await logAccountActivity({
      userId: user._id,
      activityType: 'LOGIN_SUCCESS',
      req,
      status: 'SUCCESS',
      details: { method: 'registration' }
    });

    // Initialize secure session with regeneration
    try {
      await initializeUserSession(req, user);
    } catch (sessionError) {
      console.error('Session initialization error:', sessionError);
    }

    // Generate JWT token
    const sessionId = user.createSession(req.get('User-Agent'), req.ip);
    await user.save({ validateBeforeSave: false });
    
    const token = generateToken(user._id, { sessionId });

    res.status(201).json({
      success: true,
      token,
      emailVerificationRequired: securityConfig.account.emailVerificationRequired,
      user: user.toSafeObject()
    });
  } catch (error) {
    console.error('Registration error:', error.message);
    res.status(400).json({ success: false, message: SAFE_ERRORS.VALIDATION_FAILED });
  }
});

/**
 * POST /api/auth/login
 * Login with rate limiting and account lockout
 */
router.post('/login', authRateLimiter, async (req, res) => {
  try {
    const { username, password, deviceId, deviceFingerprint, trustDevice } = req.body;

    // Input validation
    if (!username || !password) {
      return res.status(400).json({
        success: false,
        message: 'Username and password are required'
      });
    }

    // Check if account is locked
    const lockStatus = isAccountLocked(username);
    if (lockStatus.locked) {
      await logAuditEvent({
        eventType: 'AUTH_LOGIN_FAILURE',
        req,
        action: 'Login attempt on locked account',
        status: 'BLOCKED',
        details: { username },
        riskLevel: 'HIGH'
      });

      return res.status(423).json({
        success: false,
        message: `Account is temporarily locked. Try again in ${lockStatus.remainingTime} seconds.`
      });
    }

    // Find user
    const user = await User.findOne({ username })
      .select('+password +totpSecret +trustedDevices +failedLoginAttempts +sessions');

    // Timing-safe comparison - don't reveal if user exists
    if (!user) {
      // Simulate password check timing
      await new Promise(resolve => setTimeout(resolve, 100));
      trackLoginAttempt(username, false);
      
      await logAuditEvent({
        eventType: 'AUTH_LOGIN_FAILURE',
        req,
        action: 'Login attempt with invalid username',
        status: 'FAILURE',
        details: { username },
        riskLevel: 'MEDIUM'
      });

      return res.status(401).json({
        success: false,
        message: SAFE_ERRORS.INVALID_CREDENTIALS
      });
    }

    // Check if account is locked in database
    if (user.isLocked) {
      if (user.lockedUntil && user.lockedUntil < new Date()) {
        // Lock expired, unlock account
        user.unlockAccount();
        await user.save({ validateBeforeSave: false });
      } else {
        await logAuditEvent({
          eventType: 'AUTH_LOGIN_FAILURE',
          userId: user._id,
          username: user.username,
          req,
          action: 'Login attempt on locked account',
          status: 'BLOCKED',
          riskLevel: 'HIGH'
        });

        return res.status(423).json({
          success: false,
          message: 'Account is locked. Please contact support.'
        });
      }
    }

    // Verify password
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      const wasLocked = user.recordFailedLogin();
      await user.save({ validateBeforeSave: false });
      trackLoginAttempt(username, false);

      await logAuditEvent({
        eventType: 'AUTH_LOGIN_FAILURE',
        userId: user._id,
        username: user.username,
        req,
        action: 'Invalid password',
        status: 'FAILURE',
        details: { accountLocked: wasLocked },
        riskLevel: wasLocked ? 'HIGH' : 'MEDIUM'
      });

      if (wasLocked) {
        return res.status(423).json({
          success: false,
          message: 'Account locked due to too many failed attempts. Please try again later.'
        });
      }

      return res.status(401).json({
        success: false,
        message: SAFE_ERRORS.INVALID_CREDENTIALS
      });
    }

    // Clear failed login attempts
    user.clearFailedLogins();
    trackLoginAttempt(username, true);

    // Check if MFA is required
    if (user.totpSecret) {
      // Check if device is trusted (creative MFA solution #3)
      if (deviceId && deviceFingerprint && user.isDeviceTrusted(deviceId, deviceFingerprint)) {
        // Skip MFA for trusted device
        await user.save({ validateBeforeSave: false });
        
        await logAuditEvent({
          eventType: 'AUTH_LOGIN_SUCCESS',
          userId: user._id,
          username: user.username,
          req,
          action: 'Login with trusted device (MFA skipped)',
          status: 'SUCCESS'
        });
      } else {
        // MFA required
        const tempToken = generateToken(user._id, { mfaPending: true });
        
        return res.json({
          success: true,
          mfaRequired: true,
          tempToken,
          userId: user._id,
          hasBackupCodes: user.hasBackupCodes(),
          hasSecurityQuestions: user.hasSecurityQuestions()
        });
      }
    }

    // Initialize secure session with regeneration (prevents session fixation)
    try {
      await initializeUserSession(req, user);
    } catch (sessionError) {
      console.error('Session initialization error:', sessionError);
    }

    // Log account activity
    await logAccountActivity({
      userId: user._id,
      activityType: 'LOGIN_SUCCESS',
      req,
      status: 'SUCCESS',
      details: { method: 'password' }
    });

    // Create user session record
    const sessionId = user.createSession(req.get('User-Agent'), req.ip);
    user.lastLogin = new Date();
    await user.save({ validateBeforeSave: false });

    const token = generateToken(user._id, { sessionId });

    await logAuditEvent({
      eventType: 'AUTH_LOGIN_SUCCESS',
      userId: user._id,
      username: user.username,
      req,
      action: 'User logged in',
      status: 'SUCCESS'
    });

    res.json({
      success: true,
      token,
      user: user.toSafeObject()
    });
  } catch (error) {
    console.error('Login error:', error.message);
    res.status(500).json({ success: false, message: SAFE_ERRORS.SERVER_ERROR });
  }
});

/**
 * POST /api/auth/verify-mfa
 * Verify MFA code (TOTP or backup code)
 */
router.post('/verify-mfa', mfaRateLimiter, async (req, res) => {
  try {
    const { tempToken, code, useBackupCode, deviceId, deviceFingerprint, trustDevice, deviceName } = req.body;

    if (!tempToken || !code) {
      return res.status(400).json({
        success: false,
        message: 'Token and code are required'
      });
    }

    // Verify temp token
    let decoded;
    try {
      const jwt = require('jsonwebtoken');
      decoded = jwt.verify(tempToken, getJwtSecret());
    } catch (err) {
      return res.status(401).json({
        success: false,
        message: SAFE_ERRORS.UNAUTHORIZED
      });
    }

    if (!decoded.mfaPending) {
      return res.status(400).json({
        success: false,
        message: 'Invalid MFA verification request'
      });
    }

    const user = await User.findById(decoded.id)
      .select('+totpSecret +backupCodes +trustedDevices +sessions');
    
    if (!user) {
      return res.status(401).json({ success: false, message: SAFE_ERRORS.UNAUTHORIZED });
    }

    let mfaValid = false;
    let mfaMethod = 'totp';

    if (useBackupCode) {
      // Verify backup code (creative MFA solution #1)
      const backupResult = validateBackupCode(code);
      if (!backupResult.valid) {
        return res.status(400).json({ success: false, message: backupResult.error });
      }

      if (user.useBackupCode(code)) {
        mfaValid = true;
        mfaMethod = 'backup_code';
        
        await logAuditEvent({
          eventType: 'MFA_BACKUP_CODE_USED',
          userId: user._id,
          username: user.username,
          req,
          action: 'Backup code used for MFA',
          status: 'SUCCESS',
          riskLevel: 'MEDIUM'
        });
      }
    } else {
      // Verify TOTP code
      const totpResult = validateTOTPCode(code);
      if (!totpResult.valid) {
        return res.status(400).json({ success: false, message: totpResult.error });
      }

      if (verifyTOTP(code, user.totpSecret)) {
        mfaValid = true;
      }
    }

    if (!mfaValid) {
      await logAuditEvent({
        eventType: 'MFA_VERIFICATION_FAILURE',
        userId: user._id,
        username: user.username,
        req,
        action: 'Invalid MFA code',
        status: 'FAILURE',
        riskLevel: 'MEDIUM'
      });

      return res.status(401).json({ success: false, message: 'Invalid verification code' });
    }

    // Trust device if requested (creative MFA solution #3)
    if (trustDevice && deviceId && deviceFingerprint) {
      user.addTrustedDevice(deviceId, deviceFingerprint, deviceName || 'Unknown Device');
    }

    // Create session
    const sessionId = user.createSession(req.get('User-Agent'), req.ip);
    user.lastLogin = new Date();
    await user.save({ validateBeforeSave: false });

    const token = generateToken(user._id, { sessionId });

    await logAuditEvent({
      eventType: 'MFA_VERIFICATION_SUCCESS',
      userId: user._id,
      username: user.username,
      req,
      action: `MFA verified via ${mfaMethod}`,
      status: 'SUCCESS'
    });

    res.json({
      success: true,
      token,
      user: user.toSafeObject()
    });
  } catch (error) {
    console.error('MFA verification error:', error.message);
    res.status(500).json({ success: false, message: SAFE_ERRORS.SERVER_ERROR });
  }
});

/**
 * POST /api/auth/verify-email
 * Verify email address
 */
router.post('/verify-email', async (req, res) => {
  try {
    const { token } = req.body;

    if (!token) {
      return res.status(400).json({ success: false, message: 'Verification token is required' });
    }

    const user = await User.findByEmailVerificationToken(token);

    if (!user) {
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid or expired verification token' 
      });
    }

    user.emailVerified = true;
    user.emailVerificationToken = undefined;
    user.emailVerificationExpires = undefined;
    await user.save({ validateBeforeSave: false });

    await logAuditEvent({
      eventType: 'ACCOUNT_EMAIL_VERIFIED',
      userId: user._id,
      username: user.username,
      req,
      action: 'Email verified',
      status: 'SUCCESS'
    });

    res.json({ success: true, message: 'Email verified successfully' });
  } catch (error) {
    console.error('Email verification error:', error.message);
    res.status(500).json({ success: false, message: SAFE_ERRORS.SERVER_ERROR });
  }
});

/**
 * GET /api/auth/me
 * Get current user profile
 */
router.get('/me', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('+totpSecret');
    res.json({
      success: true,
      user: {
        ...user.toSafeObject(),
        mfaEnabled: !!user.totpSecret
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: SAFE_ERRORS.SERVER_ERROR });
  }
});

/**
 * POST /api/auth/enable-mfa
 * Start MFA setup process
 */
router.post('/enable-mfa', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('+totpSecret');

    if (user.totpSecret) {
      return res.status(400).json({ success: false, message: 'MFA is already enabled' });
    }

    const secret = generateSecret();
    const otpAuthUrl = generateOtpAuthUrl(user.username, secret);
    const qrCode = await generateQRCode(otpAuthUrl);

    res.json({
      success: true,
      secret,
      qrCode,
      // Only show current code in development for testing
      currentCode: process.env.NODE_ENV === 'development' ? generateTOTP(secret) : undefined
    });
  } catch (error) {
    console.error('Enable MFA error:', error.message);
    res.status(500).json({ success: false, message: SAFE_ERRORS.SERVER_ERROR });
  }
});

/**
 * POST /api/auth/confirm-mfa
 * Confirm MFA setup and generate backup codes
 */
router.post('/confirm-mfa', authenticate, async (req, res) => {
  try {
    const { secret, code } = req.body;

    if (!secret || !code) {
      return res.status(400).json({ success: false, message: 'Secret and code are required' });
    }

    const codeResult = validateTOTPCode(code);
    if (!codeResult.valid) {
      return res.status(400).json({ success: false, message: codeResult.error });
    }

    if (!verifyTOTP(code, secret)) {
      return res.status(400).json({ success: false, message: 'Invalid code. Please try again.' });
    }

    const user = await User.findById(req.user._id);
    user.totpSecret = secret;
    
    // Generate backup codes (creative MFA solution #1)
    const backupCodes = user.generateBackupCodes();
    
    await user.save({ validateBeforeSave: false });

    await logAuditEvent({
      eventType: 'MFA_ENABLED',
      userId: user._id,
      username: user.username,
      req,
      action: 'MFA enabled',
      status: 'SUCCESS'
    });

    res.json({ 
      success: true, 
      message: 'MFA enabled successfully',
      backupCodes // Show once - user must save these
    });
  } catch (error) {
    console.error('Confirm MFA error:', error.message);
    res.status(500).json({ success: false, message: SAFE_ERRORS.SERVER_ERROR });
  }
});

/**
 * POST /api/auth/disable-mfa
 * Disable MFA (requires current MFA code)
 */
router.post('/disable-mfa', authenticate, mfaRateLimiter, async (req, res) => {
  try {
    const { code } = req.body;
    const user = await User.findById(req.user._id).select('+totpSecret +backupCodes');

    if (!user.totpSecret) {
      return res.status(400).json({ success: false, message: 'MFA is not enabled' });
    }

    const codeResult = validateTOTPCode(code);
    if (!codeResult.valid) {
      return res.status(400).json({ success: false, message: codeResult.error });
    }

    if (!verifyTOTP(code, user.totpSecret)) {
      await logAuditEvent({
        eventType: 'MFA_VERIFICATION_FAILURE',
        userId: user._id,
        username: user.username,
        req,
        action: 'Invalid code while disabling MFA',
        status: 'FAILURE',
        riskLevel: 'MEDIUM'
      });

      return res.status(400).json({ success: false, message: 'Invalid code' });
    }

    user.totpSecret = null;
    user.backupCodes = [];
    user.trustedDevices = [];
    await user.save({ validateBeforeSave: false });

    await logAuditEvent({
      eventType: 'MFA_DISABLED',
      userId: user._id,
      username: user.username,
      req,
      action: 'MFA disabled',
      status: 'SUCCESS',
      riskLevel: 'MEDIUM'
    });

    res.json({ success: true, message: 'MFA disabled successfully' });
  } catch (error) {
    console.error('Disable MFA error:', error.message);
    res.status(500).json({ success: false, message: SAFE_ERRORS.SERVER_ERROR });
  }
});

/**
 * GET /api/auth/security-questions
 * Get available security questions
 */
router.get('/security-questions', (req, res) => {
  res.json({ success: true, questions: SECURITY_QUESTIONS });
});

/**
 * POST /api/auth/setup-security-questions
 * Set up security questions (creative MFA solution #2)
 */
router.post('/setup-security-questions', authenticate, async (req, res) => {
  try {
    const { answers } = req.body; // Array of { questionId, answer }

    if (!answers || !Array.isArray(answers) || answers.length < securityConfig.mfa.securityQuestionsRequired) {
      return res.status(400).json({ 
        success: false, 
        message: `Please answer at least ${securityConfig.mfa.securityQuestionsRequired} security questions` 
      });
    }

    const user = await User.findById(req.user._id).select('+securityQuestions');

    for (const { questionId, answer } of answers) {
      if (!answer || answer.trim().length < 2) {
        return res.status(400).json({ success: false, message: 'All answers must be at least 2 characters' });
      }
      await user.setSecurityQuestionAnswer(questionId, answer);
    }

    await user.save({ validateBeforeSave: false });

    await logAuditEvent({
      eventType: 'SECURITY_CONFIG_CHANGED',
      userId: user._id,
      username: user.username,
      req,
      action: 'Security questions configured',
      status: 'SUCCESS'
    });

    res.json({ success: true, message: 'Security questions configured successfully' });
  } catch (error) {
    console.error('Setup security questions error:', error.message);
    res.status(500).json({ success: false, message: SAFE_ERRORS.SERVER_ERROR });
  }
});

/**
 * POST /api/auth/logout
 * Logout and revoke session - with proper session destruction
 */
router.post('/logout', validateCsrfToken, authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('+sessions');
    
    // Revoke user session from database
    if (req.tokenData?.sessionId) {
      user.revokeSession(req.tokenData.sessionId);
      await user.save({ validateBeforeSave: false });
    }

    // Log account activity
    await logAccountActivity({
      userId: user._id,
      activityType: 'LOGOUT',
      req,
      status: 'SUCCESS',
      details: { sessionId: req.sessionID }
    });

    await logAuditEvent({
      eventType: 'AUTH_LOGOUT',
      userId: user._id,
      username: user.username,
      req,
      action: 'User logged out',
      status: 'SUCCESS'
    });

    // Destroy the express session completely
    try {
      await destroySession(req, res);
    } catch (sessionError) {
      console.error('Session destruction error:', sessionError);
    }

    res.json({ success: true, message: 'Logged out successfully' });
  } catch (error) {
    res.status(500).json({ success: false, message: SAFE_ERRORS.SERVER_ERROR });
  }
});

/**
 * POST /api/auth/logout-all
 * Logout from all devices - revokes all sessions
 */
router.post('/logout-all', validateCsrfToken, authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('+sessions');
    user.revokeAllSessions();
    await user.save({ validateBeforeSave: false });

    // Log account activity
    await logAccountActivity({
      userId: user._id,
      activityType: 'SESSION_REVOKED',
      req,
      status: 'SUCCESS',
      details: { action: 'all_sessions_revoked' }
    });

    await logAuditEvent({
      eventType: 'SESSION_REVOKED',
      userId: user._id,
      username: user.username,
      req,
      action: 'All sessions revoked',
      status: 'SUCCESS',
      riskLevel: 'LOW'
    });

    // Destroy current express session
    try {
      await destroySession(req, res);
    } catch (sessionError) {
      console.error('Session destruction error:', sessionError);
    }

    res.json({ success: true, message: 'Logged out from all devices' });
  } catch (error) {
    res.status(500).json({ success: false, message: SAFE_ERRORS.SERVER_ERROR });
  }
});

/**
 * GET /api/auth/trusted-devices
 * Get list of trusted devices
 */
router.get('/trusted-devices', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('+trustedDevices');
    
    const devices = (user.trustedDevices || []).map(d => ({
      deviceId: d.deviceId,
      name: d.name,
      lastUsed: d.lastUsed,
      createdAt: d.createdAt
    }));

    res.json({ success: true, devices });
  } catch (error) {
    res.status(500).json({ success: false, message: SAFE_ERRORS.SERVER_ERROR });
  }
});

/**
 * DELETE /api/auth/trusted-devices/:deviceId
 * Remove a trusted device
 */
router.delete('/trusted-devices/:deviceId', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('+trustedDevices');
    
    user.trustedDevices = (user.trustedDevices || []).filter(
      d => d.deviceId !== req.params.deviceId
    );
    
    await user.save({ validateBeforeSave: false });

    res.json({ success: true, message: 'Device removed' });
  } catch (error) {
    res.status(500).json({ success: false, message: SAFE_ERRORS.SERVER_ERROR });
  }
});

module.exports = router;
