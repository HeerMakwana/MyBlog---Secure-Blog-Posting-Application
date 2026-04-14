/**
 * Authentication Routes - Secure Implementation
 * Implements: Rate limiting, input validation, audit logging, MFA with backup codes
 */

const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const User = require('../models/User');
const { authenticate, generateToken, getJwtSecret } = require('../middleware/rbac');
const { authRateLimiter, trackLoginAttempt, isAccountLocked } = require('../middleware/rateLimiter');
const { logAuditEvent } = require('../utils/auditLogger');
const { 
  validateEmail, 
  validateUsername, 
  validatePassword, 
  SAFE_ERRORS 
} = require('../utils/validation');
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

const captchaStore = new Map();
const CAPTCHA_TTL_MS = 5 * 60 * 1000;
const CAPTCHA_MAX_ATTEMPTS = 3;

const cleanupCaptchaStore = () => {
  const now = Date.now();
  for (const [id, challenge] of captchaStore.entries()) {
    if (challenge.expiresAt <= now) {
      captchaStore.delete(id);
    }
  }
};

setInterval(cleanupCaptchaStore, 60 * 1000);

const createCaptchaChallenge = () => {
  const a = Math.floor(Math.random() * 9) + 1;
  const b = Math.floor(Math.random() * 9) + 1;
  const operator = Math.random() < 0.5 ? '+' : '-';

  const answer = operator === '+' ? a + b : a - b;
  const captchaId = crypto.randomBytes(16).toString('hex');

  captchaStore.set(captchaId, {
    answer,
    attempts: 0,
    expiresAt: Date.now() + CAPTCHA_TTL_MS
  });

  return {
    captchaId,
    question: `${a} ${operator} ${b} = ?`
  };
};

const verifyCaptchaChallenge = (captchaId, captchaAnswer) => {
  const challenge = captchaStore.get(captchaId);
  if (!challenge) {
    return { valid: false, message: 'Captcha expired. Please try again.' };
  }

  if (challenge.expiresAt <= Date.now()) {
    captchaStore.delete(captchaId);
    return { valid: false, message: 'Captcha expired. Please try again.' };
  }

  challenge.attempts += 1;

  const numericAnswer = Number(captchaAnswer);
  const isValid = Number.isFinite(numericAnswer) &&
    numericAnswer === challenge.answer;

  if (isValid) {
    captchaStore.delete(captchaId);
    return { valid: true };
  }

  if (challenge.attempts >= CAPTCHA_MAX_ATTEMPTS) {
    captchaStore.delete(captchaId);
    return { valid: false, message: 'Captcha expired. Please try again.' };
  }

  return { valid: false, message: 'Incorrect captcha answer' };
};

router.get('/captcha', (req, res) => {
  const challenge = createCaptchaChallenge();
  res.json({ success: true, ...challenge });
});

/**
 * POST /api/auth/register
 * Register a new user with email verification
 */
router.post('/register', authRateLimiter, async (req, res) => {
  try {
    const { username, email, password, captchaId, captchaAnswer } = req.body;

    if (!captchaId || captchaAnswer === undefined || captchaAnswer === null) {
      return res.status(400).json({
        success: false,
        message: 'Captcha is required'
      });
    }

    const captchaResult = verifyCaptchaChallenge(captchaId, captchaAnswer);
    if (!captchaResult.valid) {
      return res.status(400).json({
        success: false,
        message: captchaResult.message
      });
    }

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

    // Generate session token
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
    const { username, password, captchaId, captchaAnswer } = req.body;

    if (!captchaId || captchaAnswer === undefined || captchaAnswer === null) {
      return res.status(400).json({
        success: false,
        message: 'Captcha is required'
      });
    }

    const captchaResult = verifyCaptchaChallenge(captchaId, captchaAnswer);
    if (!captchaResult.valid) {
      return res.status(400).json({
        success: false,
        message: captchaResult.message
      });
    }

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

    // Create session
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
 * MFA removed from this project
 */
router.post('/verify-mfa', (req, res) => {
  res.status(410).json({
    success: false,
    message: 'MFA has been removed from this application'
  });
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
    const user = await User.findById(req.user._id);
    res.json({
      success: true,
      user: {
        ...user.toSafeObject(),
        mfaEnabled: false
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
  res.status(410).json({
    success: false,
    message: 'MFA has been removed from this application'
  });
});

/**
 * POST /api/auth/confirm-mfa
 * Confirm MFA setup and generate backup codes
 */
router.post('/confirm-mfa', authenticate, async (req, res) => {
  res.status(410).json({
    success: false,
    message: 'MFA has been removed from this application'
  });
});

/**
 * POST /api/auth/disable-mfa
 * Disable MFA (requires current MFA code)
 */
router.post('/disable-mfa', authenticate, async (req, res) => {
  res.status(410).json({
    success: false,
    message: 'MFA has been removed from this application'
  });
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
 * Logout and revoke session
 */
router.post('/logout', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('+sessions');
    
    if (req.tokenData?.sessionId) {
      user.revokeSession(req.tokenData.sessionId);
      await user.save({ validateBeforeSave: false });
    }

    await logAuditEvent({
      eventType: 'AUTH_LOGOUT',
      userId: user._id,
      username: user.username,
      req,
      action: 'User logged out',
      status: 'SUCCESS'
    });

    res.json({ success: true, message: 'Logged out successfully' });
  } catch (error) {
    res.status(500).json({ success: false, message: SAFE_ERRORS.SERVER_ERROR });
  }
});

/**
 * POST /api/auth/logout-all
 * Logout from all devices
 */
router.post('/logout-all', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('+sessions');
    user.revokeAllSessions();
    await user.save({ validateBeforeSave: false });

    await logAuditEvent({
      eventType: 'SESSION_REVOKED',
      userId: user._id,
      username: user.username,
      req,
      action: 'All sessions revoked',
      status: 'SUCCESS',
      riskLevel: 'LOW'
    });

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
