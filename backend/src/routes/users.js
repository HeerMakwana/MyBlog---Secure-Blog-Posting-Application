/**
 * User Profile Routes - Secure Implementation
 * Implements: RBAC, input validation, audit logging, account activity
 */

const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const User = require('../models/User');
const { authenticate, requirePermission } = require('../middleware/rbac');
const { PERMISSIONS } = require('../config/roles');
const { logAuditEvent } = require('../utils/auditLogger');
const { getAccountActivity, getSecuritySummary, logAccountActivity } = require('../utils/accountActivity');
const { validateEmail, validateUsername, validatePassword, SAFE_ERRORS } = require('../utils/validation');

/**
 * GET /api/users/profile
 * Get current user's profile
 */
router.get('/profile', authenticate, requirePermission(PERMISSIONS.VIEW_OWN_PROFILE), async (req, res) => {
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
    console.error('Get profile error:', error.message);
    res.status(500).json({ success: false, message: SAFE_ERRORS.SERVER_ERROR });
  }
});

/**
 * PUT /api/users/profile
 * Update current user's profile
 */
router.put('/profile', authenticate, requirePermission(PERMISSIONS.EDIT_OWN_PROFILE), async (req, res) => {
  try {
    const { username, email, currentPassword, newPassword } = req.body;

    // Input validation
    const usernameResult = validateUsername(username);
    if (!usernameResult.valid) {
      return res.status(400).json({ success: false, message: usernameResult.error });
    }

    const emailResult = validateEmail(email);
    if (!emailResult.valid) {
      return res.status(400).json({ success: false, message: emailResult.error });
    }

    // Check for existing user with same username/email
    const existingUser = await User.findOne({
      $and: [
        { _id: { $ne: req.user._id } },
        { $or: [{ username: usernameResult.value }, { email: emailResult.value }] }
      ]
    });

    if (existingUser) {
      return res.status(400).json({ success: false, message: 'Username or email already taken' });
    }

    const updateData = { 
      username: usernameResult.value, 
      email: emailResult.value 
    };

    // Password change
    if (newPassword) {
      if (!currentPassword) {
        return res.status(400).json({ 
          success: false, 
          message: 'Current password is required to change password' 
        });
      }

      // Validate new password strength
      const passwordResult = validatePassword(newPassword);
      if (!passwordResult.valid) {
        return res.status(400).json({ success: false, message: passwordResult.error });
      }

      // Verify current password
      const user = await User.findById(req.user._id).select('+password');
      const isMatch = await user.comparePassword(currentPassword);

      if (!isMatch) {
        await logAuditEvent({
          eventType: 'AUTH_PASSWORD_CHANGE',
          userId: req.user._id,
          username: req.user.username,
          req,
          action: 'Password change failed - wrong current password',
          status: 'FAILURE',
          riskLevel: 'MEDIUM'
        });

        return res.status(400).json({ success: false, message: 'Current password is incorrect' });
      }

      updateData.password = await bcrypt.hash(newPassword, 12);
      updateData.lastPasswordChange = new Date();
    }

    const user = await User.findByIdAndUpdate(
      req.user._id,
      updateData,
      { new: true, runValidators: true }
    );

    await logAuditEvent({
      eventType: 'USER_UPDATED',
      userId: user._id,
      username: user.username,
      req,
      action: newPassword ? 'Profile and password updated' : 'Profile updated',
      status: 'SUCCESS',
      details: { fieldsUpdated: Object.keys(updateData).filter(k => k !== 'password') }
    });

    res.json({
      success: true,
      message: 'Profile updated successfully',
      user: user.toSafeObject()
    });
  } catch (error) {
    console.error('Update profile error:', error.message);
    res.status(400).json({ success: false, message: SAFE_ERRORS.VALIDATION_FAILED });
  }
});

/**
 * GET /api/users/sessions
 * Get active sessions for current user
 */
router.get('/sessions', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('+sessions');
    
    const activeSessions = (user.sessions || [])
      .filter(s => !s.revokedAt)
      .map(s => ({
        sessionId: s.sessionId,
        userAgent: s.userAgent,
        ipAddress: s.ipAddress,
        createdAt: s.createdAt,
        lastActivity: s.lastActivity,
        isCurrent: s.sessionId === req.tokenData?.sessionId
      }));

    res.json({ success: true, sessions: activeSessions });
  } catch (error) {
    console.error('Get sessions error:', error.message);
    res.status(500).json({ success: false, message: SAFE_ERRORS.SERVER_ERROR });
  }
});

/**
 * DELETE /api/users/sessions/:sessionId
 * Revoke a specific session
 */
router.delete('/sessions/:sessionId', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('+sessions');
    
    const revoked = user.revokeSession(req.params.sessionId);
    if (!revoked) {
      return res.status(404).json({ success: false, message: 'Session not found' });
    }
    
    await user.save({ validateBeforeSave: false });

    await logAuditEvent({
      eventType: 'SESSION_REVOKED',
      userId: user._id,
      username: user.username,
      req,
      action: 'Session revoked',
      status: 'SUCCESS'
    });

    res.json({ success: true, message: 'Session revoked' });
  } catch (error) {
    console.error('Revoke session error:', error.message);
    res.status(500).json({ success: false, message: SAFE_ERRORS.SERVER_ERROR });
  }
});

/**
 * GET /api/users/activity
 * Get account activity log for current user
 */
router.get('/activity', authenticate, async (req, res) => {
  try {
    const { page = 1, limit = 20, type } = req.query;
    
    const options = {
      page: parseInt(page, 10),
      limit: Math.min(parseInt(limit, 10) || 20, 100), // Max 100 per page
      activityTypes: type ? type.split(',') : null
    };
    
    const result = await getAccountActivity(req.user._id, options);
    
    res.json({
      success: true,
      activities: result.activities,
      pagination: result.pagination
    });
  } catch (error) {
    console.error('Get activity error:', error.message);
    res.status(500).json({ success: false, message: SAFE_ERRORS.SERVER_ERROR });
  }
});

/**
 * GET /api/users/security-summary
 * Get security summary for current user
 */
router.get('/security-summary', authenticate, async (req, res) => {
  try {
    const summary = await getSecuritySummary(req.user._id);
    
    // Get MFA status
    const user = await User.findById(req.user._id).select('+totpSecret +backupCodes');
    
    res.json({
      success: true,
      security: {
        ...summary,
        mfaEnabled: !!user.totpSecret,
        backupCodesAvailable: user.backupCodes?.filter(c => !c.used).length || 0
      }
    });
  } catch (error) {
    console.error('Get security summary error:', error.message);
    res.status(500).json({ success: false, message: SAFE_ERRORS.SERVER_ERROR });
  }
});

module.exports = router;
