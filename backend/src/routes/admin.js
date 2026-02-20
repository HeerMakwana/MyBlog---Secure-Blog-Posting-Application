/**
 * Admin Routes - Secure Implementation
 * Implements: RBAC with ADMINISTRATOR role, audit logging, input validation
 */

const express = require('express');
const router = express.Router();
const User = require('../models/User');
const Post = require('../models/Post');
const { authenticate, requireRole, requirePermission } = require('../middleware/rbac');
const { ROLES, PERMISSIONS, isValidRole } = require('../config/roles');
const { logAuditEvent, getAuditLogs } = require('../utils/auditLogger');
const { validateObjectId, SAFE_ERRORS } = require('../utils/validation');

// All admin routes require authentication and ADMINISTRATOR role
router.use(authenticate, requireRole(ROLES.ADMINISTRATOR));

/**
 * GET /api/admin/users
 * Get all users (admin only)
 */
router.get('/users', requirePermission(PERMISSIONS.VIEW_ALL_USERS), async (req, res) => {
  try {
    const users = await User.find()
      .select('-password -totpSecret -backupCodes -securityQuestions')
      .sort({ createdAt: -1 });

    const safeUsers = users.map(u => ({
      id: u._id,
      username: u.username,
      email: u.email,
      role: u.role,
      isAdmin: u.isAdmin,
      emailVerified: u.emailVerified,
      isLocked: u.isLocked,
      mfaEnabled: !!u.totpSecret,
      createdAt: u.createdAt,
      lastLogin: u.lastLogin
    }));

    res.json({ success: true, count: safeUsers.length, users: safeUsers });
  } catch (error) {
    console.error('Admin get users error:', error.message);
    res.status(500).json({ success: false, message: SAFE_ERRORS.SERVER_ERROR });
  }
});

/**
 * PUT /api/admin/users/:id/role
 * Change a user's role (admin only)
 */
router.put('/users/:id/role', requirePermission(PERMISSIONS.CHANGE_USER_ROLE), async (req, res) => {
  try {
    const { role } = req.body;

    // Validate ID
    const idResult = validateObjectId(req.params.id);
    if (!idResult.valid) {
      return res.status(400).json({ success: false, message: idResult.error });
    }

    // Validate role
    if (!isValidRole(role)) {
      return res.status(400).json({ success: false, message: 'Invalid role specified' });
    }

    // Prevent self-demotion
    if (req.params.id === req.user._id.toString()) {
      return res.status(400).json({ success: false, message: 'Cannot change your own role' });
    }

    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ success: false, message: SAFE_ERRORS.NOT_FOUND });
    }

    const previousRole = user.role;
    user.role = role;
    await user.save({ validateBeforeSave: false });

    await logAuditEvent({
      eventType: 'ROLE_CHANGED',
      userId: req.user._id,
      username: req.user.username,
      req,
      resourceType: 'User',
      resourceId: user._id.toString(),
      action: `Role changed from ${previousRole} to ${role}`,
      status: 'SUCCESS',
      details: { targetUser: user.username, previousRole, newRole: role },
      riskLevel: 'HIGH'
    });

    res.json({ 
      success: true, 
      message: `User role updated to ${role}`,
      user: {
        id: user._id,
        username: user.username,
        role: user.role
      }
    });
  } catch (error) {
    console.error('Admin change role error:', error.message);
    res.status(500).json({ success: false, message: SAFE_ERRORS.SERVER_ERROR });
  }
});

/**
 * PUT /api/admin/users/:id/lock
 * Lock a user account (admin only)
 */
router.put('/users/:id/lock', requirePermission(PERMISSIONS.EDIT_ANY_USER), async (req, res) => {
  try {
    const { reason } = req.body;

    const idResult = validateObjectId(req.params.id);
    if (!idResult.valid) {
      return res.status(400).json({ success: false, message: idResult.error });
    }

    if (req.params.id === req.user._id.toString()) {
      return res.status(400).json({ success: false, message: 'Cannot lock your own account' });
    }

    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ success: false, message: SAFE_ERRORS.NOT_FOUND });
    }

    user.lockAccount(reason || 'Locked by administrator');
    user.revokeAllSessions(); // Force logout
    await user.save({ validateBeforeSave: false });

    await logAuditEvent({
      eventType: 'ACCOUNT_LOCKED',
      userId: req.user._id,
      username: req.user.username,
      req,
      resourceType: 'User',
      resourceId: user._id.toString(),
      action: 'Account locked by admin',
      status: 'SUCCESS',
      details: { targetUser: user.username, reason },
      riskLevel: 'HIGH'
    });

    res.json({ success: true, message: 'User account locked' });
  } catch (error) {
    console.error('Admin lock user error:', error.message);
    res.status(500).json({ success: false, message: SAFE_ERRORS.SERVER_ERROR });
  }
});

/**
 * PUT /api/admin/users/:id/unlock
 * Unlock a user account (admin only)
 */
router.put('/users/:id/unlock', requirePermission(PERMISSIONS.EDIT_ANY_USER), async (req, res) => {
  try {
    const idResult = validateObjectId(req.params.id);
    if (!idResult.valid) {
      return res.status(400).json({ success: false, message: idResult.error });
    }

    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ success: false, message: SAFE_ERRORS.NOT_FOUND });
    }

    user.unlockAccount();
    await user.save({ validateBeforeSave: false });

    await logAuditEvent({
      eventType: 'ACCOUNT_UNLOCKED',
      userId: req.user._id,
      username: req.user.username,
      req,
      resourceType: 'User',
      resourceId: user._id.toString(),
      action: 'Account unlocked by admin',
      status: 'SUCCESS',
      details: { targetUser: user.username },
      riskLevel: 'MEDIUM'
    });

    res.json({ success: true, message: 'User account unlocked' });
  } catch (error) {
    console.error('Admin unlock user error:', error.message);
    res.status(500).json({ success: false, message: SAFE_ERRORS.SERVER_ERROR });
  }
});

/**
 * DELETE /api/admin/users/:id
 * Delete a user and their posts (admin only)
 */
router.delete('/users/:id', requirePermission(PERMISSIONS.DELETE_ANY_USER), async (req, res) => {
  try {
    const idResult = validateObjectId(req.params.id);
    if (!idResult.valid) {
      return res.status(400).json({ success: false, message: idResult.error });
    }

    if (req.params.id === req.user._id.toString()) {
      return res.status(400).json({ success: false, message: 'Cannot delete your own account' });
    }

    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ success: false, message: SAFE_ERRORS.NOT_FOUND });
    }

    // Delete user's posts
    const deletedPosts = await Post.deleteMany({ user: user._id });
    await user.deleteOne();

    await logAuditEvent({
      eventType: 'USER_DELETED',
      userId: req.user._id,
      username: req.user.username,
      req,
      resourceType: 'User',
      resourceId: req.params.id,
      action: 'User deleted by admin',
      status: 'SUCCESS',
      details: { 
        deletedUser: user.username, 
        postsDeleted: deletedPosts.deletedCount 
      },
      riskLevel: 'HIGH'
    });

    res.json({ success: true, message: 'User and their posts deleted successfully' });
  } catch (error) {
    console.error('Admin delete user error:', error.message);
    res.status(500).json({ success: false, message: SAFE_ERRORS.SERVER_ERROR });
  }
});

/**
 * GET /api/admin/posts
 * Get all posts (admin only)
 */
router.get('/posts', requirePermission(PERMISSIONS.VIEW_ALL_POSTS), async (req, res) => {
  try {
    const posts = await Post.find()
      .populate('user', 'username')
      .sort({ createdAt: -1 });

    res.json({ success: true, count: posts.length, posts });
  } catch (error) {
    console.error('Admin get posts error:', error.message);
    res.status(500).json({ success: false, message: SAFE_ERRORS.SERVER_ERROR });
  }
});

/**
 * DELETE /api/admin/posts/:id
 * Delete any post (admin only)
 */
router.delete('/posts/:id', requirePermission(PERMISSIONS.DELETE_ANY_POST), async (req, res) => {
  try {
    const idResult = validateObjectId(req.params.id);
    if (!idResult.valid) {
      return res.status(400).json({ success: false, message: idResult.error });
    }

    const post = await Post.findById(req.params.id);
    if (!post) {
      return res.status(404).json({ success: false, message: SAFE_ERRORS.NOT_FOUND });
    }

    await post.deleteOne();

    await logAuditEvent({
      eventType: 'POST_DELETED',
      userId: req.user._id,
      username: req.user.username,
      req,
      resourceType: 'Post',
      resourceId: req.params.id,
      action: 'Post deleted by admin',
      status: 'SUCCESS',
      details: { postTitle: post.title }
    });

    res.json({ success: true, message: 'Post deleted successfully' });
  } catch (error) {
    console.error('Admin delete post error:', error.message);
    res.status(500).json({ success: false, message: SAFE_ERRORS.SERVER_ERROR });
  }
});

/**
 * GET /api/admin/stats
 * Get system statistics (admin only)
 */
router.get('/stats', requirePermission(PERMISSIONS.VIEW_ADMIN_STATS), async (req, res) => {
  try {
    const [userCount, postCount, recentUsers, recentPosts, roleDistribution] = await Promise.all([
      User.countDocuments(),
      Post.countDocuments(),
      User.find()
        .select('username email role createdAt')
        .sort({ createdAt: -1 })
        .limit(5),
      Post.find()
        .populate('user', 'username')
        .sort({ createdAt: -1 })
        .limit(5),
      User.aggregate([
        { $group: { _id: '$role', count: { $sum: 1 } } }
      ])
    ]);

    res.json({
      success: true,
      stats: {
        totalUsers: userCount,
        totalPosts: postCount,
        roleDistribution: roleDistribution.reduce((acc, r) => {
          acc[r._id] = r.count;
          return acc;
        }, {}),
        recentUsers,
        recentPosts
      }
    });
  } catch (error) {
    console.error('Admin stats error:', error.message);
    res.status(500).json({ success: false, message: SAFE_ERRORS.SERVER_ERROR });
  }
});

/**
 * GET /api/admin/audit-logs
 * Get security audit logs (admin only)
 */
router.get('/audit-logs', requirePermission(PERMISSIONS.VIEW_AUDIT_LOGS), async (req, res) => {
  try {
    const { 
      eventType, 
      userId, 
      status, 
      riskLevel, 
      startDate, 
      endDate,
      page = 1,
      limit = 50 
    } = req.query;

    const result = await getAuditLogs(
      { eventType, userId, status, riskLevel, startDate, endDate },
      { page: parseInt(page), limit: parseInt(limit) }
    );

    res.json({ success: true, ...result });
  } catch (error) {
    console.error('Admin audit logs error:', error.message);
    res.status(500).json({ success: false, message: SAFE_ERRORS.SERVER_ERROR });
  }
});

/**
 * GET /api/admin/roles
 * Get available roles and permissions
 */
router.get('/roles', async (req, res) => {
  res.json({
    success: true,
    roles: Object.values(ROLES),
    permissions: Object.values(PERMISSIONS)
  });
});

module.exports = router;
