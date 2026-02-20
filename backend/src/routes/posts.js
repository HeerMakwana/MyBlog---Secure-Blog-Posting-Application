/**
 * Posts Routes - Secure Implementation
 * Implements: RBAC, input validation, audit logging, ownership checks
 */

const express = require('express');
const router = express.Router();
const Post = require('../models/Post');
const { authenticate, optionalAuth, requirePermission, requireOwnership } = require('../middleware/rbac');
const { PERMISSIONS } = require('../config/roles');
const { logAuditEvent } = require('../utils/auditLogger');
const { validatePostTitle, validatePostBody, validateObjectId, SAFE_ERRORS } = require('../utils/validation');

/**
 * GET /api/posts
 * Get all public posts (accessible to all including guests)
 */
router.get('/', optionalAuth, async (req, res) => {
  try {
    const posts = await Post.find()
      .populate('user', 'username')
      .sort({ createdAt: -1 });

    res.json({ success: true, count: posts.length, posts });
  } catch (error) {
    console.error('Get posts error:', error.message);
    res.status(500).json({ success: false, message: SAFE_ERRORS.SERVER_ERROR });
  }
});

/**
 * GET /api/posts/my
 * Get current user's posts (requires EDITOR role or above)
 */
router.get('/my', authenticate, requirePermission(PERMISSIONS.VIEW_OWN_POSTS), async (req, res) => {
  try {
    const posts = await Post.find({ user: req.user._id })
      .sort({ createdAt: -1 });

    res.json({ success: true, count: posts.length, posts });
  } catch (error) {
    console.error('Get my posts error:', error.message);
    res.status(500).json({ success: false, message: SAFE_ERRORS.SERVER_ERROR });
  }
});

/**
 * GET /api/posts/:slug
 * Get a single post by slug (public)
 */
router.get('/:slug', optionalAuth, async (req, res) => {
  try {
    const post = await Post.findOne({ slug: req.params.slug })
      .populate('user', 'username');

    if (!post) {
      return res.status(404).json({ success: false, message: SAFE_ERRORS.NOT_FOUND });
    }

    res.json({ success: true, post });
  } catch (error) {
    console.error('Get post error:', error.message);
    res.status(500).json({ success: false, message: SAFE_ERRORS.SERVER_ERROR });
  }
});

/**
 * POST /api/posts
 * Create a new post (requires EDITOR role or above)
 */
router.post('/', authenticate, requirePermission(PERMISSIONS.CREATE_POST), async (req, res) => {
  try {
    const { title, body } = req.body;

    // Input validation
    const titleResult = validatePostTitle(title);
    if (!titleResult.valid) {
      return res.status(400).json({ success: false, message: titleResult.error });
    }

    const bodyResult = validatePostBody(body);
    if (!bodyResult.valid) {
      return res.status(400).json({ success: false, message: bodyResult.error });
    }

    const slug = Post.createSlug(titleResult.value);

    const post = await Post.create({
      user: req.user._id,
      title: titleResult.value,
      slug,
      body: bodyResult.value
    });

    await logAuditEvent({
      eventType: 'POST_CREATED',
      userId: req.user._id,
      username: req.user.username,
      req,
      resourceType: 'Post',
      resourceId: post._id.toString(),
      action: 'Post created',
      status: 'SUCCESS'
    });

    res.status(201).json({ success: true, post });
  } catch (error) {
    console.error('Create post error:', error.message);
    res.status(400).json({ success: false, message: SAFE_ERRORS.VALIDATION_FAILED });
  }
});

/**
 * PUT /api/posts/:id
 * Update a post (owner or admin only)
 */
router.put('/:id', 
  authenticate,
  async (req, res, next) => {
    // Validate ID format first
    const idResult = validateObjectId(req.params.id);
    if (!idResult.valid) {
      return res.status(400).json({ success: false, message: idResult.error });
    }
    next();
  },
  requireOwnership(async (req) => {
    const post = await Post.findById(req.params.id);
    if (!post) return null;
    req.post = post; // Cache for later use
    return post.user;
  }),
  async (req, res) => {
    try {
      const { title, body } = req.body;

      // Input validation
      const titleResult = validatePostTitle(title);
      if (!titleResult.valid) {
        return res.status(400).json({ success: false, message: titleResult.error });
      }

      const bodyResult = validatePostBody(body);
      if (!bodyResult.valid) {
        return res.status(400).json({ success: false, message: bodyResult.error });
      }

      const slug = Post.createSlug(titleResult.value);

      const post = await Post.findByIdAndUpdate(
        req.params.id,
        { 
          title: titleResult.value, 
          slug, 
          body: bodyResult.value, 
          updatedAt: Date.now() 
        },
        { new: true, runValidators: true }
      );

      await logAuditEvent({
        eventType: 'POST_UPDATED',
        userId: req.user._id,
        username: req.user.username,
        req,
        resourceType: 'Post',
        resourceId: post._id.toString(),
        action: req.isAdmin ? 'Post updated by admin' : 'Post updated by owner',
        status: 'SUCCESS'
      });

      res.json({ success: true, post });
    } catch (error) {
      console.error('Update post error:', error.message);
      res.status(400).json({ success: false, message: SAFE_ERRORS.VALIDATION_FAILED });
    }
  }
);

/**
 * DELETE /api/posts/:id
 * Delete a post (owner or admin only)
 */
router.delete('/:id',
  authenticate,
  async (req, res, next) => {
    const idResult = validateObjectId(req.params.id);
    if (!idResult.valid) {
      return res.status(400).json({ success: false, message: idResult.error });
    }
    next();
  },
  requireOwnership(async (req) => {
    const post = await Post.findById(req.params.id);
    if (!post) return null;
    req.post = post;
    return post.user;
  }),
  async (req, res) => {
    try {
      await req.post.deleteOne();

      await logAuditEvent({
        eventType: 'POST_DELETED',
        userId: req.user._id,
        username: req.user.username,
        req,
        resourceType: 'Post',
        resourceId: req.params.id,
        action: req.isAdmin ? 'Post deleted by admin' : 'Post deleted by owner',
        status: 'SUCCESS'
      });

      res.json({ success: true, message: 'Post deleted successfully' });
    } catch (error) {
      console.error('Delete post error:', error.message);
      res.status(500).json({ success: false, message: SAFE_ERRORS.SERVER_ERROR });
    }
  }
);

module.exports = router;
