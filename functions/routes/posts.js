const express = require("express");
const router = express.Router();

const Post = require("../models/Post");
const {protect} = require("../middleware/auth");
const {AppError, asyncHandler} = require("../utils/errors");
const {SAFE_ERRORS} = require("../utils/safeErrors");

router.get("/", asyncHandler(async (req, res) => {
  const posts = await Post.find()
      .populate("user", "username")
      .sort({createdAt: -1});

  res.json({success: true, count: posts.length, posts});
}));

router.get("/my", protect, asyncHandler(async (req, res) => {
  const posts = await Post.find({user: req.user._id}).sort({createdAt: -1});
  res.json({success: true, count: posts.length, posts});
}));

router.get("/:slug", asyncHandler(async (req, res) => {
  const post = await Post.findOne({slug: req.params.slug})
      .populate("user", "username");

  if (!post) {
    throw new AppError(SAFE_ERRORS.NOT_FOUND, 404, "NOT_FOUND");
  }

  res.json({success: true, post});
}));

router.post("/", protect, asyncHandler(async (req, res) => {
  const {title, body} = req.body;

  if (!title || !body) {
    throw new AppError(SAFE_ERRORS.VALIDATION_FAILED, 400, "VALIDATION_ERROR");
  }

  const slug = Post.createSlug(title);
  const post = await Post.create({
    user: req.user._id,
    title,
    slug,
    body,
  });

  res.status(201).json({success: true, post});
}));

router.put("/:id", protect, asyncHandler(async (req, res) => {
  let post = await Post.findById(req.params.id);

  if (!post) {
    throw new AppError(SAFE_ERRORS.NOT_FOUND, 404, "NOT_FOUND");
  }

  const canEdit = post.user.toString() === req.user._id.toString() || req.user.isAdmin;
  if (!canEdit) {
    throw new AppError(SAFE_ERRORS.FORBIDDEN, 403, "FORBIDDEN");
  }

  const {title, body} = req.body;
  if (!title || !body) {
    throw new AppError(SAFE_ERRORS.VALIDATION_FAILED, 400, "VALIDATION_ERROR");
  }

  post = await Post.findByIdAndUpdate(
      req.params.id,
      {title, body, slug: Post.createSlug(title), updatedAt: Date.now()},
      {new: true, runValidators: true},
  );

  res.json({success: true, post});
}));

router.delete("/:id", protect, asyncHandler(async (req, res) => {
  const post = await Post.findById(req.params.id);

  if (!post) {
    throw new AppError(SAFE_ERRORS.NOT_FOUND, 404, "NOT_FOUND");
  }

  const canDelete = post.user.toString() === req.user._id.toString() || req.user.isAdmin;
  if (!canDelete) {
    throw new AppError(SAFE_ERRORS.FORBIDDEN, 403, "FORBIDDEN");
  }

  await post.deleteOne();
  res.json({success: true, message: "Post deleted successfully"});
}));

module.exports = router;
