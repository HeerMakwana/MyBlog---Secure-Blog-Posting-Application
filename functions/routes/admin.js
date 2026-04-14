const express = require("express");
const router = express.Router();

const User = require("../models/User");
const Post = require("../models/Post");
const {protect, adminOnly} = require("../middleware/auth");
const {AppError, asyncHandler} = require("../utils/errors");
const {SAFE_ERRORS} = require("../utils/safeErrors");

router.use(protect, adminOnly);

router.get("/users", asyncHandler(async (req, res) => {
  const users = await User.find()
      .select("-password -totpSecret")
      .sort({createdAt: -1});

  res.json({success: true, count: users.length, users});
}));

router.delete("/users/:id", asyncHandler(async (req, res) => {
  const user = await User.findById(req.params.id);

  if (!user) {
    throw new AppError(SAFE_ERRORS.NOT_FOUND, 404, "NOT_FOUND");
  }

  if (user._id.toString() === req.user._id.toString()) {
    throw new AppError(SAFE_ERRORS.FORBIDDEN, 403, "FORBIDDEN");
  }

  await Post.deleteMany({user: user._id});
  await user.deleteOne();

  res.json({success: true, message: "User and posts deleted successfully"});
}));

router.get("/posts", asyncHandler(async (req, res) => {
  const posts = await Post.find()
      .populate("user", "username")
      .sort({createdAt: -1});

  res.json({success: true, count: posts.length, posts});
}));

router.delete("/posts/:id", asyncHandler(async (req, res) => {
  const post = await Post.findById(req.params.id);

  if (!post) {
    throw new AppError(SAFE_ERRORS.NOT_FOUND, 404, "NOT_FOUND");
  }

  await post.deleteOne();
  res.json({success: true, message: "Post deleted successfully"});
}));

router.get("/stats", asyncHandler(async (req, res) => {
  const [userCount, postCount, recentUsers, recentPosts] = await Promise.all([
    User.countDocuments(),
    Post.countDocuments(),
    User.find().select("-password -totpSecret").sort({createdAt: -1}).limit(5),
    Post.find().populate("user", "username").sort({createdAt: -1}).limit(5),
  ]);

  res.json({
    success: true,
    stats: {
      totalUsers: userCount,
      totalPosts: postCount,
      recentUsers,
      recentPosts,
    },
  });
}));

module.exports = router;
