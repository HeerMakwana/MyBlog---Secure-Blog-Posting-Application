const express = require("express");
const bcrypt = require("bcryptjs");
const router = express.Router();

const User = require("../models/User");
const {protect} = require("../middleware/auth");
const {AppError, asyncHandler} = require("../utils/errors");
const {SAFE_ERRORS} = require("../utils/safeErrors");

router.put("/profile", protect, asyncHandler(async (req, res) => {
  const {username, email, currentPassword, newPassword} = req.body;

  if (!username || !email) {
    throw new AppError(SAFE_ERRORS.VALIDATION_FAILED, 400, "VALIDATION_ERROR");
  }

  const existingUser = await User.findOne({
    $and: [
      {_id: {$ne: req.user._id}},
      {$or: [{username}, {email}]},
    ],
  });

  if (existingUser) {
    throw new AppError(SAFE_ERRORS.VALIDATION_FAILED, 400, "PROFILE_CONFLICT");
  }

  const updateData = {username, email};

  if (newPassword) {
    if (!currentPassword || newPassword.length < 8) {
      throw new AppError(SAFE_ERRORS.VALIDATION_FAILED, 400, "VALIDATION_ERROR");
    }

    const user = await User.findById(req.user._id).select("+password");
    if (!user || !(await user.comparePassword(currentPassword))) {
      throw new AppError(SAFE_ERRORS.INVALID_CREDENTIALS, 401, "INVALID_CREDENTIALS");
    }

    updateData.password = await bcrypt.hash(newPassword, 12);
  }

  const user = await User.findByIdAndUpdate(
      req.user._id,
      updateData,
      {new: true, runValidators: true},
  );

  if (!user) {
    throw new AppError(SAFE_ERRORS.NOT_FOUND, 404, "NOT_FOUND");
  }

  res.json({
    success: true,
    message: "Profile updated successfully",
    user: {
      id: user._id,
      username: user.username,
      email: user.email,
      isAdmin: user.isAdmin,
      createdAt: user.createdAt,
    },
  });
}));

router.get("/profile", protect, asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id).select("+totpSecret");

  if (!user) {
    throw new AppError(SAFE_ERRORS.NOT_FOUND, 404, "NOT_FOUND");
  }

  res.json({
    success: true,
    user: {
      id: user._id,
      username: user.username,
      email: user.email,
      isAdmin: user.isAdmin,
      mfaEnabled: !!user.totpSecret,
      createdAt: user.createdAt,
    },
  });
}));

module.exports = router;
