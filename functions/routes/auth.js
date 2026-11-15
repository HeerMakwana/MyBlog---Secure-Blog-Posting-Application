const express = require("express");
const router = express.Router();

const User = require("../models/User");
const {protect, generateToken} = require("../middleware/auth");
const {AppError, asyncHandler} = require("../utils/errors");
const {SAFE_ERRORS} = require("../utils/safeErrors");
const {validatePasswordPolicy} = require("../utils/passwordPolicy");
const {authRateLimiter} = require("../middleware/rateLimiter");

const INJECTION_PATTERNS = [
  /('|\"|;|--|\/\*|\*\/|\bOR\b|\bAND\b|\bUNION\b|\bSELECT\b|\bDROP\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b)/i,
  /\b1\s*=\s*1\b/i,
];

const containsInjectionPattern = (value) => (
  typeof value === "string" && INJECTION_PATTERNS.some((pattern) => pattern.test(value))
);

router.post("/register", authRateLimiter, asyncHandler(async (req, res) => {
  const {username, email, password} = req.body;

  if (!username || !email || !password) {
    throw new AppError(SAFE_ERRORS.VALIDATION_FAILED, 400, "VALIDATION_ERROR");
  }

  if (containsInjectionPattern(username) || containsInjectionPattern(email)) {
    throw new AppError("Invalid input detected", 400, "INVALID_INPUT");
  }

  const passwordPolicyResult = validatePasswordPolicy(password);
  if (!passwordPolicyResult.valid) {
    throw new AppError(SAFE_ERRORS.VALIDATION_FAILED, 400, "WEAK_PASSWORD");
  }

  const existingUser = await User.findOne({
    $or: [{email}, {username}],
  });

  if (existingUser) {
    throw new AppError(SAFE_ERRORS.REGISTRATION_FAILED, 400, "REGISTRATION_FAILED");
  }

  const user = await User.create({username, email, password});
  const token = generateToken(user._id);

  res.status(201).json({
    success: true,
    token,
    user: {
      id: user._id,
      username: user.username,
      email: user.email,
      isAdmin: user.isAdmin,
    },
  });
}));

router.post("/login", authRateLimiter, asyncHandler(async (req, res) => {
  const {username, password} = req.body;

  if (!username || !password) {
    throw new AppError(SAFE_ERRORS.INVALID_CREDENTIALS, 401, "INVALID_CREDENTIALS");
  }

  const user = await User.findOne({username})
      .select("+password +failedLoginAttempts +lockedUntil");

  await new Promise((resolve) => setTimeout(resolve, 75));

  if (user && user.isAccountLocked()) {
    throw new AppError(SAFE_ERRORS.ACCOUNT_LOCKED, 423, "ACCOUNT_LOCKED");
  }

  if (!user) {
    throw new AppError(SAFE_ERRORS.INVALID_CREDENTIALS, 401, "INVALID_CREDENTIALS");
  }

  const passwordMatches = await user.comparePassword(password);
  if (!passwordMatches) {
    user.recordFailedLogin(5, 15);
    await user.save({validateBeforeSave: false});

    if (user.isAccountLocked()) {
      throw new AppError(SAFE_ERRORS.ACCOUNT_LOCKED, 423, "ACCOUNT_LOCKED");
    }

    throw new AppError(SAFE_ERRORS.INVALID_CREDENTIALS, 401, "INVALID_CREDENTIALS");
  }

  user.clearFailedLogins();
  await user.save({validateBeforeSave: false});

  const token = generateToken(user._id);

  return res.json({
    success: true,
    token,
    user: {
      id: user._id,
      username: user.username,
      email: user.email,
      isAdmin: user.isAdmin,
    },
  });
}));

router.post("/verify-mfa", asyncHandler(async (req, res) => {
  res.status(410).json({
    success: false,
    message: "MFA has been removed from this application",
  });
}));

router.get("/me", protect, asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id);
  if (!user) {
    throw new AppError(SAFE_ERRORS.UNAUTHORIZED, 401, "UNAUTHORIZED");
  }

  res.json({
    success: true,
    user: {
      id: user._id,
      username: user.username,
      email: user.email,
      isAdmin: user.isAdmin,
      mfaEnabled: false,
      createdAt: user.createdAt,
    },
  });
}));

router.post("/enable-mfa", protect, asyncHandler(async (req, res) => {
  res.status(410).json({
    success: false,
    message: "MFA has been removed from this application",
  });
}));

router.post("/confirm-mfa", protect, asyncHandler(async (req, res) => {
  res.status(410).json({
    success: false,
    message: "MFA has been removed from this application",
  });
}));

router.post("/disable-mfa", protect, asyncHandler(async (req, res) => {
  res.status(410).json({
    success: false,
    message: "MFA has been removed from this application",
  });
}));

module.exports = router;
