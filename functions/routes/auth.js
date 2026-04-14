const express = require("express");
const crypto = require("crypto");
const router = express.Router();

const User = require("../models/User");
const {protect, generateToken} = require("../middleware/auth");
const {AppError, asyncHandler} = require("../utils/errors");
const {SAFE_ERRORS} = require("../utils/safeErrors");
const {validatePasswordPolicy} = require("../utils/passwordPolicy");
const {authRateLimiter} = require("../middleware/rateLimiter");

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
  const operator = Math.random() < 0.5 ? "+" : "-";

  const answer = operator === "+" ? a + b : a - b;
  const captchaId = crypto.randomBytes(16).toString("hex");

  captchaStore.set(captchaId, {
    answer,
    attempts: 0,
    expiresAt: Date.now() + CAPTCHA_TTL_MS,
  });

  return {
    captchaId,
    question: `${a} ${operator} ${b} = ?`,
  };
};

const verifyCaptchaChallenge = (captchaId, captchaAnswer) => {
  const challenge = captchaStore.get(captchaId);
  if (!challenge) {
    return {valid: false, message: "Captcha expired. Please try again."};
  }

  if (challenge.expiresAt <= Date.now()) {
    captchaStore.delete(captchaId);
    return {valid: false, message: "Captcha expired. Please try again."};
  }

  challenge.attempts += 1;

  const numericAnswer = Number(captchaAnswer);
  const isValid = Number.isFinite(numericAnswer) &&
    numericAnswer === challenge.answer;

  if (isValid) {
    captchaStore.delete(captchaId);
    return {valid: true};
  }

  if (challenge.attempts >= CAPTCHA_MAX_ATTEMPTS) {
    captchaStore.delete(captchaId);
    return {valid: false, message: "Captcha expired. Please try again."};
  }

  return {valid: false, message: "Incorrect captcha answer"};
};

router.get("/captcha", (req, res) => {
  const challenge = createCaptchaChallenge();
  res.json({success: true, ...challenge});
});

router.post("/register", authRateLimiter, asyncHandler(async (req, res) => {
  const {username, email, password, captchaId, captchaAnswer} = req.body;

  if (!username || !email || !password) {
    throw new AppError(SAFE_ERRORS.VALIDATION_FAILED, 400, "VALIDATION_ERROR");
  }

  if (!captchaId || captchaAnswer === undefined || captchaAnswer === null) {
    throw new AppError("Captcha is required", 400, "CAPTCHA_REQUIRED");
  }

  const captchaResult = verifyCaptchaChallenge(captchaId, captchaAnswer);
  if (!captchaResult.valid) {
    throw new AppError(captchaResult.message, 400, "CAPTCHA_INVALID");
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
  const {username, password, captchaId, captchaAnswer} = req.body;

  if (!username || !password) {
    throw new AppError(SAFE_ERRORS.INVALID_CREDENTIALS, 401, "INVALID_CREDENTIALS");
  }

  if (!captchaId || captchaAnswer === undefined || captchaAnswer === null) {
    throw new AppError("Captcha is required", 400, "CAPTCHA_REQUIRED");
  }

  const captchaResult = verifyCaptchaChallenge(captchaId, captchaAnswer);
  if (!captchaResult.valid) {
    throw new AppError(captchaResult.message, 400, "CAPTCHA_INVALID");
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
