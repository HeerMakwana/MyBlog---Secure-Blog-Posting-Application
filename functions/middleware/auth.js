const jwt = require("jsonwebtoken");
const functions = require("firebase-functions");
const User = require("../models/User");
const {AppError} = require("../utils/errors");
const {SAFE_ERRORS} = require("../utils/safeErrors");

const JWT_ALGORITHM = "HS256";

const getJwtSecret = () => {
  const fnConfig = typeof functions.config === "function" ? functions.config() : {};
  const jwtConfig = fnConfig && fnConfig.jwt ? fnConfig.jwt : {};
  const secret = process.env.JWT_SECRET || jwtConfig.secret;

  if (!secret || secret.length < 64) {
    throw new Error("JWT secret must be configured and at least 64 characters");
  }

  return secret;
};

const protect = async (req, res, next) => {
  try {
    let token;

    if (req.headers.authorization && req.headers.authorization.startsWith("Bearer")) {
      token = req.headers.authorization.split(" ")[1];
    }

    if (!token) {
      return next(new AppError(SAFE_ERRORS.UNAUTHORIZED, 401, "UNAUTHORIZED"));
    }

    const decoded = jwt.verify(token, getJwtSecret(), {
      algorithms: [JWT_ALGORITHM],
      issuer: process.env.JWT_ISSUER || "myblog-api",
      audience: process.env.JWT_AUDIENCE || "myblog-client",
    });

    const user = await User.findById(decoded.id);
    if (!user) {
      return next(new AppError(SAFE_ERRORS.UNAUTHORIZED, 401, "UNAUTHORIZED"));
    }

    if (typeof user.isAccountLocked === "function" && user.isAccountLocked()) {
      return next(new AppError(SAFE_ERRORS.ACCOUNT_LOCKED, 423, "ACCOUNT_LOCKED"));
    }

    req.user = user;
    next();
  } catch (error) {
    return next(new AppError(SAFE_ERRORS.UNAUTHORIZED, 401, "UNAUTHORIZED"));
  }
};

const adminOnly = (req, res, next) => {
  if (!req.user.isAdmin) {
    return next(new AppError(SAFE_ERRORS.FORBIDDEN, 403, "FORBIDDEN"));
  }
  next();
};

const generateToken = (userId, mfaPending = false) => {
  return jwt.sign(
    {id: userId, mfaPending},
    getJwtSecret(),
    {
      expiresIn: process.env.JWT_EXPIRES_IN || "1h",
      algorithm: JWT_ALGORITHM,
      issuer: process.env.JWT_ISSUER || "myblog-api",
      audience: process.env.JWT_AUDIENCE || "myblog-client",
    },
  );
};

module.exports = { protect, adminOnly, generateToken, getJwtSecret };
