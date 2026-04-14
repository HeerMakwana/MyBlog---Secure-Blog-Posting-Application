const jwt = require('jsonwebtoken');
const functions = require('firebase-functions');
const User = require('../models/User');
const {AppError} = require('../utils/errors');
const {SAFE_ERRORS} = require('../utils/safeErrors');

const getJwtSecret = () => {
  const fnConfig = typeof functions.config === 'function' ? functions.config() : {};
  const jwtConfig = fnConfig && fnConfig.jwt ? fnConfig.jwt : {};
  const secret = process.env.JWT_SECRET || jwtConfig.secret;

  if (!secret) {
    throw new Error('JWT secret is not configured. Set JWT_SECRET or firebase functions config jwt.secret.');
  }

  return secret;
};

const protect = async (req, res, next) => {
  try {
    let token;

    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
      return next(new AppError(SAFE_ERRORS.UNAUTHORIZED, 401, 'UNAUTHORIZED'));
    }

    const decoded = jwt.verify(token, getJwtSecret());

    const user = await User.findById(decoded.id);
    if (!user) {
      return next(new AppError(SAFE_ERRORS.UNAUTHORIZED, 401, 'UNAUTHORIZED'));
    }

    req.user = user;
    next();
  } catch (error) {
    return next(new AppError(SAFE_ERRORS.UNAUTHORIZED, 401, 'UNAUTHORIZED'));
  }
};

const adminOnly = (req, res, next) => {
  if (!req.user.isAdmin) {
    return next(new AppError(SAFE_ERRORS.FORBIDDEN, 403, 'FORBIDDEN'));
  }
  next();
};

const generateToken = (userId, mfaPending = false) => {
  return jwt.sign(
    { id: userId, mfaPending },
    getJwtSecret(),
    { expiresIn: '7d' }
  );
};

module.exports = { protect, adminOnly, generateToken, getJwtSecret };
