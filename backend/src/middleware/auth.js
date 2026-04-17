const jwt = require('jsonwebtoken');
const User = require('../models/User');

const JWT_ALGORITHM = 'HS256';

const getJwtSecret = () => {
  const secret = process.env.JWT_SECRET;
  if (!secret || secret.length < 64) {
    throw new Error('JWT_SECRET must be configured and at least 64 characters');
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
      return res.status(401).json({
        success: false,
        message: 'Not authorized to access this route'
      });
    }

    const decoded = jwt.verify(token, getJwtSecret(), {
      algorithms: [JWT_ALGORITHM],
      issuer: process.env.JWT_ISSUER || 'myblog-api',
      audience: process.env.JWT_AUDIENCE || 'myblog-client'
    });

    const user = await User.findById(decoded.id);
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'User no longer exists'
      });
    }

    req.user = user;
    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: 'Not authorized to access this route'
    });
  }
};

const adminOnly = (req, res, next) => {
  if (!req.user.isAdmin) {
    return res.status(403).json({
      success: false,
      message: 'Admin access required'
    });
  }
  next();
};

const generateToken = (userId, mfaPending = false) => {
  return jwt.sign(
    { id: userId, mfaPending },
    getJwtSecret(),
    {
      expiresIn: process.env.JWT_EXPIRES_IN || '1h',
      algorithm: JWT_ALGORITHM,
      issuer: process.env.JWT_ISSUER || 'myblog-api',
      audience: process.env.JWT_AUDIENCE || 'myblog-client'
    }
  );
};

module.exports = { protect, adminOnly, generateToken, getJwtSecret };
