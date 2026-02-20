const jwt = require('jsonwebtoken');
const functions = require('firebase-functions');
const User = require('../models/User');

const getJwtSecret = () => {
  return process.env.JWT_SECRET || functions.config().jwt?.secret || 'your-default-secret-change-in-production';
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

    const decoded = jwt.verify(token, getJwtSecret());

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
    { expiresIn: '7d' }
  );
};

module.exports = { protect, adminOnly, generateToken, getJwtSecret };
