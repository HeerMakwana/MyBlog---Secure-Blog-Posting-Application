const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { protect, generateToken, getJwtSecret } = require('../middleware/auth');
const { generateSecret, generateOtpAuthUrl, generateQRCode, verifyTOTP, generateTOTP } = require('../utils/totp');

router.post('/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    const existingUser = await User.findOne({
      $or: [{ email }, { username }]
    });

    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: 'Username or email already exists'
      });
    }

    const user = await User.create({ username, email, password });
    const token = generateToken(user._id);

    res.status(201).json({
      success: true,
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        isAdmin: user.isAdmin
      }
    });
  } catch (error) {
    res.status(400).json({ success: false, message: error.message });
  }
});

router.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({
        success: false,
        message: 'Please provide username and password'
      });
    }

    const user = await User.findOne({ username }).select('+password +totpSecret');

    if (!user || !(await user.comparePassword(password))) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    if (user.totpSecret) {
      const tempToken = generateToken(user._id, true);
      return res.json({
        success: true,
        mfaRequired: true,
        tempToken,
        userId: user._id
      });
    }

    const token = generateToken(user._id);

    res.json({
      success: true,
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        isAdmin: user.isAdmin
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

router.post('/verify-mfa', async (req, res) => {
  try {
    const { tempToken, code } = req.body;

    if (!tempToken || !code) {
      return res.status(400).json({
        success: false,
        message: 'Token and code are required'
      });
    }

    let decoded;
    try {
      decoded = jwt.verify(tempToken, getJwtSecret());
    } catch (err) {
      return res.status(401).json({
        success: false,
        message: 'Invalid or expired token'
      });
    }

    if (!decoded.mfaPending) {
      return res.status(400).json({
        success: false,
        message: 'Invalid MFA verification request'
      });
    }

    const user = await User.findById(decoded.id).select('+totpSecret');
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    if (!verifyTOTP(code, user.totpSecret)) {
      return res.status(401).json({ success: false, message: 'Invalid MFA code' });
    }

    const token = generateToken(user._id);

    res.json({
      success: true,
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        isAdmin: user.isAdmin
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

router.get('/me', protect, async (req, res) => {
  const user = await User.findById(req.user._id).select('+totpSecret');
  res.json({
    success: true,
    user: {
      id: user._id,
      username: user.username,
      email: user.email,
      isAdmin: user.isAdmin,
      mfaEnabled: !!user.totpSecret,
      createdAt: user.createdAt
    }
  });
});

router.post('/enable-mfa', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('+totpSecret');

    if (user.totpSecret) {
      return res.status(400).json({ success: false, message: 'MFA is already enabled' });
    }

    const secret = generateSecret();
    const otpAuthUrl = generateOtpAuthUrl(user.username, secret);
    const qrCode = await generateQRCode(otpAuthUrl);

    res.json({
      success: true,
      secret,
      qrCode,
      currentCode: process.env.NODE_ENV === 'development' ? generateTOTP(secret) : undefined
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

router.post('/confirm-mfa', protect, async (req, res) => {
  try {
    const { secret, code } = req.body;

    if (!secret || !code) {
      return res.status(400).json({ success: false, message: 'Secret and code are required' });
    }

    if (!verifyTOTP(code, secret)) {
      return res.status(400).json({ success: false, message: 'Invalid code. Please try again.' });
    }

    await User.findByIdAndUpdate(req.user._id, { totpSecret: secret });

    res.json({ success: true, message: 'MFA enabled successfully' });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

router.post('/disable-mfa', protect, async (req, res) => {
  try {
    const { code } = req.body;
    const user = await User.findById(req.user._id).select('+totpSecret');

    if (!user.totpSecret) {
      return res.status(400).json({ success: false, message: 'MFA is not enabled' });
    }

    if (!verifyTOTP(code, user.totpSecret)) {
      return res.status(400).json({ success: false, message: 'Invalid code' });
    }

    await User.findByIdAndUpdate(req.user._id, { totpSecret: null });

    res.json({ success: true, message: 'MFA disabled successfully' });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

module.exports = router;
