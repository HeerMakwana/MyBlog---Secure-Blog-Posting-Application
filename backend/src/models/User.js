const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { ROLES, getDefaultRole } = require('../config/roles');
const securityConfig = require('../config/security');

const sessionSchema = new mongoose.Schema({
  sessionId: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  lastActivity: { type: Date, default: Date.now },
  userAgent: String,
  ipAddress: String,
  revokedAt: Date
}, { _id: false });

const securityQuestionSchema = new mongoose.Schema({
  questionId: { type: Number, required: true },
  answerHash: { type: String, required: true }
}, { _id: false });

const trustedDeviceSchema = new mongoose.Schema({
  deviceId: { type: String, required: true },
  fingerprint: { type: String, required: true },
  name: String,
  lastUsed: { type: Date, default: Date.now },
  createdAt: { type: Date, default: Date.now }
}, { _id: false });

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: [true, 'Username is required'],
    unique: true,
    trim: true,
    minlength: [3, 'Username must be at least 3 characters'],
    maxlength: [30, 'Username cannot exceed 30 characters'],
    match: [/^[A-Za-z0-9_]+$/, 'Username can only contain letters, numbers, and underscores']
  },
  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
    trim: true,
    lowercase: true
  },
  password: {
    type: String,
    required: [true, 'Password is required'],
    minlength: [12, 'Password must be at least 12 characters'],
    select: false
  },
  
  // RBAC - Role field replaces binary isAdmin
  role: {
    type: String,
    enum: Object.values(ROLES),
    default: getDefaultRole()
  },
  
  // Legacy compatibility - maps to role
  isAdmin: {
    type: Boolean,
    default: false
  },
  
  // Email Verification
  emailVerified: {
    type: Boolean,
    default: false
  },
  emailVerificationToken: {
    type: String,
    select: false
  },
  emailVerificationExpires: {
    type: Date,
    select: false
  },
  
  // Password Reset
  passwordResetToken: {
    type: String,
    select: false
  },
  passwordResetExpires: {
    type: Date,
    select: false
  },
  
  // MFA - TOTP
  totpSecret: {
    type: String,
    default: null,
    select: false
  },
  
  // MFA - Backup Codes (creative solution #1)
  backupCodes: [{
    code: { type: String, select: false },
    used: { type: Boolean, default: false },
    usedAt: Date
  }],
  
  // MFA - Security Questions (creative solution #2)
  securityQuestions: {
    type: [securityQuestionSchema],
    select: false
  },
  
  // MFA - Trusted Devices with Fingerprinting (creative solution #3)
  trustedDevices: {
    type: [trustedDeviceSchema],
    select: false
  },
  
  // Account Security
  isLocked: {
    type: Boolean,
    default: false
  },
  lockReason: String,
  lockedAt: Date,
  lockedUntil: Date,
  
  // Failed Login Tracking
  failedLoginAttempts: {
    type: Number,
    default: 0,
    select: false
  },
  lastFailedLogin: {
    type: Date,
    select: false
  },
  
  // Session Management
  sessions: {
    type: [sessionSchema],
    select: false
  },
  
  // Activity Tracking
  lastLogin: Date,
  lastActivity: Date,
  lastPasswordChange: Date,
  
  // Account Metadata
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: Date
});

// Indexes for performance
userSchema.index({ role: 1 });
userSchema.index({ emailVerificationToken: 1 });
userSchema.index({ passwordResetToken: 1 });

// Pre-save middleware - hash password and sync isAdmin with role
userSchema.pre('save', async function(next) {
  if (this.isModified('password')) {
    this.password = await bcrypt.hash(this.password, 12);
    this.lastPasswordChange = new Date();
  }
  // Sync isAdmin with role for backwards compatibility
  this.isAdmin = this.role === ROLES.ADMINISTRATOR;
  this.updatedAt = new Date();
  next();
});

// Compare password method
userSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

// Check if user has MFA enabled
userSchema.methods.hasMFA = function() {
  return !!this.totpSecret;
};

// Check if user has backup codes available
userSchema.methods.hasBackupCodes = function() {
  return this.backupCodes && this.backupCodes.some(bc => !bc.used);
};

// Check if user has security questions set up
userSchema.methods.hasSecurityQuestions = function() {
  return this.securityQuestions && 
         this.securityQuestions.length >= securityConfig.mfa.securityQuestionsRequired;
};

// Generate email verification token
userSchema.methods.generateEmailVerificationToken = function() {
  const token = crypto.randomBytes(32).toString('hex');
  this.emailVerificationToken = crypto.createHash('sha256').update(token).digest('hex');
  this.emailVerificationExpires = new Date(Date.now() + securityConfig.emailVerification.tokenExpiry);
  return token;
};

// Generate password reset token
userSchema.methods.generatePasswordResetToken = function() {
  const token = crypto.randomBytes(32).toString('hex');
  this.passwordResetToken = crypto.createHash('sha256').update(token).digest('hex');
  this.passwordResetExpires = new Date(Date.now() + 60 * 60 * 1000); // 1 hour
  return token;
};

// Generate MFA backup codes
userSchema.methods.generateBackupCodes = function() {
  const codes = [];
  const count = securityConfig.mfa.backupCodesCount;
  const length = securityConfig.mfa.backupCodeLength;
  
  for (let i = 0; i < count; i++) {
    const code = crypto.randomBytes(length / 2 + 1)
      .toString('hex')
      .toUpperCase()
      .substring(0, length);
    codes.push(code);
  }
  
  // Store hashed codes
  this.backupCodes = codes.map(code => ({
    code: crypto.createHash('sha256').update(code).digest('hex'),
    used: false
  }));
  
  return codes; // Return plain codes to show user once
};

// Verify and use backup code
userSchema.methods.useBackupCode = function(code) {
  const hashedCode = crypto.createHash('sha256').update(code.toUpperCase()).digest('hex');
  const backupCode = this.backupCodes.find(bc => bc.code === hashedCode && !bc.used);
  
  if (backupCode) {
    backupCode.used = true;
    backupCode.usedAt = new Date();
    return true;
  }
  return false;
};

// Set security question answer (hashed)
userSchema.methods.setSecurityQuestionAnswer = async function(questionId, answer) {
  const answerHash = await bcrypt.hash(answer.toLowerCase().trim(), 10);
  
  if (!this.securityQuestions) this.securityQuestions = [];
  
  const existingIndex = this.securityQuestions.findIndex(q => q.questionId === questionId);
  if (existingIndex >= 0) {
    this.securityQuestions[existingIndex].answerHash = answerHash;
  } else {
    this.securityQuestions.push({ questionId, answerHash });
  }
};

// Verify security question answer
userSchema.methods.verifySecurityAnswer = async function(questionId, answer) {
  const question = this.securityQuestions?.find(q => q.questionId === questionId);
  if (!question) return false;
  return await bcrypt.compare(answer.toLowerCase().trim(), question.answerHash);
};

// Add trusted device
userSchema.methods.addTrustedDevice = function(deviceId, fingerprint, name) {
  if (!this.trustedDevices) this.trustedDevices = [];
  
  // Remove if already exists
  this.trustedDevices = this.trustedDevices.filter(d => d.deviceId !== deviceId);
  
  // Add new device
  this.trustedDevices.push({
    deviceId,
    fingerprint,
    name,
    lastUsed: new Date(),
    createdAt: new Date()
  });
  
  // Keep only last 10 devices
  if (this.trustedDevices.length > 10) {
    this.trustedDevices = this.trustedDevices.slice(-10);
  }
};

// Check if device is trusted
userSchema.methods.isDeviceTrusted = function(deviceId, fingerprint) {
  if (!this.trustedDevices) return false;
  
  const device = this.trustedDevices.find(d => 
    d.deviceId === deviceId && d.fingerprint === fingerprint
  );
  
  if (!device) return false;
  
  // Check if trust has expired
  const trustDuration = securityConfig.mfa.deviceTrustDuration;
  if (Date.now() - device.lastUsed.getTime() > trustDuration) {
    return false;
  }
  
  // Update last used
  device.lastUsed = new Date();
  return true;
};

// Create session
userSchema.methods.createSession = function(userAgent, ipAddress) {
  const sessionId = crypto.randomBytes(32).toString('hex');
  
  if (!this.sessions) this.sessions = [];
  
  // Remove old sessions if exceeding limit
  const maxSessions = securityConfig.session.maxConcurrentSessions;
  if (this.sessions.length >= maxSessions) {
    this.sessions = this.sessions.slice(-(maxSessions - 1));
  }
  
  this.sessions.push({
    sessionId,
    userAgent,
    ipAddress,
    createdAt: new Date(),
    lastActivity: new Date()
  });
  
  return sessionId;
};

// Revoke session
userSchema.methods.revokeSession = function(sessionId) {
  const session = this.sessions?.find(s => s.sessionId === sessionId);
  if (session) {
    session.revokedAt = new Date();
    return true;
  }
  return false;
};

// Revoke all sessions
userSchema.methods.revokeAllSessions = function() {
  if (!this.sessions) return;
  const now = new Date();
  this.sessions.forEach(s => {
    if (!s.revokedAt) {
      s.revokedAt = now;
    }
  });
};

// Lock account
userSchema.methods.lockAccount = function(reason, duration = null) {
  this.isLocked = true;
  this.lockReason = reason;
  this.lockedAt = new Date();
  if (duration) {
    this.lockedUntil = new Date(Date.now() + duration);
  }
};

// Unlock account
userSchema.methods.unlockAccount = function() {
  this.isLocked = false;
  this.lockReason = null;
  this.lockedAt = null;
  this.lockedUntil = null;
  this.failedLoginAttempts = 0;
};

// Record failed login
userSchema.methods.recordFailedLogin = function() {
  this.failedLoginAttempts = (this.failedLoginAttempts || 0) + 1;
  this.lastFailedLogin = new Date();
  
  if (this.failedLoginAttempts >= securityConfig.password.maxAttempts) {
    this.lockAccount('Too many failed login attempts', securityConfig.password.lockoutDuration);
    return true; // Account locked
  }
  return false;
};

// Clear failed login attempts on successful login
userSchema.methods.clearFailedLogins = function() {
  this.failedLoginAttempts = 0;
  this.lastFailedLogin = null;
};

// Get safe user object (no sensitive data)
userSchema.methods.toSafeObject = function() {
  return {
    id: this._id,
    username: this.username,
    email: this.email,
    role: this.role,
    isAdmin: this.isAdmin,
    emailVerified: this.emailVerified,
    mfaEnabled: !!this.totpSecret,
    hasBackupCodes: this.hasBackupCodes(),
    createdAt: this.createdAt,
    lastLogin: this.lastLogin
  };
};

// Static: Find by email verification token
userSchema.statics.findByEmailVerificationToken = async function(token) {
  const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
  return this.findOne({
    emailVerificationToken: hashedToken,
    emailVerificationExpires: { $gt: Date.now() }
  });
};

// Static: Find by password reset token
userSchema.statics.findByPasswordResetToken = async function(token) {
  const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
  return this.findOne({
    passwordResetToken: hashedToken,
    passwordResetExpires: { $gt: Date.now() }
  });
};

const User = mongoose.model('User', userSchema);

module.exports = User;
