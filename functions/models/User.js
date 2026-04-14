const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

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
    minlength: [8, 'Password must be at least 8 characters'],
    select: false
  },
  totpSecret: {
    type: String,
    default: null,
    select: false
  },
  failedLoginAttempts: {
    type: Number,
    default: 0,
    select: false,
  },
  lockedUntil: {
    type: Date,
    default: null,
    select: false,
  },
  isAdmin: {
    type: Boolean,
    default: false
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

userSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

userSchema.methods.isAccountLocked = function() {
  return !!(this.lockedUntil && this.lockedUntil.getTime() > Date.now());
};

userSchema.methods.recordFailedLogin = function(maxAttempts = 5, lockMinutes = 15) {
  this.failedLoginAttempts += 1;
  if (this.failedLoginAttempts >= maxAttempts) {
    this.lockedUntil = new Date(Date.now() + lockMinutes * 60 * 1000);
    return true;
  }
  return false;
};

userSchema.methods.clearFailedLogins = function() {
  this.failedLoginAttempts = 0;
  this.lockedUntil = null;
};

userSchema.methods.hasMFA = function() {
  return !!this.totpSecret;
};

const User = mongoose.model('User', userSchema);

module.exports = User;
