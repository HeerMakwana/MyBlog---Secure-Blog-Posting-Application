const PASSWORD_RULES = {
  minLength: 12,
  maxLength: 128,
  requireUppercase: true,
  requireLowercase: true,
  requireNumber: true,
  requireSpecial: true,
};

const PASSWORD_REGEX = {
  uppercase: /[A-Z]/,
  lowercase: /[a-z]/,
  number: /[0-9]/,
  special: /[^A-Za-z0-9]/,
};

const validatePasswordPolicy = (password) => {
  if (typeof password !== "string") {
    return {valid: false, reason: "Password must be a string"};
  }

  if (password.length < PASSWORD_RULES.minLength) {
    return {
      valid: false,
      reason: `Password must be at least ${PASSWORD_RULES.minLength} characters`,
    };
  }

  if (password.length > PASSWORD_RULES.maxLength) {
    return {
      valid: false,
      reason: `Password cannot exceed ${PASSWORD_RULES.maxLength} characters`,
    };
  }

  if (PASSWORD_RULES.requireUppercase && !PASSWORD_REGEX.uppercase.test(password)) {
    return {valid: false, reason: "Password must include an uppercase letter"};
  }

  if (PASSWORD_RULES.requireLowercase && !PASSWORD_REGEX.lowercase.test(password)) {
    return {valid: false, reason: "Password must include a lowercase letter"};
  }

  if (PASSWORD_RULES.requireNumber && !PASSWORD_REGEX.number.test(password)) {
    return {valid: false, reason: "Password must include a number"};
  }

  if (PASSWORD_RULES.requireSpecial && !PASSWORD_REGEX.special.test(password)) {
    return {valid: false, reason: "Password must include a special character"};
  }

  return {valid: true};
};

module.exports = {
  PASSWORD_RULES,
  validatePasswordPolicy,
};