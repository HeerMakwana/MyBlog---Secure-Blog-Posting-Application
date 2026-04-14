# Password Security Implementation (Security-Only)

## Scope

Implemented security measures in the Functions auth flow without adding any vulnerable code path:

1. Strong password policy validation in registration.
2. Auth endpoint rate limiting.
3. Account lockout after 5 failed login attempts.
4. Generic/safe authentication error handling.
5. Hashing and salt behavior + performance benchmark script for evidence.

## Before vs After Code Snippets

### 1) Registration Password Validation

Before:

```js
router.post("/register", asyncHandler(async (req, res) => {
  const {username, email, password} = req.body;

  if (!username || !email || !password) {
    throw new AppError(SAFE_ERRORS.VALIDATION_FAILED, 400, "VALIDATION_ERROR");
  }

  const user = await User.create({username, email, password});
```

After:

```js
router.post("/register", authRateLimiter, asyncHandler(async (req, res) => {
  const {username, email, password} = req.body;

  if (!username || !email || !password) {
    throw new AppError(SAFE_ERRORS.VALIDATION_FAILED, 400, "VALIDATION_ERROR");
  }

  const passwordPolicyResult = validatePasswordPolicy(password);
  if (!passwordPolicyResult.valid) {
    throw new AppError(SAFE_ERRORS.VALIDATION_FAILED, 400, "WEAK_PASSWORD");
  }

  const user = await User.create({username, email, password});
```

### 2) Login Lockout + Generic Error Behavior

Before:

```js
router.post("/login", asyncHandler(async (req, res) => {
  const {username, password} = req.body;

  if (!username || !password) {
    throw new AppError(SAFE_ERRORS.VALIDATION_FAILED, 400, "VALIDATION_ERROR");
  }

  const user = await User.findOne({username}).select("+password +totpSecret");

  if (!user || !(await user.comparePassword(password))) {
    throw new AppError(SAFE_ERRORS.INVALID_CREDENTIALS, 401, "INVALID_CREDENTIALS");
  }
```

After:

```js
router.post("/login", authRateLimiter, asyncHandler(async (req, res) => {
  const {username, password} = req.body;

  if (!username || !password) {
    throw new AppError(SAFE_ERRORS.INVALID_CREDENTIALS, 401, "INVALID_CREDENTIALS");
  }

  const user = await User.findOne({username})
      .select("+password +totpSecret +failedLoginAttempts +lockedUntil");

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
```

### 3) User Model Lockout Fields

Before:

```js
totpSecret: {
  type: String,
  default: null,
  select: false
},
isAdmin: {
  type: Boolean,
  default: false
},
```

After:

```js
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
```

## Results (Measured)

Command used:

```bash
npm run test:password-security
```

Run summary:

1. Same password hashed for multiple users produced different hashes.
2. Manual salt + hash also produced unique hashes per user.
3. Simple dictionary attack did not recover the password hash (`dictionaryCrackResult: null`).
4. Account lockout became `true` after 5 failed attempts.

### Bcrypt Performance

| Salt Rounds | Average Time (ms) | Security/Performance Note |
|---|---:|---|
| 5 | 2.28 | Very fast, weaker against offline brute force |
| 10 | 71.95 | Good balance for most web apps |
| 15 | 2372.08 | Stronger, but high login latency |

## Table 1: Observation Table (Before vs After)

| Aspect | Plaintext System | Hashed & Salted System |
|---|---|---|
| Database breach impact | Immediate credential exposure; attacker reads passwords directly | Attacker sees bcrypt hashes (and optional salts), not raw passwords |
| Same password detection | Trivial: identical passwords are obvious | Reduced: bcrypt per-password salt yields different hash output |
| Rainbow table attack | Highly effective | Strongly mitigated due to unique salt in hash format |
| Brute-force difficulty | Very low | High and tunable via work factor (`saltRounds`) |

## Files Added/Updated

1. `functions/utils/passwordPolicy.js`
2. `functions/middleware/rateLimiter.js`
3. `functions/models/User.js`
4. `functions/routes/auth.js`
5. `functions/utils/safeErrors.js`
6. `functions/scripts/testPasswordSecurity.js`
7. `functions/package.json`
