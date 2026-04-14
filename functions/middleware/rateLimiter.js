const {SAFE_ERRORS} = require("../utils/safeErrors");

const rateLimitStore = new Map();

const cleanupExpiredEntries = () => {
  const now = Date.now();
  for (const [key, data] of rateLimitStore.entries()) {
    if (data.resetAt <= now) {
      rateLimitStore.delete(key);
    }
  }
};

setInterval(cleanupExpiredEntries, 60 * 1000);

const getClientKey = (req) => {
  const ip = req.ip || req.connection?.remoteAddress || "unknown";
  return `${ip}`;
};

const createRateLimiter = ({
  keyPrefix,
  windowMs,
  maxRequests,
}) => {
  return (req, res, next) => {
    const key = `${keyPrefix}:${getClientKey(req)}`;
    const now = Date.now();

    let data = rateLimitStore.get(key);
    if (!data || data.resetAt <= now) {
      data = {
        count: 0,
        resetAt: now + windowMs,
      };
      rateLimitStore.set(key, data);
    }

    data.count += 1;

    res.set({
      "X-RateLimit-Limit": maxRequests,
      "X-RateLimit-Remaining": Math.max(0, maxRequests - data.count),
      "X-RateLimit-Reset": Math.ceil(data.resetAt / 1000),
    });

    if (data.count > maxRequests) {
      const retryAfter = Math.ceil((data.resetAt - now) / 1000);
      res.set("Retry-After", retryAfter);
      return res.status(429).json({
        success: false,
        message: SAFE_ERRORS.RATE_LIMITED,
        errorCode: "RATE_LIMITED",
      });
    }

    return next();
  };
};

const authRateLimiter = createRateLimiter({
  keyPrefix: "auth",
  windowMs: 15 * 60 * 1000,
  maxRequests: 10,
});

const generalRateLimiter = createRateLimiter({
  keyPrefix: "general",
  windowMs: 15 * 60 * 1000,
  maxRequests: 150,
});

module.exports = {
  generalRateLimiter,
  authRateLimiter,
};