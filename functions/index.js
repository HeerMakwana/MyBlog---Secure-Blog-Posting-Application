const {setGlobalOptions} = require("firebase-functions");
const {onRequest} = require("firebase-functions/https");
const express = require("express");

const {connectDB} = require("./config/database");
const {requestLogger} = require("./middleware/requestLogger");
const {errorHandler, notFoundHandler} = require("./middleware/errorHandler");
const {generalRateLimiter} = require("./middleware/rateLimiter");

const authRoutes = require("./routes/auth");
const userRoutes = require("./routes/users");
const postRoutes = require("./routes/posts");
const adminRoutes = require("./routes/admin");

setGlobalOptions({maxInstances: 10});

const app = express();
app.set("trust proxy", 1);

const configuredOrigins = (process.env.ALLOWED_ORIGINS || "")
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean);

const defaultDevOrigins = [
  "http://localhost:3000",
  "http://127.0.0.1:3000",
];

const allowedOrigins = configuredOrigins.length > 0 ?
  configuredOrigins :
  (process.env.NODE_ENV === "production" ? [] : defaultDevOrigins);

const securityHeaders = (req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Cross-Origin-Resource-Policy", "same-site");
  res.setHeader("Content-Security-Policy",
      "default-src 'self'; frame-ancestors 'none'; object-src 'none'");

  if (process.env.NODE_ENV === "production") {
    res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  }

  next();
};

const corsHandler = (req, res, next) => {
  const origin = req.headers.origin;

  if (allowedOrigins.length === 0) {
    return res.status(500).json({
      success: false,
      message: "CORS is not configured",
      errorCode: "SECURITY_MISCONFIGURATION",
    });
  }

  if (!origin || allowedOrigins.includes(origin)) {
    if (origin) {
      res.setHeader("Access-Control-Allow-Origin", origin);
      res.setHeader("Vary", "Origin");
    }

    res.setHeader("Access-Control-Allow-Credentials", "true");
    res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS");
    res.setHeader("Access-Control-Allow-Headers",
      "Content-Type,Authorization,X-Requested-With");

    if (req.method === "OPTIONS") {
      return res.status(204).send("");
    }

    return next();
  }

  return res.status(403).json({
    success: false,
    message: "Origin not allowed",
    errorCode: "CORS_BLOCKED",
  });
};

const sanitizeRequest = (req, res, next) => {
  const sanitize = (input) => {
    if (typeof input === "string") {
      return input.replace(/\0/g, "");
    }

    if (Array.isArray(input)) {
      return input.map((item) => sanitize(item));
    }

    if (input && typeof input === "object") {
      const result = {};

      for (const [key, value] of Object.entries(input)) {
        if (key === "__proto__" || key === "constructor" || key === "prototype") {
          continue;
        }

        // Block MongoDB operators and dotted path injection in incoming payloads.
        if (key.startsWith("$") || key.includes(".")) {
          continue;
        }

        result[key] = sanitize(value);
      }

      return result;
    }

    return input;
  };

  req.body = sanitize(req.body || {});
  req.query = sanitize(req.query || {});
  req.params = sanitize(req.params || {});

  return next();
};

app.use(express.json({limit: "10kb"}));
app.use(express.urlencoded({extended: true, limit: "10kb"}));
app.use(securityHeaders);
app.use(corsHandler);
app.use(sanitizeRequest);
app.use(generalRateLimiter);
app.use(requestLogger);

app.get("/health", (req, res) => {
  res.json({
    success: true,
    status: "ok",
    timestamp: new Date().toISOString(),
  });
});

app.use("/auth", authRoutes);
app.use("/users", userRoutes);
app.use("/posts", postRoutes);
app.use("/admin", adminRoutes);

app.use(notFoundHandler);
app.use(errorHandler);

exports.api = onRequest(async (req, res) => {
  try {
    await connectDB();
  } catch (error) {
    return res.status(503).json({
      success: false,
      message: "Service temporarily unavailable",
      errorCode: "SERVICE_UNAVAILABLE",
    });
  }

  return app(req, res);
});
