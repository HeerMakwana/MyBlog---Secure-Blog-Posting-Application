const {normalizeError} = require("../utils/errors");
const {SAFE_ERRORS} = require("../utils/safeErrors");
const {logger} = require("../utils/logger");

const notFoundHandler = (req, res) => {
  res.status(404).json({
    success: false,
    message: SAFE_ERRORS.NOT_FOUND,
    errorCode: "NOT_FOUND",
  });
};

const errorHandler = (err, req, res, next) => {
  const normalized = normalizeError(err);

  logger.error("Request failed", {
    errorCode: normalized.code,
    statusCode: normalized.statusCode,
    message: normalized.message,
    path: req.originalUrl || req.url,
    method: req.method,
    stack: process.env.NODE_ENV === "development" ? err.stack : undefined,
  });

  res.status(normalized.statusCode).json({
    success: false,
    message: normalized.statusCode >= 500 ? SAFE_ERRORS.SERVER_ERROR : normalized.message,
    errorCode: normalized.code,
  });
};

module.exports = {
  errorHandler,
  notFoundHandler,
};
