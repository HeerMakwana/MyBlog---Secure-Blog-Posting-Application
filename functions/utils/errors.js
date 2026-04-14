const {SAFE_ERRORS} = require("./safeErrors");

class AppError extends Error {
  constructor(message, statusCode, code = "APP_ERROR", isOperational = true) {
    super(message);
    this.statusCode = statusCode;
    this.code = code;
    this.isOperational = isOperational;
    Error.captureStackTrace(this, this.constructor);
  }
}

const asyncHandler = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

const normalizeError = (error) => {
  if (error instanceof AppError) {
    return error;
  }

  if (error && error.name === "ValidationError") {
    return new AppError(
        SAFE_ERRORS.VALIDATION_FAILED,
        400,
        "VALIDATION_ERROR",
    );
  }

  if (error && error.name === "CastError") {
    return new AppError(SAFE_ERRORS.INVALID_INPUT, 400, "INVALID_ID");
  }

  if (error && error.code === 11000) {
    return new AppError(
        SAFE_ERRORS.REGISTRATION_FAILED,
        400,
        "DUPLICATE_RESOURCE",
    );
  }

  return new AppError(SAFE_ERRORS.SERVER_ERROR, 500, "INTERNAL_SERVER_ERROR", false);
};

module.exports = {
  AppError,
  asyncHandler,
  normalizeError,
};
