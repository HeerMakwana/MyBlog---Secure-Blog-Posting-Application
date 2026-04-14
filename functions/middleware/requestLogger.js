const {logger} = require("../utils/logger");
const {maskData} = require("../utils/dataMasking");

const requestLogger = (req, res, next) => {
  const start = Date.now();

  res.on("finish", () => {
    logger.info("HTTP request", {
      method: req.method,
      path: req.originalUrl || req.url,
      statusCode: res.statusCode,
      durationMs: Date.now() - start,
      ip: req.ip,
      requestBody: maskData(req.body || {}),
      query: maskData(req.query || {}),
    });
  });

  next();
};

module.exports = {
  requestLogger,
};
