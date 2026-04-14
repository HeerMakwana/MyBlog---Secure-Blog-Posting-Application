const mongoose = require("mongoose");
const {logger} = require("../utils/logger");

let isConnected = false;

const connectDB = async () => {
  if (isConnected) return;

  const mongoUri = process.env.MONGODB_URI;
  if (!mongoUri) {
    logger.warn("MONGODB_URI is not set. API will run without database connectivity.");
    return;
  }

  try {
    await mongoose.connect(mongoUri);
    isConnected = true;
    logger.info("MongoDB connected");
  } catch (error) {
    logger.error("MongoDB connection failed", {error: error.message});
    throw error;
  }
};

module.exports = {connectDB};
