const path = require('path');
const dotenv = require('dotenv');
const mongoose = require('mongoose');

dotenv.config({ path: path.resolve(__dirname, '../.env') });

const connectDB = require('../src/config/database');
const User = require('../src/models/User');
const { ROLES } = require('../src/config/roles');

const requiredVars = ['ADMIN_USERNAME', 'ADMIN_EMAIL', 'ADMIN_PASSWORD'];

function validateEnv() {
  const missing = requiredVars.filter((name) => !process.env[name]);

  if (missing.length > 0) {
    throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
  }

  if (process.env.ADMIN_PASSWORD.length < 12) {
    throw new Error('ADMIN_PASSWORD must be at least 12 characters.');
  }
}

async function createOrUpdateAdmin() {
  validateEnv();

  const adminUsername = process.env.ADMIN_USERNAME.trim();
  const adminEmail = process.env.ADMIN_EMAIL.trim().toLowerCase();
  const adminPassword = process.env.ADMIN_PASSWORD;

  await connectDB();

  const existingUser = await User.findOne({
    $or: [{ email: adminEmail }, { username: adminUsername }]
  }).select('+password');

  if (existingUser) {
    existingUser.username = adminUsername;
    existingUser.email = adminEmail;
    existingUser.password = adminPassword;
    existingUser.role = ROLES.ADMINISTRATOR;
    existingUser.isAdmin = true;
    existingUser.emailVerified = true;

    await existingUser.save();

    console.log('Admin user updated and promoted successfully.');
  } else {
    const adminUser = new User({
      username: adminUsername,
      email: adminEmail,
      password: adminPassword,
      role: ROLES.ADMINISTRATOR,
      isAdmin: true,
      emailVerified: true
    });

    await adminUser.save();

    console.log('Admin user created successfully.');
  }

  console.log(`Admin username: ${adminUsername}`);
  console.log(`Admin email: ${adminEmail}`);
}

(async () => {
  try {
    await createOrUpdateAdmin();
  } catch (error) {
    console.error(`Failed to create/update admin user: ${error.message}`);
    process.exitCode = 1;
  } finally {
    await mongoose.connection.close();
  }
})();
