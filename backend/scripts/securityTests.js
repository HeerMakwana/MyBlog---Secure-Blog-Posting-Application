#!/usr/bin/env node
/**
 * Security Test Suite
 * Tests all security features and validates implementation
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

class SecurityTestSuite {
  constructor() {
    this.tests = [];
    this.results = {
      passed: 0,
      failed: 0,
      warnings: 0
    };
  }

  /**
   * Test 1: Environment Variables
   */
  async testEnvironmentVariables() {
    console.log('\n📋 Testing Environment Variables...');
    
    const requiredVars = [
      'JWT_SECRET',
      'SESSION_SECRET',
      'CSRF_SECRET',
      'MONGODB_URI',
      'ALLOWED_ORIGINS'
    ];

    requiredVars.forEach(varName => {
      if (process.env[varName]) {
        console.log(`  ✅ ${varName} is set`);
        this.results.passed++;
      } else {
        console.log(`  ❌ ${varName} is missing`);
        this.results.failed++;
      }
    });

    // Check secret strengths
    const secretVars = ['JWT_SECRET', 'SESSION_SECRET', 'CSRF_SECRET'];
    secretVars.forEach(varName => {
      const value = process.env[varName];
      if (value && value.length >= 32) {
        console.log(`  ✅ ${varName} has sufficient length (${value.length} chars)`);
        this.results.passed++;
      } else if (value) {
        console.log(`  ⚠️  ${varName} is too short (${value.length} chars, min 32 recommended)`);
        this.results.warnings++;
      }
    });
  }

  /**
   * Test 2: Security Headers
   */
  async testSecurityHeaders() {
    console.log('\n🔐 Testing Security Headers Configuration...');
    
    try {
      const securityConfig = require('../src/config/security');
      const requiredHeaders = [
        'contentSecurityPolicy',
        'hsts',
        'headers'
      ];

      requiredHeaders.forEach(header => {
        if (securityConfig[header]) {
          console.log(`  ✅ ${header} is configured`);
          this.results.passed++;
        } else {
          console.log(`  ❌ ${header} is missing`);
          this.results.failed++;
        }
      });
    } catch (error) {
      console.log(`  ❌ Error loading security config: ${error.message}`);
      this.results.failed++;
    }
  }

  /**
   * Test 3: CORS Configuration
   */
  async testCorsConfiguration() {
    console.log('\n🌐 Testing CORS Configuration...');
    
    const allowedOrigins = process.env.ALLOWED_ORIGINS;
    
    if (!allowedOrigins) {
      console.log('  ❌ ALLOWED_ORIGINS not set');
      this.results.failed++;
      return;
    }

    const origins = allowedOrigins.split(',');
    console.log(`  ✅ ${origins.length} origin(s) configured`);
    this.results.passed++;

    // Check for insecure configurations
    if (allowedOrigins.includes('*')) {
      console.log('  ❌ Wildcard CORS (*) detected - security risk!');
      this.results.failed++;
    } else if (allowedOrigins.includes('localhost') && process.env.NODE_ENV === 'production') {
      console.log('  ⚠️  Localhost origin in production');
      this.results.warnings++;
    } else {
      console.log('  ✅ CORS configuration looks secure');
      this.results.passed++;
    }
  }

  /**
   * Test 4: Password Policy
   */
  async testPasswordPolicy() {
    console.log('\n🔑 Testing Password Policy...');
    
    try {
      const securityConfig = require('../src/config/security');
      const pwd = securityConfig.password;

      console.log(`  ✅ Min length: ${pwd.minLength} characters`);
      this.results.passed++;

      const requirements = [
        { name: 'Uppercase required', value: pwd.requireUppercase },
        { name: 'Lowercase required', value: pwd.requireLowercase },
        { name: 'Numbers required', value: pwd.requireNumbers },
        { name: 'Special chars required', value: pwd.requireSpecialChars }
      ];

      requirements.forEach(req => {
        if (req.value) {
          console.log(`  ✅ ${req.name}`);
          this.results.passed++;
        } else {
          console.log(`  ❌ ${req.name}`);
          this.results.failed++;
        }
      });
    } catch (error) {
      console.log(`  ❌ Error loading password policy: ${error.message}`);
      this.results.failed++;
    }
  }

  /**
   * Test 5: Rate Limiting
   */
  async testRateLimiting() {
    console.log('\n⏱️  Testing Rate Limiting Configuration...');
    
    try {
      const securityConfig = require('../src/config/security');
      const rateLimit = securityConfig.rateLimit;

      const checks = [
        { name: 'General rate limit', value: rateLimit.maxRequests, min: 10 },
        { name: 'Auth rate limit', value: rateLimit.authMaxRequests, min: 3 },
        { name: 'MFA rate limit', value: rateLimit.mfaMaxRequests, min: 2 },
        { name: 'Window time', value: rateLimit.windowMs, min: 60000 }
      ];

      checks.forEach(check => {
        if (check.value >= check.min) {
          console.log(`  ✅ ${check.name}: ${check.value}`);
          this.results.passed++;
        } else {
          console.log(`  ❌ ${check.name}: ${check.value} (min: ${check.min})`);
          this.results.failed++;
        }
      });
    } catch (error) {
      console.log(`  ❌ Error loading rate limiting config: ${error.message}`);
      this.results.failed++;
    }
  }

  /**
   * Test 6: File Permissions
   */
  async testFilePermissions() {
    console.log('\n📁 Testing File Permissions...');
    
    const filesToCheck = [
      '../config/security.js',
      '../middleware/securityHeaders.js',
      '../utils/validation.js'
    ];

    filesToCheck.forEach(file => {
      const filePath = path.join(__dirname, file);
      try {
        fs.accessSync(filePath, fs.constants.R_OK);
        console.log(`  ✅ ${path.basename(file)} is readable`);
        this.results.passed++;
      } catch {
        console.log(`  ❌ ${path.basename(file)} is not accessible`);
        this.results.failed++;
      }
    });
  }

  /**
   * Test 7: Encryption Configuration
   */
  async testEncryptionConfiguration() {
    console.log('\n🔒 Testing Encryption Configuration...');
    
    const encryptionKey = process.env.ENCRYPTION_KEY;
    
    if (!encryptionKey) {
      console.log('  ❌ ENCRYPTION_KEY not set');
      this.results.failed++;
      return;
    }

    if (encryptionKey.length === 64) {
      console.log(`  ✅ Encryption key is 64 hex characters (256-bit)`);
      this.results.passed++;
    } else {
      console.log(`  ❌ Encryption key is ${encryptionKey.length} hex characters (expected 64)`);
      this.results.failed++;
    }

    const encryptionAlgorithm = process.env.ENCRYPTION_ALGORITHM || 'aes-256-gcm';
    if (encryptionAlgorithm === 'aes-256-gcm') {
      console.log(`  ✅ Using secure algorithm: ${encryptionAlgorithm}`);
      this.results.passed++;
    } else {
      console.log(`  ⚠️  Using non-standard algorithm: ${encryptionAlgorithm}`);
      this.results.warnings++;
    }
  }

  /**
   * Test 8: HTTPS/TLS Configuration
   */
  async testHttpsTlsConfiguration() {
    console.log('\n🔐 Testing HTTPS/TLS Configuration...');
    
    const cookieSecure = process.env.COOKIE_SECURE;
    
    if (process.env.NODE_ENV === 'production') {
      if (cookieSecure === 'true' || cookieSecure === true) {
        console.log('  ✅ Secure cookies enabled (HTTPS only)');
        this.results.passed++;
      } else {
        console.log('  ❌ Secure cookies disabled in production!');
        this.results.failed++;
      }
    } else {
      console.log('  ℹ️  Development mode - HTTPS validation skipped');
    }
  }

  /**
   * Test 9: Logging Configuration
   */
  async testLoggingConfiguration() {
    console.log('\n📊 Testing Logging Configuration...');
    
    const auditLoggingEnabled = process.env.ENABLE_AUDIT_LOGGING !== 'false';
    
    if (auditLoggingEnabled) {
      console.log('  ✅ Audit logging is enabled');
      this.results.passed++;
    } else {
      console.log('  ❌ Audit logging is disabled');
      this.results.failed++;
    }

    const logSensitiveData = process.env.LOG_SENSITIVE_DATA === 'true';
    if (!logSensitiveData) {
      console.log('  ✅ Sensitive data logging is disabled');
      this.results.passed++;
    } else if (process.env.NODE_ENV === 'development') {
      console.log('  ⚠️  Sensitive data logging enabled (OK in development)');
      this.results.warnings++;
    } else {
      console.log('  ❌ Sensitive data logging enabled in production!');
      this.results.failed++;
    }
  }

  /**
   * Test 10: Security Dependencies
   */
  async testSecurityDependencies() {
    console.log('\n📦 Testing Security Dependencies...');
    
    const requiredDeps = [
      'bcryptjs',
      'jsonwebtoken',
      'cors',
      'helmet',
      'dotenv'
    ];

    try {
      const packageJson = require('../package.json');
      const allDeps = { ...packageJson.dependencies, ...packageJson.devDependencies };

      requiredDeps.forEach(dep => {
        if (allDeps[dep]) {
          console.log(`  ✅ ${dep} is installed`);
          this.results.passed++;
        } else {
          console.log(`  ⚠️  ${dep} is not installed`);
          this.results.warnings++;
        }
      });
    } catch (error) {
      console.log(`  ❌ Error reading package.json: ${error.message}`);
      this.results.failed++;
    }
  }

  /**
   * Run all tests
   */
  async runAll() {
    console.log('═══════════════════════════════════════════════════════');
    console.log('  🔒 MyBlog Security Test Suite');
    console.log('═══════════════════════════════════════════════════════');

    await this.testEnvironmentVariables();
    await this.testSecurityHeaders();
    await this.testCorsConfiguration();
    await this.testPasswordPolicy();
    await this.testRateLimiting();
    await this.testFilePermissions();
    await this.testEncryptionConfiguration();
    await this.testHttpsTlsConfiguration();
    await this.testLoggingConfiguration();
    await this.testSecurityDependencies();

    this.printResults();
  }

  /**
   * Print test results
   */
  printResults() {
    console.log('\n═══════════════════════════════════════════════════════');
    console.log('  TEST RESULTS');
    console.log('═══════════════════════════════════════════════════════\n');

    console.log(`  ✅ Passed:  ${this.results.passed}`);
    console.log(`  ❌ Failed:  ${this.results.failed}`);
    console.log(`  ⚠️  Warnings: ${this.results.warnings}`);

    const total = this.results.passed + this.results.failed + this.results.warnings;
    const percentage = Math.round((this.results.passed / total) * 100);

    console.log(`\n  Overall Security Score: ${percentage}%`);
    
    if (this.results.failed === 0) {
      console.log('\n  ✅ All security tests passed! 🎉\n');
      process.exit(0);
    } else {
      console.log(`\n  ❌ ${this.results.failed} security issue(s) need to be addressed\n`);
      process.exit(1);
    }
  }
}

// Run tests
const suite = new SecurityTestSuite();
suite.runAll().catch(error => {
  console.error('Test suite error:', error);
  process.exit(1);
});
