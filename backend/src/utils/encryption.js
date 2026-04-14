/**
 * Data Encryption Utility
 * Provides AES-256-GCM encryption for sensitive data at rest
 * Implements authenticated encryption with associated data (AEAD)
 */

const crypto = require('crypto');

class EncryptionService {
  constructor() {
    // Validate encryption key is set
    if (!process.env.ENCRYPTION_KEY) {
      throw new Error('ENCRYPTION_KEY environment variable not set');
    }

    // Ensure encryption key is exactly 32 bytes (256 bits)
    const keyHex = process.env.ENCRYPTION_KEY;
    if (keyHex.length !== 64) {
      throw new Error('ENCRYPTION_KEY must be 64 hex characters (32 bytes for AES-256)');
    }

    this.encryptionKey = Buffer.from(keyHex, 'hex');
    this.algorithm = process.env.ENCRYPTION_ALGORITHM || 'aes-256-gcm';
    this.ivLength = 16; // 128 bits for GCM
    this.authTagLength = 16; // 128 bits for GCM
  }

  /**
   * Encrypt data using AES-256-GCM
   * Returns: iv:authTag:encrypted (hex encoded)
   * 
   * @param {string|Buffer} plaintext - Data to encrypt
   * @param {string} additionalData - Optional additional authenticated data
   * @returns {string} Encrypted data in format: iv:authTag:encrypted
   */
  encrypt(plaintext, additionalData = '') {
    try {
      // Convert to buffer if string
      const plaintextBuffer = typeof plaintext === 'string'
        ? Buffer.from(plaintext, 'utf8')
        : plaintext;

      // Generate random initialization vector
      const iv = crypto.randomBytes(this.ivLength);

      // Create cipher
      const cipher = crypto.createCipheriv(this.algorithm, this.encryptionKey, iv);

      // Add additional authenticated data if provided
      if (additionalData) {
        cipher.setAAD(Buffer.from(additionalData, 'utf8'));
      }

      // Encrypt
      let encrypted = cipher.update(plaintextBuffer);
      encrypted = Buffer.concat([encrypted, cipher.final()]);

      // Get authentication tag
      const authTag = cipher.getAuthTag();

      // Return as: iv:authTag:encrypted (all hex encoded)
      return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted.toString('hex')}`;
    } catch (error) {
      throw new Error(`Encryption failed: ${error.message}`);
    }
  }

  /**
   * Decrypt data encrypted with encrypt()
   * 
   * @param {string} encryptedData - Data in format: iv:authTag:encrypted
   * @param {string} additionalData - Optional additional authenticated data (must match encryption)
   * @returns {string} Decrypted plaintext
   */
  decrypt(encryptedData, additionalData = '') {
    try {
      // Parse the encrypted data
      const [ivHex, authTagHex, encryptedHex] = encryptedData.split(':');

      if (!ivHex || !authTagHex || !encryptedHex) {
        throw new Error('Invalid encrypted data format. Expected: iv:authTag:encrypted');
      }

      const iv = Buffer.from(ivHex, 'hex');
      const authTag = Buffer.from(authTagHex, 'hex');
      const encrypted = Buffer.from(encryptedHex, 'hex');

      // Create decipher
      const decipher = crypto.createDecipheriv(this.algorithm, this.encryptionKey, iv);

      // Set authentication tag
      decipher.setAuthTag(authTag);

      // Add additional authenticated data if provided
      if (additionalData) {
        decipher.setAAD(Buffer.from(additionalData, 'utf8'));
      }

      // Decrypt
      let decrypted = decipher.update(encrypted);
      decrypted = Buffer.concat([decrypted, decipher.final()]);

      return decrypted.toString('utf8');
    } catch (error) {
      throw new Error(`Decryption failed: ${error.message}`);
    }
  }

  /**
   * Encrypt an object (converts to JSON)
   */
  encryptObject(obj, additionalData = '') {
    const json = JSON.stringify(obj);
    return this.encrypt(json, additionalData);
  }

  /**
   * Decrypt to object (parses JSON)
   */
  decryptObject(encryptedData, additionalData = '') {
    const json = this.decrypt(encryptedData, additionalData);
    return JSON.parse(json);
  }

  /**
   * Hash data (for verification, not encryption)
   * Uses SHA-256, NOT for passwords (use bcrypt instead)
   */
  hash(data) {
    return crypto
      .createHash('sha256')
      .update(data)
      .digest('hex');
  }

  /**
   * Generate random token (e.g., for email verification, password reset)
   * Returns URL-safe Base64 encoded token
   */
  generateToken(length = 32) {
    return crypto.randomBytes(length).toString('base64url');
  }

  /**
   * Constant-time string comparison to prevent timing attacks
   */
  safeCompare(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') {
      return false;
    }
    if (a.length !== b.length) {
      return false;
    }
    return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
  }
}

// Create singleton instance
let encryptionInstance = null;

function getEncryptionService() {
  if (!encryptionInstance) {
    encryptionInstance = new EncryptionService();
  }
  return encryptionInstance;
}

module.exports = {
  EncryptionService,
  getEncryptionService
};
