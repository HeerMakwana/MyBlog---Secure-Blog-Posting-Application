/**
 * Frontend Security Configuration
 * Comprehensive security settings for React frontend
 */

// ==============================================
// SECURE STORAGE CONFIGURATION
// ==============================================

const STORAGE_CONFIG = {
  // Use sessionStorage instead of localStorage for auth tokens (cleared on browser close)
  JWT_TOKEN_KEY: 'token',
  LEGACY_JWT_TOKEN_KEY: 'auth_token',
  STORAGE_TYPE: 'sessionStorage', // or 'localStorage' - sessionStorage is more secure
  
  // Never store sensitive data that should be session-only
  NEVER_PERSIST: [
    'password',
    'mfa_code',
    'backup_codes',
    'refresh_token',
    'sensitive_data'
  ]
};

/**
 * Secure Storage Service
 */
class SecureStorage {
  static getActiveStorage() {
    return STORAGE_CONFIG.STORAGE_TYPE === 'sessionStorage'
      ? sessionStorage
      : localStorage;
  }

  static migrateLegacyTokenIfNeeded() {
    const storage = this.getActiveStorage();
    const activeToken = storage.getItem(STORAGE_CONFIG.JWT_TOKEN_KEY);
    if (activeToken) {
      return activeToken;
    }

    // Backward compatibility for old key names and storage location.
    const legacyToken =
      localStorage.getItem('token') ||
      localStorage.getItem(STORAGE_CONFIG.LEGACY_JWT_TOKEN_KEY) ||
      sessionStorage.getItem(STORAGE_CONFIG.LEGACY_JWT_TOKEN_KEY);

    if (legacyToken) {
      storage.setItem(STORAGE_CONFIG.JWT_TOKEN_KEY, legacyToken);
      localStorage.removeItem(STORAGE_CONFIG.LEGACY_JWT_TOKEN_KEY);
      sessionStorage.removeItem(STORAGE_CONFIG.LEGACY_JWT_TOKEN_KEY);
      localStorage.removeItem('token');
    }

    return legacyToken;
  }

  static setToken(token) {
    const storage = this.getActiveStorage();
    
    try {
      storage.setItem(STORAGE_CONFIG.JWT_TOKEN_KEY, token);
    } catch (error) {
      console.error('Failed to store token:', error);
    }
  }

  static getToken() {
    const storage = this.getActiveStorage();
    return storage.getItem(STORAGE_CONFIG.JWT_TOKEN_KEY) || this.migrateLegacyTokenIfNeeded();
  }

  static removeToken() {
    sessionStorage.removeItem(STORAGE_CONFIG.JWT_TOKEN_KEY);
    localStorage.removeItem(STORAGE_CONFIG.JWT_TOKEN_KEY);
    sessionStorage.removeItem(STORAGE_CONFIG.LEGACY_JWT_TOKEN_KEY);
    localStorage.removeItem(STORAGE_CONFIG.LEGACY_JWT_TOKEN_KEY);
    localStorage.removeItem('token');
  }

  static clear() {
    sessionStorage.clear();
    // Don't clear localStorage entirely - only remove sensitive tokens
    localStorage.removeItem(STORAGE_CONFIG.JWT_TOKEN_KEY);
  }
}

// ==============================================
// CONTENT SECURITY POLICY HEADERS
// ==============================================

const CSP_DIRECTIVES = {
  'default-src': ["'self'"],
  'script-src': [
    "'self'",
    // Add trusted CDN sources here
    // 'https://cdn.example.com'
  ],
  'style-src': [
    "'self'",
    "'unsafe-inline'" // Ideally replace with CSS hashes
  ],
  'img-src': [
    "'self'",
    'data:',
    'https:'
  ],
  'connect-src': [
    "'self'",
    // API endpoints
    "https://localhost:5000"
  ],
  'font-src': ["'self'"],
  'object-src': ["'none'"],
  'frame-ancestors': ["'none'"],
  'base-uri': ["'self'"],
  'form-action': ["'self'"]
};

// ==============================================
// SAME-SITE COOKIE CONFIGURATION
// ==============================================

const COOKIE_CONFIG = {
  // SameSite attribute prevents CSRF attacks
  // Strict: Cookie only sent with same-site requests
  // Lax: Cookie sent with same-site requests and top-level navigation
  sameSite: 'Strict',
  
  // Secure: Only send over HTTPS
  secure: process.env.NODE_ENV === 'production',
  
  // HttpOnly: Not accessible to JavaScript (prevents XSS attacks)
  httpOnly: true,
  
  // Max age in seconds (1 hour)
  maxAge: 3600
};

// ==============================================
// XSS PREVENTION
// ==============================================

/**
 * Sanitize HTML to prevent XSS
 * Use DOMPurify library in production
 */
const sanitizeHtml = (html) => {
  const div = document.createElement('div');
  div.textContent = html; // Use textContent, not innerHTML
  return div.innerHTML;
};

/**
 * Escape HTML special characters
 */
const escapeHtml = (text) => {
  const map = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#x27;',
    '/': '&#x2F;'
  };
  return text.replace(/[&<>"'\/]/g, (char) => map[char]);
};

// ==============================================
// SECURE COMMUNICATION
// ==============================================

const SECURITY_HEADERS = {
  // Standard headers
  'Content-Type': 'application/json',
  'Accept': 'application/json',
  
  // Security headers
  'X-Requested-With': 'XMLHttpRequest',
  'X-Content-Type-Options': 'nosniff',
  'X-XSS-Protection': '1; mode=block',
  'Referrer-Policy': 'strict-origin-when-cross-origin'
};

// ==============================================
// DATA VALIDATION
// ==============================================

/**
 * Client-side input validation (server-side validation is mandatory)
 */
const INPUT_VALIDATORS = {
  email: (value) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value),
  
  password: (value) => {
    // Min 12 chars, uppercase, lowercase, number, special char
    return /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[a-zA-Z\d@$!%*?&]{12,}$/.test(value);
  },
  
  username: (value) => /^[A-Za-z0-9_]{3,30}$/.test(value),
  
  url: (value) => {
    try {
      new URL(value);
      return true;
    } catch {
      return false;
    }
  }
};

// ==============================================
// SECURE API COMMUNICATION
// ==============================================

/**
 * Secure API request with headers and error handling
 */
const secureApiCall = async (url, options = {}) => {
  const headers = {
    ...SECURITY_HEADERS,
    ...options.headers
  };

  // Include CSRF token if available
  const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content;
  if (csrfToken) {
    headers['X-CSRF-Token'] = csrfToken;
  }

  try {
    const response = await fetch(url, {
      ...options,
      headers,
      credentials: 'include' // Include cookies
    });

    if (!response.ok) {
      throw new Error(`API Error: ${response.status}`);
    }

    return await response.json();
  } catch (error) {
    console.error('Secure API call failed:', error);
    throw error;
  }
};

// ==============================================
// SESSION SECURITY
// ==============================================

/**
 * Session timeout management
 */
class SessionManager {
  constructor(timeoutMs = 3600000) { // 1 hour
    this.timeoutMs = timeoutMs;
    this.lastActivityTime = Date.now();
    this.timeoutHandle = null;
    
    this.init();
  }

  init() {
    // Reset timeout on user activity
    document.addEventListener('click', () => this.resetTimeout());
    document.addEventListener('keypress', () => this.resetTimeout());
    document.addEventListener('scroll', () => this.resetTimeout());
    document.addEventListener('mousemove', () => this.resetTimeout());
  }

  resetTimeout() {
    this.lastActivityTime = Date.now();
    
    if (this.timeoutHandle) {
      clearTimeout(this.timeoutHandle);
    }
    
    this.timeoutHandle = setTimeout(() => {
      this.handleSessionTimeout();
    }, this.timeoutMs);
  }

  handleSessionTimeout() {
    // Clear session storage
    SecureStorage.clear();
    
    // Redirect to login
    window.location.href = '/login?sessionTimeout=true';
  }
}

// ==============================================
// SUBRESOURCE INTEGRITY (SRI)
// ==============================================

/**
 * SRI hashes for external scripts/stylesheets
 * Generate with: echo -n "content" | openssl dgst -sha384 -binary | openssl base64 -A
 */
const SRI_HASHES = {
  // Example: 'https://cdn.example.com/script.js': 'sha384-ABC123...'
};

// ==============================================
// ENVIRONMENT-SPECIFIC CONFIGURATION
// ==============================================

const SECURITY_CONFIG = {
  development: {
    enableConsoleWarnings: true,
    validateOnChange: false,
    logSecurityEvents: true
  },
  
  production: {
    enableConsoleWarnings: false,
    validateOnChange: true,
    logSecurityEvents: true,
    enableSRI: true,
    enforceHttps: true
  }
};

// ==============================================
// EXPORTS
// ==============================================

export {
  STORAGE_CONFIG,
  SecureStorage,
  CSP_DIRECTIVES,
  COOKIE_CONFIG,
  sanitizeHtml,
  escapeHtml,
  SECURITY_HEADERS,
  INPUT_VALIDATORS,
  secureApiCall,
  SessionManager,
  SRI_HASHES,
  SECURITY_CONFIG
};
