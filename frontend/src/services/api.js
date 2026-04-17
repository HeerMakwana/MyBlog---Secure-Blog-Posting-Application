import axios from 'axios';
import { SecureStorage } from '../config/securityConfig';

const API_URL = process.env.REACT_APP_API_URL || '/api';

/**
 * Get CSRF token from cookie
 */
const getCsrfToken = () => {
  const match = document.cookie.match(/XSRF-TOKEN=([^;]+)/);
  return match ? match[1] : null;
};

const api = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json'
  },
  withCredentials: true // Required for CSRF cookies
});

// Request interceptor to add token and CSRF
api.interceptors.request.use(
  async (config) => {
    // Add JWT token
    const token = SecureStorage.getToken();
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }

    // Add CSRF token for state-changing requests
    const method = config.method?.toUpperCase();
    if (method && !['GET', 'HEAD', 'OPTIONS'].includes(method)) {
      let csrfToken = getCsrfToken();
      
      // If no CSRF token, fetch one first
      if (!csrfToken) {
        try {
          const response = await axios.get(`${API_URL}/csrf-token`, {
            withCredentials: true
          });
          csrfToken = response.data.csrfToken;
        } catch (err) {
          console.warn('Failed to fetch CSRF token:', err.message);
        }
      }
      
      if (csrfToken) {
        config.headers['X-XSRF-TOKEN'] = csrfToken;
      }
    }
    
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor for error handling
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;
    
    // Handle CSRF validation failure - retry with fresh token
    if (error.response?.status === 403 && 
        error.response?.data?.message?.includes('CSRF') &&
        !originalRequest._csrfRetry) {
      originalRequest._csrfRetry = true;
      
      try {
        // Fetch fresh CSRF token
        const response = await axios.get(`${API_URL}/csrf-token`, {
          withCredentials: true
        });
        const newCsrfToken = response.data.csrfToken;
        originalRequest.headers['X-XSRF-TOKEN'] = newCsrfToken;
        
        // Retry the original request
        return api(originalRequest);
      } catch (csrfError) {
        console.error('Failed to refresh CSRF token:', csrfError);
      }
    }
    
    if (error.response?.status === 401) {
      // Token expired or invalid
      SecureStorage.removeToken();
      if (window.location.pathname !== '/login') {
        window.location.href = '/login';
      }
    }
    return Promise.reject(error);
  }
);

/**
 * Initialize CSRF token on app load
 * Call this early in app initialization
 */
export const initCsrfToken = async () => {
  try {
    await axios.get(`${API_URL}/csrf-token`, { withCredentials: true });
  } catch (err) {
    console.warn('Failed to initialize CSRF token:', err.message);
  }
};

export default api;
