import React, { createContext, useContext, useState, useEffect } from 'react';
import api, { initCsrfToken } from '../services/api';
import { SecureStorage } from '../config/securityConfig';

const AuthContext = createContext(null);

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    initApp();
  }, []);

  const initApp = async () => {
    // Initialize CSRF token first
    await initCsrfToken();
    // Then check authentication
    await checkAuth();
  };

  const checkAuth = async () => {
    const token = SecureStorage.getToken();
    if (token) {
      try {
        const response = await api.get('/auth/me');
        setUser(response.data.user);
      } catch (error) {
        SecureStorage.removeToken();
      }
    }
    setLoading(false);
  };

  const login = async (username, password, captchaId, captchaAnswer) => {
    const response = await api.post('/auth/login', {
      username,
      password,
      captchaId,
      captchaAnswer
    });

    SecureStorage.setToken(response.data.token);
    setUser(response.data.user);
    return { success: true };
  };

  const register = async (username, email, password, captchaId, captchaAnswer) => {
    const response = await api.post('/auth/register', {
      username,
      email,
      password,
      captchaId,
      captchaAnswer
    });
    SecureStorage.setToken(response.data.token);
    setUser(response.data.user);
    return { success: true };
  };

  const logout = () => {
    SecureStorage.removeToken();
    setUser(null);
  };

  const updateUser = (userData) => {
    setUser(userData);
  };

  const value = {
    user,
    loading,
    login,
    register,
    logout,
    updateUser,
    isAuthenticated: !!user,
    isAdmin: user?.isAdmin || false,
    role: user?.role || null,
    canCreatePosts: user?.role === 'editor' || user?.role === 'administrator' || user?.isAdmin,
    canManageUsers: user?.role === 'administrator' || user?.isAdmin
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};
