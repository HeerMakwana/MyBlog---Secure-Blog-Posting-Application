import React, { createContext, useContext, useState, useEffect } from 'react';
import api from '../services/api';

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
  const [mfaRequired, setMfaRequired] = useState(false);
  const [tempToken, setTempToken] = useState(null);

  useEffect(() => {
    checkAuth();
  }, []);

  const checkAuth = async () => {
    const token = localStorage.getItem('token');
    if (token) {
      try {
        const response = await api.get('/auth/me');
        setUser(response.data.user);
      } catch (error) {
        localStorage.removeItem('token');
      }
    }
    setLoading(false);
  };

  const login = async (username, password) => {
    const response = await api.post('/auth/login', { username, password });
    
    if (response.data.mfaRequired) {
      setMfaRequired(true);
      setTempToken(response.data.tempToken);
      return { mfaRequired: true };
    }

    localStorage.setItem('token', response.data.token);
    setUser(response.data.user);
    return { success: true };
  };

  const verifyMFA = async (code) => {
    const response = await api.post('/auth/verify-mfa', { tempToken, code });
    localStorage.setItem('token', response.data.token);
    setUser(response.data.user);
    setMfaRequired(false);
    setTempToken(null);
    return { success: true };
  };

  const register = async (username, email, password) => {
    const response = await api.post('/auth/register', { username, email, password });
    localStorage.setItem('token', response.data.token);
    setUser(response.data.user);
    return { success: true };
  };

  const logout = () => {
    localStorage.removeItem('token');
    setUser(null);
    setMfaRequired(false);
    setTempToken(null);
  };

  const updateUser = (userData) => {
    setUser(userData);
  };

  const value = {
    user,
    loading,
    mfaRequired,
    login,
    verifyMFA,
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
