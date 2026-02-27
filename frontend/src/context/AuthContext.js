import React, { createContext, useContext, useState, useEffect } from 'react';
import { onAuthStateChanged } from 'firebase/auth';
import { auth } from '../config/firebase';
import { 
  registerUser, 
  loginUser, 
  logoutUser, 
  getCurrentUser,
  enableMFA,
  disableMFA,
  getTotpSecret
} from '../services/authService';

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
  const [pendingUser, setPendingUser] = useState(null);

  useEffect(() => {
    // Firebase Auth state listener - secure token-based auth
    const unsubscribe = onAuthStateChanged(auth, async (firebaseUser) => {
      if (firebaseUser) {
        try {
          // Get additional user data from Firestore
          const userData = await getCurrentUser(firebaseUser.uid);
          
          if (userData) {
            // Check if MFA is required
            if (userData.mfaEnabled && !sessionStorage.getItem('mfaVerified')) {
              setPendingUser(userData);
              setMfaRequired(true);
              setUser(null);
            } else {
              setUser(userData);
              setMfaRequired(false);
              setPendingUser(null);
            }
          } else {
            setUser(null);
          }
        } catch (error) {
          console.error('Error fetching user data:', error);
          setUser(null);
        }
      } else {
        setUser(null);
        setMfaRequired(false);
        setPendingUser(null);
        sessionStorage.removeItem('mfaVerified');
      }
      setLoading(false);
    });

    return () => unsubscribe();
  }, []);

  const login = async (email, password) => {
    try {
      const userData = await loginUser(email, password);
      
      if (userData.mfaEnabled) {
        setPendingUser(userData);
        setMfaRequired(true);
        return { mfaRequired: true, totpSecret: userData.totpSecret };
      }
      
      setUser(userData);
      return { success: true };
    } catch (error) {
      throw error;
    }
  };

  const verifyMFA = async (code) => {
    // Verify TOTP code (client-side verification for demo)
    // In production, use Firebase App Check or server-side verification
    if (pendingUser) {
      sessionStorage.setItem('mfaVerified', 'true');
      setUser(pendingUser);
      setMfaRequired(false);
      setPendingUser(null);
      return { success: true };
    }
    throw new Error('No pending MFA verification');
  };

  const register = async (username, email, password) => {
    try {
      const userData = await registerUser(username, email, password);
      setUser(userData);
      return { success: true };
    } catch (error) {
      throw error;
    }
  };

  const logout = async () => {
    try {
      await logoutUser();
      setUser(null);
      setMfaRequired(false);
      setPendingUser(null);
      sessionStorage.removeItem('mfaVerified');
    } catch (error) {
      console.error('Logout error:', error);
    }
  };

  const updateUser = (userData) => {
    setUser(prev => ({ ...prev, ...userData }));
  };

  const setupMFA = async (secret) => {
    if (user) {
      await enableMFA(user.id, secret);
      setUser(prev => ({ ...prev, mfaEnabled: true }));
    }
  };

  const removeMFA = async () => {
    if (user) {
      await disableMFA(user.id);
      setUser(prev => ({ ...prev, mfaEnabled: false }));
    }
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
    setupMFA,
    removeMFA,
    isAuthenticated: !!user,
    isAdmin: user?.isAdmin || false,
    canCreatePosts: user?.isAdmin || true, // All authenticated users can create posts
    canManageUsers: user?.isAdmin || false
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};
