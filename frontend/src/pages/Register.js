import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import api from '../services/api';

const Register = () => {
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [captchaId, setCaptchaId] = useState('');
  const [captchaQuestion, setCaptchaQuestion] = useState('');
  const [captchaAnswer, setCaptchaAnswer] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const { register, isAuthenticated } = useAuth();
  const navigate = useNavigate();

  const loadCaptcha = React.useCallback(async () => {
    try {
      const response = await api.get('/auth/captcha');
      setCaptchaId(response.data.captchaId);
      setCaptchaQuestion(response.data.question);
      setCaptchaAnswer('');
    } catch (err) {
      setError('Failed to load captcha. Please refresh the page.');
    }
  }, []);

  // Redirect if already logged in
  React.useEffect(() => {
    if (isAuthenticated) {
      navigate('/dashboard');
    }
  }, [isAuthenticated, navigate]);

  React.useEffect(() => {
    loadCaptcha();
  }, [loadCaptcha]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    // Basic validation
    if (username.length < 3 || username.length > 30) {
      setError('Username must be 3-30 characters');
      setLoading(false);
      return;
    }

    if (!/^[A-Za-z0-9_]+$/.test(username)) {
      setError('Username can only contain letters, numbers, and underscores');
      setLoading(false);
      return;
    }

    if (password.length < 8) {
      setError('Password must be at least 8 characters');
      setLoading(false);
      return;
    }

    if (!captchaId || captchaAnswer.trim() === '') {
      setError('Please solve the captcha');
      setLoading(false);
      return;
    }

    try {
      await register(username, email, password, captchaId, captchaAnswer.trim());
      navigate('/dashboard');
    } catch (err) {
      setError(err.response?.data?.message || 'Registration failed');
      await loadCaptcha();
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="content">
      <h1>Create Account</h1>
      <p className="mb-2">Join MyBlog and start sharing your thoughts securely.</p>

      {error && <div className="alert alert-error">{error}</div>}

      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label htmlFor="username">Username</label>
          <input
            type="text"
            id="username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
            autoComplete="username"
          />
        </div>

        <div className="form-group">
          <label htmlFor="email">Email</label>
          <input
            type="email"
            id="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            autoComplete="email"
          />
        </div>

        <div className="form-group">
          <label htmlFor="password">Password</label>
          <input
            type="password"
            id="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            minLength="8"
            autoComplete="new-password"
          />
        </div>

        <div className="form-group">
          <label htmlFor="captcha">Captcha: {captchaQuestion || 'Loading...'}</label>
          <input
            type="text"
            id="captcha"
            value={captchaAnswer}
            onChange={(e) => setCaptchaAnswer(e.target.value)}
            required
          />
          <button type="button" className="btn btn-secondary mt-1" onClick={loadCaptcha}>
            New Captcha
          </button>
        </div>

        <button type="submit" className="btn" disabled={loading}>
          {loading ? <span className="spinner"></span> : 'Create Account'}
        </button>
      </form>

      <div className="mt-2 text-center">
        <p>Already have an account? <Link to="/login">Login here</Link></p>
      </div>
    </div>
  );
};

export default Register;
