import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import api from '../services/api';

const Login = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [captchaId, setCaptchaId] = useState('');
  const [captchaQuestion, setCaptchaQuestion] = useState('');
  const [captchaAnswer, setCaptchaAnswer] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const { login, isAuthenticated } = useAuth();
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

    if (!captchaId || captchaAnswer.trim() === '') {
      setError('Please solve the captcha');
      setLoading(false);
      return;
    }

    try {
      const result = await login(username, password, captchaId, captchaAnswer.trim());
      if (result.success) {
        navigate('/dashboard');
      }
    } catch (err) {
      setError(err.response?.data?.message || 'Invalid credentials');
      await loadCaptcha();
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="content">
      <h1>Login to MyBlog</h1>
      <p className="mb-2">Access your secure blogging dashboard.</p>

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

        <div className="form-group">
          <label htmlFor="password">Password</label>
          <input
            type="password"
            id="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            autoComplete="current-password"
          />
        </div>

        <button type="submit" className="btn" disabled={loading}>
          {loading ? <span className="spinner"></span> : 'Login'}
        </button>
      </form>

      <div className="mt-2 text-center">
        <p>Don't have an account? <Link to="/register">Register here</Link></p>
      </div>
    </div>
  );
};

export default Login;
