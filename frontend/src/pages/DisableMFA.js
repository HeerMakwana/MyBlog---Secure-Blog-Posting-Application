import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import api from '../services/api';

const DisableMFA = () => {
  const [code, setCode] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    if (!code || code.length !== 6) {
      setError('Please enter a valid 6-digit code');
      setLoading(false);
      return;
    }

    try {
      await api.post('/auth/disable-mfa', { code });
      navigate('/dashboard?mfa=disabled');
    } catch (err) {
      setError(err.response?.data?.message || 'Invalid code');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="content">
      <h1>Disable Multi-Factor Authentication</h1>
      <p className="mb-2">Enter your current MFA code to disable two-factor authentication.</p>

      <div className="alert alert-info mb-3">
        <strong>Warning:</strong> Disabling MFA will make your account less secure. 
        Only disable if necessary.
      </div>

      {error && <div className="alert alert-error">{error}</div>}

      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label htmlFor="code">Current 6-digit code</label>
          <input
            type="text"
            id="code"
            value={code}
            onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
            required
            pattern="\d{6}"
            maxLength="6"
            placeholder="000000"
            style={{ 
              fontSize: '1.5rem', 
              textAlign: 'center', 
              letterSpacing: '0.5rem',
              fontFamily: 'monospace',
              maxWidth: '200px'
            }}
            autoComplete="one-time-code"
          />
        </div>

        <button type="submit" className="btn btn-danger" disabled={loading}>
          {loading ? <span className="spinner"></span> : 'Disable MFA'}
        </button>
        <Link to="/dashboard" className="btn btn-secondary" style={{ marginLeft: '1rem' }}>
          Cancel
        </Link>
      </form>
    </div>
  );
};

export default DisableMFA;
