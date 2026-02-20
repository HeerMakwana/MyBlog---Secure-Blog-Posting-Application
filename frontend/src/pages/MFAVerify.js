import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

const MFAVerify = () => {
  const [code, setCode] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const { verifyMFA, mfaRequired } = useAuth();
  const navigate = useNavigate();

  // Redirect if MFA is not required
  React.useEffect(() => {
    if (!mfaRequired) {
      navigate('/login');
    }
  }, [mfaRequired, navigate]);

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
      await verifyMFA(code);
      navigate('/dashboard');
    } catch (err) {
      setError(err.response?.data?.message || 'Invalid code');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="content">
      <h1>Two-Factor Authentication</h1>
      <p className="mb-2">Enter the 6-digit code from your authenticator app.</p>

      {error && <div className="alert alert-error">{error}</div>}

      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label htmlFor="code">6-digit code</label>
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
              fontFamily: 'monospace'
            }}
            autoComplete="one-time-code"
          />
        </div>

        <button type="submit" className="btn" disabled={loading}>
          {loading ? <span className="spinner"></span> : 'Verify & Login'}
        </button>
      </form>

      <div className="mt-2">
        <button 
          onClick={() => navigate('/login')} 
          className="btn btn-secondary"
        >
          Cancel
        </button>
      </div>
    </div>
  );
};

export default MFAVerify;
