import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import api from '../services/api';

const EnableMFA = () => {
  const [step, setStep] = useState(1);
  const [secret, setSecret] = useState('');
  const [qrCode, setQrCode] = useState('');
  const [code, setCode] = useState('');
  const [devCode, setDevCode] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleGenerateSecret = async () => {
    setError('');
    setLoading(true);

    try {
      const response = await api.post('/auth/enable-mfa');
      setSecret(response.data.secret);
      setQrCode(response.data.qrCode);
      if (response.data.currentCode) {
        setDevCode(response.data.currentCode);
      }
      setStep(2);
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to generate MFA secret');
    } finally {
      setLoading(false);
    }
  };

  const handleVerify = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    if (!code || code.length !== 6) {
      setError('Please enter a valid 6-digit code');
      setLoading(false);
      return;
    }

    try {
      await api.post('/auth/confirm-mfa', { secret, code });
      navigate('/dashboard?mfa=enabled');
    } catch (err) {
      setError(err.response?.data?.message || 'Invalid code. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="content">
      <h1>Enable Multi-Factor Authentication</h1>
      <p className="mb-2">Add an extra layer of security to your account.</p>

      {error && <div className="alert alert-error">{error}</div>}

      {step === 1 && (
        <div>
          <div className="mb-3" style={{ 
            background: 'linear-gradient(135deg, #f0f9ff 0%, #e0f2fe 100%)',
            padding: '2rem',
            borderRadius: '16px'
          }}>
            <h3>Why enable MFA?</h3>
            <ul style={{ marginTop: '1rem', paddingLeft: '1.5rem', color: '#4a5568' }}>
              <li>Protects your account even if your password is compromised</li>
              <li>Adds an extra verification step using your phone</li>
              <li>Required for high-security applications</li>
            </ul>
          </div>

          <button onClick={handleGenerateSecret} className="btn" disabled={loading}>
            {loading ? <span className="spinner"></span> : 'Set Up MFA'}
          </button>
          <Link to="/dashboard" className="btn btn-secondary" style={{ marginLeft: '1rem' }}>
            Cancel
          </Link>
        </div>
      )}

      {step === 2 && (
        <div>
          <div className="mb-3">
            <h3>Step 1: Scan this QR code</h3>
            <p style={{ color: '#718096' }}>
              Use an authenticator app like Google Authenticator or Authy to scan this code.
            </p>
          </div>

          <div className="qr-container">
            <img src={qrCode} alt="MFA QR Code" />
          </div>

          <div className="mb-3" style={{ 
            background: '#f8fafc',
            padding: '1rem',
            borderRadius: '8px'
          }}>
            <p style={{ marginBottom: '0.5rem', color: '#4a5568', fontWeight: '600' }}>
              Can't scan? Enter this code manually:
            </p>
            <code style={{ 
              background: '#e2e8f0',
              padding: '0.5rem 1rem',
              borderRadius: '4px',
              fontFamily: 'monospace',
              fontSize: '1rem',
              letterSpacing: '0.1rem'
            }}>
              {secret}
            </code>
          </div>

          {devCode && (
            <div className="alert alert-info mb-3">
              <strong>Development Mode:</strong> Current code is <code style={{ fontWeight: 'bold' }}>{devCode}</code>
            </div>
          )}

          <div className="mb-3">
            <h3>Step 2: Enter the 6-digit code</h3>
            <p style={{ color: '#718096' }}>
              Enter the code shown in your authenticator app to verify setup.
            </p>
          </div>

          <form onSubmit={handleVerify}>
            <div className="form-group">
              <label htmlFor="code">Verification Code</label>
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

            <button type="submit" className="btn" disabled={loading}>
              {loading ? <span className="spinner"></span> : 'Verify & Enable MFA'}
            </button>
            <Link to="/dashboard" className="btn btn-secondary" style={{ marginLeft: '1rem' }}>
              Cancel
            </Link>
          </form>
        </div>
      )}
    </div>
  );
};

export default EnableMFA;
