/**
 * ForgotPasswordPage.jsx — Password recovery request for AuthLens
 * Integrated with Express / PostgreSQL backend API.
 */
import React, { useState } from 'react';
import AuthShell from './AuthShell';
import { authApi } from '../../services/authApi';

export default function ForgotPasswordPage({ onNavigate }) {
  const [email, setEmail] = useState('');
  const [loading, setLoading] = useState(false);
  const [submitted, setSubmitted] = useState(false);
  const [error, setError] = useState('');

  function validate() {
    if (!email.trim()) {
      setError('Email address is required.');
      return false;
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      setError('Please enter a valid email address.');
      return false;
    }
    setError('');
    return true;
  }

  async function handleSubmit(e) {
    e.preventDefault();
    if (!validate()) {
      return;
    }

    setLoading(true);
    try {
      await authApi.forgotPassword({ email: email.trim() });
      setSubmitted(true);
    } catch (err) {
      setError(err.message || 'Failed to dispatch password recovery. Please try again.');
    } finally {
      setLoading(false);
    }
  }

  return (
    <AuthShell
      headline="Reset Your Password"
      subheadline="Submit your registered work email to receive a secure, time-limited password recovery link."
    >
      {submitted ? (
        <div className="fade-in">
          <div className="notice success mb-16" role="status">
            <div>
              <strong>Recovery dispatched:</strong> If an active account exists for <code className="mono text-xs">{email}</code>, an authorization token has been generated and dispatched.
            </div>
          </div>

          <div className="card-xs mb-16" style={{ background: '#0B0D10', border: '1px solid #292F38', borderRadius: 'var(--r-md)', padding: '12px' }}>
            <div className="text-secondary text-xs" style={{ lineHeight: 1.5 }}>
              The recovery link is valid for <strong>15 minutes</strong> and enforces single-use token invalidation upon password reset.
            </div>
          </div>

          <button
            type="button"
            className="auth-submit-btn mb-12"
            onClick={() => onNavigate('login')}
          >
            Return to Sign In
          </button>

          <button
            type="button"
            className="btn btn-secondary btn-sm w-full"
            style={{ justifyContent: 'center' }}
            onClick={() => {
              setSubmitted(false);
              setEmail('');
            }}
          >
            Request for another email
          </button>
        </div>
      ) : (
        <form onSubmit={handleSubmit} noValidate aria-label="Password reset form">
          <div className="auth-input-group">
            <label className="auth-input-label" htmlFor="forgot-email">
              <span>Account Email</span>
            </label>
            <input
              id="forgot-email"
              type="email"
              className={`auth-input${error ? ' has-error' : ''}`}
              placeholder="engineer@company.corp"
              autoComplete="email"
              value={email}
              onChange={(e) => {
                setEmail(e.target.value);
                if (error) setError('');
              }}
              disabled={loading}
            />
            {error && (
              <div className="auth-error-text" role="alert">
                <span>●</span> {error}
              </div>
            )}
          </div>

          <button
            id="btn-forgot-submit"
            type="submit"
            className="auth-submit-btn mb-12"
            disabled={loading}
          >
            {loading ? (
              <>
                <span className="spin">⟳</span>
                <span>Generating Token…</span>
              </>
            ) : (
              <span>Send Recovery Link</span>
            )}
          </button>

          <div className="auth-footer-nav">
            <span>Remember your password? </span>
            <button
              type="button"
              className="auth-link"
              style={{ background: 'none', border: 'none', padding: 0, fontWeight: 500 }}
              onClick={() => onNavigate('login')}
            >
              Back to sign in
            </button>
          </div>
        </form>
      )}
    </AuthShell>
  );
}
