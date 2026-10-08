/**
 * ResetPasswordPage.jsx — Password reset form for AuthLens
 * Consumes single-use reset token and sets new password.
 */
import React, { useState } from 'react';
import AuthShell from './AuthShell';
import { authApi } from '../../services/authApi';

export default function ResetPasswordPage({ onNavigate, initialToken = '' }) {
  const [token, setToken] = useState(initialToken);
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState(false);
  const [errors, setErrors] = useState({});
  const [generalError, setGeneralError] = useState('');

  // Password requirements
  const reqLength = password.length >= 8;
  const reqUpper = /[A-Z]/.test(password);
  const reqNumberOrSpecial = /[\d\W_]/.test(password);
  const reqMatch = password.length > 0 && password === confirmPassword;

  function validate() {
    const errs = {};
    if (!token.trim()) {
      errs.token = 'Reset token is required.';
    }

    if (!password) {
      errs.password = 'New password is required.';
    } else if (!reqLength || !reqUpper || !reqNumberOrSpecial) {
      errs.password = 'Please satisfy all password complexity criteria.';
    }

    if (!confirmPassword) {
      errs.confirmPassword = 'Confirm your new password.';
    } else if (password !== confirmPassword) {
      errs.confirmPassword = 'Passwords do not match.';
    }

    setErrors(errs);
    return Object.keys(errs).length === 0;
  }

  async function handleSubmit(e) {
    e.preventDefault();
    setGeneralError('');

    if (!validate()) {
      return;
    }

    setLoading(true);
    try {
      await authApi.resetPassword({
        token: token.trim(),
        newPassword: password,
      });
      setSuccess(true);
    } catch (err) {
      setGeneralError(err.message || 'Password reset failed. The link may have expired or already been used.');
    } finally {
      setLoading(false);
    }
  }

  return (
    <AuthShell
      headline="Set New Password"
      subheadline="Create a strong, unique password to secure your AuthLens console account."
    >
      {generalError && (
        <div className="notice error mb-16" role="alert">
          <div>{generalError}</div>
        </div>
      )}

      {success ? (
        <div className="fade-in">
          <div className="notice success mb-16" role="status">
            <div>
              <strong>Password updated!</strong> Your password has been changed and all prior active sessions have been invalidated.
            </div>
          </div>

          <button
            id="btn-return-login"
            type="button"
            className="auth-submit-btn"
            onClick={() => onNavigate('login')}
          >
            Sign In with New Password
          </button>
        </div>
      ) : (
        <form onSubmit={handleSubmit} noValidate aria-label="Set new password form">
          {/* Token input (shown if token not in URL) */}
          {!initialToken && (
            <div className="auth-input-group">
              <label className="auth-input-label" htmlFor="reset-token">
                <span>Reset Authorization Token</span>
              </label>
              <input
                id="reset-token"
                type="text"
                className={`auth-input${errors.token ? ' has-error' : ''}`}
                placeholder="Paste the reset token from your email"
                value={token}
                onChange={(e) => {
                  setToken(e.target.value);
                  if (errors.token) setErrors((prev) => ({ ...prev, token: '' }));
                }}
                disabled={loading}
              />
              {errors.token && (
                <div className="auth-error-text" role="alert">
                  <span>●</span> {errors.token}
                </div>
              )}
            </div>
          )}

          {/* New Password */}
          <div className="auth-input-group">
            <label className="auth-input-label" htmlFor="new-password">
              <span>New Password</span>
            </label>
            <div className="auth-password-wrapper">
              <input
                id="new-password"
                type={showPassword ? 'text' : 'password'}
                className={`auth-input${errors.password ? ' has-error' : ''}`}
                placeholder="••••••••••••"
                autoComplete="new-password"
                value={password}
                onChange={(e) => {
                  setPassword(e.target.value);
                  if (errors.password) setErrors((prev) => ({ ...prev, password: '' }));
                }}
                disabled={loading}
                style={{ paddingRight: '60px' }}
                aria-invalid={errors.password ? 'true' : 'false'}
                aria-describedby={errors.password ? 'new-password-error' : undefined}
              />
              <button
                type="button"
                className="auth-password-toggle"
                onClick={() => setShowPassword((v) => !v)}
                aria-label={showPassword ? 'Hide password' : 'Show password'}
              >
                {showPassword ? 'HIDE' : 'SHOW'}
              </button>
            </div>
            {errors.password && (
              <div className="auth-error-text" id="new-password-error" role="alert">
                <span>●</span> {errors.password}
              </div>
            )}
          </div>

          {/* Confirm New Password */}
          <div className="auth-input-group">
            <label className="auth-input-label" htmlFor="confirm-new-password">
              <span>Confirm New Password</span>
            </label>
            <div className="auth-password-wrapper">
              <input
                id="confirm-new-password"
                type={showConfirmPassword ? 'text' : 'password'}
                className={`auth-input${errors.confirmPassword ? ' has-error' : ''}`}
                placeholder="••••••••••••"
                autoComplete="new-password"
                value={confirmPassword}
                onChange={(e) => {
                  setConfirmPassword(e.target.value);
                  if (errors.confirmPassword) setErrors((prev) => ({ ...prev, confirmPassword: '' }));
                }}
                disabled={loading}
                style={{ paddingRight: '60px' }}
                aria-invalid={errors.confirmPassword ? 'true' : 'false'}
                aria-describedby={errors.confirmPassword ? 'confirm-new-password-error' : undefined}
              />
              <button
                type="button"
                className="auth-password-toggle"
                onClick={() => setShowConfirmPassword((v) => !v)}
                aria-label={showConfirmPassword ? 'Hide password' : 'Show password'}
              >
                {showConfirmPassword ? 'HIDE' : 'SHOW'}
              </button>
            </div>
            {errors.confirmPassword && (
              <div className="auth-error-text" id="confirm-new-password-error" role="alert">
                <span>●</span> {errors.confirmPassword}
              </div>
            )}
          </div>

          {/* Password Requirements Checklist */}
          <div className="card-xs mb-16" style={{ background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 'var(--r-md)', padding: '12px' }}>
            <div className="text-xs text-muted mb-2" style={{ fontWeight: 600 }}>Password Requirements:</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', fontSize: '11px' }}>
              <div style={{ color: reqLength ? 'var(--success)' : 'var(--text-muted)' }}>
                {reqLength ? '✓' : '○'} At least 8 characters
              </div>
              <div style={{ color: reqUpper ? 'var(--success)' : 'var(--text-muted)' }}>
                {reqUpper ? '✓' : '○'} At least one uppercase letter (A-Z)
              </div>
              <div style={{ color: reqNumberOrSpecial ? 'var(--success)' : 'var(--text-muted)' }}>
                {reqNumberOrSpecial ? '✓' : '○'} At least one number or special symbol
              </div>
              <div style={{ color: reqMatch ? 'var(--success)' : 'var(--text-muted)' }}>
                {reqMatch ? '✓' : '○'} Passwords match
              </div>
            </div>
          </div>

          {/* Submit */}
          <button
            id="btn-reset-submit"
            type="submit"
            className="auth-submit-btn mb-12"
            disabled={loading}
          >
            {loading ? (
              <>
                <span className="spin">⟳</span>
                <span>Updating Password…</span>
              </>
            ) : (
              <span>Reset Password & Invalidate Sessions</span>
            )}
          </button>

          <div className="auth-footer-nav">
            <button
              type="button"
              className="auth-link"
              style={{ background: 'none', border: 'none', padding: 0 }}
              onClick={() => onNavigate('login')}
            >
              Cancel and return to Sign In
            </button>
          </div>
        </form>
      )}
    </AuthShell>
  );
}
