/**
 * LoginPage.jsx — Dark cybersecurity SaaS login page for AuthLens
 * Integrated with Express / PostgreSQL backend API.
 */
import React, { useState } from 'react';
import AuthShell from './AuthShell';
import { authApi } from '../../services/authApi';

export default function LoginPage({ onNavigate, onLoginSuccess, notificationNotice }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [rememberMe, setRememberMe] = useState(true);
  const [loading, setLoading] = useState(false);
  const [errors, setErrors] = useState({});
  const [generalError, setGeneralError] = useState('');

  function validate() {
    const errs = {};
    if (!email.trim()) {
      errs.email = 'Email address is required.';
    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      errs.email = 'Please enter a valid email address (e.g., name@company.corp).';
    }

    if (!password) {
      errs.password = 'Password is required.';
    } else if (password.length < 8) {
      errs.password = 'Password must be at least 8 characters.';
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
      const res = await authApi.login({ email: email.trim(), password });
      onLoginSuccess(res.user);
    } catch (err) {
      setGeneralError(err.message || 'Authentication failed. Please check your credentials.');
    } finally {
      setLoading(false);
    }
  }

  return (
    <AuthShell
      headline="Sign In to AuthLens"
      subheadline="Authentication security audits, vulnerability scanning, and WCAG accessibility diagnostics."
    >
      {notificationNotice && (
        <div className="notice success mb-16" role="status">
          <div>{notificationNotice}</div>
        </div>
      )}

      {generalError && (
        <div className="notice error mb-16" role="alert">
          <div>{generalError}</div>
        </div>
      )}

      <form onSubmit={handleSubmit} noValidate aria-label="Sign in form">
        {/* Email Field */}
        <div className="auth-input-group">
          <label className="auth-input-label" htmlFor="login-email">
            <span>Work Email</span>
          </label>
          <input
            id="login-email"
            type="email"
            className={`auth-input${errors.email ? ' has-error' : ''}`}
            placeholder="engineer@company.corp"
            autoComplete="username"
            value={email}
            onChange={(e) => {
              setEmail(e.target.value);
              if (errors.email) setErrors((prev) => ({ ...prev, email: '' }));
            }}
            disabled={loading}
            aria-invalid={errors.email ? 'true' : 'false'}
            aria-describedby={errors.email ? 'login-email-error' : undefined}
          />
          {errors.email && (
            <div className="auth-error-text" id="login-email-error" role="alert">
              <span>●</span> {errors.email}
            </div>
          )}
        </div>

        {/* Password Field */}
        <div className="auth-input-group">
          <div className="auth-input-label">
            <label htmlFor="login-password">Password</label>
            <button
              type="button"
              className="auth-link"
              style={{ background: 'none', border: 'none', padding: 0 }}
              onClick={() => onNavigate('forgot')}
            >
              Forgot password?
            </button>
          </div>
          <div className="auth-password-wrapper">
            <input
              id="login-password"
              type={showPassword ? 'text' : 'password'}
              className={`auth-input${errors.password ? ' has-error' : ''}`}
              placeholder="••••••••••••"
              autoComplete="current-password"
              value={password}
              onChange={(e) => {
                setPassword(e.target.value);
                if (errors.password) setErrors((prev) => ({ ...prev, password: '' }));
              }}
              disabled={loading}
              style={{ paddingRight: '60px' }}
              aria-invalid={errors.password ? 'true' : 'false'}
              aria-describedby={errors.password ? 'login-password-error' : undefined}
            />
            <button
              type="button"
              className="auth-password-toggle"
              onClick={() => setShowPassword((v) => !v)}
              aria-label={showPassword ? 'Hide password' : 'Show password'}
              tabIndex={0}
            >
              {showPassword ? 'HIDE' : 'SHOW'}
            </button>
          </div>
          {errors.password && (
            <div className="auth-error-text" id="login-password-error" role="alert">
              <span>●</span> {errors.password}
            </div>
          )}
        </div>

        {/* Remember Me */}
        <div className="auth-checkbox-row">
          <label className="auth-checkbox-label">
            <input
              type="checkbox"
              className="auth-checkbox"
              checked={rememberMe}
              onChange={(e) => setRememberMe(e.target.checked)}
              disabled={loading}
            />
            <span>Remember this device</span>
          </label>
        </div>

        {/* Submit Button */}
        <button
          id="btn-login-submit"
          type="submit"
          className="auth-submit-btn"
          disabled={loading}
        >
          {loading ? (
            <>
              <span className="spin">⟳</span>
              <span>Authenticating…</span>
            </>
          ) : (
            <span>Sign In to Console</span>
          )}
        </button>
      </form>

      {/* Footer Nav */}
      <div className="auth-footer-nav">
        <span>New to AuthLens? </span>
        <button
          type="button"
          className="auth-link"
          style={{ background: 'none', border: 'none', padding: 0, fontWeight: 500 }}
          onClick={() => onNavigate('register')}
        >
          Create an account
        </button>
      </div>
    </AuthShell>
  );
}
