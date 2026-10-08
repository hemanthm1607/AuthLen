/**
 * RegisterPage.jsx — Account registration for AuthLens
 * Integrated with Express / PostgreSQL backend API.
 */
import React, { useState } from 'react';
import AuthShell from './AuthShell';
import { authApi } from '../../services/authApi';

export default function RegisterPage({ onNavigate, onRegisterSuccess }) {
  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [errors, setErrors] = useState({});
  const [generalError, setGeneralError] = useState('');

  // Password requirement tests
  const reqLength = password.length >= 8;
  const reqUpper = /[A-Z]/.test(password);
  const reqNumberOrSpecial = /[\d\W_]/.test(password);
  const reqMatch = password.length > 0 && password === confirmPassword;

  function validate() {
    const errs = {};
    if (!fullName.trim()) {
      errs.fullName = 'Full name is required.';
    }

    if (!email.trim()) {
      errs.email = 'Email address is required.';
    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      errs.email = 'Please enter a valid email address.';
    }

    if (!password) {
      errs.password = 'Password is required.';
    } else if (!reqLength || !reqUpper || !reqNumberOrSpecial) {
      errs.password = 'Please satisfy all password complexity criteria below.';
    }

    if (!confirmPassword) {
      errs.confirmPassword = 'Confirm your password.';
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
      const res = await authApi.register({
        fullName: fullName.trim(),
        email: email.trim(),
        password,
      });
      onRegisterSuccess(res.user);
    } catch (err) {
      if (err.data?.field && err.data?.error) {
        setErrors((prev) => ({ ...prev, [err.data.field]: err.data.error }));
      }
      setGeneralError(err.message || 'Registration failed. Please check your details.');
    } finally {
      setLoading(false);
    }
  }

  return (
    <AuthShell
      headline="Create an AuthLens Account"
      subheadline="Deploy continuous security audits and compliance verifications across your authentication services."
    >
      {generalError && (
        <div className="notice error mb-16" role="alert">
          <div>{generalError}</div>
        </div>
      )}

      <form onSubmit={handleSubmit} noValidate aria-label="Registration form">
        {/* Full Name */}
        <div className="auth-input-group">
          <label className="auth-input-label" htmlFor="reg-name">
            <span>Full Name</span>
          </label>
          <input
            id="reg-name"
            type="text"
            className={`auth-input${errors.fullName ? ' has-error' : ''}`}
            placeholder="Alex Rivera"
            autoComplete="name"
            value={fullName}
            onChange={(e) => {
              setFullName(e.target.value);
              if (errors.fullName) setErrors((prev) => ({ ...prev, fullName: '' }));
            }}
            disabled={loading}
            aria-invalid={errors.fullName ? 'true' : 'false'}
            aria-describedby={errors.fullName ? 'reg-name-error' : undefined}
          />
          {errors.fullName && (
            <div className="auth-error-text" id="reg-name-error" role="alert">
              <span>●</span> {errors.fullName}
            </div>
          )}
        </div>

        {/* Email */}
        <div className="auth-input-group">
          <label className="auth-input-label" htmlFor="reg-email">
            <span>Work Email</span>
          </label>
          <input
            id="reg-email"
            type="email"
            className={`auth-input${errors.email ? ' has-error' : ''}`}
            placeholder="alex@company.corp"
            autoComplete="email"
            value={email}
            onChange={(e) => {
              setEmail(e.target.value);
              if (errors.email) setErrors((prev) => ({ ...prev, email: '' }));
            }}
            disabled={loading}
            aria-invalid={errors.email ? 'true' : 'false'}
            aria-describedby={errors.email ? 'reg-email-error' : undefined}
          />
          {errors.email && (
            <div className="auth-error-text" id="reg-email-error" role="alert">
              <span>●</span> {errors.email}
            </div>
          )}
        </div>

        {/* Password */}
        <div className="auth-input-group">
          <label className="auth-input-label" htmlFor="reg-password">
            <span>Password</span>
          </label>
          <div className="auth-password-wrapper">
            <input
              id="reg-password"
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
              aria-describedby={errors.password ? 'reg-password-error' : undefined}
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
            <div className="auth-error-text" id="reg-password-error" role="alert">
              <span>●</span> {errors.password}
            </div>
          )}
        </div>

        {/* Confirm Password */}
        <div className="auth-input-group">
          <label className="auth-input-label" htmlFor="reg-confirm">
            <span>Confirm Password</span>
          </label>
          <div className="auth-password-wrapper">
            <input
              id="reg-confirm"
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
              aria-describedby={errors.confirmPassword ? 'reg-confirm-error' : undefined}
            />
            <button
              type="button"
              className="auth-password-toggle"
              onClick={() => setShowConfirmPassword((v) => !v)}
              aria-label={showConfirmPassword ? 'Hide confirm password' : 'Show confirm password'}
            >
              {showConfirmPassword ? 'HIDE' : 'SHOW'}
            </button>
          </div>
          {errors.confirmPassword && (
            <div className="auth-error-text" id="reg-confirm-error" role="alert">
              <span>●</span> {errors.confirmPassword}
            </div>
          )}
        </div>

        {/* Password Requirements Checklist */}
        <div className="password-requirements-card mb-16" aria-label="Password requirements">
          <div className="text-muted text-xs mono" style={{ marginBottom: '6px', fontWeight: 600 }}>
            PASSWORD COMPLEXITY POLICY
          </div>
          <div className={`req-item${reqLength ? ' met' : ''}`}>
            <span className="req-icon">{reqLength ? '✓' : '○'}</span>
            <span>At least 8 characters in length</span>
          </div>
          <div className={`req-item${reqUpper ? ' met' : ''}`}>
            <span className="req-icon">{reqUpper ? '✓' : '○'}</span>
            <span>At least one uppercase character (A–Z)</span>
          </div>
          <div className={`req-item${reqNumberOrSpecial ? ' met' : ''}`}>
            <span className="req-icon">{reqNumberOrSpecial ? '✓' : '○'}</span>
            <span>At least one number or special symbol</span>
          </div>
          <div className={`req-item${reqMatch ? ' met' : ''}`}>
            <span className="req-icon">{reqMatch ? '✓' : '○'}</span>
            <span>Password confirmation matches</span>
          </div>
        </div>

        {/* Submit */}
        <button
          id="btn-register-submit"
          type="submit"
          className="auth-submit-btn"
          disabled={loading}
        >
          {loading ? (
            <>
              <span className="spin">⟳</span>
              <span>Creating Account…</span>
            </>
          ) : (
            <span>Create Developer Account</span>
          )}
        </button>
      </form>

      {/* Footer Nav */}
      <div className="auth-footer-nav">
        <span>Already have an account? </span>
        <button
          type="button"
          className="auth-link"
          style={{ background: 'none', border: 'none', padding: 0, fontWeight: 500 }}
          onClick={() => onNavigate('login')}
        >
          Sign in
        </button>
      </div>
    </AuthShell>
  );
}
