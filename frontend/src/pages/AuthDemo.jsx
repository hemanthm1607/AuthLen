/**
 * AuthDemo.jsx — Interactive authentication demonstration playground
 * Simulated auth testing sandbox — no credentials transmitted
 */
import React, { useState } from 'react';

const SCENARIOS = [
  { id: 'normal',     label: 'Valid Authentication', desc: 'Standard successful sign-in flow' },
  { id: 'wrong-pass', label: 'Invalid Password',     desc: 'Non-matching credentials handling' },
  { id: 'locked',     label: 'Account Lockout',      desc: 'Lockout threshold trigger simulation' },
  { id: 'otp',        label: 'MFA Verification',     desc: 'Time-based OTP token flow' },
  { id: 'forgot',     label: 'Password Recovery',    desc: 'Self-service reset dispatch flow' },
];

const SCENARIO_NOTICES = {
  'wrong-pass': { type: 'error',   msg: 'Invalid email address or password. Please verify and retry.' },
  'locked':     { type: 'error',   msg: 'Account temporarily locked after 5 failed authentication attempts.' },
  'normal':     { type: 'success', msg: 'Session established successfully. Authenticated as developer@example.com' },
};

export default function AuthDemo() {
  const [activeTab, setActiveTab]         = useState('login');
  const [scenario, setScenario]           = useState(null);
  const [showPass, setShowPass]           = useState(false);
  const [captcha, setCaptcha]             = useState(false);
  const [loading, setLoading]             = useState(false);
  const [otp, setOtp]                     = useState(['', '', '', '', '', '']);
  const [otpAttempts, setOtpAttempts]     = useState(0);
  const [otpStatus, setOtpStatus]         = useState(null);
  const [email, setEmail]                 = useState('');
  const [recoverySubmitted, setRecoverySubmitted] = useState(false);

  const activeNotice = scenario ? SCENARIO_NOTICES[scenario] : null;

  function handleLogin(e) {
    e.preventDefault();
    if (!captcha && scenario !== 'locked') {
      return;
    }
    setLoading(true);
    setTimeout(() => {
      setLoading(false);
      if (!scenario) setScenario('normal');
    }, 1000);
  }

  function handleScenario(id) {
    setScenario(id);
    setCaptcha(false);
    setLoading(false);
    if (id === 'otp') setActiveTab('otp');
    else if (id === 'forgot') setActiveTab('forgot');
    else setActiveTab('login');
  }

  function handleOtpChange(idx, val) {
    if (!/^\d?$/.test(val)) return;
    const next = [...otp];
    next[idx] = val;
    setOtp(next);
    if (val && idx < 5) {
      document.getElementById(`otp-${idx + 1}`)?.focus();
    }
  }

  function handleVerifyOtp() {
    const code = otp.join('');
    const newAttempts = otpAttempts + 1;
    setOtpAttempts(newAttempts);
    if (code === '123456') {
      setOtpStatus({ type: 'success', msg: 'MFA token validated successfully. Session token generated.' });
    } else if (newAttempts >= 5) {
      setOtpStatus({ type: 'error', msg: 'Assertion SEC-001 flagged: 5+ failed OTP verification attempts permitted without rate limit.' });
    } else {
      setOtpStatus({ type: 'error', msg: `Invalid verification token. Attempt ${newAttempts} recorded — no rate limiting throttle active.` });
    }
  }

  return (
    <div className="fade-in">
      <div className="page-header">
        <div className="page-header-row">
          <div>
            <h1 className="page-title">Authentication Lab</h1>
            <p className="page-subtitle">Interactive authentication harness for security, usability, and a11y probing</p>
          </div>
          <span className="badge badge-sample">Testing Sandbox</span>
        </div>
      </div>

      <div className="page-body">
        <div className="auth-demo-container">
          {/* Auth form card */}
          <div className="auth-form-card">
            <div className="auth-form-tabs" role="tablist">
              {[
                { id: 'login',    label: 'Sign In' },
                { id: 'register', label: 'Register' },
                { id: 'otp',      label: 'MFA Challenge' },
                { id: 'forgot',   label: 'Reset Password' },
              ].map((t) => (
                <button
                  key={t.id}
                  id={`auth-tab-${t.id}`}
                  role="tab"
                  aria-selected={activeTab === t.id}
                  className={`auth-tab${activeTab === t.id ? ' active' : ''}`}
                  onClick={() => { setActiveTab(t.id); setScenario(null); }}
                >
                  {t.label}
                </button>
              ))}
            </div>

            <div className="auth-form-body">
              {/* ── Login Tab ── */}
              {activeTab === 'login' && (
                <form onSubmit={handleLogin} noValidate aria-label="Login form">
                  <div style={{ marginBottom: '18px' }}>
                    <div style={{ fontSize: '16px', fontWeight: 600 }}>Authenticate to account</div>
                    <div className="text-secondary text-xs" style={{ marginTop: '2px' }}>
                      Controlled environment with injectable attack vectors
                    </div>
                  </div>

                  {activeNotice && (
                    <div className={`notice ${activeNotice.type} mb-12`} role="alert">
                      {activeNotice.msg}
                    </div>
                  )}

                  {scenario === 'locked' && (
                    <div className="notice error mb-12" role="alert">
                      Account locked after 5 failed attempts. Verification threshold SEC-005 triggered.
                    </div>
                  )}

                  <div className="form-group">
                    <label htmlFor="demo-email">Account Email</label>
                    <div className="input-wrap">
                      <input
                        id="demo-email"
                        type="email"
                        placeholder="developer@example.com"
                        autoComplete="username"
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                        disabled={scenario === 'locked'}
                      />
                    </div>
                  </div>

                  <div className="form-group">
                    <label htmlFor="demo-password">Password</label>
                    <div className="input-wrap">
                      <input
                        id="demo-password"
                        type={showPass ? 'text' : 'password'}
                        placeholder="••••••••••••"
                        autoComplete="current-password"
                        disabled={scenario === 'locked'}
                      />
                      <button
                        type="button"
                        className="input-toggle"
                        onClick={() => setShowPass((v) => !v)}
                        aria-label={showPass ? 'Hide password' : 'Show password'}
                        aria-pressed={showPass}
                      >
                        <span className="mono text-xs" style={{ color: 'var(--text-muted)' }}>
                          {showPass ? 'HIDE' : 'SHOW'}
                        </span>
                      </button>
                    </div>
                  </div>

                  {/* CAPTCHA */}
                  <div className="form-group">
                    <div
                      className="captcha-box"
                      onClick={() => setCaptcha((v) => !v)}
                      role="checkbox"
                      aria-checked={captcha}
                      tabIndex={0}
                      onKeyDown={(e) => e.key === ' ' && setCaptcha((v) => !v)}
                      aria-label="Bot verification"
                    >
                      <div className={`captcha-checkbox${captcha ? ' checked' : ''}`} aria-hidden="true">
                        {captcha && '✓'}
                      </div>
                      <span className="captcha-label">Verify browser integrity</span>
                      <span className="captcha-logo">BotGuard<br /><span style={{ fontSize: '9px', opacity: 0.6 }}>Demo Harness</span></span>
                    </div>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px' }}>
                    <label style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '12px', color: 'var(--text-secondary)', fontWeight: 400, margin: 0 }}>
                      <input type="checkbox" style={{ width: 'auto' }} /> Keep session active
                    </label>
                    <a href="#" style={{ fontSize: '12px' }} onClick={(e) => { e.preventDefault(); setActiveTab('forgot'); }}>
                      Forgot password?
                    </a>
                  </div>

                  <button
                    id="login-submit-btn"
                    type="submit"
                    className="auth-btn"
                    disabled={loading || scenario === 'locked'}
                  >
                    {loading ? <span className="spin" style={{ marginRight: '6px' }}>⟳</span> : null}
                    {loading ? 'Authenticating…' : 'Sign In'}
                  </button>
                </form>
              )}

              {/* ── Register Tab ── */}
              {activeTab === 'register' && (
                <form onSubmit={(e) => e.preventDefault()} aria-label="Register form">
                  <div style={{ marginBottom: '18px' }}>
                    <div style={{ fontSize: '16px', fontWeight: 600 }}>Create developer account</div>
                    <div className="text-secondary text-xs" style={{ marginTop: '2px' }}>
                      Registration entropy and password complexity test harness
                    </div>
                  </div>
                  <div className="form-group">
                    <label htmlFor="reg-name">Full Name</label>
                    <input id="reg-name" type="text" placeholder="Dev Engineer" />
                  </div>
                  <div className="form-group">
                    <label htmlFor="reg-email">Work Email</label>
                    <input id="reg-email" type="email" placeholder="engineer@company.corp" />
                  </div>
                  <div className="form-group">
                    <label htmlFor="reg-password">Password</label>
                    <div className="input-wrap">
                      <input id="reg-password" type={showPass ? 'text' : 'password'} placeholder="Min. 12 characters" />
                      <button type="button" className="input-toggle" onClick={() => setShowPass(v => !v)}>
                        <span className="mono text-xs" style={{ color: 'var(--text-muted)' }}>
                          {showPass ? 'HIDE' : 'SHOW'}
                        </span>
                      </button>
                    </div>
                  </div>
                  <div className="form-group">
                    <label htmlFor="reg-confirm">Confirm Password</label>
                    <input id="reg-confirm" type="password" placeholder="Re-enter password" />
                  </div>
                  <button type="submit" className="auth-btn">Create Account</button>
                  <div className="notice info mt-12">
                    Simulated enrollment flow &mdash; database mutations are suppressed.
                  </div>
                </form>
              )}

              {/* ── OTP Tab ── */}
              {activeTab === 'otp' && (
                <div>
                  <div style={{ marginBottom: '18px' }}>
                    <div style={{ fontSize: '16px', fontWeight: 600 }}>Multi-Factor Verification</div>
                    <p className="text-secondary text-xs" style={{ marginTop: '2px' }}>
                      Enter the 6-digit TOTP code dispatched to registered device.<br />
                      <span className="text-muted">Simulated valid token: <code className="mono text-xs" style={{ color: 'var(--accent)' }}>123456</code></span>
                    </p>
                  </div>

                  {otpStatus && (
                    <div className={`notice ${otpStatus.type} mb-12`} role="alert">
                      {otpStatus.msg}
                    </div>
                  )}

                  <div className="form-group">
                    <label>TOTP Token</label>
                    <div className="otp-inputs">
                      {otp.map((digit, idx) => (
                        <input
                          key={idx}
                          id={`otp-${idx}`}
                          className="otp-input"
                          type="text"
                          inputMode="numeric"
                          maxLength={1}
                          value={digit}
                          onChange={(e) => handleOtpChange(idx, e.target.value)}
                          aria-label={`OTP digit ${idx + 1}`}
                        />
                      ))}
                    </div>
                  </div>

                  <button id="otp-verify-btn" className="auth-btn" onClick={handleVerifyOtp} style={{ marginBottom: '12px' }}>
                    Verify Token
                  </button>

                  {otpAttempts > 0 && (
                    <div className="notice warning">
                      <strong>Audit finding SEC-001 active:</strong> Attempt count ({otpAttempts}) indicates unrestricted brute-force potential.
                    </div>
                  )}
                </div>
              )}

              {/* ── Forgot Password Tab ── */}
              {activeTab === 'forgot' && (
                <div>
                  <div style={{ marginBottom: '18px' }}>
                    <div style={{ fontSize: '16px', fontWeight: 600 }}>Account Recovery Dispatch</div>
                    <p className="text-secondary text-xs" style={{ marginTop: '2px' }}>
                      Submit target account identifier to test enumeration behavior.
                    </p>
                  </div>

                  {!recoverySubmitted ? (
                    <>
                      <div className="form-group">
                        <label htmlFor="forgot-email">Account Email</label>
                        <input
                          id="forgot-email"
                          type="email"
                          placeholder="dev@example.corp"
                          value={email}
                          onChange={(e) => setEmail(e.target.value)}
                        />
                      </div>
                      <button
                        id="forgot-submit-btn"
                        className="auth-btn"
                        onClick={() => setRecoverySubmitted(true)}
                        disabled={!email}
                      >
                        Request Recovery Link
                      </button>
                      <div className="notice warning mt-12">
                        <strong>Probe Target (REC-003):</strong> Checks whether the endpoint leaks user existence via response headers or timing discrepancies.
                      </div>
                    </>
                  ) : (
                    <div>
                      <div className="notice success mb-12">
                        If an account matches <strong>{email}</strong>, a recovery token has been queued.
                      </div>
                      <p className="text-secondary text-xs">
                        Uniform response pattern prevents email enumeration attacks by giving identical feedback regardless of whether the email exists.
                      </p>
                      <button
                        className="btn btn-secondary btn-xs mt-12"
                        onClick={() => { setRecoverySubmitted(false); setEmail(''); }}
                      >
                        Test Alternative Email
                      </button>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>

          {/* Test Controls Side Panel */}
          <div className="demo-controls-panel">
            <div className="demo-controls-card">
              <div className="demo-controls-title">Inject Attack Scenarios</div>
              {SCENARIOS.map((s) => (
                <button
                  key={s.id}
                  id={`scenario-${s.id}`}
                  className={`demo-scenario-btn${scenario === s.id ? ' active' : ''}`}
                  onClick={() => handleScenario(s.id)}
                >
                  <div style={{ textAlign: 'left' }}>
                    <div style={{ fontWeight: 600, fontSize: '12px' }}>{s.label}</div>
                    <div className="text-muted text-xs">{s.desc}</div>
                  </div>
                </button>
              ))}
            </div>

            <div className="demo-controls-card">
              <div className="demo-controls-title">Active Test Assertions</div>
              {[
                { id: 'SEC-001', label: 'Rate Limiting / Throttle Rules' },
                { id: 'SEC-002', label: 'CSRF Token Origin & Entropy' },
                { id: 'A11Y-001', label: 'ARIA Live & Screen Reader Focus' },
                { id: 'USAB-001', label: 'Password Masking Visibility Toggle' },
                { id: 'REC-001', label: 'Token Expiration & Single-Use Burning' },
              ].map((item) => (
                <div
                  key={item.id}
                  style={{
                    fontSize: '12px',
                    color: 'var(--text-secondary)',
                    padding: '6px 0',
                    borderBottom: '1px solid var(--border-subtle)',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '8px',
                  }}
                >
                  <span className="mono text-xs" style={{ color: 'var(--text-muted)' }}>{item.id}</span>
                  <span style={{ flex: 1 }}>{item.label}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
