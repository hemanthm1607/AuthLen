/**
 * AuthShell.jsx — Reusable layout shell for AuthLens authentication screens
 */
import React from 'react';

export default function AuthShell({ headline, subheadline, children }) {
  return (
    <div className="auth-experience-wrapper">
      <div className="auth-experience-bg-glow" aria-hidden="true" />
      
      <div className="auth-card-panel fade-in">
        {/* Brand Header */}
        <div className="auth-brand-header">
          <div className="auth-brand-logo">
            <div className="logo-icon" aria-hidden="true">
              <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" style={{ width: 16, height: 16 }}>
                <path d="M10 2L3 6v5c0 4 3 7 7 7s7-3 7-7V6l-7-4z"/>
                <path d="M7 10l2 2 4-4" stroke="#2563EB" strokeWidth="1.6"/>
              </svg>
            </div>
            <div style={{ textAlign: 'left' }}>
              <div className="logo-text">Auth<span>Lens</span></div>
              <div className="logo-sub">Security Audit Platform</div>
            </div>
          </div>

          <h1 className="auth-headline">{headline}</h1>
          <p className="auth-subheadline">{subheadline}</p>
        </div>

        {/* Security Notice */}
        <div className="auth-demo-disclaimer" role="note">
          <svg viewBox="0 0 16 16" fill="none" stroke="#2563EB" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" style={{ width: 14, height: 14, flexShrink: 0 }}>
            <circle cx="8" cy="8" r="6.5"/>
            <path d="M8 5v3.5M8 11h.01"/>
          </svg>
          <div>
            <strong>Secure Session:</strong> Protected by bcrypt hashing, rate-limiting, and PostgreSQL session authentication.
          </div>
        </div>

        {/* Form Body */}
        {children}
      </div>
    </div>
  );
}
