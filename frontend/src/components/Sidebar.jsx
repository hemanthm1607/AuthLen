/**
 * Sidebar.jsx — Refined navigation sidebar with SVG icons
 */
import React from 'react';

/* Inline SVG icon set — monochrome, consistent stroke weight */
const Icons = {
  dashboard: (
    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round">
      <rect x="1" y="1" width="6" height="6" rx="1"/>
      <rect x="9" y="1" width="6" height="6" rx="1"/>
      <rect x="1" y="9" width="6" height="6" rx="1"/>
      <rect x="9" y="9" width="6" height="6" rx="1"/>
    </svg>
  ),
  authDemo: (
    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round">
      <rect x="2" y="6" width="12" height="8" rx="1.5"/>
      <path d="M5 6V4.5a3 3 0 016 0V6"/>
      <circle cx="8" cy="10" r="1" fill="currentColor" stroke="none"/>
    </svg>
  ),
  security: (
    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round">
      <path d="M8 1.5L2 4v4c0 3.3 2.5 5.7 6 6.5 3.5-.8 6-3.2 6-6.5V4L8 1.5z"/>
    </svg>
  ),
  usability: (
    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="8" cy="8" r="6.5"/>
      <path d="M5.5 9.5s.8 1.5 2.5 1.5 2.5-1.5 2.5-1.5"/>
      <circle cx="6" cy="6.5" r=".75" fill="currentColor" stroke="none"/>
      <circle cx="10" cy="6.5" r=".75" fill="currentColor" stroke="none"/>
    </svg>
  ),
  recovery: (
    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round">
      <path d="M2.5 8A5.5 5.5 0 1114 8"/>
      <path d="M2.5 5v3h3"/>
    </svg>
  ),
  ai: (
    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round">
      <path d="M8 1v14M1 8h14"/>
      <circle cx="8" cy="8" r="3"/>
    </svg>
  ),
  history: (
    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="8" cy="8" r="6.5"/>
      <path d="M8 4.5V8l2.5 2"/>
    </svg>
  ),
  settings: (
    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="8" cy="8" r="2"/>
      <path d="M8 1.5v1M8 13.5v1M1.5 8h1M13.5 8h1M3.2 3.2l.7.7M12.1 12.1l.7.7M3.2 12.8l.7-.7M12.1 3.9l.7-.7"/>
    </svg>
  ),
  wordmark: (
    <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M10 2L3 6v5c0 4 3 7 7 7s7-3 7-7V6l-7-4z"/>
      <path d="M7 10l2 2 4-4" stroke="#6EA8FE" strokeWidth="1.6"/>
    </svg>
  ),
  logout: (
    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round">
      <path d="M6 14H3a1 1 0 01-1-1V3a1 1 0 011-1h3"/>
      <path d="M10 11l3-3-3-3"/>
      <path d="M13 8H6"/>
    </svg>
  ),
};

const NAV_SECTIONS = [
  {
    label: 'Overview',
    items: [
      { id: 'dashboard', icon: Icons.dashboard, label: 'Dashboard',           badge: null },
      { id: 'auth-demo', icon: Icons.authDemo,  label: 'Auth Demo',           badge: null },
    ],
  },
  {
    label: 'Testing',
    items: [
      { id: 'security',  icon: Icons.security,  label: 'Security',            badge: '2',  badgeType: '' },
      { id: 'usability', icon: Icons.usability, label: 'Usability & A11y',    badge: '3',  badgeType: '' },
      { id: 'recovery',  icon: Icons.recovery,  label: 'Account Recovery',    badge: '4',  badgeType: '' },
    ],
  },
  {
    label: 'Reports',
    items: [
      { id: 'ai',        icon: Icons.ai,        label: 'AI Recommendations',  badge: null },
      { id: 'history',   icon: Icons.history,   label: 'History',             badge: '4',  badgeType: 'info' },
      { id: 'settings',  icon: Icons.settings,  label: 'Settings',            badge: null },
    ],
  },
];

export default function Sidebar({ activePage, onNavigate, user, onLogout }) {
  return (
    <nav className="sidebar" aria-label="Main navigation">
      {/* Wordmark */}
      <div className="sidebar-logo">
        <div className="logo-mark">
          <div className="logo-icon" aria-hidden="true">
            {Icons.wordmark}
          </div>
          <div>
            <div className="logo-text">Auth<span>Lens</span></div>
            <div className="logo-sub">Security Audit</div>
          </div>
        </div>
      </div>

      {/* Navigation */}
      {NAV_SECTIONS.map((section) => (
        <div className="sidebar-section" key={section.label}>
          <div className="sidebar-section-label">{section.label}</div>
          {section.items.map((item) => (
            <button
              key={item.id}
              id={`nav-${item.id}`}
              className={`nav-item${activePage === item.id ? ' active' : ''}`}
              onClick={() => onNavigate(item.id)}
              aria-current={activePage === item.id ? 'page' : undefined}
            >
              <span className="nav-icon" aria-hidden="true">{item.icon}</span>
              {item.label}
              {item.badge && (
                <span className={`nav-badge${item.badgeType === 'info' ? ' info' : ''}`}>
                  {item.badge}
                </span>
              )}
            </button>
          ))}
        </div>
      ))}

      {/* Footer & Session Profile */}
      <div className="sidebar-footer">
        {user && (
          <div className="sidebar-user-profile">
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', minWidth: 0, flex: 1 }}>
              <div className="user-avatar" aria-hidden="true">
                {(user.name || user.email || 'U').charAt(0).toUpperCase()}
              </div>
              <div style={{ minWidth: 0, overflow: 'hidden', flex: 1 }}>
                <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-primary)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                  {user.name || 'Security Engineer'}
                </div>
                <div style={{ fontSize: '10px', color: 'var(--text-muted)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                  {user.email || 'engineer@authlens.dev'}
                </div>
              </div>
            </div>
            {onLogout && (
              <button
                id="sidebar-logout-btn"
                onClick={onLogout}
                className="btn btn-ghost btn-xs"
                style={{ padding: '3px 5px', color: 'var(--text-muted)' }}
                title="Sign Out"
                aria-label="Sign Out"
              >
                <span className="nav-icon" style={{ width: 14, height: 14 }} aria-hidden="true">
                  {Icons.logout}
                </span>
              </button>
            )}
          </div>
        )}

        <div className="env-indicator" role="note">
          <strong>Sample project</strong><br />
          Illustrative data only. No real tests performed.
        </div>
      </div>
    </nav>
  );
}
