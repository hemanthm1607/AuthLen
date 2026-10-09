/**
 * App.jsx — AuthLens main application shell
 * Supports real authentication flow with Express/PostgreSQL backend and 8 audit pages
 */
import { useState, useEffect } from 'react';
import './App.css';

import Sidebar             from './components/Sidebar';
import Dashboard           from './pages/Dashboard';
import AuthDemo            from './pages/AuthDemo';
import SecurityTesting     from './pages/SecurityTesting';
import UsabilityAccessibility from './pages/UsabilityAccessibility';
import AccountRecovery     from './pages/AccountRecovery';
import AIRecommendations   from './pages/AIRecommendations';
import ApprovedFindings   from './pages/ApprovedFindings';
import AssessmentHistory   from './pages/AssessmentHistory';
import Settings            from './pages/Settings';

import LoginPage           from './pages/auth/LoginPage';
import RegisterPage        from './pages/auth/RegisterPage';
import ForgotPasswordPage  from './pages/auth/ForgotPasswordPage';
import ResetPasswordPage   from './pages/auth/ResetPasswordPage';
import { authApi }         from './services/authApi';

const PAGE_COMPONENTS = {
  'dashboard': Dashboard,
  'auth-demo': AuthDemo,
  'security':  SecurityTesting,
  'usability': UsabilityAccessibility,
  'recovery':  AccountRecovery,
  'ai':        AIRecommendations,
  'approved-findings': ApprovedFindings,
  'history':   AssessmentHistory,
  'settings':  Settings,
};

export default function App() {
  const [activePage, setActivePage] = useState('dashboard');
  const [authView, setAuthView]     = useState('login'); // 'login' | 'register' | 'forgot' | 'reset'
  const [resetToken, setResetToken] = useState('');
  const [verifyNotice, setVerifyNotice] = useState('');
  const [user, setUser]             = useState(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [checkingAuth, setCheckingAuth]       = useState(true);
  const [mobileMenuOpen, setMobileMenuOpen]   = useState(false);
  const [targetUrl, setTargetUrl]             = useState(() => {
    try {
      const stored = localStorage.getItem('authlens_target_url');
      if (stored && typeof stored === 'string') {
        const trimmed = stored.trim();
        if (trimmed && (trimmed.startsWith('http://') || trimmed.startsWith('https://') || trimmed.startsWith('localhost'))) {
          return trimmed;
        }
      }
    } catch (_) {}
    return 'http://localhost:4000';
  });

  function handleTargetUrlChange(newUrl) {
    const val = typeof newUrl === 'string' ? newUrl : '';
    setTargetUrl(val);
    try {
      const trimmed = val.trim();
      if (trimmed) {
        localStorage.setItem('authlens_target_url', trimmed);
      }
    } catch (_) {}
  }

  // Load user-configured targetUrl from settings only if no local override exists
  useEffect(() => {
    if (!isAuthenticated) return;
    let isMounted = true;
    authApi.getUserSettings()
      .then((res) => {
        if (isMounted && res?.settings?.targetUrl) {
          const remoteTarget = res.settings.targetUrl.trim();
          let localStored = null;
          try {
            localStored = localStorage.getItem('authlens_target_url');
          } catch (_) {}
          if (!localStored && remoteTarget && (remoteTarget.startsWith('http://') || remoteTarget.startsWith('https://'))) {
            setTargetUrl(remoteTarget);
          }
        }
      })
      .catch(() => {});
    return () => { isMounted = false; };
  }, [isAuthenticated]);

  // Check URL parameters for recovery links (?view=reset&token=...) or verification (?view=verify&token=...)
  useEffect(() => {
    try {
      const params = new URLSearchParams(window.location.search);
      const view = params.get('view');
      const token = params.get('token');
      if (view === 'reset') {
        setAuthView('reset');
        if (token) setResetToken(token);
      } else if (view === 'verify' && token) {
        authApi.verifyEmail({ token })
          .then(() => setVerifyNotice('Your email address has been verified successfully! You may now sign in.'))
          .catch((err) => setVerifyNotice(err.message || 'Verification link expired or invalid.'));
      }
    } catch (_) {}
  }, []);

  // Verify authentication with backend on initial load
  useEffect(() => {
    let isMounted = true;

    async function verifySession() {
      try {
        const res = await authApi.getMe();
        if (isMounted && res?.user) {
          setUser(res.user);
          setIsAuthenticated(true);
        }
      } catch {
        // Fallback to demo session if present
        try {
          const stored = sessionStorage.getItem('authlens_demo_session');
          if (stored) {
            const parsed = JSON.parse(stored);
            if (isMounted && parsed?.email) {
              setUser(parsed);
              setIsAuthenticated(true);
            }
          }
        } catch {
          // Ignore
        }
      } finally {
        if (isMounted) setCheckingAuth(false);
      }
    }

    verifySession();
    return () => { isMounted = false; };
  }, []);

  function handleLoginSuccess(userData) {
    try {
      sessionStorage.setItem('authlens_demo_session', JSON.stringify(userData));
    } catch {
      // Ignore
    }
    setUser(userData);
    setIsAuthenticated(true);
    setActivePage('dashboard');
  }

  function handleRegisterSuccess(userData) {
    try {
      sessionStorage.setItem('authlens_demo_session', JSON.stringify(userData));
    } catch {
      // Ignore
    }
    setUser(userData);
    setIsAuthenticated(true);
    setActivePage('dashboard');
  }

  async function handleLogout() {
    try {
      await authApi.logout();
    } catch {
      // Ignore logout network errors
    }
    try {
      sessionStorage.removeItem('authlens_demo_session');
    } catch {
      // Ignore
    }
    setUser(null);
    setIsAuthenticated(false);
    setAuthView('login');
  }

  // Initial loading state while verifying backend session
  if (checkingAuth) {
    return (
      <div className="auth-experience-wrapper" style={{ justifyContent: 'center' }}>
        <div style={{ textAlign: 'center' }}>
          <span className="spin" style={{ fontSize: '24px', color: 'var(--accent)' }}>⟳</span>
          <div className="text-secondary text-xs mt-3">Verifying secure session…</div>
        </div>
      </div>
    );
  }

  // ── Unauthenticated state: display authentication flow ──
  if (!isAuthenticated) {
    if (authView === 'register') {
      return (
        <RegisterPage
          onNavigate={setAuthView}
          onRegisterSuccess={handleRegisterSuccess}
        />
      );
    }

    if (authView === 'forgot') {
      return (
        <ForgotPasswordPage
          onNavigate={setAuthView}
        />
      );
    }

    if (authView === 'reset') {
      return (
        <ResetPasswordPage
          initialToken={resetToken}
          onNavigate={setAuthView}
        />
      );
    }

    return (
      <LoginPage
        onNavigate={setAuthView}
        onLoginSuccess={handleLoginSuccess}
        notificationNotice={verifyNotice}
      />
    );
  }

  // ── Authenticated state: display full audit suite ──
  const PageComponent = PAGE_COMPONENTS[activePage] ?? Dashboard;

  return (
    <div className="app-shell">
      {/* Mobile Backdrop */}
      <div
        className={`sidebar-backdrop${mobileMenuOpen ? ' active' : ''}`}
        onClick={() => setMobileMenuOpen(false)}
        aria-hidden="true"
      />

      <Sidebar
        activePage={activePage}
        onNavigate={setActivePage}
        user={user}
        onLogout={handleLogout}
        mobileOpen={mobileMenuOpen}
        onCloseMobile={() => setMobileMenuOpen(false)}
      />

      <div style={{ display: 'flex', flexDirection: 'column', flex: 1, minWidth: 0, height: '100%', overflow: 'hidden' }}>
        {/* Mobile Header Bar */}
        <header className="mobile-topbar" aria-label="Mobile navigation header">
          <div className="mobile-topbar-brand">
            <div className="logo-icon" style={{ width: 24, height: 24 }} aria-hidden="true">
              <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" style={{ width: 14, height: 14 }}>
                <path d="M10 2L3 6v5c0 4 3 7 7 7s7-3 7-7V6l-7-4z"/>
                <path d="M7 10l2 2 4-4" stroke="#2563EB" strokeWidth="1.6"/>
              </svg>
            </div>
            <div className="logo-text" style={{ fontSize: '13px' }}>Auth<span>Lens</span></div>
          </div>
          <button
            className="mobile-menu-btn"
            onClick={() => setMobileMenuOpen((o) => !o)}
            aria-label={mobileMenuOpen ? 'Close navigation' : 'Open navigation'}
            aria-expanded={mobileMenuOpen}
          >
            <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" style={{ width: 16, height: 16 }}>
              <path d="M2 4h12M2 8h12M2 12h12"/>
            </svg>
          </button>
        </header>

        <main
          className="main-content"
          id="main-content"
          aria-label="Main content"
          tabIndex={-1}
        >
          <PageComponent
            key={activePage}
            onNavigate={setActivePage}
            targetUrl={targetUrl}
            onTargetUrlChange={handleTargetUrlChange}
          />
        </main>
      </div>
    </div>
  );
}
