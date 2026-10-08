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
      <Sidebar
        activePage={activePage}
        onNavigate={setActivePage}
        user={user}
        onLogout={handleLogout}
      />
      <main
        className="main-content"
        id="main-content"
        aria-label="Main content"
        tabIndex={-1}
      >
        <PageComponent key={activePage} />
      </main>
    </div>
  );
}
