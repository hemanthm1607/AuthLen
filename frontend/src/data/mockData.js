/**
 * mockData.js — All sample/demo data for AuthLens Round 1 UI
 * STATUS: Demo data only. No real security tests have been performed.
 */

// ─── Dashboard scores ────────────────────────────────────────────────────────
export const dashboardScores = [
  {
    id: 'security',
    label: 'Security',
    score: 75,
    max: 100,
    color: 'cyan',
    icon: '🔐',
    trend: '+3 since last assessment',
    description: 'Rate limiting, CSRF, session hygiene',
  },
  {
    id: 'usability',
    label: 'Usability',
    score: 80,
    max: 100,
    color: 'blue',
    icon: '🖱️',
    trend: 'No change',
    description: 'Error messages, visibility toggle, UX flow',
  },
  {
    id: 'accessibility',
    label: 'Accessibility',
    score: 45,
    max: 100,
    color: 'purple',
    icon: '♿',
    trend: '⚠ Needs attention',
    description: 'WCAG 2.1 AA, keyboard nav, ARIA roles',
  },
  {
    id: 'recovery',
    label: 'Account Recovery',
    score: 60,
    max: 100,
    color: 'amber',
    icon: '🔑',
    trend: '+8 since last assessment',
    description: 'Forgot password, lockout, token expiry',
  },
];

// ─── Overall findings summary ─────────────────────────────────────────────────
export const findingsSummary = {
  critical: 2,
  high: 5,
  medium: 8,
  low: 11,
};

// ─── Recent activity ──────────────────────────────────────────────────────────
export const recentActivity = [
  { id: 1, dot: 'red',   title: 'Critical: Unlimited OTP attempts',         desc: 'No rate limit found on /api/verify-otp', time: '2 minutes ago' },
  { id: 2, dot: 'red',   title: 'Critical: No CSRF token on login form',    desc: 'Login form missing anti-CSRF protection', time: '2 minutes ago' },
  { id: 3, dot: 'amber', title: 'Medium: Password field missing ARIA label', desc: 'Screen readers cannot identify the field', time: '2 minutes ago' },
  { id: 4, dot: 'blue',  title: 'Assessment completed',                     desc: 'Demo Auth Site — 26 checks run', time: '2 minutes ago' },
  { id: 5, dot: 'green', title: 'HTTPS enforced',                           desc: 'All connections use TLS 1.3', time: '2 minutes ago' },
];

// ─── Security findings ────────────────────────────────────────────────────────
export const securityFindings = [
  {
    id: 'SEC-001',
    title: 'No rate limiting on OTP verification endpoint',
    severity: 'critical',
    category: 'Security',
    risk: 'An attacker can try all 1,000,000 possible 6-digit OTP codes programmatically without any delay or lockout. This completely bypasses OTP-based multi-factor authentication.',
    recommendation: 'Implement rate limiting: allow maximum 5 attempts per 10-minute window per IP. Apply exponential backoff after 3 failures. Lock the OTP after expiry (typically 5 minutes).',
    codeBefore: `// ❌ No rate limiting — every attempt is processed
app.post('/api/verify-otp', async (req, res) => {
  const { userId, otp } = req.body;
  const stored = await db.getOtp(userId);
  if (stored === otp) return res.json({ success: true });
  return res.status(401).json({ error: 'Invalid OTP' });
});`,
    codeAfter: `// ✅ Rate-limited with lockout
const limiter = rateLimit({ windowMs: 10 * 60 * 1000, max: 5 });
app.post('/api/verify-otp', limiter, async (req, res) => {
  const { userId, otp } = req.body;
  const stored = await db.getOtp(userId);
  if (!stored || Date.now() > stored.expiresAt) {
    return res.status(400).json({ error: 'OTP expired' });
  }
  if (stored.attempts >= 5) {
    return res.status(429).json({ error: 'Too many attempts. Try again in 10 minutes.' });
  }
  if (stored.code !== otp) {
    await db.incrementOtpAttempts(userId);
    return res.status(401).json({ error: 'Invalid OTP' });
  }
  await db.clearOtp(userId);
  return res.json({ success: true });
});`,
  },
  {
    id: 'SEC-002',
    title: 'No CSRF token on login form',
    severity: 'critical',
    category: 'Security',
    risk: 'Cross-Site Request Forgery (CSRF) lets malicious websites submit authenticated requests on behalf of a logged-in user. A victim visiting an attacker\'s page could be silently logged into the attacker\'s account.',
    recommendation: 'Add a unique, unpredictable CSRF token to the login form (hidden field). Validate it server-side on every POST. Use the SameSite=Strict or SameSite=Lax cookie attribute as an additional layer.',
    codeBefore: `<!-- ❌ No CSRF protection -->
<form method="POST" action="/login">
  <input name="username" />
  <input name="password" type="password" />
  <button type="submit">Login</button>
</form>`,
    codeAfter: `<!-- ✅ CSRF token included -->
<form method="POST" action="/login">
  <input type="hidden" name="_csrf" value="{{ csrfToken }}" />
  <input name="username" />
  <input name="password" type="password" />
  <button type="submit">Login</button>
</form>`,
  },
  {
    id: 'SEC-003',
    title: 'Session cookie missing HttpOnly and Secure flags',
    severity: 'high',
    category: 'Security',
    risk: 'Session cookies without HttpOnly can be read by JavaScript, making them vulnerable to XSS theft. Without the Secure flag, they can be sent over HTTP, exposing them to network sniffing.',
    recommendation: 'Set HttpOnly, Secure, and SameSite=Strict on all session cookies. Rotate session IDs after login.',
    codeBefore: `// ❌ Insecure cookie
res.cookie('session', token);`,
    codeAfter: `// ✅ Secure cookie attributes
res.cookie('session', token, {
  httpOnly: true,
  secure: true,
  sameSite: 'strict',
  maxAge: 30 * 60 * 1000, // 30 minutes
});`,
  },
  {
    id: 'SEC-004',
    title: 'Login errors reveal whether username or password is wrong',
    severity: 'high',
    category: 'Security',
    risk: 'When the error message says "Username not found" vs. "Wrong password", attackers can enumerate valid usernames by systematically testing millions of email addresses.',
    recommendation: 'Always return the same generic message: "Invalid email or password." Never distinguish between wrong username and wrong password.',
    codeBefore: `// ❌ Enumeration-vulnerable messages
if (!user) return res.json({ error: 'No account with that email' });
if (!match) return res.json({ error: 'Password is incorrect' });`,
    codeAfter: `// ✅ Generic message in both cases
if (!user || !match) {
  return res.status(401).json({ error: 'Invalid email or password' });
}`,
  },
  {
    id: 'SEC-005',
    title: 'No account lockout after repeated failed logins',
    severity: 'high',
    category: 'Security',
    risk: 'Without lockout, an attacker can attempt unlimited password guesses (brute-force attack). Even with rate limiting, if the application has no lockout the attacker just needs to be slow.',
    recommendation: 'Lock the account for 15 minutes after 10 failed attempts. Show a clear lockout message with unlock time. Log all lockout events for security monitoring.',
    codeBefore: `// ❌ No lockout — unlimited attempts
if (password !== userPassword) {
  return res.status(401).json({ error: 'Wrong password' });
}`,
    codeAfter: `// ✅ Progressive lockout
const MAX_ATTEMPTS = 10;
const LOCKOUT_MINUTES = 15;
if (user.failedAttempts >= MAX_ATTEMPTS) {
  const unlockAt = new Date(user.lockedAt.getTime() + LOCKOUT_MINUTES * 60000);
  if (Date.now() < unlockAt) {
    return res.status(423).json({
      error: \`Account locked. Try again after \${unlockAt.toLocaleTimeString()}\`,
    });
  } else {
    await db.resetFailedAttempts(user.id);
  }
}`,
  },
];

// ─── Usability & Accessibility findings ──────────────────────────────────────
export const usabilityFindings = [
  {
    id: 'USE-001',
    title: 'Password field has no visibility toggle',
    severity: 'medium',
    category: 'Usability',
    impact: 'Users cannot verify what they have typed, leading to increased failed logins and user frustration.',
    improvement: 'Add a show/hide password toggle button (eye icon) next to the password field. This is standard UX on all modern authentication forms.',
  },
  {
    id: 'USE-002',
    title: 'Login error message is not specific enough',
    severity: 'low',
    category: 'Usability',
    impact: 'Users see "Login failed" with no guidance on whether the issue is a typo, wrong email, or locked account. They have no way to recover.',
    improvement: 'Show distinct error messages for: unrecognised email (offer register link), wrong password (offer reset link), account locked (show unlock time).',
  },
  {
    id: 'A11Y-001',
    title: 'Password input is missing an accessible label',
    severity: 'high',
    category: 'Accessibility',
    impact: 'Screen readers (NVDA, JAWS, VoiceOver) cannot announce the field purpose, making the form unusable for visually impaired users. Violates WCAG 2.1 Success Criterion 1.3.1.',
    improvement: 'Add an explicit <label for="password"> element or an aria-label="Password" attribute to the input.',
  },
  {
    id: 'A11Y-002',
    title: 'CAPTCHA has no audio alternative',
    severity: 'high',
    category: 'Accessibility',
    impact: 'Visual-only CAPTCHAs are completely inaccessible to blind users. This blocks them from registering or recovering their account. Violates WCAG 2.1 SC 1.1.1.',
    improvement: 'Provide an audio CAPTCHA alternative. Or switch to hCaptcha / Cloudflare Turnstile which offer accessible alternatives by default.',
  },
  {
    id: 'A11Y-003',
    title: 'Keyboard focus order is illogical on login page',
    severity: 'medium',
    category: 'Accessibility',
    impact: 'Tab order skips the "Forgot Password" link before the submit button, forcing keyboard users to navigate in a confusing order.',
    improvement: 'Ensure DOM order matches visual order. Use tabindex="0" only when needed, never negative values that remove elements from tab order.',
  },
  {
    id: 'A11Y-004',
    title: 'Colour contrast on placeholder text fails WCAG AA',
    severity: 'medium',
    category: 'Accessibility',
    impact: 'Placeholder text colour (#999999 on #FFFFFF) has a 2.8:1 contrast ratio, below the WCAG AA minimum of 4.5:1 for normal text.',
    improvement: 'Use #767676 or darker for placeholder text on white backgrounds. Test with a tool like WebAIM Contrast Checker.',
  },
];

// ─── Account recovery findings ────────────────────────────────────────────────
export const recoveryFindings = [
  {
    id: 'REC-001',
    title: 'Password reset links do not expire',
    severity: 'critical',
    status: 'fail',
    description: 'Reset tokens are valid indefinitely. An attacker who gains access to old emails can still use stale reset links.',
    recommendation: 'Set a 15–60 minute expiry on password reset tokens. Show a clear "This link has expired" page with a fresh request button.',
    mockScenario: 'expired-link',
  },
  {
    id: 'REC-002',
    title: 'Password reset link is reusable',
    severity: 'high',
    status: 'fail',
    description: 'After using a reset link, the token remains valid and can be used again. An attacker who intercepts the link later could change the password again.',
    recommendation: 'Invalidate the token immediately after it is used. Tokens must be single-use.',
    mockScenario: 'reused-token',
  },
  {
    id: 'REC-003',
    title: 'Recovery error reveals whether email is registered',
    severity: 'high',
    status: 'fail',
    description: 'When requesting a reset, the form says "No account found for that email" — revealing which emails are registered in your system.',
    recommendation: 'Always show: "If that email is registered, you\'ll receive a reset link." regardless of whether the account exists.',
    mockScenario: 'email-enumeration',
  },
  {
    id: 'REC-004',
    title: 'Account lockout has no self-service unlock',
    severity: 'medium',
    status: 'fail',
    description: 'When an account is locked after failed login attempts, users must contact support. There is no automated unlock via email.',
    recommendation: 'Send an unlock email automatically. Let users click a link to unlock their account after verifying identity. Include a countdown timer on the lockout page.',
    mockScenario: 'lockout-recovery',
  },
  {
    id: 'REC-005',
    title: 'Forgot password link is clearly visible',
    severity: 'info',
    status: 'pass',
    description: 'The "Forgot password?" link is present, clearly labelled, and positioned near the password field.',
    recommendation: 'No action required.',
    mockScenario: null,
  },
];

// ─── AI Recommendations ───────────────────────────────────────────────────────
export const aiRecommendations = [
  {
    id: 'AI-001',
    title: 'Implement a defence-in-depth OTP strategy',
    relatedCheck: 'SEC-001',
    severity: 'critical',
    explanation: `Your OTP endpoint accepts unlimited verification attempts with no timeout. In practical terms: a 6-digit numeric OTP has 1,000,000 combinations. At 100 requests/second — trivially achievable — an attacker can exhaust all combinations in under 3 hours. This completely undermines the security value of your MFA implementation.

The fix requires three coordinated layers:
1. Rate limiting per IP (network layer)
2. Attempt counting per OTP session (application layer)
3. Short expiry windows (token layer)`,
    code: `// Install: npm install express-rate-limit
const rateLimit = require('express-rate-limit');

const otpLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 minutes
  max: 5,                    // 5 attempts per window
  standardHeaders: true,
  message: { error: 'Too many verification attempts. Please request a new OTP.' },
  keyGenerator: (req) => req.body.userId || req.ip,
});

app.post('/api/verify-otp', otpLimiter, verifyOtpHandler);`,
    effort: 'Low',
    impact: 'Critical',
  },
  {
    id: 'AI-002',
    title: 'Add CSRF protection using csurf or helmet',
    relatedCheck: 'SEC-002',
    severity: 'critical',
    explanation: `CSRF attacks exploit the browser's automatic credential-sending behaviour. When a user is logged into your app and visits an attacker's site, the attacker's site can silently submit forms to your server with the user's cookies attached.

The simplest modern fix is the SameSite cookie attribute (free, no code changes to forms) combined with a CSRF token for defence-in-depth. The SameSite attribute prevents cross-origin cookie sending in modern browsers, but CSRF tokens catch edge cases with older browsers and complex redirect chains.`,
    code: `// Option 1: SameSite cookie (most browsers, zero-config)
res.cookie('session', token, { sameSite: 'strict' });

// Option 2: CSRF token middleware (comprehensive)
const csrf = require('csurf');
app.use(csrf({ cookie: true }));
app.get('/login', (req, res) => {
  res.render('login', { csrfToken: req.csrfToken() });
});`,
    effort: 'Low',
    impact: 'Critical',
  },
  {
    id: 'AI-003',
    title: 'Audit and fix all form accessibility violations',
    relatedCheck: 'A11Y-001',
    severity: 'high',
    explanation: `Your authentication forms have 3 WCAG 2.1 Level AA violations. These don't just affect users with disabilities — they also directly affect SEO, automated testing reliability, and legal compliance (ADA, EN 301 549).

The password field missing an accessible label means screen reader users hear "edit text" with no context. The audio CAPTCHA missing means blind users literally cannot create an account. These must be fixed before launch.`,
    code: `<!-- ✅ Accessible login form -->
<form aria-label="Login form">
  <div role="group">
    <label for="email">Email address</label>
    <input
      id="email"
      type="email"
      name="email"
      autocomplete="username"
      aria-required="true"
      aria-describedby="email-hint"
    />
    <span id="email-hint" class="sr-only">Enter your registered email</span>
  </div>

  <div role="group">
    <label for="password">Password</label>
    <input
      id="password"
      type="password"
      name="password"
      autocomplete="current-password"
      aria-required="true"
    />
    <button type="button" aria-label="Show password" aria-pressed="false">
      Show
    </button>
  </div>
</form>`,
    effort: 'Medium',
    impact: 'High',
  },
];

// ─── Assessment history ───────────────────────────────────────────────────────
export const assessmentHistory = [
  {
    id: 'ASS-004',
    date: '2026-10-08',
    target: 'Demo Auth Site v2.1',
    status: 'completed',
    duration: '1m 43s',
    critical: 2,
    high: 5,
    medium: 8,
    low: 11,
    overallScore: 65,
  },
  {
    id: 'ASS-003',
    date: '2026-10-05',
    target: 'Demo Auth Site v2.0',
    status: 'completed',
    duration: '1m 52s',
    critical: 3,
    high: 6,
    medium: 9,
    low: 10,
    overallScore: 58,
  },
  {
    id: 'ASS-002',
    date: '2026-10-01',
    target: 'Demo Auth Site v1.5',
    status: 'completed',
    duration: '2m 04s',
    critical: 4,
    high: 7,
    medium: 7,
    low: 8,
    overallScore: 51,
  },
  {
    id: 'ASS-001',
    date: '2026-09-25',
    target: 'Demo Auth Site v1.0',
    status: 'completed',
    duration: '2m 18s',
    critical: 5,
    high: 9,
    medium: 6,
    low: 6,
    overallScore: 42,
  },
];
