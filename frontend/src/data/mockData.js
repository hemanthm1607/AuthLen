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
    risk: 'Lack of request throttling on the secondary authentication factor enables automated credential stuffing and brute-force key-space exhaustion across 6-digit verification codes (1,000,000 combinations), completely undermining multi-factor authentication guarantees.',
    recommendation: 'Enforce rate-limiting policies on OTP verification routes (e.g., maximum 5 attempts per 10-minute window per client IP/session tuple), apply exponential backoff, and enforce immediate token invalidation upon time-to-live (TTL) expiration.',
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
    risk: 'Absence of anti-CSRF synchronizer tokens permits cross-origin request forgery. An adversary hosting malicious web content can silently dispatch unauthorized state-changing requests, enabling login-CSRF and malicious session induction.',
    recommendation: 'Deploy cryptographically random anti-CSRF synchronizer tokens bound to client sessions, validate tokens on all state-altering POST requests, and enforce strict or lax SameSite cookie attributes as defense-in-depth.',
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
    risk: 'Omission of HttpOnly and Secure cookie attributes exposes session identifiers to document object model (DOM) exfiltration via Cross-Site Scripting (XSS) and transmission over unencrypted transport layers.',
    recommendation: 'Configure session cookies with HttpOnly, Secure, and SameSite=Strict/Lax flags. Regenerate session identifiers upon user authentication state transitions.',
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
    risk: 'Differentiated error messages and response behaviors enable account enumeration, allowing unauthorized parties to map registered user accounts through automated dictionary scans.',
    recommendation: 'Standardize authentication error responses to uniform, non-distinguishing messages (e.g., "Invalid email address or password") with constant-time execution to prevent timing-based enumeration.',
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
    risk: 'Absence of account lockout policies or progressive cooldown delays enables sustained brute-force and credential-stuffing campaigns against targeted accounts.',
    recommendation: 'Implement progressive authentication delays and temporary account lockouts after consecutive failed authentication attempts, coupled with security audit logging and alerting.',
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
    impact: 'Absence of an unmasking control increases credential entry errors during complex password input, elevating authentication retry failures and user friction.',
    improvement: 'Provide accessible password visibility unmasking controls with explicit ARIA-pressed state indicators to reduce input friction while preserving confidentiality.',
  },
  {
    id: 'USE-002',
    title: 'Login error message is not specific enough',
    severity: 'low',
    category: 'Usability',
    impact: 'Non-descriptive failure notifications provide insufficient diagnostic guidance, impeding legitimate users from initiating appropriate self-service credential recovery.',
    improvement: 'Offer secure recovery guidance (directing users toward password reset or administrative unlock channels) without introducing account enumeration vectors.',
  },
  {
    id: 'A11Y-001',
    title: 'Password input is missing an accessible label',
    severity: 'high',
    category: 'Accessibility',
    impact: 'Missing programmatic label association prevents assistive screen reader technologies from announcing control semantics, violating WCAG 2.1 Success Criterion 1.3.1 (Info and Relationships).',
    improvement: 'Bind explicit label elements via matching for/id attributes or provide descriptive aria-label / aria-labelledby attributes for complete assistive technology compatibility.',
  },
  {
    id: 'A11Y-002',
    title: 'CAPTCHA has no audio alternative',
    severity: 'high',
    category: 'Accessibility',
    impact: 'Exclusively visual challenge-response mechanisms obstruct non-sighted users from completing authentication workflows, violating WCAG 2.1 Success Criterion 1.1.1 (Non-text Content).',
    improvement: 'Deploy multi-modal verification supporting auditory challenge alternatives, or transition to modern accessible bot-detection frameworks (e.g. Cloudflare Turnstile).',
  },
  {
    id: 'A11Y-003',
    title: 'Keyboard focus order is illogical on login page',
    severity: 'medium',
    category: 'Accessibility',
    impact: 'Discrepancy between visual DOM positioning and sequential focus navigation disrupts keyboard-only operational workflows, violating WCAG 2.1 Success Criterion 2.4.3 (Focus Order).',
    improvement: 'Align DOM source order with visual reading progression, ensuring consistent and predictable sequential tab order across all interactive form controls.',
  },
  {
    id: 'A11Y-004',
    title: 'Colour contrast on placeholder text fails WCAG AA',
    severity: 'medium',
    category: 'Accessibility',
    impact: 'Placeholder luminance contrast ratio (2.8:1) falls short of the mandatory 4.5:1 minimum threshold for standard text, violating WCAG 2.1 Success Criterion 1.4.3 (Contrast Minimum).',
    improvement: 'Adjust text and placeholder palette styling to guarantee at least a 4.5:1 contrast ratio against container background surfaces under all viewport states.',
  },
];

// ─── Account recovery findings ────────────────────────────────────────────────
export const recoveryFindings = [
  {
    id: 'REC-001',
    title: 'Password reset links do not expire',
    severity: 'critical',
    status: 'fail',
    description: 'Account recovery tokens lack time-bounded revocation. Indefinite token lifetimes enable unauthorized account takeover via compromised mail archives or stale communication channels.',
    recommendation: 'Enforce short-lived expiration windows (15 to 60 minutes) on account recovery tokens and present explicit token expiration notices upon access.',
    mockScenario: 'expired-link',
  },
  {
    id: 'REC-002',
    title: 'Password reset link is reusable',
    severity: 'high',
    status: 'fail',
    description: 'Recovery tokens remain valid following initial consumption, permitting replay attacks if URL fragments or communication channels are intercepted.',
    recommendation: 'Enforce strict single-use token semantics by immediately burning tokens upon successful credential update.',
    mockScenario: 'reused-token',
  },
  {
    id: 'REC-003',
    title: 'Recovery error reveals whether email is registered',
    severity: 'high',
    status: 'fail',
    description: 'Differential response handling during password reset requests permits user enumeration through observable error output.',
    recommendation: 'Return consistent, ambiguous confirmation messages for all recovery requests to preclude account enumeration.',
    mockScenario: 'email-enumeration',
  },
  {
    id: 'REC-004',
    title: 'Account lockout has no self-service unlock',
    severity: 'medium',
    status: 'fail',
    description: 'Lockout remediation lacks self-service verification workflows, increasing administrative overhead and potential denial-of-service friction for legitimate users.',
    recommendation: 'Introduce cryptographically signed, out-of-band self-service unlock mechanisms accompanied by progressive cooldown timers.',
    mockScenario: 'lockout-recovery',
  },
  {
    id: 'REC-005',
    title: 'Forgot password link is clearly visible',
    severity: 'info',
    status: 'pass',
    description: 'Self-service account recovery navigation is discoverable, appropriately placed adjacent to authentication inputs, and programmatically focusable.',
    recommendation: 'Maintain current placement and accessible design standards.',
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
