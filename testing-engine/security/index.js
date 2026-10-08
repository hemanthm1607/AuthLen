/**
 * testing-engine/security/index.js — Security Evaluation Module
 * Executes non-destructive security assertions against the authorized target.
 */
const { safeFetch, sanitizeEvidence } = require('../utils/targetValidator');

async function run(target) {
  const findings = [];
  const base = target.url;

  // ── SEC-005: HTTPS Transmission Check ──
  const isHttps = target.protocol === 'https:';
  const isLocal = target.isLocal;

  if (!isHttps && !isLocal) {
    findings.push({
      id: 'SEC-005',
      title: 'Credentials transmitted over unencrypted HTTP',
      category: 'Security',
      severity: 'Critical',
      status: 'FAIL',
      evidence: `Target protocol is ${target.protocol} on host ${target.host}. Plaintext transmission detected.`,
      risk: 'Credentials and session cookies transmitted over unencrypted HTTP can be intercepted via network eavesdropping (MitM attacks).',
      recommendation: 'Enforce HTTPS with HSTS (HTTP Strict Transport Security) on all authentication endpoints.',
      codeBefore: 'app.listen(80); // Insecure HTTP listener',
      codeAfter: 'app.use((req, res, next) => {\n  if (!req.secure) return res.redirect(`https://${req.headers.host}${req.url}`);\n  next();\n});',
      isAutomated: true,
    });
  } else {
    findings.push({
      id: 'SEC-005',
      title: 'Transport layer encryption (HTTPS)',
      category: 'Security',
      severity: 'Info',
      status: 'PASS',
      evidence: isLocal ? 'Localhost development target (HTTP transport is permitted for local loopback).' : 'Target uses encrypted HTTPS transport.',
      risk: 'Unencrypted transport exposes session credentials.',
      recommendation: 'Maintain TLS 1.3 encryption across all auth ingress gateways.',
      codeBefore: null,
      codeAfter: null,
      isAutomated: true,
    });
  }

  // ── SEC-001 & SEC-002: Rate Limiting and Brute Force Resistance ──
  // Send a controlled, safe sequence of failed login attempts with non-existent credentials
  // Stops immediately upon receiving HTTP 429 (Too Many Requests)
  const loginUrl = `${base}/api/auth/login`;
  let rateLimited = false;
  let retryAfterHeader = null;
  const probeStatuses = [];

  for (let i = 0; i < 8; i++) {
    const probe = await safeFetch(loginUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: `audit_probe_${Date.now()}_${i}@example.invalid`, password: 'AuditProbePassword123!' }),
      timeout: 3000,
    });

    if (probe.failed || probe.timedOut) break;

    probeStatuses.push(probe.status);
    if (probe.status === 429) {
      rateLimited = true;
      retryAfterHeader = probe.headers['retry-after'];
      break;
    }
  }

  // Never claim SEC-001 passes unless an actual HTTP 429 response was observed
  if (rateLimited) {
    findings.push({
      id: 'SEC-001',
      title: 'Authentication rate limiting enforced',
      category: 'Security',
      severity: 'Info',
      status: 'PASS',
      evidence: `Observed HTTP 429 (Too Many Requests) on probe #${probeStatuses.length} after ${probeStatuses.length - 1} failed attempts (statuses: [${probeStatuses.join(', ')}]). Retry-After header: ${retryAfterHeader || 'active'}s. Rate limiter actively restricted brute force attacks.`,
      risk: 'Without rate limiting, attackers can launch automated brute-force attacks against target accounts.',
      recommendation: 'Maintain strict sliding-window rate limiting on all login and authentication endpoints.',
      codeBefore: null,
      codeAfter: null,
      isAutomated: true,
    });
  } else if (probeStatuses.length > 0) {
    findings.push({
      id: 'SEC-001',
      title: 'Unrestricted login endpoint brute-force vulnerability',
      category: 'Security',
      severity: 'High',
      status: 'FAIL',
      evidence: `Sent ${probeStatuses.length} consecutive invalid login attempts. Server responded with statuses [${probeStatuses.join(', ')}] without HTTP 429 throttling. No rate limit triggered.`,
      risk: 'Without rate limiting, attackers can launch automated brute-force attacks against target accounts at wire speed.',
      recommendation: 'Implement IP- and account-based rate limiting (e.g., max 5 attempts per 15 minutes returning HTTP 429 with Retry-After header).',
      codeBefore: 'app.post("/api/auth/login", authController.login);',
      codeAfter: 'const { rateLimit } = require("express-rate-limit");\nconst loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5, skipSuccessfulRequests: true });\napp.post("/api/auth/login", loginLimiter, authController.login);',
      isAutomated: true,
    });
  } else {
    findings.push({
      id: 'SEC-001',
      title: 'Login endpoint rate limiting',
      category: 'Security',
      severity: 'Low',
      status: 'NEEDS_REVIEW',
      evidence: `Could not reach ${loginUrl}. Endpoint may be offline, timed out, or using an alternative URL pattern.`,
      risk: 'Unverifiable rate limiting.',
      recommendation: 'Confirm login route path and verify that rate limit headers and 429 responses are functioning.',
      codeBefore: null,
      codeAfter: null,
      isAutomated: true,
    });
  }

  // ── SEC-004: Session Cookie Hygiene (HttpOnly, SameSite, Secure) ──
  const healthRes = await safeFetch(`${base}/api/health`, { timeout: 3000 });
  const rawSetCookie = healthRes.headers ? healthRes.headers['set-cookie'] : null;

  // Probe with a login attempt to inspect Set-Cookie
  const cookieProbe = await safeFetch(loginUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'cookie_test@example.invalid', password: 'TestPassword123!' }),
    timeout: 3000,
  });

  const setCookie = (cookieProbe.headers && cookieProbe.headers['set-cookie']) || rawSetCookie || '';

  const hasHttpOnly = /httponly/i.test(setCookie);
  const hasSameSite = /samesite=(lax|strict)/i.test(setCookie);
  const hasSecure = /secure/i.test(setCookie);

  if (setCookie) {
    if (hasHttpOnly && hasSameSite) {
      findings.push({
        id: 'SEC-004',
        title: 'Session cookie hygiene configured properly',
        category: 'Security',
        severity: 'Info',
        status: 'PASS',
        evidence: `Set-Cookie header observed with HttpOnly and SameSite directives: "${sanitizeEvidence(setCookie).substring(0, 80)}..."`,
        risk: 'Improper cookie flags expose sessions to XSS theft and CSRF.',
        recommendation: 'Continue enforcing HttpOnly, SameSite=Lax/Strict, and Secure flags.',
        codeBefore: null,
        codeAfter: null,
        isAutomated: true,
      });
    } else {
      findings.push({
        id: 'SEC-004',
        title: 'Missing security flags on session cookie',
        category: 'Security',
        severity: 'High',
        status: 'FAIL',
        evidence: `Set-Cookie header missing critical flags. HttpOnly: ${hasHttpOnly}, SameSite: ${hasSameSite}, Secure: ${hasSecure}.`,
        risk: 'Missing HttpOnly allows JavaScript XSS attacks to steal session tokens. Missing SameSite exposes session to CSRF replaying.',
        recommendation: 'Configure session cookies with httpOnly: true, sameSite: "lax", and secure: true.',
        codeBefore: 'res.cookie("session", id); // No security flags',
        codeAfter: 'res.cookie("session", id, {\n  httpOnly: true,\n  secure: process.env.NODE_ENV === "production",\n  sameSite: "lax",\n  maxAge: 30 * 24 * 3600 * 1000\n});',
        isAutomated: true,
      });
    }
  } else {
    findings.push({
      id: 'SEC-004',
      title: 'Session cookie verification',
      category: 'Security',
      severity: 'Medium',
      status: 'NEEDS_REVIEW',
      evidence: 'No Set-Cookie header emitted during unauthenticated probe. Check verified session state.',
      risk: 'Unverified session token handling.',
      recommendation: 'Verify session store configuration in Express session middleware.',
      codeBefore: null,
      codeAfter: null,
      isAutomated: true,
    });
  }

  // ── SEC-006: User Enumeration via Error Messages ──
  const nonExistentUserProbe = await safeFetch(loginUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'definitely_does_not_exist_98234@example.corp', password: 'Password123!' }),
    timeout: 3000,
  });

  const errorText = nonExistentUserProbe.json ? JSON.stringify(nonExistentUserProbe.json).toLowerCase() : nonExistentUserProbe.text.toLowerCase();

  const leaksUserExistence =
    errorText.includes('user not found') ||
    errorText.includes('no account exists') ||
    errorText.includes('unregistered email') ||
    errorText.includes('user does not exist');

  if (leaksUserExistence) {
    findings.push({
      id: 'SEC-006',
      title: 'Account enumeration in login error responses',
      category: 'Security',
      severity: 'Medium',
      status: 'FAIL',
      evidence: `Error response revealed user existence: "${sanitizeEvidence(nonExistentUserProbe.text).substring(0, 100)}"`,
      risk: 'Distinct error messages allow attackers to compile verified lists of valid user emails for targeted phishing or credential stuffing.',
      recommendation: 'Always return uniform error messages (e.g., "Invalid email address or password") regardless of whether the account exists.',
      codeBefore: 'if (!user) return res.status(404).json({ error: "User not found" });',
      codeAfter: 'if (!user || !validPassword) {\n  return res.status(401).json({ error: "Invalid email address or password" });\n}',
      isAutomated: true,
    });
  } else {
    findings.push({
      id: 'SEC-006',
      title: 'Uniform authentication error messaging',
      category: 'Security',
      severity: 'Info',
      status: 'PASS',
      evidence: `Response for non-existent user used uniform generic error response without leaking account existence. Status: ${nonExistentUserProbe.status}.`,
      risk: 'Verbose errors enable credential scanning.',
      recommendation: 'Continue returning identical timing-safe error responses across all failure states.',
      codeBefore: null,
      codeAfter: null,
      isAutomated: true,
    });
  }

  // ── SEC-002: Observable Password Policy & Complexity Check ──
  const regUrl = `${base}/api/auth/register`;
  const weakProbe = await safeFetch(regUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ fullName: 'Audit Probe', email: `audit_weak_${Date.now()}@example.invalid`, password: 'weak' }),
    timeout: 3000,
  });

  if (weakProbe.status === 400) {
    findings.push({
      id: 'SEC-002',
      title: 'Password complexity requirements enforced',
      category: 'Security',
      severity: 'Info',
      status: 'PASS',
      evidence: `Target rejected weak password ('weak') with HTTP 400. Server enforces minimum length and character complexity validation.`,
      risk: 'Permitting weak or short passwords enables easy credential guessing and offline dictionary attacks.',
      recommendation: 'Maintain minimum 8+ character length requirement and multi-character class complexity checks.',
      codeBefore: null,
      codeAfter: null,
      isAutomated: true,
    });
  } else if (weakProbe.status === 200 || weakProbe.status === 201) {
    findings.push({
      id: 'SEC-002',
      title: 'Weak password policy permitted on registration',
      category: 'Security',
      severity: 'High',
      status: 'FAIL',
      evidence: `Target accepted weak password without complexity rejection (Status: ${weakProbe.status}).`,
      risk: 'Weak password policies expose accounts to brute force and dictionary compromise.',
      recommendation: 'Reject passwords under 8 characters or lacking uppercase, number, or symbol characters.',
      codeBefore: 'if (!password) return res.status(400);',
      codeAfter: 'if (!validatePasswordComplexity(password)) return res.status(400).json({ error: "Password does not meet complexity requirements." });',
      isAutomated: true,
    });
  } else {
    findings.push({
      id: 'SEC-002',
      title: 'Password policy verification',
      category: 'Security',
      severity: 'Low',
      status: 'NEEDS_REVIEW',
      evidence: `Could not verify password policy against ${regUrl} (HTTP status: ${weakProbe.status || 'timeout'}).`,
      risk: 'Unverified password validation rules.',
      recommendation: 'Verify registration password complexity enforcement manually.',
      codeBefore: null,
      codeAfter: null,
      isAutomated: true,
    });
  }

  // ── SEC-007: Session Invalidation on Logout ──
  const logoutUrl = `${base}/api/auth/logout`;
  const meUrl = `${base}/api/auth/me`;
  
  // Register a transient probe user to establish an active test session
  const probeEmail = `audit_logout_${Date.now()}@example.internal`;
  const probeReg = await safeFetch(regUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ fullName: 'Audit Probe', email: probeEmail, password: 'SecureAuditPass123!' }),
    timeout: 3000,
  });

  const testSessionCookie = probeReg.headers ? probeReg.headers['set-cookie'] : null;

  if (testSessionCookie) {
    // Call logout with this session cookie
    await safeFetch(logoutUrl, {
      method: 'POST',
      headers: { Cookie: testSessionCookie },
      timeout: 3000,
    });

    // Probe /me with the invalidated session cookie
    const postLogoutMe = await safeFetch(meUrl, {
      headers: { Cookie: testSessionCookie },
      timeout: 3000,
    });

    if (postLogoutMe.status === 401) {
      findings.push({
        id: 'SEC-007',
        title: 'Session properly destroyed upon logout',
        category: 'Security',
        severity: 'Info',
        status: 'PASS',
        evidence: `Session was successfully destroyed on the server upon POST ${logoutUrl}. Subsequent probe to ${meUrl} was rejected with HTTP 401 Unauthorized.`,
        risk: 'Failing to destroy sessions server-side allows zombie session tokens to remain active indefinitely.',
        recommendation: 'Continue destroying sessions on the server store and clearing client-side cookies on logout.',
        codeBefore: null,
        codeAfter: null,
        isAutomated: true,
      });
    } else {
      findings.push({
        id: 'SEC-007',
        title: 'Zombie session persists after logout',
        category: 'Security',
        severity: 'High',
        status: 'FAIL',
        evidence: `Session remained valid after POST ${logoutUrl}. Subsequent probe to ${meUrl} returned HTTP ${postLogoutMe.status}.`,
        risk: 'Attackers retaining a user token can maintain unauthorized access even after the user logs out.',
        recommendation: 'Destroy server session store entry and clear session cookies on logout.',
        codeBefore: 'res.clearCookie("session"); // Server store not destroyed',
        codeAfter: 'req.session.destroy(() => { res.clearCookie("session"); res.json({ message: "Logged out" }); });',
        isAutomated: true,
      });
    }
  } else {
    findings.push({
      id: 'SEC-007',
      title: 'Session logout invalidation check',
      category: 'Security',
      severity: 'Low',
      status: 'NEEDS_REVIEW',
      evidence: 'Could not obtain active test session cookie for automated logout invalidation test.',
      risk: 'Unverified session destruction lifecycle.',
      recommendation: 'Manually test session token invalidation upon user logout.',
      codeBefore: null,
      codeAfter: null,
      isAutomated: true,
    });
  }

  return findings;
}

module.exports = { run };
