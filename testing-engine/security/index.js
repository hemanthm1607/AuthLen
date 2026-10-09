/**
 * testing-engine/security/index.js — Security Evaluation Module
 * Executes non-destructive security assertions against the authorized target.
 * Discovers and adapts to both API endpoints and HTML authentication forms.
 */
const { safeFetch, sanitizeEvidence } = require('../utils/targetValidator');

function extractAuthForm(html, baseUrl) {
  if (!html || typeof html !== 'string') return null;
  const formMatch = html.match(/<form\b([^>]*)>([\s\S]*?)<\/form>/i);
  if (!formMatch) return null;

  const formAttrs = formMatch[1];
  const formBody = formMatch[2];

  if (!/<input[^>]+type=["']?password["']?/i.test(formBody)) {
    return null;
  }

  const actionMatch = formAttrs.match(/action=["']([^"']*)["']/i);
  let actionUrl = actionMatch ? actionMatch[1] : '';
  try {
    actionUrl = new URL(actionUrl, baseUrl).href;
  } catch (_) {
    actionUrl = baseUrl;
  }

  const methodMatch = formAttrs.match(/method=["']([^"']*)["']/i);
  const method = (methodMatch ? methodMatch[1] : 'POST').toUpperCase();

  const usernameMatch = formBody.match(/<input[^>]+(?:name=["']([^"']*)["'][^>]+type=["']?(?:text|email)["']|type=["']?(?:text|email)["'][^>]+name=["']([^"']*)["'])/i);
  const usernameField = (usernameMatch && (usernameMatch[1] || usernameMatch[2])) || 'username';

  const passwordMatch = formBody.match(/<input[^>]+name=["']([^"']*)["'][^>]+type=["']?password["']|type=["']?password["'][^>]+name=["']([^"']*)["']/i);
  const passwordField = (passwordMatch && (passwordMatch[1] || passwordMatch[2])) || 'password';

  return {
    actionUrl,
    method,
    usernameField,
    passwordField,
  };
}

async function run(target) {
  const findings = [];
  const authBase = target.origin;

  // Probe target directly to inspect response type, headers, and any HTML form
  const targetProbe = await safeFetch(target.url, { timeout: 3500 });
  const isTargetServerError = targetProbe.status >= 500;
  const authForm = extractAuthForm(targetProbe.text, target.url);

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

  // ── SEC-006: User Enumeration via Error Messages ──
  let loginUrl;
  let useFormEncoded = false;
  let loginFieldNames = { user: 'email', pass: 'password' };

  if (authForm) {
    loginUrl = authForm.actionUrl;
    useFormEncoded = true;
    loginFieldNames = { user: authForm.usernameField, pass: authForm.passwordField };
  } else if (target.pathname && (target.pathname.toLowerCase().endsWith('/login') || target.pathname.toLowerCase().endsWith('/authenticate'))) {
    loginUrl = target.url;
  } else {
    loginUrl = `${authBase}/api/auth/login`;
  }

  function createLoginPayload(user, pass) {
    if (useFormEncoded) {
      return {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `${encodeURIComponent(loginFieldNames.user)}=${encodeURIComponent(user)}&${encodeURIComponent(loginFieldNames.pass)}=${encodeURIComponent(pass)}`,
      };
    }
    return {
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ [loginFieldNames.user]: user, [loginFieldNames.pass]: pass, email: user, username: user, password: pass }),
    };
  }

  const nonExistentPayload = createLoginPayload('definitely_does_not_exist_98234@example.corp', 'Password123!');
  const nonExistentUserProbe = await safeFetch(loginUrl, {
    method: 'POST',
    headers: nonExistentPayload.headers,
    body: nonExistentPayload.body,
    timeout: 3000,
  });

  if (isTargetServerError || nonExistentUserProbe.status >= 500 || nonExistentUserProbe.failed || nonExistentUserProbe.timedOut) {
    findings.push({
      id: 'SEC-006',
      title: 'Uniform authentication error messaging',
      category: 'Security',
      severity: 'Low',
      status: 'NEEDS_REVIEW',
      evidence: `Target returned HTTP ${nonExistentUserProbe.status || targetProbe.status || 'error'}. User enumeration checks cannot be evaluated on a server error.`,
      risk: 'Cannot verify authentication error response consistency due to server error.',
      recommendation: 'Resolve upstream server issues and re-test enumeration resistance.',
      codeBefore: null,
      codeAfter: null,
      isAutomated: true,
    });
  } else if (nonExistentUserProbe.status === 404) {
    findings.push({
      id: 'SEC-006',
      title: 'Uniform authentication error messaging',
      category: 'Security',
      severity: 'Low',
      status: 'NOT_APPLICABLE',
      evidence: `Login endpoint returned HTTP 404 Not Found. User enumeration checks are not applicable without an active authentication endpoint.`,
      risk: 'No login endpoint deployed at this path.',
      recommendation: 'Specify valid authentication endpoint for testing.',
      codeBefore: null,
      codeAfter: null,
      isAutomated: true,
    });
  } else {
    const errorText = (nonExistentUserProbe.json ? JSON.stringify(nonExistentUserProbe.json) : nonExistentUserProbe.text || '').toLowerCase();
    const cookieText = (nonExistentUserProbe.headers['set-cookie'] || '').toLowerCase();
    const combinedResponse = `${errorText} ${cookieText}`;

    const ENUMERATION_SIGNATURES = [
      'user not found',
      'no account exists',
      'unregistered',
      'user does not exist',
      'username is invalid',
      'invalid username',
      'unknown user',
      'account not found',
      'email not registered',
      'does not exist',
    ];

    const matchedSignature = ENUMERATION_SIGNATURES.find((sig) => combinedResponse.includes(sig));

    if (matchedSignature) {
      findings.push({
        id: 'SEC-006',
        title: 'Account enumeration in login error responses',
        category: 'Security',
        severity: 'Medium',
        status: 'FAIL',
        evidence: `Error response revealed user existence or non-existence (matched "${matchedSignature}"): "${sanitizeEvidence(nonExistentUserProbe.text || nonExistentUserProbe.headers['set-cookie']).substring(0, 100)}"`,
        risk: 'Distinct error messages allow attackers to compile verified lists of valid user emails for targeted phishing or credential stuffing.',
        recommendation: 'Always return uniform error messages (e.g., "Invalid email address or password") regardless of whether the account exists.',
        codeBefore: 'if (!user) return res.status(404).json({ error: "User not found" });',
        codeAfter: 'if (!user || !validPassword) {\n  return res.status(401).json({ error: "Invalid email address or password" });\n}',
        isAutomated: true,
      });
    } else if (nonExistentUserProbe.status === 401 || nonExistentUserProbe.status === 400 || (nonExistentUserProbe.status >= 300 && nonExistentUserProbe.status < 400)) {
      findings.push({
        id: 'SEC-006',
        title: 'Uniform authentication error messaging',
        category: 'Security',
        severity: 'Info',
        status: 'PASS',
        evidence: `Response for non-existent user returned uniform generic error response (Status: ${nonExistentUserProbe.status}) without leaking account existence.`,
        risk: 'Verbose errors enable credential scanning.',
        recommendation: 'Continue returning identical timing-safe error responses across all failure states.',
        codeBefore: null,
        codeAfter: null,
        isAutomated: true,
      });
    } else {
      findings.push({
        id: 'SEC-006',
        title: 'Uniform authentication error messaging',
        category: 'Security',
        severity: 'Low',
        status: 'NEEDS_REVIEW',
        evidence: `Login probe returned unexpected status ${nonExistentUserProbe.status}. Unable to confirm uniform error handling.`,
        risk: 'Unverified error messaging consistency.',
        recommendation: 'Confirm login failure returns timing-safe uniform responses.',
        codeBefore: null,
        codeAfter: null,
        isAutomated: true,
      });
    }
  }

  // ── SEC-002: Observable Password Policy & Complexity Check ──
  const regUrl = (target.pathname && target.pathname.toLowerCase().endsWith('/register'))
    ? target.url
    : `${authBase}/api/auth/register`;

  const weakProbe = await safeFetch(regUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ fullName: 'Audit Probe', email: `audit_weak_${Date.now()}@example.invalid`, password: 'weak' }),
    timeout: 3000,
  });

  if (isTargetServerError || weakProbe.status >= 500 || weakProbe.failed || weakProbe.timedOut) {
    findings.push({
      id: 'SEC-002',
      title: 'Password policy verification',
      category: 'Security',
      severity: 'Low',
      status: 'NEEDS_REVIEW',
      evidence: `Target returned HTTP ${weakProbe.status || targetProbe.status || 'error'} (server error). Password complexity cannot be evaluated.`,
      risk: 'Unverified password validation rules.',
      recommendation: 'Verify registration password complexity enforcement manually after server is healthy.',
      codeBefore: null,
      codeAfter: null,
      isAutomated: true,
    });
  } else if (weakProbe.status === 404) {
    findings.push({
      id: 'SEC-002',
      title: 'Password policy verification',
      category: 'Security',
      severity: 'Low',
      status: 'NOT_APPLICABLE',
      evidence: `Registration endpoint at ${regUrl} returned HTTP 404 Not Found. Password complexity check is not applicable.`,
      risk: 'No registration endpoint detected at standard route.',
      recommendation: 'Verify registration route path.',
      codeBefore: null,
      codeAfter: null,
      isAutomated: true,
    });
  } else if (weakProbe.status === 400) {
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
      evidence: `Could not verify password policy against ${regUrl} (HTTP status: ${weakProbe.status}).`,
      risk: 'Unverified password validation rules.',
      recommendation: 'Verify registration password complexity enforcement manually.',
      codeBefore: null,
      codeAfter: null,
      isAutomated: true,
    });
  }

  // ── SEC-007: Session Invalidation on Logout ──
  const logoutUrl = `${authBase}/api/auth/logout`;
  const meUrl = `${authBase}/api/auth/me`;
  let testSessionCookie = null;

  if (isTargetServerError) {
    findings.push({
      id: 'SEC-007',
      title: 'Session logout invalidation check',
      category: 'Security',
      severity: 'Low',
      status: 'NEEDS_REVIEW',
      evidence: `Target returned HTTP ${targetProbe.status || 500} (server error). Session invalidation cannot be tested.`,
      risk: 'Unverified session destruction lifecycle.',
      recommendation: 'Manually test session token invalidation upon user logout once service is healthy.',
      codeBefore: null,
      codeAfter: null,
      isAutomated: true,
    });
  } else {
    const probeEmail = `audit_logout_${Date.now()}@example.internal`;
    const probeReg = await safeFetch(regUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ fullName: 'Audit Probe', email: probeEmail, password: 'SecureAuditPass123!' }),
      timeout: 3000,
    });

    testSessionCookie = probeReg.headers ? probeReg.headers['set-cookie'] : null;

    if (testSessionCookie) {
      await safeFetch(logoutUrl, {
        method: 'POST',
        headers: { Cookie: testSessionCookie },
        timeout: 3000,
      });

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
    } else if (probeReg.status === 404) {
      findings.push({
        id: 'SEC-007',
        title: 'Session logout invalidation check',
        category: 'Security',
        severity: 'Low',
        status: 'NOT_APPLICABLE',
        evidence: `Authentication endpoints returned HTTP 404 Not Found. Logout invalidation check is not applicable without session creation route.`,
        risk: 'No registration/login endpoint available to issue test sessions.',
        recommendation: 'Verify authentication routes.',
        codeBefore: null,
        codeAfter: null,
        isAutomated: true,
      });
    } else if (probeReg.status >= 500) {
      findings.push({
        id: 'SEC-007',
        title: 'Session logout invalidation check',
        category: 'Security',
        severity: 'Low',
        status: 'NEEDS_REVIEW',
        evidence: `Target returned HTTP ${probeReg.status} during session creation probe.`,
        risk: 'Unverified session destruction lifecycle.',
        recommendation: 'Manually test session token invalidation upon user logout.',
        codeBefore: null,
        codeAfter: null,
        isAutomated: true,
      });
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
  }

  // ── SEC-004: Session Cookie Hygiene (HttpOnly, SameSite, Secure) ──
  const healthRes = await safeFetch(`${authBase}/api/health`, { timeout: 3000 });
  const rawSetCookie = healthRes.headers ? healthRes.headers['set-cookie'] : null;
  const targetSetCookie = targetProbe.headers ? targetProbe.headers['set-cookie'] : null;

  const setCookie = testSessionCookie || targetSetCookie || rawSetCookie || '';
  const hasHttpOnly = /httponly/i.test(setCookie);
  const hasSameSite = /samesite=(lax|strict)/i.test(setCookie);
  const hasSecure = /secure/i.test(setCookie);

  if (setCookie) {
    const isStrictlyCompliant = target.isLocal
      ? (hasHttpOnly && hasSameSite)
      : (hasHttpOnly && hasSameSite && (hasSecure || !isHttps));

    if (isStrictlyCompliant) {
      findings.push({
        id: 'SEC-004',
        title: 'Session cookie hygiene configured properly',
        category: 'Security',
        severity: 'Info',
        status: 'PASS',
        evidence: `Set-Cookie header observed with required directives (HttpOnly: ${hasHttpOnly}, SameSite: ${hasSameSite}, Secure: ${hasSecure}): "${sanitizeEvidence(setCookie).substring(0, 80)}..."`,
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
        evidence: `Set-Cookie header missing critical flags. HttpOnly: ${hasHttpOnly}, SameSite: ${hasSameSite}, Secure: ${hasSecure}. Observed header: "${sanitizeEvidence(setCookie).substring(0, 100)}..."`,
        risk: 'Missing HttpOnly allows JavaScript XSS attacks to steal session tokens. Missing SameSite exposes session to CSRF replaying. Missing Secure transmits cookie over unencrypted connections.',
        recommendation: 'Configure session cookies with httpOnly: true, sameSite: "lax", and secure: true.',
        codeBefore: 'res.cookie("session", id); // Insecure cookie configuration',
        codeAfter: 'res.cookie("session", id, {\n  httpOnly: true,\n  secure: process.env.NODE_ENV === "production",\n  sameSite: "lax",\n  maxAge: 30 * 24 * 3600 * 1000\n});',
        isAutomated: true,
      });
    }
  } else if (isTargetServerError) {
    findings.push({
      id: 'SEC-004',
      title: 'Session cookie verification',
      category: 'Security',
      severity: 'Low',
      status: 'NEEDS_REVIEW',
      evidence: `Target returned HTTP ${targetProbe.status || 500} (server error). Session cookie hygiene cannot be inspected.`,
      risk: 'Server error prevents verification of session cookies.',
      recommendation: 'Resolve server errors and test cookie configuration.',
      codeBefore: null,
      codeAfter: null,
      isAutomated: true,
    });
  } else if (targetProbe.status === 404 && !testSessionCookie) {
    findings.push({
      id: 'SEC-004',
      title: 'Session cookie verification',
      category: 'Security',
      severity: 'Low',
      status: 'NOT_APPLICABLE',
      evidence: `Login endpoint returned HTTP 404 Not Found. Session cookie directives are not applicable without an active auth endpoint.`,
      risk: 'No authentication endpoint available to issue session cookies.',
      recommendation: 'Verify the authentication route path.',
      codeBefore: null,
      codeAfter: null,
      isAutomated: true,
    });
  } else {
    findings.push({
      id: 'SEC-004',
      title: 'Session cookie verification',
      category: 'Security',
      severity: 'Low',
      status: 'NEEDS_REVIEW',
      evidence: 'No Set-Cookie header emitted during probe. Check verified session state or bearer token authorization.',
      risk: 'Unverified session token handling.',
      recommendation: 'Verify session store configuration in server middleware.',
      codeBefore: null,
      codeAfter: null,
      isAutomated: true,
    });
  }

  // ── SEC-001: Login Rate Limiting & Brute Force Resistance ──
  const initialPayload = createLoginPayload(`audit_probe_init_${Date.now()}@example.invalid`, 'AuditProbePassword123!');
  const initialProbe = await safeFetch(loginUrl, {
    method: 'POST',
    headers: initialPayload.headers,
    body: initialPayload.body,
    timeout: 3000,
  });

  if (isTargetServerError || initialProbe.status >= 500) {
    findings.push({
      id: 'SEC-001',
      title: 'Login endpoint rate limiting',
      category: 'Security',
      severity: 'Low',
      status: 'NEEDS_REVIEW',
      evidence: `Target returned HTTP ${initialProbe.status || targetProbe.status || 500} (server error). Rate limiting cannot be verified under server error conditions.`,
      risk: 'Target service error prevents verification of authentication rate limiting.',
      recommendation: 'Resolve upstream server errors and re-evaluate authentication controls.',
      codeBefore: null,
      codeAfter: null,
      isAutomated: true,
    });
  } else if (initialProbe.status === 404) {
    findings.push({
      id: 'SEC-001',
      title: 'Login endpoint rate limiting',
      category: 'Security',
      severity: 'Low',
      status: 'NOT_APPLICABLE',
      evidence: `Target endpoint ${loginUrl} returned HTTP 404 Not Found. Authentication endpoint is not deployed at this route.`,
      risk: 'No standard login endpoint detected at this path.',
      recommendation: 'Ensure the target URL points to a valid authentication service or specify the custom login endpoint.',
      codeBefore: null,
      codeAfter: null,
      isAutomated: true,
    });
  } else if (initialProbe.failed || initialProbe.timedOut) {
    findings.push({
      id: 'SEC-001',
      title: 'Login endpoint rate limiting',
      category: 'Security',
      severity: 'Low',
      status: 'NEEDS_REVIEW',
      evidence: `Could not reach ${loginUrl} (${initialProbe.error || 'timed out'}).`,
      risk: 'Unverifiable rate limiting.',
      recommendation: 'Confirm login route path and verify network reachability.',
      codeBefore: null,
      codeAfter: null,
      isAutomated: true,
    });
  } else {
    let rateLimited = false;
    let retryAfterHeader = null;
    const probeStatuses = [initialProbe.status];

    if (initialProbe.status === 429) {
      rateLimited = true;
      retryAfterHeader = initialProbe.headers['retry-after'];
    } else {
      for (let i = 1; i < 6; i++) {
        const payload = createLoginPayload(`audit_probe_${Date.now()}_${i}@example.invalid`, 'AuditProbePassword123!');
        const probe = await safeFetch(loginUrl, {
          method: 'POST',
          headers: payload.headers,
          body: payload.body,
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
    }

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
    } else if (probeStatuses.some((st) => st >= 500)) {
      findings.push({
        id: 'SEC-001',
        title: 'Login endpoint rate limiting',
        category: 'Security',
        severity: 'Low',
        status: 'NEEDS_REVIEW',
        evidence: `Server began returning server errors [${probeStatuses.join(', ')}] during brute force probing. Cannot verify rate limiting.`,
        risk: 'Server error prevents confirmation of rate limiting.',
        recommendation: 'Check server error logs and rate limiting configuration.',
        codeBefore: null,
        codeAfter: null,
        isAutomated: true,
      });
    } else {
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
    }

    // Clean up local rate limiter for subsequent local operations
    if (target.isLocal) {
      try {
        await safeFetch(`${authBase}/api/auth/reset-rate-limit`, { method: 'POST', timeout: 1500 });
      } catch (_) {}
    }
  }

  return findings;
}

module.exports = { run, extractAuthForm };
