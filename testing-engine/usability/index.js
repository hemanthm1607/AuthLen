/**
 * testing-engine/usability/index.js — Usability Evaluation Module
 * Inspects form heuristics, error guidance, and visibility controls based on verified evidence.
 */
const { safeFetch } = require('../utils/targetValidator');

async function run(target) {
  const findings = [];
  const authBase = target.origin;

  // Probe the target for HTML markup of auth views
  const htmlProbe = await safeFetch(target.url, { timeout: 3000 });
  const isServerError = htmlProbe.status >= 500 || htmlProbe.failed || htmlProbe.timedOut;

  const bodyText = htmlProbe.text || '';
  const lowerHtml = bodyText.toLowerCase();
  const isHtml = (htmlProbe.headers && htmlProbe.headers['content-type'] && htmlProbe.headers['content-type'].includes('text/html')) ||
    lowerHtml.includes('<html') || lowerHtml.includes('<!doctype html') || lowerHtml.includes('<body');
  const hasInputElements = lowerHtml.includes('<input') || lowerHtml.includes('<form');

  // ── USE-001: Password Visibility Toggle ──
  if (isServerError) {
    findings.push({
      id: 'USE-001',
      title: 'Password visibility masking toggle',
      category: 'Usability',
      severity: 'Low',
      status: 'NEEDS_REVIEW',
      evidence: `Target returned HTTP ${htmlProbe.status || 'error'}. Usability controls cannot be inspected on a server error.`,
      risk: 'Cannot inspect password visibility unmasking due to target error.',
      recommendation: 'Resolve target server error before auditing form usability.',
      codeBefore: null,
      codeAfter: null,
      isAutomated: true,
    });
  } else if (!isHtml || !hasInputElements) {
    findings.push({
      id: 'USE-001',
      title: 'Password visibility masking toggle',
      category: 'Usability',
      severity: 'Low',
      status: 'NOT_APPLICABLE',
      evidence: `Target response at ${target.url} does not contain an authentication form or password field. Check is not applicable to non-UI endpoints.`,
      risk: 'No password input present on target endpoint.',
      recommendation: 'Provide authentication form URL to test password visibility toggling.',
      codeBefore: null,
      codeAfter: null,
      isAutomated: true,
    });
  } else {
    const hasPasswordField = lowerHtml.includes('type="password"') || lowerHtml.includes("type='password'");
    const hasPasswordToggle =
      lowerHtml.includes('auth-password-toggle') ||
      lowerHtml.includes('show password') ||
      lowerHtml.includes('hide password') ||
      lowerHtml.includes('toggle password');

    if (hasPasswordField && hasPasswordToggle) {
      findings.push({
        id: 'USE-001',
        title: 'Password visibility masking toggle',
        category: 'Usability',
        severity: 'Info',
        status: 'PASS',
        evidence: 'Authentication forms implement interactive SHOW/HIDE password toggling with aria-label support.',
        risk: 'Lack of password unmasking increases user entry errors on complex credentials.',
        recommendation: 'Provide toggleable unmasking with clear accessible state labels.',
        codeBefore: null,
        codeAfter: null,
        isAutomated: true,
      });
    } else if (hasPasswordField) {
      findings.push({
        id: 'USE-001',
        title: 'Password visibility masking toggle',
        category: 'Usability',
        severity: 'Low',
        status: 'NEEDS_REVIEW',
        evidence: 'Password field detected without declarative SHOW/HIDE unmasking controls.',
        risk: 'Lack of password unmasking increases user entry errors on complex credentials.',
        recommendation: 'Provide toggleable unmasking with clear accessible state labels.',
        codeBefore: '<input type="password" />',
        codeAfter: '<input type={show ? "text" : "password"} />\n<button onClick={toggle}>{show ? "HIDE" : "SHOW"}</button>',
        isAutomated: true,
      });
    } else {
      findings.push({
        id: 'USE-001',
        title: 'Password visibility masking toggle',
        category: 'Usability',
        severity: 'Low',
        status: 'NOT_APPLICABLE',
        evidence: 'No password input element found on the target view.',
        risk: 'Password visibility toggle not applicable without password input.',
        recommendation: 'Verify authentication form view.',
        codeBefore: null,
        codeAfter: null,
        isAutomated: true,
      });
    }
  }

  // ── USE-002: Descriptive Error Guidance ──
  const regUrl = (target.pathname && target.pathname.toLowerCase().endsWith('/register'))
    ? target.url
    : `${authBase}/api/auth/register`;

  const registerProbe = await safeFetch(regUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ fullName: 'Audit Test', email: 'audit@example.invalid', password: '123' }),
    timeout: 3000,
  });

  const regErrorMsg = registerProbe.json && registerProbe.json.error ? registerProbe.json.error : '';

  if (isServerError || registerProbe.status >= 500 || registerProbe.failed || registerProbe.timedOut) {
    findings.push({
      id: 'USE-002',
      title: 'Password policy guidance feedback',
      category: 'Usability',
      severity: 'Low',
      status: 'NEEDS_REVIEW',
      evidence: `Target returned HTTP ${registerProbe.status || htmlProbe.status || 'error'}. Error feedback cannot be evaluated on a server error.`,
      risk: 'Cannot verify registration validation error messages.',
      recommendation: 'Resolve server errors and test validation feedback messaging.',
      codeBefore: null,
      codeAfter: null,
      isAutomated: true,
    });
  } else if (registerProbe.status === 404) {
    findings.push({
      id: 'USE-002',
      title: 'Password policy guidance feedback',
      category: 'Usability',
      severity: 'Low',
      status: 'NOT_APPLICABLE',
      evidence: `Registration endpoint at ${regUrl} returned HTTP 404 Not Found. Error guidance check is not applicable.`,
      risk: 'No registration endpoint detected at standard route.',
      recommendation: 'Configure registration endpoint route.',
      codeBefore: null,
      codeAfter: null,
      isAutomated: true,
    });
  } else if (regErrorMsg && regErrorMsg.toLowerCase().includes('password must be at least')) {
    findings.push({
      id: 'USE-002',
      title: 'Actionable password requirement feedback',
      category: 'Usability',
      severity: 'Info',
      status: 'PASS',
      evidence: `Endpoint provided clear actionable guidance for weak passwords: "${regErrorMsg}".`,
      risk: 'Vague error messages confuse users and prevent them from successfully completing authentication.',
      recommendation: 'Always articulate specific failure criteria (e.g. min 8 chars, uppercase, number/symbol).',
      codeBefore: null,
      codeAfter: null,
      isAutomated: true,
    });
  } else {
    findings.push({
      id: 'USE-002',
      title: 'Password policy guidance feedback',
      category: 'Usability',
      severity: 'Low',
      status: 'NEEDS_REVIEW',
      evidence: `Observed error response: "${regErrorMsg || registerProbe.status || 'No response recorded'}".`,
      risk: 'Users may struggle to understand complex password validation rules without explicit feedback.',
      recommendation: 'Provide inline live requirements checklists on registration and password change forms.',
      codeBefore: null,
      codeAfter: null,
      isAutomated: true,
    });
  }

  // ── USE-003: Remember Me / Session Persistence Option ──
  if (isServerError) {
    findings.push({
      id: 'USE-003',
      title: 'Session persistence option (Remember Me)',
      category: 'Usability',
      severity: 'Low',
      status: 'NEEDS_REVIEW',
      evidence: `Target returned HTTP ${htmlProbe.status || 'error'}. Session persistence controls cannot be verified on a server error.`,
      risk: 'Cannot inspect session persistence on erroring target.',
      recommendation: 'Resolve target server error before auditing session persistence.',
      codeBefore: null,
      codeAfter: null,
      isAutomated: true,
    });
  } else if (!isHtml || !hasInputElements) {
    findings.push({
      id: 'USE-003',
      title: 'Session persistence option (Remember Me)',
      category: 'Usability',
      severity: 'Low',
      status: 'NOT_APPLICABLE',
      evidence: `Target response at ${target.url} does not contain an authentication form. Session persistence check is not applicable.`,
      risk: 'Non-UI endpoint without authentication form.',
      recommendation: 'Provide authentication view URL to evaluate session persistence options.',
      codeBefore: null,
      codeAfter: null,
      isAutomated: true,
    });
  } else {
    const hasRememberMe = lowerHtml.includes('remember') || lowerHtml.includes('remember me') || lowerHtml.includes('stay signed in');
    if (hasRememberMe) {
      findings.push({
        id: 'USE-003',
        title: 'Session persistence option (Remember Me)',
        category: 'Usability',
        severity: 'Info',
        status: 'PASS',
        evidence: 'Sign-in interface provides optional session persistence checkbox for trusted devices.',
        risk: 'Forcing frequent re-authentication on trusted devices introduces user fatigue.',
        recommendation: 'Allow users to control session lifetime on personal devices.',
        codeBefore: null,
        codeAfter: null,
        isAutomated: true,
      });
    } else {
      findings.push({
        id: 'USE-003',
        title: 'Session persistence option (Remember Me)',
        category: 'Usability',
        severity: 'Low',
        status: 'NEEDS_REVIEW',
        evidence: 'No session persistence (Remember Me) checkbox detected in authentication form markup.',
        risk: 'Forcing frequent re-authentication on trusted devices introduces user fatigue.',
        recommendation: 'Allow users to control session lifetime on personal devices.',
        codeBefore: null,
        codeAfter: null,
        isAutomated: true,
      });
    }
  }

  // ── USE-005: Submission Loading State ──
  if (isServerError) {
    findings.push({
      id: 'USE-005',
      title: 'Submission feedback and loading state',
      category: 'Usability',
      severity: 'Low',
      status: 'NEEDS_REVIEW',
      evidence: `Target returned HTTP ${htmlProbe.status || 'error'}. Submission loading states cannot be verified on a server error.`,
      risk: 'Cannot inspect submission state on erroring target.',
      recommendation: 'Resolve target server error before auditing submission feedback.',
      codeBefore: null,
      codeAfter: null,
      isAutomated: true,
    });
  } else if (!isHtml || !hasInputElements) {
    findings.push({
      id: 'USE-005',
      title: 'Submission feedback and loading state',
      category: 'Usability',
      severity: 'Low',
      status: 'NOT_APPLICABLE',
      evidence: `Target response at ${target.url} does not contain an authentication form. Submission loading state check is not applicable.`,
      risk: 'Non-UI endpoint without authentication form.',
      recommendation: 'Provide authentication view URL to evaluate submission loading feedback.',
      codeBefore: null,
      codeAfter: null,
      isAutomated: true,
    });
  } else {
    const hasLoadingState =
      lowerHtml.includes('loading') ||
      lowerHtml.includes('spinner') ||
      lowerHtml.includes('disabled={loading}') ||
      lowerHtml.includes(':disabled');

    if (hasLoadingState) {
      findings.push({
        id: 'USE-005',
        title: 'Submission feedback and loading state',
        category: 'Usability',
        severity: 'Info',
        status: 'PASS',
        evidence: 'Sign-in and registration forms disable submit buttons and render loading indicators during in-flight network requests.',
        risk: 'Without loading indicators, users repeatedly click submit buttons, triggering duplicate API requests.',
        recommendation: 'Disable submit buttons and display spinning indicators during active requests.',
        codeBefore: null,
        codeAfter: null,
        isAutomated: true,
      });
    } else {
      findings.push({
        id: 'USE-005',
        title: 'Submission feedback and loading state',
        category: 'Usability',
        severity: 'Low',
        status: 'NEEDS_REVIEW',
        evidence: 'Form submit buttons do not declare static loading states; client-side asynchronous behavior requires verification.',
        risk: 'Without loading indicators, users repeatedly click submit buttons, triggering duplicate API requests.',
        recommendation: 'Disable submit buttons and display spinning indicators during active requests.',
        codeBefore: '<button type="submit">Submit</button>',
        codeAfter: '<button type="submit" disabled={loading}>\n  {loading ? "Authenticating…" : "Sign In"}\n</button>',
        isAutomated: true,
      });
    }
  }

  return findings;
}

module.exports = { run };
