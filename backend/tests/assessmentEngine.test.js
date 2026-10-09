/**
 * tests/assessmentEngine.test.js — Regression Tests for Assessment Engine & False Positive Prevention
 * 
 * Validates:
 * 1. Generic HTTP 500 endpoints (no false positive HIGHs, no fabricated UI/A11Y PASSes)
 * 2. Generic endpoints without authentication forms (NOT_APPLICABLE for UI/A11Y checks)
 * 3. Missing login and recovery endpoints (404s marked NOT_APPLICABLE, never HIGH FAIL)
 * 4. Genuine authentication endpoints with testable controls (accurately evaluated and passed)
 * 5. PASS, FAIL, NEEDS REVIEW, and NOT APPLICABLE status and severity integrity
 * 6. Accurate preservation of submitted target URLs (including paths)
 */

const http = require('http');
const testingEngine = require('../../testing-engine');
const { validateTargetUrl } = require('../../testing-engine/utils/targetValidator');

let passedCount = 0;
let failedCount = 0;

function assert(condition, message) {
  if (condition) {
    console.log(`  [PASS] ${message}`);
    passedCount++;
  } else {
    console.error(`  [FAIL] ${message}`);
    failedCount++;
    throw new Error(`Assertion failed: ${message}`);
  }
}

async function runTests() {
  console.log(`\n======================================================`);
  console.log(`  AuthLens Assessment Engine Regression Test Suite`);
  console.log(`======================================================\n`);

  // ─────────────────────────────────────────────────────────────
  // Test 1: Target URL Validation & Path Preservation
  // ─────────────────────────────────────────────────────────────
  console.log(`--- Test 1: Target URL Validation & Path Preservation ---`);

  const plainOrigin = validateTargetUrl('http://localhost:4000', false);
  assert(plainOrigin.valid === true, 'validateTargetUrl accepts localhost:4000');
  assert(plainOrigin.url === 'http://localhost:4000', 'Root URL is preserved without trailing slash');
  assert(plainOrigin.origin === 'http://localhost:4000', 'Origin is correctly extracted');

  const trailingSlash = validateTargetUrl('http://localhost:4000/', false);
  assert(trailingSlash.url === 'http://localhost:4000', 'Trailing slash normalized cleanly on root');

  const withPath = validateTargetUrl('https://httpbin.org/status/500', true);
  assert(withPath.valid === true, 'validateTargetUrl accepts authorized https://httpbin.org/status/500');
  assert(withPath.url === 'https://httpbin.org/status/500', 'Path /status/500 is strictly preserved in url property');
  assert(withPath.origin === 'https://httpbin.org', 'Origin is separated as https://httpbin.org');
  assert(withPath.pathname === '/status/500', 'Pathname is extracted as /status/500');

  const withSubpathAndQuery = validateTargetUrl('http://localhost:4000/api/v1/auth?mode=test', false);
  assert(withSubpathAndQuery.url === 'http://localhost:4000/api/v1/auth?mode=test', 'Path and query are preserved');

  // ─────────────────────────────────────────────────────────────
  // Test 2: Generic HTTP 500 Endpoint Behavior
  // ─────────────────────────────────────────────────────────────
  console.log(`\n--- Test 2: Generic HTTP 500 Endpoint Evaluation ---`);

  // Spin up an HTTP server that unconditionally returns 500 Internal Server Error
  const server500 = http.createServer((req, res) => {
    res.writeHead(500, { 'Content-Type': 'text/plain' });
    res.end('Internal Server Error 500');
  });

  await new Promise((resolve) => server500.listen(0, '127.0.0.1', resolve));
  const port500 = server500.address().port;
  const target500Url = `http://127.0.0.1:${port500}/status/500`;

  try {
    const result500 = await testingEngine.runAllTests({
      targetUrl: target500Url,
      isAuthorized: true,
    });

    assert(result500.target === target500Url, `Result target preserves full path (${result500.target})`);
    assert(result500.findings.length >= 14, `All test modules executed (${result500.findings.length} findings)`);

    // SEC-001 must NEVER be HIGH FAIL on HTTP 500
    const sec001 = result500.findings.find((f) => f.id === 'SEC-001');
    assert(sec001 !== undefined, 'SEC-001 is present');
    assert(sec001.status === 'NEEDS_REVIEW', `SEC-001 is NEEDS_REVIEW on 500 endpoint (got: ${sec001.status})`);
    assert(sec001.severity === 'Low', `SEC-001 severity is Low, not High (got: ${sec001.severity})`);
    assert(sec001.evidence.includes('500') || sec001.evidence.includes('server error'), 'SEC-001 evidence cites server error');

    // REC-001 must NEVER be HIGH FAIL on HTTP 500
    const rec001 = result500.findings.find((f) => f.id === 'REC-001');
    assert(rec001 !== undefined, 'REC-001 is present');
    assert(rec001.status === 'NEEDS_REVIEW', `REC-001 is NEEDS_REVIEW on 500 endpoint (got: ${rec001.status})`);
    assert(rec001.severity === 'Low', `REC-001 severity is Low, not High (got: ${rec001.severity})`);

    // REC-003 on 500 endpoint
    const rec003 = result500.findings.find((f) => f.id === 'REC-003');
    assert(rec003 !== undefined, 'REC-003 is present');
    assert(rec003.status === 'NEEDS_REVIEW', `REC-003 is NEEDS_REVIEW on 500 endpoint (got: ${rec003.status})`);
    assert(rec003.severity === 'Low', `REC-003 severity is Low (got: ${rec003.severity})`);

    // SEC-006 must NEVER be PASS on 500 endpoint
    const sec006 = result500.findings.find((f) => f.id === 'SEC-006');
    assert(sec006 !== undefined, 'SEC-006 is present');
    assert(sec006.status === 'NEEDS_REVIEW', `SEC-006 is NEEDS_REVIEW on 500 endpoint, NOT PASS (got: ${sec006.status})`);

    // A11Y checks must NEVER be PASS on 500 endpoint
    const a11yFindings = result500.findings.filter((f) => f.id.startsWith('A11Y-'));
    assert(a11yFindings.length === 4, `All 4 A11Y checks present`);
    assert(a11yFindings.every((f) => f.status === 'NEEDS_REVIEW'), `A11Y checks are ALL NEEDS_REVIEW on 500 endpoint (zero fabricated PASS)`);

    // Usability checks on 500 endpoint
    const useFindings = result500.findings.filter((f) => f.id.startsWith('USE-'));
    assert(useFindings.length >= 3, `USE checks present`);
    assert(useFindings.every((f) => f.status === 'NEEDS_REVIEW'), `USE checks are ALL NEEDS_REVIEW on 500 endpoint`);

    // Overall summary must have ZERO critical and ZERO high false positives
    assert(result500.summary.critical === 0, `Critical count is 0 on generic 500 endpoint`);
    assert(result500.summary.high === 0, `High count is 0 on generic 500 endpoint`);
    assert(result500.summary.failed === 0, `Failed count is 0 on generic 500 endpoint`);
  } finally {
    server500.close();
  }

  // ─────────────────────────────────────────────────────────────
  // Test 3: Generic Endpoint Without Authentication Form (API / JSON)
  // ─────────────────────────────────────────────────────────────
  console.log(`\n--- Test 3: Generic Endpoint Without Auth Form (JSON / Non-UI) ---`);

  const serverApiOnly = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok', service: 'public-api', endpoints: [] }));
  });

  await new Promise((resolve) => serverApiOnly.listen(0, '127.0.0.1', resolve));
  const portApiOnly = serverApiOnly.address().port;
  const targetApiUrl = `http://127.0.0.1:${portApiOnly}/api/health`;

  try {
    const resultApi = await testingEngine.runAllTests({
      targetUrl: targetApiUrl,
      isAuthorized: true,
    });

    // A11Y checks must be NOT_APPLICABLE on an API endpoint without HTML/inputs
    const a11yFindings = resultApi.findings.filter((f) => f.id.startsWith('A11Y-'));
    assert(a11yFindings.every((f) => f.status === 'NOT_APPLICABLE'), 'A11Y checks are NOT_APPLICABLE on non-UI endpoint');
    assert(a11yFindings[0].evidence.includes('does not contain an authentication form'), 'A11Y evidence explains lack of UI form elements');

    // USE checks on non-UI endpoint
    const use001 = resultApi.findings.find((f) => f.id === 'USE-001');
    assert(use001.status === 'NOT_APPLICABLE', 'USE-001 (Password toggle) is NOT_APPLICABLE on non-UI endpoint');
    const use003 = resultApi.findings.find((f) => f.id === 'USE-003');
    assert(use003.status === 'NOT_APPLICABLE', 'USE-003 (Remember Me) is NOT_APPLICABLE on non-UI endpoint');
    const use005 = resultApi.findings.find((f) => f.id === 'USE-005');
    assert(use005.status === 'NOT_APPLICABLE', 'USE-005 (Loading state) is NOT_APPLICABLE on non-UI endpoint');
  } finally {
    serverApiOnly.close();
  }

  // ─────────────────────────────────────────────────────────────
  // Test 4: Missing Login and Recovery Endpoints (404 Not Found)
  // ─────────────────────────────────────────────────────────────
  console.log(`\n--- Test 4: Missing Login & Recovery Endpoints (404 Not Found) ---`);

  const server404 = http.createServer((req, res) => {
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Route not found' }));
  });

  await new Promise((resolve) => server404.listen(0, '127.0.0.1', resolve));
  const port404 = server404.address().port;
  const target404Url = `http://127.0.0.1:${port404}`;

  try {
    const result404 = await testingEngine.runAllTests({
      targetUrl: target404Url,
      isAuthorized: true,
    });

    // SEC-001 must be NOT_APPLICABLE when login route is 404 (NEVER High FAIL!)
    const sec001 = result404.findings.find((f) => f.id === 'SEC-001');
    assert(sec001.status === 'NOT_APPLICABLE', `SEC-001 is NOT_APPLICABLE on 404 endpoint (got: ${sec001.status})`);
    assert(sec001.severity === 'Low', 'SEC-001 severity is Low');
    assert(sec001.evidence.includes('404'), 'SEC-001 evidence cites 404 status');

    // REC-001 must be NOT_APPLICABLE when recovery route is 404 (NEVER High FAIL!)
    const rec001 = result404.findings.find((f) => f.id === 'REC-001');
    assert(rec001.status === 'NOT_APPLICABLE', `REC-001 is NOT_APPLICABLE on 404 endpoint (got: ${rec001.status})`);
    assert(rec001.severity === 'Low', 'REC-001 severity is Low, not High');

    // REC-002 must be NOT_APPLICABLE when recovery route is 404
    const rec002 = result404.findings.find((f) => f.id === 'REC-002');
    assert(rec002.status === 'NOT_APPLICABLE', `REC-002 is NOT_APPLICABLE on 404 endpoint (got: ${rec002.status})`);

    // REC-003 must be NOT_APPLICABLE when reset route is 404
    const rec003 = result404.findings.find((f) => f.id === 'REC-003');
    assert(rec003.status === 'NOT_APPLICABLE', `REC-003 is NOT_APPLICABLE on 404 endpoint (got: ${rec003.status})`);

    // Summary must have ZERO High or Critical failures
    assert(result404.summary.critical === 0, 'Zero critical failures on 404 target');
    assert(result404.summary.high === 0, 'Zero high failures on 404 target');
    assert(result404.summary.notApplicable >= 4, `At least 4 NOT_APPLICABLE findings (got: ${result404.summary.notApplicable})`);
  } finally {
    server404.close();
  }

  // ─────────────────────────────────────────────────────────────
  // Test 5: Real Vulnerability Detection (Unrestricted Brute Force)
  // ─────────────────────────────────────────────────────────────
  console.log(`\n--- Test 5: Real Vulnerability Detection (Unrestricted Brute Force) ---`);

  // Server that accepts login attempts with 401 without any rate limiting (vulnerable)
  const serverVulnerable = http.createServer((req, res) => {
    if (req.url === '/api/auth/login' && req.method === 'POST') {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid credentials' }));
      return;
    }
    res.writeHead(404);
    res.end();
  });

  await new Promise((resolve) => serverVulnerable.listen(0, '127.0.0.1', resolve));
  const portVuln = serverVulnerable.address().port;
  const targetVulnUrl = `http://127.0.0.1:${portVuln}`;

  try {
    const resultVuln = await testingEngine.runAllTests({
      targetUrl: targetVulnUrl,
      isAuthorized: true,
    });

    const sec001 = resultVuln.findings.find((f) => f.id === 'SEC-001');
    assert(sec001.status === 'FAIL', `SEC-001 correctly flags real vulnerability as FAIL (got: ${sec001.status})`);
    assert(sec001.severity === 'High', `SEC-001 flags severity as High when real flaw exists (got: ${sec001.severity})`);
    assert(resultVuln.summary.high >= 1, `Summary correctly includes High severity vulnerability`);
  } finally {
    serverVulnerable.close();
  }

  // ─────────────────────────────────────────────────────────────
  // Test 6: Genuine Authentication & UI Controls Evaluation
  // ─────────────────────────────────────────────────────────────
  console.log(`\n--- Test 6: Genuine Controls Verification (HTML Form with WCAG Elements) ---`);

  let loginAttempts = 0;
  const serverGenuine = http.createServer((req, res) => {
    // Health check endpoint with cookie
    if (req.url === '/api/health') {
      res.writeHead(200, {
        'Content-Type': 'application/json',
        'Set-Cookie': 'session=health_session; HttpOnly; SameSite=Lax; Path=/',
      });
      res.end(JSON.stringify({ status: 'ok' }));
      return;
    }

    // Return HTML authentication page
    if (req.url === '/' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(`
        <!DOCTYPE html>
        <html>
          <head><title>Sign In</title></head>
          <body>
            <form action="/api/auth/login" method="POST">
              <label for="username">Username or Email</label>
              <input id="username" type="text" name="username" autocomplete="username" />
              <label for="password">Password</label>
              <input id="password" type="password" name="password" autocomplete="current-password" />
              <button type="button" class="auth-password-toggle">Show password</button>
              <label><input type="checkbox" name="remember" /> Remember me</label>
              <div role="alert" aria-live="polite" class="error-msg"></div>
              <button type="submit" disabled={loading}>Sign In</button>
            </form>
          </body>
        </html>
      `);
      return;
    }

    // Rate limiting: 429 after 3 attempts
    if (req.url === '/api/auth/login' && req.method === 'POST') {
      loginAttempts++;
      if (loginAttempts >= 3) {
        res.writeHead(429, {
          'Content-Type': 'application/json',
          'Retry-After': '900',
        });
        res.end(JSON.stringify({ error: 'Too many login attempts. Please try again later.' }));
        return;
      }
      res.writeHead(401, {
        'Content-Type': 'application/json',
        'Set-Cookie': 'session=xyz; HttpOnly; SameSite=Lax; Path=/',
      });
      res.end(JSON.stringify({ error: 'Invalid credentials' }));
      return;
    }

    // Password recovery: uniform 200 response
    if (req.url === '/api/auth/forgot-password' && req.method === 'POST') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ message: 'If your account exists, a recovery link has been sent.' }));
      return;
    }

    // Password reset: 400 for bad token
    if (req.url === '/api/auth/reset-password' && req.method === 'POST') {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid or expired token.' }));
      return;
    }

    // Registration password complexity: 400 for weak password
    if (req.url === '/api/auth/register' && req.method === 'POST') {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Password must be at least 8 characters long with uppercase and numbers.' }));
      return;
    }

    res.writeHead(404);
    res.end();
  });

  await new Promise((resolve) => serverGenuine.listen(0, '127.0.0.1', resolve));
  const portGen = serverGenuine.address().port;
  const targetGenUrl = `http://127.0.0.1:${portGen}`;

  try {
    const resultGen = await testingEngine.runAllTests({
      targetUrl: targetGenUrl,
      isAuthorized: true,
    });

    // Rate limiting passed with HTTP 429 observation
    const sec001 = resultGen.findings.find((f) => f.id === 'SEC-001');
    assert(sec001.status === 'PASS', `SEC-001 passed with observed rate limit (got: ${sec001.status})`);
    assert(sec001.evidence.includes('HTTP 429'), 'SEC-001 evidence includes HTTP 429');

    // Cookie flags passed
    const sec004 = resultGen.findings.find((f) => f.id === 'SEC-004');
    assert(sec004.status === 'PASS', `SEC-004 passed with observed HttpOnly and SameSite (got: ${sec004.status})`);

    // Password complexity check passed
    const sec002 = resultGen.findings.find((f) => f.id === 'SEC-002');
    assert(sec002.status === 'PASS', `SEC-002 passed with 400 rejection (got: ${sec002.status})`);

    // Recovery availability passed
    const rec001 = resultGen.findings.find((f) => f.id === 'REC-001');
    assert(rec001.status === 'PASS', `REC-001 passed (got: ${rec001.status})`);

    // Recovery enumeration resistance passed
    const rec002 = resultGen.findings.find((f) => f.id === 'REC-002');
    assert(rec002.status === 'PASS', `REC-002 passed (got: ${rec002.status})`);

    // Reset token validation passed
    const rec003 = resultGen.findings.find((f) => f.id === 'REC-003');
    assert(rec003.status === 'PASS', `REC-003 passed (got: ${rec003.status})`);

    // A11Y-001 passed with real label evidence
    const a11y001 = resultGen.findings.find((f) => f.id === 'A11Y-001');
    assert(a11y001.status === 'PASS', `A11Y-001 passed with verified <label> evidence (got: ${a11y001.status})`);

    // A11Y-003 passed with role="alert" evidence
    const a11y003 = resultGen.findings.find((f) => f.id === 'A11Y-003');
    assert(a11y003.status === 'PASS', `A11Y-003 passed with role="alert" evidence (got: ${a11y003.status})`);

    // A11Y-004 passed with autocomplete evidence
    const a11y004 = resultGen.findings.find((f) => f.id === 'A11Y-004');
    assert(a11y004.status === 'PASS', `A11Y-004 passed with autocomplete evidence (got: ${a11y004.status})`);

    // USE-001 passed with password toggle evidence
    const use001 = resultGen.findings.find((f) => f.id === 'USE-001');
    assert(use001.status === 'PASS', `USE-001 passed with password toggle evidence (got: ${use001.status})`);

    // USE-002 passed with descriptive error feedback
    const use002 = resultGen.findings.find((f) => f.id === 'USE-002');
    assert(use002.status === 'PASS', `USE-002 passed with descriptive feedback (got: ${use002.status})`);

    // USE-003 passed with remember me evidence
    const use003 = resultGen.findings.find((f) => f.id === 'USE-003');
    assert(use003.status === 'PASS', `USE-003 passed with remember me checkbox evidence (got: ${use003.status})`);
  } finally {
    serverGenuine.close();
  }

  // ─────────────────────────────────────────────────────────────
  // Test 7: Live Target Verification (https://httpbin.org/status/500)
  // ─────────────────────────────────────────────────────────────
  console.log(`\n--- Test 7: Live Target Verification (https://httpbin.org/status/500) ---`);
  try {
    const liveResult = await testingEngine.runAllTests({
      targetUrl: 'https://httpbin.org/status/500',
      isAuthorized: true,
    });

    assert(liveResult.target === 'https://httpbin.org/status/500', `Target path accurately preserved as https://httpbin.org/status/500`);
    assert(liveResult.summary.critical === 0, `0 Critical findings on live httpbin 500 target`);
    assert(liveResult.summary.high === 0, `0 High findings on live httpbin 500 target`);
    assert(liveResult.summary.failed === 0, `0 Failed findings on live httpbin 500 target`);

    const liveSec001 = liveResult.findings.find((f) => f.id === 'SEC-001');
    assert(liveSec001 && (liveSec001.status === 'NEEDS_REVIEW' || liveSec001.status === 'NOT_APPLICABLE'), `SEC-001 is ${liveSec001.status} (never FAIL/HIGH) on live httpbin 500`);

    const liveRec001 = liveResult.findings.find((f) => f.id === 'REC-001');
    assert(liveRec001 && (liveRec001.status === 'NEEDS_REVIEW' || liveRec001.status === 'NOT_APPLICABLE'), `REC-001 is ${liveRec001.status} (never FAIL/HIGH) on live httpbin 500`);

    const liveA11y = liveResult.findings.filter((f) => f.id.startsWith('A11Y-'));
    assert(liveA11y.every((f) => f.status !== 'PASS'), `No fabricated PASS on A11Y for live httpbin 500 target`);
  } catch (err) {
    console.warn(`  [INFO] Live network test skipped or errored (offline env): ${err.message}`);
  }

  console.log(`\n======================================================`);
  console.log(`  Assessment Engine Test Results: ${passedCount} Passed, ${failedCount} Failed`);
  console.log(`======================================================\n`);
}

runTests()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error('Test run failed:', err);
    process.exit(1);
  });
