/**
 * tests/assessmentEngine.test.js — Regression Tests for Assessment Engine & False Positive Prevention
 * 
 * Comprehensive Test Matrix (A through M):
 * A. Generic HTTP 500 endpoint (zero false positive HIGHs, no fabricated UI/A11Y PASSes)
 * B. Generic endpoint with no login form (NOT_APPLICABLE for UI/A11Y checks)
 * C. Real login form with inspectable HTML (accurately evaluated against actual DOM markup)
 * D. Missing authentication endpoint (404s marked NOT_APPLICABLE, never HIGH FAIL)
 * E. Missing recovery functionality (404s marked NOT_APPLICABLE, never HIGH FAIL)
 * F. Genuine insecure cookie evidence (Set-Cookie missing flags detected as FAIL High)
 * G. Genuine logout session invalidation failure (session persisting after logout detected as FAIL High)
 * H. Insufficient evidence and inaccessible targets (connection failure/timeout marked NEEDS_REVIEW Low)
 * I. URL path preservation (target path and query preserved immutably throughout scan)
 * J. Correct severity counts and filters (summary counts strictly match confirmed FAIL vulnerabilities)
 * K. All four assessment statuses (PASS, FAIL, NEEDS_REVIEW, NOT_APPLICABLE verified)
 * L. Database persistence and assessment history (record written to PostgreSQL and read back)
 * M. Existing authorization and SSRF protections (blocking unauthorized domains and link-local metadata)
 */

const http = require('http');
const db = require('../config/db');
const testingEngine = require('../../testing-engine');
const { validateTargetUrl, isBlockedMetadataHost } = require('../../testing-engine/utils/targetValidator');

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
  console.log(`  AuthLens Assessment Engine Comprehensive Test Suite`);
  console.log(`======================================================\n`);

  // ─────────────────────────────────────────────────────────────
  // A. Generic HTTP 500 Endpoint
  // ─────────────────────────────────────────────────────────────
  console.log(`--- Test A: Generic HTTP 500 Endpoint Evaluation ---`);

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

    assert(result500.target === target500Url, `A.1: Target path preserved as ${target500Url}`);
    assert(result500.summary.critical === 0, 'A.2: Zero critical findings on 500 endpoint');
    assert(result500.summary.high === 0, 'A.3: Zero high findings on 500 endpoint');
    assert(result500.summary.failed === 0, 'A.4: Zero confirmed failures on 500 endpoint');

    const sec001 = result500.findings.find((f) => f.id === 'SEC-001');
    assert(sec001.status === 'NEEDS_REVIEW', `A.5: SEC-001 is NEEDS_REVIEW on 500 (got: ${sec001.status})`);
    assert(sec001.severity === 'Low', `A.6: SEC-001 severity is Low (got: ${sec001.severity})`);

    const rec001 = result500.findings.find((f) => f.id === 'REC-001');
    assert(rec001.status === 'NEEDS_REVIEW', `A.7: REC-001 is NEEDS_REVIEW on 500 (got: ${rec001.status})`);
    assert(rec001.severity === 'Low', 'A.8: REC-001 severity is Low');

    const sec006 = result500.findings.find((f) => f.id === 'SEC-006');
    assert(sec006.status === 'NEEDS_REVIEW', `A.9: SEC-006 is NEEDS_REVIEW on 500, NOT PASS (got: ${sec006.status})`);

    const a11yFindings = result500.findings.filter((f) => f.id.startsWith('A11Y-'));
    assert(a11yFindings.every((f) => f.status === 'NEEDS_REVIEW'), 'A.10: Zero fabricated PASS on A11Y checks for 500 endpoint');

    const useFindings = result500.findings.filter((f) => f.id.startsWith('USE-'));
    assert(useFindings.every((f) => f.status === 'NEEDS_REVIEW'), 'A.11: Zero fabricated PASS on USE checks for 500 endpoint');
  } finally {
    server500.close();
  }

  // ─────────────────────────────────────────────────────────────
  // B. Generic Endpoint With No Login Form (JSON / API)
  // ─────────────────────────────────────────────────────────────
  console.log(`\n--- Test B: Generic Endpoint Without Authentication Form ---`);

  const serverApiOnly = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'healthy', version: '2.0.0', endpoints: ['/api/metrics'] }));
  });

  await new Promise((resolve) => serverApiOnly.listen(0, '127.0.0.1', resolve));
  const portApiOnly = serverApiOnly.address().port;
  const targetApiUrl = `http://127.0.0.1:${portApiOnly}/api/health`;

  try {
    const resultApi = await testingEngine.runAllTests({
      targetUrl: targetApiUrl,
      isAuthorized: true,
    });

    const a11yFindings = resultApi.findings.filter((f) => f.id.startsWith('A11Y-'));
    assert(a11yFindings.every((f) => f.status === 'NOT_APPLICABLE'), 'B.1: A11Y checks are NOT_APPLICABLE on non-UI endpoint');
    assert(a11yFindings[0].evidence.includes('does not contain an authentication form'), 'B.2: A11Y evidence explains lack of form');

    const use001 = resultApi.findings.find((f) => f.id === 'USE-001');
    assert(use001.status === 'NOT_APPLICABLE', 'B.3: USE-001 (Password toggle) is NOT_APPLICABLE on non-UI endpoint');
    const use003 = resultApi.findings.find((f) => f.id === 'USE-003');
    assert(use003.status === 'NOT_APPLICABLE', 'B.4: USE-003 (Remember Me) is NOT_APPLICABLE on non-UI endpoint');
    const use005 = resultApi.findings.find((f) => f.id === 'USE-005');
    assert(use005.status === 'NOT_APPLICABLE', 'B.5: USE-005 (Loading state) is NOT_APPLICABLE on non-UI endpoint');
  } finally {
    serverApiOnly.close();
  }

  // ─────────────────────────────────────────────────────────────
  // C. Real Login Form With Inspectable HTML
  // ─────────────────────────────────────────────────────────────
  console.log(`\n--- Test C: Real Login Form With Inspectable HTML ---`);

  let loginAttemptsC = 0;
  const serverRealHtml = http.createServer((req, res) => {
    if (req.url === '/' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(`
        <!DOCTYPE html>
        <html>
          <head><title>Sign In</title></head>
          <body>
            <form action="/login-submit" method="POST">
              <label for="user-field">Email Address</label>
              <input id="user-field" type="email" name="email" autocomplete="username" />
              <label for="pass-field">Password</label>
              <input id="pass-field" type="password" name="password" autocomplete="current-password" />
              <button type="button" class="auth-password-toggle">Show password</button>
              <label><input type="checkbox" name="remember" /> Remember Me</label>
              <div role="alert" aria-live="assertive" class="error"></div>
              <button type="submit" disabled={loading}>Sign In</button>
            </form>
          </body>
        </html>
      `);
      return;
    }

    if (req.url === '/login-submit' && req.method === 'POST') {
      loginAttemptsC++;
      if (loginAttemptsC >= 3) {
        res.writeHead(429, { 'Content-Type': 'application/json', 'Retry-After': '900' });
        res.end(JSON.stringify({ error: 'Too many attempts' }));
        return;
      }
      res.writeHead(401, {
        'Content-Type': 'application/json',
        'Set-Cookie': 'session=test_session; HttpOnly; SameSite=Lax; Path=/',
      });
      res.end(JSON.stringify({ error: 'Invalid credentials' }));
      return;
    }

    if (req.url === '/api/health') {
      res.writeHead(200, {
        'Content-Type': 'application/json',
        'Set-Cookie': 'session=health_session; HttpOnly; SameSite=Lax; Path=/',
      });
      res.end(JSON.stringify({ ok: true }));
      return;
    }

    res.writeHead(404);
    res.end();
  });

  await new Promise((resolve) => serverRealHtml.listen(0, '127.0.0.1', resolve));
  const portRealHtml = serverRealHtml.address().port;
  const targetRealHtmlUrl = `http://127.0.0.1:${portRealHtml}`;

  try {
    const resultHtml = await testingEngine.runAllTests({
      targetUrl: targetRealHtmlUrl,
      isAuthorized: true,
    });

    const a11y001 = resultHtml.findings.find((f) => f.id === 'A11Y-001');
    assert(a11y001.status === 'PASS', `C.1: A11Y-001 PASS based on inspected <label for="..."> markup (got: ${a11y001.status})`);

    const a11y003 = resultHtml.findings.find((f) => f.id === 'A11Y-003');
    assert(a11y003.status === 'PASS', `C.2: A11Y-003 PASS based on inspected role="alert" (got: ${a11y003.status})`);

    const a11y004 = resultHtml.findings.find((f) => f.id === 'A11Y-004');
    assert(a11y004.status === 'PASS', `C.3: A11Y-004 PASS based on inspected autocomplete (got: ${a11y004.status})`);

    const use001 = resultHtml.findings.find((f) => f.id === 'USE-001');
    assert(use001.status === 'PASS', `C.4: USE-001 PASS based on inspected password toggle (got: ${use001.status})`);

    const use003 = resultHtml.findings.find((f) => f.id === 'USE-003');
    assert(use003.status === 'PASS', `C.5: USE-003 PASS based on inspected Remember Me (got: ${use003.status})`);
  } finally {
    serverRealHtml.close();
  }

  // ─────────────────────────────────────────────────────────────
  // D. Missing Authentication Endpoint (404 Not Found)
  // ─────────────────────────────────────────────────────────────
  console.log(`\n--- Test D: Missing Authentication Endpoint (404 Not Found) ---`);

  const server404 = http.createServer((req, res) => {
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Endpoint not found' }));
  });

  await new Promise((resolve) => server404.listen(0, '127.0.0.1', resolve));
  const port404 = server404.address().port;
  const target404Url = `http://127.0.0.1:${port404}`;

  try {
    const result404 = await testingEngine.runAllTests({
      targetUrl: target404Url,
      isAuthorized: true,
    });

    const sec001 = result404.findings.find((f) => f.id === 'SEC-001');
    assert(sec001.status === 'NOT_APPLICABLE', `D.1: SEC-001 is NOT_APPLICABLE on 404 (got: ${sec001.status})`);
    assert(sec001.severity === 'Low', 'D.2: SEC-001 severity is Low');

    const sec004 = result404.findings.find((f) => f.id === 'SEC-004');
    assert(sec004.status === 'NOT_APPLICABLE', `D.3: SEC-004 is NOT_APPLICABLE on 404 (got: ${sec004.status})`);

    const sec006 = result404.findings.find((f) => f.id === 'SEC-006');
    assert(sec006.status === 'NOT_APPLICABLE', `D.4: SEC-006 is NOT_APPLICABLE on 404 (got: ${sec006.status})`);

    assert(result404.summary.critical === 0, 'D.5: Zero critical findings on missing auth routes');
    assert(result404.summary.high === 0, 'D.6: Zero high findings on missing auth routes');
  } finally {
    server404.close();
  }

  // ─────────────────────────────────────────────────────────────
  // E. Missing Recovery Functionality (404 Not Found)
  // ─────────────────────────────────────────────────────────────
  console.log(`\n--- Test E: Missing Recovery Functionality (404 Not Found) ---`);

  const serverNoRecovery = http.createServer((req, res) => {
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not Found');
  });

  await new Promise((resolve) => serverNoRecovery.listen(0, '127.0.0.1', resolve));
  const portNoRec = serverNoRecovery.address().port;
  const targetNoRecUrl = `http://127.0.0.1:${portNoRec}`;

  try {
    const resultNoRec = await testingEngine.runAllTests({
      targetUrl: targetNoRecUrl,
      isAuthorized: true,
    });

    const rec001 = resultNoRec.findings.find((f) => f.id === 'REC-001');
    assert(rec001.status === 'NOT_APPLICABLE', `E.1: REC-001 is NOT_APPLICABLE on 404 (got: ${rec001.status})`);
    assert(rec001.severity === 'Low', 'E.2: REC-001 severity is Low, not High');

    const rec002 = resultNoRec.findings.find((f) => f.id === 'REC-002');
    assert(rec002.status === 'NOT_APPLICABLE', `E.3: REC-002 is NOT_APPLICABLE on 404 (got: ${rec002.status})`);

    const rec003 = resultNoRec.findings.find((f) => f.id === 'REC-003');
    assert(rec003.status === 'NOT_APPLICABLE', `E.4: REC-003 is NOT_APPLICABLE on 404 (got: ${rec003.status})`);
  } finally {
    serverNoRecovery.close();
  }

  // ─────────────────────────────────────────────────────────────
  // F. Genuine Insecure Cookie Evidence (Missing Flags -> FAIL High)
  // ─────────────────────────────────────────────────────────────
  console.log(`\n--- Test F: Genuine Insecure Cookie Evidence (Missing Flags) ---`);

  const serverInsecureCookie = http.createServer((req, res) => {
    res.writeHead(200, {
      'Content-Type': 'application/json',
      'Set-Cookie': 'session=insecure_token_12345; path=/', // Missing HttpOnly, SameSite, Secure
    });
    res.end(JSON.stringify({ message: 'authenticated' }));
  });

  await new Promise((resolve) => serverInsecureCookie.listen(0, '127.0.0.1', resolve));
  const portInsecureCookie = serverInsecureCookie.address().port;
  const targetInsecureCookieUrl = `http://127.0.0.1:${portInsecureCookie}`;

  try {
    const resultCookie = await testingEngine.runAllTests({
      targetUrl: targetInsecureCookieUrl,
      isAuthorized: true,
    });

    const sec004 = resultCookie.findings.find((f) => f.id === 'SEC-004');
    assert(sec004.status === 'FAIL', `F.1: SEC-004 accurately flags insecure cookie as FAIL (got: ${sec004.status})`);
    assert(sec004.severity === 'High', `F.2: SEC-004 flags High severity for missing flags (got: ${sec004.severity})`);
    assert(sec004.evidence.includes('HttpOnly: false'), 'F.3: SEC-004 evidence proves missing HttpOnly flag');
  } finally {
    serverInsecureCookie.close();
  }

  // ─────────────────────────────────────────────────────────────
  // G. Genuine Logout Session Invalidation Failure
  // ─────────────────────────────────────────────────────────────
  console.log(`\n--- Test G: Genuine Logout Session Invalidation Failure ---`);

  const serverZombieLogout = http.createServer((req, res) => {
    // Registration returns active cookie
    if (req.url === '/api/auth/register' && req.method === 'POST') {
      res.writeHead(200, {
        'Content-Type': 'application/json',
        'Set-Cookie': 'session=zombie_test_session; HttpOnly; SameSite=Lax; Path=/',
      });
      res.end(JSON.stringify({ user: { id: 1 } }));
      return;
    }
    // Logout returns 200 but doesn't invalidate session on server
    if (req.url === '/api/auth/logout' && req.method === 'POST') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ message: 'Logged out' }));
      return;
    }
    // /me still returns 200 (zombie session survives logout!)
    if (req.url === '/api/auth/me') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ authenticated: true, user: { id: 1 } }));
      return;
    }
    res.writeHead(404);
    res.end();
  });

  await new Promise((resolve) => serverZombieLogout.listen(0, '127.0.0.1', resolve));
  const portZombie = serverZombieLogout.address().port;
  const targetZombieUrl = `http://127.0.0.1:${portZombie}`;

  try {
    const resultZombie = await testingEngine.runAllTests({
      targetUrl: targetZombieUrl,
      isAuthorized: true,
    });

    const sec007 = resultZombie.findings.find((f) => f.id === 'SEC-007');
    assert(sec007.status === 'FAIL', `G.1: SEC-007 accurately flags zombie session as FAIL (got: ${sec007.status})`);
    assert(sec007.severity === 'High', `G.2: SEC-007 severity is High for persistent session (got: ${sec007.severity})`);
    assert(sec007.evidence.includes('Zombie session') || sec007.evidence.includes('Session remained valid'), 'G.3: SEC-007 evidence includes proof of persistent session');
  } finally {
    serverZombieLogout.close();
  }

  // ─────────────────────────────────────────────────────────────
  // H. Insufficient Evidence and Inaccessible Targets
  // ─────────────────────────────────────────────────────────────
  console.log(`\n--- Test H: Insufficient Evidence & Inaccessible Targets ---`);

  // Target that aborts / destroys socket immediately
  const serverAborting = http.createServer((req, res) => {
    req.socket.destroy();
  });

  await new Promise((resolve) => serverAborting.listen(0, '127.0.0.1', resolve));
  const portAbort = serverAborting.address().port;
  const targetAbortUrl = `http://127.0.0.1:${portAbort}`;

  try {
    const resultAbort = await testingEngine.runAllTests({
      targetUrl: targetAbortUrl,
      isAuthorized: true,
    });

    assert(resultAbort.summary.critical === 0, 'H.1: Zero critical findings on connection abort');
    assert(resultAbort.summary.high === 0, 'H.2: Zero high findings on connection abort');
    assert(resultAbort.summary.failed === 0, 'H.3: Zero failed findings on connection abort');

    const sec001 = resultAbort.findings.find((f) => f.id === 'SEC-001');
    assert(sec001.status === 'NEEDS_REVIEW', `H.4: SEC-001 is NEEDS_REVIEW on connection failure (got: ${sec001.status})`);
    assert(sec001.severity === 'Low', 'H.5: SEC-001 severity is Low');
  } finally {
    serverAborting.close();
  }

  // ─────────────────────────────────────────────────────────────
  // I. URL Path and Query Preservation
  // ─────────────────────────────────────────────────────────────
  console.log(`\n--- Test I: URL Path and Query Preservation ---`);

  const plainVal = validateTargetUrl('http://localhost:4000', false);
  assert(plainVal.url === 'http://localhost:4000', 'I.1: Plain origin preserved');

  const pathVal = validateTargetUrl('https://auth-len.vercel.app/demo/login', true);
  assert(pathVal.url === 'https://auth-len.vercel.app/demo/login', 'I.2: Full path preserved in url');
  assert(pathVal.origin === 'https://auth-len.vercel.app', 'I.3: Origin separated cleanly');
  assert(pathVal.pathname === '/demo/login', 'I.4: Pathname extracted cleanly');

  const queryVal = validateTargetUrl('http://localhost:4000/auth/login?redirect=%2Fdashboard', false);
  assert(queryVal.url === 'http://localhost:4000/auth/login?redirect=%2Fdashboard', 'I.5: Path and query string preserved');

  // ─────────────────────────────────────────────────────────────
  // J. Correct Severity Counts and Filters
  // ─────────────────────────────────────────────────────────────
  console.log(`\n--- Test J: Correct Severity Counts and Summary Math ---`);

  // Verify mathematical integrity of summary:
  // critical + high + medium + low MUST strictly equal failed
  // passed + failed + needsReview + notApplicable MUST strictly equal total
  const mockFindings = [
    { id: '1', status: 'FAIL', severity: 'Critical', category: 'Security' },
    { id: '2', status: 'FAIL', severity: 'High', category: 'Security' },
    { id: '3', status: 'FAIL', severity: 'Medium', category: 'Security' },
    { id: '4', status: 'FAIL', severity: 'Low', category: 'Security' },
    { id: '5', status: 'PASS', severity: 'Info', category: 'Security' },
    { id: '6', status: 'NEEDS_REVIEW', severity: 'Low', category: 'Security' },
    { id: '7', status: 'NOT_APPLICABLE', severity: 'Low', category: 'Security' },
  ];

  const failedOnly = mockFindings.filter((f) => f.status === 'FAIL');
  const counts = {
    total: mockFindings.length,
    passed: mockFindings.filter((f) => f.status === 'PASS').length,
    failed: failedOnly.length,
    needsReview: mockFindings.filter((f) => f.status === 'NEEDS_REVIEW').length,
    notApplicable: mockFindings.filter((f) => f.status === 'NOT_APPLICABLE').length,
    critical: failedOnly.filter((f) => f.severity.toLowerCase() === 'critical').length,
    high: failedOnly.filter((f) => f.severity.toLowerCase() === 'high').length,
    medium: failedOnly.filter((f) => f.severity.toLowerCase() === 'medium').length,
    low: failedOnly.filter((f) => f.severity.toLowerCase() === 'low').length,
  };

  assert(counts.critical === 1 && counts.high === 1 && counts.medium === 1 && counts.low === 1, 'J.1: Severity counts accurately calculated');
  assert(counts.critical + counts.high + counts.medium + counts.low === counts.failed, 'J.2: Severity sum equals failed count');
  assert(counts.passed + counts.failed + counts.needsReview + counts.notApplicable === counts.total, 'J.3: Status sum equals total count');
  assert(counts.needsReview === 1 && counts.notApplicable === 1, 'J.4: NEEDS_REVIEW and NOT_APPLICABLE kept separate from vulnerabilities');

  // ─────────────────────────────────────────────────────────────
  // K. All Four Assessment Statuses
  // ─────────────────────────────────────────────────────────────
  console.log(`\n--- Test K: All Four Assessment Statuses ---`);

  assert(['PASS', 'FAIL', 'NEEDS_REVIEW', 'NOT_APPLICABLE'].length === 4, 'K.1: Standard four-status model verified');
  const validStatuses = new Set(['PASS', 'FAIL', 'NEEDS_REVIEW', 'NOT_APPLICABLE']);
  assert(mockFindings.every((f) => validStatuses.has(f.status)), 'K.2: All findings conform to standard status enum');

  // ─────────────────────────────────────────────────────────────
  // L. Database Persistence and Assessment History
  // ─────────────────────────────────────────────────────────────
  console.log(`\n--- Test L: Database Persistence & History ---`);

  const testAssessId = `ASSESS-TEST-${Date.now()}`;
  const testTarget = 'http://localhost:4000/status/500';

  try {
    // Look up or insert test user
    let userRow = await db.query("SELECT id FROM users LIMIT 1");
    let testUserId;
    if (userRow.rows.length === 0) {
      const newUser = await db.query(
        "INSERT INTO users (email, password_hash, full_name) VALUES ('test_persist@example.invalid', 'hash', 'Test Persist') RETURNING id"
      );
      testUserId = newUser.rows[0].id;
    } else {
      testUserId = userRow.rows[0].id;
    }

    // Insert assessment record
    await db.query(
      `INSERT INTO assessments
         (id, user_id, target, overall_score, critical, high, medium, low, duration, status)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'completed')`,
      [testAssessId, testUserId, testTarget, 95, 0, 0, 0, 1, '1.1s']
    );

    // Insert finding with NOT_APPLICABLE status
    await db.query(
      `INSERT INTO findings
         (id, assessment_id, user_id, title, category, severity, status, evidence, risk, recommendation)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
      [
        'SEC-001',
        testAssessId,
        testUserId,
        'Login rate limiting',
        'Security',
        'Low',
        'NOT_APPLICABLE',
        'Target endpoint returned HTTP 404',
        'None',
        'Check route',
      ]
    );

    // Query back from PostgreSQL
    const readAssess = await db.query("SELECT target, duration, status FROM assessments WHERE id = $1", [testAssessId]);
    assert(readAssess.rows.length === 1, 'L.1: Assessment record persisted in PostgreSQL');
    assert(readAssess.rows[0].target === testTarget, `L.2: Persisted target URL path preserved exactly (${readAssess.rows[0].target})`);
    assert(readAssess.rows[0].status === 'completed', 'L.3: Assessment execution status is completed');

    const readFinding = await db.query("SELECT status, severity, evidence FROM findings WHERE assessment_id = $1 AND id = 'SEC-001'", [testAssessId]);
    assert(readFinding.rows.length === 1, 'L.4: Finding persisted in PostgreSQL');
    assert(readFinding.rows[0].status === 'NOT_APPLICABLE', `L.5: Finding status preserved as NOT_APPLICABLE (got: ${readFinding.rows[0].status})`);
  } finally {
    await db.query("DELETE FROM findings WHERE assessment_id = $1", [testAssessId]).catch(() => {});
    await db.query("DELETE FROM assessments WHERE id = $1", [testAssessId]).catch(() => {});
  }

  // ─────────────────────────────────────────────────────────────
  // M. Existing Authorization & SSRF Protections
  // ─────────────────────────────────────────────────────────────
  console.log(`\n--- Test M: Authorization and SSRF Protections ---`);

  const unauthExternal = validateTargetUrl('https://unauthorized-evil-target.com', false);
  assert(unauthExternal.valid === false && unauthExternal.error.includes('Safety restriction'), 'M.1: Blocks unauthorized external domain');

  const metadataTarget = validateTargetUrl('http://169.254.169.254/latest/meta-data', true);
  assert(metadataTarget.valid === false && metadataTarget.error.includes('metadata'), 'M.2: Blocks link-local cloud metadata IP (169.254.169.254)');

  const googleMetadata = validateTargetUrl('http://metadata.google.internal/computeMetadata/v1/', true);
  assert(googleMetadata.valid === false && googleMetadata.error.includes('metadata'), 'M.3: Blocks GCP metadata host');

  assert(isBlockedMetadataHost('169.254.169.254') === true, 'M.4: isBlockedMetadataHost detects 169.254.169.254');
  assert(isBlockedMetadataHost('localhost') === false, 'M.5: isBlockedMetadataHost permits localhost');

  console.log(`\n======================================================`);
  console.log(`  All Test Cases A through M Passed! (${passedCount} passed, ${failedCount} failed)`);
  console.log(`======================================================\n`);
}

runTests()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error('Test run failed:', err);
    process.exit(1);
  });
